use nm_module_runtime::{Module, ModuleError, ModuleRegistry, ModuleSlot, process::ProcessModule};
use nm_report_renderer::{
    INPUT_SCHEMA, MODULE_ID, MailTemplateSource, OUTPUT_SCHEMA, REPORT_WEEKLY_TEMPLATE_KEY,
    ReportRenderInput, ReportRenderOutput,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
    time::Duration,
};

fn registry() -> ModuleRegistry {
    ModuleRegistry::new(BTreeMap::from([(
        MODULE_ID.into(),
        ModuleSlot {
            rpc_version: 1,
            input_schema: INPUT_SCHEMA.into(),
            output_schema: OUTPUT_SCHEMA.into(),
            methods: BTreeSet::from(["render".into()]),
            max_inflight: 8,
            max_payload_bytes: 1024 * 1024,
            request_timeout: Duration::from_secs(5),
            prepare_timeout: Duration::from_secs(5),
        },
    )]))
    .unwrap()
}

fn input() -> serde_json::Value {
    serde_json::to_value(ReportRenderInput {
        template_key: REPORT_WEEKLY_TEMPLATE_KEY.into(),
        template_version: 4,
        source: MailTemplateSource {
            subject_template: "Count {{ count }}".into(),
            html_template: "<p>{{ count }}</p>".into(),
            text_template: "{{ count }}".into(),
        },
        context: serde_json::json!({"count":3}),
    })
    .unwrap()
}

#[tokio::test]
async fn real_worker_replacement_pins_old_requests_and_reaps_retired_process() {
    let executable = Path::new(env!("CARGO_BIN_EXE_nm-report-render-worker"));
    let registry = registry();
    let old = Arc::new(ProcessModule::spawn(executable, "release-a").await.unwrap());
    registry.publish(0, old.clone()).await.unwrap();
    let old_request = registry.acquire(MODULE_ID).await.unwrap();
    let new = Arc::new(ProcessModule::spawn(executable, "release-b").await.unwrap());
    let publication = registry.publish(1, new.clone()).await.unwrap();
    let retired = publication.retired.unwrap();
    assert_eq!(
        retired
            .wait_drained(Duration::from_millis(5))
            .await
            .unwrap_err(),
        ModuleError::DrainTimeout
    );
    let result = old_request.invoke("render", input()).await.unwrap();
    let result: ReportRenderOutput = serde_json::from_value(result).unwrap();
    assert_eq!(result.rendered.subject, "Count 3");
    assert_eq!(old_request.release_id(), "release-a");
    let new_request = registry.acquire(MODULE_ID).await.unwrap();
    assert_eq!(new_request.release_id(), "release-b");
    assert_eq!(new_request.generation(), 2);
    assert!(new_request.invoke("render", input()).await.is_ok());
    drop(old_request);
    retired.shutdown(Duration::from_secs(2)).await.unwrap();
    assert!(!old.is_available());
    drop(new_request);
    registry.shutdown(Duration::from_secs(2)).await.unwrap();
    assert!(!new.is_available());
}

#[tokio::test]
async fn business_validation_error_does_not_kill_the_worker() {
    let worker = ProcessModule::spawn(
        Path::new(env!("CARGO_BIN_EXE_nm-report-render-worker")),
        "validation-worker",
    )
    .await
    .unwrap();
    let mut invalid = input();
    invalid["templateKey"] = serde_json::json!("login_success");
    assert!(worker.invoke("render", invalid).await.is_err());
    assert!(worker.is_available());
    assert!(worker.invoke("render", input()).await.is_ok());
    worker.shutdown().await.unwrap();
}

#[tokio::test]
async fn oversized_request_envelope_does_not_stop_a_healthy_worker() {
    let worker = ProcessModule::spawn(
        Path::new(env!("CARGO_BIN_EXE_nm-report-render-worker")),
        "size-boundary-worker",
    )
    .await
    .unwrap();
    // The payload itself fits the registry limit; its RPC envelope does not.
    let payload = serde_json::json!("x".repeat(nm_module_runtime::process::MAX_FRAME_BYTES - 2));
    assert_eq!(
        serde_json::to_vec(&payload).unwrap().len(),
        nm_module_runtime::process::MAX_FRAME_BYTES
    );
    assert_eq!(
        worker.invoke("render", payload).await.unwrap_err(),
        ModuleError::PayloadTooLarge
    );
    assert!(worker.is_available());
    assert!(worker.invoke("render", input()).await.is_ok());
    worker.shutdown().await.unwrap();
}

#[tokio::test]
async fn failed_worker_recovers_at_the_same_revision_then_rolls_back_at_a_new_revision() {
    let executable = Path::new(env!("CARGO_BIN_EXE_nm-report-render-worker"));
    let registry = registry();
    let failed = Arc::new(ProcessModule::spawn(executable, "release-b").await.unwrap());
    let initial = registry.prepare(failed.clone()).await.unwrap();
    registry.apply_prepared(7, initial).await.unwrap();
    failed.shutdown().await.unwrap();
    assert!(!registry.acquire(MODULE_ID).await.unwrap().is_available());

    let recovered = Arc::new(ProcessModule::spawn(executable, "release-b").await.unwrap());
    let candidate = registry.prepare(recovered.clone()).await.unwrap();
    let recovery = registry.apply_prepared(7, candidate).await.unwrap();
    recovery
        .retired
        .unwrap()
        .shutdown(Duration::from_secs(2))
        .await
        .unwrap();
    let recovered_request = registry.acquire(MODULE_ID).await.unwrap();
    assert_eq!(recovered_request.generation(), 7);
    assert!(recovered_request.invoke("render", input()).await.is_ok());

    let rollback = Arc::new(ProcessModule::spawn(executable, "release-a").await.unwrap());
    let candidate = registry.prepare(rollback.clone()).await.unwrap();
    let publication = registry.apply_prepared(8, candidate).await.unwrap();
    let rolled_back_request = registry.acquire(MODULE_ID).await.unwrap();
    assert_eq!(rolled_back_request.release_id(), "release-a");
    assert_eq!(rolled_back_request.generation(), 8);
    assert!(rolled_back_request.invoke("render", input()).await.is_ok());
    // Requests acquired before rollback still use the recovered release-b.
    assert!(recovered_request.invoke("render", input()).await.is_ok());
    drop(recovered_request);
    publication
        .retired
        .unwrap()
        .shutdown(Duration::from_secs(2))
        .await
        .unwrap();
    assert!(!recovered.is_available());
    drop(rolled_back_request);
    registry.shutdown(Duration::from_secs(2)).await.unwrap();
    assert!(!rollback.is_available());
}
