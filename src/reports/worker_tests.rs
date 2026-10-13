use super::render_mail;
use crate::mail_template::{MailTemplateSource, REPORT_WEEKLY_TEMPLATE_KEY};
use crate::module_runtime::{
    Module, ModuleContract, ModuleError, ModuleFuture, ModuleRegistry, ModuleSlot,
};
use crate::reports::render_module::{
    INPUT_SCHEMA, LocalReportRenderModule, MODULE_ID, OUTPUT_SCHEMA, ReportRenderInput,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
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
            max_inflight: 1,
            max_payload_bytes: 1024 * 1024,
            request_timeout: Duration::from_secs(1),
            prepare_timeout: Duration::from_secs(1),
        },
    )]))
    .unwrap()
}

fn input() -> Value {
    serde_json::to_value(ReportRenderInput {
        template_key: REPORT_WEEKLY_TEMPLATE_KEY.into(),
        template_version: 2,
        source: MailTemplateSource {
            subject_template: "Report {{ count }}".into(),
            html_template: "<p>{{ count }}</p>".into(),
            text_template: "{{ count }}".into(),
        },
        context: json!({"count":3}),
    })
    .unwrap()
}

struct FaultModule {
    error: ModuleError,
    available: AtomicBool,
    stop_on_invoke: bool,
}

impl Module for FaultModule {
    fn contract(&self) -> ModuleContract {
        LocalReportRenderModule.contract()
    }
    fn is_available(&self) -> bool {
        self.available.load(Ordering::Acquire)
    }
    fn self_test(&self) -> ModuleFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
    fn invoke<'a>(&'a self, _: &'a str, _: Value) -> ModuleFuture<'a, Value> {
        Box::pin(async {
            if self.stop_on_invoke {
                self.available.store(false, Ordering::Release);
            }
            Err(self.error.clone())
        })
    }
}

#[tokio::test]
async fn not_ready_renderer_returns_a_job_error_and_renders_after_recovery() {
    let registry = registry();
    assert!(render_mail(&registry, input(), 2).await.is_err());
    registry
        .publish(0, Arc::new(LocalReportRenderModule))
        .await
        .unwrap();
    let attempt = render_mail(&registry, input(), 2).await.unwrap();
    assert_eq!(attempt.rendered.unwrap().subject, "Report 3");
    drop(attempt.lease);
    registry.shutdown(Duration::from_secs(1)).await.unwrap();
}

#[tokio::test]
async fn temporary_invocation_failures_do_not_become_permanent_mail_errors() {
    for error in [
        ModuleError::Busy,
        ModuleError::DeadlineExceeded,
        ModuleError::Unavailable("worker transport failed".into()),
    ] {
        let registry = registry();
        registry
            .publish(
                0,
                Arc::new(FaultModule {
                    error,
                    available: AtomicBool::new(true),
                    stop_on_invoke: false,
                }),
            )
            .await
            .unwrap();
        assert!(render_mail(&registry, input(), 2).await.is_err());
        registry.shutdown(Duration::from_secs(1)).await.unwrap();
    }
}

#[tokio::test]
async fn stopped_workers_with_legacy_or_protocol_errors_retry_and_reconcile() {
    for error in [
        ModuleError::Execution("legacy IPC failure".into()),
        ModuleError::IncompatibleContract,
        ModuleError::PayloadTooLarge,
    ] {
        let registry = registry();
        registry
            .publish(
                0,
                Arc::new(FaultModule {
                    error,
                    available: AtomicBool::new(true),
                    stop_on_invoke: true,
                }),
            )
            .await
            .unwrap();
        assert!(render_mail(&registry, input(), 2).await.is_err());
        let candidate = registry
            .prepare(Arc::new(LocalReportRenderModule))
            .await
            .unwrap();
        let publication = registry.apply_prepared(1, candidate).await.unwrap();
        publication
            .retired
            .unwrap()
            .shutdown(Duration::from_secs(1))
            .await
            .unwrap();
        let attempt = render_mail(&registry, input(), 2).await.unwrap();
        assert_eq!(attempt.rendered.unwrap().subject, "Report 3");
        assert_eq!(attempt.lease.generation(), 1);
        drop(attempt.lease);
        registry.shutdown(Duration::from_secs(1)).await.unwrap();
    }
}

#[tokio::test]
async fn permanent_template_errors_still_allow_statistics_only_archival() {
    let registry = registry();
    registry
        .publish(0, Arc::new(LocalReportRenderModule))
        .await
        .unwrap();
    let mut invalid = input();
    invalid["source"]["subjectTemplate"] = json!("{{ missing_variable }}");
    let attempt = render_mail(&registry, invalid, 2).await.unwrap();
    assert!(attempt.rendered.is_err());
    assert!(attempt.lease.is_available());
    drop(attempt.lease);
    let valid = render_mail(&registry, input(), 2).await.unwrap();
    assert!(valid.rendered.is_ok());
    drop(valid.lease);
    registry.shutdown(Duration::from_secs(1)).await.unwrap();
}
