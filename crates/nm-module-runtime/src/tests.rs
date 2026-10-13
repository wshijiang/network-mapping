use super::*;
use serde_json::json;

struct TestModule {
    release: &'static str,
    factor: u64,
    fail_prepare: bool,
    panic_on_invoke: bool,
    prepare_gate: Option<(Arc<Notify>, Arc<Notify>)>,
    invocation_gate: Option<(Arc<Notify>, Arc<Notify>)>,
}

impl TestModule {
    fn new(release: &'static str, factor: u64) -> Self {
        Self {
            release,
            factor,
            fail_prepare: false,
            panic_on_invoke: false,
            prepare_gate: None,
            invocation_gate: None,
        }
    }
}

impl Module for TestModule {
    fn contract(&self) -> ModuleContract {
        ModuleContract {
            module_id: "test".into(),
            release_id: self.release.into(),
            rpc_version: 1,
            input_schema: "number.v1".into(),
            output_schema: "number.v1".into(),
            methods: BTreeSet::from(["compute".into()]),
        }
    }

    fn self_test(&self) -> ModuleFuture<'_, ()> {
        Box::pin(async {
            if let Some((entered, release)) = &self.prepare_gate {
                entered.notify_one();
                release.notified().await;
            }
            if self.fail_prepare {
                return Err(ModuleError::Execution("self test failed".into()));
            }
            Ok(())
        })
    }

    fn invoke<'a>(&'a self, _method: &'a str, input: Value) -> ModuleFuture<'a, Value> {
        Box::pin(async move {
            assert!(!self.panic_on_invoke, "simulated execution task panic");
            if let Some((entered, release)) = &self.invocation_gate {
                entered.notify_one();
                release.notified().await;
            }
            let input = input
                .as_u64()
                .ok_or_else(|| ModuleError::Execution("not a number".into()))?;
            Ok(json!(input * self.factor))
        })
    }
}

#[tokio::test]
async fn failed_execution_task_returns_a_retryable_error_and_releases_capacity() {
    let registry = registry();
    let mut module = TestModule::new("panicking", 1);
    module.panic_on_invoke = true;
    registry.publish(0, Arc::new(module)).await.unwrap();
    let lease = registry.acquire("test").await.unwrap();
    for _ in 0..2 {
        let error = lease.invoke("compute", json!(2)).await.unwrap_err();
        assert!(matches!(error, ModuleError::Unavailable(_)));
        assert!(error.is_retryable());
    }
    drop(lease);
    registry.shutdown(Duration::from_secs(1)).await.unwrap();
}

fn slot() -> ModuleSlot {
    ModuleSlot {
        rpc_version: 1,
        input_schema: "number.v1".into(),
        output_schema: "number.v1".into(),
        methods: BTreeSet::from(["compute".into()]),
        max_inflight: 1,
        max_payload_bytes: 1024,
        request_timeout: Duration::from_secs(1),
        prepare_timeout: Duration::from_secs(1),
    }
}

fn registry() -> Arc<ModuleRegistry> {
    Arc::new(ModuleRegistry::new(BTreeMap::from([("test".into(), slot())])).unwrap())
}

#[tokio::test]
async fn old_request_keeps_implementation_and_rollback_increments_revision() {
    let registry = registry();
    registry
        .publish(0, Arc::new(TestModule::new("v1", 1)))
        .await
        .unwrap();
    let old = registry.acquire("test").await.unwrap();
    let publication = registry
        .publish(1, Arc::new(TestModule::new("v2", 10)))
        .await
        .unwrap();
    let retired = publication.retired.unwrap();
    let new = registry.acquire("test").await.unwrap();
    assert_eq!(old.invoke("compute", json!(2)).await.unwrap(), json!(2));
    assert_eq!(new.invoke("compute", json!(2)).await.unwrap(), json!(20));
    assert_eq!(old.generation(), 1);
    assert_eq!(new.generation(), 2);
    assert!(retired.held_leases() >= 1);
    drop(old);
    retired.wait_drained(Duration::from_secs(1)).await.unwrap();
    let rollback = registry
        .publish(2, Arc::new(TestModule::new("v1", 1)))
        .await
        .unwrap();
    assert_eq!(rollback.revision, 3);
    assert_eq!(registry.acquire("test").await.unwrap().release_id(), "v1");
}

#[tokio::test]
async fn bad_candidate_and_stale_revision_do_not_replace_active_implementation() {
    let registry = registry();
    registry
        .publish(0, Arc::new(TestModule::new("v1", 1)))
        .await
        .unwrap();
    let mut bad = TestModule::new("bad", 100);
    bad.fail_prepare = true;
    assert!(matches!(
        registry.publish(1, Arc::new(bad)).await,
        Err(ModuleError::Execution(_))
    ));
    assert!(matches!(
        registry
            .publish(0, Arc::new(TestModule::new("v2", 10)))
            .await,
        Err(ModuleError::RevisionConflict {
            expected: 0,
            actual: 1
        })
    ));
    assert_eq!(registry.revision().await, 1);
    assert_eq!(registry.acquire("test").await.unwrap().release_id(), "v1");
    assert!(matches!(
        registry.acquire("missing").await,
        Err(ModuleError::NotReady)
    ));
}

#[tokio::test]
async fn publisher_losing_race_during_prepare_cannot_overwrite_winner() {
    let registry = registry();
    registry
        .publish(0, Arc::new(TestModule::new("v1", 1)))
        .await
        .unwrap();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let mut slow = TestModule::new("slow", 10);
    slow.prepare_gate = Some((entered.clone(), release.clone()));
    let concurrent = registry.clone();
    let publishing = tokio::spawn(async move { concurrent.publish(1, Arc::new(slow)).await });
    entered.notified().await;
    registry
        .publish(1, Arc::new(TestModule::new("winner", 2)))
        .await
        .unwrap();
    release.notify_one();
    assert!(matches!(
        publishing.await.unwrap(),
        Err(ModuleError::RevisionConflict {
            expected: 1,
            actual: 2
        })
    ));
    assert_eq!(
        registry.acquire("test").await.unwrap().release_id(),
        "winner"
    );
}

#[tokio::test]
async fn timeout_keeps_capacity_and_retirement_waits_for_actual_execution() {
    let mut policy = slot();
    policy.request_timeout = Duration::from_millis(20);
    let registry = ModuleRegistry::new(BTreeMap::from([("test".into(), policy)])).unwrap();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let mut module = TestModule::new("slow", 1);
    module.invocation_gate = Some((entered.clone(), release.clone()));
    registry.publish(0, Arc::new(module)).await.unwrap();
    let lease = registry.acquire("test").await.unwrap();
    assert_eq!(
        lease.invoke("compute", json!(2)).await.unwrap_err(),
        ModuleError::DeadlineExceeded
    );
    entered.notified().await;
    assert_eq!(
        lease.invoke("compute", json!(2)).await.unwrap_err(),
        ModuleError::Busy
    );
    let publication = registry
        .publish(1, Arc::new(TestModule::new("new", 10)))
        .await
        .unwrap();
    let retired = publication.retired.unwrap();
    drop(lease);
    assert_eq!(retired.held_leases(), 1);
    assert_eq!(
        retired
            .wait_drained(Duration::from_millis(5))
            .await
            .unwrap_err(),
        ModuleError::DrainTimeout
    );
    release.notify_one();
    retired.wait_drained(Duration::from_secs(1)).await.unwrap();
}

#[tokio::test]
async fn module_boundaries_reject_unknown_methods_and_oversized_payloads() {
    let registry = registry();
    registry
        .publish(0, Arc::new(TestModule::new("v1", 1)))
        .await
        .unwrap();
    let lease = registry.acquire("test").await.unwrap();
    assert_eq!(
        lease.invoke("delete", json!(2)).await.unwrap_err(),
        ModuleError::UnsupportedMethod
    );
    assert_eq!(
        lease
            .invoke("compute", json!("x".repeat(1024)))
            .await
            .unwrap_err(),
        ModuleError::PayloadTooLarge
    );
}

#[tokio::test]
async fn restart_can_restore_skipped_authoritative_revisions() {
    let registry = registry();
    let candidate = registry
        .prepare(Arc::new(TestModule::new("restored", 1)))
        .await
        .unwrap();
    registry.apply_prepared(17, candidate).await.unwrap();
    assert_eq!(registry.revision().await, 17);
    assert_eq!(registry.acquire("test").await.unwrap().generation(), 17);
    let stale = registry
        .prepare(Arc::new(TestModule::new("stale", 10)))
        .await
        .unwrap();
    assert!(matches!(
        registry.apply_prepared(16, stale).await,
        Err(ModuleError::RevisionConflict { actual: 17, .. })
    ));
    assert_eq!(
        registry.acquire("test").await.unwrap().release_id(),
        "restored"
    );
}
