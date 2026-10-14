use super::*;
use crate::{
    identity::hash_scanner_token,
    scan_control::dispatch::{ApplyTaskError, apply_task, recover_scanner_task},
};
use uuid::Uuid;

const PEPPER: &str = "routing-test-pepper-with-sufficient-length";
const TOKEN: &str = "routing-test-runtime-token";
fn token(id: Uuid) -> String {
    format!("{TOKEN}-{id}")
}
struct Fixture {
    pool: Pool,
    schema: String,
    owner: i32,
}
impl Fixture {
    async fn new() -> Self {
        let mut config: tokio_postgres::Config = std::env::var("STORAGE_TEST_DATABASE_URL")
            .expect("disposable PostgreSQL URL")
            .parse()
            .unwrap();
        let schema = format!("routing_{}", Uuid::new_v4().simple());
        config.options(format!("-c search_path={schema}"));
        let pool = Pool::builder(deadpool_postgres::Manager::new(
            config,
            tokio_postgres::NoTls,
        ))
        .max_size(16)
        .build()
        .unwrap();
        let c = pool.get().await.unwrap();
        c.batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        c.batch_execute(include_str!("../../source/database/init.sql"))
            .await
            .unwrap();
        c.batch_execute(include_str!(
            "../../source/database/migrate_smart_scanning.sql"
        ))
        .await
        .unwrap();
        c.batch_execute(include_str!(
            "../../source/database/migrate_scanner_diagnostics.sql"
        ))
        .await
        .unwrap();
        let owner=c.query_one("INSERT INTO users(username,password,role) VALUES('routing','unused',0) RETURNING id", &[]).await.unwrap().get("id");
        drop(c);
        Self {
            pool,
            schema,
            owner,
        }
    }
    async fn scanner(&self) -> Uuid {
        let id = Uuid::now_v7();
        let c = self.pool.get().await.unwrap();
        c.execute("INSERT INTO scanner_info(scanner_id,name,create_user,runtime_token_hash,is_enable,last_seen_at,runtime_state,supports_ipv4,ipv4_ready,scan_capabilities) VALUES($1,$1,$2,$3,true,NOW(),'idle',true,true,$4)", &[&id.to_string(),&self.owner,&hash_scanner_token(&token(id),PEPPER).unwrap(),&json!({"profiles":["port_only","dns_records","vulnerability_scan"],"explicit_dns_resolvers":true})]).await.unwrap();
        id
    }
    async fn task(&self, mode: &str, requested: Option<Uuid>) -> (i32, Uuid, i32) {
        let id = Uuid::now_v7();
        let c = self.pool.get().await.unwrap();
        let task=c.query_one("INSERT INTO scan_task(user_id,task_id,task_initiator,task_target,task_port,task_level,dispatch_mode,scan_profile) VALUES($1,$2,'routing',ARRAY['192.0.2.1'::INET],'443',1,$3,'port_only') RETURNING id", &[&self.owner,&id.to_string(),&mode]).await.unwrap().get("id");
        let execution=c.query_one("INSERT INTO scan_task_execution(execution_id,task_id,requested_scanner_id) VALUES($1,$2,$3) RETURNING id", &[&Uuid::now_v7().to_string(),&task,&requested.map(|id|id.to_string())]).await.unwrap().get("id");
        (task, id, execution)
    }
    async fn preference(&self, task: i32, scanner: Uuid, expires: i64) {
        self.pool.get().await.unwrap().execute("INSERT INTO scan_task_routing(task_id,preferred_scanner_id,prefer_until,decision) VALUES($1,$2,$3,$4) ON CONFLICT(task_id) DO UPDATE SET preferred_scanner_id=$2,prefer_until=$3", &[&task,&scanner.to_string(),&expires,&json!({"policy":"geo_balanced","preferred_scanner_id":scanner})]).await.unwrap();
    }
    async fn finish(self) {
        self.pool
            .get()
            .await
            .unwrap()
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn preference_is_shared_by_claim_and_recovery_then_expires() {
    let f = Fixture::new().await;
    let a = f.scanner().await;
    let b = f.scanner().await;
    let (task, id, _) = f.task("automatic", None).await;
    f.preference(task, b, crate::clock::get_unix_epoch_ms() + 15000)
        .await;
    assert!(matches!(
        apply_task(&f.pool, a, &token(a), PEPPER).await,
        Err(ApplyTaskError::NoTask)
    ));
    assert!(matches!(
        recover_scanner_task(&f.pool, a, Some(id), None, &token(a), PEPPER).await,
        Err(ApplyTaskError::NoTask)
    ));
    f.preference(task, b, 0).await;
    plan_queue(
        &f.pool,
        &MaxMindState::from_directory("/workspace/work/absent-mmdb"),
    )
    .await
    .unwrap();
    assert_eq!(
        apply_task(&f.pool, a, &token(a), PEPPER)
            .await
            .unwrap()
            .task_id,
        id
    );
    assert!(matches!(
        apply_task(&f.pool, a, &token(a), PEPPER).await,
        Err(ApplyTaskError::UnfinishedTask(_))
    ));
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn disabled_or_draining_preferred_node_does_not_hold_work() {
    let f = Fixture::new().await;
    let a = f.scanner().await;
    let b = f.scanner().await;
    let (task, id, _) = f.task("automatic", None).await;
    f.preference(task, b, crate::clock::get_unix_epoch_ms() + 15000)
        .await;
    f.pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE scanner_info SET accepting_tasks=false WHERE scanner_id=$1",
            &[&b.to_string()],
        )
        .await
        .unwrap();
    assert_eq!(
        apply_task(&f.pool, a, &token(a), PEPPER)
            .await
            .unwrap()
            .task_id,
        id
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn selected_mode_and_disabled_routing_preserve_manual_choice() {
    let f = Fixture::new().await;
    let a = f.scanner().await;
    let b = f.scanner().await;
    let (task, id, _) = f.task("selected", Some(a)).await;
    f.preference(task, b, crate::clock::get_unix_epoch_ms() + 15000)
        .await;
    assert_eq!(
        apply_task(&f.pool, a, &token(a), PEPPER)
            .await
            .unwrap()
            .task_id,
        id
    );
    let (task, id, _) = f.task("automatic", None).await;
    f.preference(task, a, crate::clock::get_unix_epoch_ms() + 15000)
        .await;
    f.pool
        .get()
        .await
        .unwrap()
        .execute(
            "INSERT INTO runtime_configuration(namespace,document) VALUES('scan_routing',$1)",
            &[&json!({"enabled":false})],
        )
        .await
        .unwrap();
    assert_eq!(
        apply_task(&f.pool, b, &token(b), PEPPER)
            .await
            .unwrap()
            .task_id,
        id
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn concurrent_scanners_claim_an_execution_once() {
    let f = Fixture::new().await;
    let (_, id, _) = f.task("automatic", None).await;
    let mut scanners = Vec::new();
    for _ in 0..12 {
        scanners.push(f.scanner().await);
    }
    let results =
        futures::future::join_all(scanners.iter().map(|scanner| async {
            apply_task(&f.pool, *scanner, &token(*scanner), PEPPER).await
        }))
        .await;
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .all(|t| t.task_id == id)
    );
    assert!(
        results
            .iter()
            .all(|r| matches!(r, Ok(_) | Err(ApplyTaskError::NoTask)))
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn planner_reserves_compatible_idle_nodes_and_route_feedback_is_idempotent() {
    let f = Fixture::new().await;
    let a = f.scanner().await;
    let b = f.scanner().await;
    let (task, _, execution) = f.task("automatic", None).await;
    let c = f.pool.get().await.unwrap();
    c.execute("UPDATE scan_task_execution SET assigned_scanner_id=$2,execution_status='running',attempt_count=1 WHERE id=$1", &[&execution,&a.to_string()]).await.unwrap();
    drop(c);
    let mut c = f.pool.get().await.unwrap();
    let tx = c.transaction().await.unwrap();
    record_outcome(&tx, execution, true).await.unwrap();
    record_outcome(&tx, execution, true).await.unwrap();
    tx.execute("UPDATE scan_task_execution SET execution_status='pending',assigned_scanner_id=NULL WHERE id=$1", &[&execution]).await.unwrap();
    tx.commit().await.unwrap();
    drop(c);
    let maxmind = MaxMindState::from_directory("/workspace/work/absent-mmdb");
    plan_queue(&f.pool, &maxmind).await.unwrap();
    let c = f.pool.get().await.unwrap();
    let row = c
        .query_one(
            "SELECT preferred_scanner_id FROM scan_task_routing WHERE task_id=$1",
            &[&task],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>("preferred_scanner_id"), b.to_string());
    assert_eq!(
        c.query_one(
            "SELECT route_failures FROM scanner_target_feedback WHERE scanner_id=$1",
            &[&a.to_string()]
        )
        .await
        .unwrap()
        .get::<_, i32>("route_failures"),
        1
    );
    drop(c);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn zero_port_success_updates_freshness_and_survives_task_deletion() {
    let f = Fixture::new().await;
    let a = f.scanner().await;
    let (task, _, execution) = f.task("automatic", None).await;
    let mut c = f.pool.get().await.unwrap();
    let tx = c.transaction().await.unwrap();
    tx.execute("UPDATE scan_task SET task_source='automatic',generation_key='sequential_subnet:192.0.2.1/32',task_status='succeeded',task_end_time=$2 WHERE id=$1", &[&task,&crate::clock::get_unix_epoch_ms()]).await.unwrap();
    tx.execute("UPDATE scan_task_execution SET execution_status='succeeded',assigned_scanner_id=$2,attempt_count=1,result_port_count=0 WHERE id=$1", &[&execution,&a.to_string()]).await.unwrap();
    crate::target_generated::history::record_result(&tx, task)
        .await
        .unwrap();
    crate::target_generated::history::record_result(&tx, task)
        .await
        .unwrap();
    record_outcome(&tx, execution, false).await.unwrap();
    record_outcome(&tx, execution, false).await.unwrap();
    tx.commit().await.unwrap();
    c.execute("DELETE FROM scan_task WHERE id=$1", &[&task])
        .await
        .unwrap();
    let tx = c.transaction().await.unwrap();
    assert!(
        !crate::target_generated::history::eligible(
            &tx,
            "sequential_subnet:192.0.2.1/32",
            "port_only",
            "443",
            604800000,
            crate::clock::get_unix_epoch_ms()
        )
        .await
        .unwrap()
    );
    let success: i64 = tx
        .query_one("SELECT last_success_at FROM automatic_target_history", &[])
        .await
        .unwrap()
        .get("last_success_at");
    assert!(
        crate::target_generated::history::eligible(
            &tx,
            "sequential_subnet:192.0.2.1/32",
            "port_only",
            "443",
            1000,
            success + 2000
        )
        .await
        .unwrap()
    );
    assert!(
        !crate::target_generated::history::eligible(
            &tx,
            "sequential_subnet:192.0.2.1/32",
            "port_only",
            "443",
            2592000000,
            success + 1728000000
        )
        .await
        .unwrap()
    );
    assert_eq!(
        tx.query_one("SELECT successes FROM scanner_target_feedback", &[])
            .await
            .unwrap()
            .get::<_, i32>("successes"),
        1
    );
    tx.commit().await.unwrap();
    drop(c);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn changed_plan_can_refresh_but_active_compatible_work_is_reused() {
    let f = Fixture::new().await;
    let (task, _, _) = f.task("automatic", None).await;
    let mut c = f.pool.get().await.unwrap();
    c.execute(
        "UPDATE scan_task SET generation_key='sequential_subnet:192.0.2.1/32' WHERE id=$1",
        &[&task],
    )
    .await
    .unwrap();
    let tx = c.transaction().await.unwrap();
    let now = crate::clock::get_unix_epoch_ms();
    assert!(
        !crate::target_generated::history::eligible(
            &tx,
            "sequential_subnet:192.0.2.1/32",
            "port_only",
            "443",
            1000,
            now
        )
        .await
        .unwrap()
    );
    assert!(
        crate::target_generated::history::eligible(
            &tx,
            "sequential_subnet:192.0.2.1/32",
            "port_only",
            "80",
            1000,
            now
        )
        .await
        .unwrap()
    );
    tx.commit().await.unwrap();
    drop(c);
    f.finish().await;
}

#[actix_web::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn performance_requires_owned_live_lease_and_preserves_first_report() {
    use actix_web::{App, http::StatusCode, test, web};
    let f = Fixture::new().await;
    let a = f.scanner().await;
    let (_, id, execution) = f.task("automatic", None).await;
    apply_task(&f.pool, a, &token(a), PEPPER).await.unwrap();
    let maintenance = crate::system_maintenance::SystemMaintenanceState::from_database(&f.pool)
        .await
        .unwrap();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(f.pool.clone()))
            .app_data(web::Data::new(crate::config::SecurityConfig {
                scanner_token_pepper: PEPPER.into(),
            }))
            .app_data(web::Data::new(maintenance))
            .service(crate::handlers::scan_routing::report_performance),
    )
    .await;
    let payload = json!({"scanner_id":a,"task_id":id,"performance":{"elapsed_ms":200,"connections":[{"ip":"192.0.2.1","port":443,"elapsed_ms":5,"outcome":"connected"}]}});
    let request = test::TestRequest::post()
        .uri("/api/scanner/task/performance")
        .insert_header(("Authorization", format!("Bearer {}", token(a))))
        .set_json(&payload)
        .to_request();
    assert_eq!(
        test::call_service(&app, request).await.status(),
        StatusCode::OK
    );
    let mut changed = payload.clone();
    changed["performance"]["elapsed_ms"] = json!(999);
    let request = test::TestRequest::post()
        .uri("/api/scanner/task/performance")
        .insert_header(("Authorization", format!("Bearer {}", token(a))))
        .set_json(&changed)
        .to_request();
    assert_eq!(
        test::call_service(&app, request).await.status(),
        StatusCode::OK
    );
    let c = f.pool.get().await.unwrap();
    let performance: Value = c
        .query_one(
            "SELECT performance FROM scan_task_execution WHERE id=$1",
            &[&execution],
        )
        .await
        .unwrap()
        .get("performance");
    assert_eq!(performance["elapsed_ms"], 200);
    changed["performance"]["connections"][0]["ip"] = json!("198.51.100.1");
    let request = test::TestRequest::post()
        .uri("/api/scanner/task/performance")
        .insert_header(("Authorization", format!("Bearer {}", token(a))))
        .set_json(&changed)
        .to_request();
    assert_eq!(
        test::call_service(&app, request).await.status(),
        StatusCode::BAD_REQUEST
    );
    c.execute(
        "UPDATE scan_task_execution SET lease_expires_at=0 WHERE id=$1",
        &[&execution],
    )
    .await
    .unwrap();
    let request = test::TestRequest::post()
        .uri("/api/scanner/task/performance")
        .insert_header(("Authorization", format!("Bearer {}", token(a))))
        .set_json(&payload)
        .to_request();
    assert_eq!(
        test::call_service(&app, request).await.status(),
        StatusCode::CONFLICT
    );
    drop(c);
    drop(app);
    f.finish().await;
}

#[actix_web::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn explicit_route_failure_requeues_once_and_prefers_another_node() {
    use actix_web::{App, test, web};
    let f = Fixture::new().await;
    let a = f.scanner().await;
    let b = f.scanner().await;
    let (_, id, _) = f.task("automatic", None).await;
    apply_task(&f.pool, a, &token(a), PEPPER).await.unwrap();
    let maintenance = crate::system_maintenance::SystemMaintenanceState::from_database(&f.pool)
        .await
        .unwrap();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(f.pool.clone()))
            .app_data(web::Data::new(crate::config::SecurityConfig {
                scanner_token_pepper: PEPPER.into(),
            }))
            .app_data(web::Data::new(maintenance))
            .service(crate::handlers::task::scanner_task_failure_handler),
    )
    .await;
    let payload = json!({"scanner_id":a,"task_id":id,"error":"network is unreachable","retryable":true,"failure_class":"route_unavailable"});
    for _ in 0..2 {
        let request = test::TestRequest::post()
            .uri("/api/scanner/task/fail")
            .insert_header(("Authorization", format!("Bearer {}", token(a))))
            .set_json(&payload)
            .to_request();
        let _ = test::call_service(&app, request).await;
    }
    plan_queue(
        &f.pool,
        &MaxMindState::from_directory("/workspace/work/absent-mmdb"),
    )
    .await
    .unwrap();
    assert_eq!(
        apply_task(&f.pool, b, &token(b), PEPPER)
            .await
            .unwrap()
            .task_id,
        id
    );
    let c = f.pool.get().await.unwrap();
    assert_eq!(
        c.query_one(
            "SELECT route_failures FROM scanner_target_feedback WHERE scanner_id=$1",
            &[&a.to_string()]
        )
        .await
        .unwrap()
        .get::<_, i32>("route_failures"),
        1
    );
    drop(c);
    drop(app);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn changed_asset_gets_earlier_refresh_and_stable_asset_returns_to_normal_interval() {
    let f = Fixture::new().await;
    let key = "sequential_subnet:192.0.2.1/32";
    let c = f.pool.get().await.unwrap();
    c.execute(
        "INSERT INTO runtime_configuration(namespace,document) VALUES('automatic_target',$1)",
        &[&json!({"repeat_after_seconds":604800,"change_refresh_seconds":60})],
    )
    .await
    .unwrap();
    drop(c);
    let mut last_due = 0;
    for (index, signature) in ["0".repeat(256), "1".repeat(256), "1".repeat(256)]
        .into_iter()
        .enumerate()
    {
        let (task, _, execution) = f.task("automatic", None).await;
        let mut c = f.pool.get().await.unwrap();
        let tx = c.transaction().await.unwrap();
        let now = crate::clock::get_unix_epoch_ms();
        tx.execute("UPDATE scan_task SET task_source='automatic',generation_key=$2,task_status='succeeded',task_end_time=$3 WHERE id=$1", &[&task,&key,&now]).await.unwrap();
        tx.execute("UPDATE scan_task_execution SET execution_status='succeeded',asset_signature=$2::TEXT::BIT(256),result_port_count=1 WHERE id=$1", &[&execution,&signature]).await.unwrap();
        crate::target_generated::history::record_result(&tx, task)
            .await
            .unwrap();
        let due: i64 = tx
            .query_one(
                "SELECT next_refresh_at FROM automatic_target_history WHERE generation_key=$1",
                &[&key],
            )
            .await
            .unwrap()
            .get("next_refresh_at");
        if index == 1 {
            assert!(due - now <= 60000);
            assert!(due < last_due);
        } else {
            assert_eq!(due - now, 604800000);
        }
        last_due = due;
        tx.commit().await.unwrap();
    }
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn smart_generator_refills_authorized_targets_without_repeating_fresh_or_active_work() {
    let f = Fixture::new().await;
    let _scanner = f.scanner().await;
    let policy = crate::config::AutomaticTargetConfig {
        enabled: true,
        strategy: "smart_refresh".into(),
        authorized_cidrs: vec!["192.0.2.0/24".into()],
        excluded_cidrs: vec!["192.0.2.0/32".into(), "192.0.2.2/32".into()],
        ipv4_task_prefix: 32,
        pending_low_watermark: 1,
        pending_high_watermark: 2,
        common_ports: "443".into(),
        ..Default::default()
    };
    let profile = crate::admin::get_default_scan_profile_from_database(&f.pool)
        .await
        .unwrap();
    let c = f.pool.get().await.unwrap();
    c.execute(
        "INSERT INTO runtime_configuration(namespace,document) VALUES('automatic_target',$1)",
        &[&json!(policy)],
    )
    .await
    .unwrap();
    c.execute("INSERT INTO automatic_target_history(generation_key,plan_key,address_family,target) VALUES('outside-current-scope',$1,'ipv4','198.51.100.1/32')", &[&crate::target_generated::history::plan_key(&profile,"443")]).await.unwrap();
    drop(c);
    let service = crate::target_generated::AutomaticTargetService::new(policy).unwrap();
    assert_eq!(service.refill(&f.pool).await.unwrap().generated, 2);
    assert_eq!(service.refill(&f.pool).await.unwrap().generated, 0);
    let mut c = f.pool.get().await.unwrap();
    let tx = c.transaction().await.unwrap();
    let tasks = tx
        .query("SELECT id FROM scan_task ORDER BY id", &[])
        .await
        .unwrap();
    for task in tasks {
        let id: i32 = task.get("id");
        tx.execute(
            "UPDATE scan_task SET task_status='succeeded',task_end_time=$2 WHERE id=$1",
            &[&id, &crate::clock::get_unix_epoch_ms()],
        )
        .await
        .unwrap();
        tx.execute("UPDATE scan_task_execution SET execution_status='succeeded',result_port_count=0 WHERE task_id=$1", &[&id]).await.unwrap();
        crate::target_generated::history::record_result(&tx, id)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    drop(c);
    assert_eq!(service.refill(&f.pool).await.unwrap().generated, 2);
    let c = f.pool.get().await.unwrap();
    let targets = c
        .query("SELECT task_target::TEXT[] AS targets FROM scan_task", &[])
        .await
        .unwrap()
        .into_iter()
        .flat_map(|r| r.get::<_, Vec<String>>("targets"))
        .collect::<Vec<_>>();
    assert_eq!(targets.len(), 4);
    assert_eq!(
        targets
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        4
    );
    assert!(
        targets
            .iter()
            .all(|t| t.starts_with("192.0.2.") && t != "192.0.2.0/32" && t != "192.0.2.2/32")
    );
    drop(c);
    f.finish().await;
}
