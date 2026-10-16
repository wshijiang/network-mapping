//! Database checks use a unique schema in an explicitly supplied disposable DB.
use deadpool_postgres::{Manager, Pool};
use tokio_postgres::NoTls;
use uuid::Uuid;

pub(crate) async fn isolated_pool() -> (Pool, String) {
    let mut config: tokio_postgres::Config = std::env::var("HEALTH_TEST_DATABASE_URL")
        .expect("HEALTH_TEST_DATABASE_URL must point to a disposable PostgreSQL instance")
        .parse()
        .expect("test database config");
    let schema = format!("health_{}", Uuid::new_v4().simple());
    config.options(format!("-c search_path={schema} -c timezone=UTC"));
    let pool = Pool::builder(Manager::new(config, NoTls))
        .max_size(8)
        .build()
        .unwrap();
    let client = pool.get().await.unwrap();
    client
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    client
        .batch_execute(include_str!("../../source/database/init.sql"))
        .await
        .unwrap();
    client
        .batch_execute(include_str!(
            "../../source/database/migrate_scanner_diagnostics.sql"
        ))
        .await
        .unwrap();
    client.batch_execute("INSERT INTO users(id,username,password,role,email) VALUES(1,'admin','test',1,'admin@example.invalid');").await.unwrap();
    drop(client);
    (pool, schema)
}

pub(crate) async fn cleanup(pool: &Pool, schema: &str) {
    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable HEALTH_TEST_DATABASE_URL"]
async fn shared_gate_rejection_does_not_restart_local_cooldown() {
    use crate::{config::MonitorConfig, monitor::HealthEvent, runtime_config::Versioned};
    use std::{
        sync::{Arc, RwLock},
        time::Duration,
    };
    let (pool, schema) = isolated_pool().await;
    pool.get().await.unwrap().execute("INSERT INTO notification_health_gate(alert_key,severity,admitted_at) VALUES('shared-late-duplicate','warning',NOW())", &[]).await.unwrap();
    let config = Arc::new(RwLock::new(Versioned {
        revision: 1,
        value: MonitorConfig::default(),
    }));
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let worker = tokio::spawn(super::run_notifier(rx, pool.clone(), String::new(), config));
    let event = |key: &str| HealthEvent {
        alert_type: "slow_request",
        severity: "warning",
        key: key.into(),
        summary: "regression".into(),
        details: vec![],
        applied_rule: None,
    };
    async fn wait_for(pool: &Pool, key: &str) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let count: i64 = pool
                    .get()
                    .await
                    .unwrap()
                    .query_one(
                        "SELECT COUNT(*) FROM health_alert WHERE alert_key=$1",
                        &[&key],
                    )
                    .await
                    .unwrap()
                    .get(0);
                if count > 0 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("notifier did not finish processing the preceding event");
    }
    tx.send(event("shared-late-duplicate")).await.unwrap();
    tx.send(event("barrier-before-expiry")).await.unwrap();
    wait_for(&pool, "barrier-before-expiry").await;
    // Expire only the authoritative gate after the rejected duplicate has been consumed.
    pool.get().await.unwrap().execute("UPDATE notification_health_gate SET admitted_at=NOW()-INTERVAL '301 seconds' WHERE alert_key='shared-late-duplicate'", &[]).await.unwrap();
    tx.send(event("shared-late-duplicate")).await.unwrap();
    tx.send(event("barrier-after-expiry")).await.unwrap();
    wait_for(&pool, "barrier-after-expiry").await;
    drop(tx);
    worker.await.unwrap();
    let count: i64 = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT COUNT(*) FROM health_alert WHERE alert_key='shared-late-duplicate'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    cleanup(&pool, &schema).await;
    assert_eq!(
        count, 1,
        "a database-rejected duplicate extended the local cooldown"
    );
}

#[tokio::test]
#[ignore = "requires disposable HEALTH_TEST_DATABASE_URL"]
async fn health_policy_database_publication_presence_and_outage_lifecycle() {
    use crate::runtime_config::{
        PersistError, RuntimeSettings, RuntimeSettingsBootstrap, SCANNER_HEALTH_NAMESPACE, persist,
    };
    let (pool, schema) = isolated_pool().await;
    let settings = RuntimeSettings::load(
        &pool,
        RuntimeSettingsBootstrap {
            requests: Default::default(),
            monitor: Default::default(),
            automatic_target: Default::default(),
            dns_follow_up: Default::default(),
            dns_resolvers: Default::default(),
            analytics_snapshot: Default::default(),
            report_mail: Default::default(),
        },
    )
    .await
    .unwrap();
    let other_instance = RuntimeSettings::load(
        &pool,
        RuntimeSettingsBootstrap {
            requests: Default::default(),
            monitor: Default::default(),
            automatic_target: Default::default(),
            dns_follow_up: Default::default(),
            dns_resolvers: Default::default(),
            analytics_snapshot: Default::default(),
            report_mail: Default::default(),
        },
    )
    .await
    .unwrap();
    let id = Uuid::new_v4();
    let client = pool.get().await.unwrap();
    client.execute("INSERT INTO scanner_info(scanner_id,create_user,is_enable,runtime_state,last_seen_at,outage_monitored_at,supports_ipv4,ipv4_ready,latency_rtt_us,latency_network_rtt_us,latency_server_processing_us,latency_measured_at) VALUES($1,1,true,'idle',NOW()-INTERVAL '100 seconds',NOW()-INTERVAL '1 hour',true,true,250000,200000,50000,NOW()-INTERVAL '40 seconds');", &[&id.to_string()]).await.unwrap();
    // Administrative exclusion takes precedence over the heartbeat age.
    client.batch_execute("INSERT INTO scanner_info(scanner_id,create_user,is_enable,deleted_at,last_seen_at,outage_monitored_at) VALUES
        (gen_random_uuid()::text,1,false,NULL,NOW()-INTERVAL '1 hour',NOW()-INTERVAL '1 hour'),
        (gen_random_uuid()::text,1,true,NOW(),NOW()-INTERVAL '1 hour',NOW()-INTERVAL '1 hour');").await.unwrap();
    assert!(
        !crate::admin::get_scanner(&pool, id)
            .await
            .unwrap()
            .unwrap()
            .is_online
    );
    let mut policy = settings.scanner_health.get().await.value;
    policy.offline_after_seconds = 120;
    policy.alert_after_seconds = 180;
    policy.latency_warning_ms = 250;
    policy.latency_stale_after_seconds = 30;
    let (first, second) = tokio::join!(
        persist(
            &pool,
            SCANNER_HEALTH_NAMESPACE,
            1,
            &policy,
            "adjust threshold",
            1
        ),
        persist(
            &pool,
            SCANNER_HEALTH_NAMESPACE,
            1,
            &policy,
            "racing administrator",
            1
        )
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert!(
        matches!(first, Err(PersistError::Conflict))
            || matches!(second, Err(PersistError::Conflict))
    );
    other_instance.refresh_health(&pool).await.unwrap();
    assert_eq!(other_instance.scanner_health.get().await.revision, 2);
    let restarted = RuntimeSettings::load(
        &pool,
        RuntimeSettingsBootstrap {
            requests: Default::default(),
            monitor: Default::default(),
            automatic_target: Default::default(),
            dns_follow_up: Default::default(),
            dns_resolvers: Default::default(),
            analytics_snapshot: Default::default(),
            report_mail: Default::default(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        restarted
            .scanner_health
            .get()
            .await
            .value
            .offline_after_seconds,
        120
    );
    let scanner = crate::admin::get_scanner(&pool, id).await.unwrap().unwrap();
    assert!(scanner.is_online);
    let latency = scanner.latency.unwrap();
    assert!(latency.stale);
    assert_eq!(latency.severity, "normal");
    let profile = "legacy";
    let ready: bool = client
        .query_one(
            &crate::target_generated::ready_scanner_exists_query("ipv4"),
            &[&profile],
        )
        .await
        .unwrap()
        .get(0);
    assert!(ready);
    client
        .execute(
            "UPDATE scanner_info SET runtime_state = 'stopping' WHERE scanner_id = $1",
            &[&id.to_string()],
        )
        .await
        .unwrap();
    let ready: bool = client
        .query_one(
            &crate::target_generated::ready_scanner_exists_query("ipv4"),
            &[&profile],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!ready);
    assert!(
        !crate::admin::get_scanner(&pool, id)
            .await
            .unwrap()
            .unwrap()
            .is_online
    );
    client
        .execute("UPDATE scanner_info SET runtime_state = 'idle', is_enable = false WHERE scanner_id = $1", &[&id.to_string()])
        .await
        .unwrap();
    assert!(
        !crate::admin::get_scanner(&pool, id)
            .await
            .unwrap()
            .unwrap()
            .is_online
    );
    client
        .execute(
            "UPDATE scanner_info SET is_enable = true WHERE scanner_id = $1",
            &[&id.to_string()],
        )
        .await
        .unwrap();
    let recipients = vec!["admin@example.invalid".to_owned()];
    client
        .batch_execute("UPDATE system_maintenance_state SET enabled=true, phase='active';")
        .await
        .unwrap();
    let maintenance = crate::system_maintenance::SystemMaintenanceState::from_database(&pool)
        .await
        .unwrap();
    crate::scanner_outage::run_once(&pool, "", &maintenance, &policy)
        .await
        .unwrap();
    client
        .batch_execute(
            "UPDATE system_maintenance_state SET enabled=false, phase='off', updated_at=NOW();",
        )
        .await
        .unwrap();
    let grace = crate::system_maintenance::SystemMaintenanceState::from_database(&pool)
        .await
        .unwrap();
    crate::scanner_outage::run_once(&pool, "", &grace, &policy)
        .await
        .unwrap();
    crate::scanner_outage::detect_outages(&pool, &recipients, policy.alert_after_seconds)
        .await
        .unwrap();
    let count: i64 = client
        .query_one("SELECT count(*) FROM scanner_outage", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    client.execute("UPDATE scanner_info SET last_seen_at = NOW()-INTERVAL '400 seconds' WHERE scanner_id=$1", &[&id.to_string()]).await.unwrap();
    crate::scanner_outage::detect_outages(&pool, &recipients, policy.alert_after_seconds)
        .await
        .unwrap();
    crate::scanner_outage::detect_outages(&pool, &recipients, 90)
        .await
        .unwrap();
    let count: i64 = client
        .query_one("SELECT count(*) FROM scanner_outage", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        count, 1,
        "threshold changes must not duplicate an open outage"
    );
    let mut connection = pool.get().await.unwrap();
    let transaction = connection.transaction().await.unwrap();
    transaction
        .execute(
            "UPDATE scanner_info SET last_seen_at=NOW() WHERE scanner_id=$1",
            &[&id.to_string()],
        )
        .await
        .unwrap();
    crate::scanner_outage::record_recovery(&transaction, &id.to_string())
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    let cancelled: i64 = client
        .query_one(
            "SELECT count(*) FROM scanner_outage_delivery WHERE status='cancelled'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        cancelled, 1,
        "an undelivered outage is cancelled by recovery"
    );
    let history: i64 = client
        .query_one(
            "SELECT count(*) FROM runtime_configuration_revision WHERE namespace='scanner_health'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(history, 2);
    // Restart reads committed values, and rolling back creates a new revision.
    let old = crate::scanner_health::ScannerHealthConfig::default();
    assert_eq!(
        persist(
            &pool,
            SCANNER_HEALTH_NAMESPACE,
            2,
            &old,
            "restore revision 1",
            1
        )
        .await
        .unwrap(),
        3
    );
    other_instance.refresh_health(&pool).await.unwrap();
    assert_eq!(
        other_instance
            .scanner_health
            .get()
            .await
            .value
            .offline_after_seconds,
        90
    );
    other_instance.scanner_health.replace(policy, 2).await;
    assert_eq!(other_instance.scanner_health.get().await.revision, 3);
    drop(client);
    drop(connection);
    cleanup(&pool, &schema).await;
}

#[actix_web::test]
#[ignore = "requires disposable HEALTH_TEST_DATABASE_URL"]
async fn health_policy_catalogue_authorization_and_restorable_sql_ids() {
    use super::rules::{MonitorService, OperationRule};
    use crate::runtime_config::{
        MONITOR_NAMESPACE, RuntimeSettings, RuntimeSettingsBootstrap, persist,
    };
    use actix_web::{App, HttpMessage, http::StatusCode, test, web};
    let (pool, schema) = isolated_pool().await;
    let settings = RuntimeSettings::load(
        &pool,
        RuntimeSettingsBootstrap {
            requests: Default::default(),
            monitor: Default::default(),
            automatic_target: Default::default(),
            dns_follow_up: Default::default(),
            dns_resolvers: Default::default(),
            analytics_snapshot: Default::default(),
            report_mail: Default::default(),
        },
    )
    .await
    .unwrap();
    let mut monitor = settings.monitor.get().await.value;
    monitor.operation_rules.push(OperationRule {
        service: MonitorService::Postgresql,
        operation: "12345".into(),
        rule: monitor.default_rule(MonitorService::Postgresql),
    });
    persist(&pool, MONITOR_NAMESPACE, 1, &monitor, "SQL override", 1)
        .await
        .unwrap();
    monitor.operation_rules.clear();
    persist(
        &pool,
        MONITOR_NAMESPACE,
        2,
        &monitor,
        "restore inheritance",
        1,
    )
    .await
    .unwrap();
    settings.refresh_health(&pool).await.unwrap();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(settings))
            .service(crate::handlers::health::monitor_operations)
            .service(crate::handlers::utils::runtime_config_history),
    )
    .await;
    let user = |role| crate::admin::UserBaseI {
        id: 1,
        username: "test".into(),
        role,
        email: None,
        limit_login: false,
        enable_2fa: false,
    };
    for path in [
        "/api/config/monitor/operations",
        "/api/config/runtime/monitor/history",
    ] {
        let request = test::TestRequest::get().uri(path).to_request();
        request.extensions_mut().insert(user(2));
        assert_eq!(
            test::call_service(&app, request).await.status(),
            StatusCode::FORBIDDEN
        );
    }
    let request = test::TestRequest::get()
        .uri("/api/config/monitor/operations")
        .to_request();
    request.extensions_mut().insert(user(1));
    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(body["data"]["postgresql_available"], false);
    assert!(
        body["data"]["operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["service"] == "postgresql" && item["operation"] == "12345")
    );
    let request = test::TestRequest::get()
        .uri("/api/config/runtime/monitor/history")
        .to_request();
    request.extensions_mut().insert(user(1));
    let body: serde_json::Value =
        test::read_body_json(test::call_service(&app, request).await).await;
    assert_eq!(body["data"].as_array().unwrap().len(), 3);
    assert_eq!(body["data"][0]["revision"], 3);
    // Validate the catalogue sampling SQL without needing a shared extension.
    pool.get().await.unwrap().batch_execute("CREATE TABLE pg_stat_statements(queryid BIGINT, calls BIGINT, total_exec_time DOUBLE PRECISION, max_exec_time DOUBLE PRECISION, query TEXT);
        INSERT INTO pg_stat_statements VALUES(77889,1,100,100,'SELECT confidential_sql');").await.unwrap();
    let request = test::TestRequest::get()
        .uri("/api/config/monitor/operations")
        .to_request();
    request.extensions_mut().insert(user(1));
    let body: serde_json::Value =
        test::read_body_json(test::call_service(&app, request).await).await;
    assert_eq!(body["data"]["postgresql_available"], true);
    assert!(
        body["data"]["operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["operation"] == "77889")
    );
    assert!(!body.to_string().contains("confidential_sql"));
    cleanup(&pool, &schema).await;
}
