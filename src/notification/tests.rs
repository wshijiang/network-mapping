use super::*;
use actix_web::{App, HttpMessage, dev::Service, test as http_test, web};
use deadpool_postgres::Manager;
use tokio_postgres::NoTls;

const URL: &str =
    "https://open.feishu.cn/open-apis/bot/v2/hook/00000000-0000-4000-8000-000000000001";
fn key() -> String {
    openssl::base64::encode_block(&[7_u8; 32])
}
fn user(role: i32) -> UserBaseI {
    UserBaseI {
        id: 1,
        username: "admin".into(),
        role,
        email: None,
        limit_login: false,
        enable_2fa: false,
    }
}
fn input() -> ChannelInput {
    ChannelInput {
        name: "运维".into(),
        enabled: true,
        event_types: EVENT_TYPES.iter().map(|v| v.to_string()).collect(),
        minimum_severity: "warning".into(),
        webhook_url: URL.into(),
        signing_secret: "test-signing-secret".into(),
        clear_signing_secret: false,
        expected_revision: None,
    }
}
#[test]
fn credentials_are_authenticated_encrypted_and_short_ciphertext_is_rejected() {
    let bytes = encrypt(URL, &key()).unwrap();
    assert_ne!(bytes, URL.as_bytes());
    assert_eq!(decrypt(&bytes, &key()).unwrap(), URL);
    assert!(decrypt(&[0_u8; 27], &key()).is_err());
    assert!(decrypt(&bytes, &openssl::base64::encode_block(&[8_u8; 32])).is_err());
    assert!(encrypt(URL, "invalid").is_err());
}
#[test]
fn channels_validate_subscriptions_and_versioned_edits() {
    let mut v = input();
    assert!(v.validate(true).is_ok());
    v.event_types.push("login.success".into());
    assert!(v.validate(true).is_err());
    v = input();
    v.event_types.push("health.alert".into());
    assert!(v.validate(true).is_err());
    v = input();
    v.webhook_url.clear();
    assert!(v.validate(true).is_err());
    v.expected_revision = Some(1);
    assert!(v.validate(false).is_ok());
    v.clear_signing_secret = true;
    assert!(v.validate(false).is_err());
}

#[actix_web::test]
async fn management_endpoints_reject_non_administrators_without_accessing_database() {
    let pool = Pool::builder(Manager::new(
        "host=127.0.0.1 user=unused".parse().unwrap(),
        NoTls,
    ))
    .build()
    .unwrap();
    let app = http_test::init_service(
        App::new()
            .app_data(web::Data::new(pool))
            .wrap_fn(|req, srv| {
                req.extensions_mut().insert(user(2));
                srv.call(req)
            })
            .configure(configure),
    )
    .await;
    for req in [
        http_test::TestRequest::get().uri("/api/notifications/channels"),
        http_test::TestRequest::get().uri("/api/notifications/deliveries"),
        http_test::TestRequest::post()
            .uri("/api/notifications/channels/00000000-0000-4000-8000-000000000001/test"),
        http_test::TestRequest::post()
            .uri("/api/notifications/deliveries/00000000-0000-4000-8000-000000000001/retry"),
    ] {
        assert_eq!(
            http_test::call_service(&app, req.to_request())
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }
}

#[actix_web::test]
async fn notification_mutations_use_the_existing_csrf_middleware() {
    let pool = Pool::builder(Manager::new(
        "host=127.0.0.1 user=unused".parse().unwrap(),
        NoTls,
    ))
    .build()
    .unwrap();
    let app = http_test::init_service(
        App::new()
            .app_data(web::Data::new(pool))
            .wrap(crate::middlewares::csrfmiddleware::CsrfMiddleware)
            .configure(configure),
    )
    .await;
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::post()
            .uri("/api/notifications/channels/00000000-0000-4000-8000-000000000001/test")
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

async fn database() -> (Pool, String) {
    let mut config: tokio_postgres::Config = std::env::var("NOTIFICATION_TEST_DATABASE_URL")
        .expect("NOTIFICATION_TEST_DATABASE_URL must point to a disposable database")
        .parse()
        .unwrap();
    let schema = format!("notification_{}", Uuid::new_v4().simple());
    config.options(format!("-c search_path={schema} -c timezone=UTC"));
    let pool = Pool::builder(Manager::new(config, NoTls))
        .max_size(8)
        .build()
        .unwrap();
    let c = pool.get().await.unwrap();
    c.batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    c.batch_execute(include_str!("../../source/database/init.sql"))
        .await
        .unwrap();
    // Upgrade path is deliberately run twice to verify idempotence alongside fresh installation.
    for _ in 0..2 {
        c.batch_execute(include_str!(
            "../../source/database/migrate_notifications.sql"
        ))
        .await
        .unwrap();
    }
    c.batch_execute("INSERT INTO users(id,username,password,role) VALUES(1,'admin','test',1)")
        .await
        .unwrap();
    drop(c);
    (pool, schema)
}
async fn cleanup(pool: Pool, schema: String) {
    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn channel_lifecycle_preserves_secrets_cancels_old_work_and_audits_changes() {
    let (pool, schema) = database().await;
    let context = AuditContext::cli("notification-test");
    let first = save(&pool, &key(), None, input(), &user(1), &context)
        .await
        .unwrap();
    let serialized = serde_json::to_string(&first).unwrap();
    assert!(!serialized.contains("test-signing-secret"));
    assert!(!serialized.contains("open.feishu.cn"));
    let delivery = test_send(&pool, first.id, &user(1), &context)
        .await
        .unwrap();
    assert!(
        test_send(&pool, first.id, &user(1), &context)
            .await
            .is_err()
    );
    let mut edit = input();
    edit.webhook_url.clear();
    edit.signing_secret.clear();
    edit.expected_revision = Some(1);
    let updated = save(&pool, &key(), Some(first.id), edit, &user(1), &context)
        .await
        .unwrap();
    assert!(updated.signing_secret_configured);
    assert_eq!(updated.revision, 2);
    let c = pool.get().await.unwrap();
    let row = c
        .query_one(
            "SELECT status FROM notification_delivery WHERE id=$1",
            &[&delivery],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "cancelled");
    let bytes: Vec<u8> = c
        .query_one(
            "SELECT webhook_ciphertext FROM notification_channel WHERE id=$1",
            &[&first.id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(decrypt(&bytes, &key()).unwrap(), URL);
    drop(c);
    let mut stale = input();
    stale.expected_revision = Some(1);
    assert_eq!(
        save(&pool, &key(), Some(first.id), stale, &user(1), &context)
            .await
            .err()
            .unwrap()
            .status,
        StatusCode::CONFLICT
    );
    let mut clear = input();
    clear.webhook_url.clear();
    clear.signing_secret.clear();
    clear.clear_signing_secret = true;
    clear.expected_revision = Some(2);
    let cleared = save(&pool, &key(), Some(first.id), clear, &user(1), &context)
        .await
        .unwrap();
    assert!(!cleared.signing_secret_configured);
    remove(&pool, first.id, 3, &user(1), &context)
        .await
        .unwrap();
    assert!(list(&pool).await.unwrap().is_empty());
    let audit_count: i64 = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT COUNT(*) FROM audit_event WHERE action LIKE 'notification.%'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(audit_count, 5);
    cleanup(pool, schema).await;
}

#[tokio::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn claims_are_exclusive_and_stale_completions_cannot_overwrite_results() {
    let (pool, schema) = database().await;
    let context = AuditContext::cli("notification-test");
    let channel = save(&pool, &key(), None, input(), &user(1), &context)
        .await
        .unwrap();
    let id = test_send(&pool, channel.id, &user(1), &context)
        .await
        .unwrap();
    let (a, b) = tokio::join!(worker::claim(&pool), worker::claim(&pool));
    let mut claims = vec![a.unwrap(), b.unwrap()]
        .into_iter()
        .filter_map(|outcome| match outcome {
            worker::ClaimOutcome::Ready(claimed) => Some(claimed),
            worker::ClaimOutcome::Empty => None,
            worker::ClaimOutcome::Processed => panic!("no cleanup was expected"),
        })
        .collect::<Vec<_>>();
    assert_eq!(claims.len(), 1);
    let claim = claims.pop().unwrap();
    assert_eq!(claim.id, id);
    worker::complete(
        &pool,
        id,
        Uuid::new_v4(),
        1,
        feishu::classify(200, Some(&json!({"code":0}))),
    )
    .await
    .unwrap();
    let status: String = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT status FROM notification_delivery WHERE id=$1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(status, "sending");
    worker::complete(
        &pool,
        id,
        claim.token,
        claim.attempts,
        feishu::classify(200, Some(&json!({"code":19021}))),
    )
    .await
    .unwrap();
    retry(&pool, id, &user(1), &context).await.unwrap();
    let c = pool.get().await.unwrap();
    c.execute(
        "UPDATE notification_channel SET next_send_at=NOW() WHERE id=$1",
        &[&channel.id],
    )
    .await
    .unwrap();
    c.execute("UPDATE notification_delivery SET status='sending',claim_token=$2,lease_until=NOW()-INTERVAL '1 second' WHERE id=$1",&[&id,&Uuid::new_v4()]).await.unwrap();
    drop(c);
    let worker::ClaimOutcome::Ready(reclaimed) = worker::claim(&pool).await.unwrap() else {
        panic!("expired lease was not reclaimed");
    };
    worker::complete(
        &pool,
        id,
        reclaimed.token,
        reclaimed.attempts,
        feishu::classify(429, None),
    )
    .await
    .unwrap();
    let c = pool.get().await.unwrap();
    let row = c
        .query_one(
            "SELECT status,available_at>NOW() AS delayed FROM notification_delivery WHERE id=$1",
            &[&id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>("status"), "pending");
    assert!(row.get::<_, bool>("delayed"));
    drop(c);
    cleanup(pool, schema).await;
}

#[tokio::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn health_fanout_is_independent_of_smtp_and_cooldown_is_shared() {
    let (pool, schema) = database().await;
    let context = AuditContext::cli("notification-test");
    save(&pool, &key(), None, input(), &user(1), &context)
        .await
        .unwrap();
    let mut critical_only = input();
    critical_only.minimum_severity = "critical".into();
    save(&pool, &key(), None, critical_only, &user(1), &context)
        .await
        .unwrap();
    let event = crate::monitor::HealthEvent {
        alert_type: "slow_request",
        severity: "warning",
        key: "test:shared".into(),
        summary: "sensitive SQL must not reach the bot".into(),
        details: vec![],
        applied_rule: None,
    };
    let (a, b) = tokio::join!(
        crate::monitor::record_health_alert(&pool, &event, 300),
        crate::monitor::record_health_alert(&pool, &event, 300)
    );
    assert_eq!(usize::from(a.unwrap()) + usize::from(b.unwrap()), 1);
    let mut escalated = event.clone();
    escalated.severity = "critical";
    assert!(
        crate::monitor::record_health_alert(&pool, &escalated, 300)
            .await
            .unwrap()
    );
    let c = pool.get().await.unwrap();
    let rows = c
        .query("SELECT title,body FROM notification_event", &[])
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|r| !r.get::<_, String>("body").contains("sensitive"))
    );
    let count: i64 = c
        .query_one("SELECT COUNT(*) FROM notification_delivery", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 3);
    drop(c);
    cleanup(pool, schema).await;
}

#[tokio::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn scanner_recovery_only_notifies_destinations_that_received_the_outage() {
    let (pool, schema) = database().await;
    let context = AuditContext::cli("notification-test");
    save(&pool, &key(), None, input(), &user(1), &context)
        .await
        .unwrap();
    let scanner = Uuid::new_v4().to_string();
    let c = pool.get().await.unwrap();
    c.execute("INSERT INTO scanner_info(scanner_id,create_user,is_enable,outage_monitored_at,last_seen_at) VALUES($1,1,TRUE,NOW()-INTERVAL '1 hour',NOW()-INTERVAL '10 minutes')",&[&scanner]).await.unwrap();
    drop(c);
    crate::scanner_outage::detect_outages(&pool, &[], 90)
        .await
        .unwrap();
    crate::scanner_outage::detect_outages(&pool, &[], 90)
        .await
        .unwrap();
    let c = pool.get().await.unwrap();
    let count: i64 = c
        .query_one("SELECT COUNT(*) FROM notification_delivery", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    c.batch_execute("UPDATE notification_delivery SET status='sent'")
        .await
        .unwrap();
    drop(c);
    // A second channel added during the outage must not receive an unsolicited recovery.
    save(&pool, &key(), None, input(), &user(1), &context)
        .await
        .unwrap();
    let mut c = pool.get().await.unwrap();
    let tx = c.transaction().await.unwrap();
    crate::scanner_outage::record_recovery(&tx, &scanner)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    drop(c);
    worker::reconcile_recoveries(&pool).await.unwrap();
    worker::reconcile_recoveries(&pool).await.unwrap();
    let c = pool.get().await.unwrap();
    let count:i64=c.query_one("SELECT COUNT(*) FROM notification_delivery d JOIN notification_event e ON e.id=d.event_id WHERE e.event_type='scanner.recovered'",&[]).await.unwrap().get(0);
    assert_eq!(count, 1);
    drop(c);
    // Retention must not cause an old recovered incident to be fanned out again.
    pool.get()
        .await
        .unwrap()
        .batch_execute("DELETE FROM notification_event")
        .await
        .unwrap();
    worker::reconcile_recoveries(&pool).await.unwrap();
    let remaining: i64 = pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT COUNT(*) FROM notification_event", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(remaining, 0);
    cleanup(pool, schema).await;
}

#[actix_web::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn web_channel_api_round_trip_redacts_secrets_and_lists_queued_tests() {
    let (pool, schema) = database().await;
    let config = crate::config::ServerConfig {
        host: "127.0.0.1".into(),
        port: 0,
        encrypt_key: key(),
        max_body_size: 16384,
    };
    let app = http_test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(config))
            .wrap_fn(|req, srv| {
                req.extensions_mut().insert(user(1));
                srv.call(req)
            })
            .configure(configure),
    )
    .await;
    let response=http_test::call_service(&app,http_test::TestRequest::post().uri("/api/notifications/channels")
        .set_json(json!({"name":"Web 运维群","enabled":true,"event_types":["health.alert"],"minimum_severity":"warning","webhook_url":URL,"signing_secret":"must-not-echo"})).to_request()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value = http_test::read_body_json(response).await;
    let serialized = value.to_string();
    assert!(!serialized.contains("must-not-echo"));
    assert!(!serialized.contains("open.feishu.cn"));
    let id = value["data"]["id"].as_str().unwrap();
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::post()
            .uri(&format!("/api/notifications/channels/{id}/test"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let value: Value = http_test::call_and_read_body_json(
        &app,
        http_test::TestRequest::get()
            .uri("/api/notifications/deliveries?status=pending")
            .to_request(),
    )
    .await;
    assert_eq!(value["data"]["items"].as_array().unwrap().len(), 1);
    assert_eq!(value["data"]["items"][0]["event_type"], "notification.test");
    let bad=http_test::call_service(&app,http_test::TestRequest::post().uri("/api/notifications/channels")
        .set_json(json!({"name":"Web 运维群","enabled":true,"event_types":["health.alert"],"minimum_severity":"warning","webhook_url":"https://private.example/secret-path"})).to_request()).await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    let value: Value = http_test::read_body_json(bad).await;
    assert!(!value.to_string().contains("private.example"));
    let malformed=http_test::call_service(&app,http_test::TestRequest::post().uri("/api/notifications/channels")
        .set_json(json!({"name":"x","enabled":true,"event_types":["health.alert"],"minimum_severity":"warning","webhook_url":URL,"secret-must-not-echo":true})).to_request()).await;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    let value: Value = http_test::read_body_json(malformed).await;
    assert_eq!(value["message"], "通知请求格式无效或超过 16 KiB");
    cleanup(pool, schema).await;
}

#[tokio::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn unsent_outages_and_administrative_deactivation_do_not_create_recovery_noise() {
    let (pool, schema) = database().await;
    let context = AuditContext::cli("notification-test");
    save(&pool, &key(), None, input(), &user(1), &context)
        .await
        .unwrap();
    let scanner = Uuid::new_v4().to_string();
    let c = pool.get().await.unwrap();
    c.execute("INSERT INTO scanner_info(scanner_id,create_user,is_enable,outage_monitored_at,last_seen_at) VALUES($1,1,TRUE,NOW()-INTERVAL '1 hour',NOW()-INTERVAL '10 minutes')",&[&scanner]).await.unwrap();
    drop(c);
    crate::scanner_outage::detect_outages(&pool, &[], 90)
        .await
        .unwrap();
    let mut c = pool.get().await.unwrap();
    let tx = c.transaction().await.unwrap();
    crate::scanner_outage::record_recovery(&tx, &scanner)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    drop(c);
    worker::reconcile_recoveries(&pool).await.unwrap();
    let c = pool.get().await.unwrap();
    let rows = c
        .query("SELECT status FROM notification_delivery", &[])
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, String>(0), "cancelled");
    c.execute(
        "UPDATE scanner_info SET last_seen_at=NOW()-INTERVAL '10 minutes' WHERE scanner_id=$1",
        &[&scanner],
    )
    .await
    .unwrap();
    drop(c);
    crate::scanner_outage::detect_outages(&pool, &[], 90)
        .await
        .unwrap();
    let worker::ClaimOutcome::Ready(claimed) = worker::claim(&pool).await.unwrap() else {
        panic!("offline delivery was not claimed");
    };
    let mut c = pool.get().await.unwrap();
    let tx = c.transaction().await.unwrap();
    crate::scanner_outage::close_without_recovery(&tx, &scanner)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    drop(c);
    worker::complete(
        &pool,
        claimed.id,
        claimed.token,
        claimed.attempts,
        feishu::classify(200, Some(&json!({"code":0}))),
    )
    .await
    .unwrap();
    worker::reconcile_recoveries(&pool).await.unwrap();
    let c = pool.get().await.unwrap();
    let sent: i64 = c
        .query_one(
            "SELECT COUNT(*) FROM notification_delivery WHERE status='sent'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(sent, 0);
    let recovery:i64=c.query_one("SELECT COUNT(*) FROM notification_delivery d JOIN notification_event e ON e.id=d.event_id WHERE e.event_type='scanner.recovered'",&[]).await.unwrap().get(0);
    assert_eq!(recovery, 0);
    drop(c);
    cleanup(pool, schema).await;
}

#[tokio::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn worker_drains_expired_backlog_before_waiting_for_the_next_poll() {
    use std::time::Duration;
    let (pool, schema) = database().await;
    let context = AuditContext::cli("notification-test");
    let channel = save(&pool, &key(), None, input(), &user(1), &context)
        .await
        .unwrap();
    let c = pool.get().await.unwrap();
    // Fresh work terminates at decryption, so this test never contacts a real bot.
    c.execute(
        "UPDATE notification_channel SET webhook_ciphertext=''::BYTEA WHERE id=$1",
        &[&channel.id],
    )
    .await
    .unwrap();
    for n in 0..10 {
        let event = Uuid::now_v7();
        c.execute("INSERT INTO notification_event(id,dedup_key,event_type,severity,title,body,occurred_at) VALUES($1,$2,'notification.test','warning','old','old',NOW()-INTERVAL '25 hours')", &[&event,&format!("old:{n}")]).await.unwrap();
        c.execute("INSERT INTO notification_delivery(id,event_id,channel_id,destination_revision,available_at) VALUES($1,$2,$3,1,NOW()-INTERVAL '25 hours')", &[&Uuid::now_v7(),&event,&channel.id]).await.unwrap();
    }
    drop(c);
    let fresh = test_send(&pool, channel.id, &user(1), &context)
        .await
        .unwrap();
    let maintenance = web::Data::new(
        crate::system_maintenance::SystemMaintenanceState::from_database(&pool)
            .await
            .unwrap(),
    );
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let worker = tokio::spawn(super::run(pool.clone(), key(), maintenance, stopping));
    let drained = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let status: String = pool
                .get()
                .await
                .unwrap()
                .query_one(
                    "SELECT status FROM notification_delivery WHERE id=$1",
                    &[&fresh],
                )
                .await
                .unwrap()
                .get(0);
            if status == "failed" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    stop.send_replace(true);
    worker.await.unwrap();
    let cancelled: i64 = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT COUNT(*) FROM notification_delivery WHERE status='cancelled'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    cleanup(pool, schema).await;
    assert!(
        drained.is_ok(),
        "expired backlog stopped the batch before fresh work was reached"
    );
    assert_eq!(cancelled, 10);
}

#[tokio::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn worker_pauses_new_claims_when_maintenance_starts_during_a_batch() {
    use crate::system_maintenance::{MaintenancePhase, SystemMaintenanceState};
    use std::time::Duration;
    let (pool, schema) = database().await;
    let context = AuditContext::cli("notification-test");
    let first_channel = save(&pool, &key(), None, input(), &user(1), &context)
        .await
        .unwrap();
    let second_channel = save(&pool, &key(), None, input(), &user(1), &context)
        .await
        .unwrap();
    let first = test_send(&pool, first_channel.id, &user(1), &context)
        .await
        .unwrap();
    let second = test_send(&pool, second_channel.id, &user(1), &context)
        .await
        .unwrap();
    let c = pool.get().await.unwrap();
    // Use decryption failures instead of sending to a real bot. Both channels are ready.
    c.execute("UPDATE notification_channel SET webhook_ciphertext=''::BYTEA,next_send_at=NOW()-INTERVAL '1 hour'", &[]).await.unwrap();
    c.execute(
        "UPDATE notification_channel SET next_send_at=next_send_at-INTERVAL '1 second' WHERE id=$1",
        &[&first_channel.id],
    )
    .await
    .unwrap();
    // Pause completion of the first claim so maintenance begins inside a running batch.
    let barrier = (Uuid::new_v4().as_u128() & 0x7fff_ffff) as i32;
    c.query_one("SELECT pg_advisory_lock(728106,$1)", &[&barrier])
        .await
        .unwrap();
    c.batch_execute(&format!(
        "CREATE FUNCTION pause_first_completion() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN PERFORM pg_advisory_xact_lock(728106,{barrier}); RETURN NEW; END $$;
         CREATE TRIGGER pause_first_completion BEFORE UPDATE ON notification_delivery
         FOR EACH ROW WHEN (NEW.id='{first}' AND NEW.status='failed')
         EXECUTE FUNCTION pause_first_completion();"
    ))
    .await
    .unwrap();
    let maintenance = web::Data::new(SystemMaintenanceState::from_database(&pool).await.unwrap());
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let worker = tokio::spawn(super::run(
        pool.clone(),
        key(),
        maintenance.clone(),
        stopping,
    ));
    let blocked = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = c.query_one("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND classid=728106 AND objid=$1::INT::OID AND NOT granted)", &[&barrier]).await.unwrap().get(0);
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let mut snapshot = maintenance.snapshot().await;
    snapshot.enabled = true;
    snapshot.phase = MaintenancePhase::Draining;
    snapshot.revision += 1;
    maintenance.replace(snapshot).await;
    c.query_one("SELECT pg_advisory_unlock(728106,$1)", &[&barrier])
        .await
        .unwrap();
    async fn wait_for_failure(c: &tokio_postgres::Client, id: Uuid) {
        loop {
            let status: String = c
                .query_one(
                    "SELECT status FROM notification_delivery WHERE id=$1",
                    &[&id],
                )
                .await
                .unwrap()
                .get(0);
            if status == "failed" {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    let in_flight_finished =
        tokio::time::timeout(Duration::from_secs(4), wait_for_failure(&c, first)).await;
    let claimed_during_maintenance =
        tokio::time::timeout(Duration::from_millis(1200), wait_for_failure(&c, second))
            .await
            .is_ok();
    let paused = c
        .query_one(
            "SELECT status,attempts FROM notification_delivery WHERE id=$1",
            &[&second],
        )
        .await
        .unwrap();
    let mut snapshot = maintenance.snapshot().await;
    snapshot.enabled = false;
    snapshot.phase = MaintenancePhase::Off;
    snapshot.revision += 1;
    maintenance.replace(snapshot).await;
    let resumed = tokio::time::timeout(Duration::from_secs(4), wait_for_failure(&c, second)).await;
    stop.send_replace(true);
    worker.await.unwrap();
    drop(c);
    cleanup(pool, schema).await;
    assert!(blocked.is_ok(), "first delivery never reached the barrier");
    assert!(
        in_flight_finished.is_ok(),
        "in-flight delivery did not finish"
    );
    assert!(
        !claimed_during_maintenance,
        "worker claimed new work during maintenance"
    );
    assert_eq!(paused.get::<_, String>("status"), "pending");
    assert_eq!(paused.get::<_, i32>("attempts"), 0);
    assert!(
        resumed.is_ok(),
        "queued delivery did not resume after maintenance"
    );
}
