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
        provider: "feishu".into(),
        name: "运维".into(),
        enabled: true,
        event_types: EVENT_TYPES.iter().map(|v| v.to_string()).collect(),
        minimum_severity: "warning".into(),
        webhook_url: URL.into(),
        signing_secret: "test-signing-secret".into(),
        clear_signing_secret: false,
        bot_token: String::new(),
        smtp_password: String::new(),
        settings: ChannelSettings::default(),
        expected_revision: None,
    }
}
fn provider_input(provider: &str) -> ChannelInput {
    let mut v = input();
    v.provider = provider.into();
    if provider != "feishu" {
        v.webhook_url.clear();
        v.signing_secret.clear();
    }
    if provider == "telegram" {
        v.bot_token = "123456:abcdefghijklmnopqrstuvwxyz_ABC-123".into();
        v.settings.chat_id = "-1001234567890".into();
    }
    if provider == "email" {
        v.smtp_password = "smtp-password-secret".into();
        v.settings.smtp_host = "smtp.example.com".into();
        v.settings.smtp_port = 465;
        v.settings.smtp_sender = "notifier@example.com".into();
    }
    v
}

#[test]
fn all_providers_accept_the_same_event_catalog_and_validate_their_own_credentials() {
    for provider in ["email", "feishu", "telegram"] {
        let v = provider_input(provider);
        assert!(v.validate(true).is_ok(), "{provider}");
        assert_eq!(v.event_types.len(), EVENT_TYPES.len());
    }
    let mut v = provider_input("telegram");
    v.bot_token.push_str("/another-method");
    assert!(v.validate(true).is_err());
    v = provider_input("email");
    v.settings.smtp_port = 0;
    assert!(v.validate(true).is_err());
    v = provider_input("email");
    v.settings.recipients = vec!["bad-address".into()];
    assert!(v.validate(true).is_err());
    v = provider_input("unsupported");
    assert!(v.validate(true).is_err());
}

#[tokio::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn peer_channels_fan_out_independently_and_secrets_are_preserved_without_echo() {
    let (pool, schema) = database().await;
    let audit = AuditContext::cli("notification-test");
    let mut channels = Vec::new();
    for provider in ["email", "feishu", "telegram"] {
        channels.push(
            save(
                &pool,
                &key(),
                None,
                provider_input(provider),
                &user(1),
                &audit,
            )
            .await
            .unwrap(),
        );
    }
    let listed = serde_json::to_string(&list(&pool).await.unwrap()).unwrap();
    for secret in [
        "smtp-password-secret",
        "abcdefghijklmnopqrstuvwxyz_ABC-123",
        "test-signing-secret",
        URL,
    ] {
        assert!(!listed.contains(secret));
    }
    assert_eq!(
        crate::admin::get_mail_sender_key_from_database(&pool, &key())
            .await
            .unwrap()
            .as_deref(),
        Some("smtp-password-secret")
    );
    let mut c = pool.get().await.unwrap();
    let tx = c.transaction().await.unwrap();
    for (i, topic) in [
        "health.alert",
        "user.login",
        "report.weekly",
        "report.monthly",
    ]
    .iter()
    .enumerate()
    {
        enqueue(
            &tx,
            topic,
            "warning",
            &format!("peer:{i}"),
            "test",
            "test",
            None,
        )
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    let counts = c.query("SELECT c.provider,COUNT(*) FROM notification_delivery d JOIN notification_channel c ON c.id=d.channel_id GROUP BY c.provider", &[]).await.unwrap();
    assert_eq!(counts.len(), 3);
    assert!(counts.iter().all(|r| r.get::<_, i64>(1) == 4));
    drop(c);
    let mut edit = provider_input("email");
    edit.smtp_password.clear();
    edit.enabled = false;
    edit.expected_revision = Some(1);
    let updated = save(&pool, &key(), Some(channels[0].id), edit, &user(1), &audit)
        .await
        .unwrap();
    assert!(updated.credential_configured);
    let mut edit = provider_input("telegram");
    edit.bot_token.clear();
    edit.event_types = vec!["report.weekly".into()];
    edit.expected_revision = Some(1);
    save(&pool, &key(), Some(channels[2].id), edit, &user(1), &audit)
        .await
        .unwrap();
    let mut c = pool.get().await.unwrap();
    let tx = c.transaction().await.unwrap();
    enqueue(
        &tx,
        "health.alert",
        "warning",
        "peer:after-edit",
        "test",
        "test",
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let rows = c.query("SELECT c.provider FROM notification_delivery d JOIN notification_channel c ON c.id=d.channel_id JOIN notification_event e ON e.id=d.event_id WHERE e.dedup_key='peer:after-edit'", &[]).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, String>(0), "feishu");
    let secret: Vec<u8> = c
        .query_one(
            "SELECT secret_ciphertext FROM notification_channel WHERE id=$1",
            &[&channels[2].id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        decrypt(&secret, &key()).unwrap(),
        provider_input("telegram").bot_token
    );
    drop(c);
    let mut changed = provider_input("email");
    changed.expected_revision = Some(2);
    assert!(
        save(
            &pool,
            &key(),
            Some(channels[2].id),
            changed,
            &user(1),
            &audit
        )
        .await
        .is_err()
    );
    cleanup(pool, schema).await;
}

#[tokio::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn legacy_smtp_import_is_idempotent_and_does_not_use_the_test_recipient() {
    let (pool, schema) = database().await;
    let c = pool.get().await.unwrap();
    let secret = openssl::base64::encode_block(&encrypt("old-smtp-secret", &key()).unwrap());
    c.execute("INSERT INTO setting(item_type,key,value) VALUES('smtp','host','smtp.example.com'),('smtp','sender','sender@example.com'),('smtp','port','465'),('smtp','recipient','test-only@example.com'),('smtp','sender_key',$1),('notification','health_alert_enabled','false'),('notification','login_notify_enabled','false'),('notification','report_weekly','false'),('notification','report_monthly','true'),('notification','scanner_offline_enabled','true') ON CONFLICT(item_type,key) DO UPDATE SET value=EXCLUDED.value", &[&secret]).await.unwrap();
    c.execute(
        "DELETE FROM notification_upgrade WHERE name='unified_channels_v1'",
        &[],
    )
    .await
    .unwrap();
    c.batch_execute(include_str!(
        "../../source/database/migrate_notifications.sql"
    ))
    .await
    .unwrap();
    let row = c
        .query_one(
            "SELECT id,secret_ciphertext FROM notification_channel WHERE provider='email'",
            &[],
        )
        .await
        .unwrap();
    let id: Uuid = row.get("id");
    assert_eq!(
        decrypt(&row.get::<_, Vec<u8>>("secret_ciphertext"), &key()).unwrap(),
        "old-smtp-secret"
    );
    c.execute(
        "UPDATE notification_channel SET enabled=FALSE,name='edited' WHERE id=$1",
        &[&id],
    )
    .await
    .unwrap();
    c.batch_execute(include_str!(
        "../../source/database/migrate_notifications.sql"
    ))
    .await
    .unwrap();
    drop(c);
    let channels = list(&pool).await.unwrap();
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0].id, id);
    assert_eq!(channels[0].name, "edited");
    assert!(!channels[0].enabled);
    assert!(channels[0].settings.recipients.is_empty());
    assert!(channels[0].event_types.contains(&"report.monthly".into()));
    assert!(channels[0].event_types.contains(&"scanner.offline".into()));
    assert!(!channels[0].event_types.contains(&"health.alert".into()));
    cleanup(pool, schema).await;
}

async fn legacy_smtp(pool: &Pool) {
    let c = pool.get().await.unwrap();
    let secret = openssl::base64::encode_block(&encrypt("old-smtp-secret", &key()).unwrap());
    c.execute("INSERT INTO setting(item_type,key,value) VALUES('smtp','host','smtp.example.com'),('smtp','sender','sender@example.com'),('smtp','port','465'),('smtp','sender_key',$1),('notification','scanner_offline_enabled','true') ON CONFLICT(item_type,key) DO UPDATE SET value=EXCLUDED.value", &[&secret]).await.unwrap();
    c.batch_execute("DELETE FROM notification_upgrade; UPDATE users SET email='first@example.com' WHERE id=1; INSERT INTO users(id,username,password,role,email) VALUES(2,'second','test',1,'second@example.com'),(3,'third','test',1,'third@example.com')").await.unwrap();
}

async fn legacy_outage(pool: &Pool) -> (String, i64) {
    let c = pool.get().await.unwrap();
    let scanner = Uuid::new_v4().to_string();
    c.execute("INSERT INTO scanner_info(scanner_id,create_user,is_enable,last_seen_at) VALUES($1,1,TRUE,NOW()-INTERVAL '3 days')", &[&scanner]).await.unwrap();
    let outage = c.query_one("INSERT INTO scanner_outage(scanner_id,last_seen_at,detected_at) VALUES($1,NOW()-INTERVAL '3 days',NOW()-INTERVAL '2 days') RETURNING id", &[&scanner]).await.unwrap().get(0);
    (scanner, outage)
}

#[tokio::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn legacy_queued_mail_is_migrated_per_recipient_without_replaying_successes() {
    let (pool, schema) = database().await;
    legacy_smtp(&pool).await;
    let (_, outage) = legacy_outage(&pool).await;
    let c = pool.get().await.unwrap();
    c.execute("INSERT INTO scanner_outage_delivery(outage_id,kind,recipient,status,attempts,claimed_until) VALUES($1,'offline','first@example.com','sent',1,NULL),($1,'offline','second@example.com','pending',2,NULL),($1,'offline','third@example.com','sending',1,NOW()+INTERVAL '5 minutes')", &[&outage]).await.unwrap();
    let report = Uuid::new_v4();
    c.execute("INSERT INTO report_run(id,period_type,period_start,period_end,source,status,task_snapshot) VALUES($1,'weekly',NOW()-INTERVAL '10 days',NOW()-INTERVAL '3 days','automatic','ready','{}')", &[&report]).await.unwrap();
    for (user, status, automatic) in [
        (1_i32, "sent", true),
        (2, "pending", true),
        (3, "sending", true),
        (1, "pending", false),
    ] {
        let recipient = [
            "first@example.com",
            "second@example.com",
            "third@example.com",
        ][(user - 1) as usize];
        let seq = if automatic { 1_i32 } else { 2 };
        c.execute("INSERT INTO report_delivery(id,report_id,recipient_user_id,recipient,dispatch_seq,automatic,status,attempts,lease_until) VALUES($1,$2,$3,$4,$5,$6,$7,1,CASE WHEN $7='sending' THEN NOW()+INTERVAL '5 minutes' END)", &[&Uuid::new_v4(),&report,&user,&recipient,&seq,&automatic,&status]).await.unwrap();
    }
    c.batch_execute(include_str!(
        "../../source/database/migrate_notifications.sql"
    ))
    .await
    .unwrap();
    let pending = c.query("SELECT e.event_type,e.context,d.attempts,d.available_at FROM notification_delivery d JOIN notification_event e ON e.id=d.event_id WHERE d.status='pending' ORDER BY e.event_type,e.context->>'legacy_recipient'", &[]).await.unwrap();
    let queued_scanner = pending
        .iter()
        .filter(|r| r.get::<_, String>("event_type") == "scanner.offline")
        .count();
    let queued_report = pending
        .iter()
        .filter(|r| r.get::<_, String>("event_type") == "report.weekly")
        .count();
    let recipients: Vec<String> = pending
        .iter()
        .filter_map(|r| {
            r.get::<_, Value>("context")["legacy_recipient"]
                .as_str()
                .map(str::to_owned)
        })
        .collect();
    let manual: String = c
        .query_one(
            "SELECT status FROM report_delivery WHERE NOT automatic",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let sent: i64 = c
        .query_one(
            "SELECT COUNT(*) FROM scanner_outage_delivery WHERE status='sent'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let count: i64 = c
        .query_one("SELECT COUNT(*) FROM notification_delivery", &[])
        .await
        .unwrap()
        .get(0);
    c.batch_execute(include_str!(
        "../../source/database/migrate_notifications.sql"
    ))
    .await
    .unwrap();
    let repeated: i64 = c
        .query_one("SELECT COUNT(*) FROM notification_delivery", &[])
        .await
        .unwrap()
        .get(0);
    drop(c);
    for row in &pending {
        let third = row.get::<_, Value>("context")["legacy_recipient"] == "third@example.com";
        assert_eq!(
            row.get::<_, DateTime<Utc>>("available_at") > Utc::now() + chrono::Duration::minutes(4),
            third,
            "an unexpired old lease must be respected"
        );
    }
    let worker::ClaimOutcome::Ready(claimed) = worker::claim(&pool).await.unwrap() else {
        panic!("an old durable job must receive a fresh delivery window at upgrade");
    };
    assert_eq!(
        worker::email_recipients(&pool, &claimed).await.unwrap(),
        vec!["second@example.com"]
    );
    let mut c = pool.get().await.unwrap();
    c.batch_execute("UPDATE users SET disabled_at=NOW() WHERE id=2")
        .await
        .unwrap();
    assert!(
        worker::email_recipients(&pool, &claimed)
            .await
            .unwrap()
            .is_empty()
    );
    let tx = c.transaction().await.unwrap();
    enqueue_report(&tx, report).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        c.query_one("SELECT COUNT(*) FROM notification_delivery", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        count,
        "reopening the archived report must not broadcast it again"
    );
    // Re-running even the transfer itself must not resurrect completed replacement jobs.
    c.batch_execute("UPDATE notification_delivery SET status='failed' WHERE status IN ('pending','sending'); DELETE FROM notification_upgrade WHERE name='unified_mail_queue_v2'").await.unwrap();
    c.batch_execute(include_str!(
        "../../source/database/migrate_notifications.sql"
    ))
    .await
    .unwrap();
    assert_eq!(
        c.query_one(
            "SELECT COUNT(*) FROM notification_delivery WHERE status IN ('pending','sending')",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    drop(c);
    cleanup(pool, schema).await;
    assert_eq!(
        queued_scanner, 2,
        "pending and leased Scanner mail must survive upgrade"
    );
    assert_eq!(
        queued_report, 2,
        "ready reports must retain their unsent recipients"
    );
    assert!(recipients.iter().all(|r| r != "first@example.com"));
    assert_eq!(manual, "pending");
    assert_eq!(sent, 1);
    assert_eq!(count, repeated);
}

#[tokio::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn legacy_successful_offline_receipt_allows_recovery_only_on_imported_destination() {
    let (pool, schema) = database().await;
    legacy_smtp(&pool).await;
    let (scanner, outage) = legacy_outage(&pool).await;
    let (other_scanner, other_outage) = legacy_outage(&pool).await;
    let c = pool.get().await.unwrap();
    // Also cover databases where SMTP was already imported by the first unified release.
    c.batch_execute(include_str!(
        "../../source/database/migrate_notifications.sql"
    ))
    .await
    .unwrap();
    c.execute(
        "DELETE FROM notification_upgrade WHERE name='unified_mail_queue_v2'",
        &[],
    )
    .await
    .unwrap();
    for id in [outage, other_outage] {
        c.execute("INSERT INTO scanner_outage_delivery(outage_id,kind,recipient,status,sent_at) VALUES($1,'offline','first@example.com','sent',NOW()-INTERVAL '1 day')", &[&id]).await.unwrap();
    }
    c.batch_execute(include_str!(
        "../../source/database/migrate_notifications.sql"
    ))
    .await
    .unwrap();
    drop(c);
    let audit = AuditContext::cli("notification-test");
    let imported = list(&pool).await.unwrap().remove(0);
    let mut edit = provider_input("email");
    edit.name = "重命名邮件".into();
    edit.settings = imported.settings.clone();
    edit.smtp_password.clear();
    edit.expected_revision = Some(imported.revision);
    save(&pool, &key(), Some(imported.id), edit, &user(1), &audit)
        .await
        .unwrap();
    save(
        &pool,
        &key(),
        None,
        provider_input("email"),
        &user(1),
        &audit,
    )
    .await
    .unwrap();
    save(&pool, &key(), None, input(), &user(1), &audit)
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
    let rows = pool.get().await.unwrap().query("SELECT c.legacy_email FROM notification_delivery d JOIN notification_event e ON e.id=d.event_id JOIN notification_channel c ON c.id=d.channel_id WHERE e.event_type='scanner.recovered'", &[]).await.unwrap();
    let worker::ClaimOutcome::Ready(claimed) = worker::claim(&pool).await.unwrap() else {
        panic!("legacy receipt must remain valid after a rename");
    };
    assert_eq!(
        worker::email_recipients(&pool, &claimed).await.unwrap(),
        vec!["first@example.com"],
        "new administrators did not receive the old offline mail"
    );
    let mut edit = provider_input("email");
    edit.settings = imported.settings;
    edit.settings.smtp_host = "replacement.example.com".into();
    edit.smtp_password.clear();
    edit.expected_revision = Some(2);
    save(&pool, &key(), Some(imported.id), edit, &user(1), &audit)
        .await
        .unwrap();
    let mut c = pool.get().await.unwrap();
    let tx = c.transaction().await.unwrap();
    crate::scanner_outage::record_recovery(&tx, &other_scanner)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    drop(c);
    worker::reconcile_recoveries(&pool).await.unwrap();
    let count: i64 = pool.get().await.unwrap().query_one("SELECT COUNT(*) FROM notification_delivery d JOIN notification_event e ON e.id=d.event_id WHERE e.outage_id=$1 AND e.event_type='scanner.recovered'", &[&other_outage]).await.unwrap().get(0);
    cleanup(pool, schema).await;
    assert_eq!(rows.len(), 1, "legacy success must authorize one recovery");
    assert!(rows[0].get::<_, bool>("legacy_email"));
    assert_eq!(
        count, 0,
        "a changed SMTP destination must not inherit the old receipt"
    );
}

#[tokio::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn legacy_prepared_recovery_keeps_only_the_unsent_recipient() {
    let (pool, schema) = database().await;
    legacy_smtp(&pool).await;
    let (_, outage) = legacy_outage(&pool).await;
    let bot = save(
        &pool,
        &key(),
        None,
        input(),
        &user(1),
        &AuditContext::cli("notification-test"),
    )
    .await
    .unwrap();
    let mut c = pool.get().await.unwrap();
    let tx = c.transaction().await.unwrap();
    enqueue(
        &tx,
        "scanner.offline",
        "warning",
        &format!("outage:{outage}:offline"),
        "offline",
        "offline",
        Some(outage),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    c.execute(
        "UPDATE notification_delivery SET status='sent' WHERE channel_id=$1",
        &[&bot.id],
    )
    .await
    .unwrap();
    c.execute(
        "UPDATE notification_channel SET next_send_at=NOW()+INTERVAL '1 hour' WHERE id=$1",
        &[&bot.id],
    )
    .await
    .unwrap();
    drop(c);
    let c = pool.get().await.unwrap();
    c.execute("UPDATE scanner_outage SET recovered_at=NOW(),recovery_requested=TRUE,recovery_delivery_prepared=TRUE WHERE id=$1", &[&outage]).await.unwrap();
    c.execute("INSERT INTO scanner_outage_delivery(outage_id,kind,recipient,status) VALUES($1,'offline','first@example.com','sent'),($1,'offline','second@example.com','sent'),($1,'recovered','first@example.com','sent'),($1,'recovered','second@example.com','pending')", &[&outage]).await.unwrap();
    c.batch_execute(include_str!(
        "../../source/database/migrate_notifications.sql"
    ))
    .await
    .unwrap();
    drop(c);
    worker::reconcile_recoveries(&pool).await.unwrap();
    let count: i64 = pool.get().await.unwrap().query_one("SELECT COUNT(*) FROM notification_delivery d JOIN notification_event e ON e.id=d.event_id WHERE e.event_type='scanner.recovered'", &[]).await.unwrap().get(0);
    let worker::ClaimOutcome::Ready(claimed) = worker::claim(&pool).await.unwrap() else {
        panic!("legacy prepared recovery must be claimable");
    };
    assert_eq!(
        worker::email_recipients(&pool, &claimed).await.unwrap(),
        vec!["second@example.com"]
    );
    cleanup(pool, schema).await;
    assert_eq!(
        count, 2,
        "preserve the unsent email and the independently eligible bot recovery"
    );
}

#[tokio::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn legacy_queue_is_not_cancelled_without_an_imported_email_channel() {
    let (pool, schema) = database().await;
    let (_, outage) = legacy_outage(&pool).await;
    let c = pool.get().await.unwrap();
    c.batch_execute("DELETE FROM notification_upgrade")
        .await
        .unwrap();
    c.execute("INSERT INTO scanner_outage_delivery(outage_id,kind,recipient) VALUES($1,'offline','first@example.com')", &[&outage]).await.unwrap();
    c.batch_execute(include_str!(
        "../../source/database/migrate_notifications.sql"
    ))
    .await
    .unwrap();
    let status: String = c
        .query_one("SELECT status FROM scanner_outage_delivery", &[])
        .await
        .unwrap()
        .get(0);
    c.execute("UPDATE users SET email='first@example.com' WHERE id=1", &[])
        .await
        .unwrap();
    drop(c);
    let email = save(
        &pool,
        &key(),
        None,
        provider_input("email"),
        &user(1),
        &AuditContext::cli("notification-test"),
    )
    .await
    .unwrap();
    let recipients = match worker::claim(&pool).await.unwrap() {
        worker::ClaimOutcome::Ready(claimed) => {
            Some(worker::email_recipients(&pool, &claimed).await.unwrap())
        }
        _ => None,
    };
    let migrated: i64 = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT COUNT(*) FROM notification_delivery WHERE channel_id=$1",
            &[&email.id],
        )
        .await
        .unwrap()
        .get(0);
    cleanup(pool, schema).await;
    assert_eq!(
        status, "pending",
        "source work must not be discarded without a durable replacement"
    );
    assert_eq!(
        recipients,
        Some(vec!["first@example.com".into()]),
        "Web email configuration must make the retained queue deliverable without a restart"
    );
    assert_eq!(migrated, 1);
}

#[tokio::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn deferred_legacy_recovery_is_transferred_without_reopening_bot_delivery() {
    let (pool, schema) = database().await;
    let (scanner, outage) = legacy_outage(&pool).await;
    let audit = AuditContext::cli("notification-test");
    let bot = save(&pool, &key(), None, input(), &user(1), &audit)
        .await
        .unwrap();
    let mut c = pool.get().await.unwrap();
    c.batch_execute("UPDATE users SET email='first@example.com' WHERE id=1; INSERT INTO users(id,username,password,role,email) VALUES(2,'new-admin','test',1,'new-admin@example.com')").await.unwrap();
    c.execute("INSERT INTO scanner_outage_delivery(outage_id,kind,recipient,status,sent_at) VALUES($1,'offline','first@example.com','sent',NOW())", &[&outage]).await.unwrap();
    let tx = c.transaction().await.unwrap();
    enqueue(
        &tx,
        "scanner.offline",
        "warning",
        &format!("outage:{outage}:offline"),
        "offline",
        "offline",
        Some(outage),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    c.execute(
        "UPDATE notification_delivery SET status='sent' WHERE channel_id=$1",
        &[&bot.id],
    )
    .await
    .unwrap();
    let tx = c.transaction().await.unwrap();
    crate::scanner_outage::record_recovery(&tx, &scanner)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    drop(c);
    // Bot recovery is allowed to finish preparation even though SMTP is still absent.
    worker::reconcile_recoveries(&pool).await.unwrap();
    let c = pool.get().await.unwrap();
    c.execute(
        "UPDATE notification_channel SET next_send_at=NOW()+INTERVAL '1 hour' WHERE id=$1",
        &[&bot.id],
    )
    .await
    .unwrap();
    c.execute("INSERT INTO notification_upgrade(name) VALUES('unified_mail_queue_v2') ON CONFLICT DO NOTHING", &[]).await.unwrap();
    drop(c);
    let mut email = provider_input("email");
    email.enabled = false;
    let channel = save(&pool, &key(), None, email, &user(1), &audit)
        .await
        .unwrap();
    let c = pool.get().await.unwrap();
    assert_eq!(
        c.query_one(
            "SELECT COUNT(*) FROM notification_delivery WHERE channel_id=$1",
            &[&channel.id]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0,
        "disabled email must not take ownership"
    );
    assert!(
        !c.query_one(
            "SELECT EXISTS(SELECT 1 FROM notification_upgrade WHERE name='unified_mail_queue_v2')",
            &[]
        )
        .await
        .unwrap()
        .get::<_, bool>(0),
        "repair the previous false completion marker"
    );
    drop(c);
    let mut email = provider_input("email");
    email.settings.smtp_host = "ready.example.com".into();
    email.smtp_password.clear();
    email.expected_revision = Some(channel.revision);
    // Recovery reconciliation owns a non-key incident lock while it fans out to channels.
    // Handoff must remain compatible with that lock instead of waiting in the opposite order.
    let mut c = pool.get().await.unwrap();
    let tx = c.transaction().await.unwrap();
    tx.query_one(
        "SELECT id FROM scanner_outage WHERE id=$1 FOR NO KEY UPDATE",
        &[&outage],
    )
    .await
    .unwrap();
    let activation = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        save(&pool, &key(), Some(channel.id), email, &user(1), &audit),
    )
    .await;
    tx.commit().await.unwrap();
    drop(c);
    activation
        .expect("handoff must not block recovery reconciliation")
        .unwrap();
    worker::reconcile_recoveries(&pool).await.unwrap();
    let worker::ClaimOutcome::Ready(claimed) = worker::claim(&pool).await.unwrap() else {
        panic!("recovery during deferred setup must become deliverable");
    };
    assert_eq!(
        worker::email_recipients(&pool, &claimed).await.unwrap(),
        vec!["first@example.com"],
        "only the historical offline recipient receives email recovery"
    );
    let c = pool.get().await.unwrap();
    let revision: i64 = c
        .query_one(
            "SELECT destination_revision FROM notification_delivery WHERE id=$1",
            &[&claimed.id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        revision, 2,
        "handoff uses the destination configured at activation"
    );
    drop(c);
    // A second channel must not take the same history or trigger another bot recovery.
    let second = save(
        &pool,
        &key(),
        None,
        provider_input("email"),
        &user(1),
        &audit,
    )
    .await
    .unwrap();
    let c = pool.get().await.unwrap();
    let rows = c.query("SELECT d.channel_id,COUNT(*) AS n FROM notification_delivery d JOIN notification_event e ON e.id=d.event_id WHERE e.outage_id=$1 AND e.event_type='scanner.recovered' GROUP BY d.channel_id", &[&outage]).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|r| r.get::<_, i64>("n") == 1 && r.get::<_, Uuid>("channel_id") != second.id)
    );
    assert!(
        c.query_one(
            "SELECT EXISTS(SELECT 1 FROM notification_upgrade WHERE name='unified_mail_queue_v2')",
            &[]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    drop(c);
    cleanup(pool, schema).await;
}

#[tokio::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn login_producer_uses_channel_subscriptions_and_keeps_private_context_out_of_bot_messages() {
    let (pool, schema) = database().await;
    let audit = AuditContext::cli("notification-test");
    for provider in ["email", "feishu", "telegram"] {
        save(
            &pool,
            &key(),
            None,
            provider_input(provider),
            &user(1),
            &audit,
        )
        .await
        .unwrap();
    }
    let c = pool.get().await.unwrap();
    c.batch_execute("UPDATE users SET email='admin@example.com' WHERE id=1; INSERT INTO setting(item_type,key,value) VALUES('notification','login_notify_enabled','false') ON CONFLICT(item_type,key) DO UPDATE SET value='false'").await.unwrap();
    crate::mail_template::send_login_notification(&pool, &key(), 1, "admin", "192.0.2.99")
        .await
        .unwrap();
    let row = c
        .query_one(
            "SELECT body,context FROM notification_event WHERE event_type='user.login'",
            &[],
        )
        .await
        .unwrap();
    assert!(!row.get::<_, String>("body").contains("192.0.2.99"));
    let context: Value = row.get("context");
    assert_eq!(context["user_id"], 1);
    let rendered = email::render(&pool, &context).await.unwrap().unwrap();
    assert!(rendered.text_body.contains("192.0.2.99"));
    assert_eq!(
        c.query_one("SELECT COUNT(*) FROM notification_delivery", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        3
    );
    drop(c);
    cleanup(pool, schema).await;
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
            "../../source/database/migrate_notification_templates.sql"
        ))
        .await
        .unwrap();
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
    let outage: i64 = c
        .query_one(
            "SELECT id FROM scanner_outage WHERE scanner_id=$1",
            &[&scanner],
        )
        .await
        .unwrap()
        .get(0);
    let rendered = email::render(
        &pool,
        &json!({"outage_id":outage,"event_type":"scanner.offline"}),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(rendered.text_body.contains(&scanner));
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

#[actix_web::test]
async fn template_preview_is_admin_only_and_checks_provider_format_without_database() {
    use crate::notification::template_render::default_source;
    let app = http_test::init_service(
        App::new()
            .wrap_fn(|req, srv| {
                req.extensions_mut().insert(user(2));
                srv.call(req)
            })
            .configure(configure),
    )
    .await;
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::post()
            .uri("/api/notifications/templates/feishu/health.alert/preview")
            .set_json(default_source())
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let app = http_test::init_service(
        App::new()
            .wrap_fn(|req, srv| {
                req.extensions_mut().insert(user(1));
                srv.call(req)
            })
            .configure(configure),
    )
    .await;
    for (provider, expected) in [
        ("feishu", StatusCode::OK),
        ("telegram", StatusCode::OK),
        ("unknown", StatusCode::BAD_REQUEST),
    ] {
        let response = http_test::call_service(
            &app,
            http_test::TestRequest::post()
                .uri(&format!(
                    "/api/notifications/templates/{provider}/health.alert/preview"
                ))
                .set_json(default_source())
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn notification_templates_isolate_providers_events_and_publish_restore_with_conflicts() {
    use super::template_render::{Source, default_source};
    let (pool, schema) = database().await;
    // Publishing must release its connection before fetching the response, even in a small pool.
    pool.resize(1);
    let audit = AuditContext::cli("notification-template-test");
    let change = |revision, source: Option<Source>, version: Option<i32>| {
        serde_json::from_value::<templates::Change>(
            json!({"expectedRevision":revision,"source":source,"version":version}),
        )
        .unwrap()
    };
    let source = Source {
        format: "html".into(),
        body_template: "<b>自定义 {{ body }}</b>".into(),
        ..default_source()
    };
    let draft = templates::change(
        &pool,
        "feishu",
        "health.alert",
        "draft",
        change(0, Some(source.clone()), None),
        &user(1),
        &audit,
    )
    .await
    .unwrap();
    assert_eq!(draft["revision"], 1);
    assert_eq!(draft["status"], "draft");
    assert_eq!(
        templates::published(&pool, "feishu", "health.alert")
            .await
            .unwrap()
            .format,
        "text"
    );
    assert!(
        templates::change(
            &pool,
            "feishu",
            "health.alert",
            "publish",
            change(0, None, None),
            &user(1),
            &audit
        )
        .await
        .is_err()
    );
    let published = templates::change(
        &pool,
        "feishu",
        "health.alert",
        "publish",
        change(1, None, None),
        &user(1),
        &audit,
    )
    .await
    .unwrap();
    assert_eq!(published["activeVersion"], 1);
    assert_eq!(
        templates::published(&pool, "feishu", "health.alert")
            .await
            .unwrap()
            .format,
        "html"
    );
    assert_eq!(
        templates::published(&pool, "telegram", "health.alert")
            .await
            .unwrap()
            .format,
        "text"
    );
    assert_eq!(
        templates::published(&pool, "feishu", "user.login")
            .await
            .unwrap()
            .format,
        "text"
    );
    templates::change(
        &pool,
        "feishu",
        "health.alert",
        "draft",
        change(2, Some(default_source()), None),
        &user(1),
        &audit,
    )
    .await
    .unwrap();
    // Saving a replacement never changes the active publication.
    assert_eq!(
        templates::published(&pool, "feishu", "health.alert")
            .await
            .unwrap()
            .format,
        "html"
    );
    templates::change(
        &pool,
        "feishu",
        "health.alert",
        "publish",
        change(3, None, None),
        &user(1),
        &audit,
    )
    .await
    .unwrap();
    let restored = templates::change(
        &pool,
        "feishu",
        "health.alert",
        "restore",
        change(4, None, Some(1)),
        &user(1),
        &audit,
    )
    .await
    .unwrap();
    assert_eq!(restored["status"], "draft");
    assert_eq!(restored["source"]["format"], "html");
    assert_eq!(restored["activeVersion"], 2);
    assert_eq!(
        templates::published(&pool, "feishu", "health.alert")
            .await
            .unwrap()
            .format,
        "text"
    );
    assert_eq!(restored["versions"].as_array().unwrap().len(), 3);
    let c = pool.get().await.unwrap();
    let audits: i64 = c
        .query_one(
            "SELECT COUNT(*) FROM audit_event WHERE resource_type='notification_template'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(audits, 5);
    drop(c);
    cleanup(pool, schema).await;
}
