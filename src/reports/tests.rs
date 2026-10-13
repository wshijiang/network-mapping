use crate::mail_template::{self, MailTemplateSource};

#[test]
fn report_templates_render_complete_content_in_html_and_text() {
    for key in [
        mail_template::REPORT_WEEKLY_TEMPLATE_KEY,
        mail_template::REPORT_MONTHLY_TEMPLATE_KEY,
    ] {
        let source = MailTemplateSource {
            subject_template: "{{ system_name }} {{ report_label }}：{{ period_label }}".into(),
            html_template: include_str!("../../templates/mail/report.html").into(),
            text_template: include_str!("../../templates/mail/report.txt").into(),
        };
        let rendered = mail_template::render_template(
            key,
            &source,
            &mail_template::sample_context(key).expect("sample"),
        )
        .expect("render");
        assert!(rendered.html_body.contains("100"));
        assert!(rendered.text_body.contains("83.3%"));
        assert!(rendered.text_body.contains("/reports/"));
        assert!(rendered.html_body.contains("不是资产存量"));
        for label in [
            "与上一周期比较",
            "每日完成任务",
            "端口观测 Top 10",
            "服务观测 Top 10",
            "扫描器执行表现",
            "统计口径与完整性",
        ] {
            assert!(rendered.html_body.contains(label), "HTML missing {label}");
            assert!(rendered.text_body.contains(label), "text missing {label}");
        }
        assert!(
            rendered
                .html_body
                .contains("/mail/report-images/sample/trend.png")
        );
    }
}

use super::{
    period::{Period, PeriodType},
    storage, worker,
};
use crate::{
    config::{AnalyticsSnapshotConfig, AnalyticsSnapshotMode},
    runtime_config::RuntimeConfig,
};
use chrono::Utc;
use deadpool_postgres::{Manager, Pool};
use serde_json::{Value, json};
use tokio_postgres::NoTls;
use uuid::Uuid;

#[actix_web::test]
#[ignore = "requires disposable REPORT_TEST_DATABASE_URL"]
async fn remote_mail_images_preserve_archives_and_enforce_capabilities() {
    use super::{assets, mail_config::ReportMailConfig};
    use actix_web::{
        App, HttpMessage,
        dev::Service,
        http::{StatusCode, header},
        test, web,
    };
    let (pool, schema) = isolated_pool().await;
    let period = Period::last_closed(PeriodType::Weekly, Utc::now()).expect("period");
    execution(
        &pool,
        period.start.timestamp_millis() + 7_200_000,
        "succeeded",
        true,
        "192.0.2.1",
    )
    .await;
    let settings = ReportMailConfig {
        public_base_url: "https://reports.example.invalid/nm".into(),
        remote_images_enabled: true,
        ..Default::default()
    };
    let client = pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO runtime_configuration(namespace,document) VALUES('report_mail',$1)",
            &[&serde_json::to_value(&settings).unwrap()],
        )
        .await
        .unwrap();
    drop(client);
    let id = storage::create(&pool, &period, Some(1), "manual", None)
        .await
        .unwrap();
    assert!(worker::process_one(&pool, &config()).await.unwrap());
    let archived = report(&pool, id).await;
    assert_eq!(archived.get::<_, String>("status"), "ready");
    let rendered: Value = archived.get("rendered_mail");
    let html = rendered["htmlBody"].as_str().unwrap();
    let image_url = html
        .split("src=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    assert!(image_url.starts_with("https://reports.example.invalid/nm/mail/report-images/"));
    assert!(html.contains(&format!("https://reports.example.invalid/nm/reports/{id}")));
    assert!(!html.contains("scanner-a"), "scanner identifier is aliased");
    assert!(
        !html.contains("192.0.2.1"),
        "mail does not expose individual IPs"
    );
    let uri = image_url
        .strip_prefix("https://reports.example.invalid/nm")
        .unwrap();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .wrap(crate::middlewares::smiddleware::AuthMiddleware)
            .wrap(crate::middlewares::csrfmiddleware::CsrfMiddleware)
            .service(crate::handlers::report_mail_assets::sample)
            .service(crate::handlers::report_mail_assets::trend),
    )
    .await;
    let response = test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "image/png"
    );
    let etag = response
        .headers()
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let png = test::read_body(response).await;
    assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
    let response = test::call_service(
        &app,
        test::TestRequest::default()
            .method(actix_web::http::Method::HEAD)
            .uri(uri)
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(test::read_body(response).await.is_empty());
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(uri)
            .insert_header((header::IF_NONE_MATCH, etag.clone()))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    for uri in [
        "/mail/report-images/invalid/trend.png".to_owned(),
        format!("/mail/report-images/{}/trend.png", "a".repeat(64)),
    ] {
        assert_eq!(
            test::call_service(&app, test::TestRequest::get().uri(&uri).to_request())
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!("/api/reports/{id}"))
                .to_request()
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        test::call_service(&app, test::TestRequest::post().uri(uri).to_request())
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let client = pool.get().await.unwrap();
    client
        .batch_execute("DELETE FROM scan_task;")
        .await
        .unwrap();
    assert_eq!(
        report(&pool, id).await.get::<_, Value>("rendered_mail"),
        rendered
    );
    let response = test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
    assert_eq!(test::read_body(response).await, png);
    client
        .execute(
            "UPDATE report_mail_asset SET expires_at=NOW()-INTERVAL '1 day' WHERE report_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(uri)
            .insert_header((header::IF_NONE_MATCH, etag.clone()))
            .to_request(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "expiry must precede ETag validation"
    );
    storage::enqueue_delivery(&client, id, &[1], false, true)
        .await
        .unwrap();
    assert_eq!(
        test::call_service(&app, test::TestRequest::get().uri(uri).to_request())
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        report(&pool, id).await.get::<_, Value>("rendered_mail"),
        rendered
    );
    if let Ok(directory) = std::env::var("REPORT_MAIL_QA_DIR") {
        std::fs::write(format!("{directory}/trend.png"), &png).unwrap();
        std::fs::write(
            format!("{directory}/report.html"),
            html.replace(image_url, "trend.png"),
        )
        .unwrap();
        std::fs::write(
            format!("{directory}/report.txt"),
            rendered["textBody"].as_str().unwrap(),
        )
        .unwrap();
    }
    drop(client);
    let admin_app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .wrap_fn(|req, srv| {
                req.extensions_mut().insert(crate::admin::UserBaseI {
                    id: 1,
                    username: "admin".into(),
                    role: 1,
                    email: Some("admin@example.invalid".into()),
                    limit_login: false,
                    enable_2fa: false,
                });
                srv.call(req)
            })
            .service(crate::handlers::report_mail_assets::revoke),
    )
    .await;
    let response = test::call_service(
        &admin_app,
        test::TestRequest::post()
            .uri(&format!("/api/reports/{id}/mail-image/revoke"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(uri)
            .insert_header((header::IF_NONE_MATCH, etag))
            .to_request(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "revocation must precede ETag validation"
    );
    let client = pool.get().await.unwrap();
    assert!(assets::renew(&client, id).await.is_err());
    let pending: i64 = client
        .query_one(
            "SELECT COUNT(*)::BIGINT FROM report_delivery WHERE report_id=$1 AND status='pending'",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(pending, 0);
    // Keep a previously published summary template usable after enabling images.
    // It must neither be overwritten nor gain an unused image access capability.
    client.batch_execute("INSERT INTO mail_template_version(template_key,version,status,subject_template,html_template,text_template) VALUES('report_weekly',1,'published','Legacy {{ report_label }}','<p>{{ tasks.created }} {{ detail_path }}</p>','{{ scan_output.unique_ips }} {{ detail_path }}'); UPDATE mail_template SET active_version=1 WHERE template_key='report_weekly';").await.unwrap();
    drop(client);
    let legacy_id = storage::create(&pool, &period, Some(1), "revision", Some(id))
        .await
        .unwrap();
    assert!(worker::process_one(&pool, &config()).await.unwrap());
    let legacy = report(&pool, legacy_id).await;
    assert_eq!(legacy.get::<_, i32>("template_version"), 1);
    assert_eq!(
        legacy.get::<_, Value>("rendered_mail")["subject"],
        "Legacy 周报"
    );
    let client = pool.get().await.unwrap();
    assert!(
        client
            .query_opt(
                "SELECT report_id FROM report_mail_asset WHERE report_id=$1",
                &[&legacy_id]
            )
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        storage::enqueue_delivery(&client, legacy_id, &[1], false, true)
            .await
            .unwrap(),
        1
    );
    drop(client);
    cleanup(&pool, schema).await;
}

async fn isolated_pool() -> (Pool, String) {
    let mut config: tokio_postgres::Config = std::env::var("REPORT_TEST_DATABASE_URL")
        .expect("disposable REPORT_TEST_DATABASE_URL")
        .parse()
        .expect("config");
    let schema = format!("report_{}", Uuid::new_v4().simple());
    config.options(format!("-c search_path={schema} -c timezone=UTC"));
    let pool = Pool::builder(Manager::new(config, NoTls))
        .max_size(8)
        .build()
        .expect("pool");
    let client = pool.get().await.expect("client");
    client
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("schema");
    client
        .batch_execute(include_str!("../../source/database/init.sql"))
        .await
        .expect("initialization");
    client
        .batch_execute(include_str!(
            "../../source/database/migrate_report_mail_assets.sql"
        ))
        .await
        .expect("mail assets migration");
    client
        .batch_execute(include_str!(
            "../../source/database/migrate_report_mail_assets.sql"
        ))
        .await
        .expect("mail assets migration rerun");
    // Verify that upgrade migration is independently idempotent.
    client
        .batch_execute(include_str!("../../source/database/migrate_reports.sql"))
        .await
        .expect("migration rerun");
    client.batch_execute("INSERT INTO users(id,username,password,role,email,limit_login) VALUES (1,'admin','test',1,'admin@example.invalid',false), (2,'user','test',2,'user@example.invalid',false);").await.expect("users");
    drop(client);
    (pool, schema)
}
async fn cleanup(pool: &Pool, schema: String) {
    pool.get()
        .await
        .expect("client")
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .expect("cleanup");
}

#[tokio::test]
#[ignore = "requires disposable REPORT_TEST_DATABASE_URL"]
async fn timezone_publication_resets_future_schedules_and_preserves_archives() {
    let (pool, schema) = isolated_pool().await;
    let client = pool.get().await.expect("client");
    client
        .batch_execute(include_str!(
            "../../source/database/migrate_system_time.sql"
        ))
        .await
        .expect("idempotent migration");
    client.batch_execute("UPDATE report_schedule SET enabled = TRUE, enabled_at = NOW() - INTERVAL '1 year', last_period_end = NOW() - INTERVAL '1 week' WHERE period_type = 'weekly';").await.expect("plan");
    drop(client);
    let settings = crate::system_time::GeneralSettings {
        timezone: "America/New_York".into(),
        ..Default::default()
    };
    let revision =
        crate::runtime_config::persist(&pool, "general", 1, &settings, "test calendar", 1)
            .await
            .expect("publish");
    assert_eq!(revision, 2);
    assert!(matches!(
        crate::runtime_config::persist(&pool, "general", 1, &settings, "stale", 1).await,
        Err(crate::runtime_config::PersistError::Conflict)
    ));
    let client = pool.get().await.expect("client");
    let plan = client.query_one("SELECT revision, last_period_end, enabled_at > NOW() - INTERVAL '1 minute' AS recent FROM report_schedule WHERE period_type='weekly';", &[]).await.expect("plan");
    assert_eq!(plan.get::<_, i64>("revision"), 1);
    assert!(
        plan.get::<_, Option<chrono::DateTime<Utc>>>("last_period_end")
            .is_none()
    );
    assert!(plan.get::<_, bool>("recent"));
    drop(client);
    let date = chrono::NaiveDate::from_ymd_opt(2026, 3, 8).expect("date");
    let period =
        Period::containing_in(PeriodType::Weekly, date, "America/New_York", 2).expect("period");
    let id = storage::create(&pool, &period, Some(1), "manual", None)
        .await
        .expect("report");
    assert!(
        worker::process_one(&pool, &config())
            .await
            .expect("generate")
    );
    let row = report(&pool, id).await;
    assert_eq!(row.get::<_, String>("timezone"), "America/New_York");
    let payload: Value = row.get("payload");
    assert_eq!(payload["period"]["timezone"], "America/New_York");
    assert_eq!(payload["trend"].as_array().expect("trend").len(), 7);
    // Equivalent offsets still identify distinct named calendars.
    let tokyo = Period::containing_in(PeriodType::Weekly, date, "Asia/Tokyo", 2).expect("Tokyo");
    let seoul = Period::containing_in(PeriodType::Weekly, date, "Asia/Seoul", 2).expect("Seoul");
    assert_eq!(tokyo.start, seoul.start);
    let a = storage::create(&pool, &tokyo, Some(1), "manual", None)
        .await
        .expect("Tokyo archive");
    let b = storage::create(&pool, &seoul, Some(1), "manual", None)
        .await
        .expect("Seoul archive");
    assert_ne!(a, b);
    // Old schedule snapshots cannot publish after a timezone update.
    let stale =
        Period::containing_in(PeriodType::Weekly, date, "Asia/Shanghai", 1).expect("old rules");
    assert!(
        storage::create(&pool, &stale, None, "automatic", None)
            .await
            .is_err()
    );
    cleanup(&pool, schema).await;
}
fn config() -> RuntimeConfig<AnalyticsSnapshotConfig> {
    RuntimeConfig::new(
        AnalyticsSnapshotConfig {
            mode: AnalyticsSnapshotMode::Shadow,
            interval_minutes: 1,
        },
        0,
    )
}
async fn execution(pool: &Pool, end_ms: i64, task_status: &str, ready: bool, ip: &str) -> i32 {
    let client = pool.get().await.expect("client");
    let task: i32 = client.query_one("INSERT INTO scan_task(user_id,task_id,task_initiator,task_target,task_create_time,task_start_time,task_end_time,task_status) VALUES(1,$1,'admin','{}',$2,$2,$3,$4) RETURNING id;",
        &[&Uuid::new_v4().to_string(), &(end_ms - 3_600_000), &end_ms, &task_status]).await.expect("task").get("id");
    let id: i32 = client.query_one("INSERT INTO scan_task_execution(execution_id,task_id,execution_status,task_start_time,task_end_time,result_observation_count,assigned_scanner_id) \
        VALUES($1,$2,'succeeded',$3,$4,2,'scanner-a') RETURNING id;", &[&Uuid::new_v4().to_string(), &task, &(end_ms - 1000), &end_ms]).await.expect("execution").get("id");
    client
        .execute(
            "INSERT INTO analytics_outbox(execution_id,status) VALUES($1,$2);",
            &[&id, &if ready { "completed" } else { "pending" }],
        )
        .await
        .expect("outbox");
    client.execute("INSERT INTO analytics_discovery_fact(execution_id,day_start,owner_id,scanner_id,task_source,ip_address) VALUES($1, '2020-01-01', 1,'scanner-a','manual',$2::TEXT::INET);", &[&id,&ip]).await.expect("IP");
    // Observations deliberately predate the completion period: completion attribution must retain them.
    client.execute("INSERT INTO analytics_distribution_30m(execution_id,bucket_start,owner_id,scanner_id,task_source,dimension,label,endpoint_count) VALUES \
        ($1,'2020-01-01',1,'scanner-a','manual','port','443',1), ($1,'2020-01-01',1,'scanner-a','manual','service','https',1);", &[&id]).await.expect("distribution");
    id
}
async fn report(pool: &Pool, id: Uuid) -> tokio_postgres::Row {
    pool.get()
        .await
        .expect("client")
        .query_one("SELECT * FROM report_run WHERE id = $1;", &[&id])
        .await
        .expect("report")
}

#[tokio::test]
#[ignore = "requires disposable REPORT_TEST_DATABASE_URL"]
async fn reports_deduplicate_ips_and_preserve_archives_after_scan_deletion() {
    let (pool, schema) = isolated_pool().await;
    let period = Period::last_closed(PeriodType::Weekly, Utc::now()).expect("period");
    let previous = period.previous().expect("previous");
    execution(
        &pool,
        previous.start.timestamp_millis() + 7_200_000,
        "succeeded",
        true,
        "192.0.2.1",
    )
    .await;
    execution(
        &pool,
        period.start.timestamp_millis() + 7_200_000,
        "succeeded",
        true,
        "192.0.2.1",
    )
    .await;
    execution(
        &pool,
        period.start.timestamp_millis() + 10_800_000,
        "partial",
        true,
        "192.0.2.1",
    )
    .await;
    execution(
        &pool,
        period.start.timestamp_millis() + 14_400_000,
        "cancelled",
        true,
        "192.0.2.2",
    )
    .await;
    // Exactly at end is excluded by the half-open interval.
    execution(
        &pool,
        period.end.timestamp_millis(),
        "succeeded",
        true,
        "192.0.2.99",
    )
    .await;
    let id = storage::create(&pool, &period, Some(1), "manual", None)
        .await
        .expect("create");
    assert_eq!(
        storage::create(&pool, &period, Some(1), "manual", None)
            .await
            .expect("idempotent"),
        id
    );
    assert!(worker::process_one(&pool, &config()).await.expect("worker"));
    let archived = report(&pool, id).await;
    assert_eq!(archived.get::<_, String>("status"), "ready");
    let payload: Value = archived.get("payload");
    assert_eq!(payload["scan_output"]["unique_ips"], 2);
    assert_eq!(payload["scan_output"]["port_observations"], 3);
    assert_eq!(payload["tasks"]["success_rate"], 50.0);
    assert_eq!(payload["tasks"]["cancelled"], 1);
    assert_eq!(payload["previous_available"], true);
    assert!(archived.get::<_, Option<Value>>("rendered_mail").is_some());
    let delivery_count: i64 = pool
        .get()
        .await
        .expect("client")
        .query_one("SELECT COUNT(*)::BIGINT AS n FROM report_delivery;", &[])
        .await
        .expect("count")
        .get("n");
    assert_eq!(delivery_count, 0, "manual generation never sends mail");
    pool.get()
        .await
        .expect("client")
        .batch_execute("DELETE FROM scan_task;")
        .await
        .expect("delete source");
    let after = report(&pool, id).await;
    assert_eq!(after.get::<_, Value>("payload"), payload);
    assert_eq!(
        after.get::<_, Option<String>>("content_checksum"),
        archived.get::<_, Option<String>>("content_checksum")
    );
    cleanup(&pool, schema).await;
}

#[tokio::test]
#[ignore = "requires disposable REPORT_TEST_DATABASE_URL"]
async fn reports_wait_for_missing_facts_without_admitting_later_executions() {
    let (pool, schema) = isolated_pool().await;
    let period = Period::last_closed(PeriodType::Monthly, Utc::now()).expect("period");
    let input = execution(
        &pool,
        period.start.timestamp_millis() + 7_200_000,
        "succeeded",
        false,
        "192.0.2.1",
    )
    .await;
    let id = storage::create(&pool, &period, Some(1), "manual", None)
        .await
        .expect("create");
    worker::process_one(&pool, &config()).await.expect("wait");
    let waiting = report(&pool, id).await;
    assert_eq!(waiting.get::<_, String>("status"), "waiting_data");
    assert!(waiting.get::<_, Option<Value>>("payload").is_none());
    execution(
        &pool,
        period.start.timestamp_millis() + 10_800_000,
        "succeeded",
        true,
        "192.0.2.2",
    )
    .await;
    let client = pool.get().await.expect("client");
    client
        .execute(
            "UPDATE analytics_outbox SET status='completed' WHERE execution_id=$1;",
            &[&input],
        )
        .await
        .expect("backfill");
    client
        .execute(
            "UPDATE report_job SET available_at=NOW() WHERE report_id=$1;",
            &[&id],
        )
        .await
        .expect("retry");
    drop(client);
    worker::process_one(&pool, &config()).await.expect("ready");
    assert_eq!(
        report(&pool, id).await.get::<_, Value>("payload")["scan_output"]["unique_ips"],
        1
    );
    let revision = storage::create(&pool, &period, Some(1), "revision", Some(id))
        .await
        .expect("revision");
    worker::process_one(&pool, &config())
        .await
        .expect("generate revision");
    let r = report(&pool, revision).await;
    assert_eq!(r.get::<_, i32>("revision"), 2);
    assert_eq!(r.get::<_, Value>("payload")["scan_output"]["unique_ips"], 2);
    assert_eq!(r.get::<_, Option<Uuid>>("supersedes_report_id"), Some(id));
    cleanup(&pool, schema).await;
}

#[tokio::test]
#[ignore = "requires disposable REPORT_TEST_DATABASE_URL"]
async fn disabled_plans_do_not_send_legacy_weekly_notifications_and_reclaimed_jobs_recover() {
    let (pool, schema) = isolated_pool().await;
    worker::schedule(&pool).await.expect("schedule disabled");
    let client = pool.get().await.expect("client");
    assert_eq!(
        client
            .query_one("SELECT COUNT(*)::BIGINT AS n FROM report_run;", &[])
            .await
            .expect("count")
            .get::<_, i64>("n"),
        0
    );
    let period = Period::last_closed(PeriodType::Weekly, Utc::now()).expect("period");
    drop(client);
    let id = storage::create(&pool, &period, Some(1), "manual", None)
        .await
        .expect("create");
    pool.get().await.expect("client").execute("UPDATE report_job SET status='running', claim_token=$2, lease_until=NOW()-INTERVAL '1 second' WHERE report_id=$1;", &[&id,&Uuid::new_v4()]).await.expect("abandoned claim");
    let settings = config();
    let (a, b) = tokio::join!(
        worker::process_one(&pool, &settings),
        worker::process_one(&pool, &settings)
    );
    assert!(a.expect("worker a") || b.expect("worker b"));
    assert_eq!(report(&pool, id).await.get::<_, String>("status"), "ready");
    cleanup(&pool, schema).await;
}

#[tokio::test]
#[ignore = "requires disposable REPORT_TEST_DATABASE_URL"]
async fn delivery_revalidates_administrator_role_without_sending_smtp() {
    let (pool, schema) = isolated_pool().await;
    let period = Period::last_closed(PeriodType::Weekly, Utc::now()).expect("period");
    let id = storage::create(&pool, &period, Some(1), "manual", None)
        .await
        .expect("create");
    worker::process_one(&pool, &config()).await.expect("ready");
    let client = pool.get().await.expect("client");
    assert_eq!(
        storage::enqueue_delivery(&client, id, &[1], false, true)
            .await
            .expect("enqueue"),
        1
    );
    client
        .execute("UPDATE users SET role=2 WHERE id=1;", &[])
        .await
        .expect("demote");
    drop(client);
    worker::send_one(&pool, "unused")
        .await
        .expect("cancel before SMTP");
    let status: String = pool
        .get()
        .await
        .expect("client")
        .query_one(
            "SELECT status FROM report_delivery WHERE report_id=$1;",
            &[&id],
        )
        .await
        .expect("delivery")
        .get("status");
    assert_eq!(status, "cancelled");
    cleanup(&pool, schema).await;
}

#[actix_web::test]
async fn ordinary_users_cannot_query_or_generate_platform_reports() {
    use actix_web::{App, HttpMessage, dev::Service, test, web};
    let pool = Pool::builder(Manager::new(
        "host=127.0.0.1 port=1 user=test".parse().expect("config"),
        NoTls,
    ))
    .build()
    .expect("pool");
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool))
            .wrap_fn(|req, srv| {
                req.extensions_mut().insert(crate::admin::UserBaseI {
                    id: 2,
                    username: "user".into(),
                    role: 2,
                    email: None,
                    limit_login: false,
                    enable_2fa: false,
                });
                srv.call(req)
            })
            .service(crate::handlers::reports::list)
            .service(crate::handlers::reports::generate)
            .service(crate::handlers::reports::detail)
            .service(crate::handlers::reports::send)
            .service(crate::handlers::report_mail_assets::revoke),
    )
    .await;
    for request in [
        test::TestRequest::post().uri(&format!(
            "/api/reports/{}/mail-image/revoke",
            Uuid::new_v4()
        )),
        test::TestRequest::get().uri("/api/reports"),
        test::TestRequest::post()
            .uri("/api/reports/generate")
            .set_json(json!({"period_type":"weekly"})),
        test::TestRequest::get().uri(&format!("/api/reports/{}", Uuid::new_v4())),
        test::TestRequest::post()
            .uri(&format!("/api/reports/{}/deliveries", Uuid::new_v4()))
            .set_json(json!({"recipient_ids":[1]})),
    ] {
        let response = test::call_service(&app, request.to_request()).await;
        assert_eq!(response.status(), 403);
    }
}

#[tokio::test]
#[ignore = "requires disposable REPORT_TEST_DATABASE_URL"]
async fn concurrent_creators_return_one_canonical_period_and_distinct_revisions() {
    let (pool, schema) = isolated_pool().await;
    let period = Period::last_closed(PeriodType::Weekly, Utc::now()).expect("period");
    let (a, b) = tokio::join!(
        storage::create(&pool, &period, Some(1), "manual", None),
        storage::create(&pool, &period, Some(1), "manual", None)
    );
    let id = a.expect("creator a");
    assert_eq!(id, b.expect("creator b"));
    let (a, b) = tokio::join!(
        storage::create(&pool, &period, Some(1), "revision", Some(id)),
        storage::create(&pool, &period, Some(1), "revision", Some(id))
    );
    let a = report(&pool, a.expect("revision a"))
        .await
        .get::<_, i32>("revision");
    let b = report(&pool, b.expect("revision b"))
        .await
        .get::<_, i32>("revision");
    assert_ne!(a, b);
    assert_eq!(a + b, 5);
    cleanup(&pool, schema).await;
}

#[tokio::test]
#[ignore = "requires disposable REPORT_TEST_DATABASE_URL"]
async fn automatic_schedule_catches_up_once_and_does_not_send_before_activation() {
    let (pool, schema) = isolated_pool().await;
    let period = Period::last_closed(PeriodType::Weekly, Utc::now()).expect("period");
    let client = pool.get().await.expect("client");
    client
        .execute(
            "UPDATE report_schedule SET enabled=TRUE, enabled_at=$1 WHERE period_type='weekly';",
            &[&Utc::now()],
        )
        .await
        .expect("activate now");
    drop(client);
    worker::schedule(&pool)
        .await
        .expect("no pre-activation report");
    let client = pool.get().await.expect("client");
    assert_eq!(
        client
            .query_one("SELECT COUNT(*)::BIGINT AS n FROM report_run;", &[])
            .await
            .expect("count")
            .get::<_, i64>("n"),
        0
    );
    client
        .execute(
            "UPDATE report_schedule SET enabled_at=$1 WHERE period_type='weekly';",
            &[&period.start],
        )
        .await
        .expect("simulate older activation");
    drop(client);
    worker::schedule(&pool).await.expect("schedule");
    worker::schedule(&pool).await.expect("idempotent schedule");
    worker::process_one(&pool, &config())
        .await
        .expect("generate");
    let client = pool.get().await.expect("client");
    assert_eq!(
        client
            .query_one("SELECT COUNT(*)::BIGINT AS n FROM report_run;", &[])
            .await
            .expect("count")
            .get::<_, i64>("n"),
        1
    );
    assert_eq!(
        client
            .query_one("SELECT COUNT(*)::BIGINT AS n FROM report_delivery;", &[])
            .await
            .expect("count")
            .get::<_, i64>("n"),
        1
    );
    drop(client);
    cleanup(&pool, schema).await;
}

#[actix_web::test]
#[ignore = "requires disposable REPORT_TEST_DATABASE_URL"]
async fn administrator_report_routes_validate_periods_plans_and_archive_delivery() {
    use actix_web::{App, HttpMessage, dev::Service, test, web};
    let (pool, schema) = isolated_pool().await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(config()))
            .wrap_fn(|req, srv| {
                req.extensions_mut().insert(crate::admin::UserBaseI {
                    id: 1,
                    username: "admin".into(),
                    role: 1,
                    email: Some("admin@example.invalid".into()),
                    limit_login: false,
                    enable_2fa: false,
                });
                srv.call(req)
            })
            .service(crate::handlers::reports::generate)
            .service(crate::handlers::reports::list)
            .service(crate::handlers::reports::detail)
            .service(crate::handlers::reports::schedules)
            .service(crate::handlers::reports::save_schedule)
            .service(crate::handlers::reports::send)
            .service(crate::handlers::reports::deliveries)
            .service(crate::handlers::reports::revise)
            .service(crate::handlers::reports::retry),
    )
    .await;
    let response=test::call_service(&app,test::TestRequest::post().uri("/api/reports/generate").set_json(json!({"period_type":"weekly","date":super::period::local_date(Utc::now()).expect("date")})).to_request()).await;
    assert_eq!(response.status(), 400, "reject unfinished period");
    let response=test::call_service(&app,test::TestRequest::put().uri("/api/report-schedules/weekly").set_json(json!({"enabled":true,"send_hour":9,"send_minute":0,"recipient_ids":[2],"expected_revision":0})).to_request()).await;
    assert_eq!(
        response.status(),
        400,
        "ordinary user cannot receive platform mail"
    );
    let response=test::call_service(&app,test::TestRequest::put().uri("/api/report-schedules/weekly").set_json(json!({"enabled":true,"send_hour":9,"send_minute":0,"recipient_ids":[1],"expected_revision":0})).to_request()).await;
    assert_eq!(response.status(), 200, "plan save is audited atomically");
    let response=test::call_service(&app,test::TestRequest::put().uri("/api/report-schedules/weekly").set_json(json!({"enabled":false,"send_hour":9,"send_minute":0,"recipient_ids":[],"expected_revision":0})).to_request()).await;
    assert_eq!(
        response.status(),
        409,
        "stale plan cannot overwrite newer version"
    );
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/api/reports/generate")
            .set_json(json!({"period_type":"weekly"}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), 202);
    let body: Value = test::read_body_json(response).await;
    let id = Uuid::parse_str(body["data"]["id"].as_str().expect("id")).expect("UUID");
    worker::process_one(&pool, &config())
        .await
        .expect("generate");
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/api/reports/{id}"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), 200);
    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["data"]["status"], "ready");
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/api/reports/{id}/deliveries"))
            .set_json(json!({"recipient_ids":[1]}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), 202, "delivery enqueue audit succeeds");
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/api/reports/{id}/deliveries"))
            .set_json(json!({"recipient_ids":[1]}))
            .to_request(),
    )
    .await;
    assert_eq!(
        response.status(),
        409,
        "do not enqueue duplicate concurrent resend"
    );
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/report-schedules")
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), 200);
    let response = test::call_service(
        &app,
        test::TestRequest::get().uri("/api/reports").to_request(),
    )
    .await;
    assert_eq!(response.status(), 200);
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/api/reports/{id}/retry"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), 409, "ready report is immutable");
    pool.get().await.expect("client").execute(
        "UPDATE report_run SET period_start = period_start - INTERVAL '2 years', period_end = period_end - INTERVAL '2 years' WHERE id = $1;",
        &[&id],
    ).await.expect("old archive");
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/api/reports/{id}/revisions"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), 400, "old archive cannot be revised");
    cleanup(&pool, schema).await;
}

#[tokio::test]
#[ignore = "requires disposable REPORT_TEST_DATABASE_URL"]
async fn older_executions_without_result_counters_use_batch_receipts() {
    let (pool, schema) = isolated_pool().await;
    let period = Period::last_closed(PeriodType::Weekly, Utc::now()).expect("period");
    let input = execution(
        &pool,
        period.start.timestamp_millis() + 7_200_000,
        "succeeded",
        true,
        "192.0.2.1",
    )
    .await;
    let client = pool.get().await.expect("client");
    client
        .execute(
            "UPDATE scan_task_execution SET result_observation_count=NULL WHERE id=$1;",
            &[&input],
        )
        .await
        .expect("legacy counter");
    client.execute("INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count,storage_backend) VALUES($1,$2,0,true,2,'elasticsearch');",&[&input,&Uuid::new_v4().to_string()]).await.expect("receipt");
    drop(client);
    let id = storage::create(&pool, &period, Some(1), "manual", None)
        .await
        .expect("create");
    worker::process_one(&pool, &config()).await.expect("worker");
    let row = report(&pool, id).await;
    assert_eq!(row.get::<_, String>("status"), "ready");
    assert_eq!(
        row.get::<_, Value>("payload")["scan_output"]["unique_ips"],
        1
    );
    cleanup(&pool, schema).await;
}

#[tokio::test]
#[ignore = "requires disposable REPORT_TEST_DATABASE_URL"]
async fn temporary_renderer_outage_retries_without_archival_and_enqueues_mail_after_recovery() {
    use super::render_module::LocalReportRenderModule;
    use super::service::ReportRenderService;
    use std::{sync::Arc, time::Duration};
    let (pool, schema) = isolated_pool().await;
    let calendar = crate::system_time::refresh(&pool).await.unwrap();
    let timezone: chrono_tz::Tz = calendar.document.timezone.parse().unwrap();
    let period = Period::containing_in(
        PeriodType::Weekly,
        Utc::now().with_timezone(&timezone).date_naive(),
        &calendar.document.timezone,
        calendar.revision,
    )
    .unwrap()
    .previous()
    .unwrap();
    pool.get().await.unwrap().execute(
        "UPDATE report_schedule SET enabled=TRUE, enabled_at=$1, recipient_ids=ARRAY[1] WHERE period_type='weekly'",
        &[&period.start],
    ).await.unwrap();
    let id = storage::create(&pool, &period, None, "automatic", None)
        .await
        .unwrap();
    let renderer = ReportRenderService::builtin().await;
    renderer
        .registry()
        .shutdown(Duration::from_secs(1))
        .await
        .unwrap();

    assert!(
        worker::process_one_with_renderer(&pool, &config(), &renderer)
            .await
            .unwrap()
    );
    let waiting = report(&pool, id).await;
    assert_eq!(waiting.get::<_, String>("status"), "queued");
    assert!(waiting.get::<_, Option<Value>>("payload").is_none());
    assert!(waiting.get::<_, Option<Value>>("rendered_mail").is_none());
    let client = pool.get().await.unwrap();
    let job = client
        .query_one(
            "SELECT status,attempts,claim_token FROM report_job WHERE report_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    assert_eq!(job.get::<_, String>("status"), "retry_wait");
    assert_eq!(job.get::<_, i32>("attempts"), 1);
    assert!(job.get::<_, Option<Uuid>>("claim_token").is_none());
    assert_eq!(
        client
            .query_one(
                "SELECT COUNT(*) FROM report_delivery WHERE report_id=$1",
                &[&id]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        client
            .query_one(
                "SELECT COUNT(*) FROM report_mail_asset WHERE report_id=$1",
                &[&id]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    client
        .execute(
            "UPDATE report_job SET available_at=NOW() WHERE report_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    drop(client);

    renderer
        .registry()
        .publish(1, Arc::new(LocalReportRenderModule))
        .await
        .unwrap();
    assert!(
        worker::process_one_with_renderer(&pool, &config(), &renderer)
            .await
            .unwrap()
    );
    let archived = report(&pool, id).await;
    assert_eq!(archived.get::<_, String>("status"), "ready");
    assert!(archived.get::<_, Option<Value>>("rendered_mail").is_some());
    assert!(
        archived
            .get::<_, Value>("quality")
            .get("mail_error")
            .is_none()
    );
    let client = pool.get().await.unwrap();
    let job = client
        .query_one(
            "SELECT status,attempts FROM report_job WHERE report_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    assert_eq!(job.get::<_, String>("status"), "succeeded");
    assert_eq!(job.get::<_, i32>("attempts"), 2);
    assert_eq!(client.query_one("SELECT COUNT(*) FROM report_delivery WHERE report_id=$1 AND status='pending' AND automatic", &[&id]).await.unwrap().get::<_, i64>(0), 1);
    drop(client);
    assert!(
        !worker::process_one_with_renderer(&pool, &config(), &renderer)
            .await
            .unwrap()
    );
    renderer
        .registry()
        .shutdown(Duration::from_secs(1))
        .await
        .unwrap();
    cleanup(&pool, schema).await;
}

#[tokio::test]
#[ignore = "requires disposable REPORT_TEST_DATABASE_URL"]
async fn bad_report_template_cannot_block_valid_statistics_archival() {
    let (pool, schema) = isolated_pool().await;
    let client = pool.get().await.expect("client");
    client.batch_execute("INSERT INTO mail_template_version(template_key,version,status,subject_template,html_template,text_template) \
        VALUES('report_weekly',1,'published','Report','{% if tasks.created > 0 %}Valid{% else %}{{ missing }}{% endif %}','data'); \
        UPDATE mail_template SET active_version=1 WHERE template_key='report_weekly';").await.expect("template");
    drop(client);
    let period = Period::last_closed(PeriodType::Weekly, Utc::now()).expect("period");
    let id = storage::create(&pool, &period, Some(1), "manual", None)
        .await
        .expect("create");
    worker::process_one(&pool, &config()).await.expect("worker");
    let row = report(&pool, id).await;
    assert_eq!(row.get::<_, String>("status"), "ready");
    assert!(row.get::<_, Value>("quality")["mail_error"].is_string());
    assert!(row.get::<_, Option<Value>>("rendered_mail").is_none());
    cleanup(&pool, schema).await;
}

#[tokio::test]
#[ignore = "requires disposable REPORT_TEST_DATABASE_URL"]
async fn missing_smtp_configuration_retries_delivery_without_recomputing_report() {
    let (pool, schema) = isolated_pool().await;
    let period = Period::last_closed(PeriodType::Weekly, Utc::now()).expect("period");
    let id = storage::create(&pool, &period, Some(1), "manual", None)
        .await
        .expect("create");
    worker::process_one(&pool, &config())
        .await
        .expect("generate");
    let before = report(&pool, id).await;
    let client = pool.get().await.expect("client");
    storage::enqueue_delivery(&client, id, &[1], false, true)
        .await
        .expect("enqueue");
    drop(client);
    for _ in 0..5 {
        worker::send_one(&pool, "unused")
            .await
            .expect("failed delivery");
        pool.get()
            .await
            .expect("client")
            .execute(
                "UPDATE report_delivery SET available_at=NOW() WHERE report_id=$1;",
                &[&id],
            )
            .await
            .expect("due retry");
    }
    let client = pool.get().await.expect("client");
    let delivery = client
        .query_one(
            "SELECT status,attempts FROM report_delivery WHERE report_id=$1;",
            &[&id],
        )
        .await
        .expect("delivery");
    assert_eq!(delivery.get::<_, String>("status"), "failed");
    assert_eq!(delivery.get::<_, i32>("attempts"), 5);
    drop(client);
    let after = report(&pool, id).await;
    assert_eq!(after.get::<_, String>("status"), "ready");
    assert_eq!(
        before.get::<_, Value>("payload"),
        after.get::<_, Value>("payload")
    );
    assert_eq!(
        before.get::<_, Value>("rendered_mail"),
        after.get::<_, Value>("rendered_mail")
    );
    cleanup(&pool, schema).await;
}
