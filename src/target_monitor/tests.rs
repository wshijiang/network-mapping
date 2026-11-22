use super::{rules, worker};
use crate::admin::UserBaseI;
use crate::audit::AuditContext;
use crate::config::ElasticsearchConfig;
use crate::elasticsearch::ElasticsearchService;
use crate::maxmind::MaxMindState;
use crate::runtime_config::{RuntimeSettings, RuntimeSettingsBootstrap};
use deadpool_postgres::{Manager, Pool};
use serde_json::json;
use tokio_postgres::NoTls;
use uuid::Uuid;

async fn database() -> (Pool, String) {
    let mut config: tokio_postgres::Config = std::env::var("NOTIFICATION_TEST_DATABASE_URL")
        .expect("NOTIFICATION_TEST_DATABASE_URL must point to a disposable database")
        .parse()
        .unwrap();
    let schema = format!("target_monitor_{}", Uuid::new_v4().simple());
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
    for _ in 0..2 {
        c.batch_execute(include_str!(
            "../../source/database/migrate_notifications.sql"
        ))
        .await
        .unwrap();
        c.batch_execute(include_str!(
            "../../source/database/migrate_notification_inbox.sql"
        ))
        .await
        .unwrap();
        c.batch_execute(include_str!(
            "../../source/database/migrate_target_monitor.sql"
        ))
        .await
        .unwrap();
    }
    c.batch_execute("INSERT INTO users(id,username,password,role) VALUES(1,'admin','test',1),(2,'member','test',2)")
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

fn user(id: i32, role: i32) -> UserBaseI {
    UserBaseI {
        id,
        username: if role == 1 {
            "admin".into()
        } else {
            "member".into()
        },
        role,
        email: None,
        limit_login: false,
        enable_2fa: false,
    }
}

async fn settings(pool: &Pool) -> RuntimeSettings {
    let mut bootstrap = RuntimeSettingsBootstrap {
        requests: Default::default(),
        monitor: Default::default(),
        automatic_target: Default::default(),
        dns_follow_up: Default::default(),
        dns_resolvers: Default::default(),
        analytics_snapshot: Default::default(),
        report_mail: Default::default(),
    };
    bootstrap.automatic_target.authorized_cidrs = vec!["192.0.2.0/24".into()];
    RuntimeSettings::load(pool, bootstrap).await.unwrap()
}

fn input(value: serde_json::Value) -> rules::RuleInput {
    serde_json::from_value(value).unwrap()
}

fn ip_input(targets: &[&str]) -> rules::RuleInput {
    input(json!({"name": "测试规则", "targets": targets, "interval_seconds": 3600}))
}

#[tokio::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn rule_permissions_validation_and_revision_conflicts() {
    let (pool, schema) = database().await;
    let settings = settings(&pool).await;
    let audit = AuditContext::cli("target-monitor-test");
    let admin = user(1, 1);
    let member = user(2, 2);

    let admin_rule = rules::create(
        &pool,
        &admin,
        &settings,
        ip_input(&["192.0.2.0/24"]),
        &audit,
    )
    .await
    .unwrap();
    let admin_id: Uuid = serde_json::from_value(admin_rule["id"].clone()).unwrap();

    // 功能未开放时普通用户不能创建。
    let error = rules::create(&pool, &member, &settings, ip_input(&["192.0.2.1"]), &audit)
        .await
        .unwrap_err();
    assert_eq!(error.status, actix_web::http::StatusCode::FORBIDDEN);

    pool.get().await.unwrap().execute(
        "INSERT INTO setting(item_type,key,value) VALUES('notification','monitor_user_enabled','true')",
        &[],
    ).await.unwrap();

    // 开放后用户可创建授权范围内规则，收件人固定本人。
    let own = rules::create(&pool, &member, &settings, ip_input(&["192.0.2.1"]), &audit)
        .await
        .unwrap();
    assert_eq!(own["recipient_ids"], json!([2]));
    let own_id: Uuid = serde_json::from_value(own["id"].clone()).unwrap();

    // 授权范围外拒绝；域名规则允许。
    let error = rules::create(
        &pool,
        &member,
        &settings,
        ip_input(&["198.51.100.1"]),
        &audit,
    )
    .await
    .unwrap_err();
    assert_eq!(error.status, actix_web::http::StatusCode::FORBIDDEN);
    let domain = rules::create(
        &pool, &member, &settings,
        input(json!({"name": "域名监控", "target_type": "domain", "targets": ["example.com"], "interval_seconds": 3600})),
        &audit,
    ).await.unwrap();
    assert_eq!(domain["scan_profile"], "dns_records");
    assert_eq!(domain["ports"], "53");

    // 用户不能管理他人规则；版本冲突返回 409。
    let error = rules::remove(&pool, &member, admin_id, 1, &audit)
        .await
        .unwrap_err();
    assert_eq!(error.status, actix_web::http::StatusCode::FORBIDDEN);
    let mut edit = ip_input(&["192.0.2.2"]);
    edit.expected_revision = Some(99);
    let error = rules::update(&pool, &member, &settings, own_id, edit, &audit)
        .await
        .unwrap_err();
    assert_eq!(error.status, actix_web::http::StatusCode::CONFLICT);

    // 非法输入：混合地址族、过短周期。
    let error = rules::create(
        &pool,
        &admin,
        &settings,
        ip_input(&["192.0.2.1", "2001:db8::1"]),
        &audit,
    )
    .await
    .unwrap_err();
    assert_eq!(error.status, actix_web::http::StatusCode::BAD_REQUEST);
    let error = rules::create(
        &pool,
        &admin,
        &settings,
        input(json!({"name": "x", "targets": ["192.0.2.1"], "interval_seconds": 60})),
        &audit,
    )
    .await
    .unwrap_err();
    assert_eq!(error.status, actix_web::http::StatusCode::BAD_REQUEST);

    // 列表权限与收件人候选。
    let member_list = rules::list(&pool, &member).await.unwrap();
    assert_eq!(member_list["items"].as_array().unwrap().len(), 2);
    assert_eq!(member_list["monitor_user_enabled"], true);
    let admin_list = rules::list(&pool, &admin).await.unwrap();
    assert_eq!(admin_list["items"].as_array().unwrap().len(), 3);
    assert!(rules::recipients(&pool, &member).await.is_err());
    assert_eq!(
        rules::recipients(&pool, &admin)
            .await
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // 立即执行排队与删除。
    rules::run_now(&pool, &member, own_id, &audit)
        .await
        .unwrap();
    rules::remove(&pool, &member, own_id, 1, &audit)
        .await
        .unwrap();
    cleanup(pool, schema).await;
}

#[tokio::test]
#[ignore = "requires disposable NOTIFICATION_TEST_DATABASE_URL"]
async fn dispatch_skips_without_scanner_then_creates_monitor_task_and_degrades_without_es() {
    let (pool, schema) = database().await;
    let settings = settings(&pool).await;
    let audit = AuditContext::cli("target-monitor-test");
    let admin = user(1, 1);
    let rule = rules::create(
        &pool,
        &admin,
        &settings,
        ip_input(&["192.0.2.0/24"]),
        &audit,
    )
    .await
    .unwrap();
    let rule_id: Uuid = serde_json::from_value(rule["id"].clone()).unwrap();
    let maxmind = MaxMindState::from_directory(std::path::Path::new("/nonexistent-maxmind"));
    let es = ElasticsearchService::new(
        serde_json::from_value::<ElasticsearchConfig>(json!({"enabled": false})).unwrap(),
    )
    .unwrap();
    assert!(!es.enabled());

    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE target_monitor_rule SET next_run_at=NOW()-INTERVAL '1 second' WHERE id=$1",
            &[&rule_id],
        )
        .await
        .unwrap();

    // 无扫描器：运行跳过并产生站内提示。
    worker::dispatch_due(&pool, &maxmind).await.unwrap();
    let row = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT status,skip_reason FROM target_monitor_run WHERE rule_id=$1",
            &[&rule_id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "skipped");
    assert_eq!(row.get::<_, String>(1), "no_scanner");
    let inbox: i64 = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT COUNT(*) FROM notification_inbox WHERE user_id=1 AND category='monitor'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(inbox, 1);

    // 有扫描器：创建 task_source=monitor 的任务并关联运行。
    pool.get().await.unwrap().execute(
        "INSERT INTO scanner_info(scanner_id,create_user,runtime_token_hash,is_enable,scan_capabilities) \
         VALUES('01952f0c-0000-7000-8000-000000000001',1,'hash',true,'{\"profiles\":{\"service_inventory\":{}}}'::JSONB)",
        &[],
    ).await.unwrap();
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE target_monitor_rule SET next_run_at=NOW()-INTERVAL '1 second' WHERE id=$1",
            &[&rule_id],
        )
        .await
        .unwrap();
    worker::dispatch_due(&pool, &maxmind).await.unwrap();
    let run = pool.get().await.unwrap().query_one(
        "SELECT id,task_id,status FROM target_monitor_run WHERE rule_id=$1 ORDER BY id DESC LIMIT 1",
        &[&rule_id],
    ).await.unwrap();
    assert_eq!(run.get::<_, String>(2), "running");
    let task_id: String = run.get(1);
    let task = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT id,task_source,generation_metadata FROM scan_task WHERE task_id=$1",
            &[&task_id],
        )
        .await
        .unwrap();
    assert_eq!(task.get::<_, String>(1), "monitor");
    assert_eq!(
        task.get::<_, serde_json::Value>(2)["target_monitor"]["rule_id"],
        json!(rule_id.to_string())
    );

    // 模拟任务成功：ES 不可用时降级收尾，不更新基线。
    let task_db_id: i32 = task.get(0);
    let mut c = pool.get().await.unwrap();
    c.execute(
        "UPDATE scan_task_execution SET execution_status='succeeded',task_start_time=1000,task_end_time=2000 WHERE task_id=$1",
        &[&task_db_id],
    ).await.unwrap();
    let tx = c.transaction().await.unwrap();
    crate::scan_control::dispatch::refresh_task_aggregate(&tx, task_db_id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    drop(c);
    worker::finalize_runs(&pool, &es).await.unwrap();
    let run = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT status,skip_reason FROM target_monitor_run WHERE id=$1",
            &[&run.get::<_, Uuid>(0)],
        )
        .await
        .unwrap();
    assert_eq!(run.get::<_, String>(0), "succeeded");
    assert_eq!(run.get::<_, String>(1), "es_unavailable");
    let baseline: Option<serde_json::Value> = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT baseline FROM target_monitor_rule WHERE id=$1",
            &[&rule_id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(baseline.is_none());
    cleanup(pool, schema).await;
}
