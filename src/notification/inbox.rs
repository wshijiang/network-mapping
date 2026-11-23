//! 站内通知收件箱：事件同事务扇出、未读/已读、个人类别偏好与保留清理。
//! 收件箱行携带事件快照，独立于 notification_event 的 30 天清理；保留期与容量由管理员配置。
use crate::admin::UserBaseI;
use actix_web::{HttpResponse, delete, get, post, put, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_postgres::Transaction;
use uuid::Uuid;

use super::{Error, Result};

pub const CATEGORIES: [&str; 5] = ["task", "monitor", "alert", "security", "report"];
const MAX_BODY_CHARS: usize = 2000;

/// 事件 → 站内类别；未登记的事件（如渠道测试）不进入收件箱。
pub(crate) fn category(event_type: &str) -> Option<&'static str> {
    match event_type {
        "task.completed" | "task.failed" | "task.cancelled" => Some("task"),
        "monitor.change" | "monitor.availability" | "monitor.cert_expiring" => Some("monitor"),
        "health.alert" | "scanner.offline" | "scanner.recovered" => Some("alert"),
        "user.login" => Some("security"),
        "report.daily" | "report.weekly" | "report.monthly" => Some("report"),
        _ => None,
    }
}

/// 通知深链：前端点击后跳转并标记已读。
pub(crate) fn link(event_type: &str, context: &Value) -> Option<String> {
    if event_type.starts_with("task.") {
        return context["task_id"].as_str().map(|id| format!("/task/{id}"));
    }
    if event_type.starts_with("monitor.") {
        return context["run_id"]
            .as_str()
            .map(|id| format!("/monitor?run={id}"));
    }
    if event_type.starts_with("report.") {
        return context["report_id"]
            .as_str()
            .map(|id| format!("/reports/{id}"));
    }
    match event_type {
        "health.alert" => Some("/health".into()),
        "scanner.offline" | "scanner.recovered" => Some("/scanner".into()),
        "user.login" => Some("/user/security".into()),
        _ => None,
    }
}

fn context_user_ids(context: &Value) -> Vec<i32> {
    // 报告事件同时携带管理员选择的收件人与自助订阅者；两者都进入站内收件箱。
    let mut ids: Vec<i32> = ["recipient_ids", "subscriber_ids"]
        .into_iter()
        .filter_map(|key| context[key].as_array())
        .flatten()
        .filter_map(|v| v.as_i64().and_then(|v| i32::try_from(v).ok()))
        .collect();
    if let Some(id) = context["user_id"]
        .as_i64()
        .and_then(|v| i32::try_from(v).ok())
    {
        ids.push(id);
    }
    ids
}

/// 与渠道扇出同事务：按事件解析收件人，过滤个人偏好与失效账号后写入快照行。
pub(crate) async fn fanout(
    tx: &Transaction<'_>,
    event_id: Uuid,
    event_type: &str,
    severity: &str,
    title: &str,
    body: &str,
    context: &Value,
) -> std::result::Result<(), tokio_postgres::Error> {
    let Some(category) = category(event_type) else {
        return Ok(());
    };
    let enabled: bool = tx
        .query_opt(
            "SELECT value::boolean FROM setting WHERE item_type='notification' AND key='in_app_enabled'",
            &[],
        )
        .await?
        .map(|row| row.get::<_, bool>(0))
        .unwrap_or(true);
    if !enabled {
        return Ok(());
    }
    let candidates: Vec<i32> = if category == "alert" {
        tx.query(
            "SELECT id FROM users WHERE role=1 AND deleted_at IS NULL AND disabled_at IS NULL",
            &[],
        )
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect()
    } else {
        context_user_ids(context)
    };
    if candidates.is_empty() {
        return Ok(());
    }
    let recipients: Vec<i32> = tx
        .query(
            "SELECT u.id FROM unnest($1::INT[]) AS uid \
             JOIN users u ON u.id=uid AND u.deleted_at IS NULL AND u.disabled_at IS NULL \
             LEFT JOIN notification_user_preference p ON p.user_id=u.id AND p.category=$2 AND p.enabled=FALSE \
             WHERE p.user_id IS NULL",
            &[&candidates, &category],
        )
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect();
    let body: String = body.chars().take(MAX_BODY_CHARS).collect();
    let link = link(event_type, context);
    for user_id in recipients {
        tx.execute(
            "INSERT INTO notification_inbox(id,user_id,event_id,category,event_type,severity,title,body,link) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (user_id,event_id) DO NOTHING",
            &[
                &Uuid::now_v7(),
                &user_id,
                &event_id,
                &category,
                &event_type,
                &severity,
                &title,
                &body,
                &link,
            ],
        )
        .await?;
    }
    Ok(())
}

/// 保留期 + 每用户容量 + 已删除行清理；由通知 worker 周期调用。
pub(crate) async fn cleanup(pool: &Pool) -> Result<()> {
    let conn = pool.get().await?;
    let retention: i32 = conn
        .query_opt(
            "SELECT value::INT FROM setting WHERE item_type='notification' AND key='inbox_retention_days'",
            &[],
        )
        .await?
        .map(|row| row.get::<_, i32>(0))
        .unwrap_or(90)
        .clamp(7, 365);
    let cap: i32 = conn
        .query_opt(
            "SELECT value::INT FROM setting WHERE item_type='notification' AND key='inbox_max_per_user'",
            &[],
        )
        .await?
        .map(|row| row.get::<_, i32>(0))
        .unwrap_or(2000)
        .clamp(100, 10_000);
    conn.execute(
        "DELETE FROM notification_inbox WHERE created_at < NOW() - make_interval(days => $1)",
        &[&retention],
    )
    .await?;
    conn.execute(
        "DELETE FROM notification_inbox WHERE dismissed_at IS NOT NULL AND dismissed_at < NOW() - INTERVAL '7 days'",
        &[],
    )
    .await?;
    // 容量超限只清理最旧的已读通知，未读通知不受容量清理影响。
    conn.execute(
        "DELETE FROM notification_inbox i USING (SELECT id FROM (SELECT id, read_at, \
         ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY created_at DESC, id DESC) AS rn \
         FROM notification_inbox WHERE dismissed_at IS NULL) t WHERE rn > $1 AND read_at IS NOT NULL) old \
         WHERE i.id = old.id",
        &[&(cap as i64)],
    )
    .await?;
    Ok(())
}

fn respond<T: Serialize>(result: Result<T>) -> HttpResponse {
    match result {
        Ok(data) => HttpResponse::Ok().json(json!({"success":true,"data":data})),
        Err(error) => {
            HttpResponse::build(error.status).json(json!({"success":false,"message":error.message}))
        }
    }
}

#[derive(Deserialize)]
struct InboxQuery {
    category: Option<String>,
    unread: Option<bool>,
    before: Option<Uuid>,
}

async fn unread_total(pool: &Pool, user_id: i32) -> Result<i64> {
    Ok(pool
        .get()
        .await?
        .query_one(
            "SELECT COUNT(*) FROM notification_inbox WHERE user_id=$1 AND dismissed_at IS NULL AND read_at IS NULL",
            &[&user_id],
        )
        .await?
        .get(0))
}

#[get("/notifications")]
async fn list(
    pool: web::Data<Pool>,
    user: UserBaseI,
    query: web::Query<InboxQuery>,
) -> HttpResponse {
    let query = query.into_inner();
    if let Some(category) = &query.category
        && !CATEGORIES.contains(&category.as_str())
    {
        return respond::<()>(Err(Error::bad("通知类别无效")));
    }
    let result = async {
        let conn = pool.get().await?;
        let rows = conn
            .query(
                "SELECT id,event_id,category,event_type,severity,title,body,link,read_at,occurred_at,created_at \
                 FROM notification_inbox WHERE user_id=$1 AND dismissed_at IS NULL \
                 AND ($2::TEXT IS NULL OR category=$2) \
                 AND ($3::BOOLEAN IS NULL OR ($3 AND read_at IS NULL) OR (NOT $3 AND read_at IS NOT NULL)) \
                 AND ($4::UUID IS NULL OR id<$4) ORDER BY id DESC LIMIT 51",
                &[&user.id, &query.category, &query.unread, &query.before],
            )
            .await?;
        let items: Vec<Value> = rows
            .iter()
            .take(50)
            .map(|row| {
                json!({
                    "id": row.get::<_, Uuid>("id"),
                    "event_id": row.get::<_, Option<Uuid>>("event_id"),
                    "category": row.get::<_, String>("category"),
                    "event_type": row.get::<_, String>("event_type"),
                    "severity": row.get::<_, String>("severity"),
                    "title": row.get::<_, String>("title"),
                    "body": row.get::<_, String>("body"),
                    "link": row.get::<_, Option<String>>("link"),
                    "read_at": row.get::<_, Option<DateTime<Utc>>>("read_at"),
                    "occurred_at": row.get::<_, DateTime<Utc>>("occurred_at"),
                    "created_at": row.get::<_, DateTime<Utc>>("created_at"),
                })
            })
            .collect();
        let next = if rows.len() > 50 {
            items.last().and_then(|v| v.get("id")).cloned()
        } else {
            None
        };
        Ok(json!({"items":items,"next_before":next,"unread_count":unread_total(&pool,user.id).await?}))
    }
    .await;
    respond(result)
}

#[get("/unread-count")]
async fn unread_count(pool: web::Data<Pool>, user: UserBaseI) -> HttpResponse {
    let result = async {
        let conn = pool.get().await?;
        let rows = conn
            .query(
                "SELECT category,COUNT(*) FROM notification_inbox WHERE user_id=$1 AND dismissed_at IS NULL AND read_at IS NULL GROUP BY category",
                &[&user.id],
            )
            .await?;
        let mut by_category = json!({"task":0,"monitor":0,"alert":0,"security":0,"report":0});
        let mut count = 0_i64;
        for row in rows {
            let category: String = row.get(0);
            let n: i64 = row.get(1);
            count += n;
            by_category[category] = json!(n);
        }
        Ok(json!({"count":count,"by_category":by_category}))
    }
    .await;
    respond(result)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadInput {
    #[serde(default)]
    ids: Vec<Uuid>,
    #[serde(default)]
    all: bool,
    category: Option<String>,
}

#[post("/read")]
async fn read(pool: web::Data<Pool>, user: UserBaseI, input: web::Json<ReadInput>) -> HttpResponse {
    let input = input.into_inner();
    if input.all == !input.ids.is_empty() {
        return respond::<()>(Err(Error::bad("请选择标记全部已读或指定通知 ID")));
    }
    if input.ids.len() > 200 {
        return respond::<()>(Err(Error::bad("单次最多标记 200 条通知")));
    }
    if let Some(category) = &input.category
        && !CATEGORIES.contains(&category.as_str())
    {
        return respond::<()>(Err(Error::bad("通知类别无效")));
    }
    let result = async {
        let conn = pool.get().await?;
        let updated = if input.all {
            conn.execute(
                "UPDATE notification_inbox SET read_at=NOW() WHERE user_id=$1 AND read_at IS NULL AND dismissed_at IS NULL AND ($2::TEXT IS NULL OR category=$2)",
                &[&user.id, &input.category],
            )
            .await?
        } else {
            conn.execute(
                "UPDATE notification_inbox SET read_at=NOW() WHERE user_id=$1 AND id=ANY($2) AND read_at IS NULL AND dismissed_at IS NULL",
                &[&user.id, &input.ids],
            )
            .await?
        };
        Ok(json!({"updated":updated}))
    }
    .await;
    respond(result)
}

#[delete("/notifications/{id}")]
async fn dismiss(pool: web::Data<Pool>, user: UserBaseI, id: web::Path<Uuid>) -> HttpResponse {
    let result = async {
        let changed = pool
            .get()
            .await?
            .execute(
                "UPDATE notification_inbox SET dismissed_at=NOW() WHERE id=$1 AND user_id=$2 AND dismissed_at IS NULL",
                &[&id.into_inner(), &user.id],
            )
            .await?;
        if changed != 1 {
            return Err(Error {
                status: actix_web::http::StatusCode::NOT_FOUND,
                message: "站内通知不存在或无权访问",
            });
        }
        Ok(json!({"dismissed":true}))
    }
    .await;
    respond(result)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Preferences {
    #[serde(default = "default_true")]
    task: bool,
    #[serde(default = "default_true")]
    monitor: bool,
    #[serde(default = "default_true")]
    alert: bool,
    #[serde(default = "default_true")]
    security: bool,
    #[serde(default = "default_true")]
    report: bool,
}

fn default_true() -> bool {
    true
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            task: true,
            monitor: true,
            alert: true,
            security: true,
            report: true,
        }
    }
}

async fn load_preferences(pool: &Pool, user_id: i32) -> Result<Preferences> {
    let mut prefs = Preferences::default();
    let rows = pool
        .get()
        .await?
        .query(
            "SELECT category,enabled FROM notification_user_preference WHERE user_id=$1",
            &[&user_id],
        )
        .await?;
    for row in rows {
        let category: String = row.get(0);
        let enabled: bool = row.get(1);
        match category.as_str() {
            "task" => prefs.task = enabled,
            "monitor" => prefs.monitor = enabled,
            "alert" => prefs.alert = enabled,
            "security" => prefs.security = enabled,
            "report" => prefs.report = enabled,
            _ => {}
        }
    }
    Ok(prefs)
}

#[get("/preferences")]
async fn get_preferences(pool: web::Data<Pool>, user: UserBaseI) -> HttpResponse {
    respond(load_preferences(&pool, user.id).await)
}

#[put("/preferences")]
async fn put_preferences(
    pool: web::Data<Pool>,
    user: UserBaseI,
    input: web::Json<Preferences>,
) -> HttpResponse {
    let prefs = input.into_inner();
    let result = async {
        let mut conn = pool.get().await?;
        let tx = conn.transaction().await?;
        for (category, enabled) in [
            ("task", prefs.task),
            ("monitor", prefs.monitor),
            ("alert", prefs.alert),
            ("security", prefs.security),
            ("report", prefs.report),
        ] {
            tx.execute(
                "INSERT INTO notification_user_preference(user_id,category,enabled) VALUES($1,$2,$3) \
                 ON CONFLICT (user_id,category) DO UPDATE SET enabled=EXCLUDED.enabled, updated_at=NOW()",
                &[&user.id, &category, &enabled],
            )
            .await?;
        }
        tx.commit().await?;
        load_preferences(&pool, user.id).await
    }
    .await;
    respond(result)
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/inbox")
            .app_data(
                web::JsonConfig::default()
                    .limit(16 * 1024)
                    .error_handler(|_, _| {
                        actix_web::error::InternalError::from_response(
                            "invalid_inbox_payload",
                            HttpResponse::BadRequest().json(
                                json!({"success":false,"message":"站内通知请求格式无效或超过 16 KiB"}),
                            ),
                        )
                        .into()
                    }),
            )
            .service(list)
            .service(unread_count)
            .service(read)
            .service(dismiss)
            .service(get_preferences)
            .service(put_preferences),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_and_links_cover_every_inbox_event() {
        for (event, category, link) in [
            ("task.completed", "task", "/task/abc"),
            ("task.failed", "task", "/task/abc"),
            ("task.cancelled", "task", "/task/abc"),
            ("monitor.change", "monitor", "/monitor?run=r1"),
            ("monitor.availability", "monitor", "/monitor?run=r1"),
            ("monitor.cert_expiring", "monitor", "/monitor?run=r1"),
            ("health.alert", "alert", "/health"),
            ("scanner.offline", "alert", "/scanner"),
            ("scanner.recovered", "alert", "/scanner"),
            ("user.login", "security", "/user/security"),
            ("report.daily", "report", "/reports/r2"),
            ("report.weekly", "report", "/reports/r2"),
            ("report.monthly", "report", "/reports/r2"),
        ] {
            assert_eq!(category, super::category(event).unwrap(), "{event}");
            let context = json!({"task_id":"abc","run_id":"r1","report_id":"r2"});
            assert_eq!(
                super::link(event, &context).as_deref(),
                Some(link),
                "{event}"
            );
        }
        assert!(super::category("notification.test").is_none());
        assert!(super::category("unknown.event").is_none());
    }

    #[test]
    fn read_input_requires_exactly_one_mode() {
        let both: ReadInput =
            serde_json::from_value(json!({"all":true,"ids":[Uuid::nil()]})).unwrap();
        assert!(both.all == !both.ids.is_empty());
        let neither: ReadInput = serde_json::from_value(json!({})).unwrap();
        assert!(neither.all == !neither.ids.is_empty());
        let ids: ReadInput = serde_json::from_value(json!({"ids":[Uuid::nil()]})).unwrap();
        assert!(ids.all != !ids.ids.is_empty());
    }

    #[test]
    fn report_context_merges_selected_recipients_and_subscribers() {
        let context = json!({"recipient_ids":[2,3],"subscriber_ids":[3,4],"user_id":5});
        assert_eq!(super::context_user_ids(&context), vec![2, 3, 3, 4, 5]);
        assert_eq!(
            super::context_user_ids(&json!({"recipient_ids":["bad",2]})),
            vec![2]
        );
    }
}
