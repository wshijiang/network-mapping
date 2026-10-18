pub use super::template_render::{Source, context, render};
use super::template_render::{VARIABLES, default_source, validate_source};
use super::{AuditContext, AuditEvent, EVENT_TYPES, Error, Pool, Result, UserBaseI};
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use serde::Deserialize;
use serde_json::{Value, json};

fn validate_key(provider: &str, event: &str) -> Result<()> {
    if !matches!(provider, "feishu" | "telegram") || !EVENT_TYPES.contains(&event) {
        return Err(Error::bad("通知模板渠道或事件无效"));
    }
    Ok(())
}

pub async fn detail(pool: &Pool, provider: &str, event: &str) -> Result<Value> {
    validate_key(provider, event)?;
    let mut c = pool.get().await?;
    let tx = c
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .start()
        .await?;
    let head = tx.query_opt("SELECT revision,active_version FROM notification_template WHERE provider=$1 AND event_type=$2", &[&provider,&event]).await?;
    let revision = head
        .as_ref()
        .map(|r| r.get::<_, i64>("revision"))
        .unwrap_or(0);
    let active = head
        .as_ref()
        .and_then(|r| r.get::<_, Option<i32>>("active_version"));
    let rows = tx.query("SELECT version,status,source,created_at,published_at FROM notification_template_version WHERE provider=$1 AND event_type=$2 ORDER BY version DESC", &[&provider,&event]).await?;
    let selected = rows
        .iter()
        .find(|r| r.get::<_, String>("status") == "draft")
        .or_else(|| {
            rows.iter()
                .find(|r| Some(r.get::<_, i32>("version")) == active)
        });
    let source = selected
        .map(|r| r.get::<_, Value>("source"))
        .unwrap_or_else(|| json!(default_source()));
    let status = selected
        .map(|r| r.get::<_, String>("status"))
        .unwrap_or_else(|| "default".into());
    let versions: Vec<_> = rows.iter().map(|r| json!({"version":r.get::<_,i32>("version"),"status":r.get::<_,String>("status"),"createdAt":r.get::<_,chrono::DateTime<chrono::Utc>>("created_at"),"publishedAt":r.get::<_,Option<chrono::DateTime<chrono::Utc>>>("published_at")})).collect();
    tx.commit().await?;
    Ok(
        json!({"provider":provider,"eventType":event,"revision":revision,"activeVersion":active,"status":status,"source":source,"defaultSource":default_source(),"variables":VARIABLES,"versions":versions}),
    )
}

/// No saved publication means the legacy plain-text template, including after saving a draft.
pub async fn published(pool: &Pool, provider: &str, event: &str) -> Result<Source> {
    if event == "notification.test" {
        return Ok(default_source());
    }
    validate_key(provider, event)?;
    let c = pool.get().await?;
    let row = c.query_opt("SELECT v.source FROM notification_template t JOIN notification_template_version v ON v.provider=t.provider AND v.event_type=t.event_type AND v.version=t.active_version WHERE t.provider=$1 AND t.event_type=$2 AND v.status='published'", &[&provider,&event]).await?;
    row.map(|r| serde_json::from_value(r.get(0)).map_err(|_| Error::bad("已发布通知模板无效")))
        .unwrap_or_else(|| Ok(default_source()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Change {
    expected_revision: i64,
    source: Option<Source>,
    version: Option<i32>,
}

pub async fn change(
    pool: &Pool,
    provider: &str,
    event: &str,
    action: &str,
    input: Change,
    user: &UserBaseI,
    audit: &AuditContext,
) -> Result<Value> {
    validate_key(provider, event)?;
    if !matches!(action, "draft" | "publish" | "restore") {
        return Err(Error::bad("模板操作无效"));
    }
    // Validate before taking locks. Only fixed, public sample data is accepted by preview/save.
    if action == "draft" {
        validate_source(
            provider,
            input
                .source
                .as_ref()
                .ok_or_else(|| Error::bad("缺少模板内容"))?,
            event,
        )?;
    }
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    tx.execute("INSERT INTO notification_template(provider,event_type) VALUES($1,$2) ON CONFLICT DO NOTHING", &[&provider,&event]).await?;
    let revision: i64 = tx.query_one("SELECT revision FROM notification_template WHERE provider=$1 AND event_type=$2 FOR UPDATE", &[&provider,&event]).await?.get(0);
    if revision != input.expected_revision {
        return Err(Error::conflict());
    }
    if action == "publish" {
        let row = tx.query_opt("SELECT version,source FROM notification_template_version WHERE provider=$1 AND event_type=$2 AND status='draft'", &[&provider,&event]).await?.ok_or_else(|| Error::bad("没有可发布的草稿"))?;
        let source: Source =
            serde_json::from_value(row.get(1)).map_err(|_| Error::bad("模板内容无效"))?;
        validate_source(provider, &source, event)?;
        let version: i32 = row.get(0);
        tx.execute("UPDATE notification_template_version SET status='archived' WHERE provider=$1 AND event_type=$2 AND status='published'", &[&provider,&event]).await?;
        tx.execute("UPDATE notification_template_version SET status='published',published_at=NOW() WHERE provider=$1 AND event_type=$2 AND version=$3", &[&provider,&event,&version]).await?;
        tx.execute("UPDATE notification_template SET active_version=$3 WHERE provider=$1 AND event_type=$2", &[&provider,&event,&version]).await?;
    } else {
        let source = if action == "restore" {
            let version = input.version.ok_or_else(|| Error::bad("缺少历史版本"))?;
            let row = tx.query_opt("SELECT source FROM notification_template_version WHERE provider=$1 AND event_type=$2 AND version=$3 AND status<>'draft'", &[&provider,&event,&version]).await?.ok_or_else(|| Error::bad("历史版本不存在"))?;
            serde_json::from_value(row.get(0)).map_err(|_| Error::bad("历史版本内容无效"))?
        } else {
            input.source.unwrap()
        };
        validate_source(provider, &source, event)?;
        let version: i32 = tx.query_one("SELECT COALESCE(MAX(version),0)+1 FROM notification_template_version WHERE provider=$1 AND event_type=$2", &[&provider,&event]).await?.get(0);
        tx.execute("UPDATE notification_template_version SET status='archived' WHERE provider=$1 AND event_type=$2 AND status='draft'", &[&provider,&event]).await?;
        tx.execute("INSERT INTO notification_template_version(provider,event_type,version,status,source,created_by) VALUES($1,$2,$3,'draft',$4,$5)", &[&provider,&event,&version,&json!(source),&user.id]).await?;
    }
    tx.execute(
        "UPDATE notification_template SET revision=revision+1 WHERE provider=$1 AND event_type=$2",
        &[&provider, &event],
    )
    .await?;
    let audit_event = AuditEvent::user(
        "configuration",
        &format!("notification.template_{action}"),
        "success",
        user,
    )
    .resource("notification_template", format!("{provider}:{event}"));
    crate::audit::write(&tx, audit, &audit_event).await?;
    tx.commit().await?;
    drop(c);
    detail(pool, provider, event).await
}

fn respond<T: serde::Serialize>(result: Result<T>) -> HttpResponse {
    match result {
        Ok(data) => HttpResponse::Ok().json(json!({"success":true,"data":data})),
        Err(e) => HttpResponse::build(e.status).json(json!({"success":false,"message":e.message})),
    }
}
fn forbidden(user: &UserBaseI) -> Option<HttpResponse> {
    (user.role != 1).then(|| {
        HttpResponse::Forbidden()
            .json(json!({"success":false,"message":"仅管理员可以管理通知模板"}))
    })
}
#[get("/templates/{provider}/{event}")]
async fn get_detail(
    pool: web::Data<Pool>,
    user: UserBaseI,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    if let Some(r) = forbidden(&user) {
        return r;
    }
    let (provider, event) = path.into_inner();
    respond(detail(&pool, &provider, &event).await)
}
#[post("/templates/{provider}/{event}/preview")]
async fn preview(
    user: UserBaseI,
    path: web::Path<(String, String)>,
    source: web::Json<Source>,
) -> HttpResponse {
    if let Some(r) = forbidden(&user) {
        return r;
    }
    let (provider, event) = path.into_inner();
    respond(
        validate_key(&provider, &event).and_then(|_| validate_source(&provider, &source, &event)),
    )
}
#[post("/templates/{provider}/{event}/{action}")]
async fn mutate(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    path: web::Path<(String, String, String)>,
    input: web::Json<Change>,
) -> HttpResponse {
    if let Some(r) = forbidden(&user) {
        return r;
    }
    let (provider, event, action) = path.into_inner();
    respond(
        change(
            &pool,
            &provider,
            &event,
            &action,
            input.into_inner(),
            &user,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(get_detail).service(preview).service(mutate);
}
