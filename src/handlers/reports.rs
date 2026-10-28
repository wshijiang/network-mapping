use actix_web::{HttpRequest, HttpResponse, get, post, put, web};
use chrono::{NaiveDate, Utc};
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::error;
use uuid::Uuid;

use crate::{
    admin::UserBaseI,
    audit::{self, AuditContext, AuditEvent},
    config::AnalyticsSnapshotConfig,
    reports::{
        period::{Period, PeriodType},
        storage::{self, Report},
    },
    runtime_config::RuntimeConfig,
};

fn admin(req: &HttpRequest, pool: &Pool, user: &UserBaseI, action: &str) -> bool {
    if user.role == 1 {
        return true;
    }
    let mut event = AuditEvent::user("authorization", action, "denied", user);
    event.response_status = Some(403);
    event.reason_code = Some("administrator_required".into());
    let context = AuditContext::from_request(req);
    let pool = pool.clone();
    tokio::spawn(async move {
        audit::write_standalone(&pool, &context, &event).await;
    });
    false
}
fn denied() -> HttpResponse {
    HttpResponse::Forbidden().json(json!({"success": false, "message": "仅管理员可以访问平台报告"}))
}
fn bad(message: &str) -> HttpResponse {
    HttpResponse::BadRequest().json(json!({"success": false, "message": message}))
}
fn conflict(message: &str) -> HttpResponse {
    HttpResponse::Conflict().json(json!({"success": false, "message": message}))
}
fn missing() -> HttpResponse {
    HttpResponse::NotFound().json(json!({"success": false, "message": "报告不存在"}))
}
fn internal(error: impl std::fmt::Display) -> HttpResponse {
    error!(event = "ReportApiFailed", error = %error);
    HttpResponse::InternalServerError()
        .json(json!({"success": false, "message": "报告服务暂时不可用，请稍后重试"}))
}
async fn record(req: &HttpRequest, pool: &Pool, user: &UserBaseI, action: &str, id: impl ToString) {
    audit::write_standalone(
        pool,
        &AuditContext::from_request(req),
        &AuditEvent::user("data_access", action, "success", user)
            .resource("report", id.to_string()),
    )
    .await;
}

#[derive(Deserialize)]
pub(crate) struct ListQuery {
    page: Option<i64>,
    page_size: Option<i64>,
    period_type: Option<PeriodType>,
}
#[get("/api/reports")]
pub(crate) async fn list(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    query: web::Query<ListQuery>,
) -> HttpResponse {
    if !admin(&req, &pool, &user, "report.query") {
        return denied();
    }
    let page = query.page.unwrap_or(1).clamp(1, 1_000_000);
    let limit = query.page_size.unwrap_or(20).clamp(1, 100);
    let kind = query.period_type.map(|p| p.as_str());
    let result = async {
        let client = pool.get().await.map_err(|e| e.to_string())?;
        let total: i64 = client.query_one("SELECT COUNT(*)::BIGINT AS count FROM report_run WHERE ($1::TEXT IS NULL OR period_type = $1);", &[&kind]).await.map_err(|e| e.to_string())?.get("count");
        let rows = client.query("SELECT id, period_type, period_start, period_end, revision, source, status, cutoff_at, created_at, generated_at, timezone, settings_revision, supersedes_report_id, quality, last_error, content_checksum \
            FROM report_run WHERE ($1::TEXT IS NULL OR period_type = $1) ORDER BY period_start DESC, created_at DESC LIMIT $2 OFFSET $3;", &[&kind, &limit, &((page - 1) * limit)]).await.map_err(|e| e.to_string())?;
        Ok::<_, String>(json!({"items": rows.into_iter().map(|r| Report::from_row(r, false)).collect::<Vec<_>>(), "total": total, "page": page, "page_size": limit}))
    }.await;
    match result {
        Ok(data) => HttpResponse::Ok().json(json!({"success": true, "data": data})),
        Err(e) => internal(e),
    }
}

#[get("/api/reports/{id}")]
pub(crate) async fn detail(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    if !admin(&req, &pool, &user, "report.query") {
        return denied();
    }
    let result = async {
        let client = pool.get().await.map_err(|e| e.to_string())?;
        client
            .query_opt("SELECT r.*, (SELECT jsonb_build_object('expires_at', a.expires_at, 'revoked_at', a.revoked_at, 'renderer_version', a.renderer_version) FROM report_mail_asset a WHERE a.report_id = r.id) AS mail_image FROM report_run r WHERE r.id = $1;", &[&*id])
            .await
            .map_err(|e| e.to_string())
    }
    .await;
    match result {
        Ok(Some(row)) => {
            HttpResponse::Ok().json(json!({"success": true, "data": Report::from_row(row, true)}))
        }
        Ok(None) => missing(),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
pub(crate) struct GenerateRequest {
    period_type: PeriodType,
    date: Option<NaiveDate>,
}
#[post("/api/reports/generate")]
pub(crate) async fn generate(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    body: web::Json<GenerateRequest>,
) -> HttpResponse {
    if !admin(&req, &pool, &user, "report.generate") {
        return denied();
    }
    let calendar = match crate::system_time::refresh(&pool).await {
        Ok(value) => value,
        Err(e) => return internal(e),
    };
    let tz = match calendar.document.timezone.parse::<chrono_tz::Tz>() {
        Ok(tz) => tz,
        Err(e) => return internal(e),
    };
    let period = match body.date.map_or_else(
        || {
            Period::containing_in(
                body.period_type,
                Utc::now().with_timezone(&tz).date_naive(),
                &calendar.document.timezone,
                calendar.revision,
            )
            .and_then(|p| p.previous())
        },
        |date| {
            Period::containing_in(
                body.period_type,
                date,
                &calendar.document.timezone,
                calendar.revision,
            )
        },
    ) {
        Ok(p) => p,
        Err(e) => return bad(&e),
    };
    if let Err(e) = period.validate_closed(Utc::now()) {
        return bad(&e);
    }
    match storage::create(&pool, &period, Some(user.id), "manual", None).await {
        Ok(id) => {
            record(&req, &pool, &user, "report.generate", id).await;
            HttpResponse::Accepted().json(json!({"success": true, "data": {"id": id}, "message": "报告已加入生成队列；重复周期返回原报告"}))
        }
        Err(e) => internal(e),
    }
}

#[post("/api/reports/{id}/revisions")]
pub(crate) async fn revise(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    if !admin(&req, &pool, &user, "report.revise") {
        return denied();
    }
    let result = async {
        let client = pool.get().await.map_err(|e| e.to_string())?;
        let row = client
            .query_opt(
                "SELECT period_type, period_start, period_end, timezone, settings_revision FROM report_run WHERE id = $1;",
                &[&*id],
            )
            .await
            .map_err(|e| e.to_string())?;
        let Some(row) = row else {
            return Ok(None);
        };
        Ok::<_, String>(Some(Period {
            timezone: row.get("timezone"),
            settings_revision: row.get("settings_revision"),
            kind: PeriodType::parse(&row.get::<_, String>("period_type"))?,
            start: row.get("period_start"),
            end: row.get("period_end"),
        }))
    }
    .await;
    let period = match result {
        Ok(Some(period)) => period,
        Ok(None) => return missing(),
        Err(e) => return internal(e),
    };
    if let Err(e) = period.validate_closed(Utc::now()) {
        return bad(&e);
    }
    match storage::create(&pool, &period, Some(user.id), "revision", Some(*id)).await {
        Ok(revision_id) => {
            record(&req, &pool, &user, "report.revise", revision_id).await;
            HttpResponse::Accepted().json(json!({"success": true, "data": {"id": revision_id}}))
        }
        Err(e) => internal(e),
    }
}

#[post("/api/reports/{id}/retry")]
pub(crate) async fn retry(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    if !admin(&req, &pool, &user, "report.retry") {
        return denied();
    }
    let result = async {
        let mut client = pool.get().await.map_err(|e| e.to_string())?; let tx = client.transaction().await.map_err(|e| e.to_string())?;
        let count = tx.execute("UPDATE report_job SET status = 'pending', attempts = 0, available_at = NOW(), wait_deadline = NOW() + INTERVAL '24 hours', last_error = NULL \
            WHERE report_id = $1 AND status = 'failed';", &[&*id]).await.map_err(|e| e.to_string())?;
        if count > 0 { tx.execute("UPDATE report_run SET status = 'queued', last_error = NULL WHERE id = $1 AND status = 'failed';", &[&*id]).await.map_err(|e| e.to_string())?; }
        tx.commit().await.map_err(|e| e.to_string())?; Ok::<_, String>(count)
    }.await;
    match result {
        Ok(0) => conflict("仅失败的报告可以重试；修正输入数据请创建修订版"),
        Ok(_) => {
            record(&req, &pool, &user, "report.retry", *id).await;
            HttpResponse::Accepted().json(json!({"success": true}))
        }
        Err(e) => internal(e),
    }
}

#[get("/api/report-schedules")]
pub(crate) async fn schedules(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    analytics: web::Data<RuntimeConfig<AnalyticsSnapshotConfig>>,
) -> HttpResponse {
    if !admin(&req, &pool, &user, "report.schedule.query") {
        return denied();
    }
    match storage::schedules(&pool).await {
        Ok(mut data) => {
            data["analytics_ready"] = json!(analytics.get().await.value.mode.runs_worker());
            let client = match pool.get().await {
                Ok(client) => client,
                Err(e) => return internal(e),
            };
            match crate::reports::mail_config::load(&client).await {
                Ok(settings) => data["mail_images_ready"] = json!(settings.remote_images_enabled),
                Err(e) => return internal(e),
            }
            drop(client);
            match crate::admin::get_mail_settings_from_database(&pool).await {
                Ok(settings) => {
                    data["mail_ready"] = json!(
                        !settings.smtp_host.trim().is_empty()
                            && !settings.sender.trim().is_empty()
                            && settings.sender_key_configured
                    );
                }
                Err(e) => return internal(e),
            }
            let channels = match crate::notification::list(&pool).await {
                Ok(channels) => channels,
                Err(_) => return internal("通知渠道暂不可用"),
            };
            let subscribed = |topic: &str| {
                channels.iter().any(|channel| {
                    channel.enabled
                        && channel.minimum_severity == "warning"
                        && channel.event_types.iter().any(|event| event == topic)
                })
            };
            data["notifications"] = json!({"weekly":subscribed("report.weekly"),"monthly":subscribed("report.monthly")});
            data["bot_channels"] = json!(
                channels
                    .iter()
                    .filter(|channel| matches!(channel.provider.as_str(), "feishu" | "telegram"))
                    .map(|channel| json!({
                        "id":channel.id, "name":channel.name, "provider":channel.provider,
                        "enabled":channel.enabled, "minimum_severity":channel.minimum_severity,
                        "revision":channel.revision, "event_types":channel.event_types,
                    }))
                    .collect::<Vec<_>>()
            );
            HttpResponse::Ok().json(json!({"success": true, "data": data}))
        }
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
pub(crate) struct ScheduleChannel {
    id: Uuid,
    revision: i64,
    selected: bool,
}
#[derive(Deserialize)]
pub(crate) struct ScheduleRequest {
    enabled: bool,
    send_hour: i16,
    send_minute: i16,
    recipient_ids: Vec<i32>,
    expected_revision: i64,
    #[serde(default)]
    bot_channels: Option<Vec<ScheduleChannel>>,
}
#[put("/api/report-schedules/{kind}")]
pub(crate) async fn save_schedule(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    kind: web::Path<PeriodType>,
    body: web::Json<ScheduleRequest>,
    analytics: web::Data<RuntimeConfig<AnalyticsSnapshotConfig>>,
) -> HttpResponse {
    if !admin(&req, &pool, &user, "report.schedule.update") {
        return denied();
    }
    if !(0..=23).contains(&body.send_hour)
        || !(0..=59).contains(&body.send_minute)
        || body.recipient_ids.len() > 100
        || body.recipient_ids.iter().any(|id| *id <= 0)
        || body.bot_channels.as_ref().is_some_and(|channels| {
            channels.len() > 32
                || channels.iter().any(|c| c.revision < 1)
                || channels
                    .iter()
                    .map(|c| c.id)
                    .collect::<std::collections::HashSet<_>>()
                    .len()
                    != channels.len()
        })
    {
        return bad("发送时间或收件人列表无效");
    }
    if body.enabled && !analytics.get().await.value.mode.runs_worker() {
        return conflict("请先在运行时配置中启用 shadow 或 snapshot 分析快照模式");
    }
    let mut selected = body.recipient_ids.clone();
    selected.sort_unstable();
    selected.dedup();
    let result = async {
        let mut client = pool.get().await.map_err(|e| e.to_string())?; let tx = client.transaction().await.map_err(|e| e.to_string())?;
        if body.enabled && !selected.is_empty() {
            let valid = storage::recipients(&tx, &selected).await?;
            if valid.is_empty() || (!selected.is_empty() && valid.len() != selected.len()) { return Ok::<_, String>(Some(bad("收件人必须是有有效邮箱的启用中管理员"))); }
        }
        let key = kind.as_str();
        // Match report creation's lock order: schedule before notification channels.
        let count = tx.execute("UPDATE report_schedule SET enabled = $2, send_hour = $3, send_minute = $4, recipient_ids = $5, \
            enabled_at = CASE WHEN $2 AND NOT enabled THEN NOW() ELSE enabled_at END, \
            last_period_end = CASE WHEN $2 AND NOT enabled THEN NULL ELSE last_period_end END, revision = revision + 1, updated_at = NOW() \
            WHERE period_type = $1 AND revision = $6;", &[&key, &body.enabled, &body.send_hour, &body.send_minute, &selected, &body.expected_revision]).await.map_err(|e| e.to_string())?;
        if count == 0 { return Ok(Some(conflict("计划已被其他管理员更新，请重新加载"))); }
        let topic = format!("report.{key}");
        let mut changes = Vec::new();
        if let Some(channels) = &body.bot_channels {
            let mut ordered: Vec<_> = channels.iter().collect();
            ordered.sort_by_key(|channel| channel.id);
            for requested in ordered {
                let row = tx.query_opt("SELECT revision,enabled,minimum_severity,event_types FROM notification_channel WHERE id=$1 AND deleted_at IS NULL AND provider IN ('feishu','telegram') FOR UPDATE", &[&requested.id]).await.map_err(|e|e.to_string())?;
                let Some(row) = row else { return Ok(Some(conflict("通知渠道已变化，请刷新后重试"))); };
                if row.get::<_,i64>("revision") != requested.revision || !row.get::<_,bool>("enabled") || row.get::<_,String>("minimum_severity") != "warning" { return Ok(Some(conflict("通知渠道已变化或不可用于报告，请刷新后重试"))); }
                let mut events: Vec<String> = row.get("event_types");
                let subscribed = events.contains(&topic);
                if subscribed == requested.selected { continue; }
                if requested.selected { events.push(topic.clone()); } else { events.retain(|event| event != &topic); }
                tx.execute("UPDATE notification_channel SET event_types=$2,revision=revision+1,updated_at=NOW() WHERE id=$1", &[&requested.id,&events]).await.map_err(|e|e.to_string())?;
                if !requested.selected {
                    tx.execute("UPDATE notification_delivery d SET status='cancelled',last_error='channel_changed',finished_at=NOW(),claim_token=NULL,lease_until=NULL FROM notification_event e WHERE d.event_id=e.id AND d.channel_id=$1 AND e.event_type=$2 AND e.context->>'manual_report' IS DISTINCT FROM 'true' AND d.status IN ('pending','sending')", &[&requested.id,&topic]).await.map_err(|e|e.to_string())?;
                }
                changes.push(json!({"channel_id":requested.id,"selected":requested.selected}));
            }
        }
        let mut event = AuditEvent::user("configuration", "report.schedule.update", "success", &user).resource("report_schedule", key);
        event.changes = Some(json!({"enabled": body.enabled, "send_hour": body.send_hour, "send_minute": body.send_minute, "recipient_ids": selected, "bot_channels":changes}));
        audit::write(&tx, &AuditContext::from_request(&req), &event).await.map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?; Ok(None)
    }.await;
    match result {
        Ok(Some(response)) => response,
        Ok(None) => HttpResponse::Ok().json(json!({"success": true})),
        Err(e) => internal(e),
    }
}

#[get("/api/reports/{id}/deliveries")]
pub(crate) async fn deliveries(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    if !admin(&req, &pool, &user, "report.delivery.query") {
        return denied();
    }
    let result = async { let client = pool.get().await.map_err(|e| e.to_string())?;
        let rows = client.query("SELECT * FROM report_delivery WHERE report_id = $1 ORDER BY created_at DESC, recipient_user_id;", &[&*id]).await.map_err(|e| e.to_string())?;
        let mut items: Vec<Value> = rows.iter().map(|r| json!({"id": r.get::<_, Uuid>("id"), "recipient": r.get::<_, String>("recipient"), "status": r.get::<_, String>("status"),
            "attempts": r.get::<_, i32>("attempts"), "dispatch_seq": r.get::<_, i32>("dispatch_seq"), "created_at": r.get::<_, chrono::DateTime<Utc>>("created_at"),
            "sent_at": r.get::<_, Option<chrono::DateTime<Utc>>>("sent_at"), "last_error": r.get::<_, Option<String>>("last_error")})).collect();
        let notifications = client.query("SELECT d.id,c.name,c.provider,d.status,d.attempts,d.created_at,d.finished_at,d.last_error FROM notification_delivery d JOIN notification_event e ON e.id=d.event_id JOIN notification_channel c ON c.id=d.channel_id WHERE e.context->>'report_id'=$1 AND c.provider IN ('feishu','telegram') ORDER BY d.created_at DESC LIMIT 200", &[&id.to_string()]).await.map_err(|e| e.to_string())?;
        items.extend(notifications.iter().map(|r| json!({"id":r.get::<_,Uuid>("id"),"recipient":format!("{} · {}",r.get::<_,String>("provider"),r.get::<_,String>("name")),"status":r.get::<_,String>("status"),"attempts":r.get::<_,i32>("attempts"),"dispatch_seq":0,"created_at":r.get::<_,chrono::DateTime<Utc>>("created_at"),"sent_at":r.get::<_,Option<chrono::DateTime<Utc>>>("finished_at"),"last_error":r.get::<_,Option<String>>("last_error")})));
        items.sort_by(|a,b| b["created_at"].as_str().cmp(&a["created_at"].as_str()));
        Ok::<_, String>(items) }.await;
    match result {
        Ok(items) => HttpResponse::Ok().json(json!({"success": true, "data": items})),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
pub(crate) struct SendRequest {
    #[serde(default)]
    recipient_ids: Vec<i32>,
    #[serde(default)]
    channel_ids: Vec<Uuid>,
}
#[post("/api/reports/{id}/deliveries")]
pub(crate) async fn send(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
    body: web::Json<SendRequest>,
) -> HttpResponse {
    if !admin(&req, &pool, &user, "report.delivery.send") {
        return denied();
    }
    if (body.recipient_ids.is_empty() && body.channel_ids.is_empty())
        || body.recipient_ids.len() > 100
        || body.channel_ids.len() > 32
    {
        return bad("请选择收件人或通知渠道");
    }
    let result = async {
        let mut client = pool.get().await.map_err(|e| e.to_string())?; let tx = client.transaction().await.map_err(|e| e.to_string())?;
        let row = tx.query_opt("SELECT status, rendered_mail,period_type FROM report_run WHERE id = $1 FOR UPDATE;", &[&*id]).await.map_err(|e| e.to_string())?;
        let Some(row) = row else { return Ok::<_, String>(missing()); };
        if row.get::<_, String>("status") != "ready" { return Ok(conflict("报告尚未生成完成")); }
        if !body.recipient_ids.is_empty() && row.get::<_, Option<Value>>("rendered_mail").is_none() { return Ok(conflict("当前报告没有可发送的邮件内容，请检查模板后创建修订版")); }
        if !body.recipient_ids.is_empty() && tx.query_opt("SELECT report_id FROM report_mail_asset WHERE report_id = $1 AND revoked_at IS NOT NULL", &[&*id]).await.map_err(|e| e.to_string())?.is_some() { return Ok(conflict("报告趋势图片已撤销，请生成修订版后发送")); }
        let mut selected = body.recipient_ids.clone(); selected.sort_unstable(); selected.dedup();
        if !selected.is_empty() && storage::recipients(&tx, &selected).await?.len() != selected.len() { return Ok(bad("收件人必须是有有效邮箱的启用中管理员")); }
        let active: bool = tx.query_one("SELECT EXISTS (SELECT 1 FROM report_delivery WHERE report_id = $1 AND status IN ('pending','sending')) AS active;", &[&*id]).await.map_err(|e| e.to_string())?.get("active");
        if active && !selected.is_empty() { return Ok(conflict("已有待投递邮件，请等待投递完成后再重发")); }
        let count = if selected.is_empty() { 0 } else { storage::enqueue_delivery(&tx, *id, &selected, false, true).await? };
        let mut channels = body.channel_ids.clone(); channels.sort_unstable(); channels.dedup();
        if !channels.is_empty() {
            let destinations = tx.query("SELECT id,destination_revision FROM notification_channel WHERE id=ANY($1) AND enabled AND deleted_at IS NULL AND provider IN ('feishu','telegram') FOR SHARE", &[&channels]).await.map_err(|e|e.to_string())?;
            if destinations.len() != channels.len() { return Ok(bad("通知渠道不存在、已停用或类型无效")); }
            let event_id = Uuid::now_v7();
            let event_type = format!("report.{}", row.get::<_,String>("period_type"));
            let context = json!({"report_id":*id,"manual_report":true});
            tx.execute("INSERT INTO notification_event(id,dedup_key,event_type,severity,title,body,context) VALUES($1,$2,$3,'warning','手动发送报告','请登录平台查看报告',$4)", &[&event_id,&format!("report-manual:{event_id}"),&event_type,&context]).await.map_err(|e|e.to_string())?;
            for destination in destinations {
                let cid: Uuid = destination.get("id"); let revision: i64 = destination.get("destination_revision");
                tx.execute("INSERT INTO notification_delivery(id,event_id,channel_id,destination_revision) VALUES($1,$2,$3,$4)", &[&Uuid::now_v7(),&event_id,&cid,&revision]).await.map_err(|e|e.to_string())?;
            }
        }
        let mut audit_event = AuditEvent::user("data_access", "report.delivery.send", "success", &user).resource("report", id.to_string());
        audit_event.metadata = json!({"recipient_ids": selected, "channel_ids": channels});
        audit::write(&tx, &AuditContext::from_request(&req), &audit_event).await.map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(HttpResponse::Accepted().json(json!({"success": true, "data": {"recipients": count,"channels":channels.len()}})))
    }.await;
    match result {
        Ok(response) => response,
        Err(e) => internal(e),
    }
}
