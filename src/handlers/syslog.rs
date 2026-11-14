//! Syslog 转发管理接口：实时状态、连通性测试、转发统计。
//! 配置读写复用 `/api/config/runtime/syslog`（见 handlers::utils）。

use actix_web::{HttpRequest, HttpResponse, Responder, get, post, web};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write_standalone};
use crate::runtime_config::RuntimeSettings;
use crate::syslog::config::{Protocol, TargetConfig, TlsOptions, validate_target};
use crate::syslog::forwarder::{capture, send_test};
use crate::syslog::metrics::{self, StatsQuery};
use crate::syslog::status::StatusRegistry;

fn forbidden() -> HttpResponse {
    HttpResponse::Forbidden()
        .json(json!({"success": false, "message": "仅管理员可以管理 Syslog 转发"}))
}

#[get("/api/syslog/status")]
pub(crate) async fn syslog_status(
    settings: web::Data<RuntimeSettings>,
    registry: web::Data<StatusRegistry>,
    user: UserBaseI,
) -> impl Responder {
    if user.role != 1 {
        return forbidden();
    }
    let snapshot = settings.syslog.get().await;
    let config = snapshot.value;
    let handle = capture();
    let targets: Vec<_> = config
        .targets
        .iter()
        .map(|target| {
            let status = registry.get(target.id);
            json!({
                "id": target.id,
                "name": target.name,
                "host": target.host,
                "port": target.port,
                "protocol": target.protocol.as_str(),
                "enabled": target.enabled,
                "state": status.as_ref().map(|s| s.state.clone()).unwrap_or_else(|| {
                    if config.enabled && target.enabled { "connecting".to_owned() } else { "disabled".to_owned() }
                }),
                "sent": status.as_ref().map(|s| s.sent).unwrap_or(0),
                "failed": status.as_ref().map(|s| s.failed).unwrap_or(0),
                "dropped": status.as_ref().map(|s| s.dropped).unwrap_or(0),
                "lastSuccessAt": status.as_ref().and_then(|s| s.last_success_at),
                "lastErrorAt": status.as_ref().and_then(|s| s.last_error_at),
                "lastError": status.as_ref().map(|s| s.last_error.clone()).unwrap_or_default(),
                "updatedAt": status.as_ref().and_then(|s| s.updated_at),
            })
        })
        .collect();
    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {
            "enabled": config.enabled,
            "revision": snapshot.revision,
            "queue": {
                "capacity": config.queue_capacity,
                "enqueueDrops": handle.enqueue_drops(),
            },
            "targets": targets,
        }
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SyslogTestRequest {
    /// 已保存目标的 ID；提供时忽略其余字段。
    target_id: Option<Uuid>,
    host: Option<String>,
    port: Option<u16>,
    protocol: Option<Protocol>,
    tls: Option<TlsOptions>,
}

#[post("/api/syslog/test")]
pub(crate) async fn syslog_test(
    req: HttpRequest,
    settings: web::Data<RuntimeSettings>,
    pool: web::Data<deadpool_postgres::Pool>,
    user: UserBaseI,
    body: web::Json<SyslogTestRequest>,
) -> impl Responder {
    if user.role != 1 {
        return forbidden();
    }
    let snapshot = settings.syslog.get().await;
    let config = snapshot.value;
    let target = if let Some(target_id) = body.target_id {
        match config.targets.iter().find(|target| target.id == target_id) {
            Some(target) => target.clone(),
            None => {
                return HttpResponse::NotFound()
                    .json(json!({"success": false, "message": "未找到该 Syslog 服务器"}));
            }
        }
    } else {
        let protocol = body.protocol.unwrap_or_default();
        let candidate = TargetConfig {
            id: Uuid::now_v7(),
            name: "connectivity-test".to_owned(),
            host: body.host.clone().unwrap_or_default(),
            port: body.port.unwrap_or_else(|| protocol.default_port()),
            protocol,
            enabled: true,
            tls: body.tls.clone().unwrap_or_default(),
        };
        if let Err(message) = validate_target(&candidate) {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
        candidate
    };

    let result = send_test(&target, config.facility.code(), &config.app_name).await;
    let (ok, latency_ms, error) = match &result {
        Ok(latency) => (true, Some(*latency), String::new()),
        Err(error) => (false, None, error.clone()),
    };

    let mut event = AuditEvent::user(
        "configuration",
        "syslog_test",
        if ok { "success" } else { "failure" },
        &user,
    )
    .resource("syslog_target", target.id.to_string());
    event.metadata = json!({
        "host": target.host,
        "port": target.port,
        "protocol": target.protocol.as_str(),
        "success": ok,
        "error": error,
    });
    write_standalone(pool.get_ref(), &AuditContext::from_request(&req), &event).await;

    HttpResponse::Ok().json(json!({
        "success": true,
        "data": { "success": ok, "latencyMs": latency_ms, "error": error }
    }))
}

#[derive(Debug, Deserialize)]
struct SyslogStatsQuery {
    window: Option<String>,
    granularity: Option<String>,
    target_id: Option<Uuid>,
}

#[get("/api/syslog/statistics")]
pub(crate) async fn syslog_statistics(
    query: web::Query<SyslogStatsQuery>,
    pool: web::Data<deadpool_postgres::Pool>,
    user: UserBaseI,
) -> impl Responder {
    if user.role != 1 {
        return forbidden();
    }
    let window = query.window.as_deref().unwrap_or("24h");
    let Some((start, end)) = metrics::window_range(window) else {
        return HttpResponse::BadRequest()
            .json(json!({"success": false, "message": "window 必须为 1h/24h/7d"}));
    };
    let bucket_seconds =
        match metrics::resolve_granularity(query.granularity.as_deref(), start, end) {
            Ok(seconds) => seconds,
            Err(message) => {
                return HttpResponse::BadRequest()
                    .json(json!({"success": false, "message": message}));
            }
        };
    let stats_query = StatsQuery {
        start,
        end,
        bucket_seconds,
        target_id: query.target_id,
    };
    match metrics::query(pool.get_ref(), &stats_query).await {
        Ok((summary, trend)) => HttpResponse::Ok().json(json!({
            "success": true,
            "data": {
                "window": window,
                "granularity": bucket_seconds,
                "start": start,
                "end": end,
                "summary": summary,
                "trend": trend,
            }
        })),
        Err(error) => {
            tracing::error!(
                event = "SyslogStatisticsError",
                operation = "query_syslog_statistics",
                error_message = %error,
                "syslog 统计查询失败"
            );
            HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "Syslog 统计查询失败"}))
        }
    }
}

// ---- 历史日志回填（仅用户手动下发） ----

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BackfillCreateRequest {
    /// 「N 天前至今」，默认 7 天；提供 start/end 时忽略。
    days: Option<i64>,
    start: Option<chrono::DateTime<chrono::Utc>>,
    end: Option<chrono::DateTime<chrono::Utc>>,
}

#[post("/api/syslog/backfill")]
pub(crate) async fn syslog_backfill_create(
    req: HttpRequest,
    pool: web::Data<deadpool_postgres::Pool>,
    user: UserBaseI,
    body: web::Json<BackfillCreateRequest>,
) -> impl Responder {
    if user.role != 1 {
        return forbidden();
    }
    let (start, end) = match crate::syslog::backfill::resolve_range(body.days, body.start, body.end)
    {
        Ok(range) => range,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    match crate::syslog::backfill::create_job(pool.get_ref(), Some(user.id), start, end).await {
        Ok(id) => {
            let mut event =
                AuditEvent::user("configuration", "syslog_backfill_create", "success", &user)
                    .resource("syslog_backfill_job", id.to_string());
            event.metadata = json!({"rangeStart": start, "rangeEnd": end});
            write_standalone(pool.get_ref(), &AuditContext::from_request(&req), &event).await;
            HttpResponse::Ok().json(json!({
                "success": true,
                "data": { "id": id, "rangeStart": start, "rangeEnd": end }
            }))
        }
        Err(message) => {
            HttpResponse::BadRequest().json(json!({"success": false, "message": message}))
        }
    }
}

#[get("/api/syslog/backfill")]
pub(crate) async fn syslog_backfill_list(
    pool: web::Data<deadpool_postgres::Pool>,
    user: UserBaseI,
) -> impl Responder {
    if user.role != 1 {
        return forbidden();
    }
    match crate::syslog::backfill::list_jobs(pool.get_ref(), 20).await {
        Ok(jobs) => HttpResponse::Ok().json(json!({"success": true, "data": jobs})),
        Err(error) => {
            tracing::error!(
                event = "SyslogBackfillListError",
                operation = "list_syslog_backfill_jobs",
                error_message = %error,
                "回填任务列表查询失败"
            );
            HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "回填任务列表查询失败"}))
        }
    }
}

#[post("/api/syslog/backfill/{id}/cancel")]
pub(crate) async fn syslog_backfill_cancel(
    req: HttpRequest,
    path: web::Path<Uuid>,
    pool: web::Data<deadpool_postgres::Pool>,
    user: UserBaseI,
) -> impl Responder {
    if user.role != 1 {
        return forbidden();
    }
    let id = path.into_inner();
    match crate::syslog::backfill::cancel_job(pool.get_ref(), id).await {
        Ok(true) => {
            let event =
                AuditEvent::user("configuration", "syslog_backfill_cancel", "success", &user)
                    .resource("syslog_backfill_job", id.to_string());
            write_standalone(pool.get_ref(), &AuditContext::from_request(&req), &event).await;
            HttpResponse::Ok().json(json!({"success": true}))
        }
        Ok(false) => HttpResponse::NotFound()
            .json(json!({"success": false, "message": "任务不存在或已结束"})),
        Err(message) => {
            HttpResponse::InternalServerError().json(json!({"success": false, "message": message}))
        }
    }
}
