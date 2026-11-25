//! Independently authenticated external API and session-protected management plane.
mod analytics;
mod auth;
mod business;
mod catalog;
pub(crate) mod console;
mod contract;
mod model;
mod query;
mod resources;
mod tasks;
#[cfg(test)]
mod tests;
mod worker;

use actix_web::{HttpMessage, HttpRequest, HttpResponse, http::StatusCode, web};
use deadpool_postgres::Pool;
use serde_json::{Value, json};
use uuid::Uuid;

pub(crate) use model::{Policy, Principal};
pub(crate) use tasks::follow_up_scope;
pub(crate) use tasks::reserve_follow_up;
pub(crate) type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug)]
pub(crate) struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}
impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
    pub fn bad(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_parameter",
            message,
        )
    }
    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, "scope_denied", "未授权此操作")
    }
    pub fn missing() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "resource_not_found",
            "资源不存在或不可访问",
        )
    }
    pub fn unavailable() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "dependency_unavailable",
            "服务暂不可用，请稍后重试",
        )
    }
}
impl From<tokio_postgres::Error> for ApiError {
    fn from(error: tokio_postgres::Error) -> Self {
        tracing::error!(event="OpenApiDatabaseError",error=%error);
        Self::unavailable()
    }
}
impl From<deadpool_postgres::PoolError> for ApiError {
    fn from(error: deadpool_postgres::PoolError) -> Self {
        tracing::error!(event="OpenApiPoolError",error=%error);
        Self::unavailable()
    }
}
pub(crate) fn request_id(req: &HttpRequest) -> Uuid {
    crate::audit::AuditContext::from_request(req).request_id
}
pub(crate) fn response(req: &HttpRequest, value: Result<Value>) -> HttpResponse {
    match value {
        Ok(data) => HttpResponse::Ok()
            .insert_header(("Cache-Control", "private, no-store"))
            .json(json!({"data":data,"request_id":request_id(req)})),
        Err(e) => {
            crate::request_log::set_reason(req, e.code);
            let mut r = HttpResponse::build(e.status);
            r.insert_header(("Cache-Control", "no-store"));
            if matches!(
                e.status,
                StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
            ) {
                r.insert_header(("Retry-After", "60"));
            }
            if e.status == StatusCode::UNAUTHORIZED {
                r.insert_header(("WWW-Authenticate", "Bearer"));
            }
            r.json(
                json!({"error":{"code":e.code,"message":e.message},"request_id":request_id(req)}),
            )
        }
    }
}
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/open-api/openapi.json",
        web::get().to(|| async { HttpResponse::Ok().json(openapi_document()) }),
    );
    cfg.service(
        web::scope("/open-api/v1")
            .app_data(web::PayloadConfig::new(128 * 1024))
            .route("", web::to(external))
            .route("/{tail:.*}", web::to(external)),
    )
    .service(
        web::scope("/api/open-platform")
            .app_data(web::PayloadConfig::new(128 * 1024))
            .route("/{tail:.*}", web::to(console::handle)),
    );
}
/// Exportable public specification; no credentials or tenant configuration are included.
pub fn openapi_document() -> Value {
    catalog::openapi()
}
async fn external(
    req: HttpRequest,
    body: web::Bytes,
    pool: web::Data<Pool>,
    es: web::Data<crate::elasticsearch::ElasticsearchService>,
) -> HttpResponse {
    let started = std::time::Instant::now();
    let route = catalog::resolve(
        req.method().as_str(),
        req.match_info().get("tail").unwrap_or(""),
    );
    let authenticated = auth::authenticate(&req, &pool).await;
    let mut principal = None;
    let result = match authenticated {
        Ok(p) => {
            req.extensions_mut().insert(p.clone());
            principal = Some(p.clone());
            match route {
                Some(endpoint) => {
                    if !p.has(endpoint.scope) {
                        Err(ApiError::forbidden())
                    } else {
                        business::dispatch(&req, &body, &pool, &es, &p, &endpoint).await
                    }
                }
                None => Err(ApiError::missing()),
            }
        }
        Err(e) => Err(e),
    };
    let accepted = result.is_ok()
        && req.method().as_str() == "POST"
        && route.is_some_and(|e| {
            matches!(e.path, "/tasks" | "/exports" | "/reports")
                || e.path.ends_with("/retry") && e.scope == "tasks:retry"
        });
    let (status, reason) = match &result {
        Ok(_) => (if accepted { 202 } else { 200 }, None),
        Err(e) => (e.status.as_u16(), Some(e.code)),
    };
    auth::log_call(
        &pool,
        &req,
        principal.as_ref(),
        route.as_ref().map(|e| e.path).unwrap_or("(unmatched)"),
        status,
        reason,
        started.elapsed(),
    )
    .await;
    if let Ok(value) = &result
        && let Some(download) = business::download_response(&req, value)
    {
        return download;
    }
    let mut resp = response(&req, result);
    if accepted {
        *resp.status_mut() = StatusCode::ACCEPTED;
    }
    resp
}
pub async fn run_worker(
    pool: Pool,
    es: crate::elasticsearch::ElasticsearchService,
    encryption_key: Vec<u8>,
) {
    worker::run(pool, es, encryption_key).await;
}
