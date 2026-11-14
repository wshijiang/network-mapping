use crate::{
    admin::UserBaseI,
    audit::AuditContext,
    config::ServerConfig,
    network_proxy::{self, GlobalProxyState},
    outbound_proxy::{ProxyMode, settings},
};
use actix_web::{HttpRequest, HttpResponse, get, post, put, web};
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::json;
use std::time::Instant;

#[allow(clippy::result_large_err)]
fn admin(user: &UserBaseI) -> std::result::Result<(), HttpResponse> {
    if user.role == 1 {
        Ok(())
    } else {
        Err(HttpResponse::Forbidden()
            .json(json!({"success": false, "message": "仅管理员可以管理全局网络代理"})))
    }
}

fn settings_error(error: settings::SettingsError) -> HttpResponse {
    let status = match error {
        settings::SettingsError::Invalid(_) => actix_web::http::StatusCode::BAD_REQUEST,
        settings::SettingsError::Conflict => actix_web::http::StatusCode::CONFLICT,
        settings::SettingsError::Unavailable(_) => {
            actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
        }
        settings::SettingsError::Database => actix_web::http::StatusCode::SERVICE_UNAVAILABLE,
    };
    HttpResponse::build(status)
        .json(json!({"success": false, "code": error.code(), "message": error.code()}))
}

#[get("/api/config/network-proxy")]
pub async fn get_network_proxy(
    pool: web::Data<Pool>,
    config: web::Data<ServerConfig>,
    state: web::Data<GlobalProxyState>,
    user: UserBaseI,
) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    if let Err(error) = state.refresh(&pool, &config.encrypt_key).await {
        return HttpResponse::ServiceUnavailable()
            .json(json!({"success": false, "code": "settings_unavailable", "message": error}));
    }
    match state.public().await {
        Some(data) => HttpResponse::Ok().json(json!({"success": true, "data": data})),
        None => HttpResponse::ServiceUnavailable()
            .json(json!({"success": false, "code": "settings_unavailable"})),
    }
}

#[put("/api/config/network-proxy")]
pub async fn save_network_proxy(
    req: HttpRequest,
    pool: web::Data<Pool>,
    config: web::Data<ServerConfig>,
    state: web::Data<GlobalProxyState>,
    user: UserBaseI,
    input: web::Json<settings::SettingsInput>,
) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    match settings::save(
        &pool,
        settings::GLOBAL_SCOPE,
        &config.encrypt_key,
        input.into_inner(),
        &user,
        &AuditContext::from_request(&req),
        "network.proxy_update",
    )
    .await
    {
        Ok(stored) => {
            state.apply(stored, &config.encrypt_key).await;
            let public = state.public().await;
            HttpResponse::Ok().json(json!({"success": true, "data": public}))
        }
        Err(error) => settings_error(error),
    }
}

#[post("/api/config/network-proxy/clear")]
pub async fn clear_network_proxy(
    req: HttpRequest,
    pool: web::Data<Pool>,
    config: web::Data<ServerConfig>,
    state: web::Data<GlobalProxyState>,
    user: UserBaseI,
    input: web::Json<settings::ClearInput>,
) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    match settings::clear(
        &pool,
        settings::GLOBAL_SCOPE,
        input.into_inner(),
        &user,
        &AuditContext::from_request(&req),
        "network.proxy_clear",
    )
    .await
    {
        Ok(stored) => {
            state.apply(stored, &config.encrypt_key).await;
            let public = state.public().await;
            HttpResponse::Ok().json(json!({"success": true, "data": public}))
        }
        Err(error) => settings_error(error),
    }
}

fn default_test_url() -> String {
    "https://example.com/".into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestInput {
    pub proxy_mode: ProxyMode,
    #[serde(default)]
    pub proxy_url: String,
    #[serde(default = "default_test_url")]
    pub test_url: String,
}

#[post("/api/config/network-proxy/test")]
pub async fn test_network_proxy(
    pool: web::Data<Pool>,
    config: web::Data<ServerConfig>,
    user: UserBaseI,
    input: web::Json<TestInput>,
) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    let input = input.into_inner();
    let proxy_input = settings::ProxyTestInput {
        proxy_mode: input.proxy_mode,
        proxy_url: input.proxy_url,
    };
    let proxy = match settings::resolve_test_input(
        &pool,
        settings::GLOBAL_SCOPE,
        &config.encrypt_key,
        &proxy_input,
    )
    .await
    {
        Ok(proxy) => proxy,
        Err(error) => return settings_error(error),
    };
    let url = match network_proxy::validate_test_url(&input.test_url) {
        Ok(url) => url,
        Err(code) => {
            return HttpResponse::BadRequest()
                .json(json!({"success": false, "code": code, "message": code}));
        }
    };
    let started = Instant::now();
    let result = network_proxy::probe_url(&proxy, url.as_str()).await;
    let latency_ms = started.elapsed().as_millis() as u64;
    let data = match result {
        Ok(http_status) => json!({
            "ok": true,
            "code": serde_json::Value::Null,
            "http_status": http_status,
            "latency_ms": latency_ms,
        }),
        Err(error) => json!({
            "ok": false,
            "code": error.code,
            "latency_ms": latency_ms,
        }),
    };
    HttpResponse::Ok().json(json!({"success": true, "data": data}))
}
