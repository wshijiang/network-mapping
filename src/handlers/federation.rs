//! 数据管理 · 联测 HTTP 接口（管理员，会话鉴权 + CSRF，写审计）。
//!
//! 策略读写复用 `/api/config/runtime/federation`（handlers/utils.rs）。

use std::time::{Duration, Instant};

use actix_web::{HttpRequest, HttpResponse, Responder, delete, get, post, put, web};
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write_standalone};
use crate::federation::adapters::{self, Adapter};
use crate::federation::model::{FIELD_NAMES, PaginationMode, SourceKind, WindowMode};
use crate::federation::search::FederationService;
use crate::federation::storage::{self, SourceInput, StorageError};
use crate::federation::{executor, storage::NewRun};
use crate::outbound_proxy::{ProxyConfig, ProxyMode};

fn bad(message: impl Into<String>) -> HttpResponse {
    HttpResponse::BadRequest().json(json!({"success": false, "message": message.into()}))
}

fn server_error(message: impl Into<String>) -> HttpResponse {
    HttpResponse::InternalServerError().json(json!({"success": false, "message": message.into()}))
}

fn forbidden() -> HttpResponse {
    HttpResponse::Forbidden().json(json!({"success": false, "message": "仅管理员可以管理联测"}))
}

fn storage_response(error: StorageError) -> HttpResponse {
    match error {
        StorageError::Conflict => HttpResponse::Conflict().json(
            json!({"success": false, "message": "配置已被其他管理员更新，请重新加载后再保存"}),
        ),
        StorageError::NotFound => {
            HttpResponse::NotFound().json(json!({"success": false, "message": "对象不存在"}))
        }
        StorageError::Invalid(message) => bad(message),
    }
}

async fn audit(
    pool: &Pool,
    req: &HttpRequest,
    user: &UserBaseI,
    action: &str,
    resource: &str,
    id: &str,
    outcome: &str,
) {
    let event = AuditEvent::user("federation", action, outcome, user).resource(resource, id);
    write_standalone(pool, &AuditContext::from_request(req), &event).await;
}

/// 平台能力目录（前端表单单一事实来源）。
#[get("/api/federation/schema")]
pub(crate) async fn get_schema(user: UserBaseI) -> impl Responder {
    if user.role != 1 {
        return forbidden();
    }
    let platforms: Vec<Value> = SourceKind::ALL
        .iter()
        .map(|kind| {
            let adapter = Adapter::for_kind(*kind);
            let capabilities = adapter.capabilities();
            let credential_fields: &[&str] = match kind {
                SourceKind::Hunter => &["api_key"],
                SourceKind::Quake => &["token"],
                SourceKind::Fofa => &["key", "email"],
                SourceKind::Shodan => &["key"],
            };
            json!({
                "kind": kind.as_str(),
                "name": kind.display_name(),
                "credential_fields": credential_fields,
                "default_qps": capabilities.default_qps,
                "max_page_size": capabilities.max_page_size,
                "page_size_choices": capabilities.page_size_choices,
                "time_filter": match capabilities.time_filter {
                    crate::federation::model::TimeFilterMode::NativeParam => "native_param",
                    crate::federation::model::TimeFilterMode::NativeSyntax => "native_syntax",
                    crate::federation::model::TimeFilterMode::LocalOnly => "local_only",
                },
                "single_ip_free_endpoint": capabilities.single_ip_free_endpoint,
                "default_window_mode": if *kind == SourceKind::Hunter { "follow" } else { "none" },
            })
        })
        .collect();
    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {
            "platforms": platforms,
            "fields": FIELD_NAMES,
            "proxy_modes": ["system", "direct", "custom"],
            "pagination_modes": ["follow_local", "fixed"],
            "window_modes": ["follow", "none", "custom"],
            "limits": {
                "page_size": [1, 1000], "max_pages": [1, 50],
                "window_days": [1, 60], "timeout_seconds": [3, 120],
                "rate_limit_qps": [0.01, 10],
            },
        }
    }))
}

#[get("/api/federation/sources")]
pub(crate) async fn list_sources(
    pool: web::Data<Pool>,
    server: web::Data<crate::config::ServerConfig>,
    user: UserBaseI,
) -> impl Responder {
    if user.role != 1 {
        return forbidden();
    }
    match storage::list_sources(pool.get_ref()).await {
        Ok(sources) => {
            let items: Vec<Value> = sources
                .iter()
                .map(|source| storage::source_public(source, &server.encrypt_key))
                .collect();
            HttpResponse::Ok().json(json!({"success": true, "data": {"items": items}}))
        }
        Err(error) => server_error(error.to_string()),
    }
}

#[derive(Deserialize)]
pub(crate) struct SourceRequest {
    kind: String,
    name: String,
    #[serde(default)]
    enabled: bool,
    credential: Option<Value>,
    #[serde(default)]
    clear_credential: bool,
    #[serde(default = "default_proxy_mode")]
    proxy_mode: String,
    proxy_url: Option<String>,
    fields: Option<Vec<String>>,
    #[serde(default)]
    pagination_mode: Option<PaginationMode>,
    #[serde(default = "default_page_size")]
    page_size: u32,
    #[serde(default = "default_max_pages")]
    max_pages: u32,
    #[serde(default)]
    window_mode: Option<WindowMode>,
    #[serde(default = "default_window_days")]
    window_days: u32,
    #[serde(default = "default_timeout")]
    timeout_seconds: u32,
    rate_limit_qps: Option<f64>,
    #[serde(default)]
    expected_revision: i64,
}

fn default_proxy_mode() -> String {
    "system".into()
}
fn default_page_size() -> u32 {
    100
}
fn default_max_pages() -> u32 {
    5
}
fn default_window_days() -> u32 {
    30
}
fn default_timeout() -> u32 {
    15
}

impl SourceRequest {
    fn into_input(self, kind: SourceKind) -> SourceInput {
        let default_fields: Vec<String> = ["ip", "domain", "port", "service", "tech"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        SourceInput {
            kind,
            name: self.name,
            enabled: self.enabled,
            credential: self.credential,
            clear_credential: self.clear_credential,
            proxy_mode: self.proxy_mode,
            proxy_url: self.proxy_url,
            fields: self.fields.unwrap_or(default_fields),
            pagination_mode: self.pagination_mode.unwrap_or_default(),
            page_size: self.page_size,
            max_pages: self.max_pages,
            window_mode: self.window_mode.unwrap_or_else(|| {
                if kind == SourceKind::Hunter {
                    WindowMode::Follow
                } else {
                    WindowMode::None
                }
            }),
            window_days: self.window_days,
            timeout_seconds: self.timeout_seconds,
            rate_limit_qps: self
                .rate_limit_qps
                .unwrap_or_else(|| Adapter::for_kind(kind).capabilities().default_qps),
        }
    }
}

#[post("/api/federation/sources")]
pub(crate) async fn create_source(
    req: HttpRequest,
    pool: web::Data<Pool>,
    server: web::Data<crate::config::ServerConfig>,
    user: UserBaseI,
    body: web::Json<SourceRequest>,
) -> impl Responder {
    if user.role != 1 {
        return forbidden();
    }
    let Some(kind) = SourceKind::parse(&body.kind) else {
        return bad("kind 须为 hunter/quake/fofa/shodan");
    };
    let input = body.into_inner().into_input(kind);
    match storage::create_source(pool.get_ref(), &input, &server.encrypt_key).await {
        Ok(source) => {
            audit(
                pool.get_ref(),
                &req,
                &user,
                "source_create",
                "federation_source",
                &source.id.to_string(),
                "success",
            )
            .await;
            HttpResponse::Ok().json(json!({
                "success": true,
                "data": storage::source_public(&source, &server.encrypt_key),
            }))
        }
        Err(error) => {
            audit(
                pool.get_ref(),
                &req,
                &user,
                "source_create",
                "federation_source",
                "",
                "failed",
            )
            .await;
            server_error(error.to_string())
        }
    }
}

#[put("/api/federation/sources/{id}")]
pub(crate) async fn update_source(
    req: HttpRequest,
    pool: web::Data<Pool>,
    server: web::Data<crate::config::ServerConfig>,
    user: UserBaseI,
    path: web::Path<Uuid>,
    body: web::Json<SourceRequest>,
) -> impl Responder {
    if user.role != 1 {
        return forbidden();
    }
    let id = path.into_inner();
    let Some(kind) = SourceKind::parse(&body.kind) else {
        return bad("kind 须为 hunter/quake/fofa/shodan");
    };
    let expected_revision = body.expected_revision;
    let input = body.into_inner().into_input(kind);
    match storage::update_source(
        pool.get_ref(),
        id,
        expected_revision,
        &input,
        &server.encrypt_key,
    )
    .await
    {
        Ok(source) => {
            audit(
                pool.get_ref(),
                &req,
                &user,
                "source_update",
                "federation_source",
                &id.to_string(),
                "success",
            )
            .await;
            HttpResponse::Ok().json(json!({
                "success": true,
                "data": storage::source_public(&source, &server.encrypt_key),
            }))
        }
        Err(error) => storage_response(error),
    }
}

#[derive(Deserialize)]
pub(crate) struct DeleteQuery {
    expected_revision: i64,
}

#[delete("/api/federation/sources/{id}")]
pub(crate) async fn delete_source(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    path: web::Path<Uuid>,
    query: web::Query<DeleteQuery>,
) -> impl Responder {
    if user.role != 1 {
        return forbidden();
    }
    let id = path.into_inner();
    match storage::delete_source(pool.get_ref(), id, query.expected_revision).await {
        Ok(()) => {
            audit(
                pool.get_ref(),
                &req,
                &user,
                "source_delete",
                "federation_source",
                &id.to_string(),
                "success",
            )
            .await;
            HttpResponse::Ok().json(json!({"success": true}))
        }
        Err(error) => storage_response(error),
    }
}

/// 测试连接：账号接口探测（免费），回显会员/配额/延迟。
#[post("/api/federation/sources/{id}/test")]
pub(crate) async fn test_source(
    req: HttpRequest,
    pool: web::Data<Pool>,
    server: web::Data<crate::config::ServerConfig>,
    proxy: web::Data<crate::network_proxy::GlobalProxyState>,
    user: UserBaseI,
    path: web::Path<Uuid>,
) -> impl Responder {
    if user.role != 1 {
        return forbidden();
    }
    let id = path.into_inner();
    let source = match storage::get_source(pool.get_ref(), id).await {
        Ok(Some(source)) => source,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(json!({"success": false, "message": "数据源不存在"}));
        }
        Err(error) => return server_error(error.to_string()),
    };
    let started = Instant::now();
    let result = async {
        let credential =
            storage::decrypt_json(source.credential_ciphertext.as_deref(), &server.encrypt_key)
                .map_err(|_| "凭据解密失败")?
                .ok_or("凭据未配置")?;
        let local_proxy = ProxyConfig {
            mode: source
                .proxy_mode
                .parse::<ProxyMode>()
                .unwrap_or(ProxyMode::System),
            url: storage::decrypt_json(source.proxy_ciphertext.as_deref(), &server.encrypt_key)
                .ok()
                .flatten()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default(),
        };
        let effective = proxy.resolve(&local_proxy).await.map_err(|e| e.code)?;
        let client =
            adapters::http_client(&effective, Duration::from_secs(15)).map_err(|e| e.code)?;
        let adapter = Adapter::for_kind(source.kind);
        let probed = adapter
            .probe(&client, &credential)
            .await
            .map_err(|e| e.code)?;
        // 最小暴露面：账号接口附带的手机号/邮箱/token 等不入库也不回显。
        let mut capabilities = storage::public_capabilities(source.kind, &probed);
        capabilities["quota_updated_at"] = json!(chrono::Utc::now().timestamp_millis());
        storage::update_capabilities(pool.get_ref(), id, &capabilities)
            .await
            .map_err(|e| e.to_string())?;
        Ok::<Value, String>(capabilities)
    }
    .await;
    let latency_ms = started.elapsed().as_millis() as i64;
    match result {
        Ok(capabilities) => {
            audit(
                pool.get_ref(),
                &req,
                &user,
                "source_test",
                "federation_source",
                &id.to_string(),
                "success",
            )
            .await;
            HttpResponse::Ok().json(json!({
                "success": true,
                "data": {"latency_ms": latency_ms, "capabilities": capabilities},
            }))
        }
        Err(error_code) => {
            audit(
                pool.get_ref(),
                &req,
                &user,
                "source_test",
                "federation_source",
                &id.to_string(),
                "failed",
            )
            .await;
            HttpResponse::Ok().json(json!({
                "success": false,
                "data": {"latency_ms": latency_ms, "error_code": error_code},
                "message": format!("测试失败：{error_code}"),
            }))
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct RunRequest {
    query: String,
    mode: Option<String>,
    source_ids: Option<Vec<Uuid>>,
    window_days: Option<u32>,
    /// auto/force/skip
    persist: Option<String>,
}

/// 手动联测（Web）：进程内立即执行。
#[post("/api/federation/runs")]
pub(crate) async fn create_run(
    req: HttpRequest,
    service: web::Data<FederationService>,
    user: UserBaseI,
    body: web::Json<RunRequest>,
) -> impl Responder {
    if user.role != 1 {
        return forbidden();
    }
    let query = body.query.trim().to_owned();
    if query.is_empty() || query.chars().count() > 2048 {
        return bad("查询须为 1..2048 字符");
    }
    if crate::handlers::search_dsl::parse_query_ast(&query).is_err() {
        return bad("查询语法无效");
    }
    let policy = service.policy.get().await.value;
    if !service.config.enabled || !policy.enabled {
        return bad("联测未启用");
    }
    let mode = match body.mode.as_deref() {
        Some("blocking") => "blocking",
        _ => "async",
    };
    let window_days = body.window_days.unwrap_or(policy.query_window_days);
    if !(1..=60).contains(&window_days) {
        return bad("window_days 须在 1..=60");
    }
    let persist_override = match body.persist.as_deref() {
        Some("force") => "force",
        Some("skip") => "skip",
        _ => "auto",
    };
    // 哈希含各源解析后窗口。
    let sources = match storage::list_sources(&service.pool).await {
        Ok(sources) => sources,
        Err(error) => return server_error(error.to_string()),
    };
    let enabled: Vec<_> = sources
        .into_iter()
        .filter(|s| s.enabled)
        .filter(|s| {
            body.source_ids
                .as_ref()
                .is_none_or(|ids| ids.contains(&s.id))
        })
        .collect();
    if enabled.is_empty() {
        return bad("没有可用的启用数据源");
    }
    let resolved: Vec<(Uuid, Option<u32>)> = enabled
        .iter()
        .map(|s| (s.id, executor::resolve_source_window(s, window_days)))
        .collect();
    let query_hash = executor::compute_query_hash(&query, &resolved, 100, 0);
    // 手动提交与搜索触发共用并发上限，避免绕过 max_concurrent_runs。
    if let Ok(active) = storage::count_active_runs(&service.pool).await
        && active >= i64::from(policy.max_concurrent_runs)
    {
        return HttpResponse::TooManyRequests()
            .json(json!({"success": false, "message": "并发联测 run 已达上限，请稍后再试"}));
    }
    let Ok(run_permit) = service.run_gate.clone().try_acquire_owned() else {
        return HttpResponse::TooManyRequests()
            .json(json!({"success": false, "message": "并发联测 run 已达上限，请稍后再试"}));
    };
    let worker_id = Uuid::new_v4();
    let run = match storage::create_run(
        &service.pool,
        NewRun {
            query_text: &query,
            query_hash: &query_hash,
            trigger: "manual",
            mode,
            requested_by: user.id,
            window_days,
            local_state: "unknown",
            selected_sources: body.source_ids.clone(),
            local_limit: 100,
            local_offset: 0,
            persist_override,
            status: "running",
            worker_id: Some(worker_id),
            lease_ms: service.config.lease_seconds as i64 * 1000,
        },
    )
    .await
    {
        Ok(run) => run,
        Err(error) => return server_error(error.to_string()),
    };
    audit(
        pool_of(&service),
        &req,
        &user,
        "run_create",
        "federation_run",
        &run.id.to_string(),
        "success",
    )
    .await;

    // 进程内执行（与搜索触发同路径）。
    let services = executor::Services {
        pool: service.pool.clone(),
        maxmind: service.maxmind.clone(),
        elasticsearch: service.elasticsearch.clone(),
        dns_follow_up: service.dns_follow_up.get().await.value.clone(),
        network_proxy: service.network_proxy.clone(),
        encrypt_key: service.encrypt_key.clone(),
        pepper: service.pepper.clone(),
        config: service.config.clone(),
    };
    let run_id = run.id;
    let run_clone = run.clone();
    tokio::spawn(async move {
        let _permit = run_permit;
        if let Err(error) = executor::execute_run(&services, &run_clone, worker_id, &policy).await {
            tracing::warn!(event = "FederationRunFailed", run_id = %run_id, %error, "手动联测 run 执行失败");
            let _ = storage::finish_run(
                &services.pool,
                run_id,
                "failed",
                &json!([]),
                0,
                0,
                0,
                None,
                None,
                Some(&error.to_string()),
            )
            .await;
        }
    });
    HttpResponse::Ok().json(json!({"success": true, "data": storage::run_public(&run, false)}))
}

fn pool_of(service: &FederationService) -> &Pool {
    &service.pool
}

#[derive(Deserialize)]
pub(crate) struct RunListQuery {
    status: Option<String>,
    #[serde(default = "default_run_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_run_limit() -> i64 {
    20
}

#[get("/api/federation/runs")]
pub(crate) async fn list_runs(
    pool: web::Data<Pool>,
    user: UserBaseI,
    query: web::Query<RunListQuery>,
) -> impl Responder {
    if user.role != 1 {
        return forbidden();
    }
    let limit = query.limit.clamp(1, 100);
    let offset = query.offset.max(0);
    match storage::list_runs(pool.get_ref(), query.status.as_deref(), limit, offset).await {
        Ok((runs, total)) => {
            let items: Vec<Value> = runs
                .iter()
                .map(|run| storage::run_public(run, false))
                .collect();
            HttpResponse::Ok()
                .json(json!({"success": true, "data": {"items": items, "total": total}}))
        }
        Err(error) => server_error(error.to_string()),
    }
}

#[get("/api/federation/runs/{id}")]
pub(crate) async fn get_run(
    pool: web::Data<Pool>,
    user: UserBaseI,
    path: web::Path<Uuid>,
) -> impl Responder {
    if user.role != 1 {
        return forbidden();
    }
    match storage::get_run(pool.get_ref(), path.into_inner()).await {
        Ok(Some(run)) => HttpResponse::Ok()
            .json(json!({"success": true, "data": storage::run_public(&run, true)})),
        Ok(None) => {
            HttpResponse::NotFound().json(json!({"success": false, "message": "run 不存在"}))
        }
        Err(error) => server_error(error.to_string()),
    }
}

#[post("/api/federation/runs/{id}/cancel")]
pub(crate) async fn cancel_run(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    path: web::Path<Uuid>,
) -> impl Responder {
    if user.role != 1 {
        return forbidden();
    }
    let id = path.into_inner();
    match storage::cancel_run(pool.get_ref(), id).await {
        Ok(()) => {
            audit(
                pool.get_ref(),
                &req,
                &user,
                "run_cancel",
                "federation_run",
                &id.to_string(),
                "success",
            )
            .await;
            HttpResponse::Ok().json(json!({"success": true}))
        }
        Err(error) => storage_response(error),
    }
}

#[delete("/api/federation/runs/{id}")]
pub(crate) async fn delete_run(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    path: web::Path<Uuid>,
) -> impl Responder {
    if user.role != 1 {
        return forbidden();
    }
    let id = path.into_inner();
    match storage::delete_run(pool.get_ref(), id).await {
        Ok(()) => {
            audit(
                pool.get_ref(),
                &req,
                &user,
                "run_delete",
                "federation_run",
                &id.to_string(),
                "success",
            )
            .await;
            HttpResponse::Ok().json(json!({"success": true}))
        }
        Err(error) => storage_response(error),
    }
}
