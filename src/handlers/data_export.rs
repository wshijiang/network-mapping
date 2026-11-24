//! 数据管理 · 后台导出 HTTP 接口（会话鉴权 + CSRF，按所有权隔离，写审计）。
//!
//! 所有登录用户可导出自己搜索口径的数据（管理员为全局口径）；
//! 任务列表/详情/下载/取消/删除仅所有者或管理员可见。

use actix_files::NamedFile;
use actix_web::http::header::{self, ContentDisposition, DispositionParam, DispositionType};
use actix_web::{HttpRequest, HttpResponse, Responder, delete, get, post, put, web};
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write_standalone};
use crate::data_export::DataExportConfig;
use crate::data_export::fields;
use crate::data_export::settings::{self, Settings};
use crate::data_export::storage::{Object, Storage};
use crate::data_export::task::{self, NewTask};
use crate::elasticsearch::ElasticsearchService;
use crate::handlers::search_dsl::{ElasticsearchCompilation, parse_and_compile_elasticsearch};
use crate::runtime_config::{self, PersistError};

fn bad(message: impl Into<String>) -> HttpResponse {
    HttpResponse::BadRequest().json(json!({"success": false, "message": message.into()}))
}

fn server_error(message: impl Into<String>) -> HttpResponse {
    HttpResponse::InternalServerError().json(json!({"success": false, "message": message.into()}))
}

fn not_found() -> HttpResponse {
    HttpResponse::NotFound().json(json!({"success": false, "message": "任务不存在"}))
}

fn can_access(user: &UserBaseI, task: &task::Task) -> bool {
    user.role == 1 || task.created_by == user.id
}

fn scope_of(user: &UserBaseI) -> (&'static str, i32) {
    if user.role == 1 {
        ("global", 0)
    } else {
        ("user", user.id)
    }
}

async fn audit(
    pool: &Pool,
    req: &HttpRequest,
    user: &UserBaseI,
    action: &str,
    id: Uuid,
    outcome: &str,
) {
    let event = AuditEvent::user("data_export", action, outcome, user)
        .resource("data_export_task", id.to_string());
    write_standalone(pool, &AuditContext::from_request(req), &event).await;
}

/// 与 `/api/search/v2` 同构的语法错误响应（span 为 UTF-16 位置）。
fn syntax_error(
    query: &str,
    error: crate::handlers::search_dsl::SearchSyntaxError,
) -> HttpResponse {
    let utf16_offset = |byte_offset: usize| {
        query
            .get(..byte_offset)
            .map(|value| value.encode_utf16().count())
            .unwrap_or_else(|| query.encode_utf16().count())
    };
    HttpResponse::UnprocessableEntity().json(json!({
        "success": false,
        "code": "SEARCH_SYNTAX_ERROR",
        "message": error.message,
        "span": {"start": utf16_offset(error.start), "end": utf16_offset(error.end)},
    }))
}

#[allow(clippy::result_large_err)]
fn compile_filter(query: &str) -> Result<serde_json::Value, HttpResponse> {
    match parse_and_compile_elasticsearch(query) {
        Ok(ElasticsearchCompilation::Supported(filter))
        | Ok(ElasticsearchCompilation::RequiresElasticsearch(filter)) => Ok(filter),
        Ok(ElasticsearchCompilation::Unsupported) => Err(HttpResponse::UnprocessableEntity().json(
            json!({"success": false, "code": "SEARCH_ES_UNSUPPORTED", "message": "该查询暂不支持 Elasticsearch 读路径"}),
        )),
        Err(error) => Err(syntax_error(query, error)),
    }
}

#[get("/api/data-export/schema")]
pub(crate) async fn get_schema(
    user: UserBaseI,
    config: web::Data<DataExportConfig>,
) -> impl Responder {
    let _ = user;
    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {
            "fields": fields::catalog_json(),
            "default_fields": fields::default_keys(),
            "limits": {"max_rows": config.max_rows, "retention_days": config.retention_days},
        }
    }))
}

#[derive(Deserialize)]
pub(crate) struct PreviewBody {
    query: String,
}

/// 匹配条数预览（本地索引口径，不触发联测）。
#[post("/api/data-export/preview")]
pub(crate) async fn preview(
    elasticsearch: web::Data<ElasticsearchService>,
    user: UserBaseI,
    body: web::Json<PreviewBody>,
) -> impl Responder {
    let query = body.query.trim();
    let filter = match compile_filter(query) {
        Ok(filter) => filter,
        Err(response) => return response,
    };
    let (scope_type, scope_id) = scope_of(&user);
    match elasticsearch
        .search_count(scope_type, scope_id, filter)
        .await
    {
        Ok(total) => {
            HttpResponse::Ok().json(json!({"success": true, "data": {"matched_total": total}}))
        }
        Err(error) => {
            tracing::error!(event = "DataExportPreviewError", %error, "导出预览计数失败");
            HttpResponse::ServiceUnavailable()
                .json(json!({"success": false, "message": "搜索索引暂时不可用"}))
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct CreateBody {
    query: String,
    #[serde(default = "default_scope")]
    scope: String,
    offset: Option<i64>,
    limit: Option<i64>,
    sort_field: Option<String>,
    sort_order: Option<String>,
    fields: Option<Vec<String>>,
}

fn default_scope() -> String {
    "all".to_owned()
}

fn forbidden() -> HttpResponse {
    HttpResponse::Forbidden().json(json!({"success": false, "message": "需要管理员权限"}))
}

fn settings_response(config: &DataExportConfig, document: Settings, revision: i64) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {
            "document": document,
            "revision": revision,
            "s3_configured": config.s3.is_some(),
        },
    }))
}

#[get("/api/data-export/settings")]
pub(crate) async fn get_settings(
    pool: web::Data<Pool>,
    config: web::Data<DataExportConfig>,
    user: UserBaseI,
) -> HttpResponse {
    if user.role != 1 {
        return forbidden();
    }
    match settings::read(&pool, &config).await {
        Ok(current) => settings_response(&config, current.value, current.revision),
        Err(error) => {
            tracing::error!(event = "DataExportSettingsReadFailed", %error);
            server_error("无法读取导出设置")
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct SettingsBody {
    expected_revision: i64,
    document: Settings,
}

#[put("/api/data-export/settings")]
pub(crate) async fn put_settings(
    req: HttpRequest,
    pool: web::Data<Pool>,
    config: web::Data<DataExportConfig>,
    user: UserBaseI,
    body: web::Json<SettingsBody>,
) -> HttpResponse {
    if user.role != 1 {
        return forbidden();
    }
    let body = body.into_inner();
    if let Err(reason) = body.document.validate() {
        return bad(reason);
    }
    if body.document.s3 && config.s3.is_none() {
        return bad("请先在服务器配置 S3 连接");
    }
    match runtime_config::persist(
        &pool,
        settings::NAMESPACE,
        body.expected_revision,
        &body.document,
        "data export settings",
        user.id,
    )
    .await
    {
        Ok(revision) => {
            let event = AuditEvent::user("data_export", "settings.update", "success", &user)
                .resource("data_export_settings", revision.to_string());
            write_standalone(&pool, &AuditContext::from_request(&req), &event).await;
            settings_response(&config, body.document, revision)
        }
        Err(PersistError::Conflict) => HttpResponse::Conflict().json(json!({
            "success": false, "message": "设置已被修改，请重新加载后再保存"
        })),
        Err(error) => {
            tracing::error!(event = "DataExportSettingsWriteFailed", %error);
            server_error("无法保存导出设置")
        }
    }
}

#[post("/api/data-export/settings/test-s3")]
pub(crate) async fn test_storage(
    req: HttpRequest,
    pool: web::Data<Pool>,
    config: web::Data<DataExportConfig>,
    storage: web::Data<Storage>,
    user: UserBaseI,
) -> HttpResponse {
    if user.role != 1 {
        return forbidden();
    }
    let Some(target) = &config.s3 else {
        return bad("请先在服务器配置 S3 连接");
    };
    let result = storage.test(target).await;
    let outcome = if result.is_ok() { "success" } else { "failure" };
    let event = AuditEvent::user("data_export", "settings.test_s3", outcome, &user);
    write_standalone(&pool, &AuditContext::from_request(&req), &event).await;
    match result {
        Ok(()) => HttpResponse::Ok().json(json!({"success": true})),
        Err(error) => {
            tracing::warn!(event = "DataExportStorageTestFailed", %error);
            HttpResponse::BadGateway().json(json!({
                "success": false, "message": "S3 连接测试失败，请检查服务器日志"
            }))
        }
    }
}

#[post("/api/data-export/tasks")]
pub(crate) async fn create_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    config: web::Data<DataExportConfig>,
    user: UserBaseI,
    body: web::Json<CreateBody>,
) -> impl Responder {
    if !config.enabled {
        return bad("数据导出功能未启用");
    }
    let query = body.query.trim();
    let filter = match compile_filter(query) {
        Ok(filter) => filter,
        Err(response) => return response,
    };
    let sort = match crate::elasticsearch::SearchSort::parse(
        body.sort_field.as_deref(),
        body.sort_order.as_deref(),
    ) {
        Ok(sort) => sort,
        Err(message) => return bad(message),
    };
    let keys = body.fields.clone().unwrap_or_else(fields::default_keys);
    if let Err(message) = fields::resolve_keys(&keys) {
        return bad(message);
    }
    let (page_offset, page_limit) = match body.scope.as_str() {
        "page" => {
            let offset = body.offset.unwrap_or(0);
            let limit = body.limit.unwrap_or(50);
            if offset < 0 || !(1..=100).contains(&limit) || offset + limit > 10_000 {
                return bad("本页导出要求 offset ≥ 0、limit 1..=100 且 offset + limit ≤ 10000");
            }
            (Some(offset), Some(limit))
        }
        "all" => (None, None),
        _ => return bad("scope 必须是 page 或 all"),
    };
    let (scope_type, scope_id) = scope_of(&user);
    let matched_total = match elasticsearch
        .search_count(scope_type, scope_id, filter.clone())
        .await
    {
        Ok(total) => total,
        Err(error) => {
            tracing::error!(event = "DataExportCountError", %error, "导出创建计数失败");
            return HttpResponse::ServiceUnavailable()
                .json(json!({"success": false, "message": "搜索索引暂时不可用"}));
        }
    };
    if body.scope == "all" && matched_total > config.max_rows as i64 {
        return bad(format!(
            "匹配 {matched_total} 条，超过单任务导出上限 {} 条，请缩小查询范围",
            config.max_rows
        ));
    }
    let storage_plan = match settings::plan(&pool, &config).await {
        Ok(plan) => plan,
        Err(error) => {
            tracing::warn!(event = "DataExportPlanFailed", %error);
            return HttpResponse::ServiceUnavailable().json(json!({
                "success": false, "message": "导出存储设置暂时不可用"
            }));
        }
    };
    let id = Uuid::now_v7();
    let created = task::create_task(
        &pool,
        NewTask {
            id,
            created_by: user.id,
            scope_type,
            scope_id,
            query,
            filter,
            scope: &body.scope,
            page_offset,
            page_limit,
            sort_field: sort.field_name(),
            sort_order: sort.order_name(),
            fields: json!(keys),
            matched_total: Some(matched_total),
            storage_plan,
        },
    )
    .await;
    match created {
        Ok(t) => {
            audit(&pool, &req, &user, "create", id, "success").await;
            HttpResponse::Ok().json(json!({"success": true, "data": t}))
        }
        Err(error) => server_error(error.to_string()),
    }
}

#[derive(Deserialize)]
pub(crate) struct ListQuery {
    status: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    20
}

#[get("/api/data-export/tasks")]
pub(crate) async fn list_tasks(
    pool: web::Data<Pool>,
    user: UserBaseI,
    query: web::Query<ListQuery>,
) -> impl Responder {
    let owner = if user.role == 1 { None } else { Some(user.id) };
    let limit = query.limit.clamp(1, 200);
    match task::list_tasks(
        &pool,
        owner,
        query.status.as_deref(),
        limit,
        query.offset.max(0),
    )
    .await
    {
        Ok((items, total)) => HttpResponse::Ok()
            .json(json!({"success": true, "data": {"items": items, "total": total}})),
        Err(error) => server_error(error.to_string()),
    }
}

#[get("/api/data-export/tasks/{id}")]
pub(crate) async fn get_task(
    pool: web::Data<Pool>,
    user: UserBaseI,
    path: web::Path<Uuid>,
) -> impl Responder {
    match task::get_task(&pool, path.into_inner()).await {
        Ok(Some(t)) if can_access(&user, &t) => {
            HttpResponse::Ok().json(json!({"success": true, "data": t}))
        }
        Ok(_) => not_found(),
        Err(error) => server_error(error.to_string()),
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DownloadSource {
    Local,
    S3,
}

#[derive(Deserialize)]
pub(crate) struct DownloadQuery {
    source: Option<DownloadSource>,
}

enum Artifact {
    Local(String),
    S3(Object),
}

impl Artifact {
    fn source(&self) -> &'static str {
        match self {
            Self::Local(_) => "local",
            Self::S3(_) => "s3",
        }
    }
}

fn download_error(error: impl std::fmt::Display) -> actix_web::Error {
    tracing::warn!(event = "DataExportDownloadFailed", %error);
    actix_web::error::ErrorBadGateway("对象存储暂时不可用")
}

async fn get_artifact(
    pool: &Pool,
    user: &UserBaseI,
    id: Uuid,
    source: Option<DownloadSource>,
) -> actix_web::Result<Artifact> {
    use actix_web::error::{ErrorBadRequest, ErrorInternalServerError, ErrorNotFound};

    let task = task::get_task(pool, id)
        .await
        .map_err(|error| {
            tracing::error!(event = "DataExportTaskReadFailed", %error);
            ErrorInternalServerError("无法读取导出任务")
        })?
        .filter(|task| can_access(user, task))
        .ok_or_else(|| ErrorNotFound("任务不存在"))?;
    if task.status != task::STATUS_COMPLETED {
        return Err(ErrorBadRequest("任务尚未完成"));
    }
    let source = source.unwrap_or(if task.file_path.is_some() {
        DownloadSource::Local
    } else {
        DownloadSource::S3
    });
    match source {
        DownloadSource::Local => task
            .file_path
            .map(Artifact::Local)
            .ok_or_else(|| ErrorNotFound("任务没有本地副本")),
        DownloadSource::S3 => task
            .s3_object
            .ok_or_else(|| ErrorNotFound("任务没有对象存储副本"))
            .and_then(|value| {
                serde_json::from_value(value)
                    .map(Artifact::S3)
                    .map_err(download_error)
            }),
    }
}

fn disposition(id: Uuid) -> ContentDisposition {
    let date = chrono::Utc::now().format("%Y-%m-%d");
    let short_id = &id.to_string()[..8];
    ContentDisposition {
        disposition: DispositionType::Attachment,
        parameters: vec![DispositionParam::Filename(format!(
            "network-mapping-export-{date}-{short_id}.csv"
        ))],
    }
}

async fn audit_download(pool: &Pool, req: &HttpRequest, user: &UserBaseI, id: Uuid, source: &str) {
    let mut event = AuditEvent::user("data_export", "download", "success", user)
        .resource("data_export_task", id.to_string());
    event.metadata = json!({"source": source});
    write_standalone(pool, &AuditContext::from_request(req), &event).await;
}

#[get("/api/data-export/tasks/{id}/download-link")]
pub(crate) async fn download_link(
    req: HttpRequest,
    pool: web::Data<Pool>,
    storage: web::Data<Storage>,
    user: UserBaseI,
    path: web::Path<Uuid>,
    query: web::Query<DownloadQuery>,
) -> actix_web::Result<HttpResponse> {
    let id = path.into_inner();
    let artifact = get_artifact(&pool, &user, id, query.source).await?;
    let source = artifact.source();
    let url = match artifact {
        Artifact::Local(path) => {
            tokio::fs::metadata(path)
                .await
                .ok()
                .filter(|m| m.is_file())
                .ok_or_else(|| actix_web::error::ErrorNotFound("导出文件不存在或已被清理"))?;
            format!("/api/data-export/tasks/{id}/download?source={source}")
        }
        Artifact::S3(object) => {
            storage
                .check_object(&object)
                .await
                .map_err(download_error)?;
            if object.target.proxy_download {
                format!("/api/data-export/tasks/{id}/download?source={source}")
            } else {
                let url = storage
                    .link(&object, disposition(id).to_string())
                    .await
                    .map_err(download_error)?;
                audit_download(&pool, &req, &user, id, source).await;
                url
            }
        }
    };
    Ok(HttpResponse::Ok()
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(json!({"success": true, "data": {"url": url}})))
}

#[get("/api/data-export/tasks/{id}/download")]
pub(crate) async fn download(
    req: HttpRequest,
    pool: web::Data<Pool>,
    storage: web::Data<Storage>,
    user: UserBaseI,
    path: web::Path<Uuid>,
    query: web::Query<DownloadQuery>,
) -> actix_web::Result<HttpResponse> {
    let id = path.into_inner();
    let artifact = get_artifact(&pool, &user, id, query.source).await?;
    let source = artifact.source();
    let attachment = disposition(id);
    let response = match artifact {
        Artifact::Local(path) => web::block(move || NamedFile::open(path))
            .await?
            .map_err(|_| actix_web::error::ErrorNotFound("导出文件不存在或已被清理"))?
            .set_content_disposition(attachment)
            .into_response(&req),
        Artifact::S3(object) if object.target.proxy_download => {
            let output = storage.download(&object).await.map_err(download_error)?;
            let mut response = HttpResponse::Ok();
            response.insert_header((header::CONTENT_TYPE, "text/csv; charset=utf-8"));
            response.insert_header((header::CONTENT_DISPOSITION, attachment));
            if let Some(length) = output.content_length() {
                response.insert_header((header::CONTENT_LENGTH, length.to_string()));
            }
            response.streaming(futures_util::stream::try_unfold(
                output.body,
                |mut body| async {
                    Ok::<_, actix_web::Error>(
                        body.try_next()
                            .await
                            .map_err(download_error)?
                            .map(|bytes| (bytes, body)),
                    )
                },
            ))
        }
        Artifact::S3(object) => {
            let url = storage
                .link(&object, attachment.to_string())
                .await
                .map_err(download_error)?;
            HttpResponse::Found()
                .insert_header((header::LOCATION, url))
                .insert_header(("referrer-policy", "no-referrer"))
                .finish()
        }
    };
    audit_download(&pool, &req, &user, id, source).await;
    let mut response = response;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("private, no-store"),
    );
    Ok(response)
}

#[post("/api/data-export/tasks/{id}/cancel")]
pub(crate) async fn cancel_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    path: web::Path<Uuid>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match task::get_task(&pool, id).await {
        Ok(Some(t)) if can_access(&user, &t) => t,
        Ok(_) => return not_found(),
        Err(error) => return server_error(error.to_string()),
    };
    let _ = t;
    match task::cancel(&pool, id).await {
        Ok(true) => {
            audit(&pool, &req, &user, "cancel", id, "success").await;
            match task::get_task(&pool, id).await {
                Ok(Some(t)) => HttpResponse::Ok().json(json!({"success": true, "data": t})),
                _ => HttpResponse::Ok().json(json!({"success": true, "data": {}})),
            }
        }
        Ok(false) => bad("任务当前状态不允许取消"),
        Err(error) => server_error(error.to_string()),
    }
}

#[delete("/api/data-export/tasks/{id}")]
pub(crate) async fn delete_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    path: web::Path<Uuid>,
) -> impl Responder {
    let id = path.into_inner();
    match task::get_task(&pool, id).await {
        Ok(Some(t)) if can_access(&user, &t) => {}
        Ok(_) => return not_found(),
        Err(error) => return server_error(error.to_string()),
    }
    match task::delete_task(&pool, id).await {
        Ok(true) => {
            audit(&pool, &req, &user, "delete", id, "success").await;
            HttpResponse::Ok().json(json!({"success": true, "data": {}}))
        }
        Ok(false) => bad("仅终态任务可以删除"),
        Err(error) => server_error(error.to_string()),
    }
}
