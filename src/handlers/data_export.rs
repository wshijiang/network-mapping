//! 数据管理 · 后台导出 HTTP 接口（会话鉴权 + CSRF，按所有权隔离，写审计）。
//!
//! 所有登录用户可导出自己搜索口径的数据（管理员为全局口径）；
//! 任务列表/详情/下载/取消/删除仅所有者或管理员可见。

use actix_files::NamedFile;
use actix_web::http::header::{ContentDisposition, DispositionParam, DispositionType};
use actix_web::{HttpRequest, HttpResponse, Responder, delete, get, post, web};
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write_standalone};
use crate::data_export::DataExportConfig;
use crate::data_export::fields;
use crate::data_export::task::{self, NewTask};
use crate::elasticsearch::ElasticsearchService;
use crate::handlers::search_dsl::{ElasticsearchCompilation, parse_and_compile_elasticsearch};

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

#[get("/api/data-export/tasks/{id}/download")]
pub(crate) async fn download(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    path: web::Path<Uuid>,
) -> actix_web::Result<NamedFile> {
    let id = path.into_inner();
    let t = task::get_task(&pool, id)
        .await
        .map_err(|error| actix_web::error::ErrorInternalServerError(error.to_string()))?
        .filter(|t| can_access(&user, t))
        .ok_or_else(|| actix_web::error::ErrorNotFound("任务不存在"))?;
    if t.status != task::STATUS_COMPLETED {
        return Err(actix_web::error::ErrorBadRequest("任务尚未完成"));
    }
    let file_path = t
        .file_path
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("导出文件缺失"))?;
    let date = chrono::Utc::now().format("%Y-%m-%d");
    let short_id = &id.to_string()[..8];
    let file = NamedFile::open(&file_path)
        .map_err(|_| actix_web::error::ErrorNotFound("导出文件不存在或已被清理"))?
        .set_content_disposition(ContentDisposition {
            disposition: DispositionType::Attachment,
            parameters: vec![DispositionParam::Filename(format!(
                "network-mapping-export-{date}-{short_id}.csv"
            ))],
        });
    audit(&pool, &req, &user, "download", id, "success").await;
    Ok(file)
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
        Ok(Some(file_path)) => {
            if let Some(path) = file_path {
                let _ = tokio::fs::remove_file(&path).await;
            }
            audit(&pool, &req, &user, "delete", id, "success").await;
            HttpResponse::Ok().json(json!({"success": true, "data": {}}))
        }
        Ok(None) => bad("仅终态任务可以删除"),
        Err(error) => server_error(error.to_string()),
    }
}
