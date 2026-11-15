//! 数据管理 · 外部导入 HTTP 接口（管理员，会话鉴权 + CSRF，写审计）。

use std::collections::BTreeMap;

use actix_multipart::Multipart;
use actix_web::{HttpRequest, HttpResponse, Responder, delete, get, post, web};
use deadpool_postgres::Pool;
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write_standalone};
use crate::data_import::DataImportConfig;
use crate::data_import::csv;
use crate::data_import::schema;
use crate::data_import::task::{self, NewTask};

async fn deny_non_admin(
    req: &HttpRequest,
    pool: &Pool,
    user: &UserBaseI,
    action: &str,
) -> Option<HttpResponse> {
    if user.role == 1 {
        return None;
    }
    let mut event = AuditEvent::user("authorization", action, "denied", user);
    event.response_status = Some(403);
    event.reason_code = Some("insufficient_role".to_owned());
    write_standalone(pool, &AuditContext::from_request(req), &event).await;
    Some(
        HttpResponse::Forbidden()
            .json(json!({"success": false, "message": "仅管理员可以管理数据导入"})),
    )
}

fn bad(message: impl Into<String>) -> HttpResponse {
    HttpResponse::BadRequest().json(json!({"success": false, "message": message.into()}))
}

fn server_error(message: impl Into<String>) -> HttpResponse {
    HttpResponse::InternalServerError().json(json!({"success": false, "message": message.into()}))
}

async fn audit(
    pool: &Pool,
    req: &HttpRequest,
    user: &UserBaseI,
    action: &str,
    id: Uuid,
    outcome: &str,
) {
    let event = AuditEvent::user("data_import", action, outcome, user)
        .resource("data_import_task", id.to_string());
    write_standalone(pool, &AuditContext::from_request(req), &event).await;
}

#[get("/api/data-import/schema")]
pub(crate) async fn get_schema(
    user: UserBaseI,
    config: web::Data<DataImportConfig>,
) -> impl Responder {
    if user.role != 1 {
        return HttpResponse::Forbidden()
            .json(json!({"success": false, "message": "仅管理员可以访问"}));
    }
    HttpResponse::Ok()
        .json(json!({"success": true, "data": schema::schema_document(config.schema_limits())}))
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

#[get("/api/data-import/tasks")]
pub(crate) async fn list_tasks(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    query: web::Query<ListQuery>,
) -> impl Responder {
    if let Some(response) = deny_non_admin(&req, &pool, &user, "data_import.list").await {
        return response;
    }
    let limit = query.limit.clamp(1, 200);
    match task::list_tasks(&pool, query.status.as_deref(), limit, query.offset.max(0)).await {
        Ok((items, total)) => HttpResponse::Ok()
            .json(json!({"success": true, "data": {"items": items, "total": total}})),
        Err(error) => server_error(error.to_string()),
    }
}

#[get("/api/data-import/tasks/{id}")]
pub(crate) async fn get_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    path: web::Path<Uuid>,
) -> impl Responder {
    if let Some(response) = deny_non_admin(&req, &pool, &user, "data_import.read").await {
        return response;
    }
    match task::get_task(&pool, path.into_inner()).await {
        Ok(Some(t)) => HttpResponse::Ok().json(json!({"success": true, "data": t})),
        Ok(None) => {
            HttpResponse::NotFound().json(json!({"success": false, "message": "任务不存在"}))
        }
        Err(error) => server_error(error.to_string()),
    }
}

#[get("/api/data-import/tasks/{id}/errors")]
pub(crate) async fn get_errors(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    path: web::Path<Uuid>,
) -> impl Responder {
    if let Some(response) = deny_non_admin(&req, &pool, &user, "data_import.read").await {
        return response;
    }
    match task::error_samples(&pool, path.into_inner()).await {
        Ok(data) => HttpResponse::Ok().json(json!({"success": true, "data": data})),
        Err(error) => server_error(error.to_string()),
    }
}

fn csv_escape(value: &str) -> String {
    // 公式注入防护：以 = + - @ 开头的单元格前置单引号。
    let guarded = if value.starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if guarded.contains(',') || guarded.contains('"') || guarded.contains('\n') {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

#[get("/api/data-import/tasks/{id}/errors.csv")]
pub(crate) async fn get_errors_csv(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    path: web::Path<Uuid>,
) -> impl Responder {
    if let Some(response) = deny_non_admin(&req, &pool, &user, "data_import.read").await {
        return response;
    }
    let id = path.into_inner();
    let data = match task::error_samples(&pool, id).await {
        Ok(data) => data,
        Err(error) => return server_error(error.to_string()),
    };
    let mut body = String::from("\u{feff}row,column,value,reason\r\n");
    if let Some(samples) = data.get("samples").and_then(Value::as_array) {
        for sample in samples {
            let row = sample.get("row").and_then(Value::as_i64).unwrap_or(0);
            let column = sample.get("column").and_then(Value::as_str).unwrap_or("");
            let value = sample.get("value").and_then(Value::as_str).unwrap_or("");
            let reason = sample.get("reason").and_then(Value::as_str).unwrap_or("");
            body.push_str(&format!(
                "{},{},{},{}\r\n",
                row,
                csv_escape(column),
                csv_escape(value),
                csv_escape(reason)
            ));
        }
    }
    HttpResponse::Ok()
        .insert_header(("Content-Type", "text/csv; charset=utf-8"))
        .insert_header((
            "Content-Disposition",
            format!("attachment; filename=\"network-mapping-import-errors-{id}.csv\""),
        ))
        .body(body)
}

#[post("/api/data-import/tasks/{id}/pause")]
pub(crate) async fn pause_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    path: web::Path<Uuid>,
) -> impl Responder {
    control(req, pool, user, path, "pause").await
}

#[post("/api/data-import/tasks/{id}/cancel")]
pub(crate) async fn cancel_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    path: web::Path<Uuid>,
) -> impl Responder {
    control(req, pool, user, path, "cancel").await
}

async fn control(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    path: web::Path<Uuid>,
    action: &str,
) -> HttpResponse {
    if let Some(response) =
        deny_non_admin(&req, &pool, &user, &format!("data_import.{action}")).await
    {
        return response;
    }
    let id = path.into_inner();
    let result = match action {
        "pause" => task::pause(&pool, id).await,
        _ => task::cancel(&pool, id).await,
    };
    match result {
        Ok(true) => {
            audit(&pool, &req, &user, action, id, "success").await;
            match task::get_task(&pool, id).await {
                Ok(Some(t)) => HttpResponse::Ok().json(json!({"success": true, "data": t})),
                _ => HttpResponse::Ok().json(json!({"success": true, "data": {}})),
            }
        }
        Ok(false) => bad("任务当前状态不允许该操作"),
        Err(error) => server_error(error.to_string()),
    }
}

#[derive(Deserialize)]
pub(crate) struct ResumeBody {
    batch_size: Option<i32>,
    concurrency: Option<i32>,
}

#[post("/api/data-import/tasks/{id}/resume")]
pub(crate) async fn resume_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    path: web::Path<Uuid>,
    body: web::Json<ResumeBody>,
) -> impl Responder {
    if let Some(response) = deny_non_admin(&req, &pool, &user, "data_import.resume").await {
        return response;
    }
    let id = path.into_inner();
    if let Some(batch) = body.batch_size
        && !(1..=50000).contains(&batch)
    {
        return bad("batch_size 须在 1..=50000");
    }
    if let Some(concurrency) = body.concurrency
        && !(1..=8).contains(&concurrency)
    {
        return bad("concurrency 须在 1..=8");
    }
    match task::resume(&pool, id, body.batch_size, body.concurrency).await {
        Ok(true) => {
            audit(&pool, &req, &user, "resume", id, "success").await;
            match task::get_task(&pool, id).await {
                Ok(Some(t)) => HttpResponse::Ok().json(json!({"success": true, "data": t})),
                _ => HttpResponse::Ok().json(json!({"success": true, "data": {}})),
            }
        }
        Ok(false) => bad("仅暂停中的任务可以继续"),
        Err(error) => server_error(error.to_string()),
    }
}

#[delete("/api/data-import/tasks/{id}")]
pub(crate) async fn delete_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    path: web::Path<Uuid>,
) -> impl Responder {
    if let Some(response) = deny_non_admin(&req, &pool, &user, "data_import.delete").await {
        return response;
    }
    let id = path.into_inner();
    match task::delete_task(&pool, id).await {
        Ok(Some(path)) => {
            let _ = tokio::fs::remove_file(&path).await;
            audit(&pool, &req, &user, "delete", id, "success").await;
            HttpResponse::Ok().json(json!({"success": true, "data": {}}))
        }
        Ok(None) => bad("仅终态任务可以删除"),
        Err(error) => server_error(error.to_string()),
    }
}

/// multipart 上传并创建任务。字段：file + mapping(JSON) + batch_size/concurrency/on_invalid/overwrite_policy/fast/dry_run。
#[post("/api/data-import/tasks")]
pub(crate) async fn create_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    config: web::Data<DataImportConfig>,
    mut multipart: Multipart,
) -> impl Responder {
    if let Some(response) = deny_non_admin(&req, &pool, &user, "data_import.create").await {
        return response;
    }
    if !config.enabled {
        return bad("数据导入功能未启用");
    }
    let id = Uuid::now_v7();
    if let Err(error) = tokio::fs::create_dir_all(&config.directory).await {
        return server_error(format!("创建导入目录失败：{error}"));
    }
    let stored = config.directory.join(format!("{id}.csv"));
    let mut file = match tokio::fs::File::create(&stored).await {
        Ok(file) => file,
        Err(error) => return server_error(format!("创建临时文件失败：{error}")),
    };
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    let mut file_name = String::from("import.csv");
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut has_file = false;

    while let Some(item) = multipart.next().await {
        let mut field = match item {
            Ok(field) => field,
            Err(error) => {
                let _ = tokio::fs::remove_file(&stored).await;
                return bad(format!("上传解析失败：{error}"));
            }
        };
        let disposition = field.content_disposition().clone();
        let name = disposition.get_name().unwrap_or("").to_owned();
        if name == "file" {
            has_file = true;
            if let Some(filename) = disposition.get_filename() {
                file_name = filename.chars().take(255).collect();
            }
            while let Some(chunk) = field.next().await {
                let bytes = match chunk {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        let _ = tokio::fs::remove_file(&stored).await;
                        return bad(format!("上传读取失败：{error}"));
                    }
                };
                size += bytes.len() as u64;
                if size > config.max_upload_bytes {
                    let _ = tokio::fs::remove_file(&stored).await;
                    return HttpResponse::PayloadTooLarge().json(json!({"success": false, "message": format!("文件超过大小上限 {} 字节", config.max_upload_bytes)}));
                }
                hasher.update(&bytes);
                if let Err(error) = tokio::io::AsyncWriteExt::write_all(&mut file, &bytes).await {
                    let _ = tokio::fs::remove_file(&stored).await;
                    return server_error(format!("写入临时文件失败：{error}"));
                }
            }
        } else {
            let mut buffer = Vec::new();
            while let Some(chunk) = field.next().await {
                match chunk {
                    Ok(bytes) => buffer.extend_from_slice(&bytes),
                    Err(error) => {
                        let _ = tokio::fs::remove_file(&stored).await;
                        return bad(format!("上传读取失败：{error}"));
                    }
                }
                if buffer.len() > 1_048_576 {
                    let _ = tokio::fs::remove_file(&stored).await;
                    return bad("表单字段过大");
                }
            }
            fields.insert(name, String::from_utf8_lossy(&buffer).into_owned());
        }
    }
    if let Err(error) = tokio::io::AsyncWriteExt::flush(&mut file).await {
        let _ = tokio::fs::remove_file(&stored).await;
        return server_error(format!("刷新临时文件失败：{error}"));
    }
    drop(file);
    if !has_file || size == 0 {
        let _ = tokio::fs::remove_file(&stored).await;
        return bad("缺少上传文件");
    }

    let result = finalize_upload(
        &pool,
        &user,
        &config,
        id,
        &stored,
        &file_name,
        size,
        &hasher.finalize(),
        &fields,
    )
    .await;
    match result {
        Ok(t) => {
            audit(&pool, &req, &user, "create", id, "success").await;
            HttpResponse::Ok().json(json!({"success": true, "data": t}))
        }
        Err(message) => {
            let _ = tokio::fs::remove_file(&stored).await;
            bad(message)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn finalize_upload(
    pool: &Pool,
    user: &UserBaseI,
    config: &DataImportConfig,
    id: Uuid,
    stored: &std::path::Path,
    file_name: &str,
    size: u64,
    sha256_bytes: &[u8],
    fields: &BTreeMap<String, String>,
) -> Result<task::Task, String> {
    let headers = {
        let file = std::fs::File::open(stored).map_err(|e| format!("读取上传文件失败：{e}"))?;
        csv::read_headers(file)?
    };
    let mapping_json = fields.get("mapping").ok_or("缺少 mapping 字段")?;
    let mapping: BTreeMap<String, String> =
        serde_json::from_str(mapping_json).map_err(|e| format!("mapping 解析失败：{e}"))?;
    schema::validate_mapping(&headers, &mapping)?;

    let batch_size = parse_option(
        fields.get("batch_size"),
        config.default_batch_size,
        1,
        config.max_batch_size,
    )?;
    let concurrency = parse_option(
        fields.get("concurrency"),
        config.default_concurrency,
        1,
        config.max_concurrency,
    )?;
    let on_invalid = match fields
        .get("on_invalid")
        .map(String::as_str)
        .unwrap_or("skip")
    {
        "abort" => "abort",
        _ => "skip",
    };
    let overwrite_policy = match fields
        .get("overwrite_policy")
        .map(String::as_str)
        .unwrap_or("fill")
    {
        "overwrite" => "overwrite",
        _ => "fill",
    };
    let fast = fields.get("fast").map(|v| v == "true").unwrap_or(false);
    let dry_run = fields.get("dry_run").map(|v| v == "true").unwrap_or(false);
    let sha256: String = sha256_bytes.iter().map(|b| format!("{b:02x}")).collect();

    task::create_task(
        pool,
        NewTask {
            id,
            created_by: user.id,
            file_name,
            file_size: size as i64,
            sha256: &sha256,
            storage_path: &stored.to_string_lossy(),
            file_headers: json!(headers),
            header_mapping: json!(mapping),
            on_invalid,
            overwrite_policy,
            dry_run,
            fast_mode: fast,
            batch_size: batch_size as i32,
            concurrency: concurrency as i32,
        },
    )
    .await
    .map_err(|e| e.to_string())
}

fn parse_option(value: Option<&String>, default: u32, min: u32, max: u32) -> Result<u32, String> {
    match value {
        None => Ok(default),
        Some(raw) if raw.trim().is_empty() => Ok(default),
        Some(raw) => {
            let parsed: u32 = raw.trim().parse().map_err(|_| format!("数值非法：{raw}"))?;
            if parsed < min || parsed > max {
                return Err(format!("数值须在 {min}..={max}"));
            }
            Ok(parsed)
        }
    }
}
