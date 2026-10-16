use actix_files::NamedFile;
use actix_web::{HttpRequest, HttpResponse, error, get, post, put, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write, write_standalone};
use crate::config::SecurityConfig;
use crate::scanner_diagnostics::{self as diagnostics, Diagnostics, parser, protocol::*};
use crate::system_maintenance::SystemMaintenanceState;

type ApiResult = actix_web::Result<HttpResponse>;

const EVENTS_BODY_LIMIT: usize = 8 * 1024 * 1024;

fn internal(error: impl std::fmt::Debug) -> actix_web::Error {
    tracing::error!(event="ScannerDiagnosticsRequestFailed",error=?error);
    error::ErrorInternalServerError("诊断操作失败")
}
fn public_error(status: actix_web::http::StatusCode, code: &'static str) -> actix_web::Error {
    error::InternalError::from_response(
        code,
        HttpResponse::build(status).json(json!({"success":false,"code":code,"message":code})),
    )
    .into()
}
fn require_admin(user: &UserBaseI) -> actix_web::Result<()> {
    if user.role != 1 {
        return Err(error::ErrorForbidden("仅管理员可以访问扫描器诊断"));
    }
    Ok(())
}
async fn machine_auth(
    req: &HttpRequest,
    pool: &Pool,
    security: &SecurityConfig,
    maintenance: &SystemMaintenanceState,
    state: &Diagnostics,
    scanner: Uuid,
) -> actix_web::Result<()> {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| error::ErrorUnauthorized("missing scanner token"))?;
    crate::scan_control::dispatch::validate_scanner_credentials(
        pool,
        scanner,
        token,
        &security.scanner_token_pepper,
    )
    .await
    .map_err(|e| match e {
        crate::scan_control::dispatch::ApplyTaskError::ScannerUnauthorized => {
            error::ErrorUnauthorized("unauthorized")
        }
        e => internal(e),
    })?;
    if !state.config.enabled {
        return Err(error::ErrorServiceUnavailable("diagnostics_disabled"));
    }
    if maintenance.snapshot().await.blocks_all_scanner_requests() {
        return Err(error::ErrorServiceUnavailable("server_maintenance"));
    }
    Ok(())
}

async fn job(pool: &Pool, scanner: Uuid, id: Uuid) -> actix_web::Result<tokio_postgres::Row> {
    let row = pool
        .get()
        .await
        .map_err(internal)?
        .query_opt(
            "SELECT * FROM scanner_diagnostic_job WHERE scanner_id=$1 AND job_id=$2",
            &[&scanner.to_string(), &id],
        )
        .await
        .map_err(internal)?
        .ok_or_else(|| {
            public_error(
                actix_web::http::StatusCode::NOT_FOUND,
                "diagnostic_job_not_found",
            )
        })?;
    let status: &str = row.get("status");
    if matches!(status, "failed" | "expired" | "cancelled")
        || (status != "ready" && row.get::<_, DateTime<Utc>>("expires_at") <= Utc::now())
    {
        return Err(public_error(
            actix_web::http::StatusCode::CONFLICT,
            "diagnostic_job_expired_or_closed",
        ));
    }
    Ok(row)
}

#[derive(Deserialize)]
pub struct CreateJob {
    #[serde(rename = "type")]
    kind: JobKind,
    #[serde(default)]
    source_file_ids: Vec<String>,
}

#[post("/api/scanner/{scanner_id}/diagnostic-jobs")]
pub async fn create_job(
    req: HttpRequest,
    pool: web::Data<Pool>,
    state: web::Data<std::sync::Arc<Diagnostics>>,
    scanner: web::Path<Uuid>,
    user: UserBaseI,
    body: web::Json<CreateJob>,
) -> ApiResult {
    require_admin(&user)?;
    if !state.config.enabled {
        return Err(error::ErrorServiceUnavailable("diagnostics_disabled"));
    }
    if body.source_file_ids.len() > MAX_FILES
        || body.source_file_ids.iter().any(|id| !valid_digest(id))
        || body
            .source_file_ids
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != body.source_file_ids.len()
        || (body.kind == JobKind::ListLogs && !body.source_file_ids.is_empty())
        || (body.kind == JobKind::CollectLogs && body.source_file_ids.is_empty())
    {
        return Err(public_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "invalid_log_selection",
        ));
    }
    let scanner = scanner.into_inner().to_string();
    let mut client = pool.get().await.map_err(internal)?;
    let tx = client.transaction().await.map_err(internal)?;
    let row = tx.query_opt("SELECT diagnostics_capabilities FROM scanner_info WHERE scanner_id=$1 AND deleted_at IS NULL AND is_enable=true FOR UPDATE", &[&scanner]).await.map_err(internal)?
        .ok_or_else(||public_error(actix_web::http::StatusCode::NOT_FOUND,"scanner_unavailable"))?;
    let caps: Capabilities = serde_json::from_value(row.get(0)).map_err(internal)?;
    if !caps.supported_versions.contains(&VERSION)
        || (body.kind == JobKind::ListLogs && !caps.can_list_logs)
        || (body.kind == JobKind::CollectLogs && !caps.can_collect_logs)
    {
        return Err(public_error(
            actix_web::http::StatusCode::CONFLICT,
            "scanner_diagnostics_unsupported",
        ));
    }
    let count:i64 = tx.query_one("SELECT COUNT(*) FROM scanner_diagnostic_job WHERE scanner_id=$1 AND status IN ('queued','accepted','uploading') AND expires_at>NOW()", &[&scanner]).await.map_err(internal)?.get(0);
    if count >= 4 {
        return Err(public_error(
            actix_web::http::StatusCode::TOO_MANY_REQUESTS,
            "diagnostic_queue_full",
        ));
    }
    for id in &body.source_file_ids {
        if tx.query_opt("SELECT 1 FROM scanner_log_source WHERE scanner_id=$1 AND source_file_id=$2 AND reported_at>NOW()-INTERVAL '1 day'", &[&scanner,id]).await.map_err(internal)?.is_none() {
            return Err(public_error(actix_web::http::StatusCode::BAD_REQUEST,"log_catalog_stale"));
        }
    }
    let id = Uuid::now_v7();
    let kind = if body.kind == JobKind::ListLogs {
        "list_logs"
    } else {
        "collect_logs"
    };
    let row = tx.query_one("INSERT INTO scanner_diagnostic_job(job_id,scanner_id,kind,source_file_ids,requested_by) VALUES($1,$2,$3,$4,$5) RETURNING *", &[&id,&scanner,&kind,&json!(body.source_file_ids),&user.id]).await.map_err(internal)?;
    let event = AuditEvent::user("scanner", "scanner.diagnostics.request", "success", &user)
        .resource("scanner", &scanner);
    write(&tx, &AuditContext::from_request(&req), &event)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok(HttpResponse::Accepted().json(json!({"success":true,"data":diagnostics::job_json(&row)})))
}

#[get("/api/scanner/{scanner_id}/diagnostic-jobs")]
pub async fn list_jobs(
    pool: web::Data<Pool>,
    scanner: web::Path<Uuid>,
    user: UserBaseI,
) -> ApiResult {
    require_admin(&user)?;
    let rows=pool.get().await.map_err(internal)?.query("SELECT * FROM scanner_diagnostic_job WHERE scanner_id=$1 ORDER BY created_at DESC LIMIT 50", &[&scanner.to_string()]).await.map_err(internal)?;
    Ok(HttpResponse::Ok().json(
        json!({"success":true,"data":rows.iter().map(diagnostics::job_json).collect::<Vec<_>>()}),
    ))
}

#[get("/api/scanner/{scanner_id}/diagnostic-jobs/{job_id}")]
pub async fn get_job(
    pool: web::Data<Pool>,
    path: web::Path<(Uuid, Uuid)>,
    user: UserBaseI,
) -> ApiResult {
    require_admin(&user)?;
    let (scanner, id) = path.into_inner();
    let row = pool
        .get()
        .await
        .map_err(internal)?
        .query_opt(
            "SELECT * FROM scanner_diagnostic_job WHERE scanner_id=$1 AND job_id=$2",
            &[&scanner.to_string(), &id],
        )
        .await
        .map_err(internal)?
        .ok_or_else(|| {
            public_error(
                actix_web::http::StatusCode::NOT_FOUND,
                "diagnostic_job_not_found",
            )
        })?;
    Ok(HttpResponse::Ok().json(json!({"success":true,"data":diagnostics::job_json(&row)})))
}

#[get("/api/scanner/{scanner_id}/log-files")]
pub async fn list_files(
    pool: web::Data<Pool>,
    scanner: web::Path<Uuid>,
    user: UserBaseI,
) -> ApiResult {
    require_admin(&user)?;
    let client = pool.get().await.map_err(internal)?;
    let scanner = scanner.to_string();
    let sources=client.query("SELECT document FROM scanner_log_source WHERE scanner_id=$1 AND reported_at>NOW()-INTERVAL '1 day' ORDER BY document->>'name' DESC LIMIT 128", &[&scanner]).await.map_err(internal)?;
    let files = client
        .query(
            "SELECT * FROM scanner_log_file WHERE scanner_id=$1 ORDER BY created_at DESC LIMIT 50",
            &[&scanner],
        )
        .await
        .map_err(internal)?;
    let data:Vec<Value>=files.iter().map(|row|json!({"file_id":row.get::<_,Uuid>("file_id"),"job_id":row.get::<_,Uuid>("job_id"),"snapshot":row.get::<_,Value>("snapshot"),"ready":row.get::<_,bool>("ready"),"parse_status":row.get::<_,String>("parse_status"),"parse_summary":row.get::<_,Option<Value>>("parse_summary")})).collect();
    Ok(HttpResponse::Ok().json(json!({"success":true,"data":{"sources":sources.iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>(),"files":data}})))
}

#[get("/api/scanner/{scanner_id}/log-files/{file_id}/download")]
pub async fn download(
    req: HttpRequest,
    pool: web::Data<Pool>,
    state: web::Data<std::sync::Arc<Diagnostics>>,
    path: web::Path<(Uuid, Uuid)>,
    user: UserBaseI,
) -> actix_web::Result<NamedFile> {
    require_admin(&user)?;
    let (scanner, id) = path.into_inner();
    let row = pool
        .get()
        .await
        .map_err(internal)?
        .query_opt(
            "SELECT snapshot FROM scanner_log_file WHERE scanner_id=$1 AND file_id=$2 AND ready",
            &[&scanner.to_string(), &id],
        )
        .await
        .map_err(internal)?
        .ok_or_else(|| {
            public_error(actix_web::http::StatusCode::NOT_FOUND, "log_file_not_ready")
        })?;
    let snapshot: Snapshot = serde_json::from_value(row.get(0)).map_err(internal)?;
    let file = NamedFile::open_async(state.file_path(id))
        .await
        .map_err(|_| public_error(actix_web::http::StatusCode::NOT_FOUND, "log_file_expired"))?;
    let event = AuditEvent::user("scanner", "scanner.log.download", "success", &user)
        .resource("scanner_log", id.to_string());
    write_standalone(&pool, &AuditContext::from_request(&req), &event).await;
    Ok(file
        .set_content_disposition(actix_web::http::header::ContentDisposition {
            disposition: actix_web::http::header::DispositionType::Attachment,
            parameters: vec![actix_web::http::header::DispositionParam::Filename(
                snapshot.source.name,
            )],
        })
        .use_last_modified(false))
}

#[derive(Deserialize)]
pub struct ErrorQuery {
    page: Option<i64>,
    level: Option<String>,
    error_code: Option<String>,
    task_id: Option<Uuid>,
}

#[get("/api/scanner/{scanner_id}/errors")]
pub async fn list_errors(
    pool: web::Data<Pool>,
    scanner: web::Path<Uuid>,
    user: UserBaseI,
    query: web::Query<ErrorQuery>,
) -> ApiResult {
    require_admin(&user)?;
    if query
        .level
        .as_ref()
        .is_some_and(|s| !matches!(s.as_str(), "ERROR" | "WARN"))
        || query.error_code.as_ref().is_some_and(|s| s.len() > 128)
    {
        return Err(public_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "invalid_error_filter",
        ));
    }
    let page = query.page.unwrap_or(1).clamp(1, 1000);
    let rows=pool.get().await.map_err(internal)?.query("SELECT e.*, (SELECT jsonb_agg(jsonb_build_object('file_id',v.file_id,'line_number',v.line_number,'byte_offset',v.byte_offset)) \
        FROM scanner_error_evidence v WHERE v.scanner_id=e.scanner_id AND v.event_id=e.event_id) AS evidence FROM scanner_error_event e \
        WHERE e.scanner_id=$1 AND ($2::text IS NULL OR e.level=$2) AND ($3::text IS NULL OR e.error_code=$3) \
        AND ($4::text IS NULL OR e.document->>'task_id'=$4) ORDER BY e.occurred_at DESC,e.event_id DESC LIMIT 51 OFFSET $5",
        &[&scanner.to_string(),&query.level,&query.error_code,&query.task_id.map(|id|id.to_string()),&((page-1)*50)]).await.map_err(internal)?;
    let more = rows.len() > 50;
    let error_records:Vec<Value>=rows.iter().take(50).map(|r|json!({"event_id":r.get::<_,String>("event_id"),"occurred_at":r.get::<_,DateTime<Utc>>("occurred_at"),"received_at":r.get::<_,DateTime<Utc>>("received_at"),"level":r.get::<_,String>("level"),"fingerprint":r.get::<_,String>("fingerprint"),"document":r.get::<_,Value>("document"),"evidence":r.get::<_,Option<Value>>("evidence")})).collect();
    Ok(HttpResponse::Ok()
        .json(json!({"success":true,"data":error_records,"page":page,"has_more":more})))
}

#[get("/api/scanner/{scanner_id}/incidents")]
pub async fn list_incidents(
    pool: web::Data<Pool>,
    scanner: web::Path<Uuid>,
    user: UserBaseI,
) -> ApiResult {
    require_admin(&user)?;
    let rows=pool.get().await.map_err(internal)?.query("SELECT * FROM scanner_incident WHERE scanner_id=$1 ORDER BY (recovered_at IS NULL) DESC,last_seen_at DESC LIMIT 50", &[&scanner.to_string()]).await.map_err(internal)?;
    let incidents:Vec<Value>=rows.iter().map(|r|json!({"fingerprint":r.get::<_,String>("fingerprint"),"error_code":r.get::<_,String>("error_code"),"operation":r.get::<_,String>("operation"),"first_seen_at":r.get::<_,DateTime<Utc>>("first_seen_at"),"last_seen_at":r.get::<_,DateTime<Utc>>("last_seen_at"),"occurrences":r.get::<_,i64>("occurrences"),"acknowledged_at":r.get::<_,Option<DateTime<Utc>>>("acknowledged_at"),"recovered_at":r.get::<_,Option<DateTime<Utc>>>("recovered_at")})).collect();
    Ok(HttpResponse::Ok().json(json!({"success":true,"data":incidents})))
}

#[post("/api/scanner/{scanner_id}/incidents/{fingerprint}/ack")]
pub async fn acknowledge(
    req: HttpRequest,
    pool: web::Data<Pool>,
    path: web::Path<(Uuid, String)>,
    user: UserBaseI,
) -> ApiResult {
    require_admin(&user)?;
    let (scanner, fingerprint) = path.into_inner();
    if !valid_digest(&fingerprint) {
        return Err(public_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "invalid_incident",
        ));
    }
    let mut client = pool.get().await.map_err(internal)?;
    let tx = client.transaction().await.map_err(internal)?;
    let changed=tx.execute("UPDATE scanner_incident SET acknowledged_at=NOW(),acknowledged_by=$3 WHERE scanner_id=$1 AND fingerprint=$2", &[&scanner.to_string(),&fingerprint,&user.id]).await.map_err(internal)?;
    if changed == 0 {
        return Err(public_error(
            actix_web::http::StatusCode::NOT_FOUND,
            "incident_not_found",
        ));
    }
    write(
        &tx,
        &AuditContext::from_request(&req),
        &AuditEvent::user("scanner", "scanner.incident.ack", "success", &user)
            .resource("scanner", scanner.to_string()),
    )
    .await
    .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok(HttpResponse::Ok().json(json!({"success":true})))
}

#[post("/api/scanner/diagnostics/ack")]
pub async fn machine_ack(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
    state: web::Data<std::sync::Arc<Diagnostics>>,
    body: web::Json<Ack>,
) -> ApiResult {
    machine_auth(
        &req,
        &pool,
        &security,
        &maintenance,
        &state,
        body.scanner_id,
    )
    .await?;
    let existing = job(&pool, body.scanner_id, body.job_id).await?;
    if !matches!(body.status.as_str(), "accepted" | "failed")
        || body.error_code.as_ref().is_some_and(|s| {
            s.len() > 128
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit())
        })
    {
        return Err(public_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "invalid_diagnostic_status",
        ));
    }
    if existing.get::<_, &str>("status") != "ready" {
        pool.get().await.map_err(internal)?.execute("UPDATE scanner_diagnostic_job SET status=CASE WHEN $2='failed' THEN 'failed' WHEN status='queued' THEN 'accepted' ELSE status END,error_code=$3,updated_at=NOW() WHERE job_id=$1 AND status IN ('queued','accepted','uploading')", &[&body.job_id,&body.status,&body.error_code]).await.map_err(internal)?;
    }
    Ok(HttpResponse::Ok().json(json!({"success":true})))
}

fn validate_source(source: &SourceFile) -> bool {
    valid_log_name(&source.name)
        && valid_digest(&source.source_file_id)
        && source.size_bytes <= i64::MAX as u64
}

#[post("/api/scanner/diagnostics/manifest")]
pub async fn manifest(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
    state: web::Data<std::sync::Arc<Diagnostics>>,
    body: web::Json<Manifest>,
) -> ApiResult {
    machine_auth(
        &req,
        &pool,
        &security,
        &maintenance,
        &state,
        body.scanner_id,
    )
    .await?;
    if body.sources.len() > 128
        || body.files.len() > MAX_FILES
        || body.sources.iter().any(|s| !validate_source(s))
    {
        return Err(public_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "invalid_log_manifest",
        ));
    }
    let _lock = state.lock(body.job_id).await;
    let existing = job(&pool, body.scanner_id, body.job_id).await?;
    let kind: &str = existing.get("kind");
    let requested: Vec<String> =
        serde_json::from_value(existing.get("source_file_ids")).map_err(internal)?;
    let mut identities = std::collections::HashSet::new();
    let mut sources = std::collections::HashSet::new();
    let total: u64 = body
        .files
        .iter()
        .map(|f| f.size_bytes.min(MAX_FILE_BYTES + 1))
        .sum();
    if (kind == "list_logs" && !body.files.is_empty())
        || (kind == "collect_logs"
            && (body.files.len() != requested.len() || !body.sources.is_empty()))
        || total > MAX_JOB_BYTES
        || body.files.iter().any(|f| {
            !validate_source(&f.source)
                || !valid_digest(&f.sha256)
                || f.size_bytes > MAX_FILE_BYTES
                || f.size_bytes.checked_add(f.excluded_tail_bytes) != Some(f.source.size_bytes)
                || !requested.contains(&f.source.source_file_id)
                || !identities.insert(f.file_id)
                || !sources.insert(&f.source.source_file_id)
        })
    {
        return Err(public_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "invalid_log_manifest",
        ));
    }
    if existing.get::<_, &str>("status") == "ready" {
        return Ok(HttpResponse::Ok().json(json!({"success":true})));
    }
    let mut client = pool.get().await.map_err(internal)?;
    let tx = client.transaction().await.map_err(internal)?;
    // Serialize quota reservations across all jobs, including concurrent processes.
    tx.execute("SELECT pg_advisory_xact_lock(734283101)", &[])
        .await
        .map_err(internal)?;
    let persisted = tx
        .query(
            "SELECT file_id FROM scanner_log_file WHERE job_id=$1",
            &[&body.job_id],
        )
        .await
        .map_err(internal)?;
    if !persisted.is_empty()
        && (persisted.len() != body.files.len()
            || persisted
                .iter()
                .any(|row| !identities.contains(&row.get::<_, Uuid>(0))))
    {
        return Err(public_error(
            actix_web::http::StatusCode::CONFLICT,
            "log_manifest_conflict",
        ));
    }
    let reserved:i64=tx.query_one("SELECT COALESCE(SUM((snapshot->>'size_bytes')::bigint),0)::bigint FROM scanner_log_file",&[]).await.map_err(internal)?.get(0);
    let already:i64=tx.query_one("SELECT COALESCE(SUM((snapshot->>'size_bytes')::bigint),0)::bigint FROM scanner_log_file WHERE job_id=$1",&[&body.job_id]).await.map_err(internal)?.get(0);
    if ((reserved - already) as u64 + total).saturating_mul(2) > state.config.max_storage_bytes {
        return Err(error::ErrorInsufficientStorage("diagnostic_storage_full"));
    }
    for source in &body.sources {
        tx.execute("INSERT INTO scanner_log_source(scanner_id,source_file_id,document) VALUES($1,$2,$3) ON CONFLICT(scanner_id,source_file_id) DO UPDATE SET document=EXCLUDED.document,reported_at=NOW()", &[&body.scanner_id.to_string(),&source.source_file_id,&json!(source)]).await.map_err(internal)?;
    }
    for snapshot in &body.files {
        tx.execute("INSERT INTO scanner_log_file(file_id,job_id,scanner_id,snapshot) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING", &[&snapshot.file_id,&body.job_id,&body.scanner_id.to_string(),&json!(snapshot)]).await.map_err(internal)?;
        let row = tx
            .query_one(
                "SELECT job_id,snapshot FROM scanner_log_file WHERE file_id=$1",
                &[&snapshot.file_id],
            )
            .await
            .map_err(internal)?;
        if row.get::<_, Uuid>(0) != body.job_id || row.get::<_, Value>(1) != json!(snapshot) {
            return Err(public_error(
                actix_web::http::StatusCode::CONFLICT,
                "log_manifest_conflict",
            ));
        }
    }
    let changed = tx.execute(
        "UPDATE scanner_diagnostic_job SET status=$2,sources=$3,updated_at=NOW() WHERE job_id=$1 AND status IN ('queued','accepted','uploading') AND expires_at>NOW()",
        &[
            &body.job_id,
            &if kind == "list_logs" {
                "ready"
            } else {
                "uploading"
            },
            &json!(body.sources),
        ],
    )
    .await
    .map_err(internal)?;
    if changed == 0 {
        return Err(public_error(
            actix_web::http::StatusCode::CONFLICT,
            "diagnostic_job_expired_or_closed",
        ));
    }
    if kind == "list_logs" && existing.get::<_, bool>("automatic") {
        let selected: Vec<&str> = body
            .sources
            .iter()
            .rev()
            .take(2)
            .map(|s| s.source_file_id.as_str())
            .collect();
        if !selected.is_empty() {
            tx.execute("INSERT INTO scanner_diagnostic_job(job_id,scanner_id,kind,source_file_ids,automatic) VALUES($1,$2,'collect_logs',$3,true)", &[&Uuid::now_v7(),&body.scanner_id.to_string(),&json!(selected)]).await.map_err(internal)?;
        }
    }
    tx.commit().await.map_err(internal)?;
    Ok(HttpResponse::Ok().json(json!({"success":true})))
}

async fn transfer_file(pool: &Pool, transfer: &Transfer) -> actix_web::Result<Snapshot> {
    job(pool, transfer.scanner_id, transfer.job_id).await?;
    let row=pool.get().await.map_err(internal)?.query_opt("SELECT snapshot FROM scanner_log_file WHERE file_id=$1 AND job_id=$2 AND scanner_id=$3", &[&transfer.file_id,&transfer.job_id,&transfer.scanner_id.to_string()]).await.map_err(internal)?
        .ok_or_else(||public_error(actix_web::http::StatusCode::NOT_FOUND,"log_file_not_found"))?;
    serde_json::from_value(row.get(0)).map_err(internal)
}

#[get("/api/scanner/diagnostics/upload-status")]
pub async fn upload_status(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
    state: web::Data<std::sync::Arc<Diagnostics>>,
    query: web::Query<Transfer>,
) -> ApiResult {
    machine_auth(
        &req,
        &pool,
        &security,
        &maintenance,
        &state,
        query.scanner_id,
    )
    .await?;
    transfer_file(&pool, &query).await?;
    let rows = pool
        .get()
        .await
        .map_err(internal)?
        .query(
            "SELECT part_index FROM scanner_log_upload_part WHERE file_id=$1 ORDER BY part_index",
            &[&query.file_id],
        )
        .await
        .map_err(internal)?;
    Ok(HttpResponse::Ok().json(
        json!({"success":true,"parts":rows.iter().map(|r|r.get::<_,i32>(0)).collect::<Vec<_>>()}),
    ))
}

#[put("/api/scanner/diagnostics/chunk")]
pub async fn chunk(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
    state: web::Data<std::sync::Arc<Diagnostics>>,
    query: web::Query<Transfer>,
    mut payload: web::Payload,
) -> ApiResult {
    machine_auth(
        &req,
        &pool,
        &security,
        &maintenance,
        &state,
        query.scanner_id,
    )
    .await?;
    let _permit = state.transfer_slots.try_acquire().map_err(|_| {
        public_error(
            actix_web::http::StatusCode::TOO_MANY_REQUESTS,
            "diagnostic_upload_busy",
        )
    })?;
    let snapshot = transfer_file(&pool, &query).await?;
    let offset = query.part_index as u64 * CHUNK_BYTES as u64;
    if offset >= snapshot.size_bytes {
        return Err(public_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "invalid_log_part",
        ));
    }
    let expected = (snapshot.size_bytes - offset).min(CHUNK_BYTES as u64) as usize;
    let mut bytes = web::BytesMut::new();
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        while let Some(part) = payload.next().await {
            let part = part?;
            if bytes.len() + part.len() > expected {
                return Err(public_error(
                    actix_web::http::StatusCode::PAYLOAD_TOO_LARGE,
                    "log_part_too_large",
                ));
            }
            bytes.extend_from_slice(&part);
        }
        Ok::<(), actix_web::Error>(())
    })
    .await
    .map_err(|_| {
        public_error(
            actix_web::http::StatusCode::REQUEST_TIMEOUT,
            "log_part_timeout",
        )
    })??;
    if bytes.len() != expected {
        return Err(public_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "log_part_incomplete",
        ));
    }
    let digest = parser::digest(&bytes);
    let _lock = state.lock(query.file_id).await;
    let mut client = pool.get().await.map_err(internal)?;
    let tx = client.transaction().await.map_err(internal)?;
    let row = tx
        .query_one(
            "SELECT ready FROM scanner_log_file WHERE file_id=$1 FOR UPDATE",
            &[&query.file_id],
        )
        .await
        .map_err(internal)?;
    if let Some(existing) = tx
        .query_opt(
            "SELECT sha256 FROM scanner_log_upload_part WHERE file_id=$1 AND part_index=$2",
            &[&query.file_id, &(query.part_index as i32)],
        )
        .await
        .map_err(internal)?
    {
        if existing.get::<_, String>(0) != digest {
            return Err(public_error(
                actix_web::http::StatusCode::CONFLICT,
                "log_part_conflict",
            ));
        }
    } else {
        if row.get::<_, bool>(0) {
            return Err(public_error(
                actix_web::http::StatusCode::CONFLICT,
                "log_file_already_ready",
            ));
        }
        let temporary = state.config.directory.join(format!(
            "{}.{}.{}.tmp",
            query.file_id,
            query.part_index,
            Uuid::now_v7()
        ));
        let mut file = tokio::fs::File::create(&temporary)
            .await
            .map_err(internal)?;
        file.write_all(&bytes).await.map_err(internal)?;
        file.sync_all().await.map_err(internal)?;
        tokio::fs::rename(&temporary, state.part_path(query.file_id, query.part_index))
            .await
            .map_err(internal)?;
        tx.execute("INSERT INTO scanner_log_upload_part(file_id,part_index,size_bytes,sha256) VALUES($1,$2,$3,$4)", &[&query.file_id,&(query.part_index as i32),&(bytes.len() as i32),&digest]).await.map_err(internal)?;
    }
    tx.commit().await.map_err(internal)?;
    Ok(HttpResponse::Ok().json(json!({"success":true,"sha256":digest})))
}

#[post("/api/scanner/diagnostics/complete")]
pub async fn complete(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
    state: web::Data<std::sync::Arc<Diagnostics>>,
    body: web::Json<Complete>,
) -> ApiResult {
    machine_auth(
        &req,
        &pool,
        &security,
        &maintenance,
        &state,
        body.scanner_id,
    )
    .await?;
    let existing = job(&pool, body.scanner_id, body.job_id).await?;
    if existing.get::<_, &str>("status") == "ready" {
        return Ok(HttpResponse::Ok().json(json!({"success":true})));
    }
    if existing.get::<_, &str>("status") != "uploading" {
        return Err(public_error(
            actix_web::http::StatusCode::CONFLICT,
            "log_manifest_required",
        ));
    }
    let _permit = state.transfer_slots.try_acquire().map_err(|_| {
        public_error(
            actix_web::http::StatusCode::TOO_MANY_REQUESTS,
            "diagnostic_upload_busy",
        )
    })?;
    let rows = pool
        .get()
        .await
        .map_err(internal)?
        .query(
            "SELECT file_id,snapshot,ready FROM scanner_log_file WHERE job_id=$1 ORDER BY file_id",
            &[&body.job_id],
        )
        .await
        .map_err(internal)?;
    for row in rows {
        let id: Uuid = row.get("file_id");
        let _lock = state.lock(id).await;
        if row.get::<_, bool>("ready") {
            continue;
        }
        let snapshot: Snapshot = serde_json::from_value(row.get("snapshot")).map_err(internal)?;
        let count: i64 = pool
            .get()
            .await
            .map_err(internal)?
            .query_one(
                "SELECT COUNT(*) FROM scanner_log_upload_part WHERE file_id=$1",
                &[&id],
            )
            .await
            .map_err(internal)?
            .get(0);
        if count as u64 != snapshot.size_bytes.div_ceil(CHUNK_BYTES as u64) {
            return Err(public_error(
                actix_web::http::StatusCode::CONFLICT,
                "log_parts_missing",
            ));
        }
        if let Err(failure) = diagnostics::assemble(&state, snapshot.clone()).await {
            if matches!(
                failure.to_string().as_str(),
                "log_checksum_mismatch" | "log_size_mismatch"
            ) {
                pool.get().await.map_err(internal)?.execute("UPDATE scanner_diagnostic_job SET status='failed',error_code='log_checksum_mismatch',updated_at=NOW() WHERE job_id=$1 AND status='uploading'", &[&body.job_id]).await.map_err(internal)?;
                return Err(public_error(
                    actix_web::http::StatusCode::BAD_REQUEST,
                    "log_checksum_mismatch",
                ));
            }
            return Err(internal(failure));
        }
        pool.get()
            .await
            .map_err(internal)?
            .execute(
                "UPDATE scanner_log_file SET ready=true WHERE file_id=$1",
                &[&id],
            )
            .await
            .map_err(internal)?;
        for part in 0..count {
            let _ = tokio::fs::remove_file(state.part_path(id, part as u32)).await;
        }
    }
    pool.get().await.map_err(internal)?.execute("UPDATE scanner_diagnostic_job SET status='ready',updated_at=NOW() WHERE job_id=$1 AND status='uploading'", &[&body.job_id]).await.map_err(internal)?;
    Ok(HttpResponse::Ok().json(json!({"success":true})))
}

pub async fn events(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
    state: web::Data<std::sync::Arc<Diagnostics>>,
    body: web::Json<Events>,
) -> ApiResult {
    machine_auth(
        &req,
        &pool,
        &security,
        &maintenance,
        &state,
        body.scanner_id,
    )
    .await?;
    if body.events.len() > 100
        || body.events.iter().any(|e| {
            e.pointer("/fields/event_id")
                .and_then(Value::as_str)
                .is_none_or(|s| Uuid::parse_str(s).is_err())
                || e["timestamp"]
                    .as_str()
                    .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                    .is_none_or(|t| t > Utc::now() + chrono::Duration::minutes(5))
                || e.to_string().len() > parser::MAX_LINE_BYTES
        })
    {
        return Err(public_error(
            actix_web::http::StatusCode::BAD_REQUEST,
            "invalid_diagnostic_events",
        ));
    }
    let records: Vec<_> = body.events.iter().map(|e| (e.clone(), None)).collect();
    let confirmed = diagnostics::ingest(&pool, body.scanner_id, &records)
        .await
        .map_err(internal)?;
    Ok(HttpResponse::Ok().json(json!({"success":true,"confirmed":confirmed})))
}

fn events_resource() -> actix_web::Resource {
    // Limit only this endpoint; an empty-prefix scope would shadow later app routes.
    web::resource("/api/scanner/diagnostics/events")
        .app_data(web::JsonConfig::default().limit(EVENTS_BODY_LIMIT))
        .route(web::post().to(events))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(create_job)
        .service(list_jobs)
        .service(get_job)
        .service(list_files)
        .service(download)
        .service(list_errors)
        .service(list_incidents)
        .service(acknowledge)
        .service(machine_ack)
        .service(manifest)
        .service(upload_status)
        .service(chunk)
        .service(complete)
        .service(events_resource());
}

#[cfg(test)]
mod tests {
    use super::{EVENTS_BODY_LIMIT, Events, events_resource};
    use crate::{config, frontend};
    use actix_web::{App, HttpResponse, http::StatusCode, test, web};
    use serde_json::{Value, json};

    fn server_config() -> config::ServerConfig {
        serde_json::from_value(json!({
            "host": "127.0.0.1",
            "port": 9443,
            "encrypt_key": "test-only"
        }))
        .unwrap()
    }

    fn padded_events(size: usize) -> Vec<u8> {
        let mut body = serde_json::to_vec(&json!({
            "scanner_id": uuid::Uuid::nil(),
            "events": []
        }))
        .unwrap();
        assert!(size >= body.len());
        // Whitespace exercises the wire-size limit without violating event business rules.
        body.resize(size, b' ');
        body
    }

    async fn json_probe(_: web::Json<Events>) -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    #[actix_web::test]
    async fn diagnostics_do_not_shadow_application_routes() {
        let directory = std::env::temp_dir().join(format!(
            "network-mapping-diagnostic-routes-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(directory.join("assets")).unwrap();
        std::fs::create_dir_all(directory.join("maps")).unwrap();
        for file in ["index.html", "login.html", "search.html", "asset.html"] {
            std::fs::write(directory.join(file), "<html>route fixture</html>").unwrap();
        }
        let mut pool_config = deadpool_postgres::Config::new();
        pool_config.dbname = Some("unused_route_test".to_owned());
        let pool = pool_config
            .create_pool(
                Some(deadpool_postgres::Runtime::Tokio1),
                tokio_postgres::NoTls,
            )
            .unwrap();
        let server = server_config();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(
                    crate::human_verification::HumanVerificationService::new(
                        crate::human_verification::config::HumanVerificationConfig::default(),
                    )
                    .unwrap(),
                ))
                .app_data(web::Data::new(pool))
                .app_data(web::JsonConfig::default().limit(server.max_body_size))
                .app_data(web::Data::new(server))
                .app_data(web::Data::new(frontend::FrontendAssets::new(&directory)))
                .configure(config::init_routes)
                .configure(frontend::configure),
        )
        .await;

        for (path, status) in [
            ("/api/version", StatusCode::OK),
            ("/login", StatusCode::OK),
            ("/", StatusCode::OK),
            (
                "/api/scanner/diagnostics/events",
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            ("/api/nonexistent", StatusCode::NOT_FOUND),
        ] {
            let request = test::TestRequest::get().uri(path).to_request();
            assert_eq!(
                test::call_service(&app, request).await.status(),
                status,
                "{path}"
            );
        }
        // Invalid login JSON must reach the real extractor, without opening a DB connection.
        let request = test::TestRequest::post()
            .uri("/api/login")
            .set_json(json!({}))
            .to_request();
        assert_eq!(
            test::call_service(&app, request).await.status(),
            StatusCode::BAD_REQUEST
        );
        drop(app);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[actix_web::test]
    async fn events_limit_is_local_and_preserves_global_json_limit() {
        let default_limit = server_config().max_body_size;
        assert_eq!(default_limit, 64 * 1024 * 1024);
        for global_limit in [1024, default_limit] {
            let app = test::init_service(
                App::new()
                    .app_data(web::JsonConfig::default().limit(global_limit))
                    .wrap(crate::api_response::ApiErrorMiddleware)
                    // A test-only GET extractor on the production resource isolates JSON
                    // limits from the POST handler's database and authentication dependencies.
                    .service(events_resource().route(web::get().to(json_probe)))
                    .route("/api/body-limit-probe", web::post().to(json_probe)),
            )
            .await;

            for (size, status) in [
                (EVENTS_BODY_LIMIT - 1, StatusCode::OK),
                (EVENTS_BODY_LIMIT, StatusCode::OK),
                (EVENTS_BODY_LIMIT + 1, StatusCode::PAYLOAD_TOO_LARGE),
            ] {
                let request = test::TestRequest::get()
                    .uri("/api/scanner/diagnostics/events")
                    .insert_header(("Content-Type", "application/json"))
                    .set_payload(padded_events(size))
                    .to_request();
                let response = test::call_service(&app, request).await;
                assert_eq!(
                    response.status(),
                    status,
                    "global={global_limit}, size={size}"
                );
                if status == StatusCode::PAYLOAD_TOO_LARGE {
                    let body: Value = test::read_body_json(response).await;
                    assert_eq!(body["code"], "payload_too_large");
                    assert_eq!(body["success"], false);
                    assert!(body["request_id"].as_str().is_some());
                }
            }
            for (size, status) in [
                (global_limit, StatusCode::OK),
                (global_limit + 1, StatusCode::PAYLOAD_TOO_LARGE),
                (
                    EVENTS_BODY_LIMIT + 1,
                    if global_limit > EVENTS_BODY_LIMIT {
                        StatusCode::OK
                    } else {
                        StatusCode::PAYLOAD_TOO_LARGE
                    },
                ),
            ] {
                let request = test::TestRequest::post()
                    .uri("/api/body-limit-probe")
                    .insert_header(("Content-Type", "application/json"))
                    .set_payload(padded_events(size))
                    .to_request();
                assert_eq!(
                    test::call_service(&app, request).await.status(),
                    status,
                    "global={global_limit}, size={size}"
                );
            }
        }
    }
}
