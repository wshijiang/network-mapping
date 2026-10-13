use actix_web::{HttpRequest, HttpResponse, Responder, get, patch, post, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::error;
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write as write_audit};
use crate::config::SecurityConfig;
use crate::logs::write::error_diagnostics;
use crate::system_maintenance::{
    DEFAULT_RETRY_AFTER_SECONDS, MaintenanceSnapshot, RESULT_UPLOAD_GRACE_HOURS,
    SystemMaintenanceState, active_task_count, held_task_count,
};
use crate::{
    scan_control::dispatch::ApplyTaskError, scan_control::dispatch::validate_scanner_credentials,
};

const DEFAULT_HISTORY_LIMIT: i64 = 20;
const MAX_HISTORY_LIMIT: i64 = 100;

fn log_maintenance_failure(
    event: &'static str,
    operation: &'static str,
    error_value: &(dyn std::error::Error + 'static),
    maintenance_id: Option<Uuid>,
    revision: Option<i64>,
    outcome: &'static str,
) {
    let diagnostics = error_diagnostics(error_value);
    error!(
        event,
        operation,
        error_kind = "database",
        error_code = %format!("{operation}_failed"),
        error_message = %diagnostics.error_message,
        error_chain = %diagnostics.error_chain,
        root_cause = %diagnostics.root_cause,
        error_truncated = diagnostics.error_truncated,
        retryable = false,
        outcome,
        maintenance_id = ?maintenance_id,
        revision = ?revision,
    );
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterMaintenanceRequest {
    message: String,
    expected_end_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMaintenanceRequest {
    message: String,
    expected_end_at: Option<DateTime<Utc>>,
    revision: i64,
}

#[derive(Deserialize)]
pub struct ExitMaintenanceRequest {
    revision: i64,
}

#[derive(Deserialize)]
pub struct SystemMaintenanceHistoryQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Deserialize)]
pub struct ScannerSystemMaintenanceQuery {
    scannerid: Uuid,
}

#[derive(Serialize)]
struct SystemMaintenanceHistoryItem {
    maintenance_id: Uuid,
    message: String,
    started_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    expected_end_at: Option<DateTime<Utc>>,
    actual_duration_seconds: i64,
    operator_username: String,
    in_progress: bool,
}

// Callers immediately return the response, so preserving the unboxed type
// avoids an allocation on authorization failures.
#[allow(clippy::result_large_err)]
fn require_admin(user: &UserBaseI) -> Result<(), HttpResponse> {
    if user.role == 1 {
        Ok(())
    } else {
        Err(HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以管理系统维护模式"
        })))
    }
}

// Validation errors are returned directly by the request handlers.
#[allow(clippy::result_large_err)]
fn validate_message(message: &str) -> Result<String, HttpResponse> {
    let message = message.trim();
    if message.is_empty() {
        return Err(HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "请输入维护说明"
        })));
    }
    if message.chars().count() > 500 {
        return Err(HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "维护说明不能超过 500 个字符"
        })));
    }
    Ok(message.to_owned())
}

async fn status_response(pool: &Pool, snapshot: MaintenanceSnapshot) -> HttpResponse {
    match (active_task_count(pool).await, held_task_count(pool).await) {
        (Ok(running_tasks), Ok(held_tasks)) => HttpResponse::Ok().json(json!({
            "success": true,
            "data": snapshot,
            "running_tasks": running_tasks,
            "held_tasks": held_tasks,
        })),
        (Err(error_value), _) | (_, Err(error_value)) => {
            log_maintenance_failure(
                "SystemMaintenanceCountError",
                "load_maintenance_task_counts",
                error_value.as_ref(),
                snapshot.maintenance_id,
                Some(snapshot.revision),
                "request_failed",
            );
            HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "读取运行任务数量失败"
            }))
        }
    }
}

#[get("/api/admin/system-maintenance")]
pub async fn get_maintenance_status(
    pool: web::Data<Pool>,
    state: web::Data<SystemMaintenanceState>,
    user: UserBaseI,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    status_response(pool.get_ref(), state.snapshot().await).await
}

#[get("/api/admin/system-maintenance/history")]
pub async fn get_maintenance_history(
    pool: web::Data<Pool>,
    user: UserBaseI,
    query: web::Query<SystemMaintenanceHistoryQuery>,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    let limit = query
        .limit
        .unwrap_or(DEFAULT_HISTORY_LIMIT)
        .clamp(1, MAX_HISTORY_LIMIT);
    let offset = query.offset.unwrap_or(0).max(0);
    let client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            log_maintenance_failure(
                "SystemMaintenanceHistoryPoolError",
                "acquire_maintenance_history_connection",
                &error_value,
                None,
                None,
                "request_failed",
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let rows = match client
        .query(
            "SELECT maintenance_id, message, started_at, ended_at, expected_end_at, \
             EXTRACT(EPOCH FROM (COALESCE(ended_at, NOW()) - started_at))::BIGINT \
             AS actual_duration_seconds, started_by_username, ended_at IS NULL AS in_progress \
             FROM system_maintenance_history ORDER BY started_at DESC, id DESC LIMIT $1 OFFSET $2;",
            &[&limit, &offset],
        )
        .await
    {
        Ok(rows) => rows,
        Err(error_value) => {
            log_maintenance_failure(
                "SystemMaintenanceHistoryQueryError",
                "load_maintenance_history",
                &error_value,
                None,
                None,
                "request_failed",
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let total = match client
        .query_one(
            "SELECT COUNT(*)::BIGINT AS count FROM system_maintenance_history;",
            &[],
        )
        .await
    {
        Ok(row) => row.get::<_, i64>("count"),
        Err(error_value) => {
            log_maintenance_failure(
                "SystemMaintenanceHistoryCountError",
                "count_maintenance_history",
                &error_value,
                None,
                None,
                "request_failed",
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let items: Vec<SystemMaintenanceHistoryItem> = rows
        .iter()
        .map(|row| SystemMaintenanceHistoryItem {
            maintenance_id: row.get("maintenance_id"),
            message: row.get("message"),
            started_at: row.get("started_at"),
            ended_at: row.get("ended_at"),
            expected_end_at: row.get("expected_end_at"),
            actual_duration_seconds: row.get("actual_duration_seconds"),
            operator_username: row.get("started_by_username"),
            in_progress: row.get("in_progress"),
        })
        .collect();
    HttpResponse::Ok().json(json!({
        "success": true,
        "data": { "items": items, "total": total }
    }))
}

#[post("/api/admin/system-maintenance/enter")]
pub async fn enter_maintenance(
    req: HttpRequest,
    pool: web::Data<Pool>,
    state: web::Data<SystemMaintenanceState>,
    user: UserBaseI,
    body: web::Json<EnterMaintenanceRequest>,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    let message = match validate_message(&body.message) {
        Ok(message) => message,
        Err(response) => return response,
    };
    if body
        .expected_end_at
        .is_some_and(|value| value <= Utc::now())
    {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "预计结束时间必须晚于当前时间"
        }));
    }

    let maintenance_id = Uuid::now_v7();
    let mut client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            log_maintenance_failure(
                "SystemMaintenancePoolError",
                "acquire_maintenance_connection",
                &error_value,
                Some(maintenance_id),
                None,
                "request_failed",
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match client.transaction().await {
        Ok(transaction) => transaction,
        Err(error_value) => {
            log_maintenance_failure(
                "SystemMaintenanceTransactionError",
                "begin_maintenance_transaction",
                &error_value,
                Some(maintenance_id),
                None,
                "request_failed",
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let row = match transaction
        .query_opt(
            "UPDATE system_maintenance_state SET enabled = TRUE, phase = 'draining', \
             maintenance_id = $1, message = $2, expected_end_at = $3, retry_after_seconds = $4, \
             started_at = NOW(), started_by = $5, updated_at = NOW(), exited_at = NULL, \
             exited_by = NULL, revision = revision + 1 WHERE singleton = TRUE AND enabled = FALSE \
             RETURNING enabled, phase, maintenance_id, message, expected_end_at, \
             retry_after_seconds, started_at, updated_at, revision;",
            &[
                &maintenance_id,
                &message,
                &body.expected_end_at,
                &DEFAULT_RETRY_AFTER_SECONDS,
                &user.id,
            ],
        )
        .await
    {
        Ok(row) => row,
        Err(error_value) => {
            log_maintenance_failure(
                "SystemMaintenanceEnterError",
                "enable_system_maintenance",
                &error_value,
                Some(maintenance_id),
                None,
                "transaction_rolled_back",
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let Some(row) = row else {
        return HttpResponse::Conflict().json(json!({
            "success": false,
            "message": "系统已经处于维护模式"
        }));
    };
    match transaction
        .execute(
            "INSERT INTO system_maintenance_history (maintenance_id, message, expected_end_at, \
             started_at, started_by_user_id, started_by_username, updated_at) \
             SELECT $1, $2, $3, started_at, $4, $5, updated_at \
             FROM system_maintenance_state WHERE singleton = TRUE AND maintenance_id = $1;",
            &[
                &maintenance_id,
                &message,
                &body.expected_end_at,
                &user.id,
                &user.username,
            ],
        )
        .await
    {
        Ok(1) => {}
        Ok(_) => {
            error!(
                event = "SystemMaintenanceHistoryInsertMissing",
                operation = "insert_maintenance_history",
                error_kind = "data_integrity",
                error_code = "maintenance_history_row_missing",
                error_message = "maintenance history insert affected no row",
                retryable = false,
                outcome = "transaction_rolled_back",
                maintenance_id = %maintenance_id,
            );
            return HttpResponse::InternalServerError().finish();
        }
        Err(error_value) => {
            log_maintenance_failure(
                "SystemMaintenanceHistoryInsertError",
                "insert_maintenance_history",
                &error_value,
                Some(maintenance_id),
                None,
                "transaction_rolled_back",
            );
            return HttpResponse::InternalServerError().finish();
        }
    }
    if let Err(error_value) = transaction
        .execute(
            "UPDATE scan_task_execution SET maintenance_hold = TRUE, \
             maintenance_hold_until = NULL, lease_expires_at = NULL \
             WHERE execution_status = 'running';",
            &[],
        )
        .await
    {
        log_maintenance_failure(
            "SystemMaintenanceHoldTasksError",
            "hold_running_tasks",
            &error_value,
            Some(maintenance_id),
            None,
            "transaction_rolled_back",
        );
        return HttpResponse::InternalServerError().finish();
    }
    let snapshot = MaintenanceSnapshot::from_row(&row);
    let mut audit = AuditEvent::user(
        "configuration",
        "system.maintenance.enter",
        "success",
        &user,
    )
    .resource("system_maintenance", maintenance_id.to_string());
    audit.response_status = Some(200);
    audit.changes = Some(json!({
        "phase": "draining",
        "message": message,
        "expected_end_at": body.expected_end_at,
        "retry_after_seconds": DEFAULT_RETRY_AFTER_SECONDS,
        "task_action": "finish_and_cache",
    }));
    if let Err(error_value) =
        write_audit(&transaction, &AuditContext::from_request(&req), &audit).await
    {
        log_maintenance_failure(
            "SystemMaintenanceAuditError",
            "write_maintenance_audit",
            &error_value,
            Some(maintenance_id),
            Some(snapshot.revision),
            "transaction_rolled_back",
        );
        return HttpResponse::InternalServerError().finish();
    }
    if let Err(error_value) = transaction.commit().await {
        log_maintenance_failure(
            "SystemMaintenanceCommitError",
            "commit_maintenance_entry",
            &error_value,
            Some(maintenance_id),
            Some(snapshot.revision),
            "database_state_unknown",
        );
        return HttpResponse::InternalServerError().finish();
    }
    state.replace(snapshot.clone()).await;
    status_response(pool.get_ref(), snapshot).await
}

#[patch("/api/admin/system-maintenance")]
pub async fn update_maintenance(
    req: HttpRequest,
    pool: web::Data<Pool>,
    state: web::Data<SystemMaintenanceState>,
    user: UserBaseI,
    body: web::Json<UpdateMaintenanceRequest>,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    let message = match validate_message(&body.message) {
        Ok(message) => message,
        Err(response) => return response,
    };
    if body
        .expected_end_at
        .is_some_and(|value| value <= Utc::now())
    {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "预计结束时间必须晚于当前时间"
        }));
    }
    let current_snapshot = state.snapshot().await;
    let mut client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            log_maintenance_failure(
                "SystemMaintenancePoolError",
                "acquire_maintenance_update_connection",
                &error_value,
                current_snapshot.maintenance_id,
                Some(body.revision),
                "request_failed",
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match client.transaction().await {
        Ok(transaction) => transaction,
        Err(error_value) => {
            log_maintenance_failure(
                "SystemMaintenanceTransactionError",
                "begin_maintenance_update_transaction",
                &error_value,
                current_snapshot.maintenance_id,
                Some(body.revision),
                "request_failed",
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let row = match transaction
        .query_opt(
            "UPDATE system_maintenance_state SET message = $1, expected_end_at = $2, \
             updated_at = NOW(), revision = revision + 1 WHERE singleton = TRUE \
             AND enabled = TRUE AND revision = $3 RETURNING enabled, phase, maintenance_id, \
             message, expected_end_at, retry_after_seconds, started_at, updated_at, revision;",
            &[&message, &body.expected_end_at, &body.revision],
        )
        .await
    {
        Ok(row) => row,
        Err(error_value) => {
            log_maintenance_failure(
                "SystemMaintenanceUpdateError",
                "update_maintenance_state",
                &error_value,
                current_snapshot.maintenance_id,
                Some(body.revision),
                "transaction_rolled_back",
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let Some(row) = row else {
        return HttpResponse::Conflict().json(json!({
            "success": false,
            "message": "维护状态已变化，请刷新后重试"
        }));
    };
    let snapshot = MaintenanceSnapshot::from_row(&row);
    let Some(maintenance_id) = snapshot.maintenance_id else {
        error!(
            event = "SystemMaintenanceMissingId",
            operation = "validate_maintenance_state",
            error_kind = "data_integrity",
            error_code = "enabled_maintenance_id_missing",
            error_message = "enabled system maintenance has no identity",
            retryable = false,
            outcome = "transaction_rolled_back",
            revision = snapshot.revision,
            "enabled system maintenance has no id"
        );
        return HttpResponse::InternalServerError().finish();
    };
    match transaction
        .execute(
            "UPDATE system_maintenance_history SET message = $1, expected_end_at = $2, \
             updated_at = NOW() WHERE maintenance_id = $3 AND ended_at IS NULL;",
            &[&message, &body.expected_end_at, &maintenance_id],
        )
        .await
    {
        Ok(1) => {}
        Ok(_) => {
            error!(
                event = "SystemMaintenanceHistoryMissing",
                operation = "update_maintenance_history",
                error_kind = "data_integrity",
                error_code = "maintenance_history_row_missing",
                error_message = "active maintenance history row was not found",
                retryable = false,
                outcome = "transaction_rolled_back",
                maintenance_id = %maintenance_id,
                revision = snapshot.revision,
            );
            return HttpResponse::InternalServerError().finish();
        }
        Err(error_value) => {
            log_maintenance_failure(
                "SystemMaintenanceHistoryUpdateError",
                "update_maintenance_history",
                &error_value,
                Some(maintenance_id),
                Some(snapshot.revision),
                "transaction_rolled_back",
            );
            return HttpResponse::InternalServerError().finish();
        }
    }
    let mut audit = AuditEvent::user(
        "configuration",
        "system.maintenance.update",
        "success",
        &user,
    );
    audit.resource_type = Some("system_maintenance".to_owned());
    audit.resource_id = Some(maintenance_id.to_string());
    audit.response_status = Some(200);
    audit.changes = Some(json!({
        "message": message,
        "expected_end_at": body.expected_end_at,
    }));
    if let Err(error_value) =
        write_audit(&transaction, &AuditContext::from_request(&req), &audit).await
    {
        log_maintenance_failure(
            "SystemMaintenanceAuditError",
            "write_maintenance_update_audit",
            &error_value,
            Some(maintenance_id),
            Some(snapshot.revision),
            "transaction_rolled_back",
        );
        return HttpResponse::InternalServerError().finish();
    }
    if let Err(error_value) = transaction.commit().await {
        log_maintenance_failure(
            "SystemMaintenanceCommitError",
            "commit_maintenance_update",
            &error_value,
            Some(maintenance_id),
            Some(snapshot.revision),
            "database_state_unknown",
        );
        return HttpResponse::InternalServerError().finish();
    }
    state.replace(snapshot.clone()).await;
    status_response(pool.get_ref(), snapshot).await
}

#[post("/api/admin/system-maintenance/exit")]
pub async fn exit_maintenance(
    req: HttpRequest,
    pool: web::Data<Pool>,
    state: web::Data<SystemMaintenanceState>,
    user: UserBaseI,
    body: web::Json<ExitMaintenanceRequest>,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    let current_snapshot = state.snapshot().await;
    let mut client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            log_maintenance_failure(
                "SystemMaintenancePoolError",
                "acquire_maintenance_exit_connection",
                &error_value,
                current_snapshot.maintenance_id,
                Some(body.revision),
                "request_failed",
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match client.transaction().await {
        Ok(transaction) => transaction,
        Err(error_value) => {
            log_maintenance_failure(
                "SystemMaintenanceTransactionError",
                "begin_maintenance_exit_transaction",
                &error_value,
                current_snapshot.maintenance_id,
                Some(body.revision),
                "request_failed",
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let row = match transaction
        .query_opt(
            "UPDATE system_maintenance_state AS state SET enabled = FALSE, phase = 'off', \
             maintenance_id = NULL, message = '', expected_end_at = NULL, started_at = NULL, \
             updated_at = NOW(), exited_at = NOW(), exited_by = $1, revision = revision + 1 \
             FROM (SELECT maintenance_id AS previous_maintenance_id \
                   FROM system_maintenance_state WHERE singleton = TRUE) AS previous \
             WHERE state.singleton = TRUE AND state.enabled = TRUE AND state.revision = $2 \
             RETURNING state.enabled, state.phase, state.maintenance_id, state.message, \
             state.expected_end_at, state.retry_after_seconds, state.started_at, state.updated_at, \
             state.revision, previous.previous_maintenance_id;",
            &[&user.id, &body.revision],
        )
        .await
    {
        Ok(row) => row,
        Err(error_value) => {
            log_maintenance_failure(
                "SystemMaintenanceExitError",
                "disable_system_maintenance",
                &error_value,
                current_snapshot.maintenance_id,
                Some(body.revision),
                "transaction_rolled_back",
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let Some(row) = row else {
        return HttpResponse::Conflict().json(json!({
            "success": false,
            "message": "维护状态已变化，请刷新后重试"
        }));
    };
    let previous_maintenance_id: Option<Uuid> = row.get("previous_maintenance_id");
    let Some(previous_maintenance_id) = previous_maintenance_id else {
        error!(
            event = "SystemMaintenanceMissingId",
            operation = "validate_maintenance_exit_state",
            error_kind = "data_integrity",
            error_code = "exiting_maintenance_id_missing",
            error_message = "maintenance exit did not return the previous identity",
            retryable = false,
            outcome = "transaction_rolled_back",
            revision = body.revision,
            "exiting system maintenance has no id"
        );
        return HttpResponse::InternalServerError().finish();
    };
    match transaction
        .execute(
            "UPDATE system_maintenance_history SET ended_at = NOW(), ended_by_user_id = $1, \
             ended_by_username = $2, updated_at = NOW() \
             WHERE maintenance_id = $3 AND ended_at IS NULL;",
            &[&user.id, &user.username, &previous_maintenance_id],
        )
        .await
    {
        Ok(1) => {}
        Ok(_) => {
            error!(
                event = "SystemMaintenanceHistoryMissing",
                operation = "close_maintenance_history",
                error_kind = "data_integrity",
                error_code = "maintenance_history_row_missing",
                error_message = "active maintenance history row was not found during exit",
                retryable = false,
                outcome = "transaction_rolled_back",
                maintenance_id = %previous_maintenance_id,
                revision = body.revision,
            );
            return HttpResponse::InternalServerError().finish();
        }
        Err(error_value) => {
            log_maintenance_failure(
                "SystemMaintenanceHistoryExitError",
                "close_maintenance_history",
                &error_value,
                Some(previous_maintenance_id),
                Some(body.revision),
                "transaction_rolled_back",
            );
            return HttpResponse::InternalServerError().finish();
        }
    }
    if let Err(error_value) = transaction
        .execute(
            "UPDATE scan_task_execution SET maintenance_hold_until = \
             NOW() + make_interval(hours => $1::int) WHERE execution_status = 'running' \
             AND maintenance_hold = TRUE;",
            &[&RESULT_UPLOAD_GRACE_HOURS],
        )
        .await
    {
        log_maintenance_failure(
            "SystemMaintenanceReleaseTasksError",
            "release_maintenance_tasks",
            &error_value,
            Some(previous_maintenance_id),
            Some(body.revision),
            "transaction_rolled_back",
        );
        return HttpResponse::InternalServerError().finish();
    }
    let snapshot = MaintenanceSnapshot::from_row(&row);
    let mut audit = AuditEvent::user("configuration", "system.maintenance.exit", "success", &user);
    audit.resource_type = Some("system_maintenance".to_owned());
    audit.resource_id = Some(previous_maintenance_id.to_string());
    audit.response_status = Some(200);
    audit.changes = Some(json!({
        "phase": "off",
        "result_upload_grace_hours": RESULT_UPLOAD_GRACE_HOURS,
    }));
    if let Err(error_value) =
        write_audit(&transaction, &AuditContext::from_request(&req), &audit).await
    {
        log_maintenance_failure(
            "SystemMaintenanceAuditError",
            "write_maintenance_exit_audit",
            &error_value,
            Some(previous_maintenance_id),
            Some(snapshot.revision),
            "transaction_rolled_back",
        );
        return HttpResponse::InternalServerError().finish();
    }
    if let Err(error_value) = transaction.commit().await {
        log_maintenance_failure(
            "SystemMaintenanceCommitError",
            "commit_maintenance_exit",
            &error_value,
            Some(previous_maintenance_id),
            Some(snapshot.revision),
            "database_state_unknown",
        );
        return HttpResponse::InternalServerError().finish();
    }
    state.replace(snapshot.clone()).await;
    status_response(pool.get_ref(), snapshot).await
}

#[get("/api/scanner/maintenance")]
pub async fn scanner_system_maintenance_probe(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    state: web::Data<SystemMaintenanceState>,
    query: web::Query<ScannerSystemMaintenanceQuery>,
) -> impl Responder {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let Some(token) = token else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };
    match validate_scanner_credentials(
        pool.get_ref(),
        query.scannerid,
        token,
        &security.scanner_token_pepper,
    )
    .await
    {
        Ok(()) => HttpResponse::Ok().json(json!({
            "success": true,
            "maintenance": state.snapshot().await,
            "server_time": Utc::now(),
        })),
        Err(ApplyTaskError::ScannerUnauthorized) => {
            HttpResponse::Unauthorized().body("unauthorized")
        }
        Err(error_value) => {
            let snapshot = state.snapshot().await;
            let diagnostics = error_diagnostics(&error_value);
            error!(
                event = "SystemMaintenanceProbeError",
                operation = "validate_scanner_for_maintenance_probe",
                error_kind = "database",
                error_code = "maintenance_probe_validation_failed",
                error_message = %diagnostics.error_message,
                error_chain = %diagnostics.error_chain,
                root_cause = %diagnostics.root_cause,
                error_truncated = diagnostics.error_truncated,
                retryable = true,
                outcome = "request_failed",
                scanner_id = %query.scannerid,
                maintenance_id = ?snapshot.maintenance_id,
                phase = ?snapshot.phase,
                revision = snapshot.revision,
            );
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::validate_message;

    #[test]
    fn maintenance_message_is_trimmed_and_bounded() {
        assert_eq!(validate_message("  upgrade  ").unwrap(), "upgrade");
        assert!(validate_message("   ").is_err());
        assert!(validate_message(&"x".repeat(501)).is_err());
    }
}
