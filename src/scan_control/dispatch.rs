//! scan_control / dispatch domain implementation, migrated from the library root.

use deadpool_postgres::GenericClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use tracing::info;
use uuid::Uuid;

use crate::clock::get_unix_epoch_ms;
use crate::identity::hash_scanner_token;
use crate::result_ingest::storage::dns_sidecar_upload_id;

pub const TASK_LEASE_MS: i64 = 90_000;

#[derive(Serialize, Debug)]
pub struct ApplyTask {
    pub user_id: i32,
    pub task_id: Uuid,
    pub task_target: Vec<String>,
    pub task_port: String,
    pub address_family: String,
    pub scan_plan: Value,
    pub dns_resolvers: Value,
    pub lease_expires_at_ms: i64,
    pub lease_ttl_ms: i64,
}

#[derive(Debug)]
pub enum ApplyTaskError {
    Database(Box<dyn std::error::Error + Send + Sync>),
    ScannerUnauthorized,
    UnfinishedTask(Uuid),
    NoTask,
}

pub async fn validate_scanner_credentials(
    pool: &deadpool_postgres::Pool,
    scanner_id: Uuid,
    token: &str,
    token_pepper: &str,
) -> Result<(), ApplyTaskError> {
    let token_hash = hash_scanner_token(token, token_pepper).map_err(apply_task_database_error)?;
    let p = pool.get().await.map_err(apply_task_database_error)?;
    validate_scanner_credentials_with_client(&p, scanner_id, &token_hash).await
}

pub(crate) async fn validate_scanner_credentials_with_client<C>(
    client: &C,
    scanner_id: Uuid,
    token_hash: &str,
) -> Result<(), ApplyTaskError>
where
    C: GenericClient + Sync,
{
    let scanner = client.query_opt(
        "SELECT id FROM scanner_info WHERE scanner_id = $1 AND runtime_token_hash = $2 AND is_enable = true;",
        &[&scanner_id.to_string(), &token_hash]
    ).await.map_err(apply_task_database_error)?;

    if scanner.is_some() {
        Ok(())
    } else {
        Err(ApplyTaskError::ScannerUnauthorized)
    }
}

impl fmt::Display for ApplyTaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(e) => write!(f, "{}", e),
            Self::ScannerUnauthorized => write!(f, "扫描器认证失败"),
            Self::UnfinishedTask(task_id) => write!(f, "扫描器仍有未完成任务 {task_id}"),
            Self::NoTask => write!(f, "没有可领取的任务"),
        }
    }
}

impl std::error::Error for ApplyTaskError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(e) => Some(e.as_ref()),
            Self::ScannerUnauthorized | Self::UnfinishedTask(_) | Self::NoTask => None,
        }
    }
}

fn apply_task_database_error<E>(value: E) -> ApplyTaskError
where
    E: std::error::Error + Send + Sync + 'static,
{
    ApplyTaskError::Database(Box::new(value))
}

pub async fn refresh_task_aggregate(
    transaction: &tokio_postgres::Transaction<'_>,
    task_db_id: i32,
) -> Result<(), tokio_postgres::Error> {
    transaction.execute(
        "WITH aggregate AS (SELECT \
            COUNT(*)::INT AS total, \
            COUNT(*) FILTER (WHERE execution_status = 'pending')::INT AS pending, \
            COUNT(*) FILTER (WHERE execution_status = 'running')::INT AS running, \
            COUNT(*) FILTER (WHERE execution_status = 'succeeded')::INT AS succeeded, \
            COUNT(*) FILTER (WHERE execution_status = 'failed')::INT AS failed, \
            COUNT(*) FILTER (WHERE execution_status = 'cancelled')::INT AS cancelled, \
            MIN(task_start_time) AS started_at, MAX(task_end_time) AS ended_at, \
            SUM(attempt_count)::INT AS attempts, BOOL_OR(cancel_requested) AS cancelling, \
            CASE WHEN COUNT(*) = 1 THEN MAX(assigned_scanner_id) ELSE NULL END AS scanner_id, \
            STRING_AGG(CASE WHEN failure_reason IS NOT NULL THEN \
                COALESCE(assigned_scanner_id, requested_scanner_id, 'unassigned') || ': ' || failure_reason END, E'\\n') AS failures \
          FROM scan_task_execution WHERE task_id = $1 AND execution_status <> 'superseded') \
         UPDATE scan_task t SET \
           task_status = CASE WHEN a.running > 0 THEN 'running' WHEN a.pending > 0 THEN 'pending' \
             WHEN a.succeeded = a.total THEN 'succeeded' WHEN a.failed = a.total THEN 'failed' \
             WHEN a.cancelled = a.total THEN 'cancelled' ELSE 'partial' END, \
           task_start_time = a.started_at, \
           task_end_time = CASE WHEN a.pending = 0 AND a.running = 0 THEN a.ended_at ELSE NULL END, \
           attempt_count = a.attempts, assigned_scanner_id = a.scanner_id, \
           lease_expires_at = NULL, failure_reason = a.failures, cancel_requested = a.cancelling \
         FROM aggregate a WHERE t.id = $1;",
        &[&task_db_id],
    ).await?;
    Ok(())
}

fn assigned_task_from_row(
    row: &tokio_postgres::Row,
    lease_expires_at_ms: i64,
) -> Result<ApplyTask, ApplyTaskError> {
    let task_id = Uuid::parse_str(row.get::<_, String>("task_id").as_str())
        .map_err(apply_task_database_error)?;
    Ok(ApplyTask {
        user_id: row.get("user_id"),
        task_id,
        task_target: row.get("task_target"),
        task_port: row.get("task_port"),
        address_family: row.get("address_family"),
        scan_plan: row.get("scan_plan"),
        dns_resolvers: row.get("dns_resolvers"),
        lease_expires_at_ms,
        lease_ttl_ms: TASK_LEASE_MS,
    })
}

/// Return an execution that can safely accept the caller's next upload.
///
/// A scanner with a durable upload may continue only that upload (plus its
/// deterministic DNS sidecar). A scanner without a durable upload is starting
/// a fresh attempt, so any existing receipt makes the old execution immutable.
/// The caller must already hold a row lock for `execution_id`.
async fn execution_for_upload_attempt(
    transaction: &tokio_postgres::Transaction<'_>,
    execution_id: i32,
    expected_upload_id: Option<Uuid>,
    now: i64,
    scanner_id: &str,
    public_task_id: &str,
) -> Result<i32, ApplyTaskError> {
    let conflict = if let Some(upload_id) = expected_upload_id {
        let allowed_upload_ids = vec![
            upload_id.to_string(),
            dns_sidecar_upload_id(upload_id).to_string(),
        ];
        transaction
            .query_opt(
                "SELECT upload_id FROM scan_result_batch \
                 WHERE execution_id = $1 AND NOT (upload_id = ANY($2::TEXT[])) \
                 ORDER BY upload_id LIMIT 1;",
                &[&execution_id, &allowed_upload_ids],
            )
            .await
            .map_err(apply_task_database_error)?
    } else {
        transaction
            .query_opt(
                "SELECT upload_id FROM scan_result_batch \
                 WHERE execution_id = $1 ORDER BY upload_id LIMIT 1;",
                &[&execution_id],
            )
            .await
            .map_err(apply_task_database_error)?
    };
    let Some(conflict) = conflict else {
        return Ok(execution_id);
    };

    let conflicting_upload_id: String = conflict.get("upload_id");
    let execution = transaction
        .query_one(
            "SELECT task_id, requested_scanner_id, recovery_failure_count FROM scan_task_execution WHERE id = $1;",
            &[&execution_id],
        )
        .await
        .map_err(apply_task_database_error)?;
    let task_db_id: i32 = execution.get("task_id");
    let requested_scanner_id: Option<String> = execution.get("requested_scanner_id");
    let recovery_failure_count: i32 = execution.get("recovery_failure_count");
    let reason = if expected_upload_id.is_some() {
        "superseded after durable upload identity changed"
    } else {
        "superseded before a fresh upload attempt"
    };
    transaction
        .execute(
            "UPDATE scan_task_execution SET execution_status = 'superseded', \
             requested_scanner_id = NULL, lease_expires_at = NULL, task_end_time = $2, \
             cancel_requested = false, maintenance_hold = FALSE, maintenance_hold_until = NULL, \
             failure_reason = $3 WHERE id = $1;",
            &[&execution_id, &now, &reason],
        )
        .await
        .map_err(apply_task_database_error)?;
    let replacement_public_id = Uuid::now_v7().to_string();
    let replacement = transaction
        .query_one(
            "INSERT INTO scan_task_execution (execution_id, task_id, requested_scanner_id, recovery_failure_count) \
             VALUES ($1, $2, $3, $4) RETURNING id;",
            &[&replacement_public_id, &task_db_id, &requested_scanner_id, &recovery_failure_count],
        )
        .await
        .map_err(apply_task_database_error)?;
    let replacement_id: i32 = replacement.get("id");
    info!(
        event = "ROTATE-UPLOAD-EXECUTION",
        scanner_id,
        task_id = public_task_id,
        upload_id = ?expected_upload_id,
        conflicting_upload_id,
        retired_execution_id = execution_id,
        replacement_execution_id = replacement_id,
        replacement_public_execution_id = replacement_public_id,
        reason,
        "retired an execution that cannot accept the scanner's next upload"
    );
    Ok(replacement_id)
}

/// Return and renew a running task already owned by this scanner.
///
/// When `task_id` is supplied, only that exact task is considered. This is used
/// to reconcile a durable local upload before any new work is requested.
pub async fn recover_scanner_task(
    pool: &deadpool_postgres::Pool,
    scanner_id: Uuid,
    task_id: Option<Uuid>,
    upload_id: Option<Uuid>,
    token: &str,
    token_pepper: &str,
) -> Result<ApplyTask, ApplyTaskError> {
    recover_scanner_task_with_failure(
        pool,
        scanner_id,
        task_id,
        upload_id,
        None,
        token,
        token_pepper,
    )
    .await
}

#[derive(Debug, Clone, Copy)]
pub struct RecoveryFailureReport {
    pub task_id: Uuid,
    pub count: u32,
}

pub async fn recover_scanner_task_with_failure(
    pool: &deadpool_postgres::Pool,
    scanner_id: Uuid,
    task_id: Option<Uuid>,
    upload_id: Option<Uuid>,
    failure: Option<RecoveryFailureReport>,
    token: &str,
    token_pepper: &str,
) -> Result<ApplyTask, ApplyTaskError> {
    let mut connection = pool.get().await.map_err(apply_task_database_error)?;
    let transaction = connection
        .transaction()
        .await
        .map_err(apply_task_database_error)?;
    let token_hash = hash_scanner_token(token, token_pepper).map_err(apply_task_database_error)?;
    validate_scanner_credentials_with_client(&transaction, scanner_id, &token_hash).await?;

    let scanner_id = scanner_id.to_string();
    // Serialize recovery and claiming for one scanner so two requests cannot
    // assign different work to the same scanner concurrently.
    transaction
        .query_one(
            "SELECT id FROM scanner_info WHERE scanner_id = $1 FOR UPDATE;",
            &[&scanner_id],
        )
        .await
        .map_err(apply_task_database_error)?;

    if let Some(failure) = failure {
        // The client reports a durable cumulative count; repeated recovery requests
        // (including a lost HTTP response) must never count the same failure twice.
        let now = get_unix_epoch_ms();
        let count = i32::try_from(failure.count.min(3)).unwrap_or(3);
        let changed = transaction.query(
            "UPDATE scan_task_execution SET recovery_failure_count=GREATEST(recovery_failure_count,$1), \
             execution_status=CASE WHEN GREATEST(recovery_failure_count,$1)>=3 THEN 'failed' ELSE execution_status END, \
             task_end_time=CASE WHEN GREATEST(recovery_failure_count,$1)>=3 THEN $2 ELSE task_end_time END, \
             lease_expires_at=CASE WHEN GREATEST(recovery_failure_count,$1)>=3 THEN NULL ELSE lease_expires_at END, \
             failure_reason=CASE WHEN GREATEST(recovery_failure_count,$1)>=3 THEN 'scanner recovery limit exceeded' ELSE failure_reason END \
             WHERE task_id=(SELECT id FROM scan_task WHERE task_id=$3) AND assigned_scanner_id=$4 \
             AND execution_status='running' RETURNING task_id;",
            &[&count,&now,&failure.task_id.to_string(),&scanner_id]).await.map_err(apply_task_database_error)?;
        for row in changed {
            refresh_task_aggregate(&transaction, row.get("task_id"))
                .await
                .map_err(apply_task_database_error)?;
        }
        info!(event="RECOVERY-FAILURE-REPORTED",scanner_id,task_id=%failure.task_id,count,
            "recorded cumulative scanner recovery failures");
    }

    let requested_task_id = task_id.map(|value| value.to_string());
    let now = get_unix_epoch_ms();
    let cancelled = transaction
        .query(
            "UPDATE scan_task_execution e SET execution_status = 'cancelled', task_end_time = $1, \
             lease_expires_at = NULL, cancel_requested = false FROM scan_task t \
             WHERE e.task_id = t.id AND e.execution_status = 'running' \
               AND e.assigned_scanner_id = $2 AND e.cancel_requested = true \
               AND ($3::TEXT IS NULL OR t.task_id = $3) RETURNING e.task_id;",
            &[&now, &scanner_id, &requested_task_id],
        )
        .await
        .map_err(apply_task_database_error)?;
    for task_id in cancelled
        .iter()
        .map(|row| row.get::<_, i32>("task_id"))
        .collect::<std::collections::HashSet<_>>()
    {
        refresh_task_aggregate(&transaction, task_id)
            .await
            .map_err(apply_task_database_error)?;
    }

    let row = transaction
        .query_opt(
            &"SELECT t.id AS task_pk, e.id AS execution_pk, e.execution_status, t.user_id, t.task_id, \
             CASE WHEN t.task_kind = 'dns' THEN t.dns_targets ELSE t.task_target::text[] END AS task_target, \
             t.task_port, t.address_family, t.scan_plan, t.dns_resolvers \
             FROM scan_task_execution e JOIN scan_task t ON t.id = e.task_id \
             JOIN scanner_info s ON s.scanner_id = $1 \
             WHERE COALESCE(s.scan_capabilities->'service_protocols','[]'::jsonb) @> COALESCE(t.scan_plan->'required_services','[]'::jsonb) \
             AND e.cancel_requested = false AND api_scan_task_enabled(t) AND dns_scan_task_enabled(t) AND ( \
                 (e.execution_status = 'running' AND e.assigned_scanner_id = $1 \
                  AND ($2::TEXT IS NULL OR t.task_id = $2)) \
                 OR ($2::TEXT IS NOT NULL AND t.task_id = $2 AND e.execution_status = 'pending' \
                     AND e.assigned_scanner_id IS NULL AND s.accepting_tasks AND @routing_guard@ \
                     AND (e.requested_scanner_id IS NULL OR e.requested_scanner_id = $1) \
                     AND ((t.address_family = 'ipv4' AND s.supports_ipv4 AND s.ipv4_ready) \
                       OR (t.address_family = 'ipv6' AND s.supports_ipv6 AND s.ipv6_ready)) \
                     AND (t.scan_profile = 'legacy' OR s.scan_capabilities->'profiles' ? t.scan_profile) \
           AND COALESCE(s.scan_capabilities->'service_protocols','[]'::jsonb) @> COALESCE(t.scan_plan->'required_services','[]'::jsonb) \
                     AND (jsonb_array_length(t.dns_resolvers) = 0 \
                       OR COALESCE((s.scan_capabilities->>'explicit_dns_resolvers')::BOOLEAN, FALSE)) \
           AND (NOT EXISTS(SELECT 1 FROM jsonb_array_elements(t.dns_resolvers) d WHERE d->>'ip' LIKE '%:%') OR (s.supports_ipv6 AND s.ipv6_ready)))) \
             ORDER BY CASE WHEN e.execution_status = 'running' THEN 0 ELSE 1 END, \
                 e.task_start_time NULLS FIRST, e.id \
             FOR UPDATE OF e SKIP LOCKED LIMIT 1;".replace("@routing_guard@", &super::routing::claim_guard("$1")),
            &[&scanner_id, &requested_task_id],
        )
        .await
        .map_err(apply_task_database_error)?;

    let Some(row) = row else {
        transaction
            .commit()
            .await
            .map_err(apply_task_database_error)?;
        return Err(ApplyTaskError::NoTask);
    };

    let execution_pk = execution_for_upload_attempt(
        &transaction,
        row.get("execution_pk"),
        upload_id,
        now,
        &scanner_id,
        row.get("task_id"),
    )
    .await?;
    let lease_expires_at = now + TASK_LEASE_MS;
    transaction
        .execute(
            &"UPDATE scan_task_execution SET execution_status = 'running', assigned_scanner_id = $1::TEXT, \
             task_start_time = COALESCE(task_start_time, $2::BIGINT), task_end_time = NULL, \
             lease_expires_at = CASE WHEN maintenance_hold THEN NULL ELSE $3::BIGINT END, \
             attempt_count = attempt_count + CASE WHEN execution_status = 'pending' THEN 1 ELSE 0 END, \
             performance = CASE WHEN execution_status='pending' THEN NULL ELSE performance END, \
             routing_decision = CASE WHEN execution_status='pending' THEN @assignment_decision@ ELSE routing_decision END, \
             failure_reason = NULL WHERE id = $4;".replace("@assignment_decision@", &super::routing::assignment_decision("$1")),
            &[
                &scanner_id,
                &now,
                &lease_expires_at,
                &execution_pk,
            ],
        )
        .await
        .map_err(apply_task_database_error)?;
    refresh_task_aggregate(&transaction, row.get("task_pk"))
        .await
        .map_err(apply_task_database_error)?;
    let task = assigned_task_from_row(&row, lease_expires_at)?;
    transaction
        .commit()
        .await
        .map_err(apply_task_database_error)?;
    info!(
        event = "RECOVER-TASK",
        scanner_id,
        task_id = %task.task_id,
        "scanner recovered an unfinished task"
    );
    Ok(task)
}

/// 通过该函数实现扫描器申请任务。
/// 调用方必须先清空该扫描器的未完成任务；本函数也在事务内再次强制检查。
pub async fn apply_task(
    pool: &deadpool_postgres::Pool,
    scanner_id: Uuid,
    token: &str,
    token_pepper: &str,
) -> Result<ApplyTask, ApplyTaskError> {
    let mut p = pool.get().await.map_err(apply_task_database_error)?;
    let transaction = p.transaction().await.map_err(apply_task_database_error)?;
    let token_hash = hash_scanner_token(token, token_pepper).map_err(apply_task_database_error)?;
    validate_scanner_credentials_with_client(&transaction, scanner_id, &token_hash).await?;
    let scanner_id = scanner_id.to_string();

    let cancelled = transaction
        .query(
            "/* nm:reap_cancelled_executions */ \
             WITH candidates AS ( \
                 SELECT id FROM scan_task_execution \
                 WHERE execution_status = 'running' AND cancel_requested = true \
                   AND (lease_expires_at IS NULL OR lease_expires_at < $1) \
                 ORDER BY lease_expires_at NULLS FIRST, id \
                 FOR UPDATE SKIP LOCKED LIMIT 32 \
             ) \
             UPDATE scan_task_execution e \
             SET execution_status = 'cancelled', task_end_time = $1, \
                 lease_expires_at = NULL, cancel_requested = false \
             FROM candidates c WHERE e.id = c.id RETURNING e.task_id;",
            &[&get_unix_epoch_ms()],
        )
        .await
        .map_err(apply_task_database_error)?;
    let cancelled_tasks: std::collections::HashSet<i32> =
        cancelled.iter().map(|row| row.get("task_id")).collect();
    for task_id in cancelled_tasks {
        refresh_task_aggregate(&transaction, task_id)
            .await
            .map_err(apply_task_database_error)?;
    }

    transaction
        .query_one(
            "SELECT id FROM scanner_info WHERE scanner_id = $1 FOR UPDATE;",
            &[&scanner_id],
        )
        .await
        .map_err(apply_task_database_error)?;

    if let Some(row) = transaction
        .query_opt(
            "SELECT t.task_id FROM scan_task_execution e JOIN scan_task t ON t.id = e.task_id \
             WHERE e.execution_status = 'running' AND e.assigned_scanner_id = $1 \
             ORDER BY e.task_start_time NULLS FIRST, e.id FOR UPDATE OF e LIMIT 1;",
            &[&scanner_id],
        )
        .await
        .map_err(apply_task_database_error)?
    {
        let task_id = Uuid::parse_str(row.get::<_, String>("task_id").as_str())
            .map_err(apply_task_database_error)?;
        return Err(ApplyTaskError::UnfinishedTask(task_id));
    }

    let row = transaction
        .query_opt(
            "/* nm:claim_selected_pending */ \
             SELECT t.id AS task_pk, e.id AS execution_pk, t.user_id, t.task_id, \
             CASE WHEN t.task_kind = 'dns' THEN t.dns_targets ELSE t.task_target::text[] END AS task_target, \
             t.task_port, t.address_family, t.scan_plan, t.dns_resolvers \
         FROM scan_task_execution e \
         JOIN scan_task t ON t.id = e.task_id \
         JOIN scanner_info s ON s.scanner_id = $1 \
         WHERE s.accepting_tasks AND e.execution_status = 'pending' AND e.requested_scanner_id = $1 \
           AND t.task_status IN ('pending', 'running') \
           AND api_scan_task_enabled(t) AND dns_scan_task_enabled(t) \
           AND ((t.address_family = 'ipv4' AND s.supports_ipv4 AND s.ipv4_ready) \
             OR (t.address_family = 'ipv6' AND s.supports_ipv6 AND s.ipv6_ready)) \
           AND (t.scan_profile = 'legacy' OR s.scan_capabilities->'profiles' ? t.scan_profile) \
           AND COALESCE(s.scan_capabilities->'service_protocols','[]'::jsonb) @> COALESCE(t.scan_plan->'required_services','[]'::jsonb) \
           AND (jsonb_array_length(t.dns_resolvers) = 0 \
             OR COALESCE((s.scan_capabilities->>'explicit_dns_resolvers')::BOOLEAN, FALSE)) \
           AND (NOT EXISTS(SELECT 1 FROM jsonb_array_elements(t.dns_resolvers) d WHERE d->>'ip' LIKE '%:%') OR (s.supports_ipv6 AND s.ipv6_ready)) \
         ORDER BY t.task_level DESC, t.task_create_time, t.id, e.id \
         FOR UPDATE OF e SKIP LOCKED LIMIT 1;",
            &[&scanner_id],
        )
        .await
        .map_err(apply_task_database_error)?;
    let row = if row.is_some() {
        row
    } else {
        transaction
            .query_opt(
                &"/* nm:claim_general */ \
                 SELECT t.id AS task_pk, e.execution_pk, t.user_id, t.task_id, \
                     CASE WHEN t.task_kind = 'dns' THEN t.dns_targets ELSE t.task_target::text[] END AS task_target, \
                     t.task_port, t.address_family, t.scan_plan, t.dns_resolvers \
                 FROM scan_task t \
                 JOIN scanner_info s ON s.scanner_id = $2 \
                 JOIN LATERAL ( \
                     SELECT candidate.id AS execution_pk \
                     FROM scan_task_execution candidate \
                     WHERE candidate.task_id = t.id AND ( \
                         (candidate.execution_status = 'pending' AND candidate.requested_scanner_id IS NULL) \
                         OR (candidate.execution_status = 'running' \
                             AND candidate.maintenance_hold = FALSE \
                             AND candidate.cancel_requested = FALSE \
                             AND (candidate.lease_expires_at IS NULL OR candidate.lease_expires_at < $1) \
                             AND (candidate.requested_scanner_id IS NULL OR candidate.requested_scanner_id = $2)) \
                     ) \
                     ORDER BY candidate.id FOR UPDATE SKIP LOCKED LIMIT 1 \
                 ) e ON TRUE \
                 WHERE s.accepting_tasks AND @routing_guard@ AND t.task_status IN ('pending', 'running') \
                   AND api_scan_task_enabled(t) AND dns_scan_task_enabled(t) \
                   AND ((t.address_family = 'ipv4' AND s.supports_ipv4 AND s.ipv4_ready) \
                     OR (t.address_family = 'ipv6' AND s.supports_ipv6 AND s.ipv6_ready)) \
                   AND (t.scan_profile = 'legacy' OR s.scan_capabilities->'profiles' ? t.scan_profile) \
           AND COALESCE(s.scan_capabilities->'service_protocols','[]'::jsonb) @> COALESCE(t.scan_plan->'required_services','[]'::jsonb) \
                   AND (jsonb_array_length(t.dns_resolvers) = 0 \
                     OR COALESCE((s.scan_capabilities->>'explicit_dns_resolvers')::BOOLEAN, FALSE)) \
           AND (NOT EXISTS(SELECT 1 FROM jsonb_array_elements(t.dns_resolvers) d WHERE d->>'ip' LIKE '%:%') OR (s.supports_ipv6 AND s.ipv6_ready)) \
                 ORDER BY t.task_level DESC, t.task_create_time, t.id, e.execution_pk \
                 LIMIT 1;".replace("@routing_guard@", &super::routing::claim_guard("$2")),
                &[&get_unix_epoch_ms(), &scanner_id],
            )
            .await
            .map_err(apply_task_database_error)?
    };

    let Some(row) = row else {
        info!(
            event = "NOTFOUND-TASK",
            path = "fn apply_task",
            message = "没有可领取的扫描任务"
        );
        transaction
            .commit()
            .await
            .map_err(apply_task_database_error)?;
        return Err(ApplyTaskError::NoTask);
    };

    let task_pk: i32 = row.get("task_pk");
    let execution_pk = execution_for_upload_attempt(
        &transaction,
        row.get("execution_pk"),
        None,
        get_unix_epoch_ms(),
        &scanner_id,
        row.get("task_id"),
    )
    .await?;
    let lease_expires_at = get_unix_epoch_ms() + TASK_LEASE_MS;
    transaction
        .execute(
            &"UPDATE scan_task_execution SET task_start_time = COALESCE(task_start_time, $1::BIGINT), task_end_time = NULL, \
             execution_status = 'running', assigned_scanner_id = $2::TEXT, lease_expires_at = $3::BIGINT, \
             maintenance_hold = FALSE, maintenance_hold_until = NULL, \
             performance = NULL, routing_decision = @assignment_decision@, \
             attempt_count = attempt_count + 1, failure_reason = NULL WHERE id = $4;".replace("@assignment_decision@", &super::routing::assignment_decision("$2")),
            &[
                &get_unix_epoch_ms(),
                &scanner_id,
                &lease_expires_at,
                &execution_pk,
            ],
        )
        .await
        .map_err(apply_task_database_error)?;
    refresh_task_aggregate(&transaction, task_pk)
        .await
        .map_err(apply_task_database_error)?;

    let apply_task = assigned_task_from_row(&row, lease_expires_at)?;

    transaction
        .commit()
        .await
        .map_err(apply_task_database_error)?;
    info!(
        event = "SEARCH-TASK",
        path = "fn apply_task",
        message = apply_task.task_id.to_string()
    );
    Ok(apply_task)
}

#[derive(Deserialize)]
pub struct ApplyTaskQuery {
    pub scannerid: Uuid,
    pub dryrun: Option<bool>,
}

#[derive(Deserialize)]
pub struct CurrentTaskQuery {
    pub scannerid: Uuid,
    pub taskid: Option<Uuid>,
    pub uploadid: Option<Uuid>,
    pub failure_taskid: Option<Uuid>,
    pub failure_count: Option<u32>,
}
