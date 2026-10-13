use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use actix_web::{HttpResponse, http::header, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::Serialize;
use serde_json::json;
use tokio::sync::RwLock;
use tokio_postgres::Row;
use tracing::{error, info};
use uuid::Uuid;

use crate::logs::write::error_diagnostics;

pub const DEFAULT_RETRY_AFTER_SECONDS: i32 = 600;
pub const NOTIFICATION_GRACE_SECONDS: i64 = 60;
pub const RESULT_UPLOAD_GRACE_HOURS: i32 = 24;
pub const RESULT_UPLOAD_GRACE_TTL_MS: i64 = RESULT_UPLOAD_GRACE_HOURS as i64 * 60 * 60 * 1000;
const DRAIN_EMPTY_CHECKS_REQUIRED: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenancePhase {
    Off,
    Draining,
    Active,
}

impl MaintenancePhase {
    fn from_database(value: &str) -> Self {
        match value {
            "draining" => Self::Draining,
            "active" => Self::Active,
            _ => Self::Off,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct MaintenanceSnapshot {
    pub enabled: bool,
    pub phase: MaintenancePhase,
    pub maintenance_id: Option<Uuid>,
    pub message: String,
    pub expected_end_at: Option<DateTime<Utc>>,
    pub retry_after_seconds: i32,
    pub started_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub revision: i64,
    pub task_action: &'static str,
    pub notification_grace_seconds: i64,
    pub result_upload_grace_hours: i32,
}

impl MaintenanceSnapshot {
    pub(crate) fn from_row(row: &Row) -> Self {
        Self {
            enabled: row.get("enabled"),
            phase: MaintenancePhase::from_database(row.get("phase")),
            maintenance_id: row.get("maintenance_id"),
            message: row.get("message"),
            expected_end_at: row.get("expected_end_at"),
            retry_after_seconds: row.get("retry_after_seconds"),
            started_at: row.get("started_at"),
            updated_at: row.get("updated_at"),
            revision: row.get("revision"),
            task_action: "finish_and_cache",
            notification_grace_seconds: NOTIFICATION_GRACE_SECONDS,
            result_upload_grace_hours: RESULT_UPLOAD_GRACE_HOURS,
        }
    }

    pub fn blocks_new_work(&self) -> bool {
        self.enabled
    }

    pub fn blocks_all_scanner_requests(&self) -> bool {
        self.enabled && self.phase == MaintenancePhase::Active
    }
}

pub struct SystemMaintenanceState {
    snapshot: RwLock<MaintenanceSnapshot>,
    consecutive_empty_checks: AtomicU8,
}

impl SystemMaintenanceState {
    pub async fn from_database(
        pool: &Pool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let client = pool.get().await?;
        let row = client
            .query_one(
                "SELECT enabled, phase, maintenance_id, message, expected_end_at, \
                 retry_after_seconds, started_at, updated_at, revision \
                 FROM system_maintenance_state WHERE singleton = TRUE;",
                &[],
            )
            .await?;
        Ok(Self {
            snapshot: RwLock::new(MaintenanceSnapshot::from_row(&row)),
            consecutive_empty_checks: AtomicU8::new(0),
        })
    }

    pub async fn snapshot(&self) -> MaintenanceSnapshot {
        self.snapshot.read().await.clone()
    }

    pub async fn replace(&self, snapshot: MaintenanceSnapshot) {
        let mut current = self.snapshot.write().await;
        if snapshot.revision >= current.revision {
            self.consecutive_empty_checks.store(0, Ordering::Relaxed);
            *current = snapshot;
        }
    }

    async fn reconcile(&self, pool: &Pool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let released = release_expired_maintenance_holds(pool).await?;
        if released > 0 {
            info!(
                released,
                "expired maintenance-held tasks returned to the queue"
            );
        }
        let snapshot = self.snapshot().await;
        if !snapshot.enabled || snapshot.phase != MaintenancePhase::Draining {
            self.consecutive_empty_checks.store(0, Ordering::Relaxed);
            return Ok(());
        }

        let newly_held = freeze_running_tasks(pool).await?;
        if newly_held > 0 {
            info!(
                newly_held,
                "running scanner tasks frozen during maintenance notification window"
            );
        }
        let running_tasks = active_task_count(pool).await?;
        let held_tasks = held_task_count(pool).await?;
        let notification_window_elapsed = snapshot.started_at.is_some_and(|started_at| {
            Utc::now().signed_duration_since(started_at).num_seconds() >= NOTIFICATION_GRACE_SECONDS
        });
        if running_tasks > held_tasks || (held_tasks > 0 && !notification_window_elapsed) {
            self.consecutive_empty_checks.store(0, Ordering::Relaxed);
            return Ok(());
        }
        let checks = self
            .consecutive_empty_checks
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if checks < DRAIN_EMPTY_CHECKS_REQUIRED {
            return Ok(());
        }

        let client = pool.get().await?;
        let row = client
            .query_opt(
                "UPDATE system_maintenance_state SET phase = 'active', updated_at = NOW(), \
                 revision = revision + 1 WHERE singleton = TRUE AND enabled = TRUE \
                 AND phase = 'draining' RETURNING enabled, phase, maintenance_id, message, \
                 expected_end_at, retry_after_seconds, started_at, updated_at, revision;",
                &[],
            )
            .await?;
        if let Some(row) = row {
            let next = MaintenanceSnapshot::from_row(&row);
            info!(
                maintenance_id = ?next.maintenance_id,
                revision = next.revision,
                "system maintenance drain completed"
            );
            self.replace(next).await;
        }
        Ok(())
    }
}

async fn freeze_running_tasks(
    pool: &Pool,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let client = pool.get().await?;
    Ok(client
        .execute(
            "UPDATE scan_task_execution SET maintenance_hold = TRUE, \
             maintenance_hold_until = NULL, lease_expires_at = NULL \
             WHERE execution_status = 'running' AND maintenance_hold = FALSE;",
            &[],
        )
        .await?)
}

async fn release_expired_maintenance_holds(
    pool: &Pool,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    let rows = transaction
        .query(
            "UPDATE scan_task_execution SET execution_status = CASE WHEN cancel_requested \
             THEN 'cancelled' ELSE 'pending' END, assigned_scanner_id = CASE WHEN cancel_requested \
             THEN assigned_scanner_id ELSE NULL END, lease_expires_at = NULL, maintenance_hold = FALSE, \
             maintenance_hold_until = NULL, task_start_time = \
             CASE WHEN cancel_requested THEN task_start_time ELSE NULL END, task_end_time = CASE \
             WHEN cancel_requested THEN (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT \
             ELSE NULL END, cancel_requested = false, failure_reason = CASE WHEN cancel_requested \
             THEN NULL ELSE 'maintenance result upload grace period expired' END WHERE \
             execution_status = 'running' AND maintenance_hold = TRUE \
             AND maintenance_hold_until IS NOT NULL AND maintenance_hold_until < NOW() RETURNING task_id;",
            &[],
        )
        .await?;
    let task_ids: std::collections::HashSet<i32> =
        rows.iter().map(|row| row.get("task_id")).collect();
    for task_id in &task_ids {
        crate::scan_control::dispatch::refresh_task_aggregate(&transaction, *task_id).await?;
    }
    transaction.commit().await?;
    Ok(task_ids.len())
}

pub async fn active_task_count(
    pool: &Pool,
) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "SELECT COUNT(*)::BIGINT AS count FROM scan_task_execution \
             WHERE execution_status = 'running';",
            &[],
        )
        .await?;
    Ok(row.get("count"))
}

pub async fn held_task_count(pool: &Pool) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "SELECT COUNT(*)::BIGINT AS count FROM scan_task_execution \
             WHERE execution_status = 'running' AND maintenance_hold = TRUE;",
            &[],
        )
        .await?;
    Ok(row.get("count"))
}

pub async fn run_reconciler(state: web::Data<SystemMaintenanceState>, pool: Pool) {
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    loop {
        ticker.tick().await;
        if let Err(error_value) = state.reconcile(&pool).await {
            let snapshot = state.snapshot().await;
            let diagnostics = error_diagnostics(error_value.as_ref());
            error!(
                event = "SystemMaintenanceReconcileError",
                operation = "reconcile_system_maintenance",
                error_kind = "database",
                error_code = "system_maintenance_reconcile_failed",
                error_message = %diagnostics.error_message,
                error_chain = %diagnostics.error_chain,
                root_cause = %diagnostics.root_cause,
                error_truncated = diagnostics.error_truncated,
                retryable = true,
                outcome = "maintenance_state_unchanged",
                maintenance_id = ?snapshot.maintenance_id,
                phase = ?snapshot.phase,
                revision = snapshot.revision,
                retry_after_ms = 2_000_u64,
            );
        }
    }
}

pub fn maintenance_response(snapshot: &MaintenanceSnapshot) -> HttpResponse {
    HttpResponse::ServiceUnavailable()
        .insert_header((
            header::RETRY_AFTER,
            snapshot.retry_after_seconds.to_string(),
        ))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header(("NM-Maintenance-Version", "1"))
        .json(json!({
            "success": false,
            "code": "system_maintenance",
            "maintenance": {
                "id": snapshot.maintenance_id,
                "phase": snapshot.phase,
                "message": snapshot.message,
                "started_at": snapshot.started_at,
                "expected_end_at": snapshot.expected_end_at,
                "server_time": Utc::now(),
                "retry_after_seconds": snapshot.retry_after_seconds,
                "task_action": snapshot.task_action,
                "result_upload_grace_hours": snapshot.result_upload_grace_hours,
                "manual_exit_required": true,
                "revision": snapshot.revision,
            }
        }))
}

#[cfg(test)]
mod tests {
    use super::{
        MaintenancePhase, MaintenanceSnapshot, NOTIFICATION_GRACE_SECONDS,
        RESULT_UPLOAD_GRACE_HOURS, maintenance_response,
    };
    use actix_web::body::to_bytes;
    use chrono::Utc;

    #[actix_web::test]
    async fn maintenance_response_has_retry_contract() {
        let snapshot = MaintenanceSnapshot {
            enabled: true,
            phase: MaintenancePhase::Active,
            maintenance_id: None,
            message: "database upgrade".to_owned(),
            expected_end_at: None,
            retry_after_seconds: 600,
            started_at: Some(Utc::now()),
            updated_at: Utc::now(),
            revision: 1,
            task_action: "finish_and_cache",
            notification_grace_seconds: NOTIFICATION_GRACE_SECONDS,
            result_upload_grace_hours: RESULT_UPLOAD_GRACE_HOURS,
        };
        let response = maintenance_response(&snapshot);
        assert_eq!(
            response.status(),
            actix_web::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(response.headers().get("retry-after").unwrap(), "600");
        assert_eq!(
            response.headers().get("nm-maintenance-version").unwrap(),
            "1"
        );
        let body = to_bytes(response.into_body()).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["code"], "system_maintenance");
        assert_eq!(value["maintenance"]["phase"], "active");
        assert_eq!(value["maintenance"]["task_action"], "finish_and_cache");
        assert_eq!(value["maintenance"]["result_upload_grace_hours"], 24);
    }
}
