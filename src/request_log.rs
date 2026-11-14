//! 请求日志（`request_log`）采集：操作者槽位、错误分类、后台批量写入与过期清理。
//!
//! 与 `audit_event`（安全审计，只记录敏感操作）不同，`request_log` 是访问日志，
//! 覆盖每一个业务请求，用于请求级别的分析与错误自动识别。

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use actix_web::{HttpMessage, HttpRequest};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use tokio::sync::mpsc;
use tokio_postgres::types::ToSql;
use tracing::{error, info};
use uuid::Uuid;

use crate::config::RequestsConfig;
use crate::logs::write::error_diagnostics;
use crate::runtime_config::RuntimeConfig;

/// 操作者槽位：由最外层 `wrap_fn` 预置，内层 `AuthMiddleware` 鉴权成功后写入，
/// 最外层响应后再读取，用于把 `actor_id` / `actor_name` 写进请求日志。
///
/// 匿名请求、被 401/403 拒绝的请求、扫描器请求（直通、不注入 `UserBaseI`）保持为 `None`。
pub struct RequestActor(pub Arc<Mutex<Option<(i32, String)>>>); // (user_id, username)

/// 业务处理器写入的稳定原因代码，供请求结束时的访问记录读取。
#[derive(Clone)]
pub struct RequestReason(pub Arc<Mutex<Option<String>>>);

pub fn set_reason(req: &HttpRequest, reason: impl Into<String>) {
    if let Some(slot) = req.extensions().get::<RequestReason>() {
        *slot
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(reason.into());
    }
}

pub fn set_reason_if_absent(req: &HttpRequest, reason: impl Into<String>) {
    if let Some(slot) = req.extensions().get::<RequestReason>() {
        let mut value = slot
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if value.is_none() {
            *value = Some(reason.into());
        }
    }
}

/// 一条待写入 `request_log` 的请求记录。
pub struct RequestLogEntry {
    pub request_id: Uuid,
    pub occurred_at: DateTime<Utc>,
    pub http_method: String,
    pub request_path: String,
    pub route_pattern: Option<String>,
    pub status_code: i16,
    pub duration_ms: Option<i32>,
    pub duration_us: Option<i64>,
    pub client_ip: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub actor_id: Option<i32>,
    pub actor_name: Option<String>,
    pub error_level: String,
    pub error_type: Option<String>,
    pub reason_code: Option<String>,
}

/// 按 HTTP 状态码派生 `error_level` 与 `error_type`。
pub fn classify_status(status: u16) -> (&'static str, Option<&'static str>) {
    match status {
        400 => ("client_error", Some("bad_request")),
        401 => ("client_error", Some("unauthorized")),
        403 => ("client_error", Some("forbidden")),
        404 => ("client_error", Some("not_found")),
        408 => ("client_error", Some("timeout")),
        409 => ("client_error", Some("conflict")),
        422 => ("client_error", Some("validation")),
        429 => ("client_error", Some("rate_limited")),
        _ if (400..500).contains(&status) => ("client_error", Some("client_error")),
        500..=599 => ("server_error", Some("server_error")),
        _ => ("ok", None),
    }
}

pub const CHANNEL_CAPACITY: usize = 8192;
static DROPPED_ENQUEUE_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn record_enqueue_drop() -> u64 {
    DROPPED_ENQUEUE_COUNT.fetch_add(1, Ordering::Relaxed) + 1
}
const BATCH_SIZE: usize = 500;
const FLUSH_INTERVAL_MS: u64 = 500;
const RETRY_DELAYS_MS: [u64; 2] = [50, 200];

/// 后台写入任务：攒批 + 定时 flush，单事务多行 `INSERT`；失败重试 2 次后整批丢弃。
///
/// 该任务**永不退出**：仅在 channel 关闭（所有 sender 释放，即进程退出）时返回。
pub async fn run_writer(pool: Pool, mut rx: mpsc::Receiver<RequestLogEntry>) {
    let mut batch: Vec<RequestLogEntry> = Vec::with_capacity(BATCH_SIZE);
    let mut dropped: u64 = 0;
    let mut ticker = tokio::time::interval(Duration::from_millis(FLUSH_INTERVAL_MS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if !batch.is_empty() {
                    flush_batch(&pool, &mut batch, &mut dropped).await;
                }
            }
            maybe = rx.recv() => {
                match maybe {
                    Some(entry) => {
                        batch.push(entry);
                        if batch.len() >= BATCH_SIZE {
                            flush_batch(&pool, &mut batch, &mut dropped).await;
                        }
                    }
                    None => {
                        if !batch.is_empty() {
                            flush_batch(&pool, &mut batch, &mut dropped).await;
                        }
                        return;
                    }
                }
            }
        }
    }
}

async fn flush_batch(pool: &Pool, batch: &mut Vec<RequestLogEntry>, dropped: &mut u64) {
    let entries = std::mem::take(batch);
    let mut attempt = 0usize;
    loop {
        attempt += 1;
        match insert_batch(pool, &entries).await {
            Ok(()) => {
                for entry in &entries {
                    crate::syslog::hooks::forward_access(entry);
                }
                return;
            }
            Err(error_value) => {
                if attempt > RETRY_DELAYS_MS.len() {
                    *dropped += entries.len() as u64;
                    let diagnostics = error_diagnostics(error_value.as_ref());
                    error!(
                        event = "RequestLogWriteError",
                        operation = "insert_request_log_batch",
                        error_kind = "database",
                        error_code = "request_log_batch_write_failed",
                        error_message = %diagnostics.error_message,
                        error_chain = %diagnostics.error_chain,
                        root_cause = %diagnostics.root_cause,
                        error_truncated = diagnostics.error_truncated,
                        retryable = false,
                        outcome = "request_log_batch_dropped",
                        attempt,
                        dropped_this_batch = entries.len(),
                        total_dropped = dropped,
                        "请求日志批量写入失败，已丢弃该批次",
                    );
                    return;
                }
                tokio::time::sleep(Duration::from_millis(RETRY_DELAYS_MS[attempt - 1])).await;
            }
        }
    }
}

const COLUMN_COUNT: usize = 15;

async fn insert_batch(
    pool: &Pool,
    entries: &[RequestLogEntry],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if entries.is_empty() {
        return Ok(());
    }
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;

    let mut sql = String::from(
        "INSERT INTO request_log (request_id, occurred_at, http_method, request_path, \
         route_pattern, status_code, duration_ms, duration_us, client_ip, user_agent, actor_id, actor_name, \
         error_level, error_type, reason_code) VALUES ",
    );
    let mut params: Vec<Box<dyn ToSql + Send + Sync>> =
        Vec::with_capacity(entries.len() * COLUMN_COUNT);
    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            sql.push_str(", ");
        }
        let base = index * COLUMN_COUNT;
        sql.push_str(&format!(
            "(${},${},${},${},${},${},${},${},${},${},${},${},${},${},${})",
            base + 1,
            base + 2,
            base + 3,
            base + 4,
            base + 5,
            base + 6,
            base + 7,
            base + 8,
            base + 9,
            base + 10,
            base + 11,
            base + 12,
            base + 13,
            base + 14,
            base + 15,
        ));
        params.push(Box::new(entry.request_id));
        params.push(Box::new(entry.occurred_at));
        params.push(Box::new(entry.http_method.clone()));
        params.push(Box::new(entry.request_path.clone()));
        params.push(Box::new(entry.route_pattern.clone()));
        params.push(Box::new(entry.status_code));
        params.push(Box::new(entry.duration_ms));
        params.push(Box::new(entry.duration_us));
        params.push(Box::new(entry.client_ip));
        params.push(Box::new(entry.user_agent.clone()));
        params.push(Box::new(entry.actor_id));
        params.push(Box::new(entry.actor_name.clone()));
        params.push(Box::new(entry.error_level.clone()));
        params.push(Box::new(entry.error_type.clone()));
        params.push(Box::new(entry.reason_code.clone()));
    }

    let param_refs: Vec<&(dyn ToSql + Sync)> = params
        .iter()
        .map(|value| value.as_ref() as &(dyn ToSql + Sync))
        .collect();
    transaction.execute(&sql, &param_refs).await?;
    transaction.commit().await?;
    Ok(())
}

/// 分批删除超过 `retention_days` 的请求日志，避免长事务锁表。
pub async fn run_retention(pool: Pool, config: RuntimeConfig<RequestsConfig>) {
    // 小间隔检查配置，实际清理仍最多每天执行一次。这样保存保留期后无需重启。
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_run = None;
    let mut applied_revision = 0;
    let mut changes = config.subscribe();
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            changed = changes.changed() => if changed.is_err() { return; }
        }
        let settings = config.get().await;
        if settings.revision != applied_revision {
            applied_revision = settings.revision;
            last_run = None;
        }
        let settings = settings.value;
        if !settings.enabled
            || last_run.is_some_and(|at: std::time::Instant| {
                at.elapsed() < Duration::from_secs(24 * 60 * 60)
            })
        {
            continue;
        }
        last_run = Some(std::time::Instant::now());
        let retention_days = settings.retention_days;
        match purge_expired(&pool, retention_days).await {
            Ok(purged) => {
                if purged > 0 {
                    info!(
                        event = "RequestLogRetention",
                        purged_rows = purged,
                        retention_days,
                        "已清理过期请求日志"
                    );
                }
            }
            Err(error_value) => {
                let diagnostics = error_diagnostics(error_value.as_ref());
                error!(
                    event = "RequestLogRetentionError",
                    operation = "delete_expired_request_logs",
                    error_kind = "database",
                    error_code = "request_log_retention_failed",
                    error_message = %diagnostics.error_message,
                    error_chain = %diagnostics.error_chain,
                    root_cause = %diagnostics.root_cause,
                    error_truncated = diagnostics.error_truncated,
                    retryable = true,
                    outcome = "retention_deferred",
                    retention_days,
                    "清理过期请求日志失败"
                );
            }
        }
    }
}

const PURGE_BATCH_SIZE: i64 = 5000;

async fn purge_expired(
    pool: &Pool,
    retention_days: i32,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let client = pool.get().await?;
    let cutoff = Utc::now() - chrono::Duration::days(i64::from(retention_days));
    let mut purged = 0u64;
    loop {
        let affected = client
            .execute(
                "DELETE FROM request_log WHERE id IN (\
                 SELECT id FROM request_log WHERE occurred_at < $1 ORDER BY occurred_at ASC LIMIT $2)",
                &[&cutoff, &PURGE_BATCH_SIZE],
            )
            .await?;
        if affected == 0 {
            break;
        }
        purged += affected;
        if affected < PURGE_BATCH_SIZE as u64 {
            break;
        }
    }
    Ok(purged)
}

#[cfg(test)]
mod tests {
    use super::classify_status;

    #[test]
    fn classifies_client_and_server_errors() {
        assert_eq!(classify_status(200), ("ok", None));
        assert_eq!(classify_status(400), ("client_error", Some("bad_request")));
        assert_eq!(classify_status(401), ("client_error", Some("unauthorized")));
        assert_eq!(classify_status(403), ("client_error", Some("forbidden")));
        assert_eq!(classify_status(404), ("client_error", Some("not_found")));
        assert_eq!(classify_status(408), ("client_error", Some("timeout")));
        assert_eq!(classify_status(409), ("client_error", Some("conflict")));
        assert_eq!(classify_status(422), ("client_error", Some("validation")));
        assert_eq!(classify_status(429), ("client_error", Some("rate_limited")));
        assert_eq!(classify_status(418), ("client_error", Some("client_error")));
        assert_eq!(classify_status(500), ("server_error", Some("server_error")));
        assert_eq!(classify_status(503), ("server_error", Some("server_error")));
    }
}
