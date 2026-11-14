//! 历史日志回填：仅由用户手动下发任务，把数据库留存时间段内的审计事件、
//! IP 访问日志与扫描器诊断事件重发到已启用的目标。
//!
//! - 默认最近 7 天；可指定「N 天前至今」或自定义时间段（上限 31 天）。
//! - 不占用实时转发队列，也不计入实时分钟指标（任务自带进度计数）。
//! - 需要转发已启用且至少有一个启用目标；否则任务失败并给出原因。

use std::time::Duration;

use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use tokio::sync::watch;
use uuid::Uuid;

use crate::audit::{AuditContext, AuditEvent};
use crate::request_log::RequestLogEntry;
use crate::runtime_config::RuntimeConfig;
use crate::scanner_diagnostics::parser::ParsedEvent;
use crate::syslog::config::{Protocol, SyslogConfig, TargetConfig};
use crate::syslog::format::{self, Message, TCP_MAX_BYTES, UDP_MAX_BYTES};
use crate::syslog::forwarder::ForwardItem;
use crate::syslog::hooks;
use crate::syslog::transport::{self, Connection};

pub const DEFAULT_BACKFILL_DAYS: i64 = 7;
pub const MAX_BACKFILL_DAYS: i64 = 31;
const BATCH_SIZE: i64 = 500;
const MAX_ACTIVE_JOBS: i64 = 3;

/// 解析回填范围：自定义时间段优先，其次「N 天前至今」，默认 7 天。
pub fn resolve_range(
    days: Option<i64>,
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
) -> Result<(DateTime<Utc>, DateTime<Utc>), String> {
    let now = Utc::now();
    match (start, end) {
        (Some(start), Some(end)) => {
            if start >= end {
                return Err("开始时间必须早于结束时间".into());
            }
            if end > now + chrono::Duration::minutes(5) {
                return Err("结束时间不能晚于当前时间".into());
            }
            if (end - start).num_days() > MAX_BACKFILL_DAYS {
                return Err(format!("时间范围不能超过 {MAX_BACKFILL_DAYS} 天"));
            }
            Ok((start, end))
        }
        (None, None) => {
            let days = days.unwrap_or(DEFAULT_BACKFILL_DAYS);
            if !(1..=MAX_BACKFILL_DAYS).contains(&days) {
                return Err(format!("天数必须为 1～{MAX_BACKFILL_DAYS}"));
            }
            Ok((now - chrono::Duration::days(days), now))
        }
        _ => Err("自定义时间段必须同时提供开始与结束时间".into()),
    }
}

pub async fn create_job(
    pool: &Pool,
    user_id: Option<i32>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Uuid, String> {
    let client = pool.get().await.map_err(|e| e.to_string())?;
    let active: i64 = client
        .query_one(
            "SELECT COUNT(*)::BIGINT FROM syslog_backfill_job WHERE status IN ('queued','running')",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    if active >= MAX_ACTIVE_JOBS {
        return Err("进行中的回填任务过多，请等待完成后再下发".into());
    }
    let id = Uuid::now_v7();
    client
        .execute(
            "INSERT INTO syslog_backfill_job (id, range_start, range_end, created_by_user_id) \
             VALUES ($1,$2,$3,$4)",
            &[&id, &start, &end, &user_id],
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok(id)
}

/// queued 直接取消；running 置取消标记，由 worker 在批次间检查。
pub async fn cancel_job(pool: &Pool, id: Uuid) -> Result<bool, String> {
    let client = pool.get().await.map_err(|e| e.to_string())?;
    let changed = client
        .execute(
            "UPDATE syslog_backfill_job SET status='cancelled', finished_at=NOW() \
             WHERE id=$1 AND status='queued'",
            &[&id],
        )
        .await
        .map_err(|e| e.to_string())?;
    if changed > 0 {
        return Ok(true);
    }
    let changed = client
        .execute(
            "UPDATE syslog_backfill_job SET cancel_requested=TRUE WHERE id=$1 AND status='running'",
            &[&id],
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok(changed > 0)
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackfillJob {
    pub id: Uuid,
    pub status: String,
    pub range_start: DateTime<Utc>,
    pub range_end: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub processed_count: i64,
    pub sent_count: i64,
    pub failed_count: i64,
    pub last_error: String,
}

pub async fn list_jobs(
    pool: &Pool,
    limit: i64,
) -> Result<Vec<BackfillJob>, Box<dyn std::error::Error + Send + Sync>> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT id, status, range_start, range_end, created_at, started_at, finished_at, \
             processed_count, sent_count, failed_count, last_error \
             FROM syslog_backfill_job ORDER BY created_at DESC LIMIT $1",
            &[&limit.clamp(1, 100)],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| BackfillJob {
            id: row.get("id"),
            status: row.get("status"),
            range_start: row.get("range_start"),
            range_end: row.get("range_end"),
            created_at: row.get("created_at"),
            started_at: row.get("started_at"),
            finished_at: row.get("finished_at"),
            processed_count: row.get("processed_count"),
            sent_count: row.get("sent_count"),
            failed_count: row.get("failed_count"),
            last_error: row.get("last_error"),
        })
        .collect())
}

#[derive(Default)]
struct Counters {
    processed: i64,
    sent: i64,
    failed: i64,
}

enum Outcome {
    Done(Counters),
    Cancelled(Counters),
    Failed(String, Counters),
}

pub async fn run_worker(
    pool: Pool,
    config: RuntimeConfig<SyslogConfig>,
    mut stopping: watch::Receiver<bool>,
) {
    // 重启恢复：中断的 running 任务标记失败（同备份任务模式）。
    if let Ok(client) = pool.get().await {
        let _ = client
            .execute(
                "UPDATE syslog_backfill_job SET status='failed', finished_at=NOW(), \
                 last_error='服务重启，任务执行状态已中断' WHERE status='running'",
                &[],
            )
            .await;
    }
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = stopping.changed() => return,
            _ = ticker.tick() => {}
        }
        let job = match claim(&pool).await {
            Ok(Some(job)) => job,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(event = "SyslogBackfillClaimFailed", error_message = %error, "回填任务领取失败");
                continue;
            }
        };
        let settings = config.get().await.value;
        let outcome = process(&pool, &settings, &job, &mut stopping).await;
        let (status, counters, error) = match outcome {
            Outcome::Done(counters) => ("succeeded", counters, String::new()),
            Outcome::Cancelled(counters) => ("cancelled", counters, String::new()),
            Outcome::Failed(error, counters) => ("failed", counters, error),
        };
        if let Err(error) = finish(&pool, job.id, status, &counters, &error).await {
            tracing::warn!(event = "SyslogBackfillFinishFailed", error_message = %error, "回填任务收尾写入失败");
        }
        tracing::info!(
            event = "SyslogBackfillFinished",
            component = "syslog",
            job_id = %job.id,
            status,
            processed = counters.processed,
            sent = counters.sent,
            failed = counters.failed,
            "历史日志回填任务结束"
        );
    }
}

async fn claim(
    pool: &Pool,
) -> Result<Option<BackfillJob>, Box<dyn std::error::Error + Send + Sync>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "UPDATE syslog_backfill_job SET status='running', started_at=NOW() \
             WHERE id = (SELECT id FROM syslog_backfill_job WHERE status='queued' \
                         ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) \
             RETURNING id, status, range_start, range_end, created_at, started_at, finished_at, \
                       processed_count, sent_count, failed_count, last_error",
            &[],
        )
        .await?;
    Ok(row.map(|row| BackfillJob {
        id: row.get("id"),
        status: row.get("status"),
        range_start: row.get("range_start"),
        range_end: row.get("range_end"),
        created_at: row.get("created_at"),
        started_at: row.get("started_at"),
        finished_at: row.get("finished_at"),
        processed_count: row.get("processed_count"),
        sent_count: row.get("sent_count"),
        failed_count: row.get("failed_count"),
        last_error: row.get("last_error"),
    }))
}

async fn finish(
    pool: &Pool,
    id: Uuid,
    status: &str,
    counters: &Counters,
    error: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE syslog_backfill_job SET status=$2, finished_at=NOW(), \
             processed_count=$3, sent_count=$4, failed_count=$5, last_error=$6 WHERE id=$1",
            &[
                &id,
                &status,
                &counters.processed,
                &counters.sent,
                &counters.failed,
                &error,
            ],
        )
        .await?;
    Ok(())
}

async fn update_progress(
    pool: &Pool,
    id: Uuid,
    counters: &Counters,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE syslog_backfill_job SET processed_count=$2, sent_count=$3, failed_count=$4 WHERE id=$1",
            &[&id, &counters.processed, &counters.sent, &counters.failed],
        )
        .await?;
    Ok(())
}

async fn cancel_requested(pool: &Pool, id: Uuid) -> bool {
    match pool.get().await {
        Ok(client) => client
            .query_opt(
                "SELECT cancel_requested FROM syslog_backfill_job WHERE id=$1",
                &[&id],
            )
            .await
            .ok()
            .flatten()
            .map(|row| row.get::<_, bool>("cancel_requested"))
            .unwrap_or(false),
        Err(_) => false,
    }
}

async fn process(
    pool: &Pool,
    settings: &SyslogConfig,
    job: &BackfillJob,
    stopping: &mut watch::Receiver<bool>,
) -> Outcome {
    if !settings.enabled {
        return Outcome::Failed(
            "Syslog 转发未启用，请先启用后再下发回填".into(),
            Counters::default(),
        );
    }
    let targets: Vec<TargetConfig> = settings
        .targets
        .iter()
        .filter(|target| target.enabled)
        .cloned()
        .collect();
    if targets.is_empty() {
        return Outcome::Failed("没有已启用的 syslog 服务器".into(), Counters::default());
    }
    let mut connections: Vec<Option<Connection>> = targets.iter().map(|_| None).collect();
    let mut counters = Counters::default();

    macro_rules! check_cancel {
        () => {
            if stopping.has_changed().unwrap_or(true) {
                return Outcome::Cancelled(counters);
            }
            if cancel_requested(pool, job.id).await {
                return Outcome::Cancelled(counters);
            }
        };
    }

    // 三个历史源依次键集分页重放；游标初值保证覆盖 range_start 当刻的记录。
    let mut cursor_at = job.range_start;
    let mut cursor_id: i64 = 0;
    loop {
        check_cancel!();
        let batch = match fetch_audit(pool, job, cursor_at, cursor_id).await {
            Ok(batch) => batch,
            Err(error) => return Outcome::Failed(error.to_string(), counters),
        };
        if batch.is_empty() {
            break;
        }
        for (item, at, id) in batch {
            send_item(&targets, &mut connections, settings, &item, &mut counters).await;
            counters.processed += 1;
            cursor_at = at;
            cursor_id = id;
            pace(&counters).await;
        }
        let _ = update_progress(pool, job.id, &counters).await;
    }

    let mut cursor_at = job.range_start;
    let mut cursor_id: i64 = 0;
    loop {
        check_cancel!();
        let batch = match fetch_access(pool, job, cursor_at, cursor_id).await {
            Ok(batch) => batch,
            Err(error) => return Outcome::Failed(error.to_string(), counters),
        };
        if batch.is_empty() {
            break;
        }
        for (item, at, id) in batch {
            if let Some(item) = item {
                send_item(&targets, &mut connections, settings, &item, &mut counters).await;
            }
            counters.processed += 1;
            cursor_at = at;
            cursor_id = id;
            pace(&counters).await;
        }
        let _ = update_progress(pool, job.id, &counters).await;
    }

    let mut cursor_at = job.range_start;
    let mut cursor_scanner = String::new();
    let mut cursor_event = String::new();
    loop {
        check_cancel!();
        let batch = match fetch_scanner(pool, job, cursor_at, &cursor_scanner, &cursor_event).await
        {
            Ok(batch) => batch,
            Err(error) => return Outcome::Failed(error.to_string(), counters),
        };
        if batch.is_empty() {
            break;
        }
        for (item, at, scanner, event_id) in batch {
            if let Some(item) = item {
                send_item(&targets, &mut connections, settings, &item, &mut counters).await;
            }
            counters.processed += 1;
            cursor_at = at;
            cursor_scanner = scanner;
            cursor_event = event_id;
            pace(&counters).await;
        }
        let _ = update_progress(pool, job.id, &counters).await;
    }

    Outcome::Done(counters)
}

/// 轻量限速：避免回填突发压垮远端或本机网络。
async fn pace(counters: &Counters) {
    if counters.processed % 200 == 0 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn send_item(
    targets: &[TargetConfig],
    connections: &mut [Option<Connection>],
    settings: &SyslogConfig,
    item: &ForwardItem,
    counters: &mut Counters,
) {
    for (index, target) in targets.iter().enumerate() {
        // 与实时转发一致：只重放该目标订阅的日志类型。
        if !target.sources.contains(&item.source) {
            continue;
        }
        let max_bytes = if target.protocol == Protocol::Udp {
            UDP_MAX_BYTES
        } else {
            TCP_MAX_BYTES
        };
        let message = Message {
            timestamp: item.timestamp,
            severity: item.severity,
            msgid: item.msgid,
            sd: item.sd.clone(),
            text: item.text.clone(),
        };
        let payload = format::render(
            &message,
            settings.facility.code(),
            &settings.app_name,
            max_bytes,
        );
        let connection = &mut connections[index];
        let mut delivered = false;
        for attempt in 0..2 {
            if connection.is_none() {
                match transport::connect(target, transport::CONNECT_TIMEOUT).await {
                    Ok(created) => *connection = Some(created),
                    Err(_) => break,
                }
            }
            let active = connection.as_mut().expect("connection checked above");
            match transport::send(active, &payload, transport::SEND_TIMEOUT).await {
                Ok(()) => {
                    delivered = true;
                    break;
                }
                Err(_) => {
                    *connection = None;
                    if attempt == 1 {
                        break;
                    }
                }
            }
        }
        if delivered {
            counters.sent += 1;
        } else {
            counters.failed += 1;
        }
    }
}

type DbError = Box<dyn std::error::Error + Send + Sync>;

async fn fetch_audit(
    pool: &Pool,
    job: &BackfillJob,
    cursor_at: DateTime<Utc>,
    cursor_id: i64,
) -> Result<Vec<(ForwardItem, DateTime<Utc>, i64)>, DbError> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT id, occurred_at, category, action, outcome, severity, actor_type, actor_id, \
             actor_name, resource_type, resource_id, request_id, source_ip, user_agent, \
             http_method, request_path, response_status, reason_code, changes, metadata \
             FROM audit_event \
             WHERE occurred_at >= $1 AND occurred_at < $2 AND (occurred_at, id) > ($3, $4) \
             ORDER BY occurred_at, id LIMIT $5",
            &[
                &job.range_start,
                &job.range_end,
                &cursor_at,
                &cursor_id,
                &BATCH_SIZE,
            ],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| {
            let event = AuditEvent {
                category: row.get("category"),
                action: row.get("action"),
                outcome: row.get("outcome"),
                severity: row.get("severity"),
                actor_type: row.get("actor_type"),
                actor_id: row.get("actor_id"),
                actor_name: row.get("actor_name"),
                resource_type: row.get("resource_type"),
                resource_id: row.get("resource_id"),
                response_status: row
                    .get::<_, Option<i16>>("response_status")
                    .map(|v| v as u16),
                reason_code: row.get("reason_code"),
                changes: row.get("changes"),
                metadata: row.get("metadata"),
            };
            let context = AuditContext {
                request_id: row.get("request_id"),
                source_ip: row.get("source_ip"),
                user_agent: row.get("user_agent"),
                http_method: row.get("http_method"),
                request_path: row.get("request_path"),
            };
            let occurred_at: DateTime<Utc> = row.get("occurred_at");
            (
                hooks::audit_item(&event, &context, occurred_at),
                occurred_at,
                row.get("id"),
            )
        })
        .collect())
}

async fn fetch_access(
    pool: &Pool,
    job: &BackfillJob,
    cursor_at: DateTime<Utc>,
    cursor_id: i64,
) -> Result<Vec<(Option<ForwardItem>, DateTime<Utc>, i64)>, DbError> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT id, request_id, occurred_at, http_method, request_path, route_pattern, \
             status_code, duration_ms, duration_us, client_ip, user_agent, actor_id, actor_name, \
             error_level, error_type, reason_code \
             FROM request_log \
             WHERE occurred_at >= $1 AND occurred_at < $2 AND (occurred_at, id) > ($3, $4) \
             ORDER BY occurred_at, id LIMIT $5",
            &[
                &job.range_start,
                &job.range_end,
                &cursor_at,
                &cursor_id,
                &BATCH_SIZE,
            ],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| {
            let entry = RequestLogEntry {
                request_id: row.get("request_id"),
                occurred_at: row.get("occurred_at"),
                http_method: row.get("http_method"),
                request_path: row.get("request_path"),
                route_pattern: row.get("route_pattern"),
                status_code: row.get("status_code"),
                duration_ms: row.get("duration_ms"),
                duration_us: row.get("duration_us"),
                client_ip: row.get("client_ip"),
                user_agent: row.get("user_agent"),
                actor_id: row.get("actor_id"),
                actor_name: row.get("actor_name"),
                error_level: row.get("error_level"),
                error_type: row.get("error_type"),
                reason_code: row.get("reason_code"),
            };
            let occurred_at: DateTime<Utc> = row.get("occurred_at");
            (hooks::access_item(&entry), occurred_at, row.get("id"))
        })
        .collect())
}

async fn fetch_scanner(
    pool: &Pool,
    job: &BackfillJob,
    cursor_at: DateTime<Utc>,
    cursor_scanner: &str,
    cursor_event: &str,
) -> Result<Vec<(Option<ForwardItem>, DateTime<Utc>, String, String)>, DbError> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT scanner_id, event_id, occurred_at, level, error_code, category, fingerprint, document \
             FROM scanner_error_event \
             WHERE occurred_at >= $1 AND occurred_at < $2 \
               AND (occurred_at, scanner_id, event_id) > ($3, $4, $5) \
             ORDER BY occurred_at, scanner_id, event_id LIMIT $6",
            &[
                &job.range_start,
                &job.range_end,
                &cursor_at,
                &cursor_scanner,
                &cursor_event,
                &BATCH_SIZE,
            ],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| {
            let scanner_id: String = row.get("scanner_id");
            let event_id: String = row.get("event_id");
            let occurred_at: DateTime<Utc> = row.get("occurred_at");
            let document: serde_json::Value = row.get("document");
            let item = Uuid::parse_str(&scanner_id).ok().map(|scanner_uuid| {
                let event = ParsedEvent {
                    event_id: event_id.clone(),
                    occurred_at,
                    level: row.get("level"),
                    error_code: row.get("error_code"),
                    category: row.get("category"),
                    operation: document
                        .pointer("/fields/operation")
                        .and_then(|value| value.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    fingerprint: row.get("fingerprint"),
                    document,
                };
                hooks::scanner_item(scanner_uuid, &event)
            });
            (item, occurred_at, scanner_id, event_id)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_range_is_seven_days() {
        let (start, end) = resolve_range(None, None, None).unwrap();
        let days = (end - start).num_days();
        assert_eq!(days, 7);
        assert!(end <= Utc::now());
    }

    #[test]
    fn custom_days_range_is_bounded() {
        assert!(resolve_range(Some(0), None, None).is_err());
        assert!(resolve_range(Some(32), None, None).is_err());
        let (start, end) = resolve_range(Some(3), None, None).unwrap();
        assert_eq!((end - start).num_days(), 3);
    }

    #[test]
    fn explicit_range_requires_order_and_cap() {
        let now = Utc::now();
        let start = now - chrono::Duration::days(2);
        assert!(resolve_range(None, Some(start), Some(now)).is_ok());
        assert!(resolve_range(None, Some(now), Some(start)).is_err());
        assert!(resolve_range(None, Some(now - chrono::Duration::days(40)), Some(now)).is_err());
        assert!(resolve_range(None, Some(start), Some(now + chrono::Duration::days(1))).is_err());
        assert!(resolve_range(None, Some(start), None).is_err());
    }
}
