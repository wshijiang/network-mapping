use chrono::{DateTime, Utc};
use deadpool_postgres::{GenericClient, Pool};
use serde::Serialize;
use serde_json::{Value, json};
use tokio_postgres::{IsolationLevel, Row};
use uuid::Uuid;

use super::{
    period::{Period, PeriodType},
    statistics,
};

#[derive(Serialize)]
pub struct Report {
    pub timezone: String,
    pub settings_revision: i64,
    pub id: Uuid,
    pub period_type: String,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub revision: i32,
    pub source: String,
    pub status: String,
    pub cutoff_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub generated_at: Option<DateTime<Utc>>,
    pub supersedes_report_id: Option<Uuid>,
    pub quality: Value,
    pub last_error: Option<String>,
    pub content_checksum: Option<String>,
    pub payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mail_image: Option<Value>,
}
impl Report {
    pub fn from_row(r: Row, detail: bool) -> Self {
        Self {
            mail_image: if detail {
                r.try_get("mail_image").ok().flatten()
            } else {
                None
            },
            timezone: r.get("timezone"),
            settings_revision: r.get("settings_revision"),
            id: r.get("id"),
            period_type: r.get("period_type"),
            period_start: r.get("period_start"),
            period_end: r.get("period_end"),
            revision: r.get("revision"),
            source: r.get("source"),
            status: r.get("status"),
            cutoff_at: r.get("cutoff_at"),
            created_at: r.get("created_at"),
            generated_at: r.get("generated_at"),
            supersedes_report_id: r.get("supersedes_report_id"),
            quality: r.get("quality"),
            last_error: r.get("last_error"),
            content_checksum: r.get("content_checksum"),
            payload: if detail { r.get("payload") } else { None },
        }
    }
}

pub async fn recipients<C: GenericClient + Sync>(
    client: &C,
    selected: &[i32],
) -> Result<Vec<(i32, String)>, String> {
    let rows = client.query("SELECT id, email FROM users WHERE role = 1 AND disabled_at IS NULL AND deleted_at IS NULL \
        AND NOT limit_login AND email IS NOT NULL AND trim(email) <> '' AND (cardinality($1::INTEGER[]) = 0 OR id = ANY($1)) ORDER BY id;", &[&selected])
        .await.map_err(|e| e.to_string())?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            let email: String = r.get("email");
            let email = email.trim();
            email
                .parse::<lettre::message::Mailbox>()
                .ok()
                .map(|_| (r.get("id"), email.to_owned()))
        })
        .collect())
}

pub async fn enqueue_delivery<C: GenericClient + Sync>(
    client: &C,
    id: Uuid,
    selected: &[i32],
    automatic: bool,
    resend: bool,
) -> Result<usize, String> {
    super::assets::renew(client, id).await?;
    let recipients = recipients(client, selected).await?;
    let seq: i32 = if resend {
        client.query_one("SELECT COALESCE(MAX(dispatch_seq), 0) + 1 AS seq FROM report_delivery WHERE report_id = $1;", &[&id]).await.map_err(|e| e.to_string())?.get("seq")
    } else {
        1
    };
    for (user, email) in &recipients {
        client.execute("INSERT INTO report_delivery(id, report_id, recipient_user_id, recipient, dispatch_seq, automatic) \
            VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING;", &[&Uuid::new_v4(), &id, user, email, &seq, &automatic])
            .await.map_err(|e| e.to_string())?;
    }
    Ok(recipients.len())
}

fn database_error(error: tokio_postgres::Error) -> String {
    match error.as_db_error() {
        Some(db) => format!("{}: {}", db.code().code(), db.message()),
        None => error.to_string(),
    }
}

/// Concurrent creators may start their repeatable-read snapshot before another creator commits.
/// Retry only serialization/unique conflicts in a fresh transaction, preserving period idempotency.
pub async fn create(
    pool: &Pool,
    period: &Period,
    requested_by: Option<i32>,
    source: &str,
    supersedes: Option<Uuid>,
) -> Result<Uuid, String> {
    for attempt in 0..4 {
        match create_once(pool, period, requested_by, source, supersedes).await {
            Err(error)
                if attempt < 3 && (error.starts_with("40001:") || error.starts_with("23505:")) =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(20 * (attempt + 1))).await;
            }
            result => return result,
        }
    }
    Err("报告并发创建失败，请重试".into())
}

async fn create_once(
    pool: &Pool,
    period: &Period,
    requested_by: Option<i32>,
    source: &str,
    supersedes: Option<Uuid>,
) -> Result<Uuid, String> {
    let mut client = pool.get().await.map_err(|e| e.to_string())?;
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .start()
        .await
        .map_err(database_error)?;
    tx.batch_execute("SET LOCAL statement_timeout = '30s';")
        .await
        .map_err(database_error)?;
    let kind = period.kind.as_str();
    if source == "automatic" {
        let current = tx
            .query_one(
                "SELECT revision FROM runtime_configuration WHERE namespace = 'general' FOR SHARE;",
                &[],
            )
            .await
            .map_err(database_error)?;
        if current.get::<_, i64>("revision") != period.settings_revision {
            return Err("系统时区配置已更新，等待重新计算报告计划".into());
        }
    }
    let plan = tx
        .query_one(
            "SELECT * FROM report_schedule WHERE period_type = $1 FOR UPDATE;",
            &[&kind],
        )
        .await
        .map_err(database_error)?;
    let automatic = source == "automatic";
    let recipient_ids: Vec<i32> = plan.get("recipient_ids");
    if automatic {
        let enabled_at: Option<DateTime<Utc>> = plan.get("enabled_at");
        if !plan.get::<_, bool>("enabled") || enabled_at.is_none_or(|at| period.end < at) {
            return Err("自动计划未启用或周期早于启用时间".into());
        }
    }
    let existing = if supersedes.is_none() {
        tx.query_opt("SELECT id, status FROM report_run WHERE period_type = $1 AND period_start = $2 AND period_end = $3 AND revision = 1 AND timezone = $4;", &[&kind, &period.start, &period.end, &period.timezone]).await.map_err(database_error)?
    } else {
        None
    };
    let id = if let Some(existing) = existing {
        let id: Uuid = existing.get("id");
        if automatic {
            tx.execute(
                "UPDATE report_run SET send_email = TRUE, recipient_ids = $2 WHERE id = $1;",
                &[&id, &recipient_ids],
            )
            .await
            .map_err(database_error)?;
            if existing.get::<_, String>("status") == "ready" {
                crate::notification::enqueue_report(&tx, id)
                    .await
                    .map_err(|_| "报告通知入队失败".to_owned())?;
            }
        }
        id
    } else {
        let id = Uuid::new_v4();
        let revision: i32 = tx.query_one("SELECT COALESCE(MAX(revision), 0) + 1 AS revision FROM report_run WHERE period_type = $1 AND period_start = $2 AND period_end = $3 AND timezone = $4;", &[&kind, &period.start, &period.end, &period.timezone]).await.map_err(database_error)?.get("revision");
        let snapshot = statistics::capture(&tx, period).await?;
        tx.execute("INSERT INTO report_run(id, period_type, period_start, period_end, revision, source, requested_by, send_email, recipient_ids, task_snapshot, supersedes_report_id, timezone, settings_revision) \
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13);", &[&id, &kind, &period.start, &period.end, &revision, &source, &requested_by, &automatic, &recipient_ids, &snapshot, &supersedes, &period.timezone, &period.settings_revision]).await.map_err(database_error)?;
        let previous = period.previous()?;
        tx.execute("INSERT INTO report_input_execution(report_id, execution_id, period_slot, expected_observations) \
            SELECT $1, e.id, CASE WHEN e.task_end_time >= $2 THEN 'current' ELSE 'previous' END, COALESCE(e.result_observation_count, (SELECT SUM(b.observation_count) FROM scan_result_batch b WHERE b.execution_id = e.id), 0) \
            FROM scan_task_execution e JOIN scan_task t ON t.id = e.task_id \
            WHERE e.execution_status = 'succeeded' AND t.task_kind = 'ip' \
              AND e.task_end_time >= $3 AND e.task_end_time < $4;", &[&id, &period.start.timestamp_millis(), &previous.start.timestamp_millis(), &period.end.timestamp_millis()]).await.map_err(database_error)?;
        tx.execute("INSERT INTO report_job(report_id) VALUES ($1);", &[&id])
            .await
            .map_err(database_error)?;
        id
    };
    if automatic {
        tx.execute("UPDATE report_schedule SET last_period_end = GREATEST(last_period_end, $2) WHERE period_type = $1;", &[&kind, &period.end]).await.map_err(database_error)?;
    }
    tx.commit().await.map_err(database_error)?;
    Ok(id)
}

pub async fn schedules(pool: &Pool) -> Result<Value, String> {
    let settings = crate::system_time::refresh(pool).await?;
    let client = pool.get().await.map_err(|e| e.to_string())?;
    let rows = client
        .query(
            "SELECT * FROM report_schedule ORDER BY period_type DESC;",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
    let now = Utc::now();
    let timezone = settings.document.timezone;
    let tz = timezone
        .parse::<chrono_tz::Tz>()
        .map_err(|e| e.to_string())?;
    let mut plans = Vec::new();
    for row in rows {
        let kind: String = row.get("period_type");
        let parsed = PeriodType::parse(&kind)?;
        let enabled: bool = row.get("enabled");
        let hour: i16 = row.get("send_hour");
        let minute: i16 = row.get("send_minute");
        let last: Option<DateTime<Utc>> = row.get("last_period_end");
        let enabled_at: Option<DateTime<Utc>> = row.get("enabled_at");
        let next = if enabled {
            let base = last.or(enabled_at).unwrap_or(now);
            Some(
                Period::containing_in(
                    parsed,
                    base.with_timezone(&tz).date_naive(),
                    &timezone,
                    settings.revision,
                )?
                .due_at(hour as u32, minute as u32)?,
            )
        } else {
            None
        };
        plans.push(json!({"period_type": kind, "enabled": enabled, "send_hour": hour, "send_minute": minute,
            "recipient_ids": row.get::<_, Vec<i32>>("recipient_ids"), "revision": row.get::<_, i64>("revision"),
            "enabled_at": enabled_at, "next_run_at": next, "timezone": timezone}));
    }
    let users = client.query("SELECT id, username, email FROM users WHERE role = 1 AND disabled_at IS NULL AND deleted_at IS NULL AND NOT limit_login ORDER BY username;", &[]).await.map_err(|e| e.to_string())?;
    let users: Vec<Value> = users.iter().map(|r| json!({"id": r.get::<_, i32>("id"), "username": r.get::<_, String>("username"), "email": r.get::<_, Option<String>>("email")})).collect();
    Ok(json!({"schedules": plans, "recipients": users}))
}
