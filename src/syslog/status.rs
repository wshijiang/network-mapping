//! 目标运行状态：内存实时注册表 + 节流落库（供 CLI 与重启后查看）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use uuid::Uuid;

use crate::runtime_config::RuntimeConfig;
use crate::syslog::config::SyslogConfig;

#[derive(Clone, Debug)]
pub struct TargetStatus {
    /// connecting | connected | error | disabled
    pub state: String,
    pub sent: u64,
    pub failed: u64,
    pub dropped: u64,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_error_at: Option<DateTime<Utc>>,
    pub last_error: String,
    pub updated_at: Option<DateTime<Utc>>,
}

impl Default for TargetStatus {
    fn default() -> Self {
        Self {
            state: "connecting".to_owned(),
            sent: 0,
            failed: 0,
            dropped: 0,
            last_success_at: None,
            last_error_at: None,
            last_error: String::new(),
            updated_at: None,
        }
    }
}

#[derive(Clone, Default)]
pub struct StatusRegistry {
    inner: Arc<Mutex<HashMap<Uuid, TargetStatus>>>,
}

impl StatusRegistry {
    pub fn snapshot(&self) -> Vec<(Uuid, TargetStatus)> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|(id, status)| (*id, status.clone()))
            .collect()
    }

    pub fn get(&self, id: Uuid) -> Option<TargetStatus> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&id)
            .cloned()
    }

    fn update(&self, id: Uuid, apply: impl FnOnce(&mut TargetStatus)) {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = guard.entry(id).or_default();
        apply(entry);
        entry.updated_at = Some(Utc::now());
    }

    pub fn set_state(&self, id: Uuid, state: &str) {
        self.update(id, |status| status.state = state.to_owned());
    }

    pub fn record_success(&self, id: Uuid) {
        self.update(id, |status| {
            status.sent += 1;
            status.state = "connected".to_owned();
            status.last_success_at = Some(Utc::now());
        });
    }

    pub fn record_failure(&self, id: Uuid, error: &str) {
        self.update(id, |status| {
            status.failed += 1;
            status.state = "error".to_owned();
            status.last_error_at = Some(Utc::now());
            status.last_error = crate::syslog::transport::sanitize_error(error);
        });
    }

    pub fn add_dropped(&self, id: Uuid, count: u64) {
        self.update(id, |status| status.dropped += count);
    }

    /// 丢弃已不在配置中的目标状态。
    pub fn retain(&self, ids: &[Uuid]) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|id, _| ids.contains(id));
    }
}

/// 每 15 秒把内存状态落库；CLI 读取该快照，服务停机时仍可看到最后已知状态。
pub async fn run_persistence(
    pool: Pool,
    registry: StatusRegistry,
    config: RuntimeConfig<SyslogConfig>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(15));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let targets = config.get().await.value.targets;
        let ids: Vec<Uuid> = targets.iter().map(|target| target.id).collect();
        if let Err(error) = persist(&pool, &registry, &ids).await {
            tracing::warn!(
                event = "SyslogStatusPersistFailed",
                operation = "persist_syslog_target_status",
                error_message = %error,
                "syslog 目标状态落库失败"
            );
        }
    }
}

async fn persist(
    pool: &Pool,
    registry: &StatusRegistry,
    known: &[Uuid],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = pool.get().await?;
    for (id, status) in registry.snapshot() {
        client
            .execute(
                "INSERT INTO syslog_target_status \
                 (target_id, state, sent_count, failed_count, dropped_count, last_success_at, last_error_at, last_error, updated_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW()) \
                 ON CONFLICT (target_id) DO UPDATE SET \
                 state=EXCLUDED.state, sent_count=EXCLUDED.sent_count, failed_count=EXCLUDED.failed_count, \
                 dropped_count=EXCLUDED.dropped_count, last_success_at=EXCLUDED.last_success_at, \
                 last_error_at=EXCLUDED.last_error_at, last_error=EXCLUDED.last_error, updated_at=NOW()",
                &[
                    &id,
                    &status.state,
                    &(status.sent as i64),
                    &(status.failed as i64),
                    &(status.dropped as i64),
                    &status.last_success_at,
                    &status.last_error_at,
                    &status.last_error,
                ],
            )
            .await?;
    }
    client
        .execute(
            "DELETE FROM syslog_target_status WHERE target_id <> ALL($1::UUID[])",
            &[&known],
        )
        .await?;
    Ok(())
}

/// CLI 使用的落库快照行。
pub struct PersistedStatus {
    pub target_id: Uuid,
    pub state: String,
    pub sent: i64,
    pub failed: i64,
    pub dropped: i64,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_error_at: Option<DateTime<Utc>>,
    pub last_error: String,
    pub updated_at: DateTime<Utc>,
}

pub async fn load_persisted(
    pool: &Pool,
) -> Result<Vec<PersistedStatus>, Box<dyn std::error::Error + Send + Sync>> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT target_id, state, sent_count, failed_count, dropped_count, \
             last_success_at, last_error_at, last_error, updated_at \
             FROM syslog_target_status ORDER BY updated_at DESC",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| PersistedStatus {
            target_id: row.get("target_id"),
            state: row.get("state"),
            sent: row.get("sent_count"),
            failed: row.get("failed_count"),
            dropped: row.get("dropped_count"),
            last_success_at: row.get("last_success_at"),
            last_error_at: row.get("last_error_at"),
            last_error: row.get("last_error"),
            updated_at: row.get("updated_at"),
        })
        .collect())
}
