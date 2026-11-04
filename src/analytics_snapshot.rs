//! Offline scan-analysis snapshots.
//!
//! The worker consumes completed executions rather than repeatedly aggregating the entire scan
//! history. `analytics_outbox` is also reconciled from the control plane, so deployments upgraded
//! from older server versions do not lose executions that were completed before this module was
//! installed.

use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::BTreeSet;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
#[cfg(test)]
use chrono::{NaiveDate, Timelike};
use deadpool_postgres::Pool;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::time::Duration;
use tracing::{info, warn};

use crate::config::AnalyticsSnapshotConfig;
use crate::elasticsearch::ElasticsearchService;
use crate::runtime_config::RuntimeConfig;

const WORKER_LOCK_KEY: i64 = 0x4e4d_4153_4e50_0001;
const MAX_EXECUTIONS_PER_TICK: usize = 100;
const READ_BATCH_SIZE: usize = 5000;
#[cfg(test)]
const WRITE_BATCH_SIZE: usize = 1000;
const PAGE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Debug)]
struct ExecutionContext {
    database_id: i32,
    execution_id: String,
    owner_id: i32,
    scanner_id: String,
    task_source: String,
    locked_at: DateTime<Utc>,
    attempts: i32,
    expected_observations: i64,
    observation_indices: Vec<String>,
}

#[cfg(test)]
#[derive(Default)]
struct ExecutionFacts {
    distribution: BTreeMap<(DateTime<Utc>, String, String), i64>,
    discovery: BTreeSet<(DateTime<Utc>, IpAddr)>,
}

#[derive(Serialize)]
pub(crate) struct SnapshotProgress {
    pub data_as_of: Option<DateTime<Utc>>,
    pub build_started_at: Option<DateTime<Utc>>,
    pub build_completed_at: Option<DateTime<Utc>>,
    pub remaining: i64,
    pub pending: i64,
    pub running: i64,
    pub completed: i64,
    pub retrying: i64,
    pub failed_execution_id: Option<i32>,
    pub last_error: Option<String>,
}

pub(crate) async fn snapshot_progress(
    client: &deadpool_postgres::Client,
) -> Result<SnapshotProgress, tokio_postgres::Error> {
    let row = client.query_one(
        "SELECT \
         (SELECT data_as_of FROM analytics_watermark WHERE watermark_key = 'scan_analysis') AS data_as_of, \
         (SELECT started_at FROM analytics_snapshot_build) AS build_started_at, \
         (SELECT completed_at FROM analytics_snapshot_build) AS build_completed_at, \
         (SELECT COUNT(*) FROM analytics_snapshot_build_execution) AS remaining, \
         COUNT(*) FILTER (WHERE status = 'pending') AS pending, \
         COUNT(*) FILTER (WHERE status = 'running') AS running, \
         COUNT(*) FILTER (WHERE status = 'completed') AS completed, \
         COUNT(*) FILTER (WHERE status <> 'completed' AND last_error IS NOT NULL) AS retrying, \
         (SELECT execution_id FROM analytics_outbox WHERE status <> 'completed' AND last_error IS NOT NULL \
          ORDER BY updated_at DESC LIMIT 1) AS failed_execution_id, \
         (SELECT last_error FROM analytics_outbox WHERE status <> 'completed' AND last_error IS NOT NULL \
          ORDER BY updated_at DESC LIMIT 1) AS last_error \
         FROM analytics_outbox;", &[],
    ).await?;
    Ok(SnapshotProgress {
        data_as_of: row.get("data_as_of"),
        build_started_at: row.get("build_started_at"),
        build_completed_at: row.get("build_completed_at"),
        remaining: row.get("remaining"),
        pending: row.get("pending"),
        running: row.get("running"),
        completed: row.get("completed"),
        retrying: row.get("retrying"),
        failed_execution_id: row.get("failed_execution_id"),
        last_error: row.get("last_error"),
    })
}

/// Starts the worker only in `shadow` or `snapshot` mode. Realtime is deliberately the default
/// for an upgraded installation, preventing a switch to empty statistics before backfill.
pub async fn run_worker(
    config: RuntimeConfig<AnalyticsSnapshotConfig>,
    pool: Pool,
    elasticsearch: ElasticsearchService,
) {
    let mut changes = config.subscribe();
    let mut reconcile_at = tokio::time::Instant::now();
    let mut reconcile_failures = 0u32;
    loop {
        let settings = config.get().await.value;
        if !settings.mode.runs_worker() {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                changed = changes.changed() => if changed.is_err() { return; }
            }
            continue;
        }
        if tokio::time::Instant::now() >= reconcile_at {
            if let Err(error) = reconcile(&pool).await {
                reconcile_failures = reconcile_failures.saturating_add(1);
                let delay = reconcile_delay(reconcile_failures);
                reconcile_at = tokio::time::Instant::now() + delay;
                warn!(
                    event = "AnalyticsSnapshotReconcileError",
                    operation = "reconcile_analytics_outbox",
                    reason = %error,
                    error_code = "analytics_snapshot_reconcile_failed",
                    retryable = true,
                    outcome = "reconciliation_retry_scheduled",
                    retry_after_ms = delay.as_millis() as u64,
                );
            } else {
                reconcile_failures = 0;
                reconcile_at = tokio::time::Instant::now()
                    + Duration::from_secs(settings.interval_minutes * 60);
            }
        }
        let mut exhausted = true;
        let tick_started = tokio::time::Instant::now();
        for _ in 0..MAX_EXECUTIONS_PER_TICK {
            if tick_started.elapsed() >= Duration::from_secs(2) {
                break;
            }
            if !config.get().await.value.mode.runs_worker() {
                break;
            }
            match process_one(&pool, &elasticsearch, &settings).await {
                Ok(true) => {}
                Ok(false) => {
                    exhausted = false;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    // The failed execution is delayed by fail_execution; continue draining
                    // independent work so one legacy/corrupt execution cannot block upgrades.
                }
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(worker_delay(exhausted)) => {}
            changed = changes.changed() => if changed.is_err() { return; }
        }
    }
}

fn reconcile_delay(failures: u32) -> Duration {
    Duration::from_secs(
        (30_u64.saturating_mul(2_u64.saturating_pow(failures.saturating_sub(1).min(6)))).min(1800),
    )
}

fn worker_delay(exhausted: bool) -> Duration {
    // Yield between batches; new uploads and delayed retries are polled independently
    // of the much less frequent historical reconciliation.
    Duration::from_secs(if exhausted { 1 } else { 5 })
}

async fn reconcile(pool: &Pool) -> Result<(), String> {
    let mut connection = pool
        .get()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    let transaction = connection
        .transaction()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    let inserted = transaction
        .execute(
            "INSERT INTO analytics_snapshot_build(singleton) VALUES (TRUE) ON CONFLICT DO NOTHING;",
            &[],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    let build = transaction
        .query_one(
            "SELECT completed_at FROM analytics_snapshot_build FOR UPDATE;",
            &[],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    transaction
        .execute(
            "INSERT INTO analytics_outbox (execution_id, status, available_at) \
         SELECT e.id, 'pending', NOW() FROM scan_task_execution e \
         JOIN scan_task t ON t.id = e.task_id \
         WHERE e.execution_status = 'succeeded' AND t.task_kind = 'ip' \
         AND NOT EXISTS (SELECT 1 FROM analytics_outbox o WHERE o.execution_id = e.id) \
         ON CONFLICT (execution_id) DO NOTHING;",
            &[],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    // Upgrade completed legacy facts through the same bounded, retryable outbox.
    // If source observations were deleted, keep the legacy facts and report their limitation.
    transaction.execute(
        "UPDATE analytics_outbox o SET status = 'pending', available_at = NOW(), attempts = 0, updated_at = NOW() \
         WHERE o.status = 'completed' AND EXISTS(SELECT 1 FROM analytics_discovery_fact f WHERE f.execution_id = o.execution_id AND f.first_observed_at IS NULL);",
        &[],
    ).await.map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    // Membership is immutable until published, even when its last execution was
    // deleted. An empty membership table alone must not admit new arrivals.
    if inserted > 0
        || build
            .get::<_, Option<DateTime<Utc>>>("completed_at")
            .is_some()
    {
        transaction
            .execute(
                "UPDATE analytics_snapshot_build SET started_at = NOW(), completed_at = NULL \
         WHERE singleton;",
                &[],
            )
            .await
            .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
        transaction
            .execute(
                "INSERT INTO analytics_snapshot_build_execution(execution_id) \
         SELECT execution_id FROM analytics_outbox WHERE status <> 'completed' \
         ON CONFLICT DO NOTHING;",
                &[],
            )
            .await
            .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    }
    publish_build(&transaction).await?;
    transaction
        .commit()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))
}

async fn publish_build(transaction: &deadpool_postgres::Transaction<'_>) -> Result<(), String> {
    transaction.execute(
        "WITH finished AS ( \
             UPDATE analytics_snapshot_build SET completed_at = NOW() \
             WHERE completed_at IS NULL \
             AND NOT EXISTS (SELECT 1 FROM analytics_snapshot_build_execution) \
             RETURNING started_at \
         ) INSERT INTO analytics_watermark(watermark_key, data_as_of, updated_at) \
           SELECT 'scan_analysis', started_at, NOW() FROM finished \
           ON CONFLICT (watermark_key) DO UPDATE \
           SET data_as_of = GREATEST(analytics_watermark.data_as_of, EXCLUDED.data_as_of), updated_at = NOW();",
        &[],
    ).await.map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    Ok(())
}

/// Rebuilds all completed IP-scan executions. The operation only replaces compact analytics
/// facts; it never alters scan observations or task results. It is intentionally explicit so an
/// upgraded installation can finish historical backfill before selecting `mode = "snapshot"`.
pub async fn rebuild_all(
    pool: &Pool,
    elasticsearch: &ElasticsearchService,
    settings: &AnalyticsSnapshotConfig,
) -> Result<u64, String> {
    reconcile(pool).await?;
    let mut connection = pool
        .get()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    let transaction = connection
        .transaction()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    transaction
        .query_one(
            "SELECT singleton FROM analytics_snapshot_build FOR UPDATE;",
            &[],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    transaction
        .execute(
            "INSERT INTO analytics_outbox (execution_id, status, available_at) \
             SELECT e.id, 'pending', NOW() FROM scan_task_execution e \
             JOIN scan_task t ON t.id = e.task_id \
             WHERE e.execution_status = 'succeeded' AND t.task_kind = 'ip' \
             ON CONFLICT (execution_id) DO UPDATE SET status = 'pending', available_at = NOW(), \
                locked_at = NULL, completed_at = NULL, last_error = NULL, updated_at = NOW();",
            &[],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    transaction
        .batch_execute(
            "DELETE FROM analytics_snapshot_build_execution; \
         UPDATE analytics_snapshot_build SET started_at = NOW(), completed_at = NULL; \
         INSERT INTO analytics_snapshot_build_execution(execution_id) \
         SELECT execution_id FROM analytics_outbox WHERE status <> 'completed';",
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    publish_build(&transaction).await?;
    transaction
        .commit()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    drop(connection);
    let mut processed = 0_u64;
    while process_one(pool, elasticsearch, settings).await? {
        processed += 1;
    }
    let connection = pool
        .get()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    let progress = snapshot_progress(&connection)
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    if progress.remaining > 0 {
        return Err(format!(
            "快照重建尚未完成：剩余 {} 个执行，失败待重试 {} 个；请查看统计进度",
            progress.remaining, progress.retrying
        ));
    }
    Ok(processed)
}

async fn process_one(
    pool: &Pool,
    elasticsearch: &ElasticsearchService,
    settings: &AnalyticsSnapshotConfig,
) -> Result<bool, String> {
    let Some(context) = claim_execution(pool).await.map_err(|error| {
        warn!(
            event = "AnalyticsSnapshotClaimError",
            operation = "claim_analytics_execution",
            reason = %error,
            error_code = "analytics_snapshot_claim_failed",
            retryable = true,
            outcome = "worker_retry_scheduled",
            retry_after_ms = 1_000_u64,
        );
        error
    })?
    else {
        return Ok(false);
    };
    let started = std::time::Instant::now();
    info!(event = "AnalyticsSnapshotExecutionStarted", execution_id = %context.execution_id,
        "开始构建执行统计");
    let result = process_staged_execution(pool, elasticsearch, &context, settings).await;

    match result {
        Ok(()) => {
            info!(
                event = "AnalyticsSnapshotExecutionCompleted",
                execution_id = %context.execution_id,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "扫描分析快照已更新"
            );
            Ok(true)
        }
        Err(error) => {
            let retry_after_seconds = snapshot_retry_seconds(context.attempts);
            warn!(event = "AnalyticsSnapshotExecutionFailed",
                operation = "build_analytics_snapshot",
                reason = %error,
                error_code = "analytics_snapshot_execution_failed",
                retryable = !error.starts_with("statistics_resource_limit:"),
                outcome = "existing_snapshot_preserved",
                execution_id = %context.execution_id,
                execution_database_id = context.database_id,
                scanner_id = %context.scanner_id,
                task_source = %context.task_source,
                attempt = context.attempts,
                expected_observations = context.expected_observations,
                observation_index_count = context.observation_indices.len(),
                retry_after_ms = retry_after_seconds.saturating_mul(1_000),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "执行统计失败，保留已有统计并安排重试");
            if let Err(mark_error) = fail_execution(pool, &context, &error).await {
                warn!(
                    event = "AnalyticsSnapshotRetryScheduleError",
                    operation = "schedule_analytics_snapshot_retry",
                    reason = %mark_error,
                    error_code = "analytics_snapshot_retry_schedule_failed",
                    retryable = true,
                    outcome = "outbox_execution_left_running",
                    execution_id = %context.execution_id,
                    execution_database_id = context.database_id,
                    attempt = context.attempts,
                    locked_at = %context.locked_at,
                    retry_after_ms = 60_u64 * 60 * 1_000,
                );
                return Err(mark_error);
            }
            Err(error)
        }
    }
}

async fn claim_execution(pool: &Pool) -> Result<Option<ExecutionContext>, String> {
    let mut connection = pool
        .get()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    let transaction = connection
        .transaction()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    let locked = transaction
        .query_one("SELECT pg_try_advisory_xact_lock($1);", &[&WORKER_LOCK_KEY])
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?
        .get::<_, bool>(0);
    if !locked {
        transaction
            .commit()
            .await
            .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
        return Ok(None);
    }

    // Normalize abandoned work first so the hot candidate path only needs the pending index.
    transaction
        .execute(
            "UPDATE analytics_outbox SET status = 'pending', available_at = NOW(), locked_at = NULL, \
             updated_at = NOW() WHERE status = 'running' \
             AND COALESCE(heartbeat_at, locked_at) < NOW() - INTERVAL '60 minutes';",
            &[],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;

    // The xact lock serializes claimers. Refuse another claim while a healthy execution is
    // running so multiple server replicas cannot multiply Elasticsearch and PostgreSQL load.
    let active = transaction
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM analytics_outbox \
             WHERE status = 'running' AND COALESCE(heartbeat_at, locked_at) >= NOW() - INTERVAL '60 minutes');",
            &[],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?
        .get::<_, bool>(0);
    if active {
        transaction
            .commit()
            .await
            .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
        return Ok(None);
    }

    // Avoid sorting the complete outbox by a correlated EXISTS expression for every claim.
    // Claim the immutable build cohort through its primary key first, then use the ordinary
    // pending queue only when no build member is currently available.
    let row = claim_build_execution(&transaction).await?;
    let row = if row.is_some() {
        row
    } else {
        claim_pending_execution(&transaction).await?
    };
    transaction
        .commit()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;

    Ok(row.map(|row| ExecutionContext {
        database_id: row.get("id"),
        execution_id: row.get("execution_id"),
        owner_id: row.get("user_id"),
        scanner_id: row.get("scanner_id"),
        task_source: row.get("task_source"),
        locked_at: row.get("locked_at"),
        attempts: row.get("attempts"),
        expected_observations: row.get("expected_observations"),
        observation_indices: row.get("observation_indices"),
    }))
}

async fn claim_build_execution(
    transaction: &deadpool_postgres::Transaction<'_>,
) -> Result<Option<tokio_postgres::Row>, String> {
    transaction
        .query_opt(
            "WITH candidate AS ( \
                SELECT o.execution_id FROM analytics_snapshot_build_execution b \
                JOIN analytics_outbox o ON o.execution_id = b.execution_id \
                WHERE o.status = 'pending' AND o.available_at <= NOW() \
                ORDER BY o.available_at, o.execution_id \
                FOR UPDATE OF o SKIP LOCKED LIMIT 1 \
             ), claimed AS ( \
                UPDATE analytics_outbox o SET status = 'running', attempts = attempts + 1, \
                    locked_at = clock_timestamp(), heartbeat_at = clock_timestamp(), updated_at = NOW() \
                FROM candidate WHERE o.execution_id = candidate.execution_id \
                RETURNING o.execution_id, o.locked_at, o.attempts \
             ) \
             SELECT e.id, e.execution_id, t.user_id, \
                    COALESCE(e.assigned_scanner_id, e.requested_scanner_id, 'unknown') AS scanner_id, \
                    t.task_source, claimed.locked_at, claimed.attempts, \
                    COALESCE(e.result_observation_count, 0) AS expected_observations, \
                    ARRAY(SELECT DISTINCT ref.index_name \
                          FROM scan_result_batch batch \
                          CROSS JOIN LATERAL jsonb_array_elements_text(batch.storage_references) ref(index_name) \
                          WHERE batch.execution_id = e.id \
                            AND batch.storage_backend IN ('elasticsearch', 'dual') \
                          ORDER BY ref.index_name) AS observation_indices \
             FROM claimed JOIN scan_task_execution e ON e.id = claimed.execution_id \
             JOIN scan_task t ON t.id = e.task_id;",
            &[],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))
}

async fn claim_pending_execution(
    transaction: &deadpool_postgres::Transaction<'_>,
) -> Result<Option<tokio_postgres::Row>, String> {
    transaction
        .query_opt(
            "WITH candidate AS ( \
                SELECT o.execution_id FROM analytics_outbox o \
                WHERE o.status = 'pending' AND o.available_at <= NOW() \
                ORDER BY o.available_at, o.execution_id \
                FOR UPDATE SKIP LOCKED LIMIT 1 \
             ), claimed AS ( \
                UPDATE analytics_outbox o SET status = 'running', attempts = attempts + 1, \
                    locked_at = clock_timestamp(), heartbeat_at = clock_timestamp(), updated_at = NOW() \
                FROM candidate WHERE o.execution_id = candidate.execution_id \
                RETURNING o.execution_id, o.locked_at, o.attempts \
             ) \
             SELECT e.id, e.execution_id, t.user_id, \
                    COALESCE(e.assigned_scanner_id, e.requested_scanner_id, 'unknown') AS scanner_id, \
                    t.task_source, claimed.locked_at, claimed.attempts, \
                    COALESCE(e.result_observation_count, 0) AS expected_observations, \
                    ARRAY(SELECT DISTINCT ref.index_name \
                          FROM scan_result_batch batch \
                          CROSS JOIN LATERAL jsonb_array_elements_text(batch.storage_references) ref(index_name) \
                          WHERE batch.execution_id = e.id \
                            AND batch.storage_backend IN ('elasticsearch', 'dual') \
                          ORDER BY ref.index_name) AS observation_indices \
             FROM claimed JOIN scan_task_execution e ON e.id = claimed.execution_id \
             JOIN scan_task t ON t.id = e.task_id;",
            &[],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))
}

// A connection owns the temporary staging tables for exactly one claim. On cancellation,
// cleanup runs before it is returned to the pool; stale tables are also dropped on entry.
async fn process_staged_execution(
    pool: &Pool,
    elasticsearch: &ElasticsearchService,
    context: &ExecutionContext,
    settings: &AnalyticsSnapshotConfig,
) -> Result<(), String> {
    let mut client = pool
        .get()
        .await
        .map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?;
    let previous_timeout: String = client
        .query_one("SHOW statement_timeout", &[])
        .await
        .map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?
        .get(0);
    client.batch_execute("DROP TABLE IF EXISTS pg_temp.nm_analytics_endpoints, pg_temp.nm_analytics_ips; \
        CREATE TEMP TABLE nm_analytics_endpoints (dimension TEXT COLLATE \"C\" NOT NULL, label TEXT COLLATE \"C\" NOT NULL, endpoint TEXT COLLATE \"C\" NOT NULL, first_at TIMESTAMPTZ NOT NULL, PRIMARY KEY(dimension,label,endpoint)); \
        CREATE TEMP TABLE nm_analytics_ips (ip INET PRIMARY KEY, first_at TIMESTAMPTZ NOT NULL); \
        SET statement_timeout = '5min';").await.map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?;
    let mut pit = None;
    let result = tokio::time::timeout(
        Duration::from_secs(settings.execution_timeout_minutes * 60),
        async {
            stage_observations(
                &client,
                elasticsearch,
                context,
                &mut pit,
                settings.max_staging_mib,
            )
            .await?;
            publish_staged_facts(&mut client, context).await
        },
    )
    .await
    .unwrap_or_else(|_| {
        Err(format!(
            "扫描统计执行超过 {} 分钟时间预算",
            settings.execution_timeout_minutes
        ))
    });
    if let Some(id) = pit {
        elasticsearch.close_analytics_pit(&id).await;
    }
    let cleanup = async {
        client
            .batch_execute(
                "DROP TABLE IF EXISTS pg_temp.nm_analytics_endpoints, pg_temp.nm_analytics_ips;",
            )
            .await
            .map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?;
        client
            .query_one(
                "SELECT set_config('statement_timeout', $1, false)",
                &[&previous_timeout],
            )
            .await
            .map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?;
        Ok::<(), String>(())
    }
    .await;
    if cleanup.is_err() {
        // Do not return a session with temporary tables or a changed timeout to the pool.
        drop(deadpool_postgres::Client::take(client));
    }
    result.and(cleanup)
}

async fn stage_observations(
    client: &deadpool_postgres::Client,
    elasticsearch: &ElasticsearchService,
    context: &ExecutionContext,
    pit: &mut Option<String>,
    max_staging_mib: u64,
) -> Result<(), String> {
    if context.expected_observations == 0 && context.observation_indices.is_empty() {
        return Ok(());
    }
    *pit = Some(
        tokio::time::timeout(
            PAGE_TIMEOUT,
            elasticsearch.open_analytics_pit(&context.observation_indices),
        )
        .await
        .map_err(|_| "打开统计 PIT 超时".to_owned())??,
    );
    let mut after: Option<Value> = None;
    let mut observed_count = 0_i64;
    loop {
        let mut body = json!({"size": READ_BATCH_SIZE, "track_total_hits": false,
            "_source": ["kind", "service", "ip_address", "port", "endpoint_id", "observed_at"],
            "query": {"term": {"execution_id": &context.execution_id}},
            "sort": [{"_shard_doc": "asc"}],
            "pit": {"id": pit.as_ref().expect("PIT opened"), "keep_alive": "30m"}});
        if let Some(cursor) = &after {
            body["search_after"] = cursor.clone();
        }
        let response =
            tokio::time::timeout(PAGE_TIMEOUT, elasticsearch.search_analytics_pit(&body))
                .await
                .map_err(|_| "Elasticsearch 统计分页超时".to_owned())??;
        if let Some(id) = response.get("pit_id").and_then(Value::as_str) {
            *pit = Some(id.to_owned());
        }
        let hits = response
            .pointer("/hits/hits")
            .and_then(Value::as_array)
            .ok_or_else(|| "Elasticsearch 扫描统计响应缺少 hits".to_owned())?;
        let mut endpoints = BTreeMap::<(String, String, String), DateTime<Utc>>::new();
        let mut ips = BTreeMap::<IpAddr, DateTime<Utc>>::new();
        for hit in hits {
            observed_count += 1;
            let source = hit
                .get("_source")
                .ok_or_else(|| "Elasticsearch 统计文档缺少 _source".to_owned())?;
            let millis = source
                .get("observed_at")
                .and_then(Value::as_i64)
                .ok_or_else(|| "Elasticsearch 统计文档缺少 observed_at".to_owned())?;
            let timestamp = DateTime::<Utc>::from_timestamp_millis(millis)
                .ok_or_else(|| "Elasticsearch 统计文档 observed_at 无效".to_owned())?;
            let ip = source
                .get("ip_address")
                .and_then(Value::as_str)
                .ok_or_else(|| "Elasticsearch 统计文档缺少 ip_address".to_owned())?;
            let ip_address = ip
                .parse::<IpAddr>()
                .map_err(|error| format!("Elasticsearch 统计文档 ip_address 无效：{error}"))?;
            let port = source
                .get("port")
                .and_then(Value::as_i64)
                .ok_or_else(|| "Elasticsearch 统计文档缺少 port".to_owned())?;
            let endpoint = source
                .get("endpoint_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("{ip}:{port}"));
            update_first(
                &mut endpoints,
                ("port".into(), port.to_string(), endpoint.clone()),
                timestamp,
            );
            if source.get("kind").and_then(Value::as_str) == Some("service")
                && let Some(service) = source.get("service").and_then(Value::as_str)
            {
                let label = service.trim().to_lowercase();
                if !label.is_empty() {
                    update_first(
                        &mut endpoints,
                        ("service".into(), label, endpoint),
                        timestamp,
                    );
                }
            }
            update_first(&mut ips, ip_address, timestamp);
        }
        let next = hits.last().and_then(|hit| hit.get("sort")).cloned();
        if !hits.is_empty()
            && !next
                .as_ref()
                .is_some_and(|v| v.as_array().is_some_and(|a| a.len() == 1 && a[0].is_i64()))
        {
            return Err("Elasticsearch 统计分页游标缺失或无效".into());
        }
        if !hits.is_empty() && next == after {
            return Err("Elasticsearch 统计分页游标未推进".into());
        }
        let endpoint_rows: Vec<Value> = endpoints.into_iter().map(|((dimension,label,endpoint), first_at)| json!({"dimension":dimension,"label":label,"endpoint":endpoint,"first_at":first_at})).collect();
        let ip_rows: Vec<Value> = ips
            .into_iter()
            .map(|(ip, first_at)| json!({"ip":ip.to_string(),"first_at":first_at}))
            .collect();
        client.execute("INSERT INTO pg_temp.nm_analytics_endpoints SELECT * FROM jsonb_to_recordset($1::JSONB) AS x(dimension TEXT,label TEXT,endpoint TEXT,first_at TIMESTAMPTZ) \
            ON CONFLICT (dimension,label,endpoint) DO UPDATE SET first_at = LEAST(nm_analytics_endpoints.first_at, EXCLUDED.first_at)", &[&postgres_types::Json(json!(endpoint_rows))]).await.map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?;
        client.execute("INSERT INTO pg_temp.nm_analytics_ips SELECT * FROM jsonb_to_recordset($1::JSONB) AS x(ip INET,first_at TIMESTAMPTZ) \
            ON CONFLICT (ip) DO UPDATE SET first_at = LEAST(nm_analytics_ips.first_at, EXCLUDED.first_at)", &[&postgres_types::Json(json!(ip_rows))]).await.map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?;
        let size: i64 = client.query_one("SELECT pg_total_relation_size('pg_temp.nm_analytics_endpoints') + pg_total_relation_size('pg_temp.nm_analytics_ips')", &[]).await.map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?.get(0);
        if size > (max_staging_mib as i64) * 1024 * 1024 {
            return Err(format!(
                "statistics_resource_limit: 统计暂存空间超过 {max_staging_mib} MiB，请检查容量并调整限制"
            ));
        }
        let changed = client.execute("UPDATE analytics_outbox SET heartbeat_at = clock_timestamp(), updated_at = NOW() WHERE execution_id = $1 AND status = 'running' AND locked_at = $2", &[&context.database_id, &context.locked_at]).await.map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?;
        if changed == 0 {
            return Err("扫描统计任务已被重新排队，丢弃过期计算结果".into());
        }
        info!(
            event = "AnalyticsSnapshotProgress",
            execution_database_id = context.database_id,
            observed_count,
            staging_bytes = size
        );
        after = next;
        if hits.len() < READ_BATCH_SIZE {
            break;
        }
    }
    if observed_count < context.expected_observations {
        return Err(format!(
            "Elasticsearch 统计数据尚未完整可见：预期至少 {} 条观察，实际读取 {observed_count} 条",
            context.expected_observations
        ));
    }
    Ok(())
}

fn update_first<K: Ord>(values: &mut BTreeMap<K, DateTime<Utc>>, key: K, timestamp: DateTime<Utc>) {
    values
        .entry(key)
        .and_modify(|current| *current = (*current).min(timestamp))
        .or_insert(timestamp);
}

async fn publish_staged_facts(
    client: &mut deadpool_postgres::Client,
    context: &ExecutionContext,
) -> Result<(), String> {
    let tx = client
        .transaction()
        .await
        .map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?;
    tx.query_one(
        "SELECT singleton FROM analytics_snapshot_build FOR UPDATE",
        &[],
    )
    .await
    .map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?;
    if tx.query_opt("SELECT execution_id FROM analytics_outbox WHERE execution_id = $1 AND status = 'running' AND locked_at = $2 FOR UPDATE", &[&context.database_id,&context.locked_at]).await.map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?.is_none() {
        return Err("扫描统计任务已被重新排队，丢弃过期计算结果".into());
    }
    let legacy_count: i64 = tx.query_one("SELECT COUNT(*) FROM analytics_discovery_fact WHERE execution_id = $1 AND first_observed_at IS NULL", &[&context.database_id]).await.map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?.get(0);
    let new_count: i64 = tx
        .query_one("SELECT COUNT(*) FROM pg_temp.nm_analytics_ips", &[])
        .await
        .map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?
        .get(0);
    if legacy_count > new_count {
        return Err("原始观测不足以恢复旧统计的 UTC 时间，保留原有历史事实".into());
    }
    tx.execute(
        "DELETE FROM analytics_distribution_30m WHERE execution_id = $1",
        &[&context.database_id],
    )
    .await
    .map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?;
    tx.execute(
        "DELETE FROM analytics_discovery_fact WHERE execution_id = $1",
        &[&context.database_id],
    )
    .await
    .map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?;
    tx.execute("INSERT INTO analytics_distribution_30m (execution_id,owner_id,scanner_id,task_source,bucket_start,dimension,label,endpoint_count) \
        SELECT $1,$2,$3,$4,date_bin('30 minutes',first_at,TIMESTAMPTZ '1970-01-01 00:00:00+00'),dimension,label,COUNT(*) \
        FROM pg_temp.nm_analytics_endpoints GROUP BY 5,dimension,label", &[&context.database_id,&context.owner_id,&context.scanner_id,&context.task_source]).await.map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?;
    tx.execute("INSERT INTO analytics_discovery_fact (execution_id,owner_id,scanner_id,task_source,day_start,ip_address,first_observed_at) \
        SELECT $1,$2,$3,$4,(first_at AT TIME ZONE 'Asia/Shanghai')::date,ip,first_at FROM pg_temp.nm_analytics_ips", &[&context.database_id,&context.owner_id,&context.scanner_id,&context.task_source]).await.map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?;
    tx.execute("UPDATE analytics_outbox SET status = 'completed', completed_at = NOW(), locked_at = NULL, heartbeat_at = NULL, updated_at = NOW(), last_error = NULL WHERE execution_id = $1", &[&context.database_id]).await.map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?;
    tx.execute(
        "DELETE FROM analytics_snapshot_build_execution WHERE execution_id = $1",
        &[&context.database_id],
    )
    .await
    .map_err(|e| crate::logs::write::error_chain_diagnostics(&e))?;
    publish_build(&tx).await?;
    tx.commit()
        .await
        .map_err(|e| crate::logs::write::error_chain_diagnostics(&e))
}

#[cfg(test)]
async fn replace_execution_facts(
    pool: &Pool,
    context: &ExecutionContext,
    facts: ExecutionFacts,
) -> Result<(), String> {
    let mut connection = pool
        .get()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    let transaction = connection
        .transaction()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    // Serialize publication with cohort creation. Fence an expired/replaced claim
    // before touching facts, including when an upload requeues this execution.
    transaction
        .query_one(
            "SELECT singleton FROM analytics_snapshot_build FOR UPDATE;",
            &[],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    if transaction
        .query_opt(
            "SELECT execution_id FROM analytics_outbox \
         WHERE execution_id = $1 AND status = 'running' AND locked_at = $2 FOR UPDATE;",
            &[&context.database_id, &context.locked_at],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?
        .is_none()
    {
        return Err("扫描统计任务已被重新排队，丢弃过期计算结果".to_owned());
    }
    // Older scanners may have no observation counters. An empty/partial retained
    // source must not replace their existing legacy IP facts with an incomplete set.
    let legacy_count: i64 = transaction.query_one(
        "SELECT COUNT(*)::BIGINT AS count FROM analytics_discovery_fact WHERE execution_id = $1 AND first_observed_at IS NULL;",
        &[&context.database_id],
    ).await.map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?.get("count");
    if legacy_count > facts.discovery.len() as i64 {
        return Err("原始观测不足以恢复旧统计的 UTC 时间，保留原有历史事实".into());
    }
    transaction
        .execute(
            "DELETE FROM analytics_distribution_30m WHERE execution_id = $1;",
            &[&context.database_id],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    transaction
        .execute(
            "DELETE FROM analytics_discovery_fact WHERE execution_id = $1;",
            &[&context.database_id],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    let mut distribution = facts.distribution.into_iter();
    loop {
        let batch = distribution
            .by_ref()
            .take(WRITE_BATCH_SIZE)
            .map(|((bucket_start, dimension, label), endpoint_count)| {
                json!({
                    "bucket_start": bucket_start, "dimension": dimension,
                    "label": label, "endpoint_count": endpoint_count
                })
            })
            .collect::<Vec<_>>();
        if batch.is_empty() {
            break;
        }
        transaction.execute(
            "INSERT INTO analytics_distribution_30m \
             (execution_id, owner_id, scanner_id, task_source, bucket_start, dimension, label, endpoint_count) \
             SELECT $1, $2, $3, $4, x.bucket_start, x.dimension, x.label, x.endpoint_count \
             FROM jsonb_to_recordset($5::JSONB) AS x(bucket_start TIMESTAMPTZ, dimension TEXT, label TEXT, endpoint_count BIGINT);",
            &[&context.database_id, &context.owner_id, &context.scanner_id, &context.task_source,
              &postgres_types::Json(json!(batch))],
        ).await.map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    }
    let mut discovery = facts.discovery.into_iter();
    loop {
        let batch = discovery
            .by_ref()
            .take(WRITE_BATCH_SIZE)
            .map(
                |(first_observed_at, ip_address)| json!({"day_start": shanghai_day(first_observed_at), "first_observed_at": first_observed_at, "ip_address": ip_address}),
            )
            .collect::<Vec<_>>();
        if batch.is_empty() {
            break;
        }
        transaction
            .execute(
                "INSERT INTO analytics_discovery_fact \
             (execution_id, owner_id, scanner_id, task_source, day_start, ip_address, first_observed_at) \
             SELECT $1, $2, $3, $4, x.day_start, x.ip_address, x.first_observed_at \
             FROM jsonb_to_recordset($5::JSONB) AS x(day_start DATE, ip_address INET, first_observed_at TIMESTAMPTZ);",
                &[
                    &context.database_id,
                    &context.owner_id,
                    &context.scanner_id,
                    &context.task_source,
                    &postgres_types::Json(json!(batch)),
                ],
            )
            .await
            .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    }
    // Facts and task completion commit together: a failed write cannot strand a
    // running task or publish a watermark for uncommitted facts.
    transaction.execute(
        "UPDATE analytics_outbox SET status = 'completed', completed_at = NOW(), locked_at = NULL, \
         updated_at = NOW(), last_error = NULL WHERE execution_id = $1;",
        &[&context.database_id],
    ).await.map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    transaction
        .execute(
            "DELETE FROM analytics_snapshot_build_execution WHERE execution_id = $1;",
            &[&context.database_id],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    publish_build(&transaction).await?;
    transaction
        .commit()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    Ok(())
}

fn snapshot_retry_seconds(attempts: i32) -> i64 {
    (30_i64.saturating_mul(2_i64.saturating_pow(attempts.clamp(1, 7) as u32 - 1))).min(1800)
}

async fn fail_execution(
    pool: &Pool,
    context: &ExecutionContext,
    message: &str,
) -> Result<(), String> {
    let connection = pool
        .get()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    connection.execute(
        "UPDATE analytics_outbox SET status = 'pending', available_at = CASE WHEN $4::BOOL THEN 'infinity'::TIMESTAMPTZ ELSE NOW() + $5::BIGINT * INTERVAL '1 second' END, \
         locked_at = NULL, updated_at = NOW(), last_error = LEFT($2, 2000) \
         WHERE execution_id = $1 AND status = 'running' AND locked_at = $3;",
        &[&context.database_id, &message, &context.locked_at, &message.starts_with("statistics_resource_limit:"), &snapshot_retry_seconds(context.attempts)],
    ).await.map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    Ok(())
}

#[cfg(test)]
fn bucket_start(timestamp: DateTime<Utc>) -> DateTime<Utc> {
    timestamp
        .with_minute((timestamp.minute() / 30) * 30)
        .expect("valid minute")
        .with_second(0)
        .expect("valid second")
        .with_nanosecond(0)
        .expect("valid nanosecond")
}

#[cfg(test)]
fn shanghai_day(timestamp: DateTime<Utc>) -> NaiveDate {
    timestamp
        .with_timezone(&chrono_tz::Asia::Shanghai)
        .date_naive()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn aligns_buckets_to_half_hour_boundaries() {
        let timestamp = Utc.with_ymd_and_hms(2026, 9, 1, 10, 47, 12).unwrap();
        assert_eq!(
            bucket_start(timestamp),
            Utc.with_ymd_and_hms(2026, 9, 1, 10, 30, 0).unwrap()
        );
    }

    #[test]
    fn backlog_is_drained_without_waiting_for_reconciliation_interval() {
        assert_eq!(worker_delay(true), Duration::from_secs(1));
        assert_eq!(worker_delay(false), Duration::from_secs(5));
    }

    #[test]
    fn failed_work_backs_off_and_caps_retry_delay() {
        assert_eq!(reconcile_delay(1), Duration::from_secs(30));
        assert_eq!(reconcile_delay(2), Duration::from_secs(60));
        assert_eq!(reconcile_delay(u32::MAX), Duration::from_secs(1800));
        assert_eq!(snapshot_retry_seconds(0), 30);
        assert_eq!(snapshot_retry_seconds(3), 120);
        assert_eq!(snapshot_retry_seconds(i32::MAX), 1800);
    }

    /// Opt-in real Elasticsearch test: the named index must contain exactly 610512
    /// observations for execution `analytics-real-test`, with 210001 distinct IPs
    /// and endpoints, each having a `https` service. Uses only PG temporary tables.
    #[tokio::test]
    #[ignore = "requires disposable ANALYTICS_TEST_DATABASE_URL and a preloaded real ANALYTICS_REAL_ES_URL/INDEX"]
    async fn real_elasticsearch_large_execution() {
        let config: tokio_postgres::Config = std::env::var("ANALYTICS_TEST_DATABASE_URL")
            .unwrap()
            .parse()
            .unwrap();
        let pool = Pool::builder(deadpool_postgres::Manager::new(
            config,
            tokio_postgres::NoTls,
        ))
        .max_size(1)
        .build()
        .unwrap();
        let client = pool.get().await.unwrap();
        client.batch_execute("SET search_path TO pg_temp; \
            CREATE TEMP TABLE scan_task(id INT PRIMARY KEY, user_id INT, task_source TEXT, task_kind TEXT); \
            CREATE TEMP TABLE scan_task_execution(id INT PRIMARY KEY, execution_id TEXT, task_id INT, execution_status TEXT, assigned_scanner_id TEXT, requested_scanner_id TEXT, result_observation_count BIGINT); \
            CREATE TEMP TABLE scan_result_batch(execution_id INT, storage_backend TEXT, storage_references JSONB); \
            INSERT INTO scan_task VALUES (1, 1, 'manual', 'ip'); \
            INSERT INTO scan_task_execution VALUES (1, 'analytics-real-test', 1, 'succeeded', 'scanner', NULL, 610512);").await.unwrap();
        let schema = include_str!("../source/database/init.sql");
        let start = schema
            .find("CREATE TABLE IF NOT EXISTS analytics_outbox")
            .unwrap();
        let end = schema[start..].find("-- 表 session").unwrap() + start;
        client
            .batch_execute(&schema[start..end].replace(
                "CREATE TABLE IF NOT EXISTS",
                "CREATE TEMP TABLE IF NOT EXISTS",
            ))
            .await
            .unwrap();
        let index = std::env::var("ANALYTICS_REAL_ES_INDEX").unwrap();
        client
            .execute(
                "INSERT INTO scan_result_batch VALUES (1, 'elasticsearch', $1)",
                &[&postgres_types::Json(json!([index]))],
            )
            .await
            .unwrap();
        drop(client);
        reconcile(&pool).await.unwrap();
        let context = claim_execution(&pool).await.unwrap().unwrap();
        let service =
            crate::elasticsearch::ElasticsearchService::new(crate::config::ElasticsearchConfig {
                url: std::env::var("ANALYTICS_REAL_ES_URL").unwrap(),
                ..Default::default()
            })
            .unwrap();
        service.open_api_test_ready();
        process_staged_execution(
            &pool,
            &service,
            &context,
            &AnalyticsSnapshotConfig::default(),
        )
        .await
        .unwrap();
        let client = pool.get().await.unwrap();
        let row = client.query_one("SELECT (SELECT count(*) FROM analytics_discovery_fact), (SELECT sum(endpoint_count)::bigint FROM analytics_distribution_30m), (SELECT status FROM analytics_outbox WHERE execution_id = 1)", &[]).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), 210001);
        assert_eq!(row.get::<_, i64>(1), 420002);
        assert_eq!(row.get::<_, String>(2), "completed");
    }

    /// Uses only connection-local temporary tables, never application tables.
    #[tokio::test]
    #[ignore = "requires ANALYTICS_TEST_DATABASE_URL pointing at a disposable PostgreSQL instance"]
    async fn postgres_backfill_publication_retry_and_batch_writes() {
        let config: tokio_postgres::Config = std::env::var("ANALYTICS_TEST_DATABASE_URL")
            .expect("test database URL")
            .parse()
            .unwrap();
        let manager = deadpool_postgres::Manager::new(config, tokio_postgres::NoTls);
        let pool = Pool::builder(manager).max_size(1).build().unwrap();
        let client = pool.get().await.unwrap();
        client.batch_execute(
            "SET search_path TO pg_temp; \
             CREATE TEMP TABLE scan_task(id INT PRIMARY KEY, user_id INT, task_source TEXT, task_kind TEXT); \
             CREATE TEMP TABLE scan_task_execution(id INT PRIMARY KEY, execution_id TEXT, task_id INT, \
                 execution_status TEXT, assigned_scanner_id TEXT, requested_scanner_id TEXT, result_observation_count BIGINT); \
             CREATE TEMP TABLE scan_result_batch(execution_id INT, storage_backend TEXT, storage_references JSONB); \
             INSERT INTO scan_task VALUES (1, 1, 'manual', 'ip'); \
             INSERT INTO scan_task_execution VALUES (1, 'one', 1, 'succeeded', 'scanner', NULL, 0), \
                 (2, 'two', 1, 'succeeded', 'scanner', NULL, 0); \
             INSERT INTO scan_result_batch VALUES \
                 (1, 'elasticsearch', '[\"scan-observations-2026.08\", \"scan-observations-2026.09\"]'), \
                 (1, 'elasticsearch', '[\"scan-observations-2026.09\"]'), \
                 (1, 'postgres', '[\"ignored\"]');"
        ).await.unwrap();
        let schema = include_str!("../source/database/init.sql");
        let start = schema
            .find("CREATE TABLE IF NOT EXISTS analytics_outbox")
            .unwrap();
        let end = schema[start..].find("-- 表 session").unwrap() + start;
        client
            .batch_execute(&schema[start..end].replace(
                "CREATE TABLE IF NOT EXISTS",
                "CREATE TEMP TABLE IF NOT EXISTS",
            ))
            .await
            .unwrap();
        drop(client);

        reconcile(&pool).await.unwrap();
        let client = pool.get().await.unwrap();
        assert_eq!(snapshot_progress(&client).await.unwrap().remaining, 2);
        assert!(
            snapshot_progress(&client)
                .await
                .unwrap()
                .data_as_of
                .is_none()
        );
        // New arrivals must not grow the active backfill cohort.
        client.batch_execute("INSERT INTO scan_task_execution VALUES (3, 'three', 1, 'succeeded', 'scanner', NULL, 0);").await.unwrap();
        drop(client);
        reconcile(&pool).await.unwrap();
        let first = claim_execution(&pool).await.unwrap().unwrap();
        assert_eq!(first.database_id, 1);
        assert_eq!(
            first.observation_indices,
            [
                "scan-observations-2026.08".to_owned(),
                "scan-observations-2026.09".to_owned()
            ]
        );
        assert!(claim_execution(&pool).await.unwrap().is_none());
        let timestamp = Utc.with_ymd_and_hms(2026, 9, 1, 10, 30, 0).unwrap();
        let mut facts = ExecutionFacts::default();
        for i in 0..1005 {
            facts
                .distribution
                .insert((timestamp, "service".into(), format!("service-{i}")), 1);
            facts
                .discovery
                .insert((timestamp, IpAddr::V4(std::net::Ipv4Addr::from(i + 1))));
        }
        facts
            .discovery
            .insert((timestamp, "2001:db8::1".parse().unwrap()));
        replace_execution_facts(&pool, &first, facts).await.unwrap();
        let client = pool.get().await.unwrap();
        assert_eq!(
            client
                .query_one("SELECT COUNT(*) FROM analytics_distribution_30m", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            1005
        );
        assert_eq!(
            client
                .query_one("SELECT COUNT(*) FROM analytics_discovery_fact", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            1006
        );
        assert_eq!(snapshot_progress(&client).await.unwrap().remaining, 1);
        drop(client);

        let second = claim_execution(&pool).await.unwrap().unwrap();
        assert_eq!(second.database_id, 2);
        let mut invalid = ExecutionFacts::default();
        invalid
            .distribution
            .insert((timestamp, "service".into(), "invalid".into()), -1);
        let error = replace_execution_facts(&pool, &second, invalid)
            .await
            .unwrap_err();
        assert!(error.contains("23514")); // retain SQLSTATE and the actual constraint error
        fail_execution(&pool, &second, &error).await.unwrap();
        let client = pool.get().await.unwrap();
        let progress = snapshot_progress(&client).await.unwrap();
        assert_eq!(progress.retrying, 1);
        assert_eq!(progress.failed_execution_id, Some(2));
        assert!(progress.data_as_of.is_none());
        assert_eq!(
            client
                .query_one(
                    "SELECT COUNT(*) FROM analytics_distribution_30m WHERE execution_id = 2",
                    &[]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        client
            .execute(
                "UPDATE analytics_outbox SET available_at = NOW() WHERE execution_id = 2",
                &[],
            )
            .await
            .unwrap();
        drop(client);

        let retry = claim_execution(&pool).await.unwrap().unwrap();
        assert_ne!(retry.locked_at, second.locked_at);
        // A timed-out worker cannot overwrite a newer claim or reset its status.
        assert!(
            replace_execution_facts(&pool, &second, ExecutionFacts::default())
                .await
                .is_err()
        );
        fail_execution(&pool, &second, "stale error").await.unwrap();
        replace_execution_facts(&pool, &retry, ExecutionFacts::default())
            .await
            .unwrap();
        let client = pool.get().await.unwrap();
        let progress = snapshot_progress(&client).await.unwrap();
        assert!(progress.data_as_of.is_some());
        assert_eq!(progress.remaining, 0);
        assert_eq!(progress.pending, 1); // execution 3 never blocked publication
        assert_eq!(progress.retrying, 0);
        let published = progress.data_as_of;
        drop(client);
        reconcile(&pool).await.unwrap();
        let client = pool.get().await.unwrap();
        let progress = snapshot_progress(&client).await.unwrap();
        assert_eq!(progress.remaining, 1);
        assert_eq!(progress.data_as_of, published); // keep the published watermark during the next cohort
        // Empty installations must also become ready without processing a job.
        client.batch_execute("TRUNCATE analytics_snapshot_build_execution, analytics_snapshot_build, analytics_watermark, analytics_outbox, analytics_distribution_30m, analytics_discovery_fact, scan_task_execution CASCADE;").await.unwrap();
        drop(client);
        reconcile(&pool).await.unwrap();
        let client = pool.get().await.unwrap();
        assert!(
            snapshot_progress(&client)
                .await
                .unwrap()
                .data_as_of
                .is_some()
        );
        // Failed writes preserve old aggregates; the only fact reader is ES.
        client.batch_execute(
            "INSERT INTO scan_task_execution VALUES (4, 'four', 1, 'succeeded', 'scanner', NULL, 1); \
             INSERT INTO analytics_distribution_30m VALUES (4, '2026-09-01T10:30:00Z', 1, 'scanner', 'manual', 'service', 'old', 1); \
             ALTER TABLE analytics_distribution_30m ADD CONSTRAINT reject_test_write CHECK (label <> 'fail-write');"
        ).await.unwrap();
        drop(client);
        reconcile(&pool).await.unwrap();
        let context = claim_execution(&pool).await.unwrap().unwrap();
        let make_facts = || {
            let mut facts = ExecutionFacts::default();
            facts.distribution.insert(
                (
                    "2026-09-01T10:30:00Z".parse().unwrap(),
                    "service".into(),
                    "fail-write".into(),
                ),
                1,
            );
            facts
        };
        let error = replace_execution_facts(&pool, &context, make_facts())
            .await
            .unwrap_err();
        fail_execution(&pool, &context, &error).await.unwrap();
        let client = pool.get().await.unwrap();
        let progress = snapshot_progress(&client).await.unwrap();
        assert_eq!(progress.running, 0);
        assert_eq!(progress.retrying, 1);
        assert!(progress.last_error.unwrap().contains("reject_test_write"));
        assert!(progress.data_as_of.is_some());
        assert_eq!(
            client
                .query_one(
                    "SELECT label FROM analytics_distribution_30m WHERE execution_id = 4",
                    &[]
                )
                .await
                .unwrap()
                .get::<_, String>(0),
            "old"
        );
        client.batch_execute("ALTER TABLE analytics_distribution_30m DROP CONSTRAINT reject_test_write; UPDATE analytics_outbox SET available_at = NOW() WHERE execution_id = 4;").await.unwrap();
        drop(client);
        let context = claim_execution(&pool).await.unwrap().unwrap();
        replace_execution_facts(&pool, &context, make_facts())
            .await
            .unwrap();
        let client = pool.get().await.unwrap();
        assert_eq!(snapshot_progress(&client).await.unwrap().remaining, 0);

        // Publication handles more than the former 200,000-key in-memory limit.
        client.batch_execute("INSERT INTO scan_task_execution VALUES (5, 'five', 1, 'succeeded', 'scanner', NULL, 0);").await.unwrap();
        drop(client);
        reconcile(&pool).await.unwrap();
        let large = claim_execution(&pool).await.unwrap().unwrap();
        let mut client = pool.get().await.unwrap();
        client.batch_execute("CREATE TEMP TABLE nm_analytics_endpoints (dimension TEXT COLLATE \"C\", label TEXT COLLATE \"C\", endpoint TEXT COLLATE \"C\", first_at TIMESTAMPTZ, PRIMARY KEY(dimension,label,endpoint)); \
            CREATE TEMP TABLE nm_analytics_ips (ip INET PRIMARY KEY, first_at TIMESTAMPTZ); \
            INSERT INTO nm_analytics_endpoints SELECT 'port','443','endpoint-' || n,'2026-09-01T10:47:00Z'::timestamptz FROM generate_series(1,210001) n; \
            INSERT INTO nm_analytics_ips VALUES ('192.0.2.1','2026-09-01T16:30:00Z'),('2001:db8::1','2026-09-01T10:47:00Z');").await.unwrap();
        let mut stale = large.clone();
        stale.locked_at -= chrono::Duration::seconds(1);
        assert!(publish_staged_facts(&mut client, &stale).await.is_err());
        client.batch_execute("INSERT INTO analytics_distribution_30m VALUES (5, '2026-09-01T10:30:00Z', 1, 'scanner', 'manual', 'port', 'old', 1); ALTER TABLE analytics_distribution_30m ADD CONSTRAINT reject_staged_test CHECK (label <> '443');").await.unwrap();
        assert!(publish_staged_facts(&mut client, &large).await.is_err());
        assert_eq!(
            client
                .query_one(
                    "SELECT label FROM analytics_distribution_30m WHERE execution_id = 5",
                    &[]
                )
                .await
                .unwrap()
                .get::<_, String>(0),
            "old"
        );
        assert_eq!(
            client
                .query_one(
                    "SELECT status FROM analytics_outbox WHERE execution_id = 5",
                    &[]
                )
                .await
                .unwrap()
                .get::<_, String>(0),
            "running"
        );
        client
            .batch_execute(
                "ALTER TABLE analytics_distribution_30m DROP CONSTRAINT reject_staged_test",
            )
            .await
            .unwrap();
        publish_staged_facts(&mut client, &large).await.unwrap();
        let row = client.query_one("SELECT endpoint_count, bucket_start FROM analytics_distribution_30m WHERE execution_id = 5", &[]).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), 210001);
        assert_eq!(row.get::<_, DateTime<Utc>>(1), timestamp);
        let days = client.query("SELECT day_start::TEXT FROM analytics_discovery_fact WHERE execution_id = 5 ORDER BY day_start", &[]).await.unwrap();
        assert_eq!(
            days.iter()
                .map(|row| row.get::<_, String>(0))
                .collect::<Vec<_>>(),
            ["2026-09-01", "2026-09-02"]
        );
        client.batch_execute("DROP TABLE nm_analytics_endpoints, nm_analytics_ips; INSERT INTO scan_task_execution VALUES (6, 'six', 1, 'succeeded', 'scanner', NULL, 5001); INSERT INTO scan_result_batch VALUES (6, 'elasticsearch', '[\"network-mapping-scan-observations-v1-2026.09\"]');").await.unwrap();
        drop(client);
        reconcile(&pool).await.unwrap();
        let mut context = claim_execution(&pool).await.unwrap().unwrap();
        assert_eq!(context.database_id, 6);
        let fixture = crate::elasticsearch::storage_tests::EsFixture::start();
        let service = fixture.service();
        service.open_api_test_ready();
        {
            let mut state = fixture.state.lock().unwrap();
            state.rotate_pit_ids = true;
            for n in 0..5001 {
                let ip = format!("192.0.2.{}", n % 100 + 1);
                let document = json!({"execution_id":"six", "kind":"service", "service":" HTTPS ", "ip_address":ip, "port":443, "endpoint_id":format!("endpoint-{}", n % 100), "observed_at": 1_788_266_400_000_i64 - n as i64});
                state.documents.insert(
                    (
                        "network-mapping-scan-observations-v1-2026.09".to_owned(),
                        format!("{n:05}"),
                    ),
                    document,
                );
            }
        }
        context.expected_observations = 5002;
        assert!(
            process_staged_execution(
                &pool,
                &service,
                &context,
                &AnalyticsSnapshotConfig::default()
            )
            .await
            .unwrap_err()
            .contains("尚未完整可见")
        );
        let client = pool.get().await.unwrap();
        assert_eq!(
            client
                .query_one(
                    "SELECT count(*) FROM analytics_distribution_30m WHERE execution_id = 6",
                    &[]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        drop(client);
        context.expected_observations = 5001;
        process_staged_execution(
            &pool,
            &service,
            &context,
            &AnalyticsSnapshotConfig::default(),
        )
        .await
        .unwrap();
        let client = pool.get().await.unwrap();
        let row = client.query_one("SELECT sum(endpoint_count)::bigint FROM analytics_distribution_30m WHERE execution_id = 6", &[]).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), 200);
        assert_eq!(
            client
                .query_one(
                    "SELECT count(*) FROM analytics_discovery_fact WHERE execution_id = 6",
                    &[]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            100
        );
        assert_eq!(
            client
                .query_one(
                    "SELECT status FROM analytics_outbox WHERE execution_id = 6",
                    &[]
                )
                .await
                .unwrap()
                .get::<_, String>(0),
            "completed"
        );
        let first: DateTime<Utc> = client.query_one("SELECT first_observed_at FROM analytics_discovery_fact WHERE execution_id = 6 AND ip_address = '192.0.2.1'::inet", &[]).await.unwrap().get(0);
        assert_eq!(first.timestamp_millis(), 1_788_266_400_000_i64 - 5000);
        let state = fixture.state.lock().unwrap();
        assert_eq!(state.closed_pit_ids, ["pit-3", "pit-6"]);
    }
}
