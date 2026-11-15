//! 导入执行 worker（服务器进程内唯一执行者）。
//!
//! 阶段：validating → type_checking → importing（fast 模式合并校验进 importing）。
//! 写入经 [`crate::data_import::ingest`] 复用扫描器结果管道；批次台账保证崩溃/暂停续传幂等。

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use actix_web::web;
use deadpool_postgres::Pool;
use futures_util::stream::{FuturesUnordered, StreamExt};
use serde_json::{Value, json};
use tokio::sync::Semaphore;
use tokio::time::{Duration, sleep};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::data_import::DataImportConfig;
use crate::data_import::csv::{self, DedupOutcome, DedupWindow, ImportRow, ParseOptions};
use crate::data_import::ingest::{self, ES_BATCH_MAX, ScanLink};
use crate::data_import::task::{self, Progress, Task};
use crate::dns_follow_up::DnsFollowUpConfig;
use crate::elasticsearch::ElasticsearchService;
use crate::maxmind::MaxMindState;
use crate::runtime_config::RuntimeConfig;
use crate::system_maintenance::SystemMaintenanceState;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const ERROR_SAMPLE_CAP: usize = 1000;

#[derive(Clone, Default)]
struct Stats {
    processed: i64,
    imported: i64,
    invalid: i64,
    duplicate: i64,
    conflict: i64,
}

struct Batch {
    index: i32,
    row_start: i64,
    row_end: i64,
    rows: Vec<ImportRow>,
}

struct Services {
    maxmind: web::Data<MaxMindState>,
    elasticsearch: web::Data<ElasticsearchService>,
    dns_follow_up: DnsFollowUpConfig,
    token: String,
    pepper: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn run_worker(
    pool: Pool,
    config: DataImportConfig,
    maxmind: web::Data<MaxMindState>,
    elasticsearch: web::Data<ElasticsearchService>,
    dns_follow_up: web::Data<RuntimeConfig<DnsFollowUpConfig>>,
    maintenance: web::Data<SystemMaintenanceState>,
    encrypt_key: String,
    pepper: String,
) {
    if !config.enabled {
        info!(event = "DataImportWorkerDisabled", "数据导入 worker 未启用");
        return;
    }
    let worker_id = Uuid::new_v4();
    let lease_ms = config.lease_seconds as i64 * 1000;
    let mut token = match ingest::ensure_import_scanner(&pool, &encrypt_key, &pepper).await {
        Ok(token) => token,
        Err(error) => {
            error!(event = "DataImportScannerProvisionFailed", %error, "预留导入扫描器初始化失败");
            return;
        }
    };
    info!(event = "DataImportWorkerStarted", %worker_id, "数据导入 worker 已启动");
    let mut tick: u64 = 0;
    loop {
        tick += 1;
        if tick.is_multiple_of(600) {
            if let Ok(paths) = task::purge_expired(&pool, config.retention_days).await {
                for path in paths {
                    let _ = tokio::fs::remove_file(&path).await;
                }
            }
            if let Ok(refreshed) = ingest::ensure_import_scanner(&pool, &encrypt_key, &pepper).await
            {
                token = refreshed;
            }
        }
        if maintenance.snapshot().await.blocks_new_work() {
            sleep(Duration::from_secs(5)).await;
            continue;
        }
        match task::claim_next(&pool, worker_id, lease_ms).await {
            Ok(Some(task)) => {
                let dns = dns_follow_up.get().await.value.clone();
                let services = Services {
                    maxmind: maxmind.clone(),
                    elasticsearch: elasticsearch.clone(),
                    dns_follow_up: dns,
                    token: token.clone(),
                    pepper: pepper.clone(),
                };
                if let Err(error) =
                    execute_task(&pool, &config, &task, worker_id, lease_ms, &services).await
                {
                    warn!(event = "DataImportTaskFailed", task_id = %task.id, %error, "导入任务失败");
                    let _ = task::set_error(&pool, task.id, &error.to_string()).await;
                }
                let _ = task::release_lease(&pool, task.id, worker_id).await;
            }
            Ok(None) => sleep(Duration::from_secs(2)).await,
            Err(error) => {
                error!(event = "DataImportClaimFailed", %error, "认领导入任务失败");
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

async fn should_stop(pool: &Pool, id: Uuid) -> Result<bool> {
    Ok(matches!(
        task::get_task(pool, id).await?.map(|t| t.status),
        Some(status) if status == task::STATUS_PAUSED || status == task::STATUS_CANCELLED
    ))
}

fn open_reader(path: &Path) -> Result<::csv::Reader<std::fs::File>> {
    Ok(::csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_path(path)?)
}

#[allow(clippy::too_many_arguments)]
async fn execute_task(
    pool: &Pool,
    config: &DataImportConfig,
    task: &Task,
    worker_id: Uuid,
    lease_ms: i64,
    services: &Services,
) -> Result<()> {
    let link = ingest::ensure_scan_task(pool, task).await?;
    task::link_scan_task(
        pool,
        task.id,
        link.scan_task_db_id,
        link.execution_db_id,
        link.upload_id,
    )
    .await?;

    let mapping: BTreeMap<String, String> = serde_json::from_value(task.header_mapping.clone())?;
    let file_headers: Vec<String> = serde_json::from_value(task.file_headers.clone())?;
    let colmap = csv::build_column_map(&file_headers, &mapping)?;
    let opts = ParseOptions {
        now_ms: chrono::Utc::now().timestamp_millis(),
        future_tolerance_ms: config.observed_at_future_tolerance_seconds as i64 * 1000,
        max_banner_bytes: 64 * 1024,
    };
    let path = Path::new(&task.storage_path);
    let mut samples: Vec<Value> = Vec::new();

    // ---- 阶段 A：完整性校验（计数 + 结构） ----
    if !task.fast_mode {
        let mut total: i64 = 0;
        let mut reader = open_reader(path)?;
        let mut record = ::csv::StringRecord::new();
        while reader.read_record(&mut record)? {
            total += 1;
            if total > config.max_rows as i64 {
                return Err(format!("行数超过上限 {}", config.max_rows).into());
            }
            if record.len() != file_headers.len() {
                return Err(format!("第 {total} 行列数与头部不一致").into());
            }
        }
        task::checkpoint(
            pool,
            task.id,
            task::STATUS_VALIDATING,
            Progress {
                total_rows: Some(total),
                ..Default::default()
            },
            None,
        )
        .await?;
        if should_stop(pool, task.id).await? {
            return Ok(());
        }

        // ---- 阶段 B：类型检查 ----
        let mut invalid: i64 = 0;
        let mut reader = open_reader(path)?;
        let mut record = ::csv::StringRecord::new();
        let mut row_number: i64 = 0;
        while reader.read_record(&mut record)? {
            row_number += 1;
            if let Err(errors) = csv::parse_record(&record, row_number, &colmap, &opts) {
                invalid += 1;
                for error in errors.into_iter().take(4) {
                    if samples.len() < ERROR_SAMPLE_CAP {
                        samples.push(serde_json::to_value(error)?);
                    }
                }
                if task.on_invalid == "abort" {
                    task::checkpoint(
                        pool,
                        task.id,
                        task::STATUS_TYPE_CHECKING,
                        Progress {
                            total_rows: Some(total),
                            invalid_rows: invalid,
                            ..Default::default()
                        },
                        Some(&json!(samples)),
                    )
                    .await?;
                    return Err("类型检查发现无效行（on_invalid=abort）".into());
                }
            }
        }
        task::checkpoint(
            pool,
            task.id,
            task::STATUS_TYPE_CHECKING,
            Progress {
                total_rows: Some(total),
                invalid_rows: invalid,
                ..Default::default()
            },
            Some(&json!(samples)),
        )
        .await?;
        if should_stop(pool, task.id).await? {
            return Ok(());
        }
    }

    // ---- 阶段 C：导入（或试运行统计） ----
    let (mut next_batch_index, mut committed_rows) = task::resume_cursor(pool, task.id).await?;
    replay_pending(
        pool,
        task,
        &link,
        &colmap,
        &opts,
        services,
        &mut next_batch_index,
        &mut committed_rows,
    )
    .await?;

    let mut stats = Stats {
        processed: task.processed_rows,
        imported: task.imported_rows,
        invalid: task.invalid_rows,
        duplicate: task.duplicate_rows,
        conflict: task.conflict_rows,
    };
    let effective_batch = (task.batch_size as usize).clamp(1, ES_BATCH_MAX);
    let concurrency = (task.concurrency as usize).max(1);
    let mut dedup = DedupWindow::new(config.dedup_window);

    let mut reader = open_reader(path)?;
    let mut record = ::csv::StringRecord::new();
    let mut raw_count: i64 = 0;
    let mut batch: Vec<ImportRow> = Vec::new();
    let mut batch_start = committed_rows;
    let mut wave: Vec<Batch> = Vec::new();

    while reader.read_record(&mut record)? {
        raw_count += 1;
        if raw_count > config.max_rows as i64 {
            return Err(format!("行数超过上限 {}", config.max_rows).into());
        }
        if raw_count <= committed_rows {
            continue;
        }
        stats.processed += 1;
        let row = match csv::parse_record(&record, raw_count, &colmap, &opts) {
            Ok(row) => row,
            Err(errors) => {
                stats.invalid += 1;
                for error in errors.into_iter().take(4) {
                    if samples.len() < ERROR_SAMPLE_CAP {
                        samples.push(serde_json::to_value(error)?);
                    }
                }
                if task.on_invalid == "abort" {
                    return Err(format!("第 {raw_count} 行无效（on_invalid=abort）").into());
                }
                continue;
            }
        };
        match dedup.observe(&row) {
            DedupOutcome::Duplicate => {
                stats.duplicate += 1;
                continue;
            }
            DedupOutcome::Conflict => stats.conflict += 1,
            DedupOutcome::New => {}
        }
        if task.dry_run {
            stats.imported += 1;
            continue;
        }
        batch.push(row);
        if batch.len() >= effective_batch {
            wave.push(Batch {
                index: next_batch_index,
                row_start: batch_start,
                row_end: raw_count,
                rows: std::mem::take(&mut batch),
            });
            next_batch_index += 1;
            batch_start = raw_count;
            if wave.len() >= concurrency {
                write_wave(
                    pool,
                    task,
                    &link,
                    services,
                    std::mem::take(&mut wave),
                    false,
                    &mut stats,
                )
                .await?;
                committed_rows = raw_count;
                checkpoint_importing(
                    pool,
                    task,
                    worker_id,
                    lease_ms,
                    &stats,
                    committed_rows,
                    next_batch_index,
                    &samples,
                )
                .await?;
                if should_stop(pool, task.id).await? {
                    return Ok(());
                }
            }
        }
    }
    if !batch.is_empty() {
        wave.push(Batch {
            index: next_batch_index,
            row_start: batch_start,
            row_end: raw_count,
            rows: batch,
        });
        next_batch_index += 1;
    }
    if !wave.is_empty() {
        write_wave(
            pool,
            task,
            &link,
            services,
            std::mem::take(&mut wave),
            false,
            &mut stats,
        )
        .await?;
        committed_rows = raw_count;
    }
    if !task.dry_run {
        let final_batch = Batch {
            index: next_batch_index,
            row_start: raw_count,
            row_end: raw_count,
            rows: Vec::new(),
        };
        next_batch_index += 1;
        write_wave(
            pool,
            task,
            &link,
            services,
            vec![final_batch],
            true,
            &mut stats,
        )
        .await?;
    }

    let total_rows = if task.fast_mode {
        Some(raw_count.max(committed_rows))
    } else {
        task.total_rows
    };
    task::checkpoint(
        pool,
        task.id,
        task::STATUS_COMPLETED,
        Progress {
            total_rows,
            processed_rows: stats.processed,
            imported_rows: stats.imported,
            invalid_rows: stats.invalid,
            duplicate_rows: stats.duplicate,
            conflict_rows: stats.conflict,
            committed_rows,
            next_batch_index,
        },
        Some(&json!(samples)),
    )
    .await?;
    info!(event = "DataImportTaskCompleted", task_id = %task.id, imported = stats.imported, invalid = stats.invalid, "导入任务完成");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn checkpoint_importing(
    pool: &Pool,
    task: &Task,
    worker_id: Uuid,
    lease_ms: i64,
    stats: &Stats,
    committed_rows: i64,
    next_batch_index: i32,
    samples: &[Value],
) -> Result<()> {
    task::renew_lease(pool, task.id, worker_id, lease_ms).await?;
    task::checkpoint(
        pool,
        task.id,
        task::STATUS_IMPORTING,
        Progress {
            total_rows: task.total_rows,
            processed_rows: stats.processed,
            imported_rows: stats.imported,
            invalid_rows: stats.invalid,
            duplicate_rows: stats.duplicate,
            conflict_rows: stats.conflict,
            committed_rows,
            next_batch_index,
        },
        Some(&json!(samples)),
    )
    .await?;
    Ok(())
}

/// 续传重放：从连续已提交前缀之后，按台账原行区间与 batch_index 重放所有未提交批次，
/// 并跳过其间已（乱序）提交的批次，保证最终批次序列连续、校验和稳定。
#[allow(clippy::too_many_arguments)]
async fn replay_pending(
    pool: &Pool,
    task: &Task,
    link: &ScanLink,
    colmap: &csv::ColumnMap,
    opts: &ParseOptions,
    services: &Services,
    next_batch_index: &mut i32,
    committed_rows: &mut i64,
) -> Result<()> {
    let tail = task::ledger_batches(pool, task.id).await?;
    for (index, row_start, row_end, status) in tail {
        if index < *next_batch_index {
            continue;
        }
        if status == "pending" {
            let mut reader = open_reader(Path::new(&task.storage_path))?;
            let mut record = ::csv::StringRecord::new();
            let mut raw_count: i64 = 0;
            let mut rows = Vec::new();
            while reader.read_record(&mut record)? {
                raw_count += 1;
                if raw_count <= row_start {
                    continue;
                }
                if raw_count > row_end {
                    break;
                }
                if let Ok(row) = csv::parse_record(&record, raw_count, colmap, opts) {
                    rows.push(row);
                }
            }
            let observations: Vec<_> = rows
                .iter()
                .map(|row| ingest::build_observation(row, &task.overwrite_policy))
                .collect();
            let count = observations.len() as i32;
            ingest::write_es_batch(
                pool,
                &services.maxmind,
                &services.elasticsearch,
                &services.dns_follow_up,
                link,
                index,
                false,
                observations,
                &services.token,
                &services.pepper,
            )
            .await
            .map_err(|e| format!("重放批次 {index} 失败：{e}"))?;
            task::commit_batch(pool, task.id, index, count, "").await?;
        }
        *next_batch_index = (*next_batch_index).max(index + 1);
        *committed_rows = (*committed_rows).max(row_end);
    }
    Ok(())
}

/// 并发写入一个 wave 的批次（均非 final，或单个 final 批次）。
async fn write_wave(
    pool: &Pool,
    task: &Task,
    link: &ScanLink,
    services: &Services,
    batches: Vec<Batch>,
    is_final: bool,
    stats: &mut Stats,
) -> Result<()> {
    for batch in &batches {
        task::begin_batch(pool, task.id, batch.index, batch.row_start, batch.row_end).await?;
    }
    let semaphore = Arc::new(Semaphore::new((task.concurrency as usize).max(1)));
    let mut futures = FuturesUnordered::new();
    for batch in batches {
        let observations: Vec<_> = batch
            .rows
            .iter()
            .map(|row| ingest::build_observation(row, &task.overwrite_policy))
            .collect();
        let count = observations.len() as i32;
        let pool = pool.clone();
        let maxmind = services.maxmind.clone();
        let elasticsearch = services.elasticsearch.clone();
        let dns = services.dns_follow_up.clone();
        let link = link.clone();
        let token = services.token.clone();
        let pepper = services.pepper.clone();
        let permit = semaphore.clone().acquire_owned().await?;
        let index = batch.index;
        futures.push(async move {
            let _permit = permit;
            let result = ingest::write_es_batch(
                &pool,
                &maxmind,
                &elasticsearch,
                &dns,
                &link,
                index,
                is_final,
                observations,
                &token,
                &pepper,
            )
            .await;
            (index, count, result)
        });
    }
    while let Some((index, count, result)) = futures.next().await {
        result.map_err(|e| format!("批次 {index} 写入失败：{e}"))?;
        task::commit_batch(pool, task.id, index, count, "").await?;
        stats.imported += count as i64;
    }
    Ok(())
}
