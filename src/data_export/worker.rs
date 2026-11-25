//! 导出 worker：认领任务 → 按搜索语句查询本地资产索引 → 流式写 CSV。
//!
//! 与 data_import worker 相同的租约/维护模式；导出只读、幂等，租约过期从头重跑。

use std::path::Path;

use actix_web::web;
use deadpool_postgres::Pool;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant, interval, sleep};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::elasticsearch::{ElasticsearchService, SearchSort};
use crate::runtime_config::RuntimeConfig;
use crate::system_maintenance::SystemMaintenanceState;
use crate::system_time::GeneralSettings;

use super::DataExportConfig;
use super::csv::CsvWriter;
use super::fields::{self, FormatCtx};
use super::settings::{self, Plan};
use super::storage::{Object, Storage};
use super::task::{self, Result, Task};

pub async fn run_worker(
    pool: Pool,
    config: DataExportConfig,
    elasticsearch: web::Data<ElasticsearchService>,
    maintenance: web::Data<SystemMaintenanceState>,
    general: RuntimeConfig<GeneralSettings>,
    storage: web::Data<Storage>,
) {
    if !config.enabled {
        info!(event = "DataExportWorkerDisabled", "数据导出 worker 未启用");
        return;
    }
    info!(event = "DataExportWorkerStarted", "数据导出 worker 已启动");
    let mut running = JoinSet::new();
    let mut poll = interval(Duration::from_secs(2));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = poll.tick() => {}
            finished = running.join_next(), if !running.is_empty() => {
                if let Some(Err(error)) = finished {
                    warn!(event = "DataExportWorkerFailed", %error);
                }
            }
        }
        if maintenance.snapshot().await.blocks_new_work() {
            continue;
        }
        let limit = match settings::read(&pool, &config).await {
            Ok(current) => current.value.workers,
            Err(error) => {
                warn!(event = "DataExportSettingsReadFailed", %error);
                continue;
            }
        };
        while running.len() < limit {
            let attempt = Uuid::new_v4();
            let lease_ms = config.lease_seconds as i64 * 1000;
            match task::claim_next(&pool, attempt, lease_ms).await {
                Ok(Some(task)) => {
                    let pool = pool.clone();
                    let config = config.clone();
                    let elasticsearch = elasticsearch.clone();
                    let storage = storage.clone();
                    let timezone = general.get().await.value.timezone;
                    running.spawn(async move {
                        let (lost, mut cancel) = watch::channel(false);
                        let lease = async {
                            loop {
                                sleep(Duration::from_millis((lease_ms as u64 / 6).min(5_000))).await;
                                match task::renew_lease(&pool, task.id, attempt, lease_ms).await {
                                    Ok(true) => {}
                                    Ok(false) => break,
                                    Err(error) => warn!(event = "DataExportRenewLeaseFailed", task_id = %task.id, %error),
                                }
                            }
                            let _ = lost.send(true);
                            std::future::pending::<()>().await;
                        };
                        let result = tokio::select! {
                            result = execute_task(&pool, &config, &task, attempt, &elasticsearch, &timezone, &storage, &mut cancel) => result,
                            () = lease => unreachable!("lease heartbeat never completes"),
                        };
                        if let Err(error) = result {
                            warn!(event = "DataExportTaskFailed", task_id = %task.id, %error, "导出任务失败");
                            let _ = task::set_error(&pool, task.id, attempt, &error.to_string()).await;
                        }
                        if let Err(error) = task::release_lease(&pool, task.id, attempt).await {
                            warn!(event = "DataExportReleaseLeaseFailed", task_id = %task.id, %error);
                        }
                    });
                }
                Ok(None) => break,
                Err(error) => {
                    error!(event = "DataExportClaimFailed", %error, "认领导出任务失败");
                    break;
                }
            }
        }
    }
}

pub async fn run_cleanup(pool: Pool, retention_days: u32, storage: web::Data<Storage>) {
    loop {
        if let Err(error) = task::purge_expired(&pool, retention_days).await {
            warn!(event = "DataExportPurgeFailed", %error);
        }
        for _ in 0..100 {
            match task::claim_cleanup(&pool).await {
                Ok(Some(entry)) => {
                    let local = match entry.local_path {
                        Some(path) => remove_local(Path::new(&path)).await,
                        None => false,
                    };
                    let s3 = if let Some(document) = entry.s3_object {
                        let result = match serde_json::from_value::<Object>(document) {
                            Ok(object) => {
                                match tokio::time::timeout(
                                    Duration::from_secs(30),
                                    storage.delete(&object, entry.multipart_upload_id.as_deref()),
                                )
                                .await
                                {
                                    Ok(result) => result,
                                    Err(error) => Err(error.into()),
                                }
                            }
                            Err(error) => Err(error.into()),
                        };
                        if let Err(error) = &result {
                            warn!(event = "DataExportObjectCleanupFailed", attempt = %entry.id, %error);
                        }
                        result.is_ok()
                    } else {
                        false
                    };
                    if let Err(error) = task::finish_cleanup(&pool, entry.id, local, s3).await {
                        warn!(event = "DataExportFinishCleanupFailed", attempt = %entry.id, %error);
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    warn!(event = "DataExportClaimCleanupFailed", %error);
                    break;
                }
            }
        }
        sleep(Duration::from_secs(60)).await;
    }
}

async fn remove_local(path: &Path) -> bool {
    match tokio::fs::remove_file(path).await {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => {
            warn!(event = "DataExportLocalCleanupFailed", %error);
            false
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_task(
    pool: &Pool,
    config: &DataExportConfig,
    task: &Task,
    attempt: Uuid,
    elasticsearch: &ElasticsearchService,
    timezone: &str,
    storage: &Storage,
    cancel: &mut watch::Receiver<bool>,
) -> Result<()> {
    let started = Instant::now();
    let plan = match task.storage_plan.clone() {
        Some(document) => serde_json::from_value::<Plan>(document)?,
        None => Plan {
            revision: 0,
            local: true,
            s3: None,
            batch_size: config.batch_size,
            upload_concurrency: 1,
        },
    };
    let keys: Vec<String> = serde_json::from_value(task.fields.clone())
        .map_err(|error| format!("导出字段列表解析失败：{error}"))?;
    let fields = fields::resolve_keys(&keys)?;
    let ctx = FormatCtx::new(timezone);
    let sort = SearchSort::parse(Some(&task.sort_field), Some(&task.sort_order))?;
    let mut es_took_ms = 0;
    let filter = elasticsearch
        .resolve_search_filter(
            &task.scope_type,
            task.scope_id,
            task.filter.clone(),
            &mut es_took_ms,
        )
        .await?;
    tokio::fs::create_dir_all(&config.directory).await?;
    let path = config.directory.join(format!("{}-{attempt}.csv", task.id));
    let object = plan
        .s3
        .map(|target| storage.task_object(target, task.id, attempt))
        .transpose()?;
    let locator = object.as_ref().map(serde_json::to_value).transpose()?;
    let file_path = path.to_str().ok_or("导出目录不是有效的 UTF-8 路径")?;
    if !task::register_attempt(pool, task.id, attempt, file_path, locator.as_ref()).await? {
        return Ok(());
    }
    let Some(csv) = run_export(
        pool,
        config,
        task,
        attempt,
        elasticsearch,
        &filter,
        sort,
        &fields,
        &ctx,
        &path,
        plan.batch_size,
        cancel,
    )
    .await?
    else {
        return Ok(());
    };
    info!(event = "DataExportCsvReady", task_id = %task.id, rows = csv.rows, bytes = csv.size, elapsed_ms = started.elapsed().as_millis() as u64, query_ms = csv.query_ms, batch_size = plan.batch_size);
    let mut s3_failed = false;
    if let Some(object) = &object {
        if !task::renew_lease(pool, task.id, attempt, config.lease_seconds as i64 * 1000).await? {
            return Ok(());
        }
        let upload_started = Instant::now();
        let upload = storage
            .upload(
                pool,
                attempt,
                object,
                &path,
                csv.size as u64,
                plan.upload_concurrency,
                cancel,
            )
            .await;
        if *cancel.borrow() {
            return Ok(());
        }
        if let Err(error) = upload {
            warn!(event = "DataExportS3UploadFailed", task_id = %task.id, %error);
            if !plan.local {
                return Err("S3 上传失败，请检查服务器日志并重试导出".into());
            }
            s3_failed = true;
        } else {
            info!(event = "DataExportS3Uploaded", task_id = %task.id, bytes = csv.size, elapsed_ms = upload_started.elapsed().as_millis() as u64);
        }
    }
    let completed = task::complete(
        pool,
        task.id,
        attempt,
        plan.local.then_some(file_path),
        if s3_failed { None } else { locator.as_ref() },
        s3_failed,
        csv.size,
        &csv.sha256,
        csv.rows,
        csv.total,
    )
    .await?;
    if completed {
        info!(event = "DataExportCompleted", task_id = %task.id, elapsed_ms = started.elapsed().as_millis() as u64);
        if !plan.local && remove_local(&path).await {
            task::finish_cleanup(pool, attempt, true, false).await?;
        }
    }
    Ok(())
}

struct CsvResult {
    size: i64,
    sha256: String,
    rows: i64,
    total: Option<i64>,
    query_ms: u64,
}

#[allow(clippy::too_many_arguments)]
async fn run_export(
    pool: &Pool,
    config: &DataExportConfig,
    task: &Task,
    attempt: Uuid,
    elasticsearch: &ElasticsearchService,
    filter: &serde_json::Value,
    sort: SearchSort,
    fields: &[&fields::FieldDef],
    ctx: &FormatCtx,
    path: &Path,
    batch_size: u32,
    cancel: &watch::Receiver<bool>,
) -> Result<Option<CsvResult>> {
    let mut writer = CsvWriter::create(path, fields).await?;
    let mut exported: i64 = 0;
    let matched_total;
    let mut query_ms = 0;
    if task.scope == "page" {
        let offset = task.page_offset.unwrap_or(0);
        let limit = task.page_limit.unwrap_or(50);
        let query_started = Instant::now();
        let page = elasticsearch
            .search_with_scope(
                &task.scope_type,
                task.scope_id,
                filter.clone(),
                limit,
                offset,
                sort,
                true,
            )
            .await?;
        query_ms += query_started.elapsed().as_millis() as u64;
        matched_total = Some(page.total);
        for item in &page.items {
            writer.write_row(item, fields, ctx).await?;
            exported += 1;
        }
    } else {
        let mut pit_id = elasticsearch.open_search_pit().await?;
        let result: Result<Option<i64>> = async {
            let mut search_after: Option<serde_json::Value> = None;
            let mut total: Option<i64> = None;
            loop {
                if *cancel.borrow() {
                    return Ok(None);
                }
                let query_started = Instant::now();
                let (items, batch_total, next, refreshed_pit) = elasticsearch
                    .search_export_page(
                        &pit_id,
                        &task.scope_type,
                        task.scope_id,
                        filter,
                        sort,
                        search_after.as_ref(),
                        i64::from(batch_size),
                        total.is_none(),
                    )
                    .await?;
                query_ms += query_started.elapsed().as_millis() as u64;
                pit_id = refreshed_pit;
                if total.is_none() {
                    if batch_total > config.max_rows as i64 {
                        return Err(format!(
                            "匹配 {batch_total} 条，超过单任务导出上限 {} 条，请缩小查询范围",
                            config.max_rows
                        )
                        .into());
                    }
                    total = Some(batch_total);
                }
                for item in &items {
                    writer.write_row(item, fields, ctx).await?;
                    exported += 1;
                }
                task::checkpoint(pool, task.id, attempt, exported, total).await?;
                let exhausted = items.len() < batch_size as usize || next.is_none();
                search_after = next;
                if exhausted || exported >= config.max_rows as i64 {
                    break;
                }
            }
            Ok(total)
        }
        .await;
        elasticsearch.close_search_pit(&pit_id).await;
        matched_total = result?;
        if matched_total.is_none() {
            return Ok(None);
        }
    }
    if *cancel.borrow() {
        return Ok(None);
    }
    let (size, sha256) = writer.finish().await?;
    Ok(Some(CsvResult {
        size,
        sha256,
        rows: exported,
        total: matched_total,
        query_ms,
    }))
}
