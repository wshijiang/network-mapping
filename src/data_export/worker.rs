//! 导出 worker：认领任务 → 按搜索语句查询本地资产索引 → 流式写 CSV。
//!
//! 与 data_import worker 相同的租约/维护模式；导出只读、幂等，租约过期从头重跑。

use std::path::Path;

use actix_web::web;
use deadpool_postgres::Pool;
use tokio::time::{Duration, sleep};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::elasticsearch::{ElasticsearchService, SearchSort};
use crate::runtime_config::RuntimeConfig;
use crate::system_maintenance::SystemMaintenanceState;
use crate::system_time::GeneralSettings;

use super::DataExportConfig;
use super::csv::CsvWriter;
use super::fields::{self, FormatCtx};
use super::task::{self, Task};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub async fn run_worker(
    pool: Pool,
    config: DataExportConfig,
    elasticsearch: web::Data<ElasticsearchService>,
    maintenance: web::Data<SystemMaintenanceState>,
    general: RuntimeConfig<GeneralSettings>,
) {
    if !config.enabled {
        info!(event = "DataExportWorkerDisabled", "数据导出 worker 未启用");
        return;
    }
    let worker_id = Uuid::new_v4();
    let lease_ms = config.lease_seconds as i64 * 1000;
    info!(event = "DataExportWorkerStarted", %worker_id, "数据导出 worker 已启动");
    let mut tick: u64 = 0;
    loop {
        tick += 1;
        if tick.is_multiple_of(600)
            && let Ok(paths) = task::purge_expired(&pool, config.retention_days).await
        {
            for path in paths {
                let _ = tokio::fs::remove_file(&path).await;
            }
        }
        if maintenance.snapshot().await.blocks_new_work() {
            sleep(Duration::from_secs(5)).await;
            continue;
        }
        match task::claim_next(&pool, worker_id, lease_ms).await {
            Ok(Some(task)) => {
                let timezone = general.get().await.value.timezone;
                if let Err(error) = execute_task(
                    &pool,
                    &config,
                    &task,
                    worker_id,
                    lease_ms,
                    &elasticsearch,
                    &timezone,
                )
                .await
                {
                    warn!(event = "DataExportTaskFailed", task_id = %task.id, %error, "导出任务失败");
                    let _ = task::set_error(&pool, task.id, &error.to_string()).await;
                }
                let _ = task::release_lease(&pool, task.id, worker_id).await;
            }
            Ok(None) => sleep(Duration::from_secs(2)).await,
            Err(error) => {
                error!(event = "DataExportClaimFailed", %error, "认领导出任务失败");
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

async fn should_stop(pool: &Pool, id: Uuid) -> Result<bool> {
    Ok(matches!(
        task::get_task(pool, id).await?.map(|t| t.status),
        Some(status) if status != task::STATUS_RUNNING
    ))
}

async fn execute_task(
    pool: &Pool,
    config: &DataExportConfig,
    task: &Task,
    worker_id: Uuid,
    lease_ms: i64,
    elasticsearch: &ElasticsearchService,
    timezone: &str,
) -> Result<()> {
    let keys: Vec<String> = serde_json::from_value(task.fields.clone())
        .map_err(|error| format!("导出字段列表解析失败：{error}"))?;
    let fields = fields::resolve_keys(&keys)?;
    let ctx = FormatCtx::new(timezone);
    let sort = SearchSort::parse(Some(&task.sort_field), Some(&task.sort_order))?;
    let filter = elasticsearch
        .resolve_search_filter(&task.scope_type, task.scope_id, task.filter.clone())
        .await?;
    tokio::fs::create_dir_all(&config.directory).await?;
    let path = config.directory.join(format!("{}.csv", task.id));
    let result = run_export(
        pool,
        config,
        task,
        worker_id,
        lease_ms,
        elasticsearch,
        &filter,
        sort,
        &fields,
        &ctx,
        &path,
    )
    .await;
    if result.is_err() {
        // 失败不留半成品文件。
        let _ = tokio::fs::remove_file(&path).await;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn run_export(
    pool: &Pool,
    config: &DataExportConfig,
    task: &Task,
    worker_id: Uuid,
    lease_ms: i64,
    elasticsearch: &ElasticsearchService,
    filter: &serde_json::Value,
    sort: SearchSort,
    fields: &[&fields::FieldDef],
    ctx: &FormatCtx,
    path: &Path,
) -> Result<()> {
    let mut writer = CsvWriter::create(path, fields).await?;
    let mut exported: i64 = 0;
    let matched_total;
    if task.scope == "page" {
        let offset = task.page_offset.unwrap_or(0);
        let limit = task.page_limit.unwrap_or(50);
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
                if should_stop(pool, task.id).await? {
                    return Ok(None);
                }
                let (items, batch_total, next, refreshed_pit) = elasticsearch
                    .search_export_page(
                        &pit_id,
                        &task.scope_type,
                        task.scope_id,
                        filter,
                        sort,
                        search_after.as_ref(),
                        i64::from(config.batch_size),
                        total.is_none(),
                    )
                    .await?;
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
                task::checkpoint(pool, task.id, exported, total).await?;
                if !task::renew_lease(pool, task.id, worker_id, lease_ms).await? {
                    return Err("导出租约已失效（任务可能被重新认领）".into());
                }
                let exhausted = items.len() < config.batch_size as usize || next.is_none();
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
            // 批间被取消：清理文件，任务状态已是 cancelled。
            let _ = tokio::fs::remove_file(path).await;
            return Ok(());
        }
    }
    let (file_size, sha256) = writer.finish().await?;
    let completed = task::complete(
        pool,
        task.id,
        worker_id,
        &path.to_string_lossy(),
        file_size,
        &sha256,
        exported,
        matched_total,
    )
    .await?;
    if !completed {
        // 完成登记前被取消：不保留文件。
        let _ = tokio::fs::remove_file(path).await;
    }
    Ok(())
}
