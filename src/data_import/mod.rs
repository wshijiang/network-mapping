//! 数据管理 · 外部导入（CSV 资产端点导入）。
//!
//! Web 与服务器 CLI 共用同一任务模型：任务持久化于 PostgreSQL，
//! 由服务器进程内的 [`worker`] 唯一执行，经现有 `result_ingest` 管道写入 ES。
//! 设计见工作区 `DATA_IMPORT_PLAN.md` 与 `docs/DATA_IMPORT.md`。

pub mod cli;
pub mod csv;
pub mod ingest;
pub mod schema;
pub mod task;
pub mod worker;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// 预留系统扫描器身份（导入观察以其名义写入）。与 migrate_data_import.sql 保持一致。
pub const IMPORT_SCANNER_ID: &str = "00000000-0000-7000-8000-00000000d1a0";
pub const IMPORT_SCANNER_NAME: &str = "数据导入";
pub const IMPORT_SCANNER_REMARK: &str = "__system_data_import__";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct DataImportConfig {
    pub enabled: bool,
    pub directory: PathBuf,
    pub max_upload_bytes: u64,
    pub max_rows: u64,
    pub default_batch_size: u32,
    pub max_batch_size: u32,
    pub default_concurrency: u32,
    pub max_concurrency: u32,
    pub retention_days: u32,
    pub lease_seconds: u64,
    pub observed_at_future_tolerance_seconds: u64,
    pub dedup_window: usize,
}

impl Default for DataImportConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            directory: PathBuf::from("./data-import"),
            max_upload_bytes: 512 * 1024 * 1024,
            max_rows: 10_000_000,
            default_batch_size: 1000,
            max_batch_size: 50000,
            default_concurrency: 2,
            max_concurrency: 8,
            retention_days: 30,
            lease_seconds: 120,
            observed_at_future_tolerance_seconds: 300,
            dedup_window: 1_000_000,
        }
    }
}

impl DataImportConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_upload_bytes == 0 {
            return Err("data_import.max_upload_bytes 必须大于 0".into());
        }
        if self.max_rows == 0 {
            return Err("data_import.max_rows 必须大于 0".into());
        }
        if self.default_batch_size == 0 || self.default_batch_size > self.max_batch_size {
            return Err("data_import.default_batch_size 须在 1..=max_batch_size".into());
        }
        if self.max_batch_size > 50000 {
            return Err("data_import.max_batch_size 不能超过 50000".into());
        }
        if self.default_concurrency == 0 || self.default_concurrency > self.max_concurrency {
            return Err("data_import.default_concurrency 须在 1..=max_concurrency".into());
        }
        if self.max_concurrency > 8 {
            return Err("data_import.max_concurrency 不能超过 8".into());
        }
        if self.lease_seconds < 10 {
            return Err("data_import.lease_seconds 不能小于 10".into());
        }
        Ok(())
    }

    pub fn schema_limits(&self) -> schema::SchemaLimits {
        schema::SchemaLimits {
            max_upload_bytes: self.max_upload_bytes,
            max_rows: self.max_rows,
            default_batch_size: self.default_batch_size,
            max_batch_size: self.max_batch_size,
            default_concurrency: self.default_concurrency,
            max_concurrency: self.max_concurrency,
        }
    }
}
