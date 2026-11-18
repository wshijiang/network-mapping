//! 数据管理 · 后台导出：按搜索语句匹配本地资产索引，后台写 CSV，Web 下载。
//!
//! 任务模型与 `data_import` 一致（PostgreSQL 台账 + 租约认领 + 进程内 worker），
//! 但导出是只读短任务，状态机简化为 pending/running/completed/error/cancelled。

pub mod cli;
pub mod csv;
pub mod fields;
pub mod task;
pub mod worker;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct DataExportConfig {
    pub enabled: bool,
    /// CSV 存放目录（相对路径相对配置文件目录解析）。
    pub directory: PathBuf,
    /// 单任务「全部」导出行数上限（创建时按预览 count 校验，worker 兜底）。
    pub max_rows: u64,
    /// Elasticsearch 每批拉取行数（PIT + search_after）。
    pub batch_size: u32,
    pub lease_seconds: u64,
    /// 终态任务文件与记录保留天数。
    pub retention_days: u32,
}

impl Default for DataExportConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            directory: PathBuf::from("./data-export"),
            max_rows: 1_000_000,
            batch_size: 2000,
            lease_seconds: 120,
            retention_days: 30,
        }
    }
}

impl DataExportConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_rows == 0 {
            return Err("data_export.max_rows 必须大于 0".into());
        }
        if self.batch_size == 0 || self.batch_size > 10_000 {
            return Err("data_export.batch_size 须在 1..=10000".into());
        }
        if self.lease_seconds < 10 {
            return Err("data_export.lease_seconds 不能小于 10".into());
        }
        if self.retention_days == 0 {
            return Err("data_export.retention_days 必须大于 0".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        DataExportConfig::default().validate().unwrap();
    }

    #[test]
    fn rejects_invalid_limits() {
        assert!(
            DataExportConfig {
                max_rows: 0,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            DataExportConfig {
                batch_size: 10_001,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            DataExportConfig {
                lease_seconds: 5,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
}
