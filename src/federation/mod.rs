//! 数据管理 · 联测（多源网络空间测绘联合查询）。
//!
//! 用户搜索时按策略向 Hunter/Quake/FOFA/Shodan 发起查询，结果与本地资产
//! 聚合去重后返回，并按策略经现有 `result_ingest` 管道入库（task_source='federation'）。
//! Web 与服务器 CLI 共用同一数据源/策略/run 模型；run 由服务器进程内唯一执行。
//! 设计见工作区 `FEDERATION_PLAN.md` 与 `docs/FEDERATION.md`。

pub mod adapters;
pub mod cli;
pub mod executor;
pub mod ingest;
pub mod model;
pub mod policy;
pub mod search;
pub mod storage;
pub mod translate;
pub mod worker;

use serde::{Deserialize, Serialize};

/// 预留系统扫描器身份（联测观察以其名义写入）。与 migrate_federation.sql 保持一致。
pub const FEDERATION_SCANNER_ID: &str = "00000000-0000-7000-8000-00000000fed0";
pub const FEDERATION_SCANNER_NAME: &str = "联测";
pub const FEDERATION_SCANNER_REMARK: &str = "__system_federation__";

/// 部署级配置（`[federation]`）。运行时策略见 [`policy::FederationPolicy`]。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationConfig {
    pub enabled: bool,
    pub worker_poll_seconds: u64,
    pub run_retention_days: u32,
    pub lease_seconds: u64,
    pub observed_at_future_tolerance_seconds: u64,
    pub quota_refresh_hours: u64,
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            worker_poll_seconds: 2,
            run_retention_days: 30,
            lease_seconds: 120,
            observed_at_future_tolerance_seconds: 300,
            quota_refresh_hours: 6,
        }
    }
}

impl FederationConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.worker_poll_seconds == 0 {
            return Err("federation.worker_poll_seconds 必须大于 0".into());
        }
        if self.lease_seconds < 10 {
            return Err("federation.lease_seconds 不能小于 10".into());
        }
        if self.quota_refresh_hours == 0 {
            return Err("federation.quota_refresh_hours 必须大于 0".into());
        }
        Ok(())
    }
}
