//! 联测运行时策略（`runtime_configuration` namespace `federation`）。
//!
//! 与数据源配置（`federation_source` 表）分离：策略管触发/模式/时间窗/入库，
//! 数据源管凭据/代理/字段/分页。Web 与 CLI 读写同一行，乐观并发。

use serde::{Deserialize, Serialize};

pub const NAMESPACE: &str = "federation";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FederationMode {
    /// 本地结果立即返回，联测后台继续并入库。
    #[default]
    Async,
    /// 等待联测（总超时兜底）后合并返回。
    Blocking,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationTrigger {
    /// 每次搜索都触发。
    Always,
    /// 仅本地无结果或结果过期时触发（省额度，默认）。
    #[default]
    EmptyOrStale,
}

/// 入库条件（§10）。enabled 为总开关；三个条件开关对应触发时的本地状态。
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct PersistPolicy {
    pub enabled: bool,
    /// 本地无结果时入库（"没有数据则入库"）。
    pub on_empty: bool,
    /// 本地结果过期时入库（"过期数据入库"，用联测新数据刷新）。
    pub on_stale: bool,
    /// 本地仍新鲜时（trigger=always）也入库。
    pub on_fresh: bool,
}

impl Default for PersistPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            on_empty: true,
            on_stale: true,
            on_fresh: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationPolicy {
    pub enabled: bool,
    pub mode: FederationMode,
    pub trigger: FederationTrigger,
    /// 本地结果过期阈值（天）：匹配端点最新 last_seen 距今超过该天数视为过期。
    pub stale_days: u32,
    /// 远端查询时间窗全局默认（天），供 window_mode=follow 的数据源使用。
    pub query_window_days: u32,
    /// 查询涉及这些字段才触发；空 = 任意字段。合法值见 [`crate::federation::model::FIELD_NAMES`]。
    pub trigger_fields: Vec<String>,
    pub blocking_timeout_seconds: u64,
    pub persist: PersistPolicy,
    /// 同 query_hash 冷却窗口（秒）：窗口内复用最近 run 的结果缓存。
    pub cooldown_seconds: u64,
    pub max_records_per_run: u32,
    pub max_concurrent_runs: u32,
}

impl Default for FederationPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: FederationMode::Async,
            trigger: FederationTrigger::EmptyOrStale,
            stale_days: 60,
            query_window_days: 30,
            trigger_fields: Vec::new(),
            blocking_timeout_seconds: 30,
            persist: PersistPolicy::default(),
            cooldown_seconds: 300,
            max_records_per_run: 500,
            max_concurrent_runs: 4,
        }
    }
}

impl FederationPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=3650).contains(&self.stale_days) {
            return Err("stale_days 须在 1..=3650".into());
        }
        if !(1..=60).contains(&self.query_window_days) {
            return Err("query_window_days 须在 1..=60".into());
        }
        if !(5..=120).contains(&self.blocking_timeout_seconds) {
            return Err("blocking_timeout_seconds 须在 5..=120".into());
        }
        if self.cooldown_seconds > 86400 {
            return Err("cooldown_seconds 不能超过 86400".into());
        }
        if !(10..=5000).contains(&self.max_records_per_run) {
            return Err("max_records_per_run 须在 10..=5000".into());
        }
        if !(1..=16).contains(&self.max_concurrent_runs) {
            return Err("max_concurrent_runs 须在 1..=16".into());
        }
        for field in &self.trigger_fields {
            if !crate::federation::model::FIELD_NAMES.contains(&field.as_str()) {
                return Err(format!("trigger_fields 含非法字段 {field}"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_are_cost_optimal_and_valid() {
        let policy = FederationPolicy::default();
        assert!(policy.validate().is_ok());
        assert_eq!(policy.query_window_days, 30);
        assert_eq!(policy.stale_days, 60);
        assert_eq!(policy.mode, FederationMode::Async);
        assert_eq!(policy.trigger, FederationTrigger::EmptyOrStale);
        assert!(policy.persist.on_empty && policy.persist.on_stale && !policy.persist.on_fresh);
    }

    #[test]
    fn rejects_out_of_range_documents() {
        let base = FederationPolicy::default();
        assert!(
            FederationPolicy {
                query_window_days: 61,
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            FederationPolicy {
                query_window_days: 0,
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            FederationPolicy {
                stale_days: 0,
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            FederationPolicy {
                trigger_fields: vec!["not_a_field".into()],
                ..base
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn deserializes_partial_documents_with_defaults() {
        let policy: FederationPolicy =
            serde_json::from_value(json!({"mode": "blocking", "stale_days": 90})).unwrap();
        assert_eq!(policy.mode, FederationMode::Blocking);
        assert_eq!(policy.stale_days, 90);
        assert_eq!(policy.query_window_days, 30);
        assert!(policy.validate().is_ok());
    }
}
