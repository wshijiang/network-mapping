//! Syslog 转发运行时配置文档（`runtime_configuration` 命名空间 `syslog`）。
//!
//! 仅适配现代 syslog 产品：RFC 5424 消息 + RFC 6587 octet-counting 帧（TCP/TLS）。

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const NAMESPACE: &str = "syslog";
pub const MAX_TARGETS: usize = 10;

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Udp,
    Tcp,
    Tls,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Udp | Self::Tcp => 514,
            Self::Tls => 6514,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Facility {
    Kern,
    User,
    Mail,
    Daemon,
    Auth,
    Syslog,
    Lpr,
    News,
    Uucp,
    Cron,
    Authpriv,
    Ftp,
    #[default]
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
}

impl Facility {
    pub fn code(self) -> u8 {
        match self {
            Self::Kern => 0,
            Self::User => 1,
            Self::Mail => 2,
            Self::Daemon => 3,
            Self::Auth => 4,
            Self::Syslog => 5,
            Self::Lpr => 6,
            Self::News => 7,
            Self::Uucp => 8,
            Self::Cron => 9,
            Self::Authpriv => 10,
            Self::Ftp => 11,
            Self::Local0 => 16,
            Self::Local1 => 17,
            Self::Local2 => 18,
            Self::Local3 => 19,
            Self::Local4 => 20,
            Self::Local5 => 21,
            Self::Local6 => 22,
            Self::Local7 => 23,
        }
    }
}

/// 系统运行日志的最低转发级别；审计/访问/扫描器诊断事件不受该级别限制。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum MinLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
}

impl MinLevel {
    pub fn as_tracing(self) -> tracing::Level {
        match self {
            Self::Error => tracing::Level::ERROR,
            Self::Warn => tracing::Level::WARN,
            Self::Info => tracing::Level::INFO,
            Self::Debug => tracing::Level::DEBUG,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct TlsOptions {
    /// 自定义 CA 证书文件（PEM 或 DER）；为空时使用系统根证书。
    pub ca_file: String,
    /// 默认强制校验证书与主机名。
    pub verify: bool,
    /// 覆盖 TLS SNI/校验使用的主机名；为空时使用 host。
    pub server_name: String,
}

impl Default for TlsOptions {
    fn default() -> Self {
        Self {
            ca_file: String::new(),
            verify: true,
            server_name: String::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct TargetConfig {
    pub id: Uuid,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
    pub enabled: bool,
    pub tls: TlsOptions,
    /// 发往该目标的日志类型；默认全部。
    #[serde(default = "default_sources")]
    pub sources: Vec<crate::syslog::metrics::Source>,
}

pub fn default_sources() -> Vec<crate::syslog::metrics::Source> {
    crate::syslog::metrics::Source::ALL.to_vec()
}

impl Default for TargetConfig {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            name: String::new(),
            host: String::new(),
            port: Protocol::Udp.default_port(),
            protocol: Protocol::Udp,
            enabled: true,
            tls: TlsOptions::default(),
            sources: default_sources(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct FailureRateRule {
    pub enabled: bool,
    pub warning_percent: f64,
    pub critical_percent: f64,
    /// 窗口内最小样本数（sent+failed），低于该值不触发，避免低流量误报。
    pub min_samples: i64,
}

impl Default for FailureRateRule {
    fn default() -> Self {
        Self {
            enabled: true,
            warning_percent: 5.0,
            critical_percent: 20.0,
            min_samples: 20,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct LatencyRule {
    pub enabled: bool,
    pub warning_ms: f64,
    pub critical_ms: f64,
}

impl LatencyRule {
    fn new(warning_ms: f64, critical_ms: f64) -> Self {
        Self {
            enabled: false,
            warning_ms,
            critical_ms,
        }
    }
}

impl Default for LatencyRule {
    fn default() -> Self {
        Self::new(1000.0, 5000.0)
    }
}

/// 通知策略：整体失败率 / 发送耗时 P95 / P99 三条独立规则。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct AlertsConfig {
    pub window_minutes: i64,
    pub cooldown_seconds: i64,
    pub failure_rate: FailureRateRule,
    pub latency_p95: LatencyRule,
    pub latency_p99: LatencyRule,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            window_minutes: 5,
            cooldown_seconds: 1800,
            failure_rate: FailureRateRule::default(),
            latency_p95: LatencyRule::new(1000.0, 5000.0),
            latency_p99: LatencyRule::new(2000.0, 10000.0),
        }
    }
}

impl AlertsConfig {
    pub fn any_enabled(&self) -> bool {
        self.failure_rate.enabled || self.latency_p95.enabled || self.latency_p99.enabled
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct SyslogConfig {
    pub enabled: bool,
    pub facility: Facility,
    pub app_name: String,
    pub min_level: MinLevel,
    pub forward_audit_events: bool,
    pub forward_access_logs: bool,
    pub forward_scanner_diagnostics: bool,
    pub queue_capacity: usize,
    pub metrics_retention_days: i32,
    pub targets: Vec<TargetConfig>,
    pub alerts: AlertsConfig,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            facility: Facility::Local0,
            app_name: "network-mapping".to_owned(),
            min_level: MinLevel::Info,
            forward_audit_events: true,
            forward_access_logs: true,
            forward_scanner_diagnostics: true,
            queue_capacity: 8192,
            metrics_retention_days: 30,
            targets: Vec::new(),
            alerts: AlertsConfig::default(),
        }
    }
}

impl SyslogConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.app_name.is_empty()
            || self.app_name.len() > 48
            || !self
                .app_name
                .bytes()
                .all(|b| b.is_ascii_graphic() && b != b' ')
        {
            return Err("应用名必须为 1～48 个不含空格的可见 ASCII 字符".into());
        }
        if !(1024..=100_000).contains(&self.queue_capacity) {
            return Err("队列容量必须为 1024～100000".into());
        }
        if !(1..=365).contains(&self.metrics_retention_days) {
            return Err("指标保留天数必须为 1～365".into());
        }
        if self.targets.len() > MAX_TARGETS {
            return Err(format!("最多配置 {MAX_TARGETS} 个 syslog 服务器"));
        }
        let mut names = std::collections::HashSet::new();
        let mut endpoints = std::collections::HashSet::new();
        let mut ids = std::collections::HashSet::new();
        for target in &self.targets {
            validate_target(target)?;
            if !names.insert(target.name.to_lowercase()) {
                return Err(format!("服务器名称重复：{}", target.name));
            }
            if !endpoints.insert((target.host.to_lowercase(), target.port, target.protocol)) {
                return Err(format!(
                    "服务器地址重复：{}:{} ({})",
                    target.host,
                    target.port,
                    target.protocol.as_str()
                ));
            }
            if !ids.insert(target.id) {
                return Err("服务器 ID 重复".into());
            }
        }
        self.alerts.validate()?;
        Ok(())
    }

    pub fn find_target(&self, id_or_name: &str) -> Option<&TargetConfig> {
        if let Ok(id) = Uuid::parse_str(id_or_name)
            && let Some(target) = self.targets.iter().find(|t| t.id == id)
        {
            return Some(target);
        }
        self.targets
            .iter()
            .find(|t| t.name.eq_ignore_ascii_case(id_or_name))
    }
}

pub fn validate_target(target: &TargetConfig) -> Result<(), String> {
    if target.id.is_nil() {
        return Err("服务器 ID 无效".into());
    }
    if target.name.trim().is_empty()
        || target.name.chars().count() > 64
        || target.name.chars().any(char::is_control)
    {
        return Err("服务器名称必须为 1～64 个非控制字符".into());
    }
    if !valid_host(&target.host) {
        return Err(format!("服务器地址无效：{}", target.host));
    }
    if target.port == 0 {
        return Err("端口必须为 1～65535".into());
    }
    if target.tls.ca_file.chars().count() > 512 || target.tls.server_name.chars().count() > 253 {
        return Err("TLS 选项长度超出限制".into());
    }
    if !target.tls.server_name.is_empty() && !valid_host(&target.tls.server_name) {
        return Err("TLS 服务器名无效".into());
    }
    if target.sources.is_empty() {
        return Err("至少选择一种日志类型".into());
    }
    let mut seen_sources = std::collections::HashSet::new();
    for source in &target.sources {
        if !seen_sources.insert(*source) {
            return Err("日志类型重复".into());
        }
    }
    Ok(())
}

pub fn valid_host(host: &str) -> bool {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

impl AlertsConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=60).contains(&self.window_minutes) {
            return Err("告警统计窗口必须为 1～60 分钟".into());
        }
        if !(60..=604_800).contains(&self.cooldown_seconds) {
            return Err("告警冷却时间必须为 60～604800 秒".into());
        }
        let rate = &self.failure_rate;
        if !(0.0..=100.0).contains(&rate.warning_percent)
            || rate.warning_percent <= 0.0
            || !(0.0..=100.0).contains(&rate.critical_percent)
            || rate.critical_percent < rate.warning_percent
        {
            return Err("失败率阈值必须满足 0 < 警告 ≤ 严重 ≤ 100".into());
        }
        if !(1..=100_000).contains(&rate.min_samples) {
            return Err("最小样本数必须为 1～100000".into());
        }
        for (label, rule) in [("P95", &self.latency_p95), ("P99", &self.latency_p99)] {
            if rule.warning_ms <= 0.0
                || rule.critical_ms < rule.warning_ms
                || rule.critical_ms > 3_600_000.0
            {
                return Err(format!(
                    "{label} 耗时阈值必须满足 0 < 警告 ≤ 严重 ≤ 3600000 毫秒"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(name: &str, host: &str, port: u16, protocol: Protocol) -> TargetConfig {
        TargetConfig {
            id: Uuid::now_v7(),
            name: name.to_owned(),
            host: host.to_owned(),
            port,
            protocol,
            ..Default::default()
        }
    }

    #[test]
    fn default_document_is_valid_and_disabled() {
        let config = SyslogConfig::default();
        assert!(config.validate().is_ok());
        assert!(!config.enabled);
        assert!(config.forward_scanner_diagnostics);
        assert_eq!(config.min_level, MinLevel::Info);
    }

    #[test]
    fn rejects_duplicate_endpoints_and_names() {
        let mut config = SyslogConfig {
            targets: vec![
                target("a", "10.0.0.1", 514, Protocol::Udp),
                target("b", "10.0.0.1", 514, Protocol::Udp),
            ],
            ..Default::default()
        };
        assert!(config.validate().is_err());
        config.targets[1].name = "a".into();
        config.targets[1].port = 515;
        assert!(config.validate().is_err());
        config.targets[1].name = "b".into();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_invalid_hosts_ports_and_names() {
        let mut config = SyslogConfig {
            targets: vec![target("a", "bad host", 514, Protocol::Udp)],
            ..Default::default()
        };
        assert!(config.validate().is_err());
        config.targets[0].host = "siem.example.com".into();
        config.targets[0].port = 0;
        assert!(config.validate().is_err());
        config.targets[0].port = 6514;
        config.targets[0].name = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_more_than_ten_targets() {
        let config = SyslogConfig {
            targets: (0..11)
                .map(|i| target(&format!("t{i}"), &format!("10.0.0.{i}"), 514, Protocol::Udp))
                .collect(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn alert_rules_validate_threshold_ordering() {
        let mut alerts = AlertsConfig::default();
        assert!(alerts.validate().is_ok());
        alerts.failure_rate.critical_percent = 1.0;
        assert!(alerts.validate().is_err());
        alerts.failure_rate = FailureRateRule::default();
        alerts.latency_p95.warning_ms = 0.0;
        assert!(alerts.validate().is_err());
        alerts.latency_p95 = LatencyRule::default();
        alerts.window_minutes = 0;
        assert!(alerts.validate().is_err());
    }

    #[test]
    fn finds_target_by_id_or_name() {
        let mut config = SyslogConfig::default();
        let item = target("主 SIEM", "10.0.0.1", 514, Protocol::Tcp);
        let id = item.id.to_string();
        config.targets = vec![item];
        assert!(config.find_target(&id).is_some());
        assert!(config.find_target("主 siem").is_some());
        assert!(config.find_target("missing").is_none());
    }

    #[test]
    fn targets_default_to_all_sources_and_require_at_least_one() {
        let mut item = target("a", "10.0.0.1", 514, Protocol::Udp);
        assert_eq!(item.sources, crate::syslog::metrics::Source::ALL.to_vec());
        assert!(validate_target(&item).is_ok());
        item.sources = vec![crate::syslog::metrics::Source::Audit];
        assert!(validate_target(&item).is_ok());
        item.sources.clear();
        assert!(validate_target(&item).is_err());
        item.sources = vec![
            crate::syslog::metrics::Source::Audit,
            crate::syslog::metrics::Source::Audit,
        ];
        assert!(validate_target(&item).is_err());
    }

    #[test]
    fn legacy_target_document_without_sources_deserializes_to_all() {
        let value = serde_json::json!({
            "id": Uuid::now_v7(),
            "name": "legacy",
            "host": "10.0.0.1",
            "port": 514,
            "protocol": "udp",
            "enabled": true,
            "tls": { "caFile": "", "verify": true, "serverName": "" }
        });
        let item: TargetConfig = serde_json::from_value(value).unwrap();
        assert_eq!(item.sources, crate::syslog::metrics::Source::ALL.to_vec());
    }
}
