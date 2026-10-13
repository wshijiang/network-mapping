///web系统配置文件
use actix_web::web;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use postgres_from_row::FromRow;
use serde::{Deserialize, Serialize};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
};
use tracing::info;

use crate::{identity::decrypt_data, identity::encrypt_data};

pub trait SelfChecking {
    /// 该方法会直接 **Panic**
    fn check(&self);

    /// 该方法返回一个 Result 避免 Panic，
    ///
    /// Ok(true) 表示检验成功（符合预期）
    fn try_check(&self) -> Result<bool, Box<dyn std::error::Error>>;
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub report_renderer: crate::reports::service::ReportRendererConfig,
    #[serde(default)]
    pub scanner_diagnostics: crate::scanner_diagnostics::DiagnosticsConfig,
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub log: LogConfig,
    pub templates: TemplatesConfig,
    #[serde(default)]
    pub frontend: FrontendConfig,
    #[serde(default)]
    pub maxmind: MaxMindConfig,
    #[serde(default)]
    pub automatic_target: AutomaticTargetConfig,
    #[serde(default)]
    pub dns_follow_up: crate::dns_follow_up::DnsFollowUpConfig,
    #[serde(default)]
    pub requests: RequestsConfig,
    #[serde(default)]
    pub monitor: MonitorConfig,
    #[serde(default)]
    pub backup: BackupConfig,
    #[serde(default)]
    pub elasticsearch: ElasticsearchConfig,
    #[serde(default)]
    pub analytics_snapshot: AnalyticsSnapshotConfig,
    #[serde(default)]
    pub report_mail: crate::reports::mail_config::ReportMailConfig,
    pub database: DatabaseConfig,
    pub pwd_hash: PasswordHashConfig,
    pub security: SecurityConfig,
    pub email_config: Option<EmailConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    pub certificate_chain_file: PathBuf,
    pub private_key_file: PathBuf,
}

impl TlsConfig {
    fn resolve_relative_to(&mut self, config_path: &Path) {
        let base_directory = config_path.parent().unwrap_or_else(|| Path::new(""));

        if self.certificate_chain_file.is_relative() {
            self.certificate_chain_file = base_directory.join(&self.certificate_chain_file);
        }
        if self.private_key_file.is_relative() {
            self.private_key_file = base_directory.join(&self.private_key_file);
        }
    }
}

impl SelfChecking for Config {
    fn check(&self) {
        self.scanner_diagnostics
            .validate()
            .expect("invalid scanner diagnostics configuration");
        let _ = &self.server.check();
        let _ = &self.database.check();
        let _ = &self.security.check();
        let _ = &self.requests.check();
        let _ = &self.monitor.check();
        let _ = &self.backup.check();
        let _ = &self.elasticsearch.check();
        let _ = &self.analytics_snapshot.check();
        self.report_mail
            .validate()
            .expect("invalid report mail configuration");
        if let Err(error) = self.automatic_target.validate() {
            panic!("{error}");
        }
        if let Err(error) = self.dns_follow_up.validate() {
            panic!("{error}");
        }
    }

    fn try_check(&self) -> Result<bool, Box<dyn std::error::Error>> {
        self.scanner_diagnostics
            .validate()
            .map_err(|e| e.to_string())?;
        match self.server.try_check() {
            Ok(true) => (),
            Ok(false) => return Ok(false),
            Err(e) => return Err(e),
        }
        match self.database.try_check() {
            Ok(true) => (),
            Ok(false) => return Ok(false),
            Err(e) => return Err(e),
        }
        self.security.try_check()?;
        self.requests.try_check()?;
        self.monitor.try_check()?;
        self.backup.try_check()?;
        self.elasticsearch.try_check()?;
        self.analytics_snapshot.try_check()?;
        self.report_mail.validate()?;
        self.automatic_target.validate()?;
        self.dns_follow_up.validate()?;
        Ok(true)
    }
}

/// 扫描分析快照。默认 realtime，确保已有部署升级后不会在历史回填前读到空统计。
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnalyticsSnapshotMode {
    #[default]
    Realtime,
    Shadow,
    Snapshot,
}

impl AnalyticsSnapshotMode {
    pub fn reads_snapshot(self) -> bool {
        self == Self::Snapshot
    }

    pub fn runs_worker(self) -> bool {
        !matches!(self, Self::Realtime)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct AnalyticsSnapshotConfig {
    pub mode: AnalyticsSnapshotMode,
    pub interval_minutes: u64,
}

impl Default for AnalyticsSnapshotConfig {
    fn default() -> Self {
        Self {
            mode: AnalyticsSnapshotMode::Realtime,
            interval_minutes: 30,
        }
    }
}

impl SelfChecking for AnalyticsSnapshotConfig {
    fn check(&self) {
        if let Err(error) = self.try_check() {
            panic!("{error}");
        }
    }

    fn try_check(&self) -> Result<bool, Box<dyn std::error::Error>> {
        if !(1..=24 * 60).contains(&self.interval_minutes) {
            return Err("analytics_snapshot.interval_minutes 必须在 1 到 1440 之间".into());
        }
        Ok(true)
    }
}

/// pgBackRest 管理接口配置。默认关闭，避免未部署 pgBackRest 的现有安装在升级后失败。
#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(default)]
pub struct BackupConfig {
    pub enabled: bool,
    pub binary: PathBuf,
    pub stanza: String,
    pub config_file: Option<PathBuf>,
    pub run_as_user: Option<String>,
    pub sudo_binary: PathBuf,
    pub command_timeout_seconds: u64,
    pub max_output_bytes: usize,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            binary: PathBuf::from("/usr/bin/pgbackrest"),
            stanza: "network_mapping".to_owned(),
            config_file: None,
            run_as_user: None,
            sudo_binary: PathBuf::from("/usr/bin/sudo"),
            command_timeout_seconds: 6 * 60 * 60,
            max_output_bytes: 1024 * 1024,
        }
    }
}

impl SelfChecking for BackupConfig {
    fn check(&self) {
        if let Err(error) = self.try_check() {
            panic!("{error}");
        }
        info!(
            target: "server::startup",
            component = "backup",
            enabled = self.enabled,
            stanza = %self.stanza,
            "配置检查通过"
        );
    }

    fn try_check(&self) -> Result<bool, Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(true);
        }
        if !self.binary.is_absolute() {
            return Err("backup.binary 必须是绝对路径".into());
        }
        if self.stanza.is_empty()
            || !self
                .stanza
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'_' | b'-'))
        {
            return Err("backup.stanza 只能包含字母、数字、下划线和连字符".into());
        }
        if let Some(run_as_user) = self.run_as_user.as_deref() {
            if !valid_run_as_user(run_as_user) {
                return Err(
                    "backup.run_as_user 必须是非 root 的本机账户名，只能包含字母、数字、下划线和连字符"
                        .into(),
                );
            }
            if !self.sudo_binary.is_absolute() {
                return Err("backup.sudo_binary 必须是绝对路径".into());
            }
        }
        if self.command_timeout_seconds == 0 {
            return Err("backup.command_timeout_seconds 必须大于 0".into());
        }
        if self.max_output_bytes < 4096 {
            return Err("backup.max_output_bytes 必须大于等于 4096".into());
        }
        Ok(true)
    }
}

fn valid_run_as_user(value: &str) -> bool {
    if value.is_empty() || value == "root" {
        return false;
    }
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

impl BackupConfig {
    fn resolve_relative_to(&mut self, config_path: &Path) {
        let Some(config_file) = &mut self.config_file else {
            return;
        };
        if config_file.is_relative() {
            let base_directory = config_path.parent().unwrap_or_else(|| Path::new(""));
            *config_file = base_directory.join(&*config_file);
        }
    }
}

/// Elasticsearch 扫描结果存储配置。扫描事实仅支持 Elasticsearch。
#[derive(Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ElasticsearchConfig {
    pub enabled: bool,
    pub read_enabled: bool,
    /// 仅接受 elasticsearch；旧 PG 数据通过独立迁移命令导入。
    pub scan_storage: ScanStorageMode,
    pub url: String,
    pub observation_index_prefix: String,
    pub execution_endpoint_index: String,
    pub current_endpoint_index: String,
    pub dns_observation_data_stream: String,
    pub dns_record_index: String,
    pub dns_observation_retention_days: u16,
    pub scan_number_of_replicas: u32,
    /// Bulk 写入等待的分片副本数；单节点应使用 `1`（仅主分片）。
    pub write_wait_for_active_shards: String,
    /// 支持正式版 `9.5.x`；兼容旧 `9.5.N` 配置，不限制补丁版本。
    pub expected_version: String,
    #[serde(skip_serializing)]
    pub api_key: Option<String>,
    pub username: Option<String>,
    #[serde(skip_serializing)]
    pub password: Option<String>,
    pub ca_certificate_file: Option<PathBuf>,
    pub request_timeout_seconds: u64,
    pub poll_interval_ms: u64,
    pub bulk_batch_size: usize,
    /// Number of scan executions migrated concurrently. Batches belonging to the same
    /// execution remain ordered so that a final batch cannot publish a partial projection.
    pub scan_migration_concurrency: usize,
    /// Number of execution identifiers fetched from PostgreSQL for each scheduling page.
    pub scan_migration_page_size: usize,
    /// Maximum retries for transient Elasticsearch bulk failures.
    pub bulk_max_retries: u32,
    /// Initial exponential backoff delay for Elasticsearch bulk retries.
    pub bulk_retry_initial_ms: u64,
    /// 一次 Bulk（包含排队、请求、退避和重试）的总时间预算。
    pub bulk_total_timeout_seconds: u64,
    /// 进程内允许并发执行的 Bulk 数量，防止故障时重试风暴。
    pub bulk_max_concurrency: usize,
    /// Endpoint page size and serialized request limit for current projections.
    pub projection_page_size: usize,
    pub projection_bulk_max_bytes: usize,
    pub projection_pages_per_tick: usize,
    pub projection_lease_seconds: u64,
    pub projection_heartbeat_seconds: u64,
    /// Persist migration progress after at least this many newly migrated batches.
    pub scan_migration_checkpoint_batches: u64,
    pub fallback_to_postgres: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanStorageMode {
    #[default]
    Elasticsearch,
}

impl fmt::Debug for ElasticsearchConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ElasticsearchConfig")
            .field("enabled", &self.enabled)
            .field("read_enabled", &self.read_enabled)
            .field("scan_storage", &self.scan_storage)
            .field("url", &self.url)
            .field("observation_index_prefix", &self.observation_index_prefix)
            .field("execution_endpoint_index", &self.execution_endpoint_index)
            .field("current_endpoint_index", &self.current_endpoint_index)
            .field(
                "dns_observation_data_stream",
                &self.dns_observation_data_stream,
            )
            .field("dns_record_index", &self.dns_record_index)
            .field(
                "dns_observation_retention_days",
                &self.dns_observation_retention_days,
            )
            .field("scan_number_of_replicas", &self.scan_number_of_replicas)
            .field(
                "write_wait_for_active_shards",
                &self.write_wait_for_active_shards,
            )
            .field("expected_version", &self.expected_version)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("ca_certificate_file", &self.ca_certificate_file)
            .field("request_timeout_seconds", &self.request_timeout_seconds)
            .field("poll_interval_ms", &self.poll_interval_ms)
            .field("bulk_batch_size", &self.bulk_batch_size)
            .field("projection_page_size", &self.projection_page_size)
            .field("projection_bulk_max_bytes", &self.projection_bulk_max_bytes)
            .field("projection_pages_per_tick", &self.projection_pages_per_tick)
            .field("projection_lease_seconds", &self.projection_lease_seconds)
            .field(
                "projection_heartbeat_seconds",
                &self.projection_heartbeat_seconds,
            )
            .field(
                "scan_migration_concurrency",
                &self.scan_migration_concurrency,
            )
            .field("scan_migration_page_size", &self.scan_migration_page_size)
            .field("bulk_max_retries", &self.bulk_max_retries)
            .field("bulk_retry_initial_ms", &self.bulk_retry_initial_ms)
            .field(
                "bulk_total_timeout_seconds",
                &self.bulk_total_timeout_seconds,
            )
            .field("bulk_max_concurrency", &self.bulk_max_concurrency)
            .field(
                "scan_migration_checkpoint_batches",
                &self.scan_migration_checkpoint_batches,
            )
            .field("fallback_to_postgres", &self.fallback_to_postgres)
            .finish()
    }
}

impl Default for ElasticsearchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            read_enabled: true,
            scan_storage: ScanStorageMode::Elasticsearch,
            url: "https://127.0.0.1:9200".to_owned(),
            observation_index_prefix: "network-mapping-scan-observations-v1".to_owned(),
            execution_endpoint_index: "network-mapping-execution-endpoints-v1".to_owned(),
            current_endpoint_index: "network-mapping-endpoints-current-v2".to_owned(),
            dns_observation_data_stream: "network-mapping-dns-observations".to_owned(),
            dns_record_index: "network-mapping-dns-records-v1".to_owned(),
            dns_observation_retention_days: 180,
            scan_number_of_replicas: 0,
            write_wait_for_active_shards: "1".to_owned(),
            expected_version: "9.5.x".to_owned(),
            api_key: None,
            username: None,
            password: None,
            ca_certificate_file: None,
            request_timeout_seconds: 30,
            poll_interval_ms: 500,
            bulk_batch_size: 500,
            scan_migration_concurrency: 4,
            scan_migration_page_size: 100,
            bulk_max_retries: 4,
            bulk_retry_initial_ms: 200,
            bulk_total_timeout_seconds: 25,
            bulk_max_concurrency: 2,
            projection_page_size: 1000,
            projection_bulk_max_bytes: 5 * 1024 * 1024,
            projection_pages_per_tick: 4,
            projection_lease_seconds: 120,
            projection_heartbeat_seconds: 20,
            scan_migration_checkpoint_batches: 100,
            fallback_to_postgres: false,
        }
    }
}

/// Only canonical stable 9.5 patch versions are supported.
fn elasticsearch_patch_version(version: &str) -> Option<u64> {
    let mut parts = version.split('.');
    if parts.next()? != "9" || parts.next()? != "5" {
        return None;
    }
    let patch = parts.next()?;
    if parts.next().is_some()
        || patch.is_empty()
        || !patch.bytes().all(|byte| byte.is_ascii_digit())
        || (patch.len() > 1 && patch.starts_with('0'))
    {
        return None;
    }
    patch.parse().ok()
}

impl ElasticsearchConfig {
    pub(crate) fn validate_version_policy(&self) -> Result<(), String> {
        if self.expected_version == "9.5.x"
            || elasticsearch_patch_version(&self.expected_version).is_some()
        {
            Ok(())
        } else {
            Err("elasticsearch.expected_version 必须为 9.5.x 或旧格式 9.5.N（均允许整个 9.5.x 系列）".to_owned())
        }
    }

    pub(crate) fn validate_server_version(&self, version: &str) -> Result<(), String> {
        self.validate_version_policy()?;
        // Legacy configurations such as 9.5.3 select the supported 9.5 series,
        // rather than pinning a patch and preventing routine ES patch upgrades.
        if elasticsearch_patch_version(version).is_some() {
            Ok(())
        } else {
            Err(format!(
                "Elasticsearch 版本不匹配：允许正式版 9.5.x，实际 {version}（配置 expected_version={}）",
                self.expected_version
            ))
        }
    }

    fn resolve_relative_to(&mut self, config_path: &Path) {
        let Some(certificate) = &mut self.ca_certificate_file else {
            return;
        };
        if certificate.is_relative() {
            let base_directory = config_path.parent().unwrap_or_else(|| Path::new(""));
            *certificate = base_directory.join(&*certificate);
        }
    }
}

impl SelfChecking for ElasticsearchConfig {
    fn check(&self) {
        if let Err(error) = self.try_check() {
            panic!("{error}");
        }
        info!(
            target: "server::startup",
            component = "elasticsearch",
            enabled = self.enabled,
            read_enabled = self.read_enabled,
            index = %self.current_endpoint_index,
            expected_version = %self.expected_version,
            "配置检查通过"
        );
    }

    fn try_check(&self) -> Result<bool, Box<dyn std::error::Error>> {
        if !self.enabled || !self.read_enabled {
            return Err(
                "扫描结果仅支持 Elasticsearch，要求 enabled=true 且 read_enabled=true".into(),
            );
        }
        if self.fallback_to_postgres {
            return Err(
                "扫描结果不再支持 PostgreSQL 回退，请设置 fallback_to_postgres=false".into(),
            );
        }
        let url = reqwest::Url::parse(&self.url)
            .map_err(|_| "elasticsearch.url 必须是有效的 HTTP(S) URL")?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err("elasticsearch.url 必须是有效的 HTTP(S) URL".into());
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("elasticsearch.url 不得包含用户名或密码，请使用独立认证字段".into());
        }
        self.validate_version_policy()?;
        for (name, value) in [
            ("observation_index_prefix", &self.observation_index_prefix),
            ("execution_endpoint_index", &self.execution_endpoint_index),
            ("current_endpoint_index", &self.current_endpoint_index),
            (
                "dns_observation_data_stream",
                &self.dns_observation_data_stream,
            ),
            ("dns_record_index", &self.dns_record_index),
        ] {
            if value.is_empty()
                || value.len() > 240
                || value.chars().any(|character| {
                    character.is_ascii_uppercase()
                        || character.is_whitespace()
                        || matches!(
                            character,
                            '\\' | '/' | '*' | '?' | '"' | '<' | '>' | '|' | ',' | '#'
                        )
                })
            {
                return Err(format!("elasticsearch.{name} 不是有效的索引名前缀").into());
            }
        }
        if self.api_key.is_some() && (self.username.is_some() || self.password.is_some()) {
            return Err("elasticsearch.api_key 与 username/password 不能同时配置".into());
        }
        if self.username.is_some() != self.password.is_some() {
            return Err("elasticsearch.username 和 password 必须同时配置".into());
        }
        if self.request_timeout_seconds == 0 {
            return Err("elasticsearch.request_timeout_seconds 必须大于 0".into());
        }
        if !(100..=60_000).contains(&self.poll_interval_ms) {
            return Err("elasticsearch.poll_interval_ms 必须在 100 到 60000 之间".into());
        }
        if !(1..=2_000).contains(&self.bulk_batch_size) {
            return Err("elasticsearch.bulk_batch_size 必须在 1 到 2000 之间".into());
        }
        if !(1..=32).contains(&self.scan_migration_concurrency) {
            return Err("elasticsearch.scan_migration_concurrency 必须在 1 到 32 之间".into());
        }
        if !(1..=10_000).contains(&self.scan_migration_page_size) {
            return Err("elasticsearch.scan_migration_page_size 必须在 1 到 10000 之间".into());
        }
        if self.scan_migration_page_size < self.scan_migration_concurrency {
            return Err(
                "elasticsearch.scan_migration_page_size 不能小于 scan_migration_concurrency".into(),
            );
        }
        if self.bulk_max_retries > 10 {
            return Err("elasticsearch.bulk_max_retries 必须在 0 到 10 之间".into());
        }
        if !(10..=60_000).contains(&self.bulk_retry_initial_ms) {
            return Err("elasticsearch.bulk_retry_initial_ms 必须在 10 到 60000 之间".into());
        }
        if !(1..=300).contains(&self.bulk_total_timeout_seconds) {
            return Err("elasticsearch.bulk_total_timeout_seconds 必须在 1 到 300 之间".into());
        }
        if !(1..=32).contains(&self.bulk_max_concurrency) {
            return Err("elasticsearch.bulk_max_concurrency 必须在 1 到 32 之间".into());
        }
        if !(1..=2000).contains(&self.projection_page_size)
            || !(64 * 1024..=16 * 1024 * 1024).contains(&self.projection_bulk_max_bytes)
            || !(1..=32).contains(&self.projection_pages_per_tick)
            || !(10..=3600).contains(&self.projection_lease_seconds)
            || self.projection_heartbeat_seconds == 0
            || self.projection_heartbeat_seconds > self.projection_lease_seconds / 3
        {
            return Err(
                "elasticsearch.projection_* 配置超出范围或续租周期超过租约的三分之一".into(),
            );
        }
        if self.write_wait_for_active_shards != "1"
            && self.write_wait_for_active_shards != "all"
            && self
                .write_wait_for_active_shards
                .parse::<u32>()
                .ok()
                .is_none_or(|value| value == 0)
        {
            return Err("elasticsearch.write_wait_for_active_shards 必须是 1、all 或正整数".into());
        }
        if self.scan_migration_checkpoint_batches == 0 {
            return Err("elasticsearch.scan_migration_checkpoint_batches 必须大于 0".into());
        }
        if self.scan_number_of_replicas > 5 {
            return Err("elasticsearch.scan_number_of_replicas 必须在 0 到 5 之间".into());
        }
        if !(30..=365).contains(&self.dns_observation_retention_days) {
            return Err(
                "elasticsearch.dns_observation_retention_days 必须在 30 到 365 之间".into(),
            );
        }
        Ok(true)
    }
}

#[derive(Deserialize, Clone)]
pub struct SecurityConfig {
    pub scanner_token_pepper: String,
}

impl fmt::Debug for SecurityConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecurityConfig")
            .field("scanner_token_pepper", &"[REDACTED]")
            .finish()
    }
}

impl SelfChecking for SecurityConfig {
    fn check(&self) {
        if let Err(error) = self.try_check() {
            panic!("{error}");
        }
        info!(target: "server::startup", component = "security", "配置检查通过");
    }

    fn try_check(&self) -> Result<bool, Box<dyn std::error::Error>> {
        if self.scanner_token_pepper.trim().len() < 32 {
            return Err(
                "scanner_token_pepper 至少需要 32 个字符，请使用 openssl rand -hex 32 生成".into(),
            );
        }
        Ok(true)
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(default)]
pub struct RequestsConfig {
    /// 是否采集请求日志（`request_log`）。
    pub enabled: bool,
    /// 请求日志在线保留天数，超过该天数的记录会被后台任务分批清理。
    pub retention_days: i32,
}

impl Default for RequestsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 30,
        }
    }
}

impl SelfChecking for RequestsConfig {
    fn check(&self) {
        if let Err(error) = self.try_check() {
            panic!("{error}");
        }
        info!(target: "server::startup", component = "requests", enabled = self.enabled, retention_days = self.retention_days, "配置检查通过");
    }

    fn try_check(&self) -> Result<bool, Box<dyn std::error::Error>> {
        if self.retention_days < 1 {
            return Err("requests.retention_days 必须大于等于 1".into());
        }
        Ok(true)
    }
}

/// 健康监控与告警配置。
///
/// 慢请求与 5xx 错误由请求中间件实时判定，慢 SQL 由后台任务轮询
/// `pg_stat_statements` 视图判定，三者统一走邮件通知并共享同一冷却去重窗口。
#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MonitorConfig {
    /// 是否启用健康监控与告警。
    pub enabled: bool,
    /// 慢请求阈值（毫秒），响应耗时达到该值即触发告警。
    pub slow_request_threshold_ms: i64,
    /// 是否对 5xx 服务端错误告警。
    pub server_error_enabled: bool,
    /// 慢 SQL 阈值（毫秒），基于 `pg_stat_statements.mean_exec_time`。
    pub slow_sql_threshold_ms: i64,
    /// 慢 SQL 轮询间隔（秒）。
    pub slow_sql_check_interval_seconds: u64,
    /// Elasticsearch 查询告警阈值（毫秒）。
    pub elasticsearch_query_warning_threshold_ms: i64,
    /// Elasticsearch 查询严重告警阈值（毫秒）。
    pub elasticsearch_query_critical_threshold_ms: i64,
    /// Elasticsearch 写入告警阈值（毫秒）。
    pub elasticsearch_write_warning_threshold_ms: i64,
    /// Elasticsearch 写入严重告警阈值（毫秒）。
    pub elasticsearch_write_critical_threshold_ms: i64,
    /// 同一告警 key 的冷却时间（秒），冷却窗口内的重复事件被合并丢弃。
    pub alert_cooldown_seconds: u64,
    pub service_defaults: std::collections::BTreeMap<
        crate::monitor::rules::MonitorService,
        crate::monitor::rules::SlowRule,
    >,
    pub operation_rules: Vec<crate::monitor::rules::OperationRule>,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            slow_request_threshold_ms: 3000,
            server_error_enabled: true,
            slow_sql_threshold_ms: 3000,
            slow_sql_check_interval_seconds: 60,
            elasticsearch_query_warning_threshold_ms: 1000,
            elasticsearch_query_critical_threshold_ms: 3000,
            elasticsearch_write_warning_threshold_ms: 5000,
            elasticsearch_write_critical_threshold_ms: 15000,
            alert_cooldown_seconds: 300,
            service_defaults: Default::default(),
            operation_rules: Vec::new(),
        }
    }
}

impl SelfChecking for MonitorConfig {
    fn check(&self) {
        if let Err(error) = self.try_check() {
            panic!("{error}");
        }
        info!(target: "server::startup", component = "monitor", enabled = self.enabled, slow_request_threshold_ms = self.slow_request_threshold_ms, slow_sql_threshold_ms = self.slow_sql_threshold_ms, "配置检查通过");
    }

    fn try_check(&self) -> Result<bool, Box<dyn std::error::Error>> {
        if self.slow_request_threshold_ms <= 0 {
            return Err("monitor.slow_request_threshold_ms 必须大于 0".into());
        }
        if self.slow_sql_threshold_ms <= 0 {
            return Err("monitor.slow_sql_threshold_ms 必须大于 0".into());
        }
        if !(1..=86_400).contains(&self.slow_sql_check_interval_seconds) {
            return Err("monitor.slow_sql_check_interval_seconds 必须为 1～86400 秒".into());
        }
        for (name, value) in [
            (
                "monitor.elasticsearch_query_warning_threshold_ms",
                self.elasticsearch_query_warning_threshold_ms,
            ),
            (
                "monitor.elasticsearch_query_critical_threshold_ms",
                self.elasticsearch_query_critical_threshold_ms,
            ),
            (
                "monitor.elasticsearch_write_warning_threshold_ms",
                self.elasticsearch_write_warning_threshold_ms,
            ),
            (
                "monitor.elasticsearch_write_critical_threshold_ms",
                self.elasticsearch_write_critical_threshold_ms,
            ),
        ] {
            if value <= 0 {
                return Err(format!("{name} 必须大于 0").into());
            }
        }
        if self.elasticsearch_query_critical_threshold_ms
            < self.elasticsearch_query_warning_threshold_ms
        {
            return Err("Elasticsearch 查询严重阈值不能小于告警阈值".into());
        }
        if self.elasticsearch_write_critical_threshold_ms
            < self.elasticsearch_write_warning_threshold_ms
        {
            return Err("Elasticsearch 写入严重阈值不能小于告警阈值".into());
        }
        self.validate_rules()?;
        if self.alert_cooldown_seconds == 0 {
            return Err("monitor.alert_cooldown_seconds 必须大于 0".into());
        }
        Ok(true)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub encrypt_key: String,
    /// 全局请求体大小上限（字节）。actix-web 的 JSON 提取器默认 2MB，
    /// 这里放宽以容纳扫描器大批量结果上传，对所有 JSON 接口生效。
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
}

/// 默认 64MB：500 条/批 × 64KB/条 ≈ 32MB，再预留 JSON 转义与协议字段开销。
pub(crate) fn default_max_body_size() -> usize {
    64 * 1024 * 1024
}

impl SelfChecking for ServerConfig {
    fn check(&self) {
        if self.host.is_empty() {
            panic!("监听地址为空")
        }

        if self.max_body_size == 0 {
            panic!("max_body_size 必须大于 0")
        }

        match &self.encrypt_key.len() {
            44 => (),
            0 => panic!("加密密钥为空，请生成 Base64 格式的密钥\n如：openssl rand -base64 32"),
            ..44 => panic!(
                "加密密钥过短，base64 编码后应为 44 个字符,请生成 Base64 格式的密钥\n如：openssl rand -base64 32"
            ),
            45.. => panic!(
                "加密密钥过长，base64 编码后应为 44 个字符,请生成 Base64 格式的密钥\n如：openssl rand -base64 32"
            ),
        }

        info!(target: "server::startup", component = "server", "配置检查通过");
    }

    fn try_check(&self) -> Result<bool, Box<dyn std::error::Error>> {
        if self.host.is_empty() {
            println!("监听地址为空");
            return Ok(false);
        }

        match &self.encrypt_key.len() {
            44 => Ok(true),
            0 => {
                println!("加密密钥为空，请生成 Base64 格式的密钥\n如：openssl rand -base64 32");
                Ok(false)
            }
            ..44 => {
                println!(
                    "加密密钥过短，base64 编码后应为 44 个字符,请生成 Base64 格式的密钥\n如：openssl rand -base64 32"
                );
                Ok(false)
            }
            45.. => {
                println!(
                    "加密密钥过长，base64 编码后应为 44 个字符,请生成 Base64 格式的密钥\n如：openssl rand -base64 32"
                );
                Ok(false)
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LogConfig {
    pub directory: String,
    pub file_name: String,
    pub file_rolling: u8,
    pub status_duration: u64,
}

#[derive(Debug, Deserialize)]
pub struct TemplatesConfig {
    pub templates_directory: String,
    pub templates_name: String,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(default)]
pub struct FrontendConfig {
    /// Vite 生产构建目录；文件缺失时对应页面或资源返回 404。
    pub directory: PathBuf,
}

impl Default for FrontendConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from("../network-mapping-vue/dist"),
        }
    }
}

impl FrontendConfig {
    fn resolve_relative_to(&mut self, config_path: &Path) {
        if self.directory.is_relative() {
            let base_directory = config_path.parent().unwrap_or_else(|| Path::new(""));
            self.directory = base_directory.join(&self.directory);
        }
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(default)]
pub struct MaxMindConfig {
    /// GeoLite2 数据库目录；文件缺失时相关 IP 情报字段保持为空。
    pub directory: PathBuf,
}

impl Default for MaxMindConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from("source/maxmind"),
        }
    }
}

impl MaxMindConfig {
    fn resolve_relative_to(&mut self, config_path: &Path) {
        if self.directory.is_relative() {
            let base_directory = config_path.parent().unwrap_or_else(|| Path::new(""));
            self.directory = base_directory.join(&self.directory);
        }
    }
}

pub const DEFAULT_COMMON_SCAN_PORTS: &str = "21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,1433,1521,2049,2375,2376,3000,3306,3389,5432,5900,6379,8080,8443,9200,11211,27017";

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(default)]
pub struct SearchGenerationConfig {
    pub enabled: bool,
    pub stale_after_days: u32,
    pub cooldown_minutes: u32,
    pub max_pending_tasks: u32,
    pub per_user_hourly_limit: u32,
    pub domain_enabled: bool,
    /// Exact domains and their subdomains; never inferred from search input.
    pub authorized_domains: Vec<String>,
}

impl Default for SearchGenerationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            stale_after_days: 7,
            cooldown_minutes: 1440,
            max_pending_tasks: 100,
            per_user_hourly_limit: 20,
            domain_enabled: false,
            authorized_domains: Vec::new(),
        }
    }
}

impl SearchGenerationConfig {
    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !(1..=3650).contains(&self.stale_after_days)
            || !(1..=525600).contains(&self.cooldown_minutes)
            || !(1..=10000).contains(&self.max_pending_tasks)
            || !(1..=10000).contains(&self.per_user_hourly_limit)
        {
            return Err(
                "搜索生成有效期须为 1-3650 天，冷却为 1-525600 分钟，队列和每小时额度为 1-10000"
                    .into(),
            );
        }
        if self.enabled && self.domain_enabled && self.authorized_domains.is_empty() {
            return Err("启用域名搜索生成时必须配置授权域名".into());
        }
        for domain in &self.authorized_domains {
            crate::dns::canonical_scan_domain(domain)?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(default)]
pub struct AutomaticTargetConfig {
    pub search_generation: SearchGenerationConfig,
    pub enabled: bool,
    pub strategy: String,
    pub interval_seconds: u64,
    pub pending_low_watermark: u32,
    pub pending_high_watermark: u32,
    pub priority: i32,
    pub authorized_cidrs: Vec<String>,
    pub excluded_cidrs: Vec<String>,
    pub ipv4_task_prefix: u8,
    pub ipv6_enabled: bool,
    pub ipv6_authorized_cidrs: Vec<String>,
    pub ipv6_excluded_cidrs: Vec<String>,
    pub ipv6_task_prefix: u8,
    pub ipv6_pending_low_watermark: u32,
    pub ipv6_pending_high_watermark: u32,
    pub common_ports: String,
    pub repeat_after_seconds: u64,
}

impl Default for AutomaticTargetConfig {
    fn default() -> Self {
        Self {
            search_generation: SearchGenerationConfig::default(),
            enabled: false,
            strategy: "sequential_subnet".to_owned(),
            interval_seconds: 30,
            pending_low_watermark: 2,
            pending_high_watermark: 5,
            priority: 0,
            authorized_cidrs: Vec::new(),
            excluded_cidrs: Vec::new(),
            ipv4_task_prefix: 24,
            ipv6_enabled: false,
            ipv6_authorized_cidrs: Vec::new(),
            ipv6_excluded_cidrs: Vec::new(),
            // 避免把完整 /64 直接交给扫描器；默认每个任务最多覆盖 256 个地址。
            ipv6_task_prefix: 120,
            ipv6_pending_low_watermark: 1,
            ipv6_pending_high_watermark: 2,
            common_ports: DEFAULT_COMMON_SCAN_PORTS.to_owned(),
            repeat_after_seconds: 7 * 24 * 60 * 60,
        }
    }
}

impl AutomaticTargetConfig {
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.search_generation.validate()?;
        if self.strategy != "sequential_subnet" {
            return Err(format!("不支持的自动目标生成策略：{}", self.strategy).into());
        }
        if self.interval_seconds < 5 {
            return Err("automatic_target.interval_seconds 不能小于 5".into());
        }
        if self.pending_low_watermark > self.pending_high_watermark
            || self.pending_high_watermark == 0
            || self.pending_high_watermark > 100
        {
            return Err(
                "automatic_target 队列水位必须满足 0 <= low <= high <= 100 且 high > 0".into(),
            );
        }
        if !(0..=4).contains(&self.priority) {
            return Err("automatic_target.priority 必须在 0 到 4 之间".into());
        }
        if self.ipv4_task_prefix > 32 {
            return Err("automatic_target.ipv4_task_prefix 不能大于 32".into());
        }
        if self.ipv6_task_prefix > 128 {
            return Err("automatic_target.ipv6_task_prefix 不能大于 128".into());
        }
        if self.ipv6_pending_low_watermark > self.ipv6_pending_high_watermark
            || self.ipv6_pending_high_watermark == 0
            || self.ipv6_pending_high_watermark > 100
        {
            return Err("IPv6 自动目标队列水位必须满足 0 <= low <= high <= 100 且 high > 0".into());
        }
        validate_port_list(&self.common_ports)?;
        if self.enabled && self.authorized_cidrs.is_empty() {
            return Err("启用自动目标生成时必须配置 authorized_cidrs".into());
        }
        let mut authorized_networks = Vec::with_capacity(self.authorized_cidrs.len());
        for value in &self.authorized_cidrs {
            let network: ipnet::IpNet = value
                .parse()
                .map_err(|error| format!("无效的自动目标授权 CIDR {value}: {error}"))?;
            let ipnet::IpNet::V4(network) = network else {
                return Err(format!("IPv4 自动目标授权范围包含 IPv6：{value}").into());
            };
            if network.prefix_len() > self.ipv4_task_prefix {
                return Err(format!(
                    "授权范围 {value} 小于配置的 /{} 任务网段",
                    self.ipv4_task_prefix
                )
                .into());
            }
            authorized_networks.push(network);
        }
        if self.ipv6_enabled && self.ipv6_authorized_cidrs.is_empty() {
            return Err("启用 IPv6 自动目标生成时必须配置 ipv6_authorized_cidrs".into());
        }
        let mut authorized_ipv6 = Vec::with_capacity(self.ipv6_authorized_cidrs.len());
        let mut ipv6_total_subnets = 0_u128;
        for value in &self.ipv6_authorized_cidrs {
            let network: ipnet::Ipv6Net = value
                .parse()
                .map_err(|error| format!("无效的 IPv6 自动目标授权 CIDR {value}: {error}"))?;
            if network.prefix_len() > self.ipv6_task_prefix {
                return Err(format!(
                    "IPv6 授权范围 {value} 小于配置的 /{} 任务网段",
                    self.ipv6_task_prefix
                )
                .into());
            }
            let subnet_count = 1_u128
                .checked_shl(u32::from(self.ipv6_task_prefix - network.prefix_len()))
                .ok_or_else(|| {
                    format!(
                        "IPv6 授权范围 {value} 按 /{} 划分将产生 2^128 个任务网段，超出游标容量",
                        self.ipv6_task_prefix
                    )
                })?;
            ipv6_total_subnets = ipv6_total_subnets
                .checked_add(subnet_count)
                .ok_or("IPv6 授权范围的任务网段总数超出 128 位游标容量")?;
            authorized_ipv6.push(network);
        }
        for (index, network) in authorized_ipv6.iter().enumerate() {
            if authorized_ipv6[index + 1..].iter().any(|other| {
                network.contains(&other.network()) || other.contains(&network.network())
            }) {
                return Err(format!("IPv6 自动目标授权 CIDR 存在重复或重叠：{network}").into());
            }
        }
        for (index, network) in authorized_networks.iter().enumerate() {
            if authorized_networks[index + 1..].iter().any(|other| {
                network.contains(&other.network()) || other.contains(&network.network())
            }) {
                return Err(format!("自动目标授权 CIDR 存在重复或重叠：{network}").into());
            }
        }
        validate_excluded_cidrs(&self.excluded_cidrs, false)?;
        validate_excluded_cidrs(&self.ipv6_excluded_cidrs, true)?;
        Ok(())
    }
}

fn validate_excluded_cidrs(
    values: &[String],
    expect_ipv6: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut networks = Vec::with_capacity(values.len());
    for value in values {
        let network: ipnet::IpNet = value
            .parse()
            .map_err(|error| format!("无效的自动目标排除 CIDR {value}: {error}"))?;
        if network.addr().is_ipv6() != expect_ipv6 {
            let family = if expect_ipv6 { "IPv6" } else { "IPv4" };
            return Err(format!("{family} 自动目标排除范围地址族错误：{value}").into());
        }
        networks.push(network);
    }
    for (index, network) in networks.iter().enumerate() {
        if networks[index + 1..]
            .iter()
            .any(|other| network.contains(&other.network()) || other.contains(&network.network()))
        {
            return Err(format!("自动目标排除 CIDR 存在重复或重叠：{network}").into());
        }
    }
    Ok(())
}

fn validate_port_list(value: &str) -> Result<(), Box<dyn std::error::Error>> {
    if value.is_empty() {
        return Err("automatic_target.common_ports 不能为空".into());
    }
    for segment in value.split(',') {
        let mut bounds = segment.split('-');
        let start = bounds
            .next()
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| format!("无效的自动扫描端口：{segment}"))?;
        let end = bounds
            .next()
            .map(|value| value.parse::<u16>())
            .transpose()
            .map_err(|_| format!("无效的自动扫描端口：{segment}"))?
            .unwrap_or(start);
        if bounds.next().is_some() || end == 0 || start > end {
            return Err(format!("无效的自动扫描端口：{segment}").into());
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub host: String,         //数据库主机地址
    pub port: u16,            //数据库端口
    pub username: String,     //用户名
    pub password: String,     //密码
    pub db_name: String,      //数据库名
    pub pool_max_size: usize, //连接池最大连接数
    /// 请求等待空闲连接的上限。到期后快速失败，避免所有 HTTP worker 一起堆积。
    #[serde(default = "default_pool_wait_timeout_ms")]
    pub pool_wait_timeout_ms: u64,
    #[serde(default = "default_pool_create_timeout_ms")]
    pub pool_create_timeout_ms: u64,
    #[serde(default = "default_pool_recycle_timeout_ms")]
    pub pool_recycle_timeout_ms: u64,
    pub tls: bool,                  //是否使用tls
    pub init_database_file: String, //初始化数据库表的sql文件
    pub sql_file_path: String,      //sql文件存放路径（相对）
}

impl SelfChecking for DatabaseConfig {
    fn check(&self) {
        if self.host.is_empty()
            || self.username.is_empty()
            || self.password.is_empty()
            || self.db_name.is_empty()
            || self.pool_max_size == 0
            || self.pool_wait_timeout_ms == 0
            || self.pool_create_timeout_ms == 0
            || self.pool_recycle_timeout_ms == 0
            || self.init_database_file.is_empty()
        {
            panic!("数据库关键字段为空")
        }

        info!(target: "server::startup", component = "database", "配置检查通过");
    }

    fn try_check(&self) -> Result<bool, Box<dyn std::error::Error>> {
        if self.host.is_empty()
            || self.username.is_empty()
            || self.password.is_empty()
            || self.db_name.is_empty()
            || self.pool_max_size == 0
            || self.pool_wait_timeout_ms == 0
            || self.pool_create_timeout_ms == 0
            || self.pool_recycle_timeout_ms == 0
            || self.init_database_file.is_empty()
        {
            println!("数据库关键字段为空");
            return Ok(false);
        }
        Ok(true)
    }
}

pub(crate) fn default_pool_wait_timeout_ms() -> u64 {
    2_000
}

pub(crate) fn default_pool_create_timeout_ms() -> u64 {
    5_000
}

pub(crate) fn default_pool_recycle_timeout_ms() -> u64 {
    3_000
}

#[derive(Debug, Deserialize, Clone)]
pub struct PasswordHashConfig {
    pub m: u32, // 内存，单位 MiB
    pub t: u32, // 迭代，最大可设置为 4294967295
    pub p: u32, // 并行，最大可设置为 4294967295
}

#[derive(Debug, Deserialize, Clone)]
pub struct EmailConfig {
    pub host: String,
    pub account_username: String,
    pub account_password: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationPreferences {
    pub login_notify_enabled: bool,
    pub notify_on_stuck: bool,
    pub notify_on_complete: bool,
    pub report_daily: bool,
    pub report_weekly: bool,
    pub report_monthly: bool,
    /// 是否发送健康告警（慢请求 / 5xx / 慢 SQL）。
    /// 字段级默认值为 `true`，保证旧前端保存邮件设置时不带该字段也能正常反序列化。
    #[serde(default = "default_health_alert_enabled")]
    pub health_alert_enabled: bool,
    #[serde(default)]
    pub scanner_offline_enabled: bool,
    #[serde(default = "default_scanner_recovery_enabled")]
    pub scanner_recovery_enabled: bool,
}

fn default_scanner_recovery_enabled() -> bool {
    true
}

fn default_health_alert_enabled() -> bool {
    true
}

impl Default for NotificationPreferences {
    fn default() -> Self {
        Self {
            login_notify_enabled: true,
            notify_on_stuck: true,
            notify_on_complete: true,
            report_daily: false,
            report_weekly: true,
            report_monthly: false,
            health_alert_enabled: true,
            scanner_offline_enabled: false,
            scanner_recovery_enabled: true,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailSettingsRequest {
    /// 仅用于 SMTP 连通性测试和邮件模板测试，不作为真实通知的收件人。
    pub recipient: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub sender: String,
    #[serde(default)]
    pub sender_key: String,
    #[serde(default)]
    pub notification_prefs: NotificationPreferences,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailSettingsResponse {
    /// 仅用于 SMTP 连通性测试和邮件模板测试，不作为真实通知的收件人。
    pub recipient: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub sender: String,
    pub sender_key_configured: bool,
    pub notification_prefs: NotificationPreferences,
}

pub const DEFAULT_SESSION_TTL_SECONDS: i32 = 45 * 60;
pub const MIN_SESSION_TTL_MINUTES: i32 = 5;
pub const MAX_SESSION_TTL_MINUTES: i32 = 24 * 60;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSettingsRequest {
    pub default_scan_profile: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSettingsResponse {
    pub default_scan_profile: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSettingsRequest {
    pub session_ttl_minutes: i32,
    #[serde(default)]
    pub invalidate_other_sessions: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSettingsResponse {
    pub session_ttl_minutes: i32,
    pub minimum_minutes: i32,
    pub maximum_minutes: i32,
    pub invalidated_session_count: u64,
}

impl SessionSettingsResponse {
    pub fn new(session_ttl_seconds: i32, invalidated_session_count: u64) -> Self {
        Self {
            session_ttl_minutes: session_ttl_seconds / 60,
            minimum_minutes: MIN_SESSION_TTL_MINUTES,
            maximum_minutes: MAX_SESSION_TTL_MINUTES,
            invalidated_session_count,
        }
    }
}

pub fn session_ttl_seconds_from_minutes(minutes: i32) -> Result<i32, &'static str> {
    if !(MIN_SESSION_TTL_MINUTES..=MAX_SESSION_TTL_MINUTES).contains(&minutes) {
        return Err("会话有效期必须在 5 分钟到 24 小时之间");
    }
    minutes.checked_mul(60).ok_or("会话有效期超出允许范围")
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailTestRequest {
    pub recipient: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub sender: String,
    #[serde(default)]
    pub sender_key: String,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Self {
        Self::from_file_with_check(path)
            .expect("无法加载配置文件")
            .0
    }

    pub fn from_file_with_check<P: AsRef<Path>>(
        path: P,
    ) -> Result<(Self, crate::config_check::ConfigCheck), std::io::Error> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)?;
        // Error.message() omits source lines, which can contain credentials.
        let raw: serde_json::Value = toml::from_str(&content).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("配置文件格式错误：{}", error.message()),
            )
        })?;
        let report = crate::config_check::inspect_server(&raw);
        if report.error_count() > 0 {
            report.emit_startup();
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "缺少必需配置，请根据启动提示补齐参数",
            ));
        }
        let mut config: Self = toml::from_str(&content).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("配置字段无效：{}", error.message()),
            )
        })?;
        if config.scanner_diagnostics.directory.is_relative() {
            config.scanner_diagnostics.directory = path
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .join(&config.scanner_diagnostics.directory);
        }
        config.tls.resolve_relative_to(path);
        config.frontend.resolve_relative_to(path);
        config.maxmind.resolve_relative_to(path);
        config.backup.resolve_relative_to(path);
        config.elasticsearch.resolve_relative_to(path);
        config.report_renderer.resolve_relative_to(path);
        config
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AutomaticTargetConfig, BackupConfig, Clis, DatabaseConfig, ElasticsearchConfig,
        FrontendConfig, MaxMindConfig, MonitorConfig, NotificationPreferences, SecurityConfig,
        SelfChecking, TlsConfig, session_ttl_seconds_from_minutes,
    };
    use clap::Parser;
    use std::path::{Path, PathBuf};

    #[test]
    fn notification_preferences_default_health_alert_when_field_missing() {
        let prefs: NotificationPreferences = serde_json::from_value(serde_json::json!({
            "loginNotifyEnabled": true,
            "notifyOnStuck": true,
            "notifyOnComplete": true,
            "reportDaily": false,
            "reportWeekly": true,
            "reportMonthly": false
        }))
        .expect("旧前端缺少 healthAlertEnabled 时应能正常反序列化");
        assert!(prefs.health_alert_enabled);
        assert!(!prefs.scanner_offline_enabled);
        assert!(prefs.scanner_recovery_enabled);
    }

    #[test]
    fn database_connection_pool_size_must_be_positive() {
        let mut database = DatabaseConfig {
            host: "127.0.0.1".to_owned(),
            port: 5432,
            username: "network_mapping".to_owned(),
            password: "password".to_owned(),
            db_name: "network_mapping".to_owned(),
            pool_max_size: 10,
            pool_wait_timeout_ms: 2_000,
            pool_create_timeout_ms: 5_000,
            pool_recycle_timeout_ms: 3_000,
            tls: false,
            init_database_file: "source/database/init.sql".to_owned(),
            sql_file_path: "source/database".to_owned(),
        };

        assert!(database.try_check().expect("valid database config"));

        database.pool_max_size = 0;
        assert!(!database.try_check().expect("zero pool size is invalid"));

        database.pool_max_size = 10;
        database.pool_wait_timeout_ms = 0;
        assert!(
            !database
                .try_check()
                .expect("zero pool wait timeout is invalid")
        );
    }

    #[test]
    fn session_ttl_minutes_are_converted_and_bounded() {
        assert_eq!(session_ttl_seconds_from_minutes(45), Ok(2700));
        assert_eq!(session_ttl_seconds_from_minutes(5), Ok(300));
        assert_eq!(session_ttl_seconds_from_minutes(1440), Ok(86_400));
        assert!(session_ttl_seconds_from_minutes(4).is_err());
        assert!(session_ttl_seconds_from_minutes(1441).is_err());
    }

    #[test]
    fn tls_paths_are_resolved_relative_to_config_file() {
        let mut tls = TlsConfig {
            certificate_chain_file: PathBuf::from("ssl/cert.pem"),
            private_key_file: PathBuf::from("ssl/key.pem"),
        };

        tls.resolve_relative_to(Path::new("/etc/network-mapping/config.toml"));

        assert_eq!(
            tls.certificate_chain_file,
            PathBuf::from("/etc/network-mapping/ssl/cert.pem")
        );
        assert_eq!(
            tls.private_key_file,
            PathBuf::from("/etc/network-mapping/ssl/key.pem")
        );
    }

    #[test]
    fn absolute_tls_paths_are_unchanged() {
        let mut tls = TlsConfig {
            certificate_chain_file: PathBuf::from("/run/secrets/cert.pem"),
            private_key_file: PathBuf::from("/run/secrets/key.pem"),
        };

        tls.resolve_relative_to(Path::new("/etc/network-mapping/config.toml"));

        assert_eq!(
            tls.certificate_chain_file,
            PathBuf::from("/run/secrets/cert.pem")
        );
        assert_eq!(tls.private_key_file, PathBuf::from("/run/secrets/key.pem"));
    }

    #[test]
    fn backup_config_validates_allowlisted_stanza_and_resolves_config_path() {
        let mut backup = BackupConfig {
            enabled: true,
            config_file: Some(PathBuf::from("pgbackrest/pgbackrest.conf")),
            ..BackupConfig::default()
        };
        backup.resolve_relative_to(Path::new("/etc/network-mapping/config.toml"));
        assert_eq!(
            backup.config_file,
            Some(PathBuf::from(
                "/etc/network-mapping/pgbackrest/pgbackrest.conf"
            ))
        );
        assert!(matches!(backup.try_check(), Ok(true)));

        backup.stanza = "unsafe stanza".to_owned();
        assert!(backup.try_check().is_err());
    }

    #[test]
    fn backup_run_as_user_rejects_root_and_unsafe_names() {
        let mut backup = BackupConfig {
            enabled: true,
            run_as_user: Some("postgres".to_owned()),
            ..BackupConfig::default()
        };
        assert!(matches!(backup.try_check(), Ok(true)));

        backup.run_as_user = Some("root".to_owned());
        assert!(backup.try_check().is_err());
        backup.run_as_user = Some("postgres --preserve-env".to_owned());
        assert!(backup.try_check().is_err());
        backup.run_as_user = Some("#0".to_owned());
        assert!(backup.try_check().is_err());
        backup.run_as_user = Some("postgres".to_owned());
        backup.sudo_binary = PathBuf::from("sudo");
        assert!(backup.try_check().is_err());
    }

    #[test]
    fn frontend_directory_is_resolved_relative_to_config_file() {
        let mut frontend = FrontendConfig {
            directory: PathBuf::from("../frontend/dist"),
        };

        frontend.resolve_relative_to(Path::new("/etc/network-mapping/config.toml"));

        assert_eq!(
            frontend.directory,
            PathBuf::from("/etc/network-mapping/../frontend/dist")
        );
    }

    #[test]
    fn maxmind_directory_is_resolved_relative_to_config_file() {
        let mut maxmind = MaxMindConfig {
            directory: PathBuf::from("geoip"),
        };

        maxmind.resolve_relative_to(Path::new("/etc/network-mapping/config.toml"));

        assert_eq!(
            maxmind.directory,
            PathBuf::from("/etc/network-mapping/geoip")
        );
    }

    #[test]
    fn scanner_token_pepper_requires_sufficient_length() {
        let short = SecurityConfig {
            scanner_token_pepper: "too-short".into(),
        };
        let valid = SecurityConfig {
            scanner_token_pepper: "0123456789abcdef0123456789abcdef".into(),
        };

        assert!(short.try_check().is_err());
        assert!(valid.try_check().expect("valid pepper"));
    }

    #[test]
    fn terminal_logging_is_concise_by_default() {
        let cli = Clis::try_parse_from(["networkm"]).expect("default CLI should parse");

        assert!(!cli.terminal_verbose);
        assert!(!cli.refresh_ip_intel);
        assert!(!cli.migrate_scan_data_to_elasticsearch);
    }

    #[test]
    fn verbose_flag_enables_detailed_terminal_logging() {
        let cli =
            Clis::try_parse_from(["networkm", "--verbose"]).expect("verbose CLI flag should parse");

        assert!(cli.terminal_verbose);
    }

    #[test]
    fn refresh_ip_intel_is_migration_only() {
        let cli = Clis::try_parse_from([
            "networkm",
            "--refresh-ip-intel",
            "--migrate-scan-data-to-elasticsearch",
        ])
        .expect("refresh CLI flag should parse");

        assert!(Clis::try_parse_from(["networkm", "--refresh-ip-intel"]).is_err());
        assert!(Clis::try_parse_from(["networkm", "--rebuild-elasticsearch"]).is_err());
        assert!(cli.refresh_ip_intel);
    }

    #[test]
    fn elasticsearch_config_is_safe_by_default_and_supports_9_5_patches() {
        let mut config = ElasticsearchConfig::default();
        assert!(config.enabled);
        assert!(config.read_enabled);
        assert_eq!(config.scan_migration_concurrency, 4);
        assert!(config.scan_migration_page_size >= config.scan_migration_concurrency);
        assert_eq!(config.bulk_max_retries, 4);
        assert_eq!(config.scan_number_of_replicas, 0);
        assert_eq!(config.write_wait_for_active_shards, "1");
        assert_eq!(config.bulk_total_timeout_seconds, 25);
        assert_eq!(config.bulk_max_concurrency, 2);
        assert!(config.try_check().unwrap());

        config.enabled = true;
        assert_eq!(config.expected_version, "9.5.x");
        config.expected_version = "9.5.2".to_owned();
        assert!(config.try_check().unwrap());
        config.expected_version = "9.5.3".to_owned();
        assert!(config.try_check().unwrap());
        config.read_enabled = true;
        config.enabled = false;
        assert!(config.try_check().is_err());
    }

    #[test]
    fn elasticsearch_version_policy_rejects_unsupported_and_malformed_versions() {
        let mut config = ElasticsearchConfig::default();
        for version in ["9.5.0", "9.5.2", "9.5.3", "9.5.4", "9.5.123"] {
            assert!(config.validate_server_version(version).is_ok(), "{version}");
            config.expected_version = version.to_owned();
            assert!(config.try_check().unwrap());
            assert!(config.validate_server_version(version).is_ok());
            assert!(config.validate_server_version("9.5.124").is_ok());
            config.expected_version = "9.5.x".to_owned();
        }
        for version in [
            "",
            "9",
            "9.5",
            "9.5.x",
            "9.4.9",
            "9.6.0",
            "10.5.0",
            "9.50.0",
            "9.5.0-SNAPSHOT",
            "9.5.0-rc1",
            "9.5.3+build",
            "9.5.03",
            "9.5.-1",
            "9.5.+1",
            "9.5.3.0",
            " 9.5.3",
            "9.5.3 ",
            "9.5.18446744073709551616",
        ] {
            assert!(
                config.validate_server_version(version).is_err(),
                "{version}"
            );
            if version != "9.5.x" {
                config.expected_version = version.to_owned();
                assert!(config.try_check().is_err(), "{version}");
                assert!(config.validate_server_version("9.5.3").is_err());
                config.expected_version = "9.5.x".to_owned();
            }
        }
        // Old deployment configs accept patch upgrades without being edited.
        let legacy: ElasticsearchConfig = toml::from_str("expected_version = \"9.5.3\"").unwrap();
        assert!(legacy.try_check().unwrap());
        for version in ["9.5.0", "9.5.2", "9.5.3", "9.5.4", "9.5.123"] {
            assert!(legacy.validate_server_version(version).is_ok(), "{version}");
        }
        for version in ["9.4.9", "9.6.0", "10.0.0", "9.5.4-SNAPSHOT"] {
            assert!(
                legacy.validate_server_version(version).is_err(),
                "{version}"
            );
        }
        let omitted: ElasticsearchConfig = toml::from_str("").unwrap();
        assert_eq!(omitted.expected_version, "9.5.x");
    }

    #[test]
    fn projection_configuration_bounds_memory_and_lease_renewal() {
        let mut config = ElasticsearchConfig {
            enabled: true,
            read_enabled: true,
            ..Default::default()
        };
        assert!(config.try_check().unwrap());
        config.projection_heartbeat_seconds = config.projection_lease_seconds;
        assert!(config.try_check().is_err());
        config.projection_heartbeat_seconds = 20;
        config.projection_bulk_max_bytes = usize::MAX;
        assert!(config.try_check().is_err());
    }

    #[test]
    fn rejects_pg_dual_disabled_and_fallback_storage_configurations() {
        for mode in ["postgres", "dual"] {
            assert!(
                toml::from_str::<ElasticsearchConfig>(&format!("scan_storage = \"{mode}\""))
                    .is_err()
            );
        }
        for input in [
            "enabled = false",
            "read_enabled = false",
            "fallback_to_postgres = true",
        ] {
            let config: ElasticsearchConfig = toml::from_str(input).unwrap();
            assert!(config.try_check().is_err());
        }
        let config: ElasticsearchConfig = toml::from_str("").unwrap();
        assert!(config.try_check().is_ok());
    }

    #[test]
    fn elasticsearch_config_rejects_unsafe_scan_migration_limits() {
        let mut config = ElasticsearchConfig {
            enabled: true,
            scan_migration_concurrency: 0,
            ..ElasticsearchConfig::default()
        };
        assert!(config.try_check().is_err());

        config.scan_migration_concurrency = 8;
        config.scan_migration_page_size = 4;
        assert!(config.try_check().is_err());

        config.scan_migration_page_size = 100;
        config.bulk_max_retries = 11;
        assert!(config.try_check().is_err());

        config.bulk_max_retries = 4;
        config.bulk_retry_initial_ms = 0;
        assert!(config.try_check().is_err());

        config.bulk_retry_initial_ms = 200;
        config.bulk_total_timeout_seconds = 0;
        assert!(config.try_check().is_err());
        config.bulk_total_timeout_seconds = 25;
        config.bulk_max_concurrency = 0;
        assert!(config.try_check().is_err());
        config.bulk_max_concurrency = 2;
        config.write_wait_for_active_shards = "0".to_owned();
        assert!(config.try_check().is_err());
    }

    #[test]
    fn monitor_config_orders_elasticsearch_warning_and_critical_thresholds() {
        let mut config = MonitorConfig::default();
        assert!(config.try_check().is_ok());

        config.elasticsearch_query_critical_threshold_ms =
            config.elasticsearch_query_warning_threshold_ms - 1;
        assert!(config.try_check().is_err());

        config = MonitorConfig::default();
        config.elasticsearch_write_warning_threshold_ms = 0;
        assert!(config.try_check().is_err());
    }

    #[test]
    fn migrate_scan_data_flag_enables_one_off_migration() {
        let cli = Clis::try_parse_from(["networkm", "--migrate-scan-data-to-elasticsearch"])
            .expect("scan migration CLI flag should parse");
        assert!(cli.migrate_scan_data_to_elasticsearch);
    }

    #[test]
    fn automatic_target_requires_authorized_ipv4_ranges_when_enabled() {
        let mut config = AutomaticTargetConfig {
            enabled: true,
            ..AutomaticTargetConfig::default()
        };
        assert!(config.validate().is_err());

        config.authorized_cidrs = vec!["10.20.0.0/16".to_owned()];
        assert!(config.validate().is_ok());

        config.authorized_cidrs = vec!["2001:db8::/32".to_owned()];
        assert!(config.validate().is_err());

        config.authorized_cidrs = vec!["10.20.0.0/16".to_owned(), "10.20.1.0/24".to_owned()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn automatic_target_validates_ipv6_ranges_independently() {
        let mut config = AutomaticTargetConfig {
            ipv6_enabled: true,
            ..AutomaticTargetConfig::default()
        };
        assert!(config.validate().is_err());

        config.ipv6_authorized_cidrs = vec!["2001:db8::/64".to_owned()];
        assert!(config.validate().is_ok());

        config.ipv6_authorized_cidrs = vec!["10.0.0.0/8".to_owned()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn automatic_target_accepts_full_ipv6_range_with_bounded_task_subnets() {
        let config = AutomaticTargetConfig {
            ipv6_enabled: true,
            ipv6_authorized_cidrs: vec!["::/0".to_owned()],
            ipv6_task_prefix: 120,
            ..AutomaticTargetConfig::default()
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn automatic_target_rejects_an_unrepresentable_ipv6_cursor_space() {
        let config = AutomaticTargetConfig {
            ipv6_enabled: true,
            ipv6_authorized_cidrs: vec!["::/0".to_owned()],
            ipv6_task_prefix: 128,
            ..AutomaticTargetConfig::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn automatic_target_validates_exclusion_families_and_overlap() {
        let mut config = AutomaticTargetConfig {
            excluded_cidrs: vec!["10.0.0.0/8".to_owned()],
            ipv6_excluded_cidrs: vec!["fc00::/7".to_owned()],
            ..AutomaticTargetConfig::default()
        };
        assert!(config.validate().is_ok());

        config.excluded_cidrs = vec!["fc00::/7".to_owned()];
        assert!(config.validate().is_err());

        config.excluded_cidrs = vec!["10.0.0.0/8".to_owned(), "10.1.0.0/16".to_owned()];
        assert!(config.validate().is_err());
    }
}

/// Compatibility entry point; HTTP composition is owned by the transport layer.
pub fn init_routes(cfg: &mut web::ServiceConfig) {
    crate::http::configure(cfg);
}

#[derive(Serialize)]
pub enum ConfigType {
    None,
    SmtpConfig,
}

impl ConfigType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConfigType::None => "None",
            ConfigType::SmtpConfig => "smtp",
        }
    }
}

/// 系统配置
#[derive(FromRow, Serialize)]
pub struct SystemConfig {
    pub item_type: String,
    pub key: String,
    pub value: String,
    pub create_at: DateTime<chrono::Utc>,
    pub update_at: Option<DateTime<chrono::Utc>>,
}

impl SystemConfig {
    pub fn new() -> Self {
        SystemConfig {
            item_type: String::new(),
            key: String::new(),
            value: String::new(),
            create_at: DateTime::<Utc>::UNIX_EPOCH,
            update_at: None,
        }
    }

    /// 该函数返回的值为 nonce + tag + 密文
    ///
    /// 该函数可以直接更改 value
    pub fn encrypt(mut self, e_key: &str) -> Result<(), Box<dyn std::error::Error>> {
        let tmp_value = self.value;
        if tmp_value.is_empty() {
            Err("空值".into())
        } else {
            let (nonce, tag, ciphertext) = encrypt_data(tmp_value.as_bytes(), e_key.as_bytes())?;

            let mut encrypted = Vec::new();

            encrypted.extend_from_slice(&nonce);
            encrypted.extend_from_slice(&tag);
            encrypted.extend_from_slice(&ciphertext);
            self.value = openssl::base64::encode_block(&encrypted);

            Ok(())
        }
    }

    /// 函数
    pub fn decrypt(mut self, e_key: &str) -> Result<(), Box<dyn std::error::Error>> {
        let tmp_value = self.value;
        if tmp_value.is_empty() {
            Err("空值".into())
        } else {
            let v = openssl::base64::decode_block(&tmp_value)?;
            let t = decrypt_data(&v, e_key.as_bytes())?;
            self.value = openssl::base64::encode_block(&t);
            Ok(())
        }
    }
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Deserialize)]
pub struct GetConfig {
    pub item_type: String,
    pub key: Option<String>,
}

pub struct MailConfig {
    pub server_type: String,
    pub host: String,
    pub account_username: String,
    pub account_password: String,
}

#[derive(Parser, Debug)]
#[command(
    name = "networkm",
    version,
    about = "这是一个网络测绘系统的服务端，可用于向扫描器分发扫描任务，并接收扫描器上传的数据，然后存入数据库。"
)]
pub struct Clis {
    /// 配置文件路径
    #[arg(long, default_value = "config.toml")]
    pub config: String,

    /// 启用 DEBUG 日志级别和源码位置；完整终端日志还需配合 --verbose
    #[arg(short, long, default_value = "false")]
    pub debug_model: bool,

    /// 在终端输出完整日志；默认仅显示启动摘要、警告和错误
    #[arg(short = 'v', long = "verbose")]
    pub terminal_verbose: bool,

    /// 执行用户管理命令后退出；省略时启动服务
    #[command(subcommand)]
    pub command: Option<ServerCommand>,

    /// 重置指定管理员的密码，并在终端显示新的随机密码后退出
    #[arg(long, value_name = "USERNAME")]
    pub reset_admin_password: Option<String>,

    /// 在 PG -> ES 迁移前刷新尚未迁移的 PG 历史 IP 情报
    #[arg(long, requires = "migrate_scan_data_to_elasticsearch")]
    pub refresh_ip_intel: bool,

    /// 将 PostgreSQL 中现有扫描事实幂等迁移到新的 Elasticsearch 扫描索引后退出
    #[arg(long)]
    pub migrate_scan_data_to_elasticsearch: bool,

    /// 从所有已成功的 IP 扫描执行重建分析快照后退出；不会修改扫描原始事实
    #[arg(long)]
    pub rebuild_analytics_snapshots: bool,
}

#[derive(Debug, Subcommand)]
pub enum ServerCommand {
    /// 管理平台用户
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum UserCommand {
    /// 修改用户密码
    Password {
        #[command(subcommand)]
        command: PasswordCommand,
    },
    /// 管理用户双因素认证
    #[command(name = "2fa")]
    TwoFactor {
        #[command(subcommand)]
        command: TwoFactorCommand,
    },
    /// 管理登录 IP 白名单
    Allowlist {
        #[command(subcommand)]
        command: AllowlistCommand,
    },
    /// 管理用户登录限制
    Login {
        #[command(subcommand)]
        command: LoginAccessCommand,
    },
    /// 创建用户
    Create {
        username: String,
        #[arg(long, value_enum, default_value_t = UserRole::User)]
        role: UserRole,
        #[arg(long)]
        email: Option<String>,
        /// 从标准输入读取密码；默认从终端隐藏输入
        #[arg(long, conflicts_with = "generate")]
        password_stdin: bool,
        /// 生成随机密码并只在终端显示一次
        #[arg(long)]
        generate: bool,
    },
    /// 查看用户信息和会话
    Show {
        username: String,
        #[arg(long, value_enum, default_value_t = SessionSelection::Active)]
        sessions: SessionSelection,
    },
    /// 查看用户登录日志
    #[command(name = "login-log")]
    LoginLog {
        username: String,
        #[arg(long, value_enum)]
        outcome: Option<LoginOutcome>,
        /// 起始时间：RFC3339 或 Nd/Nh/Nm（例如 7d）
        #[arg(long)]
        since: Option<String>,
        /// 结束时间：RFC3339
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value_t = 100, conflicts_with = "all")]
        limit: usize,
        #[arg(long)]
        all: bool,
        #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
        format: OutputFormat,
        #[arg(long, value_enum, default_value_t = PagerMode::Auto)]
        pager: PagerMode,
    },
}

#[derive(Debug, Subcommand)]
pub enum PasswordCommand {
    Set {
        username: String,
        #[arg(long, conflicts_with = "generate")]
        password_stdin: bool,
        #[arg(long)]
        generate: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum TwoFactorCommand {
    Clear {
        username: String,
        /// 确认执行破坏性操作
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AllowlistCommand {
    List {
        username: String,
    },
    Add {
        username: String,
        #[arg(required = true)]
        entries: Vec<String>,
    },
    Remove {
        username: String,
        #[arg(required = true)]
        entries: Vec<String>,
        #[arg(long)]
        ignore_missing: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum LoginAccessCommand {
    Restrict {
        /// 逗号分隔的用户名，可重复传入
        #[arg(long, required = true, value_delimiter = ',')]
        users: Vec<String>,
        #[arg(long)]
        dry_run: bool,
    },
    Unrestrict {
        /// 逗号分隔的用户名，可重复传入
        #[arg(long, required = true, value_delimiter = ',')]
        users: Vec<String>,
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum UserRole {
    Admin,
    User,
}

impl UserRole {
    pub fn database_value(self) -> i32 {
        match self {
            Self::Admin => 1,
            Self::User => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum SessionSelection {
    Active,
    All,
    None,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum LoginOutcome {
    Success,
    Failure,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
    Csv,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum PagerMode {
    #[default]
    Auto,
    Always,
    Never,
}

#[cfg(test)]
mod cli_tests {
    use clap::Parser;

    use super::{Clis, LoginAccessCommand, ServerCommand, UserCommand};

    #[test]
    fn no_subcommand_keeps_server_startup_mode() {
        let cli = Clis::try_parse_from(["networkm"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn parses_comma_delimited_login_restrictions() {
        let cli = Clis::try_parse_from([
            "networkm",
            "user",
            "login",
            "restrict",
            "--users",
            "alice,bob",
        ])
        .unwrap();
        let Some(ServerCommand::User {
            command:
                UserCommand::Login {
                    command: LoginAccessCommand::Restrict { users, .. },
                },
        }) = cli.command
        else {
            panic!("unexpected command tree");
        };
        assert_eq!(users, ["alice", "bob"]);
    }
}
