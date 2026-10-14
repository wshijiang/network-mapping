//! 可由管理员发布的运行时配置。
//!
//! `config.toml` 仅作为首次初始化/数据库配置缺失时的安全默认值。成功发布后，
//! PostgreSQL 中的文档和 revision 是权威来源；进程内只读取已校验的快照。

use std::sync::Arc;

use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use tokio::sync::{RwLock, watch};
use tracing::{info, warn};

use crate::config::{
    AnalyticsSnapshotConfig, AutomaticTargetConfig, MonitorConfig, RequestsConfig, SelfChecking,
};
use crate::dns_follow_up::DnsFollowUpConfig;
use crate::dns_resolvers::DnsResolverSettings;

pub const GENERAL_NAMESPACE: &str = "general";

pub const REQUESTS_NAMESPACE: &str = "requests";
pub const SCANNER_HEALTH_NAMESPACE: &str = "scanner_health";
pub const MONITOR_NAMESPACE: &str = "monitor";
pub const SCAN_ROUTING_NAMESPACE: &str = "scan_routing";

pub const AUTOMATIC_TARGET_NAMESPACE: &str = "automatic_target";
pub const DNS_FOLLOW_UP_NAMESPACE: &str = "dns_follow_up";
pub const DNS_RESOLVERS_NAMESPACE: &str = "dns_resolvers";
pub const REPORT_MAIL_NAMESPACE: &str = crate::reports::mail_config::NAMESPACE;

pub const ANALYTICS_SNAPSHOT_NAMESPACE: &str = "analytics_snapshot";

#[derive(Clone, Debug)]
pub struct Versioned<T> {
    pub value: T,
    pub revision: i64,
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig<T> {
    value: Arc<RwLock<Versioned<T>>>,
    revisions: watch::Sender<i64>,
}

impl<T: Clone> RuntimeConfig<T> {
    pub fn new(value: T, revision: i64) -> Self {
        let (revisions, _) = watch::channel(revision);
        Self {
            value: Arc::new(RwLock::new(Versioned { value, revision })),
            revisions,
        }
    }

    pub async fn get(&self) -> Versioned<T> {
        self.value.read().await.clone()
    }

    pub async fn replace(&self, value: T, revision: i64) {
        let mut current = self.value.write().await;
        if revision > current.revision {
            *current = Versioned { value, revision };
            self.revisions.send_replace(revision);
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<i64> {
        self.revisions.subscribe()
    }
}

#[derive(Clone)]
pub struct RuntimeSettings {
    pub statistics_cache: RuntimeConfig<crate::statistics::CacheConfig>,
    pub general: RuntimeConfig<crate::system_time::GeneralSettings>,
    pub requests: RuntimeConfig<RequestsConfig>,
    pub monitor: RuntimeConfig<MonitorConfig>,
    pub scanner_health: RuntimeConfig<crate::scanner_health::ScannerHealthConfig>,
    pub scan_routing: RuntimeConfig<crate::scan_control::routing::RoutingConfig>,
    pub automatic_target: RuntimeConfig<AutomaticTargetConfig>,
    pub dns_follow_up: RuntimeConfig<DnsFollowUpConfig>,
    pub dns_resolvers: RuntimeConfig<DnsResolverSettings>,
    pub analytics_snapshot: RuntimeConfig<AnalyticsSnapshotConfig>,
    pub report_mail: RuntimeConfig<crate::reports::mail_config::ReportMailConfig>,
}

#[derive(Clone)]
pub struct RuntimeSettingsBootstrap {
    pub requests: RequestsConfig,
    pub monitor: MonitorConfig,
    pub automatic_target: AutomaticTargetConfig,
    pub dns_follow_up: DnsFollowUpConfig,
    pub dns_resolvers: DnsResolverSettings,
    pub analytics_snapshot: AnalyticsSnapshotConfig,
    pub report_mail: crate::reports::mail_config::ReportMailConfig,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRuntimeConfigRequest {
    pub expected_revision: i64,
    pub document: Value,
    #[serde(default)]
    pub change_reason: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeConfigResponse<T> {
    pub namespace: &'static str,
    pub revision: i64,
    pub document: T,
}

impl RuntimeSettings {
    /// Refresh only the new policy domains; never replace a validated snapshot
    /// with an invalid document or an older revision from a racing publisher.
    pub async fn refresh_health(
        &self,
        pool: &Pool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = pool.get().await?;
        let rows = client.query("SELECT namespace, document, revision FROM runtime_configuration WHERE namespace IN ('monitor', 'scanner_health', 'scan_routing', 'automatic_target');", &[]).await?;
        for row in rows {
            let namespace: String = row.get("namespace");
            let document: Value = row.get("document");
            let revision: i64 = row.get("revision");
            match namespace.as_str() {
                MONITOR_NAMESPACE => {
                    self.monitor
                        .replace(
                            parse_monitor(document).map_err(std::io::Error::other)?,
                            revision,
                        )
                        .await
                }
                SCANNER_HEALTH_NAMESPACE => {
                    self.scanner_health
                        .replace(
                            parse_scanner_health(document).map_err(std::io::Error::other)?,
                            revision,
                        )
                        .await
                }
                SCAN_ROUTING_NAMESPACE => {
                    self.scan_routing
                        .replace(
                            parse_scan_routing(document).map_err(std::io::Error::other)?,
                            revision,
                        )
                        .await
                }
                AUTOMATIC_TARGET_NAMESPACE => {
                    self.automatic_target
                        .replace(
                            parse_automatic_target(document).map_err(std::io::Error::other)?,
                            revision,
                        )
                        .await
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub async fn load(
        pool: &Pool,
        bootstrap: RuntimeSettingsBootstrap,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let general = load_namespace(
            pool,
            GENERAL_NAMESPACE,
            crate::system_time::GeneralSettings::default(),
            crate::system_time::GeneralSettings::default(),
            crate::system_time::GeneralSettings::validate,
        )
        .await?;
        let loaded = general.get().await;
        crate::system_time::apply(loaded.value, loaded.revision);
        Ok(Self {
            statistics_cache: load_namespace(
                pool,
                crate::statistics::NAMESPACE,
                Default::default(),
                Default::default(),
                crate::statistics::CacheConfig::validate,
            )
            .await?,
            general,
            requests: load_namespace(
                pool,
                REQUESTS_NAMESPACE,
                bootstrap.requests.clone(),
                bootstrap.requests,
                validate_requests,
            )
            .await?,
            monitor: load_namespace(
                pool,
                MONITOR_NAMESPACE,
                bootstrap.monitor.clone(),
                bootstrap.monitor,
                validate_monitor,
            )
            .await?,
            scanner_health: load_namespace(
                pool,
                SCANNER_HEALTH_NAMESPACE,
                Default::default(),
                Default::default(),
                crate::scanner_health::ScannerHealthConfig::validate,
            )
            .await?,
            scan_routing: load_namespace(
                pool,
                SCAN_ROUTING_NAMESPACE,
                Default::default(),
                Default::default(),
                crate::scan_control::routing::RoutingConfig::validate,
            )
            .await?,
            automatic_target: load_namespace(
                pool,
                AUTOMATIC_TARGET_NAMESPACE,
                bootstrap.automatic_target,
                AutomaticTargetConfig::default(),
                validate_automatic_target,
            )
            .await?,
            dns_follow_up: load_namespace(
                pool,
                DNS_FOLLOW_UP_NAMESPACE,
                bootstrap.dns_follow_up.clone(),
                DnsFollowUpConfig::default(),
                validate_dns_follow_up,
            )
            .await?,
            dns_resolvers: load_namespace(
                pool,
                DNS_RESOLVERS_NAMESPACE,
                bootstrap.dns_resolvers,
                DnsResolverSettings::default(),
                validate_dns_resolvers,
            )
            .await?,
            report_mail: load_namespace(
                pool,
                REPORT_MAIL_NAMESPACE,
                bootstrap.report_mail,
                Default::default(),
                crate::reports::mail_config::ReportMailConfig::validate,
            )
            .await?,
            analytics_snapshot: load_namespace(
                pool,
                ANALYTICS_SNAPSHOT_NAMESPACE,
                bootstrap.analytics_snapshot.clone(),
                bootstrap.analytics_snapshot,
                validate_analytics_snapshot,
            )
            .await?,
        })
    }
}

async fn load_namespace<T>(
    pool: &Pool,
    namespace: &'static str,
    bootstrap: T,
    invalid_fallback: T,
    validate: fn(&T) -> Result<(), String>,
) -> Result<RuntimeConfig<T>, Box<dyn std::error::Error + Send + Sync>>
where
    T: Clone + Serialize + DeserializeOwned,
{
    let client = pool.get().await?;
    let document = serde_json::to_value(&bootstrap)?;
    client.execute(
        "INSERT INTO runtime_configuration (namespace, document) VALUES ($1, $2) ON CONFLICT (namespace) DO NOTHING;",
        &[&namespace, &document],
    ).await?;
    // 首次插入也需要保留可回滚的 revision 1；已存在时不重复写入。
    client.execute(
        "INSERT INTO runtime_configuration_revision (namespace, revision, schema_version, document, change_reason) \
         SELECT namespace, revision, schema_version, document, 'initial TOML seed' FROM runtime_configuration \
         WHERE namespace = $1 ON CONFLICT (namespace, revision) DO NOTHING;",
        &[&namespace],
    ).await?;
    let row = client
        .query_one(
            "SELECT document, revision FROM runtime_configuration WHERE namespace = $1;",
            &[&namespace],
        )
        .await?;
    let revision = row.get::<_, i64>("revision");
    let persisted = row.get::<_, Value>("document");
    match serde_json::from_value::<T>(persisted) {
        Ok(value) if validate(&value).is_ok() => Ok(RuntimeConfig::new(value, revision)),
        Ok(_) | Err(_) if namespace == GENERAL_NAMESPACE => {
            Err("数据库常规设置无效，无法确定系统业务时区".into())
        }
        Ok(_) | Err(_) => {
            warn!(namespace, "数据库运行时配置无效，已使用安全默认值");
            Ok(RuntimeConfig::new(invalid_fallback, revision))
        }
    }
}

pub async fn persist<T>(
    pool: &Pool,
    namespace: &'static str,
    expected_revision: i64,
    value: &T,
    change_reason: &str,
    user_id: i32,
) -> Result<i64, PersistError>
where
    T: Serialize,
{
    let document =
        serde_json::to_value(value).map_err(|error| PersistError::Other(error.to_string()))?;
    let mut client = pool
        .get()
        .await
        .map_err(|error| PersistError::Other(error.to_string()))?;
    let transaction = client
        .transaction()
        .await
        .map_err(|error| PersistError::Other(error.to_string()))?;
    let previous = if namespace == GENERAL_NAMESPACE {
        transaction
            .query_opt(
                "SELECT document FROM runtime_configuration WHERE namespace = $1 FOR UPDATE;",
                &[&namespace],
            )
            .await
            .map_err(|e| PersistError::Other(e.to_string()))?
            .map(|r| r.get::<_, Value>("document"))
    } else {
        None
    };
    let row = transaction.query_opt(
        "UPDATE runtime_configuration SET document = $1, revision = revision + 1, updated_at = NOW(), updated_by_user_id = $2 \
         WHERE namespace = $3 AND revision = $4 RETURNING revision, schema_version;",
        &[&document, &user_id, &namespace, &expected_revision],
    ).await.map_err(|error| PersistError::Other(error.to_string()))?;
    let Some(row) = row else {
        return Err(PersistError::Conflict);
    };
    let revision = row.get::<_, i64>("revision");
    let schema_version = row.get::<_, i32>("schema_version");
    transaction.execute(
        "INSERT INTO runtime_configuration_revision (namespace, revision, schema_version, document, changed_by_user_id, change_reason) \
         VALUES ($1, $2, $3, $4, $5, $6);",
        &[&namespace, &revision, &schema_version, &document, &user_id, &change_reason],
    ).await.map_err(|error| PersistError::Other(error.to_string()))?;
    if previous
        .as_ref()
        .is_some_and(|old| old["timezone"] != document["timezone"])
    {
        // New calendar rules start from this publication; do not re-send old periods.
        transaction.execute("UPDATE report_schedule SET enabled_at = CASE WHEN enabled THEN NOW() ELSE enabled_at END, last_period_end = NULL, revision = revision + 1, updated_at = NOW();", &[]).await.map_err(|e| PersistError::Other(e.to_string()))?;
    }
    transaction
        .commit()
        .await
        .map_err(|error| PersistError::Other(error.to_string()))?;
    info!(namespace, revision, "运行时配置已发布");
    Ok(revision)
}

#[derive(Debug)]
pub enum PersistError {
    Conflict,
    Other(String),
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict => f.write_str("configuration revision conflict"),
            Self::Other(error) => f.write_str(error),
        }
    }
}
impl std::error::Error for PersistError {}

fn validate_requests(value: &RequestsConfig) -> Result<(), String> {
    value
        .try_check()
        .map(|_| ())
        .map_err(|error| error.to_string())
}
fn validate_monitor(value: &MonitorConfig) -> Result<(), String> {
    value
        .try_check()
        .map(|_| ())
        .map_err(|error| error.to_string())
}
fn validate_automatic_target(value: &AutomaticTargetConfig) -> Result<(), String> {
    value.validate().map_err(|error| error.to_string())
}
fn validate_dns_follow_up(value: &DnsFollowUpConfig) -> Result<(), String> {
    value.validate().map_err(|error| error.to_string())
}
fn validate_dns_resolvers(value: &DnsResolverSettings) -> Result<(), String> {
    value.validate()
}
fn validate_analytics_snapshot(value: &AnalyticsSnapshotConfig) -> Result<(), String> {
    value
        .try_check()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

pub fn parse_general(value: Value) -> Result<crate::system_time::GeneralSettings, String> {
    parse(value, crate::system_time::GeneralSettings::validate)
}

pub fn parse_requests(value: Value) -> Result<RequestsConfig, String> {
    parse(value, validate_requests)
}
pub fn parse_scanner_health(
    value: Value,
) -> Result<crate::scanner_health::ScannerHealthConfig, String> {
    parse(value, crate::scanner_health::ScannerHealthConfig::validate)
}

pub fn parse_monitor(value: Value) -> Result<MonitorConfig, String> {
    let mut config: MonitorConfig = parse(value, validate_monitor)?;
    // Keep legacy metadata meaningful after editing a service default in the UI.
    use crate::monitor::rules::MonitorService;
    config.slow_request_threshold_ms = config
        .default_rule(MonitorService::WebApi)
        .warning_threshold_ms;
    config.slow_sql_threshold_ms = config
        .default_rule(MonitorService::Postgresql)
        .warning_threshold_ms;
    let query = config.default_rule(MonitorService::ElasticsearchQuery);
    config.elasticsearch_query_warning_threshold_ms = query.warning_threshold_ms;
    config.elasticsearch_query_critical_threshold_ms = query
        .critical_threshold_ms
        .unwrap_or(query.warning_threshold_ms);
    let write = config.default_rule(MonitorService::ElasticsearchWrite);
    config.elasticsearch_write_warning_threshold_ms = write.warning_threshold_ms;
    config.elasticsearch_write_critical_threshold_ms = write
        .critical_threshold_ms
        .unwrap_or(write.warning_threshold_ms);
    Ok(config)
}
pub fn parse_scan_routing(
    value: Value,
) -> Result<crate::scan_control::routing::RoutingConfig, String> {
    parse(value, crate::scan_control::routing::RoutingConfig::validate)
}

pub fn parse_automatic_target(value: Value) -> Result<AutomaticTargetConfig, String> {
    parse(value, validate_automatic_target)
}
pub fn parse_dns_follow_up(value: Value) -> Result<DnsFollowUpConfig, String> {
    parse(value, validate_dns_follow_up)
}
pub fn parse_dns_resolvers(value: Value) -> Result<DnsResolverSettings, String> {
    parse(value, validate_dns_resolvers)
}
pub fn parse_report_mail(
    value: Value,
) -> Result<crate::reports::mail_config::ReportMailConfig, String> {
    parse(
        value,
        crate::reports::mail_config::ReportMailConfig::validate,
    )
}

pub fn parse_analytics_snapshot(value: Value) -> Result<AnalyticsSnapshotConfig, String> {
    parse(value, validate_analytics_snapshot)
}

fn parse<T>(value: Value, validate: fn(&T) -> Result<(), String>) -> Result<T, String>
where
    T: DeserializeOwned,
{
    let parsed = serde_json::from_value(value).map_err(|error| error.to_string())?;
    validate(&parsed)?;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{RuntimeConfig, parse_dns_follow_up, parse_requests};
    use crate::config::RequestsConfig;

    #[test]
    fn rejects_invalid_runtime_documents_before_persistence() {
        assert!(parse_requests(json!({"enabled": true, "retention_days": 0})).is_err());
        assert!(
            parse_dns_follow_up(json!({
                "enabled": true,
                "authorized_cidrs": [],
                "excluded_cidrs": [],
                "max_targets_per_task": 100
            }))
            .is_err()
        );
    }

    #[tokio::test]
    async fn replacement_is_immediately_visible_with_new_revision() {
        let config = RuntimeConfig::new(RequestsConfig::default(), 1);
        config
            .replace(
                RequestsConfig {
                    enabled: false,
                    retention_days: 14,
                },
                2,
            )
            .await;
        let loaded = config.get().await;
        assert_eq!(loaded.revision, 2);
        assert!(!loaded.value.enabled);
        assert_eq!(loaded.value.retention_days, 14);
    }
}
