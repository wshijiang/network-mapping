//! 健康监控与告警：慢请求、5xx、PostgreSQL 慢 SQL 和 Elasticsearch 慢操作。
//!
//! 检测分三类来源：
//! - 请求级：`main.rs` 的请求中间件在响应后按状态码与耗时实时判定，投递到有界 channel；
//! - 数据库级：[`slow_sql`] 后台任务轮询 `pg_stat_statements` 视图。
//! - Elasticsearch：统一请求入口上报端到端耗时、响应状态和分片结果。
//!
//! 三类信号统一由 [`run_notifier`] 消费，做冷却去重后复用邮件模板系统发送给管理员。

#[cfg(test)]
pub(crate) mod policy_tests;
mod routes;
pub mod rules;
mod slow_sql;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use deadpool_postgres::Pool;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::config::MonitorConfig;
use crate::logs::write::error_diagnostics;
use crate::mail_template;
use crate::runtime_config::Versioned;
use rules::{AppliedRule, MonitorService};

pub const CHANNEL_CAPACITY: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ElasticsearchOperationKind {
    Query,
    Write,
    Maintenance,
}

#[derive(Clone, Debug)]
pub(crate) struct ElasticsearchObservation {
    pub operation: &'static str,
    pub kind: ElasticsearchOperationKind,
    pub duration_ms: i64,
    pub es_took_ms: Option<i64>,
    pub http_status: Option<u16>,
    pub timed_out: bool,
    pub failed_shards: i64,
    pub trace_id: String,
    pub failure_kind: Option<&'static str>,
}

/// 一条健康告警事件。去重 key 相同的事件在冷却窗口内会被合并丢弃。
#[derive(Debug, Clone)]
pub struct HealthEvent {
    pub alert_type: &'static str,
    pub severity: &'static str,
    pub key: String,
    pub summary: String,
    pub details: Vec<(String, String)>,
    pub applied_rule: Option<AppliedRule>,
}

struct SlowSqlObservation<'a> {
    queryid: i64,
    query: &'a str,
    mean_exec_time_ms: f64,
    max_exec_time_ms: f64,
    calls_delta: i64,
    total_exec_time_ms: f64,
    rows_delta: i64,
    shared_blks_hit_delta: i64,
    shared_blks_read_delta: i64,
    temp_blks_read_delta: i64,
    temp_blks_written_delta: i64,
}

impl HealthEvent {
    pub fn with_rule(mut self, applied: AppliedRule) -> Self {
        self.details.extend([
            ("命中规则".into(), applied.source.clone()),
            (
                "警告阈值".into(),
                format!("{} ms", applied.rule.warning_threshold_ms),
            ),
            (
                "严重阈值".into(),
                applied
                    .rule
                    .critical_threshold_ms
                    .map(|ms| format!("{ms} ms"))
                    .unwrap_or_else(|| "未启用".into()),
            ),
            (
                "冷却时间".into(),
                format!("{} 秒", applied.rule.cooldown_seconds),
            ),
            ("配置版本".into(), applied.revision.to_string()),
        ]);
        self.applied_rule = Some(applied);
        self
    }

    pub fn slow_request(
        method: &str,
        path: &str,
        status: u16,
        duration_ms: i64,
        request_id: Uuid,
        client_ip: Option<String>,
        actor_name: Option<String>,
    ) -> Self {
        Self {
            applied_rule: None,
            alert_type: "slow_request",
            severity: "warning",
            key: format!("slow_request:{method}:{path}"),
            summary: format!("请求耗时 {duration_ms}ms 超过阈值：{method} {path}"),
            details: request_details(
                method,
                path,
                status,
                Some(duration_ms),
                request_id,
                client_ip,
                actor_name,
            ),
        }
    }

    pub fn server_error(
        method: &str,
        path: &str,
        status: u16,
        duration_ms: Option<i64>,
        request_id: Uuid,
        client_ip: Option<String>,
        actor_name: Option<String>,
    ) -> Self {
        Self {
            applied_rule: None,
            alert_type: "server_error",
            severity: "critical",
            key: format!("server_error:{path}:{status}"),
            summary: format!("服务端错误 {status}：{method} {path}"),
            details: request_details(
                method,
                path,
                status,
                duration_ms,
                request_id,
                client_ip,
                actor_name,
            ),
        }
    }

    fn slow_sql(observation: &SlowSqlObservation<'_>) -> Self {
        let SlowSqlObservation {
            queryid,
            query,
            mean_exec_time_ms,
            max_exec_time_ms,
            calls_delta,
            total_exec_time_ms,
            rows_delta,
            shared_blks_hit_delta,
            shared_blks_read_delta,
            temp_blks_read_delta,
            temp_blks_written_delta,
        } = observation;
        let query_text = if query.is_empty() {
            format!("queryid={queryid}")
        } else {
            query.chars().take(2000).collect()
        };
        Self {
            applied_rule: None,
            alert_type: "slow_sql",
            severity: "warning",
            key: format!("slow_sql:{queryid}"),
            summary: format!(
                "检测到慢 SQL（本周期平均 {mean_exec_time_ms:.1}ms，历史峰值 {max_exec_time_ms:.1}ms）"
            ),
            details: vec![
                ("查询".to_owned(), query_text),
                (
                    "本周期平均耗时".to_owned(),
                    format!("{mean_exec_time_ms:.1} ms"),
                ),
                (
                    "本周期总耗时".to_owned(),
                    format!("{total_exec_time_ms:.1} ms"),
                ),
                (
                    "历史峰值耗时".to_owned(),
                    format!("{max_exec_time_ms:.1} ms"),
                ),
                ("本周期调用次数".to_owned(), calls_delta.to_string()),
                ("本周期返回行数".to_owned(), rows_delta.to_string()),
                (
                    "本周期共享块命中".to_owned(),
                    shared_blks_hit_delta.to_string(),
                ),
                (
                    "本周期共享块读取".to_owned(),
                    shared_blks_read_delta.to_string(),
                ),
                (
                    "本周期临时块读取".to_owned(),
                    temp_blks_read_delta.to_string(),
                ),
                (
                    "本周期临时块写入".to_owned(),
                    temp_blks_written_delta.to_string(),
                ),
            ],
        }
    }

    fn elasticsearch(observation: &ElasticsearchObservation, severity: &'static str) -> Self {
        let operation_kind = match observation.kind {
            ElasticsearchOperationKind::Query => "query",
            ElasticsearchOperationKind::Write => "write",
            ElasticsearchOperationKind::Maintenance => "maintenance",
        };
        let failed = observation.failure_kind.is_some()
            || observation.http_status.is_some_and(|status| status >= 400)
            || observation.timed_out
            || observation.failed_shards > 0;
        let alert_type = match (operation_kind, failed) {
            ("query", false) => "slow_elasticsearch_query",
            ("write", false) => "slow_elasticsearch_write",
            ("query", true) => "elasticsearch_query_error",
            ("write", true) => "elasticsearch_write_error",
            (_, _) => "elasticsearch_error",
        };
        let summary = if failed {
            format!(
                "Elasticsearch {} {} 失败或返回异常（{}ms）",
                operation_kind, observation.operation, observation.duration_ms
            )
        } else {
            format!(
                "Elasticsearch {} {} 耗时 {}ms",
                operation_kind, observation.operation, observation.duration_ms
            )
        };
        let mut details = vec![
            ("操作".to_owned(), observation.operation.to_owned()),
            ("类型".to_owned(), operation_kind.to_owned()),
            (
                "服务端总耗时".to_owned(),
                format!("{} ms", observation.duration_ms),
            ),
            (
                "Elasticsearch took".to_owned(),
                observation
                    .es_took_ms
                    .map(|value| format!("{value} ms"))
                    .unwrap_or_else(|| "未知".to_owned()),
            ),
            (
                "应用额外耗时".to_owned(),
                observation
                    .es_took_ms
                    .map(|value| {
                        format!(
                            "{} ms",
                            observation.duration_ms.saturating_sub(value).max(0)
                        )
                    })
                    .unwrap_or_else(|| "未知".to_owned()),
            ),
            (
                "HTTP 状态".to_owned(),
                observation
                    .http_status
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "无响应".to_owned()),
            ),
            ("是否超时".to_owned(), observation.timed_out.to_string()),
            ("失败分片".to_owned(), observation.failed_shards.to_string()),
            ("Trace ID".to_owned(), observation.trace_id.clone()),
        ];
        if let Some(failure_kind) = observation.failure_kind {
            details.push(("失败类型".to_owned(), failure_kind.to_owned()));
        }
        Self {
            applied_rule: None,
            alert_type,
            severity,
            key: format!("{alert_type}:{}", observation.operation),
            summary,
            details,
        }
    }
}

fn request_details(
    method: &str,
    path: &str,
    status: u16,
    duration_ms: Option<i64>,
    request_id: Uuid,
    client_ip: Option<String>,
    actor_name: Option<String>,
) -> Vec<(String, String)> {
    vec![
        ("请求方法".to_owned(), method.to_owned()),
        ("请求路径".to_owned(), path.to_owned()),
        ("状态码".to_owned(), status.to_string()),
        (
            "耗时".to_owned(),
            duration_ms
                .map(|value| format!("{value} ms"))
                .unwrap_or_else(|| "未知".to_owned()),
        ),
        ("请求 ID".to_owned(), request_id.to_string()),
        (
            "来源 IP".to_owned(),
            client_ip.unwrap_or_else(|| "未知".to_owned()),
        ),
        (
            "操作者".to_owned(),
            actor_name.unwrap_or_else(|| "匿名/扫描器".to_owned()),
        ),
    ]
}

/// 健康监控句柄：请求中间件通过 [`MonitorHandle::emit`] 投递事件；`None` 表示监控已关闭。
#[derive(Clone)]
pub struct MonitorHandle {
    tx: mpsc::Sender<HealthEvent>,
    config: Arc<RwLock<Versioned<MonitorConfig>>>,
    dropped_events: Arc<AtomicU64>,
    revisions: tokio::sync::watch::Sender<i64>,
}

impl MonitorHandle {
    /// Compatibility constructor for callers that own their Tokio runtime.
    pub fn new(config: Versioned<MonitorConfig>, pool: Pool, encryption_key: String) -> Self {
        Self::build(config, pool, encryption_key, |_, task| {
            tokio::spawn(task);
        })
    }

    pub fn new_managed(
        config: Versioned<MonitorConfig>,
        pool: Pool,
        encryption_key: String,
        background: &mut crate::application::background::BackgroundServices,
    ) -> Self {
        Self::build(config, pool, encryption_key, |name, task| {
            background.spawn(name, task)
        })
    }

    fn build(
        config: Versioned<MonitorConfig>,
        pool: Pool,
        encryption_key: String,
        mut spawn: impl FnMut(&'static str, futures_util::future::BoxFuture<'static, ()>),
    ) -> Self {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (revisions, _) = tokio::sync::watch::channel(config.revision);
        let config = Arc::new(RwLock::new(config));
        spawn(
            "monitor-notifier",
            Box::pin(run_notifier(
                rx,
                pool.clone(),
                encryption_key,
                config.clone(),
            )),
        );
        spawn(
            "slow-sql-monitor",
            Box::pin(slow_sql::run_monitor(
                pool,
                tx.clone(),
                config.clone(),
                revisions.subscribe(),
            )),
        );
        info!(target: "server::startup", component = "monitor", "健康监控任务已启动");
        Self {
            tx,
            config,
            dropped_events: Arc::new(AtomicU64::new(0)),
            revisions,
        }
    }

    pub fn replace_config(&self, config: MonitorConfig, revision: i64) {
        let mut current = self
            .config
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if revision > current.revision {
            *current = Versioned {
                value: config,
                revision,
            };
            self.revisions.send_replace(revision);
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .value
            .enabled
    }

    pub fn classify_request(
        &self,
        method: &str,
        route: &str,
        duration_ms: i64,
    ) -> Option<AppliedRule> {
        let current = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !current.value.enabled {
            return None;
        }
        let applied = current.value.resolve_rule(
            MonitorService::WebApi,
            &format!("{method} {route}"),
            current.revision,
        );
        applied.rule.severity(duration_ms as f64).map(|_| applied)
    }

    /// 是否启用 5xx 服务端错误告警。
    pub fn server_error_enabled(&self) -> bool {
        let config = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        config.value.enabled && config.value.server_error_enabled
    }

    /// 非阻塞投递一条告警事件；channel 满时直接丢弃，绝不阻塞请求路径。
    pub fn emit(&self, event: HealthEvent) {
        if self.tx.try_send(event).is_err() {
            let dropped = self.dropped_events.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped.is_power_of_two() {
                warn!(
                    event = "HealthAlertChannelFull",
                    dropped_events = dropped,
                    "健康告警队列已满，事件被丢弃"
                );
            }
        }
    }

    pub(crate) fn observe_elasticsearch(&self, observation: ElasticsearchObservation) {
        if observation.kind == ElasticsearchOperationKind::Maintenance {
            return;
        }
        let config = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !config.value.enabled {
            return;
        }
        let service = match observation.kind {
            ElasticsearchOperationKind::Query => MonitorService::ElasticsearchQuery,
            ElasticsearchOperationKind::Write => MonitorService::ElasticsearchWrite,
            ElasticsearchOperationKind::Maintenance => return,
        };
        let applied = config
            .value
            .resolve_rule(service, observation.operation, config.revision);
        let failed = observation.failure_kind.is_some()
            || observation.http_status.is_some_and(|status| status >= 400)
            || observation.timed_out
            || observation.failed_shards > 0;
        let severity = if failed {
            "critical"
        } else {
            let Some(severity) = applied.rule.severity(observation.duration_ms as f64) else {
                return;
            };
            severity
        };
        drop(config);
        warn!(
            event = "ElasticsearchSlowOperation",
            operation = observation.operation,
            operation_kind = ?observation.kind,
            duration_ms = observation.duration_ms,
            es_took_ms = observation.es_took_ms,
            http_status = observation.http_status,
            timed_out = observation.timed_out,
            failed_shards = observation.failed_shards,
            trace_id = %observation.trace_id,
            failure_kind = observation.failure_kind,
            "Elasticsearch 操作达到告警条件"
        );
        self.emit(HealthEvent::elasticsearch(&observation, severity).with_rule(applied));
    }
}

/// Atomically persist history and bot fanout after a cross-instance cooldown check.
pub(crate) async fn record_health_alert(
    pool: &Pool,
    event: &HealthEvent,
    cooldown_seconds: i64,
) -> Result<bool, Box<dyn std::error::Error>> {
    let details = event
        .details
        .iter()
        .map(|(label, value)| serde_json::json!({ "label": label, "value": value }))
        .collect::<Vec<_>>();
    let detail = serde_json::json!({ "details": details, "policy": event.applied_rule.as_ref().map(|applied| serde_json::json!({
        "source": applied.source, "revision": applied.revision, "rule": applied.rule
    })) });
    let mut conn = pool.get().await?;
    let tx = conn.transaction().await?;
    let gate = tx.query_opt(
        "INSERT INTO notification_health_gate(alert_key,severity,admitted_at) VALUES($1,$2,NOW()) \
         ON CONFLICT(alert_key) DO UPDATE SET severity=EXCLUDED.severity,admitted_at=NOW() \
         WHERE notification_health_gate.admitted_at<=NOW()-$3::BIGINT*INTERVAL '1 second' \
         OR ($2='critical' AND notification_health_gate.severity<>'critical') RETURNING alert_key",
        &[&event.key,&event.severity,&cooldown_seconds],
    ).await?;
    if gate.is_none() {
        return Ok(false);
    }
    let row = tx
        .query_one(
            "INSERT INTO health_alert (alert_type, alert_key, severity, summary, detail) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id;",
            &[
                &event.alert_type,
                &event.key,
                &event.severity,
                &event.summary,
                &detail,
            ],
        )
        .await?;
    let id: i64 = row.get("id");
    // Group notifications contain a bounded operational summary, not raw SQL, IPs or request details.
    let title = format!("健康告警：{}", event.alert_type);
    let body = format!(
        "告警类型：{}\n告警记录：{}\n请登录平台“健康告警”查看详情。",
        event.alert_type, id
    );
    crate::notification::enqueue_with_context(
        &tx,
        "health.alert",
        event.severity,
        &format!("health:{id}"),
        &title,
        &body,
        None,
        serde_json::json!({"mail_template":mail_template::HEALTH_ALERT_TEMPLATE_KEY,"mail_context":mail_template::health_alert_context(event)?.into_json()}),
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

#[derive(Default)]
struct AlertCooldown {
    entries: HashMap<String, (Instant, &'static str)>,
}

impl AlertCooldown {
    fn allows(&self, key: &str, severity: &'static str, cooldown: Duration, now: Instant) -> bool {
        if let Some((previous, previous_severity)) = self.entries.get(key)
            && now.duration_since(*previous) < cooldown
            && !(severity == "critical" && *previous_severity != "critical")
        {
            return false;
        }
        true
    }

    fn record_admission(&mut self, key: &str, severity: &'static str, now: Instant) {
        // Keep finite memory even when many SQL query IDs are observed over time.
        if self.entries.len() >= 4096 {
            self.entries
                .retain(|_, (at, _)| now.duration_since(*at) < Duration::from_secs(604_800));
            if self.entries.len() >= 4096 {
                self.entries.clear();
            }
        }
        self.entries.insert(key.to_owned(), (now, severity));
    }
}

/// 消费健康事件：冷却去重后写入历史并调用邮件模板系统向管理员发送告警。
async fn run_notifier(
    mut rx: mpsc::Receiver<HealthEvent>,
    pool: Pool,
    _encryption_key: String,
    config: Arc<RwLock<Versioned<MonitorConfig>>>,
) {
    let last_alert = Mutex::new(AlertCooldown::default());

    while let Some(event) = rx.recv().await {
        let settings = config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if !settings.value.enabled {
            continue;
        }
        let cooldown = Duration::from_secs(
            event
                .applied_rule
                .as_ref()
                .map(|applied| applied.rule.cooldown_seconds)
                .unwrap_or(settings.value.alert_cooldown_seconds),
        );
        // Capture before the database attempt so slow admission cannot extend its window.
        let now = Instant::now();
        {
            let last = last_alert
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !last.allows(&event.key, event.severity, cooldown, now) {
                debug!(event = "HealthAlertCooldown", alert_type = event.alert_type, key = %event.key, "告警处于冷却期，已合并丢弃");
                continue;
            }
        }

        match record_health_alert(&pool, &event, cooldown.as_secs() as i64).await {
            Ok(false) => continue,
            Ok(true) => last_alert
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .record_admission(&event.key, event.severity, now),
            Err(error) => {
                let diagnostics = error_diagnostics(error.as_ref());
                error!(
                    event = "HealthAlertRecordError",
                    operation = "record_health_alert",
                    error_kind = "database",
                    error_code = "health_alert_record_failed",
                    error_message = %diagnostics.error_message,
                    error_chain = %diagnostics.error_chain,
                    root_cause = %diagnostics.root_cause,
                    error_truncated = diagnostics.error_truncated,
                    retryable = false,
                    outcome = "alert_history_missing",
                    alert_type = event.alert_type,
                    key = %event.key,
                    "健康告警历史写入失败"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ElasticsearchObservation, ElasticsearchOperationKind, MonitorHandle};
    use crate::config::MonitorConfig;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn cooldown_suppresses_repeats_but_allows_immediate_escalation() {
        let mut cooldown = super::AlertCooldown::default();
        let at = std::time::Instant::now();
        let window = std::time::Duration::from_secs(300);
        assert!(cooldown.allows("operation", "warning", window, at));
        cooldown.record_admission("operation", "warning", at);
        assert!(!cooldown.allows(
            "operation",
            "warning",
            window,
            at + std::time::Duration::from_secs(1)
        ));
        assert!(cooldown.allows(
            "operation",
            "critical",
            window,
            at + std::time::Duration::from_secs(2)
        ));
        cooldown.record_admission(
            "operation",
            "critical",
            at + std::time::Duration::from_secs(2),
        );
        assert!(!cooldown.allows(
            "operation",
            "critical",
            window,
            at + std::time::Duration::from_secs(3)
        ));
        assert!(cooldown.allows("different-operation", "warning", window, at));
        assert!(cooldown.allows(
            "operation",
            "critical",
            window,
            at + window + std::time::Duration::from_secs(2)
        ));
    }

    #[tokio::test]
    async fn disabled_slow_rule_preserves_failure_alerts_and_records_policy_revision() {
        use super::rules::{MonitorService, OperationRule};
        let (handle, mut rx) = handle();
        let mut config = MonitorConfig::default();
        let mut rule = config.default_rule(MonitorService::ElasticsearchQuery);
        rule.enabled = false;
        config.operation_rules.push(OperationRule {
            service: MonitorService::ElasticsearchQuery,
            operation: "asset-search".into(),
            rule,
        });
        handle.replace_config(config, 2);
        handle.observe_elasticsearch(query_observation(10_000));
        assert!(rx.try_recv().is_err());
        let mut failed = query_observation(20);
        failed.timed_out = true;
        handle.observe_elasticsearch(failed);
        let event = rx.recv().await.unwrap();
        assert_eq!(event.alert_type, "elasticsearch_query_error");
        assert_eq!(event.severity, "critical");
        assert_eq!(event.applied_rule.as_ref().unwrap().revision, 2);
        assert!(
            event
                .details
                .iter()
                .any(|(key, value)| key == "配置版本" && value == "2")
        );
        handle.replace_config(MonitorConfig::default(), 1);
        assert!(
            handle
                .classify_request("GET", "/api/task/all", 3000)
                .is_some()
        );
        assert_eq!(handle.config.read().unwrap().revision, 2);
    }

    #[test]
    fn request_overrides_use_method_and_route_template() {
        use super::rules::{MonitorService, OperationRule};
        let (handle, _) = handle();
        let mut config = MonitorConfig::default();
        let mut rule = config.default_rule(MonitorService::WebApi);
        rule.warning_threshold_ms = 1000;
        rule.critical_threshold_ms = Some(2000);
        config.operation_rules.push(OperationRule {
            service: MonitorService::WebApi,
            operation: "GET /api/task/{task_id}".into(),
            rule,
        });
        handle.replace_config(config, 2);
        assert!(
            handle
                .classify_request("GET", "/api/task/{task_id}", 999)
                .is_none()
        );
        let applied = handle
            .classify_request("GET", "/api/task/{task_id}", 2000)
            .unwrap();
        assert_eq!(applied.rule.severity(2000.0), Some("critical"));
        assert!(
            handle
                .classify_request("POST", "/api/task/{task_id}", 2000)
                .is_none()
        );
    }

    fn handle() -> (
        MonitorHandle,
        tokio::sync::mpsc::Receiver<super::HealthEvent>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        (
            MonitorHandle {
                tx,
                config: Arc::new(std::sync::RwLock::new(crate::runtime_config::Versioned {
                    value: MonitorConfig::default(),
                    revision: 1,
                })),
                dropped_events: Arc::new(AtomicU64::new(0)),
                revisions: tokio::sync::watch::channel(1).0,
            },
            rx,
        )
    }

    fn query_observation(duration_ms: i64) -> ElasticsearchObservation {
        ElasticsearchObservation {
            operation: "asset-search",
            kind: ElasticsearchOperationKind::Query,
            duration_ms,
            es_took_ms: Some(duration_ms.saturating_sub(20)),
            http_status: Some(200),
            timed_out: false,
            failed_shards: 0,
            trace_id: "0123456789abcdef0123456789abcdef".to_owned(),
            failure_kind: None,
        }
    }

    #[tokio::test]
    async fn elasticsearch_observer_ignores_fast_queries_and_emits_slow_queries() {
        let (handle, mut rx) = handle();
        handle.observe_elasticsearch(query_observation(999));
        assert!(rx.try_recv().is_err());

        handle.observe_elasticsearch(query_observation(1_000));
        let event = rx.recv().await.unwrap();
        assert_eq!(event.alert_type, "slow_elasticsearch_query");
        assert_eq!(event.severity, "warning");
        assert_eq!(event.key, "slow_elasticsearch_query:asset-search");
    }

    #[tokio::test]
    async fn elasticsearch_failures_are_critical_without_sensitive_details() {
        let (handle, mut rx) = handle();
        let mut observation = query_observation(10);
        observation.http_status = Some(429);
        observation.failure_kind = Some("http");
        handle.observe_elasticsearch(observation);

        let event = rx.recv().await.unwrap();
        assert_eq!(event.alert_type, "elasticsearch_query_error");
        assert_eq!(event.severity, "critical");
        let rendered = format!("{event:?}");
        assert!(!rendered.contains("SELECT "));
        assert!(!rendered.contains("password="));
    }
}
