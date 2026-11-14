//! 转发管道：tracing 捕获层 → 有界队列 → 分发 → 每目标 worker（UDP/TCP/TLS）。
//!
//! 设计约束：
//! - 绝不阻塞请求路径：所有入队均为 `try_send`，队列满则丢弃并计数。
//! - 防回环：`syslog` 模块自身的日志不进入转发队列。
//! - 热重载：配置 revision 变化时主管任务重建管道，无需重启进程。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use uuid::Uuid;

use crate::runtime_config::RuntimeConfig;
use crate::syslog::config::{Protocol, SyslogConfig, TargetConfig};
use crate::syslog::format::{self, Message, Severity, TCP_MAX_BYTES, UDP_MAX_BYTES};
use crate::syslog::metrics::{self, MinuteMetrics, Source};
use crate::syslog::status::StatusRegistry;
use crate::syslog::transport::{self, Connection};

/// 一条待转发消息（目标无关）。
#[derive(Clone, Debug)]
pub struct ForwardItem {
    pub source: Source,
    pub severity: Severity,
    pub msgid: &'static str,
    pub timestamp: DateTime<Utc>,
    pub text: String,
    pub sd: Vec<(String, String)>,
}

// ---- 捕获句柄（进程全局） ----

struct CaptureState {
    sender: Option<mpsc::Sender<ForwardItem>>,
    min_level: tracing::Level,
    audit: bool,
    access: bool,
    scanner: bool,
}

pub struct CaptureHandle {
    active: AtomicBool,
    state: RwLock<CaptureState>,
    enqueue_drops: AtomicU64,
}

static CAPTURE: OnceLock<Arc<CaptureHandle>> = OnceLock::new();

pub fn capture() -> Arc<CaptureHandle> {
    CAPTURE
        .get_or_init(|| {
            Arc::new(CaptureHandle {
                active: AtomicBool::new(false),
                state: RwLock::new(CaptureState {
                    sender: None,
                    min_level: tracing::Level::INFO,
                    audit: false,
                    access: false,
                    scanner: false,
                }),
                enqueue_drops: AtomicU64::new(0),
            })
        })
        .clone()
}

impl CaptureHandle {
    /// 主管任务在管道建立/拆除时调用。
    pub fn install(&self, sender: Option<mpsc::Sender<ForwardItem>>, config: &SyslogConfig) {
        let active = sender.is_some() && config.enabled;
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.sender = sender;
        state.min_level = config.min_level.as_tracing();
        state.audit = config.forward_audit_events;
        state.access = config.forward_access_logs;
        state.scanner = config.forward_scanner_diagnostics;
        self.active.store(active, Ordering::SeqCst);
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    pub fn enqueue_drops(&self) -> u64 {
        self.enqueue_drops.load(Ordering::Relaxed)
    }

    /// 系统运行日志：受 min_level 过滤。
    pub fn enqueue_system(&self, item: ForwardItem, level: tracing::Level) -> bool {
        if !self.is_active() {
            return false;
        }
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // tracing::Level 按 verbosity 排序：ERROR < WARN < INFO < DEBUG < TRACE。
        // 只转发不低于最低级别（即 verbosity 不高于 min_level）的事件。
        if level > state.min_level {
            return false;
        }
        self.try_enqueue(&state, item)
    }

    /// 审计/访问/扫描器诊断：各自独立开关。
    pub fn enqueue_source(&self, item: ForwardItem) -> bool {
        if !self.is_active() {
            return false;
        }
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let allowed = match item.source {
            Source::Audit => state.audit,
            Source::Access => state.access,
            Source::Scanner => state.scanner,
            Source::System => true,
        };
        if !allowed {
            return false;
        }
        self.try_enqueue(&state, item)
    }

    fn try_enqueue(&self, state: &CaptureState, item: ForwardItem) -> bool {
        let Some(sender) = &state.sender else {
            return false;
        };
        if sender.try_send(item).is_err() {
            self.enqueue_drops.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }
}

// ---- tracing 捕获层 ----

struct RequestIdField(String);

/// 挂到全局 tracing registry；管道未建立时开销仅为一次原子读。
pub struct SyslogLayer;

impl<S> tracing_subscriber::Layer<S> for SyslogLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        if attrs.metadata().name() != "http_request" {
            return;
        }
        let mut visitor = RequestIdVisitor(None);
        attrs.record(&mut visitor);
        if let Some(request_id) = visitor.0
            && let Some(span) = ctx.span(id)
        {
            span.extensions_mut().insert(RequestIdField(request_id));
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let handle = capture();
        if !handle.is_active() {
            return;
        }
        let metadata = event.metadata();
        // 防回环：转发器自身的日志（连接失败、丢弃告警等）不再转发。
        let target = metadata.target();
        if target.contains("::syslog::") || target.starts_with("syslog") {
            return;
        }
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        let request_id = ctx.event_span(event).and_then(|span| {
            span.extensions()
                .get::<RequestIdField>()
                .map(|field| field.0.clone())
        });
        let mut sd = Vec::new();
        if let Some(event_name) = visitor.event_name {
            sd.push(("event".to_owned(), event_name));
        }
        if let Some(request_id) = request_id {
            sd.push(("request_id".to_owned(), request_id));
        }
        sd.push(("target".to_owned(), target.to_owned()));
        for (key, value) in visitor.fields.into_iter().take(10) {
            sd.push((key, value));
        }
        let level = *metadata.level();
        let item = ForwardItem {
            source: Source::System,
            severity: Severity::from_tracing(&level),
            msgid: "AppLog",
            timestamp: Utc::now(),
            text: visitor.message,
            sd,
        };
        handle.enqueue_system(item, level);
    }
}

struct RequestIdVisitor(Option<String>);

impl tracing::field::Visit for RequestIdVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "request_id" {
            self.0 = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "request_id" {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

#[derive(Default)]
struct EventVisitor {
    message: String,
    event_name: Option<String>,
    fields: Vec<(String, String)>,
}

impl EventVisitor {
    fn push(&mut self, name: &str, value: String) {
        if name == "message" {
            self.message = value;
        } else if name == "event" {
            self.event_name = Some(value);
        } else if self.fields.len() < 16 {
            self.fields.push((name.to_owned(), value));
        }
    }
}

impl tracing::field::Visit for EventVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.push(field.name(), value.chars().take(2048).collect());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.push(
            field.name(),
            format!("{value:?}").chars().take(2048).collect(),
        );
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.push(field.name(), value.to_string());
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.push(field.name(), value.to_string());
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.push(field.name(), value.to_string());
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.push(field.name(), value.to_string());
    }
}

// ---- 主管任务：热重载 ----

pub async fn run_supervisor(
    pool: Pool,
    config: RuntimeConfig<SyslogConfig>,
    registry: StatusRegistry,
    mut stopping: watch::Receiver<bool>,
) {
    let mut changes = config.subscribe();
    let mut pipeline: Option<Pipeline> = None;
    loop {
        let snapshot = config.get().await;
        let settings = snapshot.value;
        if let Some(previous) = pipeline.take() {
            previous.shutdown().await;
        }
        let ids: Vec<Uuid> = settings.targets.iter().map(|target| target.id).collect();
        registry.retain(&ids);
        let active = settings.enabled && settings.targets.iter().any(|target| target.enabled);
        if active {
            let started = Pipeline::start(&pool, &settings, registry.clone());
            capture().install(Some(started.sender.clone()), &settings);
            pipeline = Some(started);
            tracing::info!(
                event = "SyslogForwarderStarted",
                component = "syslog",
                targets = settings.targets.iter().filter(|t| t.enabled).count(),
                revision = snapshot.revision,
                "syslog 转发管道已启动"
            );
        } else {
            capture().install(None, &settings);
            for target in &settings.targets {
                registry.set_state(target.id, "disabled");
            }
        }
        tokio::select! {
            _ = stopping.changed() => break,
            changed = changes.changed() => {
                if changed.is_err() {
                    break;
                }
            }
        }
    }
    if let Some(previous) = pipeline.take() {
        previous.shutdown().await;
    }
    capture().install(None, &SyslogConfig::default());
}

struct Pipeline {
    sender: mpsc::Sender<ForwardItem>,
    stop: watch::Sender<bool>,
    tasks: JoinSet<()>,
}

impl Pipeline {
    fn start(pool: &Pool, config: &SyslogConfig, registry: StatusRegistry) -> Self {
        let (sender, receiver) = mpsc::channel(config.queue_capacity);
        let (stop, stop_receiver) = watch::channel(false);
        let mut tasks = JoinSet::new();
        let mut target_senders = Vec::new();
        for target in config.targets.iter().filter(|target| target.enabled) {
            let (target_sender, target_receiver) = mpsc::channel(config.queue_capacity);
            target_senders.push((target.id, target.sources.clone(), target_sender));
            tasks.spawn(worker(
                pool.clone(),
                target.clone(),
                target_receiver,
                registry.clone(),
                config.facility.code(),
                config.app_name.clone(),
                stop_receiver.clone(),
            ));
        }
        tasks.spawn(dispatcher(
            receiver,
            target_senders,
            registry,
            stop_receiver.clone(),
        ));
        Self {
            sender,
            stop,
            tasks,
        }
    }

    async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        drop(self.sender);
        let drained = tokio::time::timeout(Duration::from_secs(10), async {
            while self.tasks.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            self.tasks.abort_all();
            while self.tasks.join_next().await.is_some() {}
        }
    }
}

async fn dispatcher(
    mut receiver: mpsc::Receiver<ForwardItem>,
    targets: Vec<(Uuid, Vec<Source>, mpsc::Sender<ForwardItem>)>,
    registry: StatusRegistry,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            maybe = receiver.recv() => match maybe {
                Some(item) => {
                    for (id, sources, sender) in &targets {
                        // 按目标订阅的日志类型过滤；未订阅的类型不入队也不计丢弃。
                        if !sources.contains(&item.source) {
                            continue;
                        }
                        if sender.try_send(item.clone()).is_err() {
                            registry.add_dropped(*id, 1);
                        }
                    }
                }
                None => break,
            },
        }
    }
}

fn backoff(failures: u32) -> Duration {
    Duration::from_secs(1u64 << failures.min(6))
}

async fn worker(
    pool: Pool,
    target: TargetConfig,
    mut receiver: mpsc::Receiver<ForwardItem>,
    registry: StatusRegistry,
    facility_code: u8,
    app_name: String,
    mut stop: watch::Receiver<bool>,
) {
    let max_bytes = if target.protocol == Protocol::Udp {
        UDP_MAX_BYTES
    } else {
        TCP_MAX_BYTES
    };
    let mut connection: Option<Connection> = None;
    let mut failures: u32 = 0;
    let mut next_retry_at: Option<Instant> = None;
    let mut metrics = MinuteMetrics::new(metrics::minute_bucket(Utc::now()));
    registry.set_state(target.id, "connecting");

    loop {
        let item = tokio::select! {
            _ = stop.changed() => break,
            maybe = receiver.recv() => match maybe {
                Some(item) => item,
                None => break,
            },
        };

        // 失败退避期内不发起连接；消息按失败计数（失败率告警口径 = 消息丢失率）。
        if let Some(at) = next_retry_at.take() {
            let now = Instant::now();
            if at > now {
                tokio::select! {
                    _ = stop.changed() => break,
                    _ = tokio::time::sleep(at - now) => {}
                }
            }
        }

        if connection.is_none() {
            match transport::connect(&target, transport::CONNECT_TIMEOUT).await {
                Ok(created) => {
                    connection = Some(created);
                    failures = 0;
                    registry.set_state(target.id, "connected");
                }
                Err(error) => {
                    failures = failures.saturating_add(1);
                    registry.record_failure(target.id, &error);
                    metrics.record(item.source, false, 0.0);
                    next_retry_at = Some(Instant::now() + backoff(failures));
                    roll_minute(&pool, target.id, &mut metrics).await;
                    continue;
                }
            }
        }

        let message = Message {
            timestamp: item.timestamp,
            severity: item.severity,
            msgid: item.msgid,
            sd: item.sd,
            text: item.text,
        };
        let payload = format::render(&message, facility_code, &app_name, max_bytes);
        let started = Instant::now();
        // unwrap 安全：上方已确保 connection 为 Some。
        let active = connection.as_mut().expect("connection checked above");
        match transport::send(active, &payload, transport::SEND_TIMEOUT).await {
            Ok(()) => {
                let latency_ms = started.elapsed().as_secs_f64() * 1000.0;
                metrics.record(item.source, true, latency_ms);
                registry.record_success(target.id);
                failures = 0;
            }
            Err(error) => {
                connection = None;
                failures = failures.saturating_add(1);
                registry.record_failure(target.id, &error);
                metrics.record(item.source, false, 0.0);
                next_retry_at = Some(Instant::now() + backoff(failures));
            }
        }
        roll_minute(&pool, target.id, &mut metrics).await;
    }

    // 停机：队列中剩余消息计为丢弃，聚合器落库。
    let mut remaining = 0u64;
    while receiver.try_recv().is_ok() {
        remaining += 1;
    }
    if remaining > 0 {
        metrics.record_dropped(remaining);
        registry.add_dropped(target.id, remaining);
    }
    if let Err(error) = metrics::flush(&pool, target.id, &mut metrics).await {
        tracing::warn!(
            event = "SyslogMetricsFlushFailed",
            component = "syslog",
            target_id = %target.id,
            error_message = %error,
            "syslog 分钟指标落库失败"
        );
    }
}

async fn roll_minute(pool: &Pool, target_id: Uuid, metrics: &mut MinuteMetrics) {
    let bucket = metrics::minute_bucket(Utc::now());
    if bucket != metrics.bucket_start {
        if let Err(error) = metrics::flush(pool, target_id, metrics).await {
            tracing::warn!(
                event = "SyslogMetricsFlushFailed",
                component = "syslog",
                target_id = %target_id,
                error_message = %error,
                "syslog 分钟指标落库失败"
            );
        }
        *metrics = MinuteMetrics::new(bucket);
    }
}

/// 发送一条测试消息（Web 测试按钮与 CLI `syslog test` 共用）。
pub async fn send_test(
    target: &TargetConfig,
    facility_code: u8,
    app_name: &str,
) -> Result<f64, String> {
    let message = Message {
        timestamp: Utc::now(),
        severity: Severity::Info,
        msgid: "Test",
        sd: vec![("purpose".to_owned(), "connectivity-test".to_owned())],
        text: "network-mapping syslog connectivity test".to_owned(),
    };
    let max_bytes = if target.protocol == Protocol::Udp {
        UDP_MAX_BYTES
    } else {
        TCP_MAX_BYTES
    };
    let payload = format::render(&message, facility_code, app_name, max_bytes);
    let started = Instant::now();
    let mut connection = transport::connect(target, transport::CONNECT_TIMEOUT).await?;
    transport::send(&mut connection, &payload, transport::SEND_TIMEOUT).await?;
    Ok(started.elapsed().as_secs_f64() * 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_is_inactive_before_pipeline_install() {
        let handle = capture();
        handle.install(None, &SyslogConfig::default());
        let item = ForwardItem {
            source: Source::System,
            severity: Severity::Info,
            msgid: "AppLog",
            timestamp: Utc::now(),
            text: "test".into(),
            sd: vec![],
        };
        assert!(!handle.enqueue_system(item, tracing::Level::INFO));
    }

    #[test]
    fn backoff_grows_and_caps_at_64_seconds() {
        assert_eq!(backoff(1), Duration::from_secs(2));
        assert_eq!(backoff(3), Duration::from_secs(8));
        assert_eq!(backoff(6), Duration::from_secs(64));
        assert_eq!(backoff(20), Duration::from_secs(64));
    }

    #[test]
    fn system_events_respect_min_level_verbosity_order() {
        let handle = capture();
        let (sender, mut receiver) = mpsc::channel(16);
        let config = SyslogConfig {
            enabled: true,
            min_level: crate::syslog::config::MinLevel::Info,
            ..Default::default()
        };
        handle.install(Some(sender), &config);
        let item = |severity| ForwardItem {
            source: Source::System,
            severity,
            msgid: "AppLog",
            timestamp: Utc::now(),
            text: "test".into(),
            sd: vec![],
        };
        assert!(!handle.enqueue_system(item(Severity::Debug), tracing::Level::DEBUG));
        assert!(!handle.enqueue_system(item(Severity::Debug), tracing::Level::TRACE));
        assert!(handle.enqueue_system(item(Severity::Info), tracing::Level::INFO));
        assert!(handle.enqueue_system(item(Severity::Warning), tracing::Level::WARN));
        assert!(handle.enqueue_system(item(Severity::Error), tracing::Level::ERROR));
        assert_eq!(receiver.try_recv().unwrap().severity, Severity::Info);
        handle.install(None, &SyslogConfig::default());
    }
}
