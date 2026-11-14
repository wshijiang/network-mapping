//! `networkm syslog` 管理命令：与 Web 管理功能对等。
//!
//! 仅需 PostgreSQL，不启动 HTTP/Elasticsearch；所有变更走与 Web 相同的
//! 校验 + `runtime_configuration` 持久化 + 审计（系统身份）。

use chrono::{DateTime, Utc};
use clap::{Subcommand, ValueEnum};
use deadpool_postgres::Pool;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::audit::{AuditContext, AuditEvent, write_standalone};
use crate::runtime_config::{PersistError, persist_with_actor};
use crate::syslog::config::{
    Facility, MinLevel, NAMESPACE, Protocol, SyslogConfig, TargetConfig, TlsOptions,
};
use crate::syslog::forwarder::send_test;
use crate::syslog::metrics;
use crate::syslog::status;

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Switch {
    On,
    Off,
}

impl Switch {
    fn enabled(self) -> bool {
        matches!(self, Self::On)
    }
}

#[derive(Debug, Subcommand)]
pub enum SyslogCommand {
    /// 查看当前配置
    Show {
        #[arg(long)]
        json: bool,
    },
    /// 查看各目标运行状态（读取服务端落库快照）
    Status {
        #[arg(long)]
        json: bool,
    },
    /// 查看配置修订历史
    History {
        #[arg(long, default_value_t = 20)]
        limit: i64,
        #[arg(long)]
        json: bool,
    },
    /// 启用转发
    Enable {
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// 停用转发
    Disable {
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// 修改全局设置
    Set {
        #[arg(long, value_enum)]
        facility: Option<Facility>,
        #[arg(long, value_enum)]
        min_level: Option<MinLevel>,
        #[arg(long)]
        app_name: Option<String>,
        /// 审计事件转发开关
        #[arg(long, value_enum)]
        audit: Option<Switch>,
        /// IP 访问日志转发开关
        #[arg(long, value_enum)]
        access_logs: Option<Switch>,
        /// 扫描器诊断事件转发开关
        #[arg(long, value_enum)]
        scanner_diagnostics: Option<Switch>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1024..=100000))]
        queue_capacity: Option<u32>,
        #[arg(long)]
        metrics_retention_days: Option<i32>,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// 添加 syslog 服务器
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long, value_enum, default_value = "udp")]
        protocol: Protocol,
        /// 添加后立即停用该目标
        #[arg(long)]
        disabled: bool,
        #[arg(long)]
        tls_ca: Option<String>,
        #[arg(long)]
        no_tls_verify: bool,
        #[arg(long)]
        tls_server_name: Option<String>,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// 修改 syslog 服务器（可用 ID 或名称定位）
    Update {
        target: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long, value_enum)]
        protocol: Option<Protocol>,
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        #[arg(long)]
        disable: bool,
        #[arg(long)]
        tls_ca: Option<String>,
        #[arg(long)]
        no_tls_verify: bool,
        #[arg(long)]
        tls_server_name: Option<String>,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// 删除 syslog 服务器
    Remove {
        target: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// 向目标发送测试消息
    Test { target: String },
    /// 转发统计（终端图表，malevich 渲染）
    Stats {
        /// 统计窗口：1h / 24h / 7d
        #[arg(long, default_value = "24h")]
        window: String,
        /// 只统计指定目标（ID 或名称）
        #[arg(long)]
        target: Option<String>,
        /// 分桶粒度：auto / 1m / 5m / 15m / 30m / 1h / 2h / 6h
        #[arg(long, default_value = "auto")]
        granularity: String,
        #[arg(long)]
        json: bool,
    },
    /// 通知策略（失败率 / P95 / P99 独立开关）
    Alerts {
        #[command(subcommand)]
        command: AlertsCommand,
    },
    /// 历史日志回填（下发任务，由运行中的服务执行）
    Backfill {
        #[command(subcommand)]
        command: BackfillCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum BackfillCommand {
    /// 下发回填任务：默认最近 7 天；--days N 或 --start/--end 自定义
    Create {
        #[arg(long)]
        days: Option<i64>,
        /// 开始时间（RFC 3339，如 2026-11-01T00:00:00Z）
        #[arg(long, requires = "end")]
        start: Option<DateTime<Utc>>,
        /// 结束时间（RFC 3339）
        #[arg(long, requires = "start")]
        end: Option<DateTime<Utc>>,
        #[arg(long)]
        json: bool,
    },
    /// 查看回填任务列表
    List {
        #[arg(long)]
        json: bool,
    },
    /// 取消回填任务
    Cancel { id: String },
}

#[derive(Debug, Subcommand)]
pub enum AlertsCommand {
    /// 查看通知策略
    Show {
        #[arg(long)]
        json: bool,
    },
    /// 修改通知策略
    Set {
        #[arg(long)]
        window_minutes: Option<i64>,
        #[arg(long)]
        cooldown_seconds: Option<i64>,
        #[arg(long, value_enum)]
        failure_rate: Option<Switch>,
        #[arg(long)]
        failure_rate_warning: Option<f64>,
        #[arg(long)]
        failure_rate_critical: Option<f64>,
        #[arg(long)]
        min_samples: Option<i64>,
        #[arg(long, value_enum)]
        p95: Option<Switch>,
        #[arg(long)]
        p95_warning: Option<f64>,
        #[arg(long)]
        p95_critical: Option<f64>,
        #[arg(long, value_enum)]
        p99: Option<Switch>,
        #[arg(long)]
        p99_warning: Option<f64>,
        #[arg(long)]
        p99_critical: Option<f64>,
        #[arg(long, default_value = "")]
        reason: String,
    },
}

pub async fn execute(command: &SyslogCommand, pool: &Pool) -> CliResult {
    match command {
        SyslogCommand::Show { json } => show(pool, *json).await,
        SyslogCommand::Status { json } => show_status(pool, *json).await,
        SyslogCommand::History { limit, json } => history(pool, *limit, *json).await,
        SyslogCommand::Enable { reason } => set_enabled(pool, true, reason).await,
        SyslogCommand::Disable { reason } => set_enabled(pool, false, reason).await,
        SyslogCommand::Set {
            facility,
            min_level,
            app_name,
            audit,
            access_logs,
            scanner_diagnostics,
            queue_capacity,
            metrics_retention_days,
            reason,
        } => {
            let (mut config, revision) = load_current(pool).await?;
            if let Some(value) = facility {
                config.facility = *value;
            }
            if let Some(value) = min_level {
                config.min_level = *value;
            }
            if let Some(value) = app_name {
                config.app_name = value.clone();
            }
            if let Some(value) = audit {
                config.forward_audit_events = value.enabled();
            }
            if let Some(value) = access_logs {
                config.forward_access_logs = value.enabled();
            }
            if let Some(value) = scanner_diagnostics {
                config.forward_scanner_diagnostics = value.enabled();
            }
            if let Some(value) = queue_capacity {
                config.queue_capacity = *value as usize;
            }
            if let Some(value) = metrics_retention_days {
                config.metrics_retention_days = *value;
            }
            let revision = save_change(pool, &config, revision, reason, "cli.syslog.set").await?;
            println!("全局设置已保存，当前版本 #{revision}");
            Ok(())
        }
        SyslogCommand::Add {
            name,
            host,
            port,
            protocol,
            disabled,
            tls_ca,
            no_tls_verify,
            tls_server_name,
            reason,
        } => {
            let (mut config, revision) = load_current(pool).await?;
            let target = TargetConfig {
                id: Uuid::now_v7(),
                name: name.clone(),
                host: host.clone(),
                port: port.unwrap_or_else(|| protocol.default_port()),
                protocol: *protocol,
                enabled: !disabled,
                tls: TlsOptions {
                    ca_file: tls_ca.clone().unwrap_or_default(),
                    verify: !no_tls_verify,
                    server_name: tls_server_name.clone().unwrap_or_default(),
                },
            };
            config.targets.push(target.clone());
            let revision = save_change(pool, &config, revision, reason, "cli.syslog.add").await?;
            println!(
                "已添加服务器 {}（ID: {}），当前版本 #{revision}",
                target.name, target.id
            );
            Ok(())
        }
        SyslogCommand::Update {
            target,
            name,
            host,
            port,
            protocol,
            enable,
            disable,
            tls_ca,
            no_tls_verify,
            tls_server_name,
            reason,
        } => {
            let (mut config, revision) = load_current(pool).await?;
            let index = config
                .targets
                .iter()
                .position(|item| {
                    item.id.to_string() == *target || item.name.eq_ignore_ascii_case(target)
                })
                .ok_or_else(|| format!("未找到服务器：{target}"))?;
            let item = &mut config.targets[index];
            if let Some(value) = name {
                item.name = value.clone();
            }
            if let Some(value) = host {
                item.host = value.clone();
            }
            if let Some(value) = port {
                item.port = *value;
            }
            if let Some(value) = protocol {
                item.protocol = *value;
            }
            if *enable {
                item.enabled = true;
            }
            if *disable {
                item.enabled = false;
            }
            if let Some(value) = tls_ca {
                item.tls.ca_file = value.clone();
            }
            if *no_tls_verify {
                item.tls.verify = false;
            }
            if let Some(value) = tls_server_name {
                item.tls.server_name = value.clone();
            }
            let revision =
                save_change(pool, &config, revision, reason, "cli.syslog.update").await?;
            println!("服务器已更新，当前版本 #{revision}");
            Ok(())
        }
        SyslogCommand::Remove { target, reason } => {
            let (mut config, revision) = load_current(pool).await?;
            let before = config.targets.len();
            config.targets.retain(|item| {
                !(item.id.to_string() == *target || item.name.eq_ignore_ascii_case(target))
            });
            if config.targets.len() == before {
                return Err(format!("未找到服务器：{target}").into());
            }
            let revision =
                save_change(pool, &config, revision, reason, "cli.syslog.remove").await?;
            println!("服务器已删除，当前版本 #{revision}");
            Ok(())
        }
        SyslogCommand::Test { target } => {
            let (config, _) = load_current(pool).await?;
            let item = config
                .find_target(target)
                .ok_or_else(|| format!("未找到服务器：{target}"))?;
            println!(
                "向 {}:{} ({}) 发送测试消息…",
                item.host,
                item.port,
                item.protocol.as_str()
            );
            match send_test(item, config.facility.code(), &config.app_name).await {
                Ok(latency) => {
                    println!("测试成功，耗时 {latency:.1} ms");
                    Ok(())
                }
                Err(error) => Err(format!("测试失败：{error}").into()),
            }
        }
        SyslogCommand::Stats {
            window,
            target,
            granularity,
            json,
        } => stats(pool, window, target.as_deref(), granularity, *json).await,
        SyslogCommand::Alerts { command } => alerts(pool, command).await,
        SyslogCommand::Backfill { command } => backfill(pool, command).await,
    }
}

// ---- 配置读写（与 Web 共用校验与持久化） ----

async fn load_current(pool: &Pool) -> CliResult<(SyslogConfig, i64)> {
    let client = pool.get().await?;
    if let Some(row) = client
        .query_opt(
            "SELECT document, revision FROM runtime_configuration WHERE namespace = $1",
            &[&NAMESPACE],
        )
        .await?
    {
        let document: Value = row.get("document");
        let revision: i64 = row.get("revision");
        let config: SyslogConfig = serde_json::from_value(document)
            .map_err(|error| format!("数据库 syslog 配置无法解析：{error}"))?;
        config.validate()?;
        Ok((config, revision))
    } else {
        // CLI 先于服务启动时播种默认文档（与 load_namespace 同逻辑）。
        let config = SyslogConfig::default();
        let document = serde_json::to_value(&config)?;
        client
            .execute(
                "INSERT INTO runtime_configuration (namespace, document) VALUES ($1, $2) \
                 ON CONFLICT (namespace) DO NOTHING",
                &[&NAMESPACE, &document],
            )
            .await?;
        client
            .execute(
                "INSERT INTO runtime_configuration_revision (namespace, revision, schema_version, document, change_reason) \
                 SELECT namespace, revision, schema_version, document, 'initial CLI seed' FROM runtime_configuration \
                 WHERE namespace = $1 ON CONFLICT (namespace, revision) DO NOTHING",
                &[&NAMESPACE],
            )
            .await?;
        Ok((config, 1))
    }
}

async fn save_change(
    pool: &Pool,
    config: &SyslogConfig,
    expected_revision: i64,
    reason: &str,
    action: &'static str,
) -> CliResult<i64> {
    config.validate()?;
    let reason = if reason.trim().is_empty() {
        action.to_owned()
    } else {
        reason.to_owned()
    };
    let revision = persist_with_actor(pool, NAMESPACE, expected_revision, config, &reason, None)
        .await
        .map_err(|error| match error {
            PersistError::Conflict => "配置已被其他管理员更新，请重新执行命令".to_owned(),
            PersistError::Other(message) => message,
        })?;
    let mut event =
        AuditEvent::system("configuration", action, "success").resource("setting", NAMESPACE);
    event.metadata = json!({"revision": revision, "change_reason": reason});
    write_standalone(pool, &AuditContext::cli(format!("syslog {action}")), &event).await;
    Ok(revision)
}

// ---- 查看类命令 ----

fn display_time(value: Option<DateTime<Utc>>) -> String {
    value
        .map(|at| at.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "--".to_owned())
}

async fn show(pool: &Pool, as_json: bool) -> CliResult {
    let (config, revision) = load_current(pool).await?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"revision": revision, "document": config}))?
        );
        return Ok(());
    }
    println!("Syslog 转发配置（版本 #{revision}）");
    println!("  启用：{}", if config.enabled { "是" } else { "否" });
    println!(
        "  facility：{}　应用名：{}　最低级别：{}",
        serde_json::to_value(config.facility)?
            .as_str()
            .unwrap_or("local0"),
        config.app_name,
        serde_json::to_value(config.min_level)?
            .as_str()
            .unwrap_or("info")
    );
    println!(
        "  转发源：审计={} IP访问日志={} 扫描器诊断={}",
        on_off(config.forward_audit_events),
        on_off(config.forward_access_logs),
        on_off(config.forward_scanner_diagnostics)
    );
    println!(
        "  队列容量：{}　指标保留：{} 天",
        config.queue_capacity, config.metrics_retention_days
    );
    if config.targets.is_empty() {
        println!("  服务器：（无）");
    } else {
        println!("  服务器：");
        for target in &config.targets {
            println!(
                "    - {} [{}] {}:{} ({}){}",
                target.name,
                target.id,
                target.host,
                target.port,
                target.protocol.as_str(),
                if target.enabled {
                    ""
                } else {
                    "（已停用）"
                }
            );
        }
    }
    print_alerts(&config);
    Ok(())
}

fn on_off(enabled: bool) -> &'static str {
    if enabled { "开" } else { "关" }
}

fn print_alerts(config: &SyslogConfig) {
    let alerts = &config.alerts;
    println!(
        "  通知策略：窗口 {} 分钟　冷却 {} 秒",
        alerts.window_minutes, alerts.cooldown_seconds
    );
    println!(
        "    失败率：{}（警告 {}% / 严重 {}%，最小样本 {}）",
        on_off(alerts.failure_rate.enabled),
        alerts.failure_rate.warning_percent,
        alerts.failure_rate.critical_percent,
        alerts.failure_rate.min_samples
    );
    println!(
        "    P95 耗时：{}（警告 {} ms / 严重 {} ms）",
        on_off(alerts.latency_p95.enabled),
        alerts.latency_p95.warning_ms,
        alerts.latency_p95.critical_ms
    );
    println!(
        "    P99 耗时：{}（警告 {} ms / 严重 {} ms）",
        on_off(alerts.latency_p99.enabled),
        alerts.latency_p99.warning_ms,
        alerts.latency_p99.critical_ms
    );
}

async fn show_status(pool: &Pool, as_json: bool) -> CliResult {
    let (config, _) = load_current(pool).await?;
    let rows = status::load_persisted(pool).await?;
    let now = Utc::now();
    let items: Vec<Value> = rows
        .iter()
        .map(|row| {
            let name = config
                .targets
                .iter()
                .find(|target| target.id == row.target_id)
                .map(|target| target.name.clone())
                .unwrap_or_else(|| row.target_id.to_string());
            let stale = (now - row.updated_at).num_seconds() > 90;
            json!({
                "targetId": row.target_id,
                "name": name,
                "state": row.state,
                "stale": stale,
                "sent": row.sent,
                "failed": row.failed,
                "dropped": row.dropped,
                "lastSuccessAt": row.last_success_at,
                "lastErrorAt": row.last_error_at,
                "lastError": row.last_error,
                "updatedAt": row.updated_at,
            })
        })
        .collect();
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"targets": items}))?
        );
        return Ok(());
    }
    if items.is_empty() {
        println!("暂无状态快照（服务尚未运行过转发管道）。");
        return Ok(());
    }
    println!("Syslog 服务器状态（服务端落库快照，超过 90 秒未更新标记为陈旧）");
    for item in &items {
        let stale = item["stale"].as_bool().unwrap_or(false);
        println!(
            "  - {}：{}{}　发送 {} / 失败 {} / 丢弃 {}",
            item["name"].as_str().unwrap_or("--"),
            item["state"].as_str().unwrap_or("--"),
            if stale { "（陈旧）" } else { "" },
            item["sent"],
            item["failed"],
            item["dropped"],
        );
        println!(
            "    最近成功：{}　最近错误：{} {}",
            display_time(
                item["lastSuccessAt"]
                    .as_str()
                    .and_then(|value| value.parse().ok())
            ),
            display_time(
                item["lastErrorAt"]
                    .as_str()
                    .and_then(|value| value.parse().ok())
            ),
            item["lastError"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

async fn history(pool: &Pool, limit: i64, as_json: bool) -> CliResult {
    let limit = limit.clamp(1, 100);
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT revision, changed_at, change_reason FROM runtime_configuration_revision \
             WHERE namespace = $1 ORDER BY revision DESC LIMIT $2",
            &[&NAMESPACE, &limit],
        )
        .await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "revision": row.get::<_, i64>("revision"),
                "changedAt": row.get::<_, DateTime<Utc>>("changed_at"),
                "changeReason": row.get::<_, String>("change_reason"),
            })
        })
        .collect();
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"history": items}))?
        );
        return Ok(());
    }
    for item in &items {
        println!(
            "  #{}　{}　{}",
            item["revision"],
            item["changedAt"].as_str().unwrap_or("--"),
            item["changeReason"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

async fn set_enabled(pool: &Pool, enabled: bool, reason: &str) -> CliResult {
    let (mut config, revision) = load_current(pool).await?;
    config.enabled = enabled;
    let action = if enabled {
        "cli.syslog.enable"
    } else {
        "cli.syslog.disable"
    };
    let revision = save_change(pool, &config, revision, reason, action).await?;
    println!(
        "转发已{}，当前版本 #{revision}",
        if enabled { "启用" } else { "停用" }
    );
    Ok(())
}

// ---- 统计（malevich 终端图表） ----

async fn stats(
    pool: &Pool,
    window: &str,
    target: Option<&str>,
    granularity: &str,
    as_json: bool,
) -> CliResult {
    let (config, _) = load_current(pool).await?;
    let (start, end) =
        metrics::window_range(window).ok_or_else(|| "window 必须为 1h/24h/7d".to_owned())?;
    let bucket_seconds = metrics::resolve_granularity(Some(granularity), start, end)?;
    let target_id = match target {
        Some(name) => Some(
            config
                .find_target(name)
                .ok_or_else(|| format!("未找到服务器：{name}"))?
                .id,
        ),
        None => None,
    };
    let query = metrics::StatsQuery {
        start,
        end,
        bucket_seconds,
        target_id,
    };
    let (summary, trend) = metrics::query(pool, &query).await?;

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "window": window, "granularity": bucket_seconds,
                "summary": summary, "trend": trend,
            }))?
        );
        return Ok(());
    }

    println!(
        "Syslog 转发统计（{window}，粒度 {bucket_seconds}s）：发送 {} / 失败 {} / 丢弃 {}，失败率 {:.2}%",
        summary.sent,
        summary.failed,
        summary.dropped,
        summary.failure_rate * 100.0
    );
    if let Some(p95) = summary.p95_ms {
        println!("  发送耗时 P95（窗口最差分钟）：{p95:.1} ms");
    }
    if let Some(p99) = summary.p99_ms {
        println!("  发送耗时 P99（窗口最差分钟）：{p99:.1} ms");
    }
    if !summary.by_source.is_empty() {
        let parts: Vec<String> = summary
            .by_source
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        println!("  按源：{}", parts.join(" "));
    }
    if trend.is_empty() {
        println!("暂无数据。");
        return Ok(());
    }

    use malevich::{Frame, Line, Plot, Rule};
    let frame = Frame::plain(88, 14);
    let sent: Vec<f64> = trend.iter().map(|point| point.sent as f64).collect();
    let failed: Vec<f64> = trend.iter().map(|point| point.failed as f64).collect();
    println!(
        "{}",
        Plot::new()
            .layer(Line::y(&sent[..]).label("sent"))
            .layer(Line::y(&failed[..]).label("failed"))
            .title(format!("forwarded messages ({window})"))
            .x_label("time bucket")
            .render(&frame)
    );

    let rates: Vec<f64> = trend
        .iter()
        .map(|point| point.failure_rate * 100.0)
        .collect();
    let mut rate_chart = Plot::new()
        .layer(Line::y(&rates[..]).label("failure %"))
        .title("failure rate")
        .x_label("time bucket");
    if config.alerts.failure_rate.enabled {
        rate_chart =
            rate_chart.layer(Rule::h(config.alerts.failure_rate.warning_percent).label("warning"));
    }
    println!("{}", rate_chart.render(&frame));

    // 未指定目标时附每目标对比。
    if target_id.is_none() && config.targets.len() > 1 {
        let totals = metrics::target_totals(pool, start, end).await?;
        let mut names: Vec<String> = Vec::new();
        let mut values: Vec<f64> = Vec::new();
        for (id, sent, _failed) in totals {
            let name = config
                .targets
                .iter()
                .find(|item| item.id == id)
                .map(|item| item.name.clone())
                .unwrap_or_else(|| id.to_string());
            names.push(name);
            values.push(sent as f64);
        }
        if !names.is_empty() {
            println!(
                "{}",
                malevich::bar(names, &values[..])
                    .title("sent by target")
                    .render(&frame)
            );
        }
    }
    Ok(())
}

// ---- 通知策略 ----

async fn alerts(pool: &Pool, command: &AlertsCommand) -> CliResult {
    match command {
        AlertsCommand::Show { json } => {
            let (config, revision) = load_current(pool).await?;
            if *json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "revision": revision, "alerts": config.alerts,
                    }))?
                );
            } else {
                println!("Syslog 通知策略（版本 #{revision}）");
                print_alerts(&config);
            }
            Ok(())
        }
        AlertsCommand::Set {
            window_minutes,
            cooldown_seconds,
            failure_rate,
            failure_rate_warning,
            failure_rate_critical,
            min_samples,
            p95,
            p95_warning,
            p95_critical,
            p99,
            p99_warning,
            p99_critical,
            reason,
        } => {
            let (mut config, revision) = load_current(pool).await?;
            let alerts = &mut config.alerts;
            if let Some(value) = window_minutes {
                alerts.window_minutes = *value;
            }
            if let Some(value) = cooldown_seconds {
                alerts.cooldown_seconds = *value;
            }
            if let Some(value) = failure_rate {
                alerts.failure_rate.enabled = value.enabled();
            }
            if let Some(value) = failure_rate_warning {
                alerts.failure_rate.warning_percent = *value;
            }
            if let Some(value) = failure_rate_critical {
                alerts.failure_rate.critical_percent = *value;
            }
            if let Some(value) = min_samples {
                alerts.failure_rate.min_samples = *value;
            }
            if let Some(value) = p95 {
                alerts.latency_p95.enabled = value.enabled();
            }
            if let Some(value) = p95_warning {
                alerts.latency_p95.warning_ms = *value;
            }
            if let Some(value) = p95_critical {
                alerts.latency_p95.critical_ms = *value;
            }
            if let Some(value) = p99 {
                alerts.latency_p99.enabled = value.enabled();
            }
            if let Some(value) = p99_warning {
                alerts.latency_p99.warning_ms = *value;
            }
            if let Some(value) = p99_critical {
                alerts.latency_p99.critical_ms = *value;
            }
            let revision =
                save_change(pool, &config, revision, reason, "cli.syslog.alerts_set").await?;
            println!("通知策略已保存，当前版本 #{revision}");
            Ok(())
        }
    }
}

// ---- 历史日志回填 ----

async fn backfill(pool: &Pool, command: &BackfillCommand) -> CliResult {
    use crate::syslog::backfill;
    match command {
        BackfillCommand::Create {
            days,
            start,
            end,
            json,
        } => {
            let (range_start, range_end) = backfill::resolve_range(*days, *start, *end)?;
            let id = backfill::create_job(pool, None, range_start, range_end).await?;
            let mut event =
                AuditEvent::system("configuration", "cli.syslog.backfill_create", "success")
                    .resource("syslog_backfill_job", id.to_string());
            event.metadata = json!({"rangeStart": range_start, "rangeEnd": range_end});
            write_standalone(pool, &AuditContext::cli("syslog backfill create"), &event).await;
            if *json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "id": id, "rangeStart": range_start, "rangeEnd": range_end,
                    }))?
                );
            } else {
                println!(
                    "回填任务已下发：{id}\n范围：{} ～ {}\n由运行中的服务执行；用 `syslog backfill list` 查看进度。",
                    range_start.format("%Y-%m-%d %H:%M:%S UTC"),
                    range_end.format("%Y-%m-%d %H:%M:%S UTC")
                );
            }
            Ok(())
        }
        BackfillCommand::List { json } => {
            let jobs = backfill::list_jobs(pool, 20).await?;
            if *json {
                println!("{}", serde_json::to_string_pretty(&json!({"jobs": jobs}))?);
                return Ok(());
            }
            if jobs.is_empty() {
                println!("暂无回填任务。");
                return Ok(());
            }
            for job in &jobs {
                println!(
                    "  {}　{}　{} ～ {}　处理 {} / 发送 {} / 失败 {}",
                    job.id,
                    job.status,
                    job.range_start.format("%m-%d %H:%M"),
                    job.range_end.format("%m-%d %H:%M"),
                    job.processed_count,
                    job.sent_count,
                    job.failed_count
                );
                if !job.last_error.is_empty() {
                    println!("    错误：{}", job.last_error);
                }
            }
            Ok(())
        }
        BackfillCommand::Cancel { id } => {
            let job_id = Uuid::parse_str(id).map_err(|_| "任务 ID 必须为 UUID")?;
            if backfill::cancel_job(pool, job_id).await? {
                let event =
                    AuditEvent::system("configuration", "cli.syslog.backfill_cancel", "success")
                        .resource("syslog_backfill_job", job_id.to_string());
                write_standalone(pool, &AuditContext::cli("syslog backfill cancel"), &event).await;
                println!("已请求取消任务 {job_id}");
                Ok(())
            } else {
                Err("任务不存在或已结束".into())
            }
        }
    }
}
