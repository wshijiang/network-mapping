//! Syslog 通知策略评估器：整体失败率 / 发送耗时 P95 / P99 三条独立规则。
//!
//! 命中后构造 `HealthEvent` 并复用现有健康告警管道（`record_health_alert`）：
//! 冷却去重、`health_alert` 历史、邮件与机器人渠道 fanout、健康告警页可见。
//! 不依赖 monitor 总开关，syslog 规则自治。

use std::time::Duration;

use deadpool_postgres::Pool;
use tokio::sync::watch;

use crate::monitor::HealthEvent;
use crate::runtime_config::RuntimeConfig;
use crate::syslog::config::SyslogConfig;

pub async fn run_evaluator(
    pool: Pool,
    config: RuntimeConfig<SyslogConfig>,
    mut stopping: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = stopping.changed() => return,
            _ = ticker.tick() => {}
        }
        let settings = config.get().await.value;
        if !settings.enabled || !settings.alerts.any_enabled() {
            continue;
        }
        match evaluate(&pool, &settings).await {
            Ok(events) => {
                for event in events {
                    if let Err(error) = crate::monitor::record_health_alert(
                        &pool,
                        &event,
                        settings.alerts.cooldown_seconds,
                    )
                    .await
                    {
                        tracing::warn!(
                            event = "SyslogAlertRecordFailed",
                            component = "syslog",
                            error_message = %error,
                            "syslog 告警写入健康告警管道失败"
                        );
                    }
                }
            }
            Err(error) => {
                tracing::warn!(
                    event = "SyslogAlertEvaluateFailed",
                    component = "syslog",
                    error_message = %error,
                    "syslog 告警评估失败"
                );
            }
        }
    }
}

/// 阈值判定：返回命中的严重级别。独立出来便于单元测试。
pub fn rule_severity(value: f64, warning: f64, critical: f64) -> Option<&'static str> {
    if value >= critical {
        Some("critical")
    } else if value >= warning {
        Some("warning")
    } else {
        None
    }
}

struct WindowStats {
    sent: i64,
    failed: i64,
    p95: Option<f64>,
    p99: Option<f64>,
}

async fn evaluate(
    pool: &Pool,
    settings: &SyslogConfig,
) -> Result<Vec<HealthEvent>, Box<dyn std::error::Error + Send + Sync>> {
    let alerts = &settings.alerts;
    let client = pool.get().await?;
    let row = client
        .query_one(
            "SELECT COALESCE(SUM(sent),0)::BIGINT AS sent, COALESCE(SUM(failed),0)::BIGINT AS failed, \
             MAX(p95_ms) AS p95, MAX(p99_ms) AS p99 \
             FROM syslog_metric_minute \
             WHERE bucket_start >= NOW() - ($1::BIGINT * INTERVAL '1 minute')",
            &[&alerts.window_minutes],
        )
        .await?;
    let stats = WindowStats {
        sent: row.get("sent"),
        failed: row.get("failed"),
        p95: row.get::<_, Option<f32>>("p95").map(f64::from),
        p99: row.get::<_, Option<f32>>("p99").map(f64::from),
    };

    // 每目标明细（最多 5 条，按失败数排序），只含计数摘要，不含原始日志。
    let breakdown_rows = client
        .query(
            "SELECT target_id, SUM(sent)::BIGINT AS sent, SUM(failed)::BIGINT AS failed \
             FROM syslog_metric_minute \
             WHERE bucket_start >= NOW() - ($1::BIGINT * INTERVAL '1 minute') \
             GROUP BY target_id ORDER BY SUM(failed) DESC, SUM(sent) DESC LIMIT 5",
            &[&alerts.window_minutes],
        )
        .await?;
    let mut details: Vec<(String, String)> = vec![
        ("统计窗口".into(), format!("{} 分钟", alerts.window_minutes)),
        ("发送成功".into(), stats.sent.to_string()),
        ("发送失败".into(), stats.failed.to_string()),
    ];
    for breakdown in &breakdown_rows {
        let target_id: uuid::Uuid = breakdown.get("target_id");
        let name = settings
            .targets
            .iter()
            .find(|target| target.id == target_id)
            .map(|target| target.name.clone())
            .unwrap_or_else(|| target_id.to_string());
        let sent: i64 = breakdown.get("sent");
        let failed: i64 = breakdown.get("failed");
        details.push((
            format!("目标 {name}"),
            format!("失败 {failed} / 共 {}", sent + failed),
        ));
    }

    let mut events = Vec::new();
    let total = stats.sent + stats.failed;

    if alerts.failure_rate.enabled && total >= alerts.failure_rate.min_samples {
        let rate = stats.failed as f64 / total as f64 * 100.0;
        if let Some(severity) = rule_severity(
            rate,
            alerts.failure_rate.warning_percent,
            alerts.failure_rate.critical_percent,
        ) {
            let mut event_details = details.clone();
            event_details.push(("整体失败率".into(), format!("{rate:.2}%")));
            event_details.push((
                "警告阈值".into(),
                format!("{}%", alerts.failure_rate.warning_percent),
            ));
            event_details.push((
                "严重阈值".into(),
                format!("{}%", alerts.failure_rate.critical_percent),
            ));
            events.push(HealthEvent {
                alert_type: "syslog_failure_rate",
                severity,
                key: "syslog:failure_rate:overall".to_owned(),
                summary: format!(
                    "Syslog 转发整体失败率 {rate:.2}%（{}/{}，窗口 {} 分钟）",
                    stats.failed, total, alerts.window_minutes
                ),
                details: event_details,
                applied_rule: None,
            });
        }
    }

    for (enabled, label, alert_type, value, rule) in [
        (
            alerts.latency_p95.enabled,
            "P95",
            "syslog_latency_p95",
            stats.p95,
            &alerts.latency_p95,
        ),
        (
            alerts.latency_p99.enabled,
            "P99",
            "syslog_latency_p99",
            stats.p99,
            &alerts.latency_p99,
        ),
    ] {
        let Some(value) = value else { continue };
        if !enabled {
            continue;
        }
        if let Some(severity) = rule_severity(value, rule.warning_ms, rule.critical_ms) {
            let mut event_details = details.clone();
            event_details.push((format!("发送耗时 {label}"), format!("{value:.1} ms")));
            event_details.push(("警告阈值".into(), format!("{} ms", rule.warning_ms)));
            event_details.push(("严重阈值".into(), format!("{} ms", rule.critical_ms)));
            events.push(HealthEvent {
                alert_type,
                severity,
                key: format!("syslog:{alert_type}:overall"),
                summary: format!(
                    "Syslog 转发发送耗时 {label} 达到 {value:.1} ms（窗口 {} 分钟内最差分钟）",
                    alerts.window_minutes
                ),
                details: event_details,
                applied_rule: None,
            });
        }
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::rule_severity;

    #[test]
    fn severity_escalates_at_critical_threshold() {
        assert_eq!(rule_severity(1.0, 5.0, 20.0), None);
        assert_eq!(rule_severity(5.0, 5.0, 20.0), Some("warning"));
        assert_eq!(rule_severity(19.9, 5.0, 20.0), Some("warning"));
        assert_eq!(rule_severity(20.0, 5.0, 20.0), Some("critical"));
    }
}
