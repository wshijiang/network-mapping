//! 分钟级转发指标：worker 内存聚合 → 每分钟 upsert；统计查询供 Web API 与 CLI 共用。

use std::time::Duration;

use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::runtime_config::RuntimeConfig;
use crate::syslog::config::SyslogConfig;

pub const SOURCE_KEYS: [&str; 4] = ["system", "audit", "access", "scanner"];

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    System,
    Audit,
    Access,
    Scanner,
}

impl Source {
    pub const ALL: [Source; 4] = [
        Source::System,
        Source::Audit,
        Source::Access,
        Source::Scanner,
    ];

    pub fn index(self) -> usize {
        match self {
            Self::System => 0,
            Self::Audit => 1,
            Self::Access => 2,
            Self::Scanner => 3,
        }
    }

    pub fn as_str(self) -> &'static str {
        SOURCE_KEYS[self.index()]
    }
}

/// 单个目标当前分钟的聚合器。延迟样本有上限，超限均匀降采样。
pub struct MinuteMetrics {
    pub bucket_start: DateTime<Utc>,
    pub sent: u64,
    pub failed: u64,
    pub dropped: u64,
    latencies: Vec<f32>,
    by_source: [u64; 4],
}

const MAX_LATENCY_SAMPLES: usize = 65_536;

impl MinuteMetrics {
    pub fn new(bucket_start: DateTime<Utc>) -> Self {
        Self {
            bucket_start,
            sent: 0,
            failed: 0,
            dropped: 0,
            latencies: Vec::new(),
            by_source: [0; 4],
        }
    }

    pub fn record(&mut self, source: Source, success: bool, latency_ms: f64) {
        if success {
            self.sent += 1;
            self.by_source[source.index()] += 1;
            if self.latencies.len() >= MAX_LATENCY_SAMPLES {
                // 均匀降采样：保留偶数位样本，保持分布形状。
                let mut kept = Vec::with_capacity(MAX_LATENCY_SAMPLES / 2);
                for (index, value) in self.latencies.iter().enumerate() {
                    if index % 2 == 0 {
                        kept.push(*value);
                    }
                }
                self.latencies = kept;
            }
            self.latencies.push(latency_ms as f32);
        } else {
            self.failed += 1;
        }
    }

    pub fn record_dropped(&mut self, count: u64) {
        self.dropped += count;
    }

    pub fn is_empty(&self) -> bool {
        self.sent == 0 && self.failed == 0 && self.dropped == 0
    }

    /// 排序后计算分位数；无样本时返回 None。
    pub fn percentiles(&mut self) -> (Option<f32>, Option<f32>, Option<f32>, Option<f32>) {
        if self.latencies.is_empty() {
            return (None, None, None, None);
        }
        self.latencies
            .sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let pick = |percent: f64| -> Option<f32> {
            let count = self.latencies.len();
            let index = ((percent / 100.0) * count as f64).ceil() as usize;
            let index = index.saturating_sub(1).min(count - 1);
            self.latencies.get(index).copied()
        };
        (
            pick(50.0),
            pick(95.0),
            pick(99.0),
            self.latencies.last().copied(),
        )
    }

    pub fn by_source_json(&self) -> Value {
        let mut map = Map::new();
        for (index, key) in SOURCE_KEYS.iter().enumerate() {
            if self.by_source[index] > 0 {
                map.insert((*key).to_owned(), Value::from(self.by_source[index]));
            }
        }
        Value::Object(map)
    }
}

pub fn minute_bucket(at: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp(at.timestamp().div_euclid(60) * 60, 0).unwrap_or(at)
}

/// 单写者（每目标一个 worker）：直接替换该分钟行。
pub async fn flush(
    pool: &Pool,
    target_id: Uuid,
    metrics: &mut MinuteMetrics,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if metrics.is_empty() {
        return Ok(());
    }
    let (p50, p95, p99, max) = metrics.percentiles();
    let by_source = metrics.by_source_json();
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO syslog_metric_minute \
             (target_id, bucket_start, sent, failed, dropped, p50_ms, p95_ms, p99_ms, max_ms, by_source) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) \
             ON CONFLICT (target_id, bucket_start) DO UPDATE SET \
             sent=EXCLUDED.sent, failed=EXCLUDED.failed, dropped=EXCLUDED.dropped, \
             p50_ms=EXCLUDED.p50_ms, p95_ms=EXCLUDED.p95_ms, p99_ms=EXCLUDED.p99_ms, \
             max_ms=EXCLUDED.max_ms, by_source=EXCLUDED.by_source",
            &[
                &target_id,
                &metrics.bucket_start,
                &(metrics.sent as i64),
                &(metrics.failed as i64),
                &(metrics.dropped as i64),
                &p50,
                &p95,
                &p99,
                &max,
                &by_source,
            ],
        )
        .await?;
    Ok(())
}

// ---- 统计查询（Web API 与 CLI 共用） ----

pub struct StatsQuery {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub bucket_seconds: i64,
    pub target_id: Option<Uuid>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TrendPoint {
    pub bucket: DateTime<Utc>,
    pub sent: i64,
    pub failed: i64,
    pub dropped: i64,
    pub failure_rate: f64,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
    pub by_source: Map<String, Value>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Summary {
    pub sent: i64,
    pub failed: i64,
    pub dropped: i64,
    pub failure_rate: f64,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
    pub by_source: Map<String, Value>,
}

pub fn failure_rate(sent: i64, failed: i64) -> f64 {
    let total = sent + failed;
    if total <= 0 {
        0.0
    } else {
        failed as f64 / total as f64
    }
}

pub fn window_range(window: &str) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let seconds: i64 = match window {
        "1h" => 3600,
        "24h" => 86_400,
        "7d" => 604_800,
        _ => return None,
    };
    let end = Utc::now();
    Some((end - chrono::Duration::seconds(seconds), end))
}

/// auto 按跨度自适应；固定档校验桶数上限（与请求日志统计同口径）。
pub fn resolve_granularity(
    requested: Option<&str>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<i64, String> {
    let span = (end - start).num_seconds().max(1);
    let seconds = match requested.unwrap_or("auto") {
        "auto" => {
            if span <= 7200 {
                60
            } else if span <= 86_400 {
                300
            } else {
                3600
            }
        }
        "1m" => 60,
        "5m" => 300,
        "15m" => 900,
        "30m" => 1800,
        "1h" => 3600,
        "2h" => 7200,
        "6h" => 21_600,
        _ => return Err("granularity 必须为 auto/1m/5m/15m/30m/1h/2h/6h".into()),
    };
    if (span + seconds - 1) / seconds > 1500 {
        return Err("时间范围与粒度组合产生的数据点过多".into());
    }
    Ok(seconds)
}

pub async fn query(
    pool: &Pool,
    query: &StatsQuery,
) -> Result<(Summary, Vec<TrendPoint>), Box<dyn std::error::Error + Send + Sync>> {
    let client = pool.get().await?;
    let target_filter = if query.target_id.is_some() {
        " AND target_id = $4"
    } else {
        ""
    };

    // 汇总：计数求和；百分位取窗口内最差分钟（保守口径，界面已标注）。
    let summary_sql = format!(
        "SELECT COALESCE(SUM(sent),0)::BIGINT AS sent, COALESCE(SUM(failed),0)::BIGINT AS failed, \
         COALESCE(SUM(dropped),0)::BIGINT AS dropped, MAX(p95_ms) AS p95, MAX(p99_ms) AS p99 \
         FROM syslog_metric_minute WHERE bucket_start >= $1 AND bucket_start < $2{target_filter}"
    );
    let mut summary_params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
        vec![&query.start, &query.end];
    if let Some(target_id) = &query.target_id {
        summary_params.push(target_id);
    }
    let row = client.query_one(&summary_sql, &summary_params).await?;
    let sent: i64 = row.get("sent");
    let failed: i64 = row.get("failed");
    let dropped: i64 = row.get("dropped");
    let p95: Option<f32> = row.get("p95");
    let p99: Option<f32> = row.get("p99");

    let source_sql = format!(
        "SELECT e.key AS key, SUM(e.value::BIGINT)::BIGINT AS total \
         FROM syslog_metric_minute m, LATERAL jsonb_each_text(m.by_source) e \
         WHERE m.bucket_start >= $1 AND m.bucket_start < $2{target_filter} \
         GROUP BY e.key"
    );
    let source_rows = client.query(&source_sql, &summary_params).await?;
    let mut by_source = Map::new();
    for source_row in &source_rows {
        let key: String = source_row.get("key");
        let total: i64 = source_row.get("total");
        by_source.insert(key, Value::from(total));
    }
    let summary = Summary {
        sent,
        failed,
        dropped,
        failure_rate: failure_rate(sent, failed),
        p95_ms: p95.map(f64::from),
        p99_ms: p99.map(f64::from),
        by_source,
    };

    // 趋势：epoch 分桶 + generate_series 补空桶，保证时间轴连续。
    let bucket = query.bucket_seconds;
    let trend_sql = format!(
        "WITH bucket_range AS ( \
             SELECT generate_series( \
                 (EXTRACT(EPOCH FROM $1::TIMESTAMPTZ)::BIGINT / $3::BIGINT) * $3::BIGINT, \
                 ((EXTRACT(EPOCH FROM $2::TIMESTAMPTZ)::BIGINT - 1) / $3::BIGINT) * $3::BIGINT, \
                 $3::BIGINT)::BIGINT AS bucket_start \
         ), aggregated AS ( \
             SELECT (EXTRACT(EPOCH FROM bucket_start)::BIGINT / $3::BIGINT) * $3::BIGINT AS bucket_start, \
                    SUM(sent)::BIGINT AS sent, SUM(failed)::BIGINT AS failed, SUM(dropped)::BIGINT AS dropped, \
                    MAX(p95_ms) AS p95, MAX(p99_ms) AS p99 \
             FROM syslog_metric_minute WHERE bucket_start >= $1 AND bucket_start < $2{target_filter} \
             GROUP BY 1 \
         ), source_agg AS ( \
             SELECT (EXTRACT(EPOCH FROM m.bucket_start)::BIGINT / $3::BIGINT) * $3::BIGINT AS bucket_start, \
                    e.key AS key, SUM(e.value::BIGINT)::BIGINT AS total \
             FROM syslog_metric_minute m, LATERAL jsonb_each_text(m.by_source) e \
             WHERE m.bucket_start >= $1 AND m.bucket_start < $2{target_filter} \
             GROUP BY 1, 2 \
         ) \
         SELECT to_timestamp(b.bucket_start) AS bucket, \
                COALESCE(a.sent, 0)::BIGINT AS sent, COALESCE(a.failed, 0)::BIGINT AS failed, \
                COALESCE(a.dropped, 0)::BIGINT AS dropped, a.p95 AS p95, a.p99 AS p99, \
                (SELECT jsonb_object_agg(s.key, s.total) FROM source_agg s WHERE s.bucket_start = b.bucket_start) AS by_source \
         FROM bucket_range b LEFT JOIN aggregated a USING (bucket_start) \
         ORDER BY b.bucket_start"
    );
    let mut trend_params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
        vec![&query.start, &query.end, &bucket];
    if let Some(target_id) = &query.target_id {
        trend_params.push(target_id);
    }
    let rows = client.query(&trend_sql, &trend_params).await?;
    let trend = rows
        .iter()
        .map(|row| {
            let sent: i64 = row.get("sent");
            let failed: i64 = row.get("failed");
            let p95: Option<f32> = row.get("p95");
            let p99: Option<f32> = row.get("p99");
            let by_source: Option<Value> = row.get("by_source");
            TrendPoint {
                bucket: row.get("bucket"),
                sent,
                failed,
                dropped: row.get("dropped"),
                failure_rate: failure_rate(sent, failed),
                p95_ms: p95.map(f64::from),
                p99_ms: p99.map(f64::from),
                by_source: by_source
                    .and_then(|value| value.as_object().cloned())
                    .unwrap_or_default(),
            }
        })
        .collect();
    Ok((summary, trend))
}

/// 每目标窗口总量（CLI 对比条形图用）。
pub async fn target_totals(
    pool: &Pool,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Vec<(Uuid, i64, i64)>, Box<dyn std::error::Error + Send + Sync>> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT target_id, SUM(sent)::BIGINT AS sent, SUM(failed)::BIGINT AS failed \
             FROM syslog_metric_minute WHERE bucket_start >= $1 AND bucket_start < $2 \
             GROUP BY target_id ORDER BY sent DESC",
            &[&start, &end],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| (row.get("target_id"), row.get("sent"), row.get("failed")))
        .collect())
}

/// 指标保留期清理：小间隔检查配置，实际清理最多每天一次（同请求日志模式）。
pub async fn run_retention(pool: Pool, config: RuntimeConfig<SyslogConfig>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_run: Option<std::time::Instant> = None;
    let mut applied_revision = 0;
    let mut changes = config.subscribe();
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            changed = changes.changed() => if changed.is_err() { return; }
        }
        let settings = config.get().await;
        if settings.revision != applied_revision {
            applied_revision = settings.revision;
            last_run = None;
        }
        if last_run.is_some_and(|at: std::time::Instant| at.elapsed() < Duration::from_secs(86_400))
        {
            continue;
        }
        last_run = Some(std::time::Instant::now());
        let cutoff =
            Utc::now() - chrono::Duration::days(i64::from(settings.value.metrics_retention_days));
        loop {
            let client = match pool.get().await {
                Ok(client) => client,
                Err(error) => {
                    tracing::warn!(event = "SyslogMetricsRetentionError", error_message = %error, "syslog 指标清理获取连接失败");
                    break;
                }
            };
            match client
                .execute(
                    "DELETE FROM syslog_metric_minute WHERE ctid IN (\
                     SELECT ctid FROM syslog_metric_minute WHERE bucket_start < $1 LIMIT 5000)",
                    &[&cutoff],
                )
                .await
            {
                Ok(5000) => {}
                Ok(_) => break,
                Err(error) => {
                    tracing::warn!(event = "SyslogMetricsRetentionError", error_message = %error, "syslog 指标清理失败");
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_use_nearest_rank() {
        let mut metrics = MinuteMetrics::new(minute_bucket(Utc::now()));
        for value in 1..=100 {
            metrics.record(Source::System, true, value as f64);
        }
        let (p50, p95, p99, max) = metrics.percentiles();
        assert_eq!(p50, Some(50.0));
        assert_eq!(p95, Some(95.0));
        assert_eq!(p99, Some(99.0));
        assert_eq!(max, Some(100.0));
    }

    #[test]
    fn empty_metrics_have_no_percentiles() {
        let mut metrics = MinuteMetrics::new(minute_bucket(Utc::now()));
        assert_eq!(metrics.percentiles(), (None, None, None, None));
        assert!(metrics.is_empty());
    }

    #[test]
    fn by_source_counts_only_successes() {
        let mut metrics = MinuteMetrics::new(minute_bucket(Utc::now()));
        metrics.record(Source::Access, true, 1.0);
        metrics.record(Source::Access, true, 2.0);
        metrics.record(Source::Audit, true, 1.0);
        metrics.record(Source::Scanner, false, 0.0);
        let json = metrics.by_source_json();
        assert_eq!(json["access"], 2);
        assert_eq!(json["audit"], 1);
        assert!(json.get("scanner").is_none());
        assert_eq!(metrics.failed, 1);
    }

    #[test]
    fn latency_samples_are_decimated_not_unbounded() {
        let mut metrics = MinuteMetrics::new(minute_bucket(Utc::now()));
        for index in 0..(MAX_LATENCY_SAMPLES + 10) {
            metrics.record(Source::System, true, index as f64);
        }
        assert!(metrics.latencies.len() <= MAX_LATENCY_SAMPLES);
        assert_eq!(metrics.sent, (MAX_LATENCY_SAMPLES + 10) as u64);
    }

    #[test]
    fn minute_bucket_truncates_to_minute() {
        let at: DateTime<Utc> = "2026-11-14T10:00:59.999Z".parse().unwrap();
        let bucket = minute_bucket(at);
        assert_eq!(bucket.to_rfc3339(), "2026-11-14T10:00:00+00:00");
    }

    #[test]
    fn granularity_auto_adapts_and_rejects_excessive_buckets() {
        let end = Utc::now();
        let hour = end - chrono::Duration::hours(1);
        assert_eq!(resolve_granularity(None, hour, end).unwrap(), 60);
        let week = end - chrono::Duration::days(7);
        assert_eq!(resolve_granularity(None, week, end).unwrap(), 3600);
        assert!(resolve_granularity(Some("1m"), week, end).is_err());
        assert!(resolve_granularity(Some("bogus"), hour, end).is_err());
    }

    #[test]
    fn failure_rate_handles_zero_samples() {
        assert_eq!(failure_rate(0, 0), 0.0);
        assert_eq!(failure_rate(80, 20), 0.2);
    }
}
