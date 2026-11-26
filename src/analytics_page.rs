//! Published chart projections. Only the background publisher reads the execution facts.
use std::{collections::BTreeSet, time::Duration};

use chrono::{DateTime, Datelike, Days, NaiveDate, Utc};
use chrono_tz::{Asia::Shanghai, Tz};
use deadpool_postgres::{Pool, Transaction};
use serde_json::{Value, json};
use tokio_postgres::IsolationLevel;

use crate::{
    config::{AnalyticsPageRollups, AnalyticsSnapshotConfig},
    runtime_config::RuntimeConfig,
    system_time,
};

const WEEK_OPTIONS: [u64; 3] = [4, 8, 12];
const REFRESH_INTERVAL: Duration = Duration::from_secs(15);
const PUBLICATION_LOCK: i64 = 0x4e4d_4150_4147_4501;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct Window {
    start: NaiveDate,
    end: NaiveDate,
}

impl Window {
    fn new(today: NaiveDate, weeks: u64) -> Self {
        let days_to_monday = u64::from(today.weekday().num_days_from_monday());
        Self {
            start: today - Days::new(days_to_monday + (weeks - 1) * 7),
            end: today + Days::new(1),
        }
    }

    pub(crate) fn for_request(
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        zone: &str,
        now: DateTime<Utc>,
    ) -> Option<Self> {
        let zone: Tz = zone.parse().ok()?;
        // Consider the previous day for requests already in flight at midnight.
        windows(now.with_timezone(&zone).date_naive())
            .into_iter()
            .find(|window| {
                boundary(window.start, zone).ok() == Some(start)
                    && boundary(window.end, zone).ok() == Some(end)
            })
    }

    fn contains(self, day: NaiveDate) -> bool {
        self.start <= day && day < self.end
    }
}

fn windows(today: NaiveDate) -> BTreeSet<Window> {
    [today - Days::new(1), today, today + Days::new(1)]
        .into_iter()
        .flat_map(|day| WEEK_OPTIONS.map(|weeks| Window::new(day, weeks)))
        .collect()
}

fn bounds(windows: &BTreeSet<Window>) -> Window {
    Window {
        start: windows.first().expect("page has preset windows").start,
        end: windows
            .iter()
            .map(|window| window.end)
            .max()
            .expect("page has preset windows"),
    }
}

fn boundary(day: NaiveDate, zone: Tz) -> Result<DateTime<Utc>, String> {
    system_time::scheduled_time(zone, day.and_time(chrono::NaiveTime::MIN))
}

#[derive(Clone, Copy)]
pub(crate) enum Chart {
    Heatmap,
    Distribution(&'static str),
}

pub(crate) struct PublishedChart {
    pub revision: i64,
    pub data_as_of: DateTime<Utc>,
    pub legacy_timezone_error: bool,
    pub data: Value,
}

pub(crate) async fn read(
    pool: &Pool,
    window: Window,
    filters: &crate::handlers::data_saa::AnalysisFilters,
    owner_id: Option<i32>,
    chart: Chart,
) -> Result<Option<PublishedChart>, String> {
    let scope = json!([owner_id, filters.scanner_id, filters.task_source]);
    let legacy_start = filters.start_at.with_timezone(&Shanghai).date_naive();
    let legacy_end = filters.end_at.with_timezone(&Shanghai).date_naive();
    let started = std::time::Instant::now();
    let client = pool.get().await.map_err(diagnostics)?;
    let connection_ms = started.elapsed().as_millis() as u64;
    let (sql, dimension) = match chart {
        Chart::Heatmap => (READ_HEATMAP, None),
        Chart::Distribution(dimension) => (READ_DISTRIBUTION, Some(dimension)),
    };
    let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = vec![
        &window.start,
        &window.end,
        &filters.timezone,
        &scope,
        &filters.start_at,
        &filters.end_at,
        &legacy_start,
        &legacy_end,
    ];
    if let Some(ref dimension) = dimension {
        params.push(dimension);
    }
    let started = std::time::Instant::now();
    let result = client.query_opt(sql, &params).await.map_err(diagnostics)?;
    tracing::debug!(
        event = "AnalysisPageSnapshotRead",
        connection_ms,
        query_ms = started.elapsed().as_millis() as u64,
        ready = result.is_some(),
    );
    Ok(result.map(|row| PublishedChart {
        revision: row.get("revision"),
        data_as_of: row.get("data_as_of"),
        legacy_timezone_error: row.get("legacy_timezone_error"),
        data: row.get("data"),
    }))
}

// Check invalidation and read chart rows under the same PostgreSQL statement snapshot.
macro_rules! read_sql {
    ($select:literal) => {
        concat!(
            "WITH publication AS (
                 SELECT revision, data_as_of FROM analytics_page_publication
                 WHERE singleton AND timezone = $3
                 AND $1::DATE <= $2::DATE
                 AND $2 BETWEEN calendar_day AND calendar_day + 2
                 AND EXISTS (
                     SELECT FROM runtime_configuration WHERE namespace = 'analytics_snapshot'
                     AND document->>'mode' = 'snapshot' AND document->>'page_rollups' = 'read'
                 )
                 AND EXISTS (SELECT FROM analytics_watermark WHERE watermark_key = 'scan_analysis')
                 AND NOT EXISTS (
                     SELECT 1 FROM analytics_page_dirty
                     WHERE destructive AND (rebuild
                         OR (first_instant < $6 AND last_instant >= $5)
                         OR (first_legacy_day <= $8 AND last_legacy_day >= $7))
                 )
             ) ",
            $select,
        )
    };
}

const READ_HEATMAP: &str = read_sql!(
    "SELECT revision, data_as_of,
         $3 <> 'Asia/Shanghai' AND EXISTS (
             SELECT 1 FROM analytics_page_legacy_day WHERE scope = $4 AND day BETWEEN $7 AND $8
         ) AS legacy_timezone_error,
         COALESCE((SELECT jsonb_agg(jsonb_build_object('date', day, 'count', count) ORDER BY day)
                   FROM analytics_page_heat_day WHERE scope = $4 AND day >= $1 AND day < $2),
                  '[]'::JSONB) AS data
     FROM publication"
);
const READ_DISTRIBUTION: &str = read_sql!(
    "SELECT revision, data_as_of, FALSE AS legacy_timezone_error,
         COALESCE((SELECT jsonb_build_object('total', total, 'items', items)
                   FROM analytics_page_distribution_window
                   WHERE window_start = $1 AND window_end = $2 AND scope = $4 AND dimension = $9),
                  '{\"total\":0,\"items\":[]}'::JSONB) AS data
     FROM publication"
);

#[derive(serde::Serialize)]
pub(crate) struct Progress {
    revision: i64,
    timezone: String,
    data_as_of: DateTime<Utc>,
    ready: bool,
    pending_changes: i64,
}

pub(crate) async fn progress(
    client: &deadpool_postgres::Client,
) -> Result<Option<Progress>, tokio_postgres::Error> {
    let row = client.query_opt(
        "SELECT revision, timezone, data_as_of, (SELECT count(*) FROM analytics_page_dirty) AS pending_changes,
           timezone = COALESCE((SELECT document->>'timezone' FROM runtime_configuration WHERE namespace = 'general'), 'Asia/Shanghai')
           AND calendar_day = (NOW() AT TIME ZONE timezone)::DATE
           AND NOT EXISTS (SELECT FROM analytics_page_dirty WHERE destructive) AS ready
         FROM analytics_page_publication WHERE singleton",
        &[],
    ).await?;
    Ok(row.map(|row| Progress {
        revision: row.get("revision"),
        timezone: row.get("timezone"),
        data_as_of: row.get("data_as_of"),
        ready: row.get("ready"),
        pending_changes: row.get("pending_changes"),
    }))
}

fn diagnostics(error: impl std::error::Error + 'static) -> String {
    crate::logs::write::error_chain_diagnostics(&error)
}

pub(crate) async fn run_worker(config: RuntimeConfig<AnalyticsSnapshotConfig>, pool: Pool) {
    let mut changes = config.subscribe();
    loop {
        let settings = config.get().await.value;
        if settings.mode.runs_worker() && settings.page_rollups != AnalyticsPageRollups::Off {
            match tokio::time::timeout(Duration::from_secs(180), refresh(&pool, Utc::now())).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(event = "AnalysisPagePublicationFailed", %error),
                Err(_) => tracing::warn!(event = "AnalysisPagePublicationTimedOut"),
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(REFRESH_INTERVAL) => {}
            changed = changes.changed() => if changed.is_err() { return; }
        }
    }
}

struct DirtyRange {
    first: Option<DateTime<Utc>>,
    last: Option<DateTime<Utc>>,
    first_legacy: Option<NaiveDate>,
    last_legacy: Option<NaiveDate>,
}

impl DirtyRange {
    fn affects_day(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> bool {
        matches!((self.first, self.last), (Some(first), Some(last)) if first < end && last >= start)
    }

    fn affects_legacy_day(&self, day: NaiveDate) -> bool {
        matches!((self.first_legacy, self.last_legacy), (Some(first), Some(last)) if first <= day && last >= day)
    }
}

async fn refresh(pool: &Pool, now: DateTime<Utc>) -> Result<(), String> {
    let mut client = pool.get().await.map_err(diagnostics)?;
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .start()
        .await
        .map_err(diagnostics)?;
    tx.batch_execute("SET LOCAL statement_timeout = '30s'; SET LOCAL lock_timeout = '2s';")
        .await
        .map_err(diagnostics)?;
    let active: bool = tx.query_one(
        "SELECT pg_try_advisory_xact_lock($1) AND EXISTS (
             SELECT FROM runtime_configuration WHERE namespace = 'analytics_snapshot'
             AND document->>'mode' IN ('shadow', 'snapshot') AND document->>'page_rollups' IN ('build', 'read')
         )",
        &[&PUBLICATION_LOCK],
    ).await.map_err(diagnostics)?.get(0);
    if !active {
        return Ok(());
    }
    let data_as_of: DateTime<Utc> = tx
        .query_one("SELECT transaction_timestamp()", &[])
        .await
        .map_err(diagnostics)?
        .get(0);
    if !tx
        .query_one(
            "SELECT EXISTS (SELECT FROM analytics_watermark WHERE watermark_key = 'scan_analysis')",
            &[],
        )
        .await
        .map_err(diagnostics)?
        .get::<_, bool>(0)
    {
        return Ok(());
    }
    let calendar_zone: String = tx.query_one(
        "SELECT COALESCE((SELECT document->>'timezone' FROM runtime_configuration WHERE namespace = 'general'), 'Asia/Shanghai')",
        &[],
    ).await.map_err(diagnostics)?.get(0);
    let zone: Tz = calendar_zone.parse().map_err(diagnostics)?;
    let today = now.with_timezone(&zone).date_naive();
    let current_windows = windows(today);
    let previous = tx
        .query_opt(
            "SELECT timezone, calendar_day FROM analytics_page_publication WHERE singleton",
            &[],
        )
        .await
        .map_err(diagnostics)?;
    let changes = tx
        .query("SELECT * FROM analytics_page_dirty", &[])
        .await
        .map_err(diagnostics)?;
    let rebuild = changes.iter().any(|row| row.get::<_, bool>("rebuild"));
    let previous_windows = previous
        .filter(|row| !rebuild && row.get::<_, String>("timezone") == calendar_zone)
        .map(|row| windows(row.get("calendar_day")));
    if changes.is_empty() && previous_windows.as_ref() == Some(&current_windows) {
        return Ok(());
    }
    let dirty = changes
        .into_iter()
        .map(|row| DirtyRange {
            first: row.get("first_instant"),
            last: row.get("last_instant"),
            first_legacy: row.get("first_legacy_day"),
            last_legacy: row.get("last_legacy_day"),
        })
        .collect::<Vec<_>>();
    let retained = bounds(&current_windows);
    let previous_bounds = previous_windows.as_ref().map(bounds);
    let started = std::time::Instant::now();
    let changed =
        refresh_days(&tx, retained, previous_bounds, &dirty, &calendar_zone, zone).await?;

    for window in &current_windows {
        if previous_windows
            .as_ref()
            .is_none_or(|old| !old.contains(window))
            || changed.iter().any(|day| window.contains(*day))
        {
            tx.execute(
                "SELECT analytics_page_refresh_window($1, $2)",
                &[&window.start, &window.end],
            )
            .await
            .map_err(diagnostics)?;
        }
    }
    if let Some(previous_windows) = previous_windows {
        for expired in previous_windows.difference(&current_windows) {
            tx.execute("DELETE FROM analytics_page_distribution_window WHERE window_start = $1 AND window_end = $2",
                &[&expired.start, &expired.end]).await.map_err(diagnostics)?;
        }
    } else {
        // A timezone change or a newly enabled publisher may have left arbitrary old windows.
        let starts = current_windows
            .iter()
            .map(|window| window.start)
            .collect::<Vec<_>>();
        let ends = current_windows
            .iter()
            .map(|window| window.end)
            .collect::<Vec<_>>();
        tx.execute(
            "DELETE FROM analytics_page_distribution_window w WHERE NOT EXISTS (
            SELECT FROM unnest($1::DATE[], $2::DATE[]) AS active(start_day, end_day)
            WHERE start_day = w.window_start AND end_day = w.window_end)",
            &[&starts, &ends],
        )
        .await
        .map_err(diagnostics)?;
    }

    // Repeatable read deletes only events visible in this transaction's snapshot.
    tx.execute("DELETE FROM analytics_page_dirty", &[])
        .await
        .map_err(diagnostics)?;
    let revision: i64 = tx.query_one(
        "INSERT INTO analytics_page_publication (singleton, revision, timezone, calendar_day, data_as_of)
         VALUES (TRUE, 1, $1, $2, $3) ON CONFLICT (singleton) DO UPDATE
         SET revision = analytics_page_publication.revision + 1, timezone = EXCLUDED.timezone,
             calendar_day = EXCLUDED.calendar_day, data_as_of = EXCLUDED.data_as_of
         RETURNING revision",
        &[&calendar_zone, &today, &data_as_of],
    ).await.map_err(diagnostics)?.get(0);
    tx.commit().await.map_err(diagnostics)?;
    tracing::info!(
        event = "AnalysisPageSnapshotPublished",
        revision,
        changed_days = changed.len(),
        duration_ms = started.elapsed().as_millis() as u64,
    );
    Ok(())
}

async fn refresh_days(
    tx: &Transaction<'_>,
    retained: Window,
    previous: Option<Window>,
    dirty: &[DirtyRange],
    calendar_zone: &str,
    zone: Tz,
) -> Result<Vec<NaiveDate>, String> {
    let mut changed = Vec::new();
    for day in retained
        .start
        .iter_days()
        .take_while(|day| *day < retained.end)
    {
        let start = boundary(day, zone)?;
        let end = boundary(day + Days::new(1), zone)?;
        if previous.is_none_or(|old| !old.contains(day))
            || dirty.iter().any(|range| {
                range.affects_day(start, end) || (zone == Shanghai && range.affects_legacy_day(day))
            })
        {
            tx.execute(
                "SELECT analytics_page_refresh_day($1, $2, $3, $4)",
                &[&day, &start, &end, &calendar_zone],
            )
            .await
            .map_err(diagnostics)?;
            changed.push(day);
        }
    }

    // The legacy compatibility test uses Shanghai dates and an inclusive upper bound.
    let legacy_bounds = |range: Window| Window {
        start: range.start - Days::new(2),
        end: range.end + Days::new(2),
    };
    let legacy = legacy_bounds(retained);
    let previous_legacy = previous.map(legacy_bounds);
    for day in legacy.start.iter_days().take_while(|day| *day < legacy.end) {
        if previous_legacy.is_none_or(|old| !old.contains(day))
            || dirty.iter().any(|range| range.affects_legacy_day(day))
        {
            tx.execute("SELECT analytics_page_refresh_legacy_day($1)", &[&day])
                .await
                .map_err(diagnostics)?;
        }
    }
    for (sql, range) in [
        (
            "DELETE FROM analytics_page_heat_day WHERE day < $1 OR day >= $2",
            retained,
        ),
        (
            "DELETE FROM analytics_page_distribution_day WHERE day < $1 OR day >= $2",
            retained,
        ),
        (
            "DELETE FROM analytics_page_legacy_day WHERE day < $1 OR day >= $2",
            legacy,
        ),
    ] {
        tx.execute(sql, &[&range.start, &range.end])
            .await
            .map_err(diagnostics)?;
    }
    Ok(changed)
}

#[cfg(test)]
#[path = "analytics_page_tests.rs"]
mod tests;
