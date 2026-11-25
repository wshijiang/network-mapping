use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

use crate::admin::UserBaseI;
use crate::logs::write::{database_error_diagnostics, error_logs};

const DEFAULT_RANGE_MINUTES: i64 = 30;
const MAX_RANGE_DAYS: i64 = 30;
pub(crate) const MAX_BUCKETS: i64 = 1_500;
const RESOURCE_HISTORY_SQL: &str = r#"
WITH bucket_range AS (
    SELECT generate_series(
        ($1::BIGINT / $3::BIGINT) * $3::BIGINT,
        (($2::BIGINT - 1) / $3::BIGINT) * $3::BIGINT,
        $3
    )::BIGINT AS bucket_start
), metrics AS (
    SELECT
        (create_time / $3::BIGINT) * $3::BIGINT AS bucket_start,
        CASE WHEN cpu->>'cpu_usage' ~ '^[0-9]+([.][0-9]+)?$'
             THEN (cpu->>'cpu_usage')::DOUBLE PRECISION END AS cpu_usage,
        CASE WHEN ram->>'ram_usage' ~ '^[0-9]+([.][0-9]+)?$'
             THEN (ram->>'ram_usage')::DOUBLE PRECISION
             WHEN ram->>'used_ram' ~ '^[0-9]+([.][0-9]+)?$'
              AND ram->>'total_ram' ~ '^[0-9]+([.][0-9]+)?$'
              AND (ram->>'total_ram')::DOUBLE PRECISION > 0
             THEN (ram->>'used_ram')::DOUBLE PRECISION
                  / (ram->>'total_ram')::DOUBLE PRECISION * 100 END AS ram_usage,
        CASE WHEN ram->>'total_swap' ~ '^[0-9]+([.][0-9]+)?$'
              AND (ram->>'total_swap')::DOUBLE PRECISION > 0
              AND ram->>'swap_usage' ~ '^[0-9]+([.][0-9]+)?$'
             THEN (ram->>'swap_usage')::DOUBLE PRECISION
             WHEN ram->>'total_swap' ~ '^[0-9]+([.][0-9]+)?$'
              AND (ram->>'total_swap')::DOUBLE PRECISION > 0
              AND ram->>'use_swap' ~ '^[0-9]+([.][0-9]+)?$'
             THEN (ram->>'use_swap')::DOUBLE PRECISION
                  / (ram->>'total_swap')::DOUBLE PRECISION * 100 END AS swap_usage,
        CASE WHEN disk->>'disk_total_usage' ~ '^[0-9]+([.][0-9]+)?$'
              AND disk->>'disk_total_space' ~ '^[0-9]+([.][0-9]+)?$'
              AND (disk->>'disk_total_space')::DOUBLE PRECISION > 0
             THEN (disk->>'disk_total_usage')::DOUBLE PRECISION
                  / (disk->>'disk_total_space')::DOUBLE PRECISION * 100 END AS disk_usage
    FROM system_status
    WHERE create_time >= $1 AND create_time < $2
), aggregates AS (
    SELECT bucket_start,
           COUNT(*)::BIGINT AS sample_count,
           AVG(cpu_usage) FILTER (WHERE cpu_usage BETWEEN 0 AND 100) AS cpu_avg,
           MAX(cpu_usage) FILTER (WHERE cpu_usage BETWEEN 0 AND 100) AS cpu_max,
           AVG(ram_usage) FILTER (WHERE ram_usage BETWEEN 0 AND 100) AS ram_avg,
           MAX(ram_usage) FILTER (WHERE ram_usage BETWEEN 0 AND 100) AS ram_max,
           AVG(swap_usage) FILTER (WHERE swap_usage BETWEEN 0 AND 100) AS swap_avg,
           MAX(swap_usage) FILTER (WHERE swap_usage BETWEEN 0 AND 100) AS swap_max,
           AVG(disk_usage) FILTER (WHERE disk_usage BETWEEN 0 AND 100) AS disk_avg,
           MAX(disk_usage) FILTER (WHERE disk_usage BETWEEN 0 AND 100) AS disk_max
    FROM metrics
    GROUP BY bucket_start
)
SELECT b.bucket_start,
       COALESCE(a.sample_count, 0)::BIGINT AS sample_count,
       a.cpu_avg, a.cpu_max, a.ram_avg, a.ram_max, a.swap_avg, a.swap_max,
       a.disk_avg, a.disk_max
FROM bucket_range b
LEFT JOIN aggregates a ON a.bucket_start = b.bucket_start
ORDER BY b.bucket_start;
"#;
const DATABASE_HISTORY_SQL: &str = r#"
WITH bucket_range AS (
    SELECT generate_series(
        ($1::BIGINT / $3::BIGINT) * $3::BIGINT,
        (($2::BIGINT - 1) / $3::BIGINT) * $3::BIGINT,
        $3
    )::BIGINT AS bucket_start
), ranked AS (
    SELECT (create_time / $3::BIGINT) * $3::BIGINT AS bucket_start,
        CASE WHEN db_postgresql->>'db_library_size' ~ '^[0-9]+$'
             THEN (db_postgresql->>'db_library_size')::BIGINT END AS database_size,
        CASE WHEN db_postgresql->>'db_conn' ~ '^[0-9]+$'
             THEN (db_postgresql->>'db_conn')::BIGINT END AS connection_count,
        CASE WHEN jsonb_typeof(db_postgresql->'db_table_size') = 'object'
             THEN db_postgresql->'db_table_size'
             ELSE '{}'::JSONB END AS tables,
        CASE WHEN jsonb_typeof(db_elasticsearch->'enabled') = 'boolean'
             THEN (db_elasticsearch->>'enabled')::BOOLEAN ELSE FALSE END AS elasticsearch_enabled,
        CASE WHEN jsonb_typeof(db_elasticsearch->'available') = 'boolean'
             THEN (db_elasticsearch->>'available')::BOOLEAN ELSE FALSE END AS elasticsearch_available,
        CASE WHEN db_elasticsearch->>'primary_size' ~ '^[0-9]+$'
             THEN (db_elasticsearch->>'primary_size')::BIGINT END AS elasticsearch_primary_size,
        CASE WHEN db_elasticsearch->>'replica_size' ~ '^[0-9]+$'
             THEN (db_elasticsearch->>'replica_size')::BIGINT END AS elasticsearch_replica_size,
        CASE WHEN db_elasticsearch->>'total_size' ~ '^[0-9]+$'
             THEN (db_elasticsearch->>'total_size')::BIGINT END AS elasticsearch_total_size,
        CASE WHEN jsonb_typeof(db_elasticsearch->'indices') = 'object'
             THEN db_elasticsearch->'indices'
             ELSE '{}'::JSONB END AS elasticsearch_indices,
        COUNT(*) OVER (
            PARTITION BY (create_time / $3::BIGINT) * $3::BIGINT
        )::BIGINT AS sample_count,
        ROW_NUMBER() OVER (
            PARTITION BY (create_time / $3::BIGINT) * $3::BIGINT
            ORDER BY create_time DESC, id DESC
        ) AS sample_rank
    FROM system_status
    WHERE create_time >= $1 AND create_time < $2
)
SELECT b.bucket_start,
       COALESCE(r.sample_count, 0)::BIGINT AS sample_count,
       r.database_size,
       r.connection_count,
       COALESCE(r.tables, '{}'::JSONB) AS tables,
       COALESCE(r.elasticsearch_enabled, FALSE) AS elasticsearch_enabled,
       COALESCE(r.elasticsearch_available, FALSE) AS elasticsearch_available,
       r.elasticsearch_primary_size,
       r.elasticsearch_replica_size,
       r.elasticsearch_total_size,
       COALESCE(r.elasticsearch_indices, '{}'::JSONB) AS elasticsearch_indices
FROM bucket_range b
LEFT JOIN ranked r
       ON r.bucket_start = b.bucket_start
      AND r.sample_rank = 1
ORDER BY b.bucket_start;
"#;

#[derive(Deserialize)]
pub(crate) struct ResourceHistoryQuery {
    start_at: Option<DateTime<Utc>>,
    end_at: Option<DateTime<Utc>>,
    granularity: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Granularity {
    TenSeconds,
    ThirtySeconds,
    OneMinute,
    FiveMinutes,
    FifteenMinutes,
    ThirtyMinutes,
    OneHour,
    TwoHours,
    SixHours,
}

impl Granularity {
    pub(crate) fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "10s" => Ok(Self::TenSeconds),
            "30s" => Ok(Self::ThirtySeconds),
            "1m" => Ok(Self::OneMinute),
            "5m" => Ok(Self::FiveMinutes),
            "15m" => Ok(Self::FifteenMinutes),
            "30m" => Ok(Self::ThirtyMinutes),
            "1h" => Ok(Self::OneHour),
            "2h" => Ok(Self::TwoHours),
            "6h" => Ok(Self::SixHours),
            _ => Err("granularity must be auto, 10s, 30s, 1m, 5m, 15m, 30m, 1h, 2h or 6h"),
        }
    }

    fn auto_for(duration: Duration) -> Self {
        if duration <= Duration::minutes(30) {
            Self::TenSeconds
        } else if duration <= Duration::hours(1) {
            Self::ThirtySeconds
        } else if duration <= Duration::hours(6) {
            Self::OneMinute
        } else if duration <= Duration::hours(24) {
            Self::FiveMinutes
        } else if duration <= Duration::days(7) {
            Self::ThirtyMinutes
        } else {
            Self::TwoHours
        }
    }

    fn auto_for_database(duration: Duration) -> Self {
        if duration <= Duration::hours(1) {
            Self::OneMinute
        } else if duration <= Duration::hours(6) {
            Self::FiveMinutes
        } else if duration <= Duration::hours(24) {
            Self::FifteenMinutes
        } else if duration <= Duration::days(7) {
            Self::OneHour
        } else {
            Self::SixHours
        }
    }

    pub(crate) fn auto_for_request(duration: Duration) -> Self {
        if duration <= Duration::hours(6) {
            Self::OneMinute
        } else if duration <= Duration::days(1) {
            Self::FiveMinutes
        } else if duration <= Duration::days(7) {
            Self::ThirtyMinutes
        } else {
            Self::OneHour
        }
    }

    pub(crate) fn seconds(self) -> i64 {
        match self {
            Self::TenSeconds => 10,
            Self::ThirtySeconds => 30,
            Self::OneMinute => 60,
            Self::FiveMinutes => 300,
            Self::FifteenMinutes => 900,
            Self::ThirtyMinutes => 1_800,
            Self::OneHour => 3_600,
            Self::TwoHours => 7_200,
            Self::SixHours => 21_600,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::TenSeconds => "10s",
            Self::ThirtySeconds => "30s",
            Self::OneMinute => "1m",
            Self::FiveMinutes => "5m",
            Self::FifteenMinutes => "15m",
            Self::ThirtyMinutes => "30m",
            Self::OneHour => "1h",
            Self::TwoHours => "2h",
            Self::SixHours => "6h",
        }
    }
}

struct NormalizedHistoryQuery {
    start_at: DateTime<Utc>,
    end_at: DateTime<Utc>,
    granularity: Granularity,
}

#[derive(Serialize)]
struct ResourceHistoryPoint {
    timestamp_ms: i64,
    sample_count: i64,
    cpu_avg: Option<f64>,
    cpu_max: Option<f64>,
    ram_avg: Option<f64>,
    ram_max: Option<f64>,
    swap_avg: Option<f64>,
    swap_max: Option<f64>,
    disk_avg: Option<f64>,
    disk_max: Option<f64>,
}

#[derive(Serialize)]
struct ResourceHistoryData {
    points: Vec<ResourceHistoryPoint>,
}

#[derive(Serialize)]
struct ResourceHistoryMeta {
    start_at: DateTime<Utc>,
    end_at: DateTime<Utc>,
    granularity: &'static str,
    granularity_seconds: i64,
    timezone: String,
    point_count: usize,
}

#[derive(Serialize)]
struct ResourceHistoryResponse {
    success: bool,
    data: ResourceHistoryData,
    meta: ResourceHistoryMeta,
}

#[derive(Serialize)]
struct DatabaseTableSize {
    total: i64,
    data: i64,
    index: i64,
}

#[derive(Serialize)]
struct ElasticsearchIndexSize {
    primary: i64,
    replica: i64,
    total: i64,
}

#[derive(Serialize)]
struct DatabaseHistoryPoint {
    timestamp_ms: i64,
    sample_count: i64,
    database_size: Option<i64>,
    connection_count: Option<i64>,
    tables: BTreeMap<String, DatabaseTableSize>,
    elasticsearch_enabled: bool,
    elasticsearch_available: bool,
    elasticsearch_primary_size: Option<i64>,
    elasticsearch_replica_size: Option<i64>,
    elasticsearch_total_size: Option<i64>,
    elasticsearch_indices: BTreeMap<String, ElasticsearchIndexSize>,
}

#[derive(Serialize)]
struct DatabaseHistoryData {
    table_names: Vec<String>,
    elasticsearch_index_names: Vec<String>,
    points: Vec<DatabaseHistoryPoint>,
}

#[derive(Serialize)]
struct DatabaseHistoryResponse {
    success: bool,
    data: DatabaseHistoryData,
    meta: ResourceHistoryMeta,
}

fn normalize_query_with(
    query: &ResourceHistoryQuery,
    automatic_granularity: fn(Duration) -> Granularity,
) -> Result<NormalizedHistoryQuery, &'static str> {
    let end_at = query.end_at.unwrap_or_else(Utc::now);
    let start_at = query
        .start_at
        .unwrap_or_else(|| end_at - Duration::minutes(DEFAULT_RANGE_MINUTES));
    if start_at >= end_at {
        return Err("start_at must be earlier than end_at");
    }

    let duration = end_at - start_at;
    if duration > Duration::days(MAX_RANGE_DAYS) {
        return Err("resource history range cannot exceed 30 days");
    }

    let granularity = match query.granularity.as_deref().unwrap_or("auto") {
        "auto" => automatic_granularity(duration),
        value => Granularity::parse(value)?,
    };
    let duration_seconds = duration.num_seconds();
    let bucket_count = (duration_seconds + granularity.seconds() - 1) / granularity.seconds();
    if bucket_count > MAX_BUCKETS {
        return Err("selected granularity produces more than 1500 data points");
    }

    Ok(NormalizedHistoryQuery {
        start_at,
        end_at,
        granularity,
    })
}

fn normalize_query(query: &ResourceHistoryQuery) -> Result<NormalizedHistoryQuery, &'static str> {
    normalize_query_with(query, Granularity::auto_for)
}

fn normalize_database_query(
    query: &ResourceHistoryQuery,
) -> Result<NormalizedHistoryQuery, &'static str> {
    normalize_query_with(query, Granularity::auto_for_database)
}

fn rounded(value: Option<f64>) -> Option<f64> {
    value.map(|number| (number * 100.0).round() / 100.0)
}

fn bad_request(message: &'static str) -> HttpResponse {
    HttpResponse::BadRequest().json(json!({"success": false, "message": message}))
}

fn table_sizes_from_json(value: serde_json::Value) -> BTreeMap<String, DatabaseTableSize> {
    let Some(tables) = value.as_object() else {
        return BTreeMap::new();
    };

    tables
        .iter()
        .filter_map(|(name, metrics)| {
            let total = metrics.get("total")?.as_i64()?;
            let data = metrics.get("data")?.as_i64()?;
            let index = metrics.get("index")?.as_i64()?;
            (total >= 0 && data >= 0 && index >= 0)
                .then(|| (name.clone(), DatabaseTableSize { total, data, index }))
        })
        .collect()
}

fn elasticsearch_sizes_from_json(
    value: serde_json::Value,
) -> BTreeMap<String, ElasticsearchIndexSize> {
    let Some(indices) = value.as_object() else {
        return BTreeMap::new();
    };

    indices
        .iter()
        .filter_map(|(name, metrics)| {
            let primary = metrics.get("primary")?.as_i64()?;
            let replica = metrics.get("replica")?.as_i64()?;
            let total = metrics.get("total")?.as_i64()?;
            (primary >= 0
                && replica >= 0
                && total >= 0
                && primary.checked_add(replica) == Some(total))
            .then(|| {
                (
                    name.clone(),
                    ElasticsearchIndexSize {
                        primary,
                        replica,
                        total,
                    },
                )
            })
        })
        .collect()
}

#[get("/api/data/system-resource-history")]
pub(crate) async fn get_system_resource_history(
    req: HttpRequest,
    query: web::Query<ResourceHistoryQuery>,
    pool: web::Data<Pool>,
    user: UserBaseI,
) -> impl Responder {
    if user.role != crate::access::ADMIN {
        return HttpResponse::Forbidden().finish();
    }
    let normalized = match normalize_query(&query) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let start_seconds = normalized.start_at.timestamp();
    let end_seconds = normalized.end_at.timestamp();
    let bucket_seconds = normalized.granularity.seconds();
    let client = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            error_logs(
                &req,
                "SystemResourceHistoryPoolError",
                &error_value.to_string(),
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let rows = match client
        .query(
            RESOURCE_HISTORY_SQL,
            &[&start_seconds, &end_seconds, &bucket_seconds],
        )
        .await
    {
        Ok(value) => value,
        Err(error_value) => {
            error_logs(
                &req,
                "SystemResourceHistoryQueryError",
                &database_error_diagnostics(&error_value),
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let points: Vec<ResourceHistoryPoint> = rows
        .into_iter()
        .map(|row| ResourceHistoryPoint {
            timestamp_ms: row.get::<_, i64>("bucket_start") * 1_000,
            sample_count: row.get("sample_count"),
            cpu_avg: rounded(row.get("cpu_avg")),
            cpu_max: rounded(row.get("cpu_max")),
            ram_avg: rounded(row.get("ram_avg")),
            ram_max: rounded(row.get("ram_max")),
            swap_avg: rounded(row.get("swap_avg")),
            swap_max: rounded(row.get("swap_max")),
            disk_avg: rounded(row.get("disk_avg")),
            disk_max: rounded(row.get("disk_max")),
        })
        .collect();
    let point_count = points.len();

    HttpResponse::Ok().json(ResourceHistoryResponse {
        success: true,
        data: ResourceHistoryData { points },
        meta: ResourceHistoryMeta {
            start_at: normalized.start_at,
            end_at: normalized.end_at,
            granularity: normalized.granularity.label(),
            granularity_seconds: bucket_seconds,
            timezone: crate::system_time::snapshot().document.timezone,
            point_count,
        },
    })
}

#[get("/api/data/database-size-history")]
pub(crate) async fn get_database_size_history(
    req: HttpRequest,
    query: web::Query<ResourceHistoryQuery>,
    pool: web::Data<Pool>,
    user: UserBaseI,
) -> impl Responder {
    if user.role != crate::access::ADMIN {
        return HttpResponse::Forbidden().finish();
    }
    let normalized = match normalize_database_query(&query) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let client = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            error_logs(
                &req,
                "DatabaseSizeHistoryPoolError",
                &error_value.to_string(),
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    let start_seconds = normalized.start_at.timestamp();
    let end_seconds = normalized.end_at.timestamp();
    let bucket_seconds = normalized.granularity.seconds();
    let rows = match client
        .query(
            DATABASE_HISTORY_SQL,
            &[&start_seconds, &end_seconds, &bucket_seconds],
        )
        .await
    {
        Ok(value) => value,
        Err(error_value) => {
            error_logs(
                &req,
                "DatabaseSizeHistoryQueryError",
                &database_error_diagnostics(&error_value),
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    let mut table_names = BTreeSet::new();
    let mut elasticsearch_index_names = BTreeSet::new();
    let points: Vec<DatabaseHistoryPoint> = rows
        .into_iter()
        .map(|row| {
            let tables = table_sizes_from_json(row.get("tables"));
            let elasticsearch_indices =
                elasticsearch_sizes_from_json(row.get("elasticsearch_indices"));
            table_names.extend(tables.keys().cloned());
            elasticsearch_index_names.extend(elasticsearch_indices.keys().cloned());
            DatabaseHistoryPoint {
                timestamp_ms: row.get::<_, i64>("bucket_start") * 1_000,
                sample_count: row.get("sample_count"),
                database_size: row.get("database_size"),
                connection_count: row.get("connection_count"),
                tables,
                elasticsearch_enabled: row.get("elasticsearch_enabled"),
                elasticsearch_available: row.get("elasticsearch_available"),
                elasticsearch_primary_size: row.get("elasticsearch_primary_size"),
                elasticsearch_replica_size: row.get("elasticsearch_replica_size"),
                elasticsearch_total_size: row.get("elasticsearch_total_size"),
                elasticsearch_indices,
            }
        })
        .collect();
    let point_count = points.len();

    HttpResponse::Ok().json(DatabaseHistoryResponse {
        success: true,
        data: DatabaseHistoryData {
            table_names: table_names.into_iter().collect(),
            elasticsearch_index_names: elasticsearch_index_names.into_iter().collect(),
            points,
        },
        meta: ResourceHistoryMeta {
            start_at: normalized.start_at,
            end_at: normalized.end_at,
            granularity: normalized.granularity.label(),
            granularity_seconds: bucket_seconds,
            timezone: crate::system_time::snapshot().document.timezone,
            point_count,
        },
    })
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone, Utc};

    use super::{
        DATABASE_HISTORY_SQL, Granularity, RESOURCE_HISTORY_SQL, ResourceHistoryQuery,
        elasticsearch_sizes_from_json, normalize_database_query, normalize_query, rounded,
        table_sizes_from_json,
    };

    fn query(duration: Duration, granularity: &str) -> ResourceHistoryQuery {
        let end_at = Utc.with_ymd_and_hms(2026, 8, 16, 12, 0, 0).unwrap();
        ResourceHistoryQuery {
            start_at: Some(end_at - duration),
            end_at: Some(end_at),
            granularity: Some(granularity.to_owned()),
        }
    }

    #[test]
    fn automatic_granularity_matches_supported_ranges() {
        assert_eq!(
            normalize_query(&query(Duration::minutes(30), "auto"))
                .unwrap()
                .granularity,
            Granularity::TenSeconds
        );
        assert_eq!(
            normalize_query(&query(Duration::hours(1), "auto"))
                .unwrap()
                .granularity,
            Granularity::ThirtySeconds
        );
        assert_eq!(
            normalize_query(&query(Duration::hours(6), "auto"))
                .unwrap()
                .granularity,
            Granularity::OneMinute
        );
        assert_eq!(
            normalize_query(&query(Duration::hours(24), "auto"))
                .unwrap()
                .granularity,
            Granularity::FiveMinutes
        );
        assert_eq!(
            normalize_query(&query(Duration::days(7), "auto"))
                .unwrap()
                .granularity,
            Granularity::ThirtyMinutes
        );
        assert_eq!(
            normalize_query(&query(Duration::days(30), "auto"))
                .unwrap()
                .granularity,
            Granularity::TwoHours
        );
    }

    #[test]
    fn database_granularity_uses_slower_buckets() {
        assert_eq!(
            normalize_database_query(&query(Duration::minutes(30), "auto"))
                .unwrap()
                .granularity,
            Granularity::OneMinute
        );
        assert_eq!(
            normalize_database_query(&query(Duration::days(30), "auto"))
                .unwrap()
                .granularity,
            Granularity::SixHours
        );
    }

    #[test]
    fn rejects_oversized_ranges_and_point_counts() {
        assert!(normalize_query(&query(Duration::days(31), "auto")).is_err());
        assert!(normalize_query(&query(Duration::days(7), "1m")).is_err());
    }

    #[test]
    fn rejects_invalid_boundaries_and_granularity() {
        assert!(normalize_query(&query(Duration::hours(1), "10m")).is_err());
        let mut inverted = query(Duration::hours(1), "auto");
        inverted.start_at = inverted.end_at;
        assert!(normalize_query(&inverted).is_err());
    }

    #[test]
    fn rounds_optional_metrics() {
        assert_eq!(rounded(Some(12.345)), Some(12.35));
        assert_eq!(rounded(None), None);
    }

    #[test]
    fn history_query_keeps_sql_clause_boundaries() {
        assert!(RESOURCE_HISTORY_SQL.contains("FROM system_status"));
        assert!(RESOURCE_HISTORY_SQL.contains("AS swap_usage"));
        assert!(DATABASE_HISTORY_SQL.contains("FROM system_status"));
    }

    #[test]
    fn database_schema_and_status_insert_include_elasticsearch_metrics() {
        let initialization_sql = include_str!("../../source/database/init.sql");
        let insert_sql = include_str!("../../source/database/insert_system_status.sql");
        assert!(initialization_sql.contains("db_elasticsearch JSONB DEFAULT NULL"));
        assert!(
            initialization_sql.contains(
                "ALTER TABLE system_status ADD COLUMN IF NOT EXISTS db_elasticsearch JSONB"
            )
        );
        assert!(insert_sql.contains("db_postgresql, db_elasticsearch, network"));
        assert!(insert_sql.contains("$1, $2, $3, $4, $5, $6, $7"));
    }

    #[test]
    fn table_sizes_are_sorted_and_invalid_entries_are_ignored() {
        let tables = table_sizes_from_json(serde_json::json!({
            "z_table": {"total": 30, "data": 20, "index": 10},
            "a_table": {"total": 15, "data": 10, "index": 5},
            "error": {"total": -1, "data": -1, "index": -1}
        }));
        assert_eq!(
            tables.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["a_table", "z_table"]
        );
        assert_eq!(tables["a_table"].total, 15);
    }

    #[test]
    fn elasticsearch_sizes_are_sorted_and_invalid_entries_are_ignored() {
        let indices = elasticsearch_sizes_from_json(serde_json::json!({
            "z-index": {"primary": 20, "replica": 10, "total": 30},
            "a-index": {"primary": 10, "replica": 5, "total": 15},
            "broken": {"primary": 10, "replica": 10, "total": 99}
        }));
        assert_eq!(
            indices.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["a-index", "z-index"]
        );
        assert_eq!(indices["a-index"].replica, 5);
        assert_eq!(indices["z-index"].total, 30);
    }
}
