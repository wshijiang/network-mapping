use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::logs::write::error_logs_error;

const MAX_RANGE_DAYS: i64 = 30;
const MAX_BUCKETS: i64 = 1_500;

#[derive(Deserialize)]
pub struct ScannerLatencyHistoryQuery {
    start_at: Option<DateTime<Utc>>,
    end_at: Option<DateTime<Utc>>,
    granularity: Option<String>,
}

#[derive(Serialize)]
struct ScannerLatencyPoint {
    timestamp_ms: i64,
    sample_count: i64,
    network_avg_ms: Option<f64>,
    network_p50_ms: Option<f64>,
    network_p95_ms: Option<f64>,
    network_max_ms: Option<f64>,
    rtt_avg_ms: Option<f64>,
    server_processing_avg_ms: Option<f64>,
}

#[derive(Clone, Copy)]
enum Granularity {
    ThirtySeconds,
    OneMinute,
    FiveMinutes,
    ThirtyMinutes,
    TwoHours,
}

impl Granularity {
    fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "30s" => Ok(Self::ThirtySeconds),
            "1m" => Ok(Self::OneMinute),
            "5m" => Ok(Self::FiveMinutes),
            "30m" => Ok(Self::ThirtyMinutes),
            "2h" => Ok(Self::TwoHours),
            _ => Err("granularity must be auto, 30s, 1m, 5m, 30m or 2h"),
        }
    }

    fn automatic(duration: Duration) -> Self {
        if duration <= Duration::hours(6) {
            Self::OneMinute
        } else if duration <= Duration::days(1) {
            Self::FiveMinutes
        } else if duration <= Duration::days(7) {
            Self::ThirtyMinutes
        } else {
            Self::TwoHours
        }
    }

    fn seconds(self) -> i64 {
        match self {
            Self::ThirtySeconds => 30,
            Self::OneMinute => 60,
            Self::FiveMinutes => 300,
            Self::ThirtyMinutes => 1_800,
            Self::TwoHours => 7_200,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ThirtySeconds => "30s",
            Self::OneMinute => "1m",
            Self::FiveMinutes => "5m",
            Self::ThirtyMinutes => "30m",
            Self::TwoHours => "2h",
        }
    }
}

fn normalize_query(
    query: &ScannerLatencyHistoryQuery,
) -> Result<(DateTime<Utc>, DateTime<Utc>, Granularity), &'static str> {
    let end = query.end_at.unwrap_or_else(Utc::now);
    let start = query
        .start_at
        .unwrap_or_else(|| end - Duration::minutes(30));
    if start >= end {
        return Err("start_at must be earlier than end_at");
    }
    let duration = end - start;
    if duration > Duration::days(MAX_RANGE_DAYS) {
        return Err("latency history range cannot exceed 30 days");
    }
    let granularity = match query.granularity.as_deref().unwrap_or("auto") {
        "auto" => Granularity::automatic(duration),
        value => Granularity::parse(value)?,
    };
    let bucket_count = (duration.num_seconds() + granularity.seconds() - 1) / granularity.seconds();
    if bucket_count > MAX_BUCKETS {
        return Err("granularity produces too many data points");
    }
    Ok((start, end, granularity))
}

#[get("/api/scanner/{scanner_id}/latency-history")]
pub(crate) async fn get_scanner_latency_history(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    scanner_id: web::Path<Uuid>,
    query: web::Query<ScannerLatencyHistoryQuery>,
) -> impl Responder {
    if user.role != crate::access::ADMIN {
        return HttpResponse::Forbidden().finish();
    }
    let (start, end, granularity) = match normalize_query(&query) {
        Ok(value) => value,
        Err(message) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"success": false, "message": message}));
        }
    };
    let connection = match pool.get().await {
        Ok(connection) => connection,
        Err(error_value) => {
            error_logs_error(
                &req,
                "ScannerLatencyPoolError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let scanner_id = scanner_id.into_inner().to_string();
    let exists = match connection
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM scanner_info WHERE scanner_id = $1 AND deleted_at IS NULL);",
            &[&scanner_id],
        )
        .await
    {
        Ok(row) => row.get::<_, bool>(0),
        Err(error_value) => {
            error_logs_error(&req, "ScannerLatencyLookupError", "database_operation", &error_value);
            return HttpResponse::InternalServerError().finish();
        }
    };
    if !exists {
        return HttpResponse::NotFound()
            .json(serde_json::json!({"success": false, "message": "scanner not found"}));
    }

    let rows = match connection
        .query(
            "SELECT \
               ((FLOOR(EXTRACT(EPOCH FROM measured_at))::BIGINT / $4) * $4 * 1000)::BIGINT AS timestamp_ms, \
               COUNT(*)::BIGINT AS sample_count, \
               AVG(network_rtt_us::DOUBLE PRECISION) / 1000.0 AS network_avg_ms, \
               percentile_cont(0.50) WITHIN GROUP (ORDER BY network_rtt_us::DOUBLE PRECISION) / 1000.0 AS network_p50_ms, \
               percentile_cont(0.95) WITHIN GROUP (ORDER BY network_rtt_us::DOUBLE PRECISION) / 1000.0 AS network_p95_ms, \
               MAX(network_rtt_us)::DOUBLE PRECISION / 1000.0 AS network_max_ms, \
               AVG(rtt_us::DOUBLE PRECISION) / 1000.0 AS rtt_avg_ms, \
               AVG(server_processing_us::DOUBLE PRECISION) / 1000.0 AS server_processing_avg_ms \
             FROM scanner_latency_sample \
             WHERE scanner_id = $1 AND measured_at >= $2 AND measured_at < $3 \
             GROUP BY (FLOOR(EXTRACT(EPOCH FROM measured_at))::BIGINT / $4) \
             ORDER BY timestamp_ms;",
            &[&scanner_id, &start, &end, &granularity.seconds()],
        )
        .await
    {
        Ok(rows) => rows,
        Err(error_value) => {
            error_logs_error(&req, "ScannerLatencyHistoryError", "database_operation", &error_value);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let points: Vec<ScannerLatencyPoint> = rows
        .iter()
        .map(|row| ScannerLatencyPoint {
            timestamp_ms: row.get("timestamp_ms"),
            sample_count: row.get("sample_count"),
            network_avg_ms: row.get("network_avg_ms"),
            network_p50_ms: row.get("network_p50_ms"),
            network_p95_ms: row.get("network_p95_ms"),
            network_max_ms: row.get("network_max_ms"),
            rtt_avg_ms: row.get("rtt_avg_ms"),
            server_processing_avg_ms: row.get("server_processing_avg_ms"),
        })
        .collect();

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": {"points": points},
        "meta": {
            "start_at": start,
            "end_at": end,
            "granularity": granularity.label(),
            "granularity_seconds": granularity.seconds(),
            "point_count": points.len(),
            "retention_days": crate::scanner_latency::RETENTION_DAYS,
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_excessive_history_ranges() {
        let end = Utc::now();
        let query = ScannerLatencyHistoryQuery {
            start_at: Some(end - Duration::days(31)),
            end_at: Some(end),
            granularity: Some("2h".into()),
        };
        assert!(normalize_query(&query).is_err());
    }

    #[test]
    fn automatic_granularity_limits_default_range() {
        let end = Utc::now();
        let query = ScannerLatencyHistoryQuery {
            start_at: Some(end - Duration::minutes(30)),
            end_at: Some(end),
            granularity: Some("auto".into()),
        };
        let (_, _, granularity) = normalize_query(&query).unwrap();
        assert_eq!(granularity.seconds(), 60);
    }
}
