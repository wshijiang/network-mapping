use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use tokio_postgres::types::ToSql;
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::config::AnalyticsSnapshotConfig;
use crate::elasticsearch::{ElasticsearchService, ScanQueryIndex};
use crate::logs::write::{error_logs, error_logs_error};
use crate::runtime_config::RuntimeConfig;
use crate::system_resource_cache::SystemResourceCache;
use crate::{
    system_resources::SystemDetails, system_resources::SystemStatusJson, system_resources::Systems,
};

const DEFAULT_RANGE_WEEKS: i64 = 12;
const MAX_RANGE_DAYS: i64 = 366;

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct AnalysisFilterQuery {
    start_at: Option<DateTime<Utc>>,
    end_at: Option<DateTime<Utc>>,
    scanner_id: Option<Uuid>,
    task_source: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct DistributionQuery {
    #[serde(flatten)]
    filters: AnalysisFilterQuery,
    dimension: Option<String>,
    limit: Option<i64>,
}

#[derive(Deserialize)]
pub(crate) struct HeatmapQuery {
    #[serde(flatten)]
    filters: AnalysisFilterQuery,
}

#[derive(Clone)]
pub(super) struct AnalysisFilters {
    pub(super) timezone: String,
    pub(super) start_at: DateTime<Utc>,
    pub(super) end_at: DateTime<Utc>,
    pub(super) start_ms: i64,
    pub(super) end_ms: i64,
    pub(super) scanner_id: Option<String>,
    pub(super) task_source: Option<String>,
}

#[derive(Clone, Copy)]
enum DistributionDimension {
    Service,
    Port,
}

impl DistributionDimension {
    fn parse(value: Option<&str>) -> Result<Self, &'static str> {
        match value.unwrap_or("service") {
            "service" => Ok(Self::Service),
            "port" => Ok(Self::Port),
            _ => Err("dimension must be service or port"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Port => "port",
        }
    }
}

#[derive(Serialize)]
struct AnalysisMeta {
    start_at: DateTime<Utc>,
    end_at: DateTime<Utc>,
    timezone: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_as_of: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct AnalysisResponse<T> {
    success: bool,
    data: T,
    meta: AnalysisMeta,
}

#[derive(Serialize)]
struct DistributionItem {
    name: String,
    count: i64,
    percentage: f64,
}

#[derive(Serialize)]
struct DistributionData {
    dimension: &'static str,
    items: Vec<DistributionItem>,
    other_count: i64,
    total: i64,
}

#[derive(Serialize)]
struct HeatmapItem {
    date: String,
    count: i64,
}

#[derive(Serialize)]
struct HeatmapData {
    items: Vec<HeatmapItem>,
}

pub(super) fn normalize_filters(
    query: &AnalysisFilterQuery,
) -> Result<AnalysisFilters, &'static str> {
    let end_at = query.end_at.unwrap_or_else(Utc::now);
    let start_at = query
        .start_at
        .unwrap_or_else(|| end_at - Duration::weeks(DEFAULT_RANGE_WEEKS));

    if start_at >= end_at {
        return Err("start_at must be earlier than end_at");
    }
    if end_at - start_at > Duration::days(MAX_RANGE_DAYS) {
        return Err("analysis range cannot exceed 366 days");
    }

    let task_source = query.task_source.as_deref().map(str::trim);
    if task_source.is_some_and(|value| !matches!(value, "manual" | "automatic" | "search")) {
        return Err("task_source must be manual, automatic or search");
    }

    Ok(AnalysisFilters {
        timezone: crate::system_time::snapshot().document.timezone,
        start_at,
        end_at,
        start_ms: start_at.timestamp_millis(),
        end_ms: end_at.timestamp_millis(),
        scanner_id: query.scanner_id.map(|value| value.to_string()),
        task_source: task_source.map(str::to_owned),
    })
}

fn analysis_meta(filters: &AnalysisFilters) -> AnalysisMeta {
    AnalysisMeta {
        start_at: filters.start_at,
        end_at: filters.end_at,
        timezone: filters.timezone.clone(),
        data_as_of: None,
    }
}

fn percentage(count: i64, total: i64) -> f64 {
    if total <= 0 {
        return 0.0;
    }
    ((count as f64 / total as f64) * 1000.0).round() / 10.0
}

fn bad_request(message: &'static str) -> HttpResponse {
    HttpResponse::BadRequest().json(json!({"success": false, "message": message}))
}

#[get("/api/data/system-data")]
async fn get_system_data_handler(
    _req: HttpRequest,
    cache: web::Data<SystemResourceCache>,
    systems: web::Data<Systems>,
) -> impl Responder {
    let status_item: Vec<_> = cache.latest().into_iter().collect();

    let t_json = SystemStatusJson {
        total_c: status_item.len() as i32,
        status_item,
        system_info: SystemDetails::new(systems.get_ref()),
    };

    HttpResponse::Ok().json(t_json)
}

#[get("/api/analysis/distribution")]
pub(crate) async fn get_analysis_distribution(
    req: HttpRequest,
    query: web::Query<DistributionQuery>,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    analytics_snapshot: web::Data<RuntimeConfig<AnalyticsSnapshotConfig>>,
    user: UserBaseI,
) -> impl Responder {
    let filters = match normalize_filters(&query.filters) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let dimension = match DistributionDimension::parse(query.dimension.as_deref()) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let limit = query.limit.unwrap_or(5);
    if !matches!(limit, 5 | 7 | 10) {
        return bad_request("limit must be 5, 7 or 10");
    }
    if analytics_snapshot.get().await.value.mode.reads_snapshot() {
        return analysis_distribution_from_snapshot(
            &req,
            pool.get_ref(),
            &filters,
            dimension,
            limit,
            &user,
        )
        .await;
    }

    return analysis_distribution_from_elasticsearch(
        &req,
        elasticsearch.get_ref(),
        &filters,
        dimension,
        limit,
        &user,
    )
    .await;
}

#[get("/api/analysis/discovery-heatmap")]
pub(crate) async fn get_analysis_discovery_heatmap(
    req: HttpRequest,
    query: web::Query<HeatmapQuery>,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    analytics_snapshot: web::Data<RuntimeConfig<AnalyticsSnapshotConfig>>,
    user: UserBaseI,
) -> impl Responder {
    let filters = match normalize_filters(&query.filters) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    if analytics_snapshot.get().await.value.mode.reads_snapshot() {
        return analysis_heatmap_from_snapshot(&req, pool.get_ref(), &filters, &user).await;
    }

    return analysis_heatmap_from_elasticsearch(&req, elasticsearch.get_ref(), &filters, &user)
        .await;
}

async fn snapshot_data_as_of(
    client: &deadpool_postgres::Client,
) -> Result<Option<DateTime<Utc>>, tokio_postgres::Error> {
    let row = client
        .query_opt(
            "SELECT data_as_of FROM analytics_watermark WHERE watermark_key = 'scan_analysis';",
            &[],
        )
        .await?;
    Ok(row.map(|row| row.get("data_as_of")))
}

pub(super) async fn snapshot_not_ready(
    client: &deadpool_postgres::Client,
    user: &UserBaseI,
) -> HttpResponse {
    if user.role == 1 {
        match crate::analytics_snapshot::snapshot_progress(client).await {
            Ok(progress) => return HttpResponse::ServiceUnavailable().json(json!({
                "success": false, "code": "analytics_backfill_pending",
                "message": format!("分析快照历史回填尚未完成：本轮剩余 {} 个执行，队列待处理 {} 个、处理中 {} 个、失败待重试 {} 个。",
                    progress.remaining, progress.pending, progress.running, progress.retrying),
                "progress": progress
            })),
            Err(_) => return HttpResponse::ServiceUnavailable().json(json!({
                "success": false, "code": "analytics_progress_unavailable", "message": "分析快照状态读取失败，请检查数据库及迁移状态"
            })),
        }
    }
    HttpResponse::ServiceUnavailable().json(json!({
        "success": false, "code": "analytics_backfill_pending", "message": "分析快照尚未完成历史回填，请联系管理员查看统计任务进度"
    }))
}

async fn analysis_distribution_from_snapshot(
    req: &HttpRequest,
    pool: &Pool,
    filters: &AnalysisFilters,
    dimension: DistributionDimension,
    limit: i64,
    user: &UserBaseI,
) -> HttpResponse {
    let client = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                req,
                "AnalysisSnapshotPoolError",
                "database_operation",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let data_as_of = match snapshot_data_as_of(&client).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return snapshot_not_ready(&client, user).await;
        }
        Err(error) => {
            error_logs_error(
                req,
                "AnalysisSnapshotWatermarkError",
                "database_operation",
                &error,
            );
            return HttpResponse::ServiceUnavailable()
                .json(json!({"success": false, "code": "analytics_watermark_unavailable", "message": "分析快照水位读取失败，请检查数据库及迁移状态"}));
        }
    };
    let mut conditions = vec![
        "bucket_start >= $1".to_owned(),
        "bucket_start < $2".to_owned(),
        "dimension = $3".to_owned(),
    ];
    let dimension_name = dimension.as_str();
    let mut params: Vec<&(dyn ToSql + Sync)> =
        vec![&filters.start_at, &filters.end_at, &dimension_name];
    if user.role != 1 {
        params.push(&user.id);
        conditions.push(format!("owner_id = ${}", params.len()));
    }
    if let Some(scanner_id) = filters.scanner_id.as_ref() {
        params.push(scanner_id);
        conditions.push(format!("scanner_id = ${}", params.len()));
    }
    if let Some(task_source) = filters.task_source.as_ref() {
        params.push(task_source);
        conditions.push(format!("task_source = ${}", params.len()));
    }
    params.push(&limit);
    let sql = format!(
        "WITH grouped AS ( \
             SELECT label, SUM(endpoint_count)::BIGINT AS endpoint_count \
             FROM analytics_distribution_30m WHERE {} GROUP BY label \
         ) SELECT label, endpoint_count, (SUM(endpoint_count) OVER ())::BIGINT AS total \
           FROM grouped ORDER BY endpoint_count DESC, label LIMIT ${};",
        conditions.join(" AND "),
        params.len()
    );
    let rows = match client.query(&sql, &params).await {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                req,
                "AnalysisSnapshotDistributionError",
                "database_operation",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows
        .into_iter()
        .map(|row| {
            let count = row.get("endpoint_count");
            DistributionItem {
                name: row.get("label"),
                count,
                percentage: percentage(count, total),
            }
        })
        .collect::<Vec<_>>();
    let visible_count = items.iter().map(|item| item.count).sum::<i64>();
    let mut meta = analysis_meta(filters);
    meta.data_as_of = Some(data_as_of);
    HttpResponse::Ok().json(AnalysisResponse {
        success: true,
        data: DistributionData {
            dimension: dimension.as_str(),
            items,
            other_count: total.saturating_sub(visible_count),
            total,
        },
        meta,
    })
}

async fn analysis_heatmap_from_snapshot(
    req: &HttpRequest,
    pool: &Pool,
    filters: &AnalysisFilters,
    user: &UserBaseI,
) -> HttpResponse {
    let client = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                req,
                "AnalysisSnapshotPoolError",
                "database_operation",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let data_as_of = match snapshot_data_as_of(&client).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return snapshot_not_ready(&client, user).await;
        }
        Err(error) => {
            error_logs_error(
                req,
                "AnalysisSnapshotWatermarkError",
                "database_operation",
                &error,
            );
            return HttpResponse::ServiceUnavailable()
                .json(json!({"success": false, "code": "analytics_watermark_unavailable", "message": "分析快照水位读取失败，请检查数据库及迁移状态"}));
        }
    };
    // Legacy DATE facts can only be read in their original Shanghai calendar.
    // UTC facts support arbitrary calendars without rebuilding on each settings change.
    let mut conditions = vec![
        "((first_observed_at >= $1 AND first_observed_at < $2) OR (first_observed_at IS NULL AND day_start >= ($1 AT TIME ZONE 'Asia/Shanghai')::DATE AND day_start < ($2 AT TIME ZONE 'Asia/Shanghai')::DATE))".to_owned(),
    ];
    let mut params: Vec<&(dyn ToSql + Sync)> =
        vec![&filters.start_at, &filters.end_at, &filters.timezone];
    if user.role != 1 {
        params.push(&user.id);
        conditions.push(format!("owner_id = ${}", params.len()));
    }
    if let Some(scanner_id) = filters.scanner_id.as_ref() {
        params.push(scanner_id);
        conditions.push(format!("scanner_id = ${}", params.len()));
    }
    if let Some(task_source) = filters.task_source.as_ref() {
        params.push(task_source);
        conditions.push(format!("task_source = ${}", params.len()));
    }
    if filters.timezone != crate::system_time::DEFAULT_TIMEZONE {
        // $3 is included explicitly so parameter typing remains stable.
        let legacy_sql = format!(
            "SELECT EXISTS(SELECT 1 FROM analytics_discovery_fact WHERE {} AND first_observed_at IS NULL AND $3::TEXT <> 'Asia/Shanghai') AS legacy",
            conditions
                .join(" AND ")
                .replace("day_start < ($2", "day_start <= ($2")
        );
        match client.query_one(&legacy_sql, &params).await {
            Ok(row) if row.get::<_, bool>("legacy") => return HttpResponse::ServiceUnavailable().json(json!({"success": false, "code": "analytics_timezone_backfill_required", "message": "该范围包含仅保留上海日期的旧统计，请重建分析快照；已删除原始观测的数据无法换算时区。"})),
            Ok(_) => {},
            Err(error) => {
                error_logs_error(req, "AnalysisTimezoneLegacyCheckError", "database_operation", &error);
                return HttpResponse::ServiceUnavailable().finish();
            }
        }
    }
    let sql = format!(
        "SELECT to_char(COALESCE((first_observed_at AT TIME ZONE $3)::DATE, day_start), 'YYYY-MM-DD') AS day, COUNT(DISTINCT ip_address)::BIGINT AS discovered_count FROM analytics_discovery_fact WHERE {} GROUP BY COALESCE((first_observed_at AT TIME ZONE $3)::DATE, day_start) ORDER BY day;",
        conditions.join(" AND ")
    );
    let rows = match client.query(&sql, &params).await {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                req,
                "AnalysisSnapshotHeatmapError",
                "database_operation",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let items = rows
        .into_iter()
        .map(|row| HeatmapItem {
            date: row.get("day"),
            count: row.get("discovered_count"),
        })
        .collect();
    let mut meta = analysis_meta(filters);
    meta.data_as_of = Some(data_as_of);
    HttpResponse::Ok().json(AnalysisResponse {
        success: true,
        data: HeatmapData { items },
        meta,
    })
}

pub(super) fn analysis_es_filters(filters: &AnalysisFilters, user: &UserBaseI) -> Vec<Value> {
    let mut result = vec![json!({"range": {"observed_at": {
        "gte": filters.start_ms, "lt": filters.end_ms, "format": "epoch_millis"
    }}})];
    if user.role != 1 {
        result.push(json!({"term": {"user_id": user.id}}));
    }
    if let Some(scanner_id) = filters.scanner_id.as_deref() {
        result.push(json!({"term": {"scanner_id": scanner_id}}));
    }
    if let Some(task_source) = filters.task_source.as_deref() {
        result.push(json!({"term": {"task_source": task_source}}));
    }
    result
}

async fn analysis_distribution_from_elasticsearch(
    req: &HttpRequest,
    elasticsearch: &ElasticsearchService,
    filters: &AnalysisFilters,
    dimension: DistributionDimension,
    limit: i64,
    user: &UserBaseI,
) -> HttpResponse {
    let mut query_filters = analysis_es_filters(filters, user);
    let field = match dimension {
        DistributionDimension::Service => {
            query_filters.push(json!({"term": {"kind": "service"}}));
            query_filters.push(json!({"exists": {"field": "service"}}));
            "service"
        }
        DistributionDimension::Port => "port",
    };
    let mut after = None;
    let mut counts = HashMap::<String, i64>::new();
    loop {
        let mut composite = json!({
            "size": 1000,
            "sources": [
                {"label": {"terms": {"field": field}}},
                {"endpoint": {"terms": {"field": "endpoint_id"}}}
            ]
        });
        if let Some(value) = after.take() {
            composite
                .as_object_mut()
                .expect("composite aggregation is an object")
                .insert("after".to_owned(), value);
        }
        let result = match elasticsearch
            .scan_query(
                ScanQueryIndex::Observations,
                &json!({
                    "size": 0,
                    "query": {"bool": {"filter": query_filters}},
                    "aggs": {"groups": {"composite": composite}}
                }),
            )
            .await
        {
            Ok(value) => value,
            Err(error) => {
                error_logs(req, "AnalysisDistributionElasticsearchError", &error);
                return HttpResponse::ServiceUnavailable()
                    .json(json!({"message": "扫描结果索引暂时不可用"}));
            }
        };
        let buckets = result
            .pointer("/aggregations/groups/buckets")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for bucket in &buckets {
            let label = bucket
                .pointer("/key/label")
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string())
                })
                .unwrap_or_default();
            *counts.entry(label).or_default() += 1;
        }
        after = result.pointer("/aggregations/groups/after_key").cloned();
        if buckets.len() < 1000 || after.is_none() {
            break;
        }
    }
    let mut all_items = counts.into_iter().collect::<Vec<_>>();
    all_items.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let total = all_items.iter().map(|item| item.1).sum::<i64>();
    let items = all_items
        .into_iter()
        .take(limit as usize)
        .map(|(name, count)| DistributionItem {
            name,
            count,
            percentage: percentage(count, total),
        })
        .collect::<Vec<_>>();
    let visible_count = items.iter().map(|item| item.count).sum::<i64>();
    HttpResponse::Ok().json(AnalysisResponse {
        success: true,
        data: DistributionData {
            dimension: dimension.as_str(),
            items,
            other_count: total.saturating_sub(visible_count),
            total,
        },
        meta: analysis_meta(filters),
    })
}

async fn analysis_heatmap_from_elasticsearch(
    req: &HttpRequest,
    elasticsearch: &ElasticsearchService,
    filters: &AnalysisFilters,
    user: &UserBaseI,
) -> HttpResponse {
    let mut after = None;
    let mut counts = BTreeMap::<i64, i64>::new();
    loop {
        let mut composite = json!({
            "size": 1000,
            "sources": [
                {"day": {"date_histogram": {"field": "observed_at",
                    "calendar_interval": "1d", "time_zone": filters.timezone}}},
                {"address": {"terms": {"field": "ip_address"}}}
            ]
        });
        if let Some(value) = after.take() {
            composite
                .as_object_mut()
                .expect("composite aggregation is an object")
                .insert("after".to_owned(), value);
        }
        let result = match elasticsearch
            .scan_query(
                ScanQueryIndex::Observations,
                &json!({
                    "size": 0,
                    "query": {"bool": {"filter": analysis_es_filters(filters, user)}},
                    "aggs": {"groups": {"composite": composite}}
                }),
            )
            .await
        {
            Ok(value) => value,
            Err(error) => {
                error_logs(req, "AnalysisHeatmapElasticsearchError", &error);
                return HttpResponse::ServiceUnavailable()
                    .json(json!({"message": "扫描结果索引暂时不可用"}));
            }
        };
        let buckets = result
            .pointer("/aggregations/groups/buckets")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for bucket in &buckets {
            if let Some(day) = bucket.pointer("/key/day").and_then(Value::as_i64) {
                *counts.entry(day).or_default() += 1;
            }
        }
        after = result.pointer("/aggregations/groups/after_key").cloned();
        if buckets.len() < 1000 || after.is_none() {
            break;
        }
    }
    let timezone = filters
        .timezone
        .parse::<chrono_tz::Tz>()
        .unwrap_or(chrono_tz::Asia::Shanghai);
    let items = counts
        .into_iter()
        .filter_map(|(day, count)| {
            DateTime::<Utc>::from_timestamp_millis(day).map(|time| HeatmapItem {
                date: time.with_timezone(&timezone).format("%Y-%m-%d").to_string(),
                count,
            })
        })
        .collect::<Vec<_>>();
    HttpResponse::Ok().json(AnalysisResponse {
        success: true,
        data: HeatmapData { items },
        meta: analysis_meta(filters),
    })
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone, Utc};
    use uuid::Uuid;

    use super::{
        AnalysisFilterQuery, DistributionDimension, MAX_RANGE_DAYS, normalize_filters, percentage,
    };

    #[tokio::test]
    #[ignore = "requires disposable ANALYTICS_TEST_DATABASE_URL"]
    async fn snapshot_heatmap_uses_named_timezone_and_rejects_unconvertible_history() {
        use actix_web::{body::to_bytes, test::TestRequest};
        use deadpool_postgres::{Manager, Pool};
        let config = std::env::var("ANALYTICS_TEST_DATABASE_URL")
            .expect("test database")
            .parse::<tokio_postgres::Config>()
            .expect("config");
        let pool = Pool::builder(Manager::new(config, tokio_postgres::NoTls))
            .max_size(1)
            .build()
            .expect("pool");
        let client = pool.get().await.expect("client");
        client.batch_execute("CREATE TEMP TABLE analytics_watermark(watermark_key TEXT, data_as_of TIMESTAMPTZ); INSERT INTO analytics_watermark VALUES('scan_analysis', NOW()); \
            CREATE TEMP TABLE analytics_discovery_fact(day_start DATE, first_observed_at TIMESTAMPTZ, owner_id INT, scanner_id TEXT, task_source TEXT, ip_address INET); \
            INSERT INTO analytics_discovery_fact VALUES \
            ('2026-09-02','2026-09-01T20:00:00Z',1,'scanner','manual','192.0.2.1'), \
            ('2026-09-02','2026-09-01T20:05:00Z',1,'scanner','manual','192.0.2.1'), \
            ('2026-09-02','2026-09-02T05:00:00Z',1,'scanner','manual','192.0.2.2');").await.expect("fixtures");
        drop(client);
        let req = TestRequest::default().to_http_request();
        let user = crate::admin::UserBaseI {
            id: 1,
            username: "admin".into(),
            role: 1,
            email: None,
            limit_login: false,
            enable_2fa: false,
        };
        let mut filters = super::normalize_filters(&AnalysisFilterQuery {
            start_at: Some(Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).unwrap()),
            end_at: Some(Utc.with_ymd_and_hms(2026, 9, 3, 0, 0, 0).unwrap()),
            scanner_id: None,
            task_source: None,
        })
        .expect("filters");
        filters.timezone = "Asia/Shanghai".into();
        let response = super::analysis_heatmap_from_snapshot(&req, &pool, &filters, &user).await;
        assert_eq!(response.status(), 200);
        let data: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body()).await.expect("body"))
                .expect("JSON");
        assert_eq!(
            data["data"]["items"],
            serde_json::json!([{"date":"2026-09-02","count":2}])
        );
        filters.timezone = "America/New_York".into();
        let response = super::analysis_heatmap_from_snapshot(&req, &pool, &filters, &user).await;
        assert_eq!(response.status(), 200);
        let data: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body()).await.expect("body"))
                .expect("JSON");
        assert_eq!(
            data["data"]["items"],
            serde_json::json!([{"date":"2026-09-01","count":1},{"date":"2026-09-02","count":1}])
        );
        pool.get().await.expect("client").batch_execute("INSERT INTO analytics_discovery_fact VALUES('2026-09-02', NULL, 9, 'scanner', 'manual', '192.0.2.3');").await.expect("legacy");
        let response = super::analysis_heatmap_from_snapshot(&req, &pool, &filters, &user).await;
        assert_eq!(response.status(), 503);
        let ordinary = crate::admin::UserBaseI { role: 2, ..user };
        let response =
            super::analysis_heatmap_from_snapshot(&req, &pool, &filters, &ordinary).await;
        assert_eq!(
            response.status(),
            200,
            "another user's legacy data must not block this user's statistics"
        );
    }

    fn query(start_offset_days: i64, task_source: Option<&str>) -> AnalysisFilterQuery {
        let end_at = Utc.with_ymd_and_hms(2026, 8, 16, 12, 0, 0).unwrap();
        AnalysisFilterQuery {
            start_at: Some(end_at - Duration::days(start_offset_days)),
            end_at: Some(end_at),
            scanner_id: Some(Uuid::nil()),
            task_source: task_source.map(str::to_owned),
        }
    }

    #[test]
    fn normalizes_valid_filters() {
        let filters = normalize_filters(&query(84, Some("manual"))).unwrap();
        assert_eq!(filters.task_source.as_deref(), Some("manual"));
        assert_eq!(filters.scanner_id, Some(Uuid::nil().to_string()));
        assert!(filters.start_ms < filters.end_ms);
    }

    #[test]
    fn rejects_invalid_ranges_and_sources() {
        assert!(normalize_filters(&query(MAX_RANGE_DAYS + 1, None)).is_err());
        assert!(normalize_filters(&query(84, Some("system"))).is_err());

        let mut inverted = query(84, None);
        inverted.start_at = inverted.end_at.map(|value| value + Duration::seconds(1));
        assert!(normalize_filters(&inverted).is_err());
    }

    #[test]
    fn validates_distribution_dimension() {
        assert!(matches!(
            DistributionDimension::parse(Some("service")),
            Ok(DistributionDimension::Service)
        ));
        assert!(matches!(
            DistributionDimension::parse(Some("port")),
            Ok(DistributionDimension::Port)
        ));
        assert!(DistributionDimension::parse(Some("product")).is_err());
    }

    #[test]
    fn calculates_percentages_to_one_decimal_place() {
        assert_eq!(percentage(1, 3), 33.3);
        assert_eq!(percentage(0, 0), 0.0);
    }
}
