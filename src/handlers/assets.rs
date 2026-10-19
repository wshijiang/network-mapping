use std::net::IpAddr;
use std::str::FromStr;

use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::admin::UserBaseI;
use crate::elasticsearch::{ElasticsearchService, ScanQueryIndex};
use crate::handlers::tags::{AssetTag, tags_from_json};
use crate::logs::write::error_logs;

const DEFAULT_PORT_LIMIT: i64 = 20;
const MAX_PORT_LIMIT: i64 = 100;
const DEFAULT_HISTORY_LIMIT: i64 = 50;
const MAX_HISTORY_LIMIT: i64 = 100;

#[derive(Deserialize)]
pub(crate) struct AssetQuery {
    ip: String,
}

#[derive(Deserialize)]
pub(crate) struct AssetPortsQuery {
    ip: String,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Deserialize)]
pub(crate) struct AssetPortHistoryQuery {
    ip: String,
    port: u16,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Serialize)]
struct AssetPortCurrent {
    port: i32,
    intel: crate::threat_intel::Annotation,
    protocol: Option<String>,
    service: Option<String>,
    banner: Option<String>,
    source: String,
    service_source: Option<String>,
    first_seen_at: i64,
    last_seen_at: i64,
    service_observed_at: Option<i64>,
    service_stale: bool,
    os: Option<crate::os_detection::OsInference>,
    web: Option<crate::web_detection::WebInference>,
    execution_id: String,
    task_id: String,
}

#[derive(Serialize)]
struct AssetSummary {
    os: crate::os_detection::OsInference,
    ip: String,
    asn: Option<String>,
    isp: Option<String>,
    as_org: Option<String>,
    country_code: Option<String>,
    country_name: Option<String>,
    region_name: Option<String>,
    city_name: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    port_count: i64,
    service_count: i64,
    scanner_count: i64,
    observation_count: i64,
    first_seen_at: Option<i64>,
    last_seen_at: Option<i64>,
    intel: crate::threat_intel::Annotation,
    tags: Vec<AssetTag>,
    can_manage_tags: bool,
}

#[derive(Serialize)]
struct AssetObservationHistoryItem {
    id: i64,
    kind: String,
    state: String,
    protocol: Option<String>,
    service: Option<String>,
    banner: Option<String>,
    source: String,
    data: Option<Value>,
    observed_at: i64,
    execution_id: String,
    task_id: String,
    scanner_name: Option<String>,
    upload_id: String,
    batch_index: i32,
}

fn normalize_ip(value: &str) -> Result<String, &'static str> {
    IpAddr::from_str(value.trim())
        .map(|address| address.to_string())
        .map_err(|_| "IP 地址格式无效")
}

fn normalize_port_pagination(
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<(i64, i64), &'static str> {
    let limit = limit.unwrap_or(DEFAULT_PORT_LIMIT);
    let offset = offset.unwrap_or(0);
    if !(1..=MAX_PORT_LIMIT).contains(&limit) {
        return Err("limit 必须在 1 到 100 之间");
    }
    if !(0..=10_000).contains(&offset) {
        return Err("offset 超出允许范围");
    }
    Ok((limit, offset))
}

fn normalize_history_pagination(
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<(i64, i64), &'static str> {
    let limit = limit.unwrap_or(DEFAULT_HISTORY_LIMIT);
    let offset = offset.unwrap_or(0);
    if !(1..=MAX_HISTORY_LIMIT).contains(&limit) {
        return Err("limit 必须在 1 到 100 之间");
    }
    if !(0..=10_000).contains(&offset) {
        return Err("offset 超出允许范围");
    }
    Ok((limit, offset))
}

fn bad_request(message: &'static str) -> HttpResponse {
    HttpResponse::BadRequest().json(serde_json::json!({"message": message}))
}

#[get("/api/assets/summary")]
pub(crate) async fn get_asset_summary(
    req: HttpRequest,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    query: web::Query<AssetQuery>,
    user: UserBaseI,
) -> impl Responder {
    let ip = match normalize_ip(&query.ip) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };

    return get_asset_summary_from_elasticsearch(
        &req,
        pool.get_ref(),
        elasticsearch.get_ref(),
        &ip,
        &user,
    )
    .await;
}

#[get("/api/assets/ports")]
pub(crate) async fn get_asset_ports(
    req: HttpRequest,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    query: web::Query<AssetPortsQuery>,
    user: UserBaseI,
) -> impl Responder {
    let ip = match normalize_ip(&query.ip) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let (limit, offset) = match normalize_port_pagination(query.limit, query.offset) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };

    return get_asset_ports_from_elasticsearch(
        &req,
        pool.get_ref(),
        elasticsearch.get_ref(),
        &ip,
        limit,
        offset,
        &user,
    )
    .await;
}

#[get("/api/assets/port-history")]
pub(crate) async fn get_asset_port_history(
    req: HttpRequest,
    elasticsearch: web::Data<ElasticsearchService>,
    query: web::Query<AssetPortHistoryQuery>,
    user: UserBaseI,
) -> impl Responder {
    let ip = match normalize_ip(&query.ip) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    if query.port == 0 {
        return bad_request("端口必须在 1 到 65535 之间");
    }
    let (limit, offset) = match normalize_history_pagination(query.limit, query.offset) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let port = i32::from(query.port);

    return get_asset_history_from_elasticsearch(
        &req,
        elasticsearch.get_ref(),
        &ip,
        port,
        limit,
        offset,
        &user,
    )
    .await;
}

fn current_scope_filters(user: &UserBaseI) -> Vec<Value> {
    if user.role == 1 {
        vec![
            json!({"term": {"scope_type": "global"}}),
            json!({"term": {"scope_id": 0}}),
        ]
    } else {
        vec![
            json!({"term": {"scope_type": "user"}}),
            json!({"term": {"scope_id": user.id}}),
        ]
    }
}

fn observation_access_filters(user: &UserBaseI) -> Vec<Value> {
    if user.role == 1 {
        Vec::new()
    } else {
        vec![json!({"term": {"user_id": user.id}})]
    }
}

fn es_total(result: &Value) -> i64 {
    result
        .pointer("/hits/total/value")
        .and_then(Value::as_i64)
        .unwrap_or(0)
}

fn es_time_ms(value: Option<&Value>) -> Option<i64> {
    value.and_then(|value| {
        value.as_i64().or_else(|| {
            value
                .as_str()
                .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
                .map(|time| time.timestamp_millis())
        })
    })
}

fn asset_history_search_body(filters: Vec<Value>, limit: i64, offset: i64) -> Value {
    json!({
        "from": offset,
        "size": limit,
        "track_total_hits": true,
        "query": {"bool": {"filter": filters}},
        "sort": [
            {"observed_at": {"order": "desc", "format": "epoch_millis"}},
            {"execution_id": "desc"},
            {"observation_key": "desc"}
        ]
    })
}

fn asset_summary_current_search_body(filters: Vec<Value>) -> Value {
    json!({
        "size": 0,
        "track_total_hits": true,
        "query": {"bool": {"filter": filters}},
        "aggs": {
            "os_by_status": {"terms":{"field":"os.status","size":8}, "aggs":{
                "families":{"terms":{"field":"os.family","missing":"unknown","size":8}, "aggs":{
                    "samples":{"top_hits":{"size":8,"sort":[{"os.observed_at":{"order":"desc","missing":"_last"}},{"port":"asc"}],"_source":["os","port","scanner_id","observed_at_ms"]}}
                }}
            }},
            "services": {"cardinality": {"field": "service", "precision_threshold": 40000}},
            "scanners": {"cardinality": {"field": "scanner_id", "precision_threshold": 40000}},
            "latest": {"top_hits": {"size": 1, "sort": [
                {"observed_at_ms": "desc"},
                {"port": "asc"}
            ], "_source": ["asn", "isp", "as_org", "country_code", "country_name", "region_name", "city_name", "latitude", "longitude"]}}
        }
    })
}

async fn get_asset_summary_from_elasticsearch(
    req: &HttpRequest,
    pool: &Pool,
    elasticsearch: &ElasticsearchService,
    ip: &str,
    user: &UserBaseI,
) -> HttpResponse {
    let mut current_filters = current_scope_filters(user);
    current_filters.push(json!({"term": {"ip": ip}}));
    let current = elasticsearch
        .scan_query(
            ScanQueryIndex::CurrentEndpoints,
            &asset_summary_current_search_body(current_filters),
        )
        .await;
    let mut observation_filters = observation_access_filters(user);
    observation_filters.push(json!({"term": {"ip_address": ip}}));
    let observations = elasticsearch
        .scan_query(
            ScanQueryIndex::Observations,
            &json!({
                "size": 0, "track_total_hits": true,
                "query": {"bool": {"filter": observation_filters}},
                "aggs": {"first": {"min": {"field": "observed_at"}}, "last": {"max": {"field": "observed_at"}}}
            }),
        )
        .await;
    let (current, observations) = match (current, observations) {
        (Ok(current), Ok(observations)) => (current, observations),
        (Err(error), _) | (_, Err(error)) => {
            error_logs(req, "AssetSummaryElasticsearchError", &error);
            return HttpResponse::ServiceUnavailable()
                .json(json!({"message": "扫描结果索引暂时不可用"}));
        }
    };
    let observation_count = es_total(&observations);
    if observation_count == 0 {
        return HttpResponse::NotFound().json(json!({"message": "没有可访问的资产观察记录"}));
    }
    let latest = current.pointer("/aggregations/latest/hits/hits/0/_source");
    let tags = match pool.get().await {
        Ok(connection) => connection
            .query_one(
                "SELECT COALESCE(JSONB_AGG(JSONB_BUILD_OBJECT('id', tag.id, 'name', tag.name, \
                    'kind', tag.kind, 'description', tag.description, 'category_id', category.id, \
                    'category_name', category.name) ORDER BY category.sort_order, LOWER(category.name), tag.id) \
                    FILTER (WHERE tag.id IS NOT NULL), '[]'::JSONB) AS tags \
                 FROM asset_ip_tag assignment JOIN asset_tag tag ON tag.id = assignment.tag_id \
                 JOIN asset_tag_category category ON category.id = tag.category_id \
                 WHERE assignment.ip_address = $1::TEXT::INET AND tag.is_active AND category.is_active;",
                &[&ip],
            )
            .await
            .map(|row| tags_from_json(row.get("tags")))
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let text = |field: &str| {
        latest
            .and_then(|source| source.get(field))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let number = |field: &str| {
        latest
            .and_then(|source| source.get(field))
            .and_then(Value::as_f64)
    };
    let mut os_sources = Vec::new();
    if let Some(statuses) = current
        .pointer("/aggregations/os_by_status/buckets")
        .and_then(Value::as_array)
    {
        for status in statuses {
            if let Some(families) = status
                .pointer("/families/buckets")
                .and_then(Value::as_array)
            {
                for family in families {
                    if let Some(hits) = family
                        .pointer("/samples/hits/hits")
                        .and_then(Value::as_array)
                    {
                        os_sources
                            .extend(hits.iter().filter_map(|hit| hit.get("_source")).cloned());
                    }
                }
            }
        }
    }
    let mut host_os =
        crate::os_detection::summarize(&os_sources, chrono::Utc::now().timestamp_millis());
    if current
        .pointer("/aggregations/scanners/value")
        .and_then(Value::as_f64)
        .unwrap_or(0.0)
        > 1.0
        && host_os.confidence == "high"
    {
        host_os.confidence = "medium".into();
    }
    if es_total(&current) > os_sources.len() as i64 {
        host_os.distribution = None;
    }
    let mut intelligence =
        crate::threat_intel::annotate(pool, &[crate::threat_intel::endpoint_keys(ip, None)]).await;
    let summary = AssetSummary {
        intel: intelligence.remove(0),
        os: host_os,
        ip: ip.to_owned(),
        asn: text("asn"),
        isp: text("isp"),
        as_org: text("as_org"),
        country_code: text("country_code"),
        country_name: text("country_name"),
        region_name: text("region_name"),
        city_name: text("city_name"),
        latitude: number("latitude"),
        longitude: number("longitude"),
        port_count: es_total(&current),
        service_count: current
            .pointer("/aggregations/services/value")
            .and_then(Value::as_f64)
            .unwrap_or(0.0) as i64,
        scanner_count: current
            .pointer("/aggregations/scanners/value")
            .and_then(Value::as_f64)
            .unwrap_or(0.0) as i64,
        observation_count,
        first_seen_at: observations
            .pointer("/aggregations/first/value")
            .and_then(Value::as_f64)
            .map(|v| v as i64),
        last_seen_at: observations
            .pointer("/aggregations/last/value")
            .and_then(Value::as_f64)
            .map(|v| v as i64),
        tags,
        can_manage_tags: user.role == 1,
    };
    HttpResponse::Ok().json(json!({"success": true, "data": {"summary": summary}}))
}

async fn get_asset_ports_from_elasticsearch(
    req: &HttpRequest,
    pool: &Pool,
    elasticsearch: &ElasticsearchService,
    ip: &str,
    limit: i64,
    offset: i64,
    user: &UserBaseI,
) -> HttpResponse {
    let mut filters = current_scope_filters(user);
    filters.push(json!({"term": {"ip": ip}}));
    let result = match elasticsearch
        .scan_query(
            ScanQueryIndex::CurrentEndpoints,
            &json!({
                "from": offset, "size": limit, "track_total_hits": true,
                "query": {"bool": {"filter": filters}},
                "sort": [{"port": "asc"}]
            }),
        )
        .await
    {
        Ok(value) => value,
        Err(error) => {
            error_logs(req, "AssetPortsElasticsearchError", &error);
            return HttpResponse::ServiceUnavailable()
                .json(json!({"message": "扫描结果索引暂时不可用"}));
        }
    };
    let total = es_total(&result);
    if total == 0 {
        return HttpResponse::NotFound().json(json!({"message": "没有可访问的资产观察记录"}));
    }
    let mut items = result
        .pointer("/hits/hits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|hit| hit.get("_source"))
        .map(|source| {
            let last_seen_at = source
                .get("observed_at_ms")
                .and_then(Value::as_i64)
                .or_else(|| es_time_ms(source.get("last_seen")))
                .unwrap_or(0);
            let service_observed_at = source.get("service_observed_at_ms").and_then(Value::as_i64);
            AssetPortCurrent {
                intel: Default::default(),
                port: source.get("port").and_then(Value::as_i64).unwrap_or(0) as i32,
                protocol: source
                    .get("protocol")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                service: source
                    .get("service")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                banner: source
                    .get("banner")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                source: source
                    .get("source")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
                service_source: source
                    .get("service")
                    .and_then(Value::as_str)
                    .and_then(|_| source.get("source"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                first_seen_at: es_time_ms(source.get("first_seen")).unwrap_or(last_seen_at),
                last_seen_at,
                service_observed_at,
                service_stale: service_observed_at.is_some_and(|time| time < last_seen_at),
                web: crate::web_detection::endpoint_view(
                    source
                        .get("web")
                        .cloned()
                        .and_then(|v| serde_json::from_value(v).ok()),
                    last_seen_at,
                    chrono::Utc::now().timestamp_millis(),
                ),
                os: crate::os_detection::endpoint_view(
                    source
                        .get("os")
                        .cloned()
                        .and_then(|value| serde_json::from_value(value).ok()),
                    last_seen_at,
                    chrono::Utc::now().timestamp_millis(),
                ),
                execution_id: source
                    .get("execution_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                task_id: source
                    .get("task_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            }
        })
        .collect::<Vec<_>>();
    let keys = items
        .iter()
        .map(|item| crate::threat_intel::endpoint_keys(ip, Some(item.port)))
        .collect::<Vec<_>>();
    for (item, intel) in items
        .iter_mut()
        .zip(crate::threat_intel::annotate(pool, &keys).await)
    {
        item.intel = intel;
    }
    HttpResponse::Ok().json(json!({"success": true, "data": {
        "ip": ip, "items": items, "total": total, "limit": limit, "offset": offset
    }}))
}

async fn get_asset_history_from_elasticsearch(
    req: &HttpRequest,
    elasticsearch: &ElasticsearchService,
    ip: &str,
    port: i32,
    limit: i64,
    offset: i64,
    user: &UserBaseI,
) -> HttpResponse {
    let mut filters = observation_access_filters(user);
    filters.push(json!({"term": {"ip_address": ip}}));
    filters.push(json!({"term": {"port": port}}));
    let result = match elasticsearch
        .scan_query(
            ScanQueryIndex::Observations,
            &asset_history_search_body(filters, limit, offset),
        )
        .await
    {
        Ok(value) => value,
        Err(error) => {
            error_logs(req, "AssetHistoryElasticsearchError", &error);
            return HttpResponse::ServiceUnavailable()
                .json(json!({"message": "扫描结果索引暂时不可用"}));
        }
    };
    let total = es_total(&result);
    let items = result
        .pointer("/hits/hits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|hit| Some((hit.get("_id")?.as_str()?, hit.get("_source")?)))
        .map(|(id, source)| AssetObservationHistoryItem {
            id: i64::from_str_radix(&id[..id.len().min(15)], 16).unwrap_or_default(),
            kind: source
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            state: source
                .pointer("/data/state")
                .and_then(Value::as_str)
                .unwrap_or("open")
                .to_owned(),
            protocol: source
                .get("protocol")
                .and_then(Value::as_str)
                .map(str::to_owned),
            service: source
                .get("service")
                .and_then(Value::as_str)
                .map(str::to_owned),
            banner: source
                .get("banner")
                .and_then(Value::as_str)
                .map(str::to_owned),
            source: source
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned(),
            data: source.get("data").cloned().filter(|value| !value.is_null()),
            observed_at: es_time_ms(source.get("observed_at")).unwrap_or_default(),
            execution_id: source
                .get("execution_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            task_id: source
                .get("task_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            scanner_name: source
                .get("scanner_name")
                .and_then(Value::as_str)
                .map(str::to_owned),
            upload_id: source
                .get("upload_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            batch_index: source
                .get("batch_index")
                .and_then(Value::as_i64)
                .unwrap_or_default() as i32,
        })
        .collect::<Vec<_>>();
    HttpResponse::Ok().json(json!({"success": true, "data": {
        "ip": ip, "port": port, "items": items, "total": total, "limit": limit, "offset": offset
    }}))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        asset_history_search_body, asset_summary_current_search_body, normalize_history_pagination,
        normalize_ip, normalize_port_pagination,
    };

    #[test]
    fn normalizes_asset_ip_addresses() {
        assert_eq!(normalize_ip(" 192.0.2.1 "), Ok("192.0.2.1".to_owned()));
        assert_eq!(normalize_ip("2001:0db8::1"), Ok("2001:db8::1".to_owned()));
        assert!(normalize_ip("192.0.2.0/24").is_err());
    }

    #[test]
    fn validates_asset_query_ranges() {
        assert_eq!(normalize_port_pagination(None, None), Ok((20, 0)));
        assert!(normalize_port_pagination(Some(101), None).is_err());
        assert_eq!(normalize_history_pagination(None, None), Ok((50, 0)));
        assert!(normalize_history_pagination(Some(101), None).is_err());
    }

    #[test]
    fn asset_history_search_uses_sortable_stable_tie_breakers() {
        let body = asset_history_search_body(
            vec![
                json!({"term": {"ip_address": "192.0.2.1"}}),
                json!({"term": {"port": 443}}),
            ],
            50,
            100,
        );

        assert_eq!(
            body["sort"],
            json!([
                {"observed_at": {"order": "desc", "format": "epoch_millis"}},
                {"execution_id": "desc"},
                {"observation_key": "desc"}
            ])
        );
        assert_eq!(body["from"], 100);
        assert_eq!(body["size"], 50);
        assert!(!body.to_string().contains("\"_id\""));
    }

    #[test]
    fn asset_summary_latest_hit_has_stable_tie_breaker() {
        let body = asset_summary_current_search_body(vec![json!({"term": {"ip": "192.0.2.1"}})]);

        assert_eq!(
            body["aggs"]["latest"]["top_hits"]["sort"],
            json!([
                {"observed_at_ms": "desc"},
                {"port": "asc"}
            ])
        );
    }
}
