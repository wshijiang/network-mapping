use actix_web::{HttpRequest, HttpResponse, Responder, get, post, web};
use deadpool_postgres::Pool;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;
use tracing::error;

use crate::admin::UserBaseI;
use crate::elasticsearch::{ElasticsearchService, SearchSort};
use crate::handlers::search_dsl::{ElasticsearchCompilation, parse_and_compile_elasticsearch};
use crate::handlers::tags::AssetTag;

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 100;
const MAX_RESULT_WINDOW: i64 = 10_000;

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: String,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub sort_field: Option<String>,
    pub sort_order: Option<String>,
}

#[derive(Deserialize)]
pub struct PortSearchQuery {
    pub port: String,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub sort_field: Option<String>,
    pub sort_order: Option<String>,
}

#[derive(Deserialize)]
pub struct AdvancedSearchRequest {
    pub query: String,
    #[serde(default)]
    pub generate_if_needed: bool,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub sort_field: Option<String>,
    pub sort_order: Option<String>,
}

#[derive(Serialize)]
struct SearchResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_generation: Option<crate::target_generated::search::GenerationResult>,
    query_type: &'static str,
    query: String,
    items: Vec<SearchItem>,
    total: i64,
    limit: i64,
    offset: i64,
    sort_field: &'static str,
    sort_order: &'static str,
}

#[derive(Serialize)]
struct SearchItem {
    ip_address: String,
    port: Option<i32>,
    protocol: Option<String>,
    service: Option<String>,
    banner: Option<String>,
    title: Option<String>,
    tls_mode: Option<String>,
    tls_version: Option<String>,
    tls_cipher_suite: Option<String>,
    tls_subject: Option<String>,
    tls_issuer: Option<String>,
    tls_names: Vec<String>,
    tls_serial_number: Option<String>,
    tls_not_before: Option<i64>,
    tls_not_after: Option<i64>,
    tls_fingerprint_sha256: Option<String>,
    tls_self_signed: Option<bool>,
    os: Option<crate::os_detection::OsInference>,
    web: Option<crate::web_detection::WebInference>,
    scanner_name: Option<String>,
    scan_time: Option<i64>,
    asn: Option<String>,
    isp: Option<String>,
    as_org: Option<String>,
    country_code: Option<String>,
    country_name: Option<String>,
    region_name: Option<String>,
    city_name: Option<String>,
    tags: Vec<AssetTag>,
    intel: crate::threat_intel::Annotation,
}

fn pagination(limit: Option<i64>, offset: Option<i64>) -> Result<(i64, i64), &'static str> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    let offset = offset.unwrap_or(0);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err("limit 必须在 1 到 100 之间");
    }
    if !(0..MAX_RESULT_WINDOW).contains(&offset) || offset + limit > MAX_RESULT_WINDOW {
        return Err("offset 与 limit 超出前 10000 条结果窗口");
    }
    Ok((limit, offset))
}

fn validate_ip(value: &str) -> Result<(), &'static str> {
    IpAddr::from_str(value)
        .map(|_| ())
        .map_err(|_| "IP 地址格式无效")
}

fn normalize_cidr(value: &str) -> Result<String, &'static str> {
    let Some((ip, prefix)) = value.split_once('/') else {
        return Err("CIDR 必须包含前缀长度");
    };
    let ip = IpAddr::from_str(ip).map_err(|_| "CIDR 中的 IP 地址格式无效")?;
    let prefix = prefix.parse::<u8>().map_err(|_| "CIDR 前缀长度格式无效")?;
    if prefix > if ip.is_ipv4() { 32 } else { 128 } {
        return Err("CIDR 前缀长度超出范围");
    }
    Ok(IpNet::new(ip, prefix)
        .map_err(|_| "CIDR 前缀长度超出范围")?
        .trunc()
        .to_string())
}

fn validate_keyword(value: &str, name: &str) -> Result<(), String> {
    let length = value.chars().count();
    if !(2..=128).contains(&length) {
        return Err(format!("{} 的长度必须在 2 到 128 个字符之间", name));
    }
    Ok(())
}

fn bad_request(message: impl Into<String>) -> HttpResponse {
    HttpResponse::BadRequest().json(serde_json::json!({ "message": message.into() }))
}

fn domain_result_too_broad(error: &str) -> HttpResponse {
    HttpResponse::UnprocessableEntity().json(serde_json::json!({
        "code": "DOMAIN_RESULT_TOO_BROAD",
        "message": error.strip_prefix("DOMAIN_RESULT_TOO_BROAD: ").unwrap_or(error),
    }))
}

#[get("/api/search/elasticsearch/status")]
pub async fn elasticsearch_status(
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    user: UserBaseI,
) -> impl Responder {
    if user.role != 1 {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"message": "仅管理员可以查看搜索索引状态"}));
    }
    match elasticsearch.status(pool.get_ref()).await {
        Ok(status) => HttpResponse::Ok().json(status),
        Err(error_value) => {
            error!(
                event = "ElasticsearchStatusError",
                operation = "load_elasticsearch_status",
                error_kind = "search_storage",
                error_code = "elasticsearch_status_load_failed",
                error_message = %error_value,
                retryable = false,
                outcome = "request_failed",
                user_id = user.id,
            );
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"message": "无法读取搜索索引状态"}))
        }
    }
}

#[post("/api/search/v2")]
pub async fn search_v2(
    req: HttpRequest,
    pool: web::Data<Pool>,
    settings: web::Data<crate::runtime_config::RuntimeSettings>,
    elasticsearch: web::Data<ElasticsearchService>,
    payload: web::Json<AdvancedSearchRequest>,
    user: UserBaseI,
) -> impl Responder {
    let query = payload.query.trim();
    let (limit, offset) = match pagination(payload.limit, payload.offset) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let sort = match SearchSort::parse(payload.sort_field.as_deref(), payload.sort_order.as_deref())
    {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let elasticsearch_compilation = match parse_and_compile_elasticsearch(query) {
        Ok(value) => value,
        Err(error_value) => {
            let utf16_offset = |byte_offset: usize| {
                query
                    .get(..byte_offset)
                    .map(|value| value.encode_utf16().count())
                    .unwrap_or_else(|| query.encode_utf16().count())
            };
            return HttpResponse::UnprocessableEntity().json(serde_json::json!({
                "code": "SEARCH_SYNTAX_ERROR",
                "message": error_value.message,
                "span": {
                    "start": utf16_offset(error_value.start),
                    "end": utf16_offset(error_value.end),
                },
            }));
        }
    };

    match elasticsearch_compilation {
            ElasticsearchCompilation::Supported(filter)
            | ElasticsearchCompilation::RequiresElasticsearch(filter) => respond_search_elasticsearch(
                pool.get_ref(), elasticsearch.get_ref(), &user, "advanced", query.to_owned(), filter, (limit, offset), sort,
                (payload.generate_if_needed && offset == 0).then_some(GenerationContext { pool: pool.get_ref(), settings: settings.get_ref(), audit: crate::audit::AuditContext::from_request(&req) }),
            ).await,
            ElasticsearchCompilation::Unsupported => HttpResponse::UnprocessableEntity().json(
                serde_json::json!({"code": "SEARCH_ES_UNSUPPORTED", "message": "该查询暂不支持 Elasticsearch 读路径"}),
            ),
        }
}

struct GenerationContext<'a> {
    pool: &'a Pool,
    settings: &'a crate::runtime_config::RuntimeSettings,
    audit: crate::audit::AuditContext,
}

#[allow(clippy::too_many_arguments)]
async fn respond_search_elasticsearch(
    pool: &Pool,
    elasticsearch: &ElasticsearchService,
    user: &UserBaseI,
    query_type: &'static str,
    query: String,
    filter: serde_json::Value,
    pagination: (i64, i64),
    sort: SearchSort,
    generation: Option<GenerationContext<'_>>,
) -> HttpResponse {
    let (limit, offset) = pagination;
    match elasticsearch
        .search(user.role, user.id, filter, limit, offset, sort)
        .await
    {
        Ok(page) => {
            let keys = page
                .items
                .iter()
                .map(|item| crate::threat_intel::endpoint_keys(&item.ip_address, Some(item.port)))
                .collect::<Vec<_>>();
            let intelligence = crate::threat_intel::annotate(pool, &keys).await;
            let auto_generation = if let Some(context) = generation {
                let policy = context.settings.automatic_target.get().await;
                let dns_policy = context.settings.dns_follow_up.get().await.value;
                match tokio::time::timeout(
                    std::time::Duration::from_secs(4),
                    crate::target_generated::search::generate(
                        context.pool,
                        elasticsearch,
                        user,
                        &policy.value,
                        policy.revision,
                        &query,
                        &dns_policy,
                        &context.audit,
                    ),
                )
                .await
                {
                    Ok(Ok(result)) => Some(result),
                    result => {
                        tracing::warn!(event = "SearchGenerationUnavailable", error = ?result);
                        Some(crate::target_generated::search::GenerationResult::status(
                            "unavailable",
                        ))
                    }
                }
            } else {
                None
            };
            HttpResponse::Ok().json(SearchResponse {
                auto_generation,
                query_type,
                query,
                items: page
                    .items
                    .into_iter()
                    .zip(intelligence)
                    .map(|(item, intel)| SearchItem {
                        intel,
                        ip_address: item.ip_address,
                        port: Some(item.port),
                        protocol: item.protocol,
                        service: item.service,
                        banner: item.banner,
                        title: item.title,
                        tls_mode: item.tls_mode,
                        tls_version: item.tls_version,
                        tls_cipher_suite: item.tls_cipher_suite,
                        tls_subject: item.tls_subject,
                        tls_issuer: item.tls_issuer,
                        tls_names: item.tls_names,
                        tls_serial_number: item.tls_serial_number,
                        tls_not_before: item.tls_not_before,
                        tls_not_after: item.tls_not_after,
                        tls_fingerprint_sha256: item.tls_fingerprint_sha256,
                        tls_self_signed: item.tls_self_signed,
                        os: item.os,
                        web: item.web,
                        scanner_name: item.scanner_name,
                        scan_time: Some(item.scan_time),
                        asn: item.asn,
                        isp: item.isp,
                        as_org: item.as_org,
                        country_code: item.country_code,
                        country_name: item.country_name,
                        region_name: item.region_name,
                        city_name: item.city_name,
                        tags: item.tags,
                    })
                    .collect(),
                total: page.total,
                limit,
                offset,
                sort_field: sort.field_name(),
                sort_order: sort.order_name(),
            })
        }
        Err(error_value) if error_value.starts_with("DOMAIN_RESULT_TOO_BROAD:") => {
            domain_result_too_broad(&error_value)
        }
        Err(error_value) => {
            error!(
                event = "SearchElasticsearchError",
                operation = "execute_elasticsearch_search",
                error_kind = "search_storage",
                error_code = "elasticsearch_search_failed",
                error_message = %error_value,
                retryable = true,
                outcome = "request_failed",
                query_type,
                user_id = user.id,
                user_role = user.role,
                limit,
                offset,
            );
            HttpResponse::ServiceUnavailable()
                .json(serde_json::json!({"message": "搜索索引暂时不可用"}))
        }
    }
}

#[get("/api/search/ip")]
pub async fn search_ip(
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    query: web::Query<SearchQuery>,
    user: UserBaseI,
) -> impl Responder {
    let q = query.q.trim();
    if let Err(message) = validate_ip(q) {
        return bad_request(message);
    }
    let (limit, offset) = match pagination(query.limit, query.offset) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let sort = match SearchSort::parse(query.sort_field.as_deref(), query.sort_order.as_deref()) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };

    return respond_search_elasticsearch(
        pool.get_ref(),
        elasticsearch.get_ref(),
        &user,
        "ip",
        q.to_owned(),
        serde_json::json!({"term": {"ip": q}}),
        (limit, offset),
        sort,
        None,
    )
    .await;
}

#[get("/api/search/network")]
pub async fn search_network(
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    query: web::Query<SearchQuery>,
    user: UserBaseI,
) -> impl Responder {
    let q = query.q.trim();
    let normalized_cidr = match normalize_cidr(q) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let (limit, offset) = match pagination(query.limit, query.offset) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let sort = match SearchSort::parse(query.sort_field.as_deref(), query.sort_order.as_deref()) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };

    return respond_search_elasticsearch(
        pool.get_ref(),
        elasticsearch.get_ref(),
        &user,
        "network",
        q.to_owned(),
        serde_json::json!({"term": {"ip": normalized_cidr}}),
        (limit, offset),
        sort,
        None,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::{normalize_cidr, pagination};

    #[test]
    fn search_pagination_stays_within_elasticsearch_result_window() {
        assert_eq!(pagination(Some(50), Some(9950)), Ok((50, 9950)));
        assert!(pagination(Some(50), Some(10000)).is_err());
        assert!(pagination(Some(100), Some(9950)).is_err());
    }

    #[test]
    fn normalizes_ipv4_cidr_with_host_bits() {
        assert_eq!(
            normalize_cidr("192.168.1.123/24"),
            Ok("192.168.1.0/24".to_owned())
        );
    }

    #[test]
    fn normalizes_ipv6_cidr_with_host_bits() {
        assert_eq!(
            normalize_cidr("2001:db8::1234/64"),
            Ok("2001:db8::/64".to_owned())
        );
    }

    #[test]
    fn rejects_out_of_range_prefixes() {
        assert_eq!(normalize_cidr("192.0.2.1/33"), Err("CIDR 前缀长度超出范围"));
        assert_eq!(
            normalize_cidr("2001:db8::1/129"),
            Err("CIDR 前缀长度超出范围")
        );
    }
}

#[get("/api/search/port")]
pub async fn search_port(
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    query: web::Query<PortSearchQuery>,
    user: UserBaseI,
) -> impl Responder {
    let port = match query.port.trim().parse::<u16>() {
        Ok(value @ 1..=65535) => value,
        _ => return bad_request("端口必须在 1 到 65535 之间"),
    };
    let (limit, offset) = match pagination(query.limit, query.offset) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let sort = match SearchSort::parse(query.sort_field.as_deref(), query.sort_order.as_deref()) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };

    return respond_search_elasticsearch(
        pool.get_ref(),
        elasticsearch.get_ref(),
        &user,
        "port",
        port.to_string(),
        serde_json::json!({"term": {"port": port}}),
        (limit, offset),
        sort,
        None,
    )
    .await;
}

#[get("/api/search/service")]
pub async fn search_service(
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    query: web::Query<SearchQuery>,
    user: UserBaseI,
) -> impl Responder {
    let q = query.q.trim();
    if let Err(message) = validate_keyword(q, "服务名") {
        return bad_request(message);
    }
    let (limit, offset) = match pagination(query.limit, query.offset) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let sort = match SearchSort::parse(query.sort_field.as_deref(), query.sort_order.as_deref()) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };

    let escaped = q
        .replace('\\', "\\\\")
        .replace('*', "\\*")
        .replace('?', "\\?");
    return respond_search_elasticsearch(
            pool.get_ref(), elasticsearch.get_ref(), &user, "service", q.to_owned(),
            serde_json::json!({"wildcard": {"service": {"value": format!("*{escaped}*"), "case_insensitive": true}}}),
            (limit, offset), sort,
            None,
        ).await;
}

#[get("/api/search/banner")]
pub async fn search_banner(
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    query: web::Query<SearchQuery>,
    user: UserBaseI,
) -> impl Responder {
    let q = query.q.trim();
    if let Err(message) = validate_keyword(q, "Banner 关键字") {
        return bad_request(message);
    }
    let (limit, offset) = match pagination(query.limit, query.offset) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let sort = match SearchSort::parse(query.sort_field.as_deref(), query.sort_order.as_deref()) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };

    let escaped = q
        .replace('\\', "\\\\")
        .replace('*', "\\*")
        .replace('?', "\\?");
    return respond_search_elasticsearch(
            pool.get_ref(), elasticsearch.get_ref(), &user, "banner", q.to_owned(),
            serde_json::json!({"wildcard": {"banner": {"value": format!("*{escaped}*"), "case_insensitive": true}}}),
            (limit, offset), sort,
            None,
        ).await;
}
