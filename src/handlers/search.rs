use actix_web::{HttpRequest, HttpResponse, Responder, get, post, web};
use deadpool_postgres::Pool;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;
use tracing::error;

use crate::admin::UserBaseI;
use crate::elasticsearch::{ElasticsearchService, SearchSort, SearchValueField};
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SearchValuesQuery {
    field: SearchValueField,
}

#[derive(Serialize)]
struct SearchResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_generation: Option<crate::target_generated::search::GenerationResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    federation: Option<serde_json::Value>,
    query_type: &'static str,
    query: String,
    items: Vec<SearchItem>,
    total: i64,
    limit: i64,
    offset: i64,
    sort_field: &'static str,
    sort_order: &'static str,
    /// 服务端处理本次搜索的总耗时（毫秒，含情报标注与联测合流）。
    took_ms: i64,
    /// Elasticsearch 自报的查询耗时（`took`，毫秒）。
    es_took_ms: i64,
    /// Elasticsearch 调用墙钟耗时（毫秒，含网络往返与响应解析）。
    es_wall_ms: i64,
    /// 威胁情报标注累计耗时（毫秒，含联测新增端点的补充标注）。
    intel_took_ms: i64,
}

#[derive(Serialize)]
struct SearchItem {
    ip_address: String,
    port: Option<i32>,
    protocol: Option<String>,
    service: Option<String>,
    products: Vec<crate::service_products::Product>,
    product_identification: Option<crate::service_products::Identification>,
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
    /// Favicon MD5（与 Hunter web.icon / Quake favicon.hash 一致）。
    icon_md5: Option<String>,
    favicon_url: Option<String>,
    /// 图标元数据（字节经 /api/assets/favicon 中继，不内联进搜索响应）。
    favicon: Option<crate::web_assets::FaviconView>,
    js_names: Vec<String>,
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
    /// local / federation / merged（联测展示合并标记）。
    #[serde(skip_serializing_if = "Option::is_none")]
    data_origin: Option<String>,
    /// 贡献该端点的联测平台。
    #[serde(skip_serializing_if = "Vec::is_empty")]
    federation_sources: Vec<String>,
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

#[get("/api/search/values")]
pub(crate) async fn search_values(
    elasticsearch: web::Data<ElasticsearchService>,
    query: web::Query<SearchValuesQuery>,
    user: UserBaseI,
) -> impl Responder {
    let values = elasticsearch
        .suggest_search_values(user.role, user.id, query.field)
        .await;
    HttpResponse::Ok()
        .insert_header(("Cache-Control", "private, no-store"))
        .json(values)
}

#[post("/api/search/v2")]
pub async fn search_v2(
    req: HttpRequest,
    pool: web::Data<Pool>,
    settings: web::Data<crate::runtime_config::RuntimeSettings>,
    elasticsearch: web::Data<ElasticsearchService>,
    federation: web::Data<crate::federation::search::FederationService>,
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

    let may_generate = crate::access::Access::from_request(&req)
        .is_some_and(|access| access.allows_automatic_scan());
    match elasticsearch_compilation {
            ElasticsearchCompilation::Supported(filter)
            | ElasticsearchCompilation::RequiresElasticsearch(filter) => respond_search_elasticsearch(
                pool.get_ref(), elasticsearch.get_ref(), &user, "advanced", query.to_owned(), filter, (limit, offset), sort,
                (may_generate && payload.generate_if_needed && offset == 0).then(|| GenerationContext { pool: pool.get_ref(), settings: settings.get_ref(), audit: crate::audit::AuditContext::from_request(&req) }),
                Some(federation.get_ref()),
                Some(query.to_owned()),
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
    federation: Option<&crate::federation::search::FederationService>,
    federation_query: Option<String>,
) -> HttpResponse {
    let started = std::time::Instant::now();
    let (limit, offset) = pagination;
    // 联测触发评估（含新鲜度探测），run 与本地搜索并行执行（§7/§8）。
    let prepared = match (federation, federation_query.as_deref()) {
        (Some(service), Some(federation_query)) => {
            crate::federation::search::prepare(
                service,
                user.id,
                user.role,
                federation_query,
                filter.clone(),
                limit as u32,
                offset as u32,
            )
            .await
        }
        _ => crate::federation::search::Prepared::NotTriggered,
    };
    let es_started = std::time::Instant::now();
    match elasticsearch
        .search(user.role, user.id, filter, limit, offset, sort)
        .await
    {
        Ok(page) => {
            let es_wall_ms = es_started.elapsed().as_millis() as i64;
            let es_took_ms = page.took_ms;
            let keys = page
                .items
                .iter()
                .map(|item| crate::threat_intel::endpoint_keys(&item.ip_address, Some(item.port)))
                .collect::<Vec<_>>();
            let asns = page
                .items
                .iter()
                .map(|item| item.asn.as_deref())
                .collect::<Vec<_>>();
            let intel_started = std::time::Instant::now();
            let intelligence = crate::threat_intel::annotate_assets(pool, &keys, &asns).await;
            let mut intel_took_ms = intel_started.elapsed().as_millis() as i64;
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
            let mut items: Vec<SearchItem> = page
                .items
                .into_iter()
                .zip(intelligence)
                .map(|(item, intel)| SearchItem {
                    intel,
                    ip_address: item.ip_address,
                    port: Some(item.port),
                    protocol: item.protocol,
                    service: item.service,
                    products: item.products,
                    product_identification: item.product_identification,
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
                    icon_md5: item.icon_md5,
                    favicon_url: item.favicon_url,
                    favicon: item.favicon,
                    js_names: item.js_names,
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
                    data_origin: None,
                    federation_sources: Vec::new(),
                })
                .collect();
            let mut total = page.total;
            // 联测合流：async 立即返回（已完成则并入），blocking 等待预算（§8）。
            let federation = if let Some(service) = federation {
                match crate::federation::search::resolve(service, prepared).await {
                    Some(outcome) => {
                        let merged_new =
                            merge_federation_items(&mut items, &outcome.records, sort, limit);
                        if merged_new > 0 {
                            // 新增联测端点补情报标注。
                            let new_indices: Vec<usize> = items
                                .iter()
                                .enumerate()
                                .filter(|(_, item)| {
                                    item.data_origin.as_deref() == Some("federation")
                                })
                                .map(|(index, _)| index)
                                .collect();
                            let keys: Vec<_> = new_indices
                                .iter()
                                .map(|&index| {
                                    crate::threat_intel::endpoint_keys(
                                        &items[index].ip_address,
                                        items[index].port,
                                    )
                                })
                                .collect();
                            let asns: Vec<_> = new_indices
                                .iter()
                                .map(|&index| items[index].asn.as_deref())
                                .collect();
                            let intel_started = std::time::Instant::now();
                            let annotations =
                                crate::threat_intel::annotate_assets(pool, &keys, &asns).await;
                            intel_took_ms += intel_started.elapsed().as_millis() as i64;
                            for (&index, annotation) in new_indices.iter().zip(annotations) {
                                items[index].intel = annotation;
                            }
                            total += merged_new as i64;
                        }
                        Some(crate::federation::search::outcome_json(
                            &outcome, merged_new,
                        ))
                    }
                    None => None,
                }
            } else {
                None
            };
            HttpResponse::Ok().json(SearchResponse {
                auto_generation,
                federation,
                query_type,
                query,
                items,
                total,
                limit,
                offset,
                sort_field: sort.field_name(),
                sort_order: sort.order_name(),
                took_ms: started.elapsed().as_millis() as i64,
                es_took_ms,
                es_wall_ms,
                intel_took_ms,
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

/// 联测记录 → Web 技术栈展示对象（§9.3）。
fn federation_web(
    record: &crate::federation::model::NormalizedRecord,
) -> Option<crate::web_detection::WebInference> {
    if record.tech.is_empty() {
        return None;
    }
    Some(crate::web_detection::WebInference {
        status: "identified".into(),
        inference_scope: "federation".into(),
        technologies: record
            .tech
            .iter()
            .map(|entry| crate::web_detection::Technology {
                id: entry.id.clone(),
                name: entry.id.clone(),
                category: "other".into(),
                version: entry.version.clone(),
                version_conflict: false,
                confidence: "medium".into(),
                basis: "federation".into(),
                usage: "imported".into(),
                evidence: vec![crate::web_detection::WebEvidence {
                    rule_id: "federation".into(),
                    module: "federation".into(),
                    field_path: "/federation/tech".into(),
                    excerpt: entry.id.clone(),
                    observation_ref: None,
                }],
            })
            .collect(),
        truncated: false,
        ruleset_revision: crate::web_detection::RULESET_REVISION,
        ruleset_version: crate::web_detection::RULESET_VERSION.into(),
        observed_at: Some(record.observed_at),
        stale: false,
    })
}

/// 联测展示合并（§9.3）：端点键去重、observed_at 新者胜、空字段 COALESCE、
/// 来源标记；按当前排序重排并截断。返回新增端点数。
fn merge_federation_items(
    items: &mut Vec<SearchItem>,
    records: &[crate::federation::model::NormalizedRecord],
    sort: SearchSort,
    limit: i64,
) -> usize {
    use std::collections::HashMap;
    let endpoint_key = |item: &SearchItem| {
        format!(
            "{}|{}|{}",
            item.ip_address,
            item.port.unwrap_or(0),
            item.protocol.as_deref().unwrap_or("tcp")
        )
    };
    let mut index_by_key: HashMap<String, usize> = items
        .iter()
        .enumerate()
        .map(|(index, item)| (endpoint_key(item), index))
        .collect();
    let mut added = 0usize;
    for record in records {
        let key = record.endpoint_key();
        if let Some(&index) = index_by_key.get(&key) {
            let item = &mut items[index];
            if record.observed_at > item.scan_time.unwrap_or(0) {
                // 联测更新：覆盖非空字段。
                if record.service.is_some() {
                    item.service = record.service.clone();
                }
                if record.banner.is_some() {
                    item.banner = record.banner.clone();
                }
                if record.title.is_some() {
                    item.title = record.title.clone();
                }
                if let Some(web) = federation_web(record) {
                    item.web = Some(web);
                }
                if record.asn.is_some() {
                    item.asn = record.asn.clone();
                }
                if record.as_org.is_some() {
                    item.as_org = record.as_org.clone();
                }
                if record.isp.is_some() {
                    item.isp = record.isp.clone();
                }
                if record.country_name.is_some() {
                    item.country_name = record.country_name.clone();
                }
                if record.region_name.is_some() {
                    item.region_name = record.region_name.clone();
                }
                if record.city_name.is_some() {
                    item.city_name = record.city_name.clone();
                }
                item.scan_time = Some(record.observed_at);
                item.scanner_name = Some(crate::federation::FEDERATION_SCANNER_NAME.to_owned());
            } else {
                // 本地更新：仅补空字段。
                item.service = item.service.take().or_else(|| record.service.clone());
                item.banner = item.banner.take().or_else(|| record.banner.clone());
                item.title = item.title.take().or_else(|| record.title.clone());
                if item.web.is_none() {
                    item.web = federation_web(record);
                }
                item.asn = item.asn.take().or_else(|| record.asn.clone());
                item.as_org = item.as_org.take().or_else(|| record.as_org.clone());
                item.isp = item.isp.take().or_else(|| record.isp.clone());
            }
            item.data_origin = Some("merged".into());
            for source in &record.sources {
                if !item.federation_sources.contains(source) {
                    item.federation_sources.push(source.clone());
                }
            }
        } else {
            let item = SearchItem {
                intel: crate::threat_intel::Annotation::default(),
                ip_address: record.ip.clone(),
                port: Some(i32::from(record.port)),
                protocol: Some(record.protocol.clone()),
                service: record.service.clone(),
                products: Vec::new(),
                product_identification: None,
                banner: record.banner.clone(),
                title: record.title.clone(),
                tls_mode: None,
                tls_version: None,
                tls_cipher_suite: None,
                tls_subject: None,
                tls_issuer: None,
                tls_names: Vec::new(),
                tls_serial_number: None,
                tls_not_before: None,
                tls_not_after: None,
                tls_fingerprint_sha256: None,
                tls_self_signed: None,
                icon_md5: None,
                favicon_url: None,
                favicon: None,
                js_names: Vec::new(),
                os: None,
                web: federation_web(record),
                scanner_name: Some(crate::federation::FEDERATION_SCANNER_NAME.to_owned()),
                scan_time: Some(record.observed_at),
                asn: record.asn.clone(),
                isp: record.isp.clone(),
                as_org: record.as_org.clone(),
                country_code: None,
                country_name: record.country_name.clone(),
                region_name: record.region_name.clone(),
                city_name: record.city_name.clone(),
                tags: Vec::new(),
                data_origin: Some("federation".into()),
                federation_sources: record.sources.clone(),
            };
            index_by_key.insert(key, items.len());
            items.push(item);
            added += 1;
        }
    }
    // first_seen 顺序由 ES 决定；联测合并后保持本地顺序，新端点追加在末尾。
    if sort.field_name() != "first_seen" {
        let descending = sort.order_name() == "desc";
        items.sort_by(|a, b| {
            let ordering = match sort.field_name() {
                "ip" => a.ip_address.cmp(&b.ip_address),
                "port" => a.port.unwrap_or(0).cmp(&b.port.unwrap_or(0)),
                _ => a.scan_time.unwrap_or(0).cmp(&b.scan_time.unwrap_or(0)),
            };
            if descending {
                ordering.reverse()
            } else {
                ordering
            }
        });
    }
    items.truncate(limit.max(0) as usize);
    added
}

#[get("/api/search/ip")]
pub async fn search_ip(
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    federation: web::Data<crate::federation::search::FederationService>,
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
        Some(federation.get_ref()),
        Some(format!("ip = {}", serde_json::json!(q))),
    )
    .await;
}

#[get("/api/search/network")]
pub async fn search_network(
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    federation: web::Data<crate::federation::search::FederationService>,
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
        Some(federation.get_ref()),
        Some(format!("ip = {}", serde_json::json!(normalized_cidr))),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::{normalize_cidr, pagination};

    #[test]
    fn field_value_query_is_limited_to_a_canonical_field() {
        assert!(
            actix_web::web::Query::<super::SearchValuesQuery>::from_query("field=os.family")
                .is_ok()
        );
        for invalid in [
            "",
            "field=banner",
            "field=port",
            "field=web.tech",
            "field=service&scope_id=8",
            "field=service&prefix=h",
        ] {
            assert!(
                actix_web::web::Query::<super::SearchValuesQuery>::from_query(invalid).is_err()
            );
        }
    }

    #[test]
    fn search_pagination_stays_within_elasticsearch_result_window() {
        assert_eq!(pagination(Some(50), Some(9950)), Ok((50, 9950)));
        assert!(pagination(Some(50), Some(10000)).is_err());
        assert!(pagination(Some(100), Some(9950)).is_err());
    }

    fn local_item(ip: &str, port: i32, scan_time: i64) -> super::SearchItem {
        super::SearchItem {
            intel: crate::threat_intel::Annotation::default(),
            ip_address: ip.into(),
            port: Some(port),
            protocol: Some("tcp".into()),
            service: Some("https".into()),
            products: Vec::new(),
            product_identification: None,
            banner: None,
            title: None,
            tls_mode: None,
            tls_version: None,
            tls_cipher_suite: None,
            tls_subject: None,
            tls_issuer: None,
            tls_names: Vec::new(),
            tls_serial_number: None,
            tls_not_before: None,
            tls_not_after: None,
            tls_fingerprint_sha256: None,
            tls_self_signed: None,
            icon_md5: None,
            favicon_url: None,
            favicon: None,
            js_names: Vec::new(),
            os: None,
            web: None,
            scanner_name: Some("scanner-1".into()),
            scan_time: Some(scan_time),
            asn: None,
            isp: None,
            as_org: None,
            country_code: None,
            country_name: None,
            region_name: None,
            city_name: None,
            tags: Vec::new(),
            data_origin: None,
            federation_sources: Vec::new(),
        }
    }

    fn fed_record(
        ip: &str,
        port: u16,
        observed_at: i64,
    ) -> crate::federation::model::NormalizedRecord {
        crate::federation::model::NormalizedRecord {
            ip: ip.into(),
            port,
            protocol: "tcp".into(),
            domain: None,
            service: Some("http".into()),
            tech: vec![],
            title: Some("Fed".into()),
            banner: None,
            observed_at,
            timestamp_inferred: false,
            asn: None,
            as_org: None,
            isp: None,
            country_name: None,
            region_name: None,
            city_name: None,
            latitude: None,
            longitude: None,
            sources: vec!["fofa".into()],
        }
    }

    #[test]
    fn merge_adds_new_endpoint_and_marks_origin() {
        let mut items = vec![local_item("1.1.1.1", 443, 100)];
        let records = vec![fed_record("2.2.2.2", 80, 200)];
        let added = super::merge_federation_items(
            &mut items,
            &records,
            crate::elasticsearch::SearchSort::default(),
            50,
        );
        assert_eq!(added, 1);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].data_origin.as_deref(), Some("federation")); // 200 > 100 排前
        assert_eq!(items[0].federation_sources, vec!["fofa".to_owned()]);
    }

    #[test]
    fn merge_newer_federation_wins_older_fills_empty() {
        // 联测更新 → 覆盖服务/标题/时间。
        let mut items = vec![local_item("1.1.1.1", 443, 100)];
        let added = super::merge_federation_items(
            &mut items,
            &[fed_record("1.1.1.1", 443, 200)],
            crate::elasticsearch::SearchSort::default(),
            50,
        );
        assert_eq!(added, 0);
        assert_eq!(items[0].service.as_deref(), Some("http"));
        assert_eq!(items[0].title.as_deref(), Some("Fed"));
        assert_eq!(items[0].scan_time, Some(200));
        assert_eq!(items[0].data_origin.as_deref(), Some("merged"));
        // 本地更新 → 保留本地服务，仅补空标题。
        let mut items = vec![local_item("1.1.1.1", 443, 300)];
        super::merge_federation_items(
            &mut items,
            &[fed_record("1.1.1.1", 443, 200)],
            crate::elasticsearch::SearchSort::default(),
            50,
        );
        assert_eq!(items[0].service.as_deref(), Some("https"));
        assert_eq!(items[0].title.as_deref(), Some("Fed"));
        assert_eq!(items[0].scan_time, Some(300));
    }

    #[test]
    fn merge_truncates_to_limit() {
        let mut items = vec![local_item("1.1.1.1", 443, 100)];
        let records = vec![
            fed_record("2.2.2.2", 80, 300),
            fed_record("3.3.3.3", 80, 200),
        ];
        let added = super::merge_federation_items(
            &mut items,
            &records,
            crate::elasticsearch::SearchSort::default(),
            2,
        );
        assert_eq!(added, 2);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].ip_address, "2.2.2.2");
    }

    #[test]
    fn merge_preserves_first_seen_order() {
        let mut items = vec![
            local_item("3.3.3.3", 443, 300),
            local_item("1.1.1.1", 80, 100),
        ];
        let sort =
            crate::elasticsearch::SearchSort::parse(Some("first_seen"), Some("desc")).unwrap();
        super::merge_federation_items(&mut items, &[fed_record("2.2.2.2", 80, 200)], sort, 50);
        // 本地 first_seen 顺序不变，新端点追加在末尾。
        assert_eq!(items[0].ip_address, "3.3.3.3");
        assert_eq!(items[1].ip_address, "1.1.1.1");
        assert_eq!(items[2].ip_address, "2.2.2.2");
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
    federation: web::Data<crate::federation::search::FederationService>,
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
        Some(federation.get_ref()),
        Some(format!("port = {port}")),
    )
    .await;
}

#[get("/api/search/service")]
pub async fn search_service(
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    federation: web::Data<crate::federation::search::FederationService>,
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
            Some(federation.get_ref()),
            Some(format!("service ~ {}", serde_json::json!(q))),
        ).await;
}

#[get("/api/search/banner")]
pub async fn search_banner(
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    federation: web::Data<crate::federation::search::FederationService>,
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
            Some(federation.get_ref()),
            Some(format!("banner ~ {}", serde_json::json!(q))),
        ).await;
}
