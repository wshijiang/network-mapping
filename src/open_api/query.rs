use super::{ApiError, Principal, Result, model};
use crate::elasticsearch::{ElasticsearchService, ScanQueryIndex};
use crate::handlers::search_dsl::{ElasticsearchCompilation, parse_and_compile_elasticsearch};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use uuid::Uuid;

pub(crate) async fn db_after(
    pool: &Pool,
    p: &Principal,
    cursor: Option<Uuid>,
    label: &str,
) -> Result<i64> {
    let Some(cursor) = cursor else {
        return Ok(i32::MAX as i64);
    };
    let row=pool.get().await?.query_opt("SELECT after_value FROM api_cursor WHERE id=$1 AND client_id=$2 AND credential_id=$3 AND policy_revision=$4 AND query_hash=$5 AND expires_at>NOW()",&[&cursor,&p.client_pk,&p.credential_id,&p.revision,&label]).await?.ok_or_else(||ApiError::bad("游标失效"))?;
    row.get::<_, Value>(0)
        .as_i64()
        .ok_or_else(|| ApiError::bad("游标无效"))
}
pub(crate) async fn db_next(pool: &Pool, p: &Principal, after: i64, label: &str) -> Result<Uuid> {
    let id = Uuid::new_v4();
    pool.get().await?.execute("INSERT INTO api_cursor(id,client_id,credential_id,policy_revision,query_hash,after_value) VALUES($1,$2,$3,$4,$5,$6)",&[&id,&p.client_pk,&p.credential_id,&p.revision,&label,&json!(after)]).await?;
    Ok(id)
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Search {
    pub query: Option<String>,
    pub page_size: Option<usize>,
    pub cursor: Option<Uuid>,
    pub fields: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_instant")]
    pub start_at: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_instant")]
    pub end_at: Option<i64>,
    pub execution_id: Option<Uuid>,
    pub task_id: Option<Uuid>,
    pub severity: Option<String>,
    pub template_id: Option<String>,
}
pub(crate) fn instant(value: &Value) -> Result<Option<i64>> {
    if value.is_null() {
        return Ok(None);
    }
    if let Some(n) = value.as_i64() {
        return Ok(Some(n));
    }
    value
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| Some(t.timestamp_millis()))
        .ok_or_else(|| ApiError::bad("时间必须为 RFC 3339 或毫秒时间戳"))
}
fn deserialize_instant<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<i64>, D::Error> {
    instant(&Value::deserialize(d)?).map_err(|e| serde::de::Error::custom(e.message))
}
impl Search {
    pub fn size(&self) -> Result<usize> {
        let n = self.page_size.unwrap_or(50);
        if !(1..=100).contains(&n) {
            return Err(ApiError::bad("page_size 必须为 1–100"));
        }
        Ok(n)
    }
    pub fn validate(&self, p: &Principal) -> Result<()> {
        self.size()?;
        if self.start_at.zip(self.end_at).is_some_and(|(a, b)| a >= b) {
            return Err(ApiError::bad("时间范围无效"));
        }
        if self.fields.as_ref().is_some_and(|f| {
            f.is_empty()
                || f.len() > model::FIELDS.len()
                || f.iter().any(|f| !p.policy.fields.contains(f))
        }) {
            return Err(ApiError::forbidden());
        }
        Ok(())
    }
}
fn constrain_markers(value: &mut Value, p: &Principal) {
    if let Some(filter) = value.get_mut("network_mapping_has_endpoint") {
        let mut restrictions = vec![filter.clone(), p.policy.ip_filter("ip")];
        time_filter(&mut restrictions, p, &Search::default(), "last_seen");
        *filter = json!({"bool":{"filter":restrictions}});
        return;
    }
    match value {
        Value::Object(o) => {
            for v in o.values_mut() {
                constrain_markers(v, p)
            }
        }
        Value::Array(a) => {
            for v in a {
                constrain_markers(v, p)
            }
        }
        _ => {}
    }
}
fn validate_fields(value: &Value, p: &Principal) -> Result<()> {
    if let Value::Object(o) = value {
        for (key, child) in o {
            if ["term", "terms", "wildcard", "range", "match", "exists"].contains(&key.as_str()) {
                let fields = if key == "exists" {
                    child
                        .get("field")
                        .and_then(Value::as_str)
                        .into_iter()
                        .collect::<Vec<_>>()
                } else {
                    child
                        .as_object()
                        .into_iter()
                        .flat_map(|o| o.keys().map(String::as_str))
                        .collect()
                };
                for field in fields {
                    let field = field.strip_suffix(".raw").unwrap_or(field);
                    if field.starts_with("tag") {
                        if !p.has("tags:read") || p.policy.tag_ids.is_empty() || field != "tag_ids"
                        {
                            return Err(ApiError::forbidden());
                        }
                        let ids = child
                            .get(field)
                            .map(|v| {
                                if let Some(a) = v.as_array() {
                                    a.clone()
                                } else {
                                    vec![v.clone()]
                                }
                            })
                            .unwrap_or_default();
                        if ids
                            .iter()
                            .any(|v| v.as_i64().is_none_or(|id| !p.policy.tag_ids.contains(&id)))
                        {
                            return Err(ApiError::forbidden());
                        }
                    } else if !p.policy.fields.iter().any(|f| {
                        f == if field.starts_with("web.") {
                            "web"
                        } else if field.starts_with("os.") {
                            "os"
                        } else {
                            field
                        }
                    }) && field != "domain"
                    {
                        return Err(ApiError::forbidden());
                    }
                }
            }
            validate_fields(child, p)?;
        }
    } else if let Value::Array(a) = value {
        for v in a {
            validate_fields(v, p)?;
        }
    }
    Ok(())
}
pub(crate) fn compile(q: &str, p: &Principal) -> Result<Value> {
    if q.len() > 2048 {
        return Err(ApiError::bad("搜索表达式最多 2048 字节"));
    }
    if q.trim().is_empty() {
        return Ok(json!({"match_all":{}}));
    }
    let compiled = parse_and_compile_elasticsearch(q)
        .map_err(|e| ApiError::bad(format!("{}（位置 {}–{}）", e.message, e.start, e.end)))?;
    let mut filter = match compiled {
        ElasticsearchCompilation::Supported(v)
        | ElasticsearchCompilation::RequiresElasticsearch(v) => v,
        _ => return Err(ApiError::bad("此表达式不支持当前查询路径")),
    };
    validate_fields(&filter, p)?;
    constrain_markers(&mut filter, p);
    Ok(filter)
}
pub(crate) async fn task_ids(pool: &Pool, p: &Principal) -> Result<Vec<String>> {
    let rows=pool.get().await?.query("SELECT t.task_id FROM scan_task t WHERE t.user_id=$1 AND ($2 OR t.api_client_id=$3) AND EXISTS(SELECT 1 FROM scan_task_execution e WHERE e.task_id=t.id AND e.execution_status='succeeded') AND ($4::BIGINT IS NULL OR t.task_end_time >= $4) AND ($5::BIGINT IS NULL OR t.task_end_time<$5) ORDER BY t.id DESC LIMIT 10001",&[&p.owner_id,&(p.policy.data_mode=="owner"),&p.client_pk,&p.policy.from_at,&p.policy.to_at]).await?;
    if rows.len() > 10000 {
        return Err(ApiError::new(
            actix_web::http::StatusCode::UNPROCESSABLE_ENTITY,
            "query_budget_exceeded",
            "授权任务集合超过 10000，请在策略中限定时间范围",
        ));
    }
    Ok(rows.iter().map(|r| r.get(0)).collect())
}
pub(crate) async fn execution_ids(pool: &Pool, p: &Principal) -> Result<Vec<String>> {
    let rows=pool.get().await?.query("SELECT e.execution_id FROM scan_task_execution e JOIN scan_task t ON t.id=e.task_id WHERE e.execution_status='succeeded' AND t.user_id=$1 AND ($2 OR t.api_client_id=$3) AND ($4::BIGINT IS NULL OR t.task_end_time>=$4) AND ($5::BIGINT IS NULL OR t.task_end_time<$5) ORDER BY e.id LIMIT 10001",&[&p.owner_id,&(p.policy.data_mode=="owner"),&p.client_pk,&p.policy.from_at,&p.policy.to_at]).await?;
    if rows.len() > 10000 {
        return Err(ApiError::bad("授权成功执行集合超过 10000，请限定时间范围"));
    }
    Ok(rows.iter().map(|r| r.get(0)).collect())
}
fn dns_scope(p: &Principal) -> Option<Value> {
    if p.policy.domains.is_empty() {
        return None;
    }
    Some(
        json!({"bool":{"should":p.policy.domains.iter().flat_map(|d|[json!({"term":{"dns.question.name":d}}),json!({"wildcard":{"dns.question.name":format!("*.{d}")}})]).collect::<Vec<_>>(),"minimum_should_match":1}}),
    )
}
pub(crate) async fn fact_filters(pool: &Pool, p: &Principal, s: &Search) -> Result<Vec<Value>> {
    let mut filters = vec![
        json!({"term":{"user_id":p.owner_id}}),
        json!({"terms":{"task_id":task_ids(pool,p).await?}}),
        json!({"terms":{"execution_id":execution_ids(pool,p).await?}}),
        p.policy.ip_filter("ip_address"),
    ];
    time_filter(&mut filters, p, s, "observed_at");
    if let Some(id) = s.execution_id {
        filters.push(json!({"term":{"execution_id":id.to_string()}}));
    }
    if let Some(id) = s.task_id {
        filters.push(json!({"term":{"task_id":id.to_string()}}));
    }
    Ok(filters)
}
pub(crate) fn time_filter(filters: &mut Vec<Value>, p: &Principal, s: &Search, field: &str) {
    let start = match (p.policy.from_at, s.start_at) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    let end = match (p.policy.to_at, s.end_at) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    let mut bounds = serde_json::Map::new();
    if let Some(v) = start {
        bounds.insert("gte".into(), json!(v));
    }
    if let Some(v) = end {
        bounds.insert("lt".into(), json!(v));
    }
    if !bounds.is_empty() {
        filters.push(json!({"range":{field:bounds}}));
    }
}
pub(crate) async fn dns(
    pool: &Pool,
    es: &ElasticsearchService,
    p: &Principal,
    domain: Option<&str>,
    s: &Search,
) -> Result<Value> {
    s.validate(p)?;
    if s.query.as_ref().is_some_and(|s| !s.trim().is_empty())
        || s.fields.is_some()
        || s.severity.is_some()
        || s.template_id.is_some()
    {
        return Err(ApiError::bad("DNS 观察只接受分页、时间和任务/执行条件"));
    }
    let mut filters = vec![json!({"terms":{"network_mapping.task_id":task_ids(pool,p).await?}})];
    filters.push(json!({"terms":{"network_mapping.execution_id":execution_ids(pool,p).await?}}));
    if let Some(id) = s.task_id {
        filters.push(json!({"term":{"network_mapping.task_id":id.to_string()}}));
    }
    if let Some(id) = s.execution_id {
        filters.push(json!({"term":{"network_mapping.execution_id":id.to_string()}}));
    }
    if let Some(domain) = domain {
        if !p.policy.allows_domain(domain) {
            return Err(ApiError::missing());
        }
        filters.push(json!({"term":{"dns.question.name":domain}}));
    }
    if !p.policy.domains.is_empty() {
        filters.push(json!({"bool":{"should":p.policy.domains.iter().flat_map(|d|[json!({"term":{"dns.question.name":d}}),json!({"wildcard":{"dns.question.name":format!("*.{d}")}})]).collect::<Vec<_>>(),"minimum_should_match":1}}));
    }
    time_filter(&mut filters, p, s, "@timestamp");
    let sort = json!([{"@timestamp":"desc"},{"event_id":"asc"}]);
    let body = json!({"size":s.size()?+1,"track_total_hits":false,"query":{"bool":{"filter":filters}},"sort":sort});
    let result = paged(pool, es, p, s, body, true).await?;
    let items=result["items"].as_array().unwrap_or(&vec![]).iter().map(|v| {
        let mut dns=v.get("dns").cloned().unwrap_or_else(||json!({}));
        // A domain grant does not grant every co-hosted address. Address exclusions are
        // enforced on response records as well as on follow-up scan creation.
        for section in ["answers","authority","additional"] {
            if let Some(records)=dns.get_mut(section).and_then(Value::as_array_mut){records.retain(|r|r.get("ip").or_else(||r.get("value")).and_then(Value::as_str).and_then(|s|s.parse().ok()).is_none_or(|ip|p.policy.allows_ip(ip)));}
        }
        json!({"id":v["event_id"],"observed_at":v["@timestamp"],"dns":dns,"resolver_id":v.pointer("/resolver/id"),"resolver_label":v.pointer("/resolver/label"),"latency_ms":v["latency_ms"]})
    }).collect::<Vec<_>>();
    Ok(
        json!({"items":items,"next_cursor":result["next_cursor"],"semantics":"observations_from_authorized_successful_executions"}),
    )
}
async fn resolve_domains(
    pool: &Pool,
    es: &ElasticsearchService,
    p: &Principal,
    filter: Value,
) -> Result<Value> {
    let mut markers = Vec::new();
    crate::elasticsearch::collect_domain_filters(&filter, &mut markers);
    if markers.is_empty() {
        return Ok(filter);
    }
    if !p.has("dns:read") {
        return Err(ApiError::forbidden());
    }
    let ids = task_ids(pool, p).await?;
    let mut replacements = Vec::new();
    for marker in markers {
        let operator = marker["operator"]
            .as_str()
            .ok_or_else(|| ApiError::bad("域名条件无效"))?;
        let values = marker["values"]
            .as_array()
            .ok_or_else(|| ApiError::bad("域名条件无效"))?;
        let mut addresses = BTreeSet::new();
        for value in values {
            let domain = model::normalize_domain(
                value
                    .as_str()
                    .ok_or_else(|| ApiError::bad("域名条件无效"))?,
            )?;
            if !p.policy.allows_domain(&domain) {
                return Err(ApiError::forbidden());
            }
            let name = if matches!(operator, "contains" | "not_contains") {
                json!({"wildcard":{"dns.question.name":format!("*{domain}*")}})
            } else {
                json!({"term":{"dns.question.name":domain}})
            };
            let mut filters = vec![
                json!({"terms":{"network_mapping.task_id":ids}}),
                name,
                json!({"term":{"dns.response_code":"NOERROR"}}),
            ];
            filters.push(
                json!({"terms":{"network_mapping.execution_id":execution_ids(pool,p).await?}}),
            );
            if let Some(scope) = dns_scope(p) {
                filters.push(scope);
            }
            time_filter(&mut filters, p, &Search::default(), "@timestamp");
            let r=es.open_api_dns_query(&json!({"size":1000,"track_total_hits":true,"query":{"bool":{"filter":filters}}})).await.map_err(|_|ApiError::unavailable())?;
            if r.pointer("/hits/total/value")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                > 1000
            {
                return Err(ApiError::bad("域名观察超过查询预算，请缩小范围"));
            }
            for h in r
                .pointer("/hits/hits")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                for record in h
                    .pointer("/_source/dns/answers")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(ip) = record
                        .get("ip")
                        .and_then(Value::as_str)
                        .or_else(|| record.get("value").and_then(Value::as_str))
                        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                        && p.policy.allows_ip(ip)
                    {
                        addresses.insert(ip.to_string());
                    }
                }
            }
        }
        let positive = json!({"terms":{"ip":addresses.into_iter().collect::<Vec<_>>()}});
        replacements.push(
            if matches!(operator, "not_eq" | "not_contains" | "not_in") {
                json!({"bool":{"must_not":[positive]}})
            } else {
                positive
            },
        );
    }
    Ok(crate::elasticsearch::replace_domain_filters(
        filter,
        &mut replacements.into_iter(),
    ))
}
pub(crate) async fn endpoints(
    pool: &Pool,
    es: &ElasticsearchService,
    p: &Principal,
    s: &Search,
    extra: Vec<Value>,
) -> Result<Value> {
    s.validate(p)?;
    if s.execution_id.is_some()
        || s.task_id.is_some()
        || s.severity.is_some()
        || s.template_id.is_some()
    {
        return Err(ApiError::bad("资产投影查询不接受任务、执行或漏洞条件"));
    }
    let filter = compile(s.query.as_deref().unwrap_or(""), p)?;
    let filter = resolve_domains(pool, es, p, filter).await?;
    let (scope, id) = p.scope();
    let filter = es
        .open_api_endpoint_filter(scope, id, filter)
        .await
        .map_err(|_| ApiError::unavailable())?;
    let mut filters = vec![
        json!({"term":{"scope_type":scope}}),
        json!({"term":{"scope_id":id}}),
        p.policy.ip_filter("ip"),
        filter,
    ];
    time_filter(&mut filters, p, s, "last_seen");
    filters.extend(extra);
    let body = json!({"size":s.size()?+1,"track_total_hits":false,"query":{"bool":{"filter":filters}},"sort":[{"last_seen":"desc"},{"ip":"asc"},{"port":"asc"},{"endpoint_key":"asc"}],"_source":{"excludes":["http_body","data"]}});
    let result = paged(pool, es, p, s, body, false).await?;
    Ok(
        json!({"items":result["items"].as_array().into_iter().flatten().map(|v|p.project_endpoint(v,s.fields.as_ref())).collect::<Vec<_>>(),"next_cursor":result["next_cursor"],"consistency":"live_projection","total_relation":"not_computed"}),
    )
}
pub(crate) async fn facts(
    pool: &Pool,
    es: &ElasticsearchService,
    p: &Principal,
    s: &Search,
    extra: Vec<Value>,
) -> Result<Value> {
    s.validate(p)?;
    if s.query.as_ref().is_some_and(|s| !s.trim().is_empty()) || s.fields.is_some() {
        return Err(ApiError::bad(
            "观察查询使用时间和任务/执行条件，不接受资产 DSL 或 fields",
        ));
    }
    let mut filters = fact_filters(pool, p, s).await?;
    filters.extend(extra);
    let body = json!({"size":s.size()?+1,"track_total_hits":false,"query":{"bool":{"filter":filters}},"sort":[{"observed_at":"desc"},{"execution_id":"asc"},{"observation_key":"asc"}]});
    paged_index(pool, es, p, s, body, ScanQueryIndex::Observations).await
}
async fn paged(
    pool: &Pool,
    es: &ElasticsearchService,
    p: &Principal,
    s: &Search,
    body: Value,
    dns: bool,
) -> Result<Value> {
    if dns {
        page_impl(pool, es, p, s, body, None).await
    } else {
        paged_index(pool, es, p, s, body, ScanQueryIndex::CurrentEndpoints).await
    }
}
async fn paged_index(
    pool: &Pool,
    es: &ElasticsearchService,
    p: &Principal,
    s: &Search,
    body: Value,
    index: ScanQueryIndex,
) -> Result<Value> {
    page_impl(pool, es, p, s, body, Some(index)).await
}
async fn page_impl(
    pool: &Pool,
    es: &ElasticsearchService,
    p: &Principal,
    s: &Search,
    mut body: Value,
    index: Option<ScanQueryIndex>,
) -> Result<Value> {
    let mut query_spec = s.clone();
    query_spec.cursor = None;
    let hash = model::fingerprint(
        serde_json::to_string(
            &json!({"body":body,"query_spec":query_spec,"index":format!("{index:?}")}),
        )
        .map_err(|_| ApiError::bad("查询格式无效"))?
        .as_bytes(),
    );
    if let Some(cursor) = s.cursor {
        let row=pool.get().await?.query_opt("SELECT after_value FROM api_cursor WHERE id=$1 AND client_id=$2 AND credential_id=$3 AND policy_revision=$4 AND query_hash=$5 AND expires_at>NOW()",&[&cursor,&p.client_pk,&p.credential_id,&p.revision,&hash]).await?.ok_or_else(||ApiError::bad("游标失效或与当前查询不匹配"))?;
        body["search_after"] = row.get::<_, Value>(0);
    }
    body["timeout"] = json!("3s");
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        match index {
            Some(i) => es.scan_query(i, &body).await,
            None => es.open_api_dns_query(&body).await,
        }
    })
    .await
    .map_err(|_| ApiError::unavailable())?
    .map_err(|_| ApiError::unavailable())?;
    crate::elasticsearch::validate_scan_search_response(&result)
        .map_err(|_| ApiError::unavailable())?;
    let hits = result
        .pointer("/hits/hits")
        .and_then(Value::as_array)
        .ok_or_else(ApiError::unavailable)?;
    let size = s.size()?;
    let mut next = None;
    if hits.len() > size {
        let after = hits[size - 1]
            .get("sort")
            .ok_or_else(ApiError::unavailable)?;
        let id = Uuid::new_v4();
        pool.get().await?.execute("INSERT INTO api_cursor(id,client_id,credential_id,policy_revision,query_hash,after_value) VALUES($1,$2,$3,$4,$5,$6)",&[&id,&p.client_pk,&p.credential_id,&p.revision,&hash,after]).await?;
        next = Some(id);
    }
    Ok(
        json!({"items":hits.iter().take(size).filter_map(|h|h.get("_source")).cloned().collect::<Vec<_>>(),"next_cursor":next}),
    )
}
