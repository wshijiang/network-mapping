use super::{
    ApiError, Principal, Result, analytics, auth,
    catalog::Endpoint,
    console, model,
    query::{self, Search},
    resources, tasks,
};
use crate::elasticsearch::ElasticsearchService;
use actix_web::{HttpRequest, HttpResponse, web};
use deadpool_postgres::Pool;
use serde_json::{Value, json};
use std::{collections::HashMap, net::IpAddr};

pub(crate) fn search(req: &HttpRequest, v: &Value) -> Result<Search> {
    if req.method().as_str() == "GET" {
        let q = web::Query::<HashMap<String, String>>::from_query(req.query_string())
            .map_err(|_| ApiError::bad("查询参数无效"))?;
        let mut object = serde_json::Map::new();
        for (key, value) in q.iter() {
            let value = if key == "page_size" {
                json!(
                    value
                        .parse::<i64>()
                        .map_err(|_| ApiError::bad("数字查询参数无效"))?
                )
            } else if key == "fields" {
                json!(value.split(',').collect::<Vec<_>>())
            } else if matches!(key.as_str(), "start_at" | "end_at") {
                value
                    .parse::<i64>()
                    .map(|n| json!(n))
                    .unwrap_or_else(|_| json!(value))
            } else {
                json!(value)
            };
            object.insert(key.clone(), value);
        }
        serde_json::from_value(Value::Object(object)).map_err(|_| ApiError::bad("不支持的查询参数"))
    } else {
        serde_json::from_value(v.clone())
            .map_err(|_| ApiError::bad("查询参数无效或含有不支持的字段"))
    }
}
pub(crate) async fn dispatch(
    req: &HttpRequest,
    body: &[u8],
    pool: &Pool,
    es: &ElasticsearchService,
    p: &Principal,
    e: &Endpoint,
) -> Result<Value> {
    dispatch_at(
        req,
        body,
        pool,
        es,
        p,
        e,
        req.match_info().get("tail").unwrap_or(""),
    )
    .await
}
pub(crate) async fn dispatch_at(
    req: &HttpRequest,
    body: &[u8],
    pool: &Pool,
    es: &ElasticsearchService,
    p: &Principal,
    e: &Endpoint,
    path: &str,
) -> Result<Value> {
    let v = console::json_body(body)?;
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match e.path {
        "/capabilities" => Ok(
            json!({"api_version":"v1","endpoints":super::catalog::ENDPOINTS.iter().filter(|e|p.has(e.scope)&&super::contract::additional_scopes(e).iter().all(|scope|p.has(scope))).collect::<Vec<_>>(),"user_management":false}),
        ),
        "/me" => Ok(
            json!({"client_id":p.client_id,"name":p.name,"environment":p.environment,"credential_id":p.credential_id,"expires_at":p.expires_at,"policy_revision":p.revision}),
        ),
        "/me/scopes" => Ok(
            json!({"scopes":p.scopes.iter().filter(|s|p.has(s)).collect::<Vec<_>>(),"fields":p.policy.fields,"data_mode":p.policy.data_mode,"cidrs":p.policy.cidrs,"domains":p.policy.domains,"excluded_cidrs":p.policy.excluded_cidrs,"from_at":p.policy.from_at,"to_at":p.policy.to_at}),
        ),
        "/me/quotas" => Ok(json!(p.policy)),
        "/me/usage" => {
            let rows=pool.get().await?.query("SELECT category,bucket_start,units FROM api_usage_bucket WHERE client_id=$1 AND bucket_start>NOW()-INTERVAL '31 days' ORDER BY bucket_start DESC LIMIT 500",&[&p.client_pk]).await?;
            Ok(
                json!({"items":rows.iter().map(|r|json!({"category":r.get::<_,String>(0),"bucket_start":r.get::<_,chrono::DateTime<chrono::Utc>>(1),"units":r.get::<_,i64>(2)})).collect::<Vec<_>>()}),
            )
        }
        "/service-status" => Ok(
            json!({"available":es.can_read(),"business_timezone":crate::system_time::timezone().name()}),
        ),
        "/catalog/search-fields" => Ok(
            json!({"fields":p.policy.fields,"operators":["AND","OR","NOT","IN","EXISTS","has_endpoint"],"domain_search":p.has("dns:read"),"tag_search":"tag_id only; approved tag IDs"}),
        ),
        "/catalog/scan-profiles" => {
            Ok(json!({"profiles":p.policy.profiles,"can_create":p.has("tasks:create")}))
        }
        "/catalog/dns-resolvers" => {
            let runtime = req
                .app_data::<web::Data<crate::runtime_config::RuntimeSettings>>()
                .ok_or_else(ApiError::unavailable)?;
            let settings = runtime.dns_resolvers.get().await;
            Ok(
                json!({"items":settings.value.resolvers.iter().filter(|r|r.enabled).map(|r|json!({"id":r.id,"label":r.label})).collect::<Vec<_>>(),"selection":"platform-managed"}),
            )
        }
        "/catalog/statistics" => Ok(analytics::catalog()),
        "/assets/search/validate" => {
            console::allowed_keys(&v, &["query"])?;
            let q = console::text(&v, "query", 2048)?;
            query::compile(&q, p)?;
            Ok(json!({"valid":true}))
        }
        "/assets/search" => {
            auth::category_quota(
                pool,
                p,
                "search.minute",
                p.policy.searches_per_minute,
                false,
            )
            .await?;
            query::endpoints(pool, es, p, &search(req, &v)?, vec![]).await
        }
        "/assets/lookup" => {
            console::allowed_keys(&v, &["ips", "fields", "page_size", "cursor"])?;
            let ips: Vec<String> = serde_json::from_value(v["ips"].clone())
                .map_err(|_| ApiError::bad("ips 必须为 IP 列表"))?;
            if ips.is_empty() || ips.len() > 100 {
                return Err(ApiError::bad("每次可查询 1–100 个 IP"));
            }
            let mut normalized = Vec::new();
            for ip in ips {
                let ip = ip
                    .parse::<IpAddr>()
                    .map_err(|_| ApiError::bad("IP 格式无效"))?;
                if p.policy.allows_ip(ip) {
                    normalized.push(ip.to_string());
                }
            }
            let fields = v
                .get("fields")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| ApiError::bad("字段格式无效"))?;
            query::endpoints(
                pool,
                es,
                p,
                &Search {
                    fields,
                    page_size: v
                        .get("page_size")
                        .map(|v| serde_json::from_value(v.clone()))
                        .transpose()
                        .map_err(|_| ApiError::bad("page_size 无效"))?,
                    cursor: v
                        .get("cursor")
                        .map(|v| serde_json::from_value(v.clone()))
                        .transpose()
                        .map_err(|_| ApiError::bad("cursor 无效"))?,
                    ..Search::default()
                },
                vec![json!({"terms":{"ip":normalized}})],
            )
            .await
        }
        "/tags" | "/tag-categories" => {
            let rows=pool.get().await?.query("SELECT t.id,t.name,t.kind,t.description,c.id AS category_id,c.name AS category_name FROM asset_tag t JOIN asset_tag_category c ON c.id=t.category_id WHERE t.is_active AND c.is_active AND t.id=ANY($1) ORDER BY t.id",&[&p.policy.tag_ids]).await?;
            let items = if e.path == "/tags" {
                rows.iter().map(|r|json!({"id":r.get::<_,i64>("id"),"name":r.get::<_,String>("name"),"kind":r.get::<_,String>("kind"),"description":r.get::<_,Option<String>>("description"),"category_id":r.get::<_,i64>("category_id"),"category_name":r.get::<_,String>("category_name")})).collect::<Vec<_>>()
            } else {
                let mut seen = std::collections::BTreeSet::new();
                rows.iter().filter(|r|seen.insert(r.get::<_,i64>("category_id"))).map(|r|json!({"id":r.get::<_,i64>("category_id"),"name":r.get::<_,String>("category_name")})).collect()
            };
            Ok(json!({"items":items}))
        }
        "/domains/lookup" => {
            console::allowed_keys(&v, &["domains"])?;
            let domains: Vec<String> = serde_json::from_value(v["domains"].clone())
                .map_err(|_| ApiError::bad("domains 格式无效"))?;
            if domains.is_empty() || domains.len() > 20 {
                return Err(ApiError::bad("批量域名查询上限 20"));
            }
            let mut items = Vec::new();
            for domain in domains {
                let d = model::normalize_domain(&domain)?;
                let data = query::dns(pool, es, p, Some(&d), &Search::default()).await?;
                items.push(json!({"domain":d,"data":data}));
            }
            Ok(json!({"items":items}))
        }
        path if path.starts_with("/domains/") => {
            let d = model::normalize_domain(parts[1])?;
            let mut data = query::dns(pool, es, p, Some(&d), &search(req, &v)?).await?;
            if matches!(
                e.path,
                "/domains/{domain}/records"
                    | "/domains/{domain}/addresses"
                    | "/domains/{domain}/related-domains"
            ) {
                let mut records = Vec::new();
                let mut unique = std::collections::BTreeSet::new();
                for item in data["items"].as_array().into_iter().flatten() {
                    if item.pointer("/dns/response_code").and_then(Value::as_str) != Some("NOERROR")
                    {
                        continue;
                    }
                    for record in item
                        .pointer("/dns/answers")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let record = if e.path.ends_with("/addresses") {
                            record
                                .get("ip")
                                .or_else(|| record.get("value"))
                                .filter(|v| {
                                    v.as_str().and_then(|s| s.parse::<IpAddr>().ok()).is_some()
                                })
                                .cloned()
                        } else if e.path.ends_with("/related-domains") {
                            record
                                .get("target_domain")
                                .or_else(|| record.get("target"))
                                .or_else(|| {
                                    if matches!(
                                        record.get("type").and_then(Value::as_str),
                                        Some("CNAME" | "NS" | "MX" | "PTR" | "SRV")
                                    ) {
                                        record.get("value")
                                    } else {
                                        None
                                    }
                                })
                                .filter(|v| {
                                    v.as_str()
                                        .is_some_and(|s| model::normalize_domain(s).is_ok())
                                })
                                .cloned()
                        } else {
                            Some(record.clone())
                        };
                        if let Some(r) = record
                            && unique.insert(r.to_string())
                        {
                            records.push(r);
                        }
                    }
                }
                data["items"] = json!(records);
                data["semantics"] =
                    json!("records_in_returned_observations; absence_does_not_mean_inactive");
            }
            Ok(data)
        }
        path if path.starts_with("/tasks") => {
            tasks::dispatch(req, pool, es, p, e, &parts, &v).await
        }
        path if path.starts_with("/analytics") => {
            analytics::dispatch(req, pool, es, p, e, &v).await
        }
        path if path.starts_with("/vulnerabilities") => {
            vulnerabilities(req, pool, es, p, e, None, &parts, &v).await
        }
        path if path.starts_with("/assets/") => {
            let ip = parts[1]
                .parse::<IpAddr>()
                .map_err(|_| ApiError::missing())?;
            if !p.policy.allows_ip(ip) {
                return Err(ApiError::missing());
            }
            let ip = ip.to_string();
            match e.path {
                "/assets/{ip}/refresh" => {
                    if !p.has("tasks:create") {
                        return Err(ApiError::forbidden());
                    }
                    let mut input = v.clone();
                    input["targets"] = json!([ip]);
                    tasks::create(req, pool, p, &input, None).await
                }
                "/assets/{ip}/observations" | "/assets/{ip}/ports/{port}/history" => {
                    let mut filters = vec![json!({"term":{"ip_address":ip}})];
                    if e.path.ends_with("/history") {
                        let port = parts[3].parse::<u16>().map_err(|_| ApiError::missing())?;
                        if port == 0 {
                            return Err(ApiError::missing());
                        }
                        filters.push(json!({"term":{"port":port}}));
                    }
                    let result = query::facts(pool, es, p, &search(req, &v)?, filters).await?;
                    Ok(project_facts(p, result, false))
                }
                "/assets/{ip}/vulnerabilities" => {
                    vulnerabilities(req, pool, es, p, e, Some(&ip), &parts, &v).await
                }
                path if path.contains("/annotations") => {
                    resources::annotations(req, pool, es, p, e, &parts, &v, &ip).await
                }
                _ => {
                    let mut s = search(req, &v)?;
                    if e.path.ends_with("/tags") {
                        s.fields = Some(vec!["tags".into()]);
                    } else if e.path.ends_with("/services") || e.path.ends_with("/tls") {
                        let fields: &[&str] = if e.path.ends_with("/services") {
                            &[
                                "ip",
                                "port",
                                "protocol",
                                "service",
                                "title",
                                "banner",
                                "os",
                                "service_observed_at_ms",
                            ]
                        } else {
                            &[
                                "ip",
                                "port",
                                "protocol",
                                "tls_mode",
                                "tls_version",
                                "tls_cipher_suite",
                                "tls_subject",
                                "tls_issuer",
                                "tls_names",
                                "tls_serial_number",
                                "tls_not_before",
                                "tls_not_after",
                                "tls_fingerprint_sha256",
                                "tls_self_signed",
                            ]
                        };
                        s.fields = Some(
                            fields
                                .iter()
                                .filter(|field| p.policy.fields.iter().any(|f| f == **field))
                                .map(|f| (*f).to_owned())
                                .collect(),
                        );
                    }
                    let data =
                        query::endpoints(pool, es, p, &s, vec![json!({"term":{"ip":ip}})]).await?;
                    if data["items"].as_array().is_none_or(|a| a.is_empty()) {
                        return Err(ApiError::missing());
                    }
                    if e.path == "/assets/{ip}" {
                        Ok(
                            json!({"ip":ip,"endpoints":data["items"],"next_cursor":data["next_cursor"],"state_semantics":"observed_open; absence_is_not_closed"}),
                        )
                    } else if e.path.ends_with("/tags") {
                        let mut unique = std::collections::BTreeSet::new();
                        let tags: Vec<_> = data["items"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .flat_map(|v| v["tags"].as_array().into_iter().flatten())
                            .filter(|tag| unique.insert(tag.to_string()))
                            .cloned()
                            .collect();
                        Ok(json!({"items":tags,"next_cursor":data["next_cursor"]}))
                    } else {
                        Ok(data)
                    }
                }
            }
        }
        _ => resources::dispatch(req, pool, es, p, e, &parts, &v).await,
    }
}
pub(crate) fn project_facts(p: &Principal, mut result: Value, vulnerability: bool) -> Value {
    let items=result["items"].as_array().into_iter().flatten().map(|source| {
        let mut endpoint=source.clone();endpoint["ip"]=source["ip_address"].clone();let mut out=p.project_endpoint(&endpoint,None);
        out["kind"]=source["kind"].clone();out["observed_at"]=source["observed_at"].clone();out["task_id"]=source["task_id"].clone();out["execution_id"]=source["execution_id"].clone();
        if vulnerability {
            let data=source.get("data").unwrap_or(&Value::Null);
            for key in ["template_id","name","severity","description","remediation","tags","references","classification"] {if let Some(value)=data.get(key){out[key]=value.clone();}}
            let locator=json!({"execution_id":source["execution_id"],"observation_key":source["observation_key"]});
            out["finding_id"]=json!(openssl::base64::encode_block(locator.to_string().as_bytes()).replace('+',"-").replace('/',"_").trim_end_matches('='));
            if p.has("vulnerabilities:evidence"){for key in ["matcher_name","matched_at","extracted_results"] {if let Some(value)=data.get(key){out[key]=value.clone();}}}
            out["verification_status"]=json!("scanner_observation");
        }
        out
    }).collect::<Vec<_>>();
    result["items"] = json!(items);
    result
}
#[allow(clippy::too_many_arguments)]
pub(crate) async fn vulnerabilities(
    req: &HttpRequest,
    pool: &Pool,
    es: &ElasticsearchService,
    p: &Principal,
    e: &Endpoint,
    ip: Option<&str>,
    parts: &[&str],
    v: &Value,
) -> Result<Value> {
    if e.path == "/vulnerabilities/summary" {
        return analytics::vulnerability_summary(pool, es, p, &search(req, v)?).await;
    }
    let s = search(req, v)?;
    let mut filters = vec![json!({"term":{"kind":"vulnerability"}})];
    if let Some(ip) = ip {
        filters.push(json!({"term":{"ip_address":ip}}));
    }
    if e.path == "/tasks/{task_id}/vulnerabilities" {
        filters.push(json!({"term":{"task_id":parts[1]}}));
    }
    if let Some(severity) = &s.severity
        && !["info", "low", "medium", "high", "critical"].contains(&severity.as_str())
    {
        return Err(ApiError::bad("严重程度无效"));
    }
    if e.path == "/vulnerabilities/{finding_id}" {
        let id = parts[1];
        if id.len() > 2048 {
            return Err(ApiError::missing());
        }
        let mut encoded = id.replace('-', "+").replace('_', "/");
        while !encoded.len().is_multiple_of(4) {
            encoded.push('=');
        }
        let decoded = openssl::base64::decode_block(&encoded).map_err(|_| ApiError::missing())?;
        let locator: Value = serde_json::from_slice(&decoded).map_err(|_| ApiError::missing())?;
        if !locator["execution_id"].is_string() || !locator["observation_key"].is_string() {
            return Err(ApiError::missing());
        }
        filters.extend([
            json!({"term":{"execution_id":locator["execution_id"]}}),
            json!({"term":{"observation_key":locator["observation_key"]}}),
        ]);
    }
    let mut result = project_facts(p, query::facts(pool, es, p, &s, filters).await?, true);
    if let Some(items) = result["items"].as_array_mut() {
        items.retain(|v| {
            s.severity
                .as_ref()
                .is_none_or(|x| v["severity"].as_str() == Some(x))
                && s.template_id
                    .as_ref()
                    .is_none_or(|x| v["template_id"].as_str() == Some(x))
        });
    }
    if e.path == "/vulnerabilities/{finding_id}"
        && result["items"].as_array().is_none_or(|a| a.is_empty())
    {
        return Err(ApiError::missing());
    }
    Ok(result)
}
pub(crate) fn download_response(req: &HttpRequest, value: &Value) -> Option<HttpResponse> {
    let d = value.get("_download")?;
    let bytes = openssl::base64::decode_block(d["base64"].as_str()?).ok()?;
    let filename = d["filename"].as_str()?;
    if !filename
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return None;
    }
    Some(
        HttpResponse::Ok()
            .insert_header(("Cache-Control", "private, no-store"))
            .insert_header(("X-Request-ID", super::request_id(req).to_string()))
            .insert_header(("X-Content-SHA256", model::fingerprint(&bytes)))
            .insert_header((
                "Content-Disposition",
                format!("attachment; filename=\"{filename}\""),
            ))
            .content_type(d["content_type"].as_str()?.to_string())
            .body(bytes),
    )
}
