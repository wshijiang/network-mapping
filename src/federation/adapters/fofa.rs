//! FOFA（fofa.info，v5.5.19）。
//!
//! 官方文档核实 2026-11-16（官方页面渲染 + 资源包原文 + 用户保存页面）：
//! GET /api/v1/search/all?key&qbase64(标准base64)&fields&page&size&full&r_type。
//! key-only 认证（email 旧参数可选兼容）；results 为按 fields 顺序的二维数组；
//! error:true + errmsg；403 = IP 永久封禁；lastupdatetime/product 需专业版及以上；
//! after/before 时间语法需个人版及以上；size 上限：含 body 查询 500、含 cert/banner 2000。

use serde_json::{Map, Value, json};

use crate::data_import::csv::TechEntry;
use crate::federation::adapters::{
    FederationAdapter, SearchRequest, base64_standard, parse_cn_datetime, parse_port_value,
    resolve_observed_at, response_json, string_field, transport_error, window_dates_cn,
};
use crate::federation::model::{
    Capabilities, FieldSelection, NormalizedRecord, RawPage, SourceError, SourceKind,
    TimeFilterMode, clean_text, normalize_asn, normalize_service, normalize_tech_id,
};

const BASE: &str = "https://fofa.info";

pub struct Fofa;

fn key(credential: &Value) -> Result<&str, SourceError> {
    credential
        .get("key")
        .and_then(Value::as_str)
        .filter(|k| !k.is_empty())
        .ok_or(SourceError::permanent("auth_failed"))
}

/// 已选字段 → fields 列表（顺序即 results 列序）。
fn fofa_fields(fields: &FieldSelection) -> Vec<String> {
    let mut list: Vec<String> = [
        "ip",
        "port",
        "protocol",
        "base_protocol",
        "lastupdatetime",
        "asn",
        "org",
        "region",
        "city",
        "longitude",
        "latitude",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    if fields.domain {
        list.push("host".into());
        list.push("domain".into());
    }
    if fields.title {
        list.push("title".into());
    }
    if fields.banner {
        list.push("banner".into());
    }
    if fields.tech {
        list.push("product".into());
    }
    list
}

/// 降级字段（免费/个人账号无 lastupdatetime/product 权限时重试）。
pub fn basic_fields(fields: &FieldSelection) -> Vec<String> {
    fofa_fields(fields)
        .into_iter()
        .filter(|f| f != "lastupdatetime" && f != "product")
        .collect()
}

/// 查询含 body → size≤500；含 cert/banner → size≤2000（官方脚注）。
fn clamp_size(query: &str, size: u32) -> u32 {
    if query.contains("body=") || query.contains("body =") {
        size.min(500)
    } else if query.contains("cert=") || query.contains("banner=") {
        size.min(2000)
    } else {
        size.min(10_000)
    }
}

fn classify_errmsg(errmsg: &str) -> SourceError {
    let lower = errmsg.to_ascii_lowercase();
    if lower.contains("key") || lower.contains("email") || lower.contains("token") {
        SourceError::permanent("auth_failed")
    } else if lower.contains("频繁") || lower.contains("rate") || lower.contains("limit") {
        SourceError::transient("rate_limited")
    } else if lower.contains("f点") || lower.contains("point") || lower.contains("额度") {
        SourceError::permanent("quota_exhausted")
    } else {
        SourceError::permanent("query_rejected")
    }
}

impl FederationAdapter for Fofa {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            default_qps: 1.0,
            max_page_size: 1000,
            page_size_choices: None,
            time_filter: TimeFilterMode::NativeSyntax,
            single_ip_free_endpoint: false,
        }
    }

    async fn search(
        &self,
        client: &reqwest::Client,
        credential: &Value,
        request: &SearchRequest<'_>,
    ) -> Result<RawPage, SourceError> {
        let api_key = key(credential)?;
        let fields = request
            .field_override
            .clone()
            .unwrap_or_else(|| fofa_fields(request.fields));
        let mut query_text = request.query.text.clone();
        if let Some(days) = request.window_days {
            let (start, end) = window_dates_cn(days);
            query_text = format!(
                "({}) && after=\"{}\" && before=\"{}\"",
                query_text, start, end
            );
        }
        let size = clamp_size(&query_text, request.page.size);
        let mut params = vec![
            ("key", api_key.to_owned()),
            ("qbase64", base64_standard(&query_text)),
            ("fields", fields.join(",")),
            ("page", (request.page.index + 1).to_string()),
            ("size", size.to_string()),
            ("full", "false".to_owned()),
            ("r_type", "json".to_owned()),
        ];
        if let Some(email) = credential.get("email").and_then(Value::as_str)
            && !email.is_empty()
        {
            params.push(("email", email.to_owned()));
        }
        let response = client
            .get(format!("{BASE}/api/v1/search/all"))
            .query(&params)
            .send()
            .await
            .map_err(|e| transport_error(&e))?;
        let status = response.status();
        if status == reqwest::StatusCode::FORBIDDEN {
            // 官方：请求过频致 IP 永久封禁，不重试。
            return Err(SourceError::permanent("ip_banned"));
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(SourceError::transient("rate_limited"));
        }
        let body = response_json(response).await?;
        if body.get("error").and_then(Value::as_bool).unwrap_or(false) {
            let errmsg = body
                .get("errmsg")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            return Err(classify_errmsg(errmsg));
        }
        // results 二维数组 → 按 fields 顺序转为对象，供 normalize 使用。
        let rows = body
            .get("results")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let records = rows
            .into_iter()
            .map(|row| {
                let mut object = Map::new();
                if let Some(values) = row.as_array() {
                    for (index, field) in fields.iter().enumerate() {
                        object.insert(
                            field.clone(),
                            values.get(index).cloned().unwrap_or(Value::Null),
                        );
                    }
                }
                Value::Object(object)
            })
            .collect();
        let quota = json!({
            "consumed_fpoint": body.get("consumed_fpoint").cloned().unwrap_or(Value::Null),
            "required_fpoints": body.get("required_fpoints").cloned().unwrap_or(Value::Null),
        });
        Ok(RawPage {
            records,
            total: body.get("size").and_then(Value::as_i64),
            quota: Some(quota),
            prompt: None,
        })
    }

    fn normalize(
        &self,
        raw: &Value,
        fields: &FieldSelection,
        now_ms: i64,
        future_tolerance_ms: i64,
    ) -> Option<NormalizedRecord> {
        let ip = string_field(raw, "ip")?;
        ip.parse::<std::net::IpAddr>().ok()?;
        let port = parse_port_value(raw.get("port")?)?;
        if port == 0 {
            return None;
        }
        let service = if fields.service {
            string_field(raw, "protocol").and_then(|s| normalize_service(&s))
        } else {
            None
        };
        let protocol = string_field(raw, "base_protocol")
            .map(|p| p.to_ascii_lowercase())
            .filter(|p| p == "tcp" || p == "udp")
            .unwrap_or_else(|| crate::federation::model::infer_protocol(service.as_deref(), None));
        let tech = if fields.tech {
            string_field(raw, "product")
                .and_then(|p| normalize_tech_id(&p))
                .map(|id| vec![TechEntry { id, version: None }])
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let (observed_at, timestamp_inferred) = resolve_observed_at(
            string_field(raw, "lastupdatetime")
                .as_deref()
                .and_then(parse_cn_datetime),
            now_ms,
            future_tolerance_ms,
        );
        let domain = if fields.domain {
            string_field(raw, "domain")
                .or_else(|| string_field(raw, "host"))
                .and_then(|d| {
                    // host 可能是 URL 或 host:port，提取主机名部分。
                    let d = d.trim();
                    let d = d
                        .strip_prefix("https://")
                        .or_else(|| d.strip_prefix("http://"))
                        .unwrap_or(d);
                    let d = d.split('/').next().unwrap_or(d);
                    let d = d.rsplit_once(':').map(|(h, _)| h).unwrap_or(d);
                    clean_text(&d.to_ascii_lowercase(), 253)
                })
        } else {
            None
        };
        Some(NormalizedRecord {
            ip,
            port,
            protocol,
            domain,
            service,
            tech,
            title: if fields.title {
                string_field(raw, "title").and_then(|t| clean_text(&t, 512))
            } else {
                None
            },
            banner: if fields.banner {
                string_field(raw, "banner").and_then(|b| clean_text(&b, 64 * 1024))
            } else {
                None
            },
            observed_at,
            timestamp_inferred,
            asn: string_field(raw, "asn").and_then(|s| normalize_asn(&s)),
            as_org: string_field(raw, "org").and_then(|v| clean_text(&v, 256)),
            isp: None,
            country_name: None,
            region_name: string_field(raw, "region").and_then(|v| clean_text(&v, 128)),
            city_name: string_field(raw, "city").and_then(|v| clean_text(&v, 128)),
            latitude: raw.get("latitude").and_then(Value::as_f64),
            longitude: raw.get("longitude").and_then(Value::as_f64),
            sources: vec![SourceKind::Fofa.as_str().to_owned()],
        })
    }

    async fn probe(
        &self,
        client: &reqwest::Client,
        credential: &Value,
    ) -> Result<Value, SourceError> {
        let api_key = key(credential)?;
        let response = client
            .get(format!("{BASE}/api/v1/info/my"))
            .query(&[("key", api_key)])
            .send()
            .await
            .map_err(|e| transport_error(&e))?;
        if response.status() == reqwest::StatusCode::FORBIDDEN {
            return Err(SourceError::permanent("ip_banned"));
        }
        let body = response_json(response).await?;
        if body.get("error").and_then(Value::as_bool).unwrap_or(false) {
            return Err(SourceError::permanent("auth_failed"));
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_zipped_row() {
        let raw = json!({
            "ip": "172.67.213.134", "port": "443", "protocol": "https",
            "base_protocol": "tcp", "host": "https://bingchillin.org",
            "domain": "bingchillin.org", "title": "Bing", "banner": "",
            "product": "Nginx", "lastupdatetime": "2022-05-23 15:00:00",
            "asn": "13335", "org": "Cloudflare", "region": "California", "city": "SF",
            "longitude": -122.4, "latitude": 37.8
        });
        let record = Fofa
            .normalize(&raw, &FieldSelection::default(), 1_800_000_000_000, 300_000)
            .expect("normalize");
        assert_eq!(record.port, 443);
        assert_eq!(record.service.as_deref(), Some("https"));
        assert_eq!(record.domain.as_deref(), Some("bingchillin.org"));
        assert_eq!(record.tech[0].id, "nginx");
        assert_eq!(record.observed_at, 1653289200000);
        assert_eq!(record.asn.as_deref(), Some("13335"));
    }

    #[test]
    fn host_url_and_port_extraction() {
        let raw = json!({"ip": "1.1.1.1", "port": "8080", "host": "76.158.236.234:8080"});
        let record = Fofa
            .normalize(&raw, &FieldSelection::default(), 1_000_000, 300_000)
            .expect("normalize");
        assert_eq!(record.domain.as_deref(), Some("76.158.236.234"));
    }

    #[test]
    fn size_clamping_by_query_content() {
        assert_eq!(clamp_size("body=\"x\"", 1000), 500);
        assert_eq!(clamp_size("banner=\"x\"", 5000), 2000);
        assert_eq!(clamp_size("ip=\"1.1.1.1\"", 1000), 1000);
        assert_eq!(clamp_size("ip=\"1.1.1.1\"", 20000), 10000);
    }

    #[test]
    fn basic_fields_drop_paid_columns() {
        let fields = basic_fields(&FieldSelection::default());
        assert!(!fields.contains(&"lastupdatetime".to_owned()));
        assert!(!fields.contains(&"product".to_owned()));
        assert!(fields.contains(&"ip".to_owned()));
    }
}
