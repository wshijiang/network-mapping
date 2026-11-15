//! Shodan（shodan.io）。
//!
//! 官方文档核实 2026-11-16（developer.shodan.io/api + changelog）：
//! GET /shodan/host/search?key&query&page(1-based,100/页)&minify；带 filter 每页 1 credit。
//! 单 IP 走免费 GET /shodan/host/{ip}（history=true 回溯 ≤90 天）。
//! 无时间过滤器：search 固定近 30 天窗口；timestamp 为 UTC 无时区后缀 ISO8601。
//! 限速 1 req/s；2025-11-10 起超速仅当次 429。

use serde_json::{Value, json};

use crate::data_import::csv::TechEntry;
use crate::federation::adapters::{
    FederationAdapter, SearchRequest, parse_iso_utc, parse_port_value, resolve_observed_at,
    response_json, string_field, transport_error,
};
use crate::federation::model::{
    Capabilities, FieldSelection, NormalizedRecord, RawPage, SourceError, SourceKind,
    TimeFilterMode, clean_text, normalize_asn, normalize_service, normalize_tech_id,
};

const BASE: &str = "https://api.shodan.io";

pub struct Shodan;

fn key(credential: &Value) -> Result<&str, SourceError> {
    credential
        .get("key")
        .and_then(Value::as_str)
        .filter(|k| !k.is_empty())
        .ok_or(SourceError::permanent("auth_failed"))
}

fn classify_status(status: reqwest::StatusCode) -> Option<SourceError> {
    match status {
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
            Some(SourceError::permanent("auth_failed"))
        }
        reqwest::StatusCode::TOO_MANY_REQUESTS => Some(SourceError::transient("rate_limited")),
        _ => None,
    }
}

impl FederationAdapter for Shodan {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            default_qps: 1.0,
            max_page_size: 100,
            page_size_choices: None,
            time_filter: TimeFilterMode::LocalOnly,
            single_ip_free_endpoint: true,
        }
    }

    async fn search(
        &self,
        client: &reqwest::Client,
        credential: &Value,
        request: &SearchRequest<'_>,
    ) -> Result<RawPage, SourceError> {
        let api_key = key(credential)?;
        // 单 IP 目标：免费 host 端点（0 credit）；窗口 >30 天时 history=true 回溯 ≤90 天。
        if let Some(ip) = &request.single_ip {
            let history = request.window_days.is_some_and(|days| days > 30);
            let response = client
                .get(format!("{BASE}/shodan/host/{ip}"))
                .query(&[
                    ("key", api_key),
                    ("history", if history { "true" } else { "false" }),
                ])
                .send()
                .await
                .map_err(|e| transport_error(&e))?;
            let status = response.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                return Ok(RawPage::default());
            }
            if let Some(error) = classify_status(status) {
                return Err(error);
            }
            if !status.is_success() {
                return Err(SourceError::transient("transport"));
            }
            let body = response_json(response).await?;
            let records = body
                .get("data")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            return Ok(RawPage {
                total: Some(records.len() as i64),
                records,
                quota: None,
                prompt: None,
            });
        }
        let response = client
            .get(format!("{BASE}/shodan/host/search"))
            .query(&[
                ("key", api_key),
                ("query", request.query.text.as_str()),
                ("page", &(request.page.index + 1).to_string()),
                ("minify", "true"),
            ])
            .send()
            .await
            .map_err(|e| transport_error(&e))?;
        let status = response.status();
        if let Some(error) = classify_status(status) {
            return Err(error);
        }
        if !status.is_success() {
            return Err(SourceError::transient("transport"));
        }
        let body = response_json(response).await?;
        let records = body
            .get("matches")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(RawPage {
            records,
            total: body.get("total").and_then(Value::as_i64),
            quota: None,
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
        let ip = string_field(raw, "ip_str")?;
        ip.parse::<std::net::IpAddr>().ok()?;
        let port = parse_port_value(raw.get("port")?)?;
        if port == 0 {
            return None;
        }
        let service = if fields.service {
            string_field(raw, "product").and_then(|s| normalize_service(&s))
        } else {
            None
        };
        let protocol = string_field(raw, "transport")
            .map(|p| p.to_ascii_lowercase())
            .filter(|p| p == "tcp" || p == "udp")
            .unwrap_or_else(|| crate::federation::model::infer_protocol(service.as_deref(), None));
        let tech = if fields.tech {
            raw.pointer("/http/components")
                .and_then(Value::as_object)
                .map(|components| {
                    components
                        .keys()
                        .filter_map(|name| normalize_tech_id(name))
                        .map(|id| TechEntry { id, version: None })
                        .take(64)
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let (observed_at, timestamp_inferred) = resolve_observed_at(
            string_field(raw, "timestamp")
                .as_deref()
                .and_then(parse_iso_utc),
            now_ms,
            future_tolerance_ms,
        );
        let domain = if fields.domain {
            raw.get("domains")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_str)
                .or_else(|| {
                    raw.get("hostnames")
                        .and_then(Value::as_array)
                        .and_then(|a| a.first())
                        .and_then(Value::as_str)
                })
                .and_then(|d| clean_text(&d.to_ascii_lowercase(), 253))
        } else {
            None
        };
        let location = raw.get("location").cloned().unwrap_or(Value::Null);
        Some(NormalizedRecord {
            ip,
            port,
            protocol,
            domain,
            service,
            tech,
            title: if fields.title {
                raw.pointer("/http/title")
                    .and_then(Value::as_str)
                    .and_then(|t| clean_text(t, 512))
            } else {
                None
            },
            banner: if fields.banner {
                string_field(raw, "data").and_then(|b| clean_text(&b, 64 * 1024))
            } else {
                None
            },
            observed_at,
            timestamp_inferred,
            asn: string_field(raw, "asn").and_then(|s| normalize_asn(&s)),
            as_org: string_field(raw, "org").and_then(|v| clean_text(&v, 256)),
            isp: string_field(raw, "isp").and_then(|v| clean_text(&v, 256)),
            country_name: location
                .get("country_name")
                .and_then(Value::as_str)
                .and_then(|v| clean_text(v, 128)),
            region_name: None,
            city_name: location
                .get("city")
                .and_then(Value::as_str)
                .and_then(|v| clean_text(v, 128)),
            latitude: location.get("latitude").and_then(Value::as_f64),
            longitude: location.get("longitude").and_then(Value::as_f64),
            sources: vec![SourceKind::Shodan.as_str().to_owned()],
        })
    }

    async fn probe(
        &self,
        client: &reqwest::Client,
        credential: &Value,
    ) -> Result<Value, SourceError> {
        let api_key = key(credential)?;
        let response = client
            .get(format!("{BASE}/api-info"))
            .query(&[("key", api_key)])
            .send()
            .await
            .map_err(|e| transport_error(&e))?;
        if let Some(error) = classify_status(response.status()) {
            return Err(error);
        }
        let body = response_json(response).await?;
        Ok(json!({
            "query_credits": body.get("query_credits").cloned().unwrap_or(Value::Null),
            "scan_credits": body.get("scan_credits").cloned().unwrap_or(Value::Null),
            "plan": body.get("plan").cloned().unwrap_or(Value::Null),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_banner() {
        let raw = json!({
            "ip_str": "8.8.8.8", "port": 443, "transport": "tcp",
            "hostnames": ["dns.google"], "domains": ["dns.google"],
            "product": "nginx", "version": "1.18.0",
            "http": {"title": "DNS", "components": {"jQuery": {"categories": []}}},
            "data": "HTTP/1.1 200 OK",
            "timestamp": "2021-01-25T21:33:49.154513",
            "asn": "AS15169", "org": "Google", "isp": "Google",
            "location": {"country_name": "United States", "city": "Mountain View", "latitude": 37.4, "longitude": -122.1}
        });
        let record = Shodan
            .normalize(&raw, &FieldSelection::default(), 1_800_000_000_000, 300_000)
            .expect("normalize");
        assert_eq!(record.ip, "8.8.8.8");
        assert_eq!(record.domain.as_deref(), Some("dns.google"));
        assert_eq!(record.tech[0].id, "jquery");
        assert_eq!(record.observed_at, 1611610429154);
        assert_eq!(record.asn.as_deref(), Some("15169"));
    }

    #[test]
    fn missing_timestamp_inferred() {
        let raw = json!({"ip_str": "1.1.1.1", "port": 80});
        let record = Shodan
            .normalize(&raw, &FieldSelection::default(), 1_000_000, 300_000)
            .expect("normalize");
        assert!(record.timestamp_inferred);
    }
}
