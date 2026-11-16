//! 奇安信 Hunter 鹰图（hunter.qianxin.com，国内版）。
//!
//! 官方文档核实 2026-11-16（用户手动复制的帮助中心文档 + 实时 /api/syntax）：
//! GET /openApi/search，api-key + search(base64url) + page/page_size(必填) +
//! start_time/end_time(YYYY-MM-DD，超近30天扣权益积分) + is_web + fields。
//! 响应 data.arr[]；updated_at 现行示例为仅日期。限速约 2s/请求。

use serde_json::{Value, json};

use crate::data_import::csv::TechEntry;
use crate::federation::adapters::{
    FederationAdapter, SearchRequest, base64_url, parse_cn_datetime, parse_port_value,
    resolve_observed_at, response_json, string_field, transport_error, window_dates_cn,
};
use crate::federation::model::{
    Capabilities, FieldSelection, NormalizedRecord, RawPage, SourceError, SourceKind,
    TimeFilterMode, clean_text, normalize_service, normalize_tech_id,
};

const BASE: &str = "https://hunter.qianxin.com";
const PAGE_SIZE_CHOICES: &[u32] = &[1, 10, 50, 100];

pub struct Hunter;

fn api_key(credential: &Value) -> Result<&str, SourceError> {
    credential
        .get("api_key")
        .and_then(Value::as_str)
        .filter(|k| !k.is_empty())
        .ok_or(SourceError::permanent("auth_failed"))
}

/// 已选字段 → Hunter fields 枚举（updated_at/geo 恒带）。
fn hunter_fields(fields: &FieldSelection) -> String {
    let mut list = vec![
        "ip",
        "port",
        "protocol",
        "base_protocol",
        "updated_at",
        "os",
        "country",
        "province",
        "city",
        "isp",
        "as_org",
    ];
    if fields.domain {
        list.push("domain");
        list.push("url");
    }
    if fields.tech {
        list.push("component");
    }
    if fields.title {
        list.push("web_title");
    }
    if fields.banner {
        list.push("banner");
        list.push("header");
    }
    list.join(",")
}

fn clamp_page_size(size: u32) -> u32 {
    PAGE_SIZE_CHOICES
        .iter()
        .copied()
        .filter(|choice| *choice <= size)
        .max()
        .unwrap_or(1)
}

impl FederationAdapter for Hunter {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            default_qps: 0.5,
            max_page_size: 100,
            page_size_choices: Some(PAGE_SIZE_CHOICES),
            time_filter: TimeFilterMode::NativeParam,
            single_ip_free_endpoint: false,
        }
    }

    async fn search(
        &self,
        client: &reqwest::Client,
        credential: &Value,
        request: &SearchRequest<'_>,
    ) -> Result<RawPage, SourceError> {
        let key = api_key(credential)?;
        let fields = request
            .field_override
            .as_ref()
            .map(|f| f.join(","))
            .unwrap_or_else(|| hunter_fields(request.fields));
        let mut params = vec![
            ("api-key", key.to_owned()),
            ("search", base64_url(&request.query.text)),
            ("page", (request.page.index + 1).to_string()),
            ("page_size", clamp_page_size(request.page.size).to_string()),
            ("is_web", "3".to_owned()),
            ("fields", fields),
        ];
        if let Some(days) = request.window_days {
            let (start, end) = window_dates_cn(days);
            params.push(("start_time", start));
            params.push(("end_time", end));
        }
        let response = client
            .get(format!("{BASE}/openApi/search"))
            .query(&params)
            .send()
            .await
            .map_err(|e| transport_error(&e))?;
        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(SourceError::transient("rate_limited"));
        }
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(SourceError::permanent("auth_failed"));
        }
        let body = response_json(response).await?;
        let code = body.get("code");
        let ok = code.and_then(Value::as_i64) == Some(200)
            || code.and_then(Value::as_str) == Some("200");
        if !ok {
            let code_num = code.and_then(Value::as_i64).unwrap_or(0);
            return Err(match code_num {
                401 => SourceError::permanent("auth_failed"),
                429 => SourceError::transient("rate_limited"),
                _ => SourceError::permanent("query_rejected"),
            });
        }
        let data = body.get("data").cloned().unwrap_or(Value::Null);
        let records = data
            .get("arr")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let quota = json!({
            "consume_quota": data.get("consume_quota").cloned().unwrap_or(Value::Null),
            "rest_quota": data.get("rest_quota").cloned().unwrap_or(Value::Null),
        });
        Ok(RawPage {
            total: data.get("total").and_then(Value::as_i64),
            records,
            quota: Some(quota),
            prompt: data
                .get("syntax_prompt")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned),
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
            raw.get("component")
                .and_then(Value::as_array)
                .map(|components| {
                    components
                        .iter()
                        .filter_map(|c| {
                            let name = c.get("name").and_then(Value::as_str)?;
                            let id = normalize_tech_id(name)?;
                            let version = c
                                .get("version")
                                .and_then(Value::as_str)
                                .and_then(|v| clean_text(v, 64));
                            Some(TechEntry { id, version })
                        })
                        .take(64)
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let (observed_at, timestamp_inferred) = resolve_observed_at(
            string_field(raw, "updated_at")
                .as_deref()
                .and_then(parse_cn_datetime),
            now_ms,
            future_tolerance_ms,
        );
        Some(NormalizedRecord {
            ip,
            port,
            protocol,
            domain: if fields.domain {
                string_field(raw, "domain").and_then(|d| clean_text(&d.to_ascii_lowercase(), 253))
            } else {
                None
            },
            service,
            tech,
            title: if fields.title {
                string_field(raw, "web_title").and_then(|t| clean_text(&t, 512))
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
            asn: None,
            as_org: string_field(raw, "as_org").and_then(|v| clean_text(&v, 256)),
            isp: string_field(raw, "isp").and_then(|v| clean_text(&v, 256)),
            country_name: string_field(raw, "country").and_then(|v| clean_text(&v, 128)),
            region_name: string_field(raw, "province").and_then(|v| clean_text(&v, 128)),
            city_name: string_field(raw, "city").and_then(|v| clean_text(&v, 128)),
            latitude: None,
            longitude: None,
            sources: vec![SourceKind::Hunter.as_str().to_owned()],
        })
    }

    async fn probe(
        &self,
        client: &reqwest::Client,
        credential: &Value,
    ) -> Result<Value, SourceError> {
        let key = api_key(credential)?;
        let response = client
            .get(format!("{BASE}/openApi/userInfo"))
            .query(&[("api-key", key)])
            .send()
            .await
            .map_err(|e| transport_error(&e))?;
        if !response.status().is_success() {
            return Err(SourceError::permanent("auth_failed"));
        }
        let body = response_json(response).await?;
        let code_ok = body.get("code").and_then(Value::as_i64) == Some(200)
            || body.get("code").and_then(Value::as_str) == Some("200");
        if !code_ok {
            return Err(SourceError::permanent("auth_failed"));
        }
        Ok(body.get("data").cloned().unwrap_or(Value::Null))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_size_clamped_to_choices() {
        assert_eq!(clamp_page_size(100), 100);
        assert_eq!(clamp_page_size(75), 50);
        assert_eq!(clamp_page_size(10), 10);
        assert_eq!(clamp_page_size(3), 1);
    }

    #[test]
    fn normalizes_official_example() {
        let raw = json!({
            "ip": "127.0.0.1", "port": 443, "domain": "abc.qianxin.com",
            "protocol": "https", "base_protocol": "tcp",
            "web_title": "欢迎登录", "banner": "xxx",
            "component": [{"name": "Nginx", "version": "1.20.2"}],
            "updated_at": "2025-01-01",
            "country": "中国", "province": "山东省", "city": "济南市",
            "isp": "中国电信", "as_org": "Chinanet"
        });
        let record = Hunter
            .normalize(&raw, &FieldSelection::default(), 1_800_000_000_000, 300_000)
            .expect("normalize");
        assert_eq!(record.ip, "127.0.0.1");
        assert_eq!(record.port, 443);
        assert_eq!(record.protocol, "tcp");
        assert_eq!(record.service.as_deref(), Some("https"));
        assert_eq!(record.tech[0].id, "nginx");
        assert_eq!(record.tech[0].version.as_deref(), Some("1.20.2"));
        assert_eq!(record.observed_at, 1735660800000);
        assert!(!record.timestamp_inferred);
    }

    #[test]
    fn missing_timestamp_is_inferred() {
        let raw = json!({"ip": "1.1.1.1", "port": 80});
        let record = Hunter
            .normalize(&raw, &FieldSelection::default(), 1_000_000, 300_000)
            .expect("normalize");
        assert!(record.timestamp_inferred);
        assert_eq!(record.observed_at, 1_000_000);
    }

    #[test]
    fn rejects_invalid_endpoint() {
        assert!(
            Hunter
                .normalize(
                    &json!({"ip": "999.1.1.1", "port": 80}),
                    &FieldSelection::default(),
                    0,
                    0
                )
                .is_none()
        );
        assert!(
            Hunter
                .normalize(
                    &json!({"ip": "1.1.1.1", "port": 0}),
                    &FieldSelection::default(),
                    0,
                    0
                )
                .is_none()
        );
    }
}
