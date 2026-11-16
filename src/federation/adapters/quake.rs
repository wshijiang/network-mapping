//! 360 Quake（quake.360.net）。
//!
//! 官方文档核实 2026-11-16（帮助中心文档接口 + 用户保存页面二次确认）：
//! POST /api/v3/search/quake_service，X-QuakeToken 头 + JSON body
//! {query, start(偏移), size(≤100), latest(默认true), include, start_time/end_time(UTC，仅高级+)}。
//! HTTP 恒 200 + code 区分；认证失败 HTTP 401 且 body 非 JSON（/quake/login）。
//! 基础会员 include 无 time/components/domain/service.response。

use serde_json::{Value, json};

use crate::data_import::csv::TechEntry;
use crate::federation::adapters::{
    FederationAdapter, SearchRequest, parse_iso_utc, parse_port_value, resolve_observed_at,
    response_json, string_field, transport_error, window_datetimes_utc,
};
use crate::federation::model::{
    Capabilities, FieldSelection, NormalizedRecord, RawPage, SourceError, SourceKind,
    TimeFilterMode, clean_text, normalize_service, normalize_tech_id,
};

const BASE: &str = "https://quake.360.net";

pub struct Quake;

fn token(credential: &Value) -> Result<&str, SourceError> {
    credential
        .get("token")
        .and_then(Value::as_str)
        .filter(|k| !k.is_empty())
        .ok_or(SourceError::permanent("auth_failed"))
}

/// 已选字段 → include 列表（time/geo 恒带；会员白名单由执行器覆盖）。
fn quake_include(fields: &FieldSelection) -> Vec<String> {
    let mut list = vec![
        "ip".to_owned(),
        "port".to_owned(),
        "transport".to_owned(),
        "hostname".to_owned(),
        "time".to_owned(),
        "asn".to_owned(),
        "org".to_owned(),
        "service.name".to_owned(),
        "location.country_cn".to_owned(),
        "location.province_cn".to_owned(),
        "location.city_cn".to_owned(),
        "location.isp".to_owned(),
    ];
    if fields.domain {
        list.push("domain".into());
    }
    if fields.tech {
        list.push("components.product_name_en".into());
        list.push("components.product_name_cn".into());
        list.push("components.version".into());
    }
    if fields.title {
        list.push("service.http.title".into());
    }
    if fields.banner {
        list.push("service.response".into());
    }
    list
}

/// 基础会员白名单（官方文档；降级重试用）。
pub const BASIC_INCLUDE: &[&str] = &[
    "ip",
    "port",
    "hostname",
    "transport",
    "asn",
    "org",
    "service.name",
    "location.country_cn",
    "location.province_cn",
    "location.city_cn",
    "service.http.host",
    "service.http.title",
    "service.http.server",
];

fn classify_code(code: &str) -> SourceError {
    match code {
        "q3005" => SourceError::transient("rate_limited"),
        "q3007" | "q2001" => SourceError::permanent("quota_exhausted"),
        "q3011" => SourceError::permanent("auth_failed"),
        "q3015" => SourceError::permanent("query_rejected"),
        "q3017" => SourceError::permanent("field_permission"),
        _ => SourceError::permanent("invalid_response"),
    }
}

impl FederationAdapter for Quake {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            default_qps: 1.0,
            max_page_size: 100,
            page_size_choices: None,
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
        let token = token(credential)?;
        let include = request
            .field_override
            .clone()
            .unwrap_or_else(|| quake_include(request.fields));
        let mut body = json!({
            "query": request.query.text,
            "start": u64::from(request.page.index) * u64::from(request.page.size),
            "size": request.page.size.min(100),
            "latest": true,
            "include": include,
        });
        if let Some(days) = request.window_days {
            let (start, end) = window_datetimes_utc(days);
            body["start_time"] = json!(start);
            body["end_time"] = json!(end);
        }
        let response = client
            .post(format!("{BASE}/api/v3/search/quake_service"))
            .header("X-QuakeToken", token)
            .json(&body)
            .send()
            .await
            .map_err(|e| transport_error(&e))?;
        let status = response.status();
        // 认证失败：HTTP 401，body 为 /quake/login（非 JSON），特判。
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(SourceError::permanent("auth_failed"));
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(SourceError::transient("rate_limited"));
        }
        if !status.is_success() {
            return Err(SourceError::transient("transport"));
        }
        let body = response_json(response).await?;
        let code = body.get("code").and_then(Value::as_i64).unwrap_or(-1);
        if code != 0 {
            let code_str = body
                .get("code")
                .map(|c| match c {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .unwrap_or_default();
            return Err(classify_code(&code_str));
        }
        let records = body
            .get("data")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let total = body
            .pointer("/meta/pagination/total")
            .and_then(Value::as_i64);
        Ok(RawPage {
            records,
            total,
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
        let ip = string_field(raw, "ip")?;
        ip.parse::<std::net::IpAddr>().ok()?;
        let port = parse_port_value(raw.get("port")?)?;
        if port == 0 {
            return None;
        }
        let service = if fields.service {
            raw.pointer("/service/name")
                .and_then(Value::as_str)
                .and_then(normalize_service)
        } else {
            None
        };
        let protocol = string_field(raw, "transport")
            .map(|p| p.to_ascii_lowercase())
            .filter(|p| p == "tcp" || p == "udp")
            .unwrap_or_else(|| crate::federation::model::infer_protocol(service.as_deref(), None));
        let tech = if fields.tech {
            raw.get("components")
                .and_then(Value::as_array)
                .map(|components| {
                    components
                        .iter()
                        .filter_map(|c| {
                            let name = c
                                .get("product_name_en")
                                .and_then(Value::as_str)
                                .or_else(|| c.get("product_name_cn").and_then(Value::as_str))?;
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
            string_field(raw, "time").as_deref().and_then(parse_iso_utc),
            now_ms,
            future_tolerance_ms,
        );
        let location = raw.get("location").cloned().unwrap_or(Value::Null);
        Some(NormalizedRecord {
            ip,
            port,
            protocol,
            domain: if fields.domain {
                string_field(raw, "domain")
                    .or_else(|| string_field(raw, "hostname"))
                    .and_then(|d| clean_text(&d.to_ascii_lowercase(), 253))
            } else {
                None
            },
            service,
            tech,
            title: if fields.title {
                raw.pointer("/service/http/title")
                    .and_then(Value::as_str)
                    .and_then(|t| clean_text(t, 512))
            } else {
                None
            },
            banner: if fields.banner {
                raw.pointer("/service/response")
                    .and_then(Value::as_str)
                    .and_then(|b| clean_text(b, 64 * 1024))
            } else {
                None
            },
            observed_at,
            timestamp_inferred,
            asn: raw
                .get("asn")
                .map(|v| match v {
                    Value::Number(n) => n.to_string(),
                    Value::String(s) => s.clone(),
                    _ => String::new(),
                })
                .filter(|s| !s.is_empty())
                .and_then(|s| crate::federation::model::normalize_asn(&s)),
            as_org: string_field(raw, "org").and_then(|v| clean_text(&v, 256)),
            isp: location
                .get("isp")
                .and_then(Value::as_str)
                .and_then(|v| clean_text(v, 256)),
            country_name: location
                .get("country_cn")
                .and_then(Value::as_str)
                .and_then(|v| clean_text(v, 128)),
            region_name: location
                .get("province_cn")
                .and_then(Value::as_str)
                .and_then(|v| clean_text(v, 128)),
            city_name: location
                .get("city_cn")
                .and_then(Value::as_str)
                .and_then(|v| clean_text(v, 128)),
            latitude: None,
            longitude: None,
            sources: vec![SourceKind::Quake.as_str().to_owned()],
        })
    }

    async fn probe(
        &self,
        client: &reqwest::Client,
        credential: &Value,
    ) -> Result<Value, SourceError> {
        let token = token(credential)?;
        let response = client
            .get(format!("{BASE}/api/v3/user/info"))
            .header("X-QuakeToken", token)
            .send()
            .await
            .map_err(|e| transport_error(&e))?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(SourceError::permanent("auth_failed"));
        }
        let body = response_json(response).await?;
        if body.get("code").and_then(Value::as_i64) != Some(0) {
            return Err(SourceError::permanent("auth_failed"));
        }
        Ok(body.get("data").cloned().unwrap_or(Value::Null))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_service_record() {
        let raw = json!({
            "ip": "193.36.119.50", "port": 8022, "transport": "tcp",
            "domain": "example.com",
            "time": "2026-07-03T05:08:19.848Z",
            "service": {"name": "ssh", "response": "SSH-2.0-OpenSSH_8.9p1"},
            "components": [{"product_name_en": "openssh", "version": "8.9p1"}],
            "asn": 12345, "org": "Example Org",
            "location": {"country_cn": "美国", "province_cn": "加州", "city_cn": "洛杉矶", "isp": "Example ISP"}
        });
        let fields = FieldSelection {
            domain: true,
            service: true,
            tech: true,
            title: true,
            banner: true,
        };
        let record = Quake
            .normalize(&raw, &fields, 1_900_000_000_000, 300_000)
            .expect("normalize");
        assert_eq!(record.service.as_deref(), Some("ssh"));
        assert_eq!(record.tech[0].id, "openssh");
        assert_eq!(record.observed_at, 1783055299848);
        assert_eq!(record.asn.as_deref(), Some("12345"));
        assert_eq!(record.banner.as_deref(), Some("SSH-2.0-OpenSSH_8.9p1"));
    }

    #[test]
    fn basic_member_missing_fields_inferred() {
        let raw = json!({"ip": "1.1.1.1", "port": 80, "service": {"name": "http"}});
        let record = Quake
            .normalize(&raw, &FieldSelection::default(), 1_000_000, 300_000)
            .expect("normalize");
        assert!(record.timestamp_inferred);
        assert!(record.tech.is_empty());
        assert!(record.domain.is_none());
    }

    #[test]
    fn error_code_classification() {
        assert!(classify_code("q3005").retryable);
        assert_eq!(classify_code("q3007").code, "quota_exhausted");
        assert_eq!(classify_code("q3017").code, "field_permission");
        assert_eq!(classify_code("q3011").code, "auth_failed");
    }
}
