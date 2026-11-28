//! Mining identities derived from stored service evidence.
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Evidence, Product, ProductCategory, bounded};

const MAX_SUMMARY_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Attempt {
    pub status: String,
    pub status_code: Option<u16>,
    pub host: Option<String>,
    pub observed_at: i64,
    pub observation_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct Confirmation {
    pub observed_at: i64,
    pub observation_id: String,
    pub product: Option<Product>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ProductObservation {
    pub observed_at: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub observation_id: String,
    #[serde(default)]
    pub stale: bool,
}

pub(super) fn incomplete_summary(item: &Value, response: &Value) -> bool {
    item["status"] != "success" || item["truncated"] == true || response["body_truncated"] == true
}

pub(super) fn host(value: &Value) -> Option<String> {
    let value = value.as_str().filter(|host| host.len() <= 260)?;
    let url = reqwest::Url::parse(&format!("http://{value}")).ok()?;
    if url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    url.domain().map(str::to_owned)
}

pub(super) fn probe_status(data: Option<&Value>) -> Option<(&Value, &'static str)> {
    let probe = data?.get("xmrig_probe")?;
    let status = match probe["status"].as_str() {
        Some("success") => "success",
        Some("not_attempted") => "not_attempted",
        Some("no_summary") => "no_summary",
        Some("auth_required") => "auth_required",
        Some("timeout") => "timeout",
        Some("cancelled") => "cancelled",
        Some("transport_error") => "transport_error",
        Some("http_error") => "http_error",
        Some("response_too_large") => "response_too_large",
        Some("budget_exceeded") => "budget_exceeded",
        _ => "invalid_response",
    };
    Some((probe, status))
}

pub(super) enum Declaration {
    Xmrig(Product),
    OtherMiner,
}

pub(super) fn declaration(
    item: &Value,
    response: &Value,
    source: (&str, &str, usize),
    observed_at: i64,
    observation_id: &str,
) -> Option<Declaration> {
    if incomplete_summary(item, response) || response["status_code"] != 200 {
        return None;
    }

    let content_type = &response["headers"]["content_type"];
    let content_type = content_type.as_str().or_else(|| {
        let [value] = content_type.as_array()?.as_slice() else {
            return None;
        };
        value.as_str()
    })?;
    if !content_type
        .split(';')
        .next()?
        .trim()
        .eq_ignore_ascii_case("application/json")
    {
        return None;
    }

    let body = response["body"].as_str()?;
    if body.len() > MAX_SUMMARY_BYTES || (!body.contains("hashrate") && !body.contains('\\')) {
        return None;
    }
    let summary: Value = serde_json::from_str(body).ok()?;
    let version = summary["version"].as_str()?;
    let agent = summary["ua"].as_str()?.split_whitespace().next()?;
    let (software, agent_version) = agent.split_once('/')?;
    let rates = summary.pointer("/hashrate/total")?.as_array()?;
    let mut parts = version.split('.');
    if summary["kind"] != "miner"
        || agent_version != version
        || software.is_empty()
        || software.len() > 32
        || !software
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
        || version.len() > 32
        || !(0..3).all(|_| {
            parts
                .next()
                .is_some_and(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()))
        })
        || parts.next().is_some()
        || !summary["paused"].is_boolean()
        || !summary["algorithms"].as_array().is_some_and(|algorithms| {
            algorithms
                .iter()
                .filter_map(Value::as_str)
                .any(|name| !name.is_empty() && name.len() <= 64)
        })
        || rates.len() != 3
        || !rates
            .iter()
            .all(|rate| rate.is_null() || rate.as_f64().is_some_and(|value| value >= 0.0))
    {
        return None;
    }
    if !software.eq_ignore_ascii_case("xmrig") {
        return Some(Declaration::OtherMiner);
    }

    let (module, path, index) = source;
    Some(Declaration::Xmrig(Product {
        id: "xmrig".into(),
        name: "XMRig".into(),
        category: ProductCategory::MiningSoftware,
        component: None,
        version: Some(version.into()),
        assessment: "identified".into(),
        basis: "service_declaration".into(),
        observation: Some(ProductObservation {
            observed_at,
            observation_id: observation_id.to_owned(),
            stale: false,
        }),
        evidence: vec![Evidence {
            detection_method: Some("http_fingerprint".into()),
            rule_id: "xmrig_miner_summary".into(),
            probe: module.into(),
            field_path: format!("/evidence/{index}/result{path}/body"),
            details: vec![
                ("kind".into(), "miner".into()),
                ("version".into(), version.into()),
            ],
            sni: response
                .pointer("/request/tls_log/handshake_log/client_hello/server_name")
                .and_then(Value::as_str)
                .map(bounded),
            http_host: response["request"]["host"].as_str().map(bounded),
            source_url: Some("https://xmrig.com/docs/miner/api".into()),
        }],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn xmrig_summary_contract_matches_the_scanner_fixtures() {
        // Keep this fixture in sync with Network-Mapping-Scanner's web_content tests.
        let cases: Vec<Value> =
            serde_json::from_str(include_str!("xmrig_summary_fixtures.json")).unwrap();
        for case in cases {
            let item = json!({"status":"success"});
            let response = json!({
                "status_code":200,
                "headers":{"content_type":"application/json"},
                "body":case["body"].to_string(),
            });
            let actual =
                match declaration(&item, &response, ("web_assets", "/xmrig_summary", 0), 1, "") {
                    Some(Declaration::Xmrig(_)) => "xmrig",
                    Some(Declaration::OtherMiner) => "other",
                    None => "invalid",
                };
            assert_eq!(case["expected"], actual, "{}", case["name"]);
        }
    }
}
