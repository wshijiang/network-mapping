//! Mining identities derived from stored service evidence.
use serde_json::Value;

use super::{Evidence, Product, ProductCategory, bounded};

const MAX_SUMMARY_BYTES: usize = 64 * 1024;

pub(super) fn xmrig(
    item: &Value,
    response: &Value,
    module: &str,
    path: &str,
    index: usize,
) -> Option<Product> {
    if item["status"] != "success"
        || item["truncated"] == true
        || response["body_truncated"] == true
        || response["status_code"] != 200
    {
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
    if body.len() > MAX_SUMMARY_BYTES || !body.contains("hashrate") {
        return None;
    }
    let summary: Value = serde_json::from_str(body).ok()?;
    let version = summary["version"].as_str()?;
    let agent = summary["ua"].as_str()?.split_whitespace().next()?;
    let (software, agent_version) = agent.split_once('/')?;
    let rates = summary.pointer("/hashrate/total")?.as_array()?;
    if summary["kind"] != "miner"
        || !software.eq_ignore_ascii_case("xmrig")
        || agent_version != version
        || version.len() > 32
        || version.split('.').count() != 3
        || version
            .split('.')
            .any(|part| part.is_empty() || !part.bytes().all(|c| c.is_ascii_digit()))
        || !summary["paused"].is_boolean()
        || !summary["algorithms"].as_array().is_some_and(|algorithms| {
            algorithms
                .iter()
                .any(|algorithm| algorithm.as_str().is_some_and(|name| !name.is_empty()))
        })
        || rates.len() != 3
        || !rates
            .iter()
            .all(|rate| rate.is_null() || rate.as_f64().is_some_and(|value| value >= 0.0))
    {
        return None;
    }

    Some(Product {
        id: "xmrig".into(),
        name: "XMRig".into(),
        category: ProductCategory::MiningSoftware,
        component: None,
        version: Some(version.into()),
        assessment: "identified".into(),
        basis: "service_declaration".into(),
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
    })
}
