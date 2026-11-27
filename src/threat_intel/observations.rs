//! Exact IOC lookups for evidence from an authorized asset's HTTP observation.
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Annotation, annotate, model::normalize};

const MAX_URL_BYTES: usize = 2048;
const MAX_INDICATORS: usize = 12;
const BATCH_ENDPOINTS: usize = 40; // At most 480 keys per lookup.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Basis {
    HttpRequest,
    HttpRedirect,
    JavascriptSha256,
}

impl Basis {
    fn kind(self) -> &'static str {
        match self {
            Self::HttpRequest | Self::HttpRedirect => "url",
            Self::JavascriptSha256 => "sha256",
        }
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct Indicator {
    basis: Basis,
    value: String,
}

#[derive(Serialize)]
pub(crate) struct WebIntel {
    observed_at: i64,
    #[serde(flatten)]
    annotation: Annotation,
}

pub(crate) fn scanner_observation(task_source: &str) -> bool {
    !matches!(task_source, "import" | "federation")
}

fn http_url(raw: &str) -> Option<Url> {
    if raw.len() > MAX_URL_BYTES
        || raw
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        return None;
    }
    let url = Url::parse(raw).ok()?;
    (matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none())
    .then_some(url)
}

fn request_url(request: &Value) -> Option<Url> {
    if let Some(raw) = request.as_str() {
        return http_url(raw);
    }

    // zgrab2 serializes the request URL as Go URL fields.
    let scheme = request["scheme"].as_str()?;
    let host = request["host"].as_str()?;
    if !matches!(scheme, "http" | "https") || host.contains(['/', '\\', '@', '?', '#']) {
        return None;
    }
    let mut url = http_url(&format!("{scheme}://{host}"))?;
    let path = request["raw_path"]
        .as_str()
        .filter(|path| !path.is_empty())
        .or_else(|| request["path"].as_str())?;
    let query = request["raw_query"]
        .as_str()
        .filter(|query| !query.is_empty());
    if !path.starts_with('/') || path.len() + query.map_or(0, str::len) > MAX_URL_BYTES {
        return None;
    }
    url.set_path(path);
    url.set_query(query);
    http_url(url.as_str())
}

fn push_indicator(indicators: &mut Vec<Indicator>, basis: Basis, raw: &str) {
    if indicators.len() < MAX_INDICATORS
        && let Ok((kind, value)) = normalize(basis.kind(), raw)
        && !indicators
            .iter()
            .any(|item| item.basis.kind() == kind && item.value == value)
    {
        indicators.push(Indicator { basis, value });
    }
}

pub(crate) fn extract(data: Option<&Value>) -> Vec<Indicator> {
    let Some(evidence) = data
        .filter(|data| data["schema_version"] == 2)
        .and_then(|data| data["evidence"].as_array())
    else {
        return Vec::new();
    };

    let mut indicators = Vec::new();
    let http = evidence.iter().find(|item| {
        matches!(item["module"].as_str(), Some("http" | "https")) && item["status"] == "success"
    });
    if let Some(http) = http {
        let result = &http["result"];
        let response = result["redirect_response_chain"]
            .as_array()
            .and_then(|chain| chain.first())
            .unwrap_or(&result["response"]);
        if let Some(url) = request_url(&response["request"]["url"]) {
            push_indicator(&mut indicators, Basis::HttpRequest, url.as_str());
            if matches!(
                response["status_code"].as_u64(),
                Some(301 | 302 | 303 | 307 | 308)
            ) {
                let header = &response["headers"]["location"];
                let location = header
                    .as_str()
                    .or_else(|| header.as_array().filter(|values| values.len() == 1)?[0].as_str());
                if let Some(location) = location.filter(|value| {
                    !value.is_empty()
                        && value.len() <= MAX_URL_BYTES
                        && !value
                            .chars()
                            .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
                }) && let Ok(destination) = url.join(location)
                    && let Some(destination) = http_url(destination.as_str())
                {
                    push_indicator(&mut indicators, Basis::HttpRedirect, destination.as_str());
                }
            }
        }
    }

    let scripts = evidence
        .iter()
        .find(|item| item["module"] == "web_assets" && item["status"] == "success")
        .and_then(|item| item.pointer("/result/js"))
        .and_then(Value::as_array);
    for script in scripts.into_iter().flatten().take(MAX_INDICATORS) {
        if script["status"] == "success"
            && let Some(hash) = script["hash_sha256"].as_str()
        {
            push_indicator(&mut indicators, Basis::JavascriptSha256, hash);
        }
    }
    indicators
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_the_original_request_redirect_and_full_script_digest() {
        let hash = "B".repeat(64);
        let data = json!({"schema_version": 2, "evidence": [
            {"module": "https", "status": "success", "result": {
                "redirect_response_chain": [{
                    "request": {"url": {"scheme": "https", "host": "[2001:db8::1]:8443",
                        "path": "/start/next", "raw_path": "/start%2Fnext", "raw_query": "one=2"}},
                    "status_code": 302, "headers": {"location": ["../download.js#note"]}
                }],
                "response": {"request": {"url": "https://different.example/last"}, "status_code": 200}
            }},
            {"module": "web_assets", "status": "success", "result": {
                "landing": {"url": "https://different.example/"},
                "js": [
                    {"status": "truncated", "hash_sha256": "A".repeat(64)},
                    {"status": "success", "hash_sha256": hash},
                    {"status": "success", "hash_sha256": "invalid"},
                    {"status": "success", "hash_md5": "2".repeat(32)}
                ]
            }}
        ]});
        let indicators = extract(Some(&data));
        assert_eq!(indicators.len(), 3);
        assert_eq!(indicators[0].basis, Basis::HttpRequest);
        assert_eq!(
            indicators[0].value,
            "https://[2001:db8::1]:8443/start%2Fnext?one=2"
        );
        assert_eq!(indicators[1].basis, Basis::HttpRedirect);
        assert_eq!(
            indicators[1].value,
            "https://[2001:db8::1]:8443/download.js"
        );
        assert_eq!(indicators[2].basis, Basis::JavascriptSha256);
        assert_eq!(indicators[2].value, "b".repeat(64));
    }

    #[test]
    fn ignores_non_redirect_location_headers_and_unsafe_request_urls() {
        let mut data = json!({"schema_version": 2, "evidence": [
            {"module": "http", "status": "success", "result": {"response": {
                "request":{"url": "http://asset.example/"},
                "status_code": 200, "headers":{"location":["https://other.example/"]}
            }}}
        ]});
        assert_eq!(extract(Some(&data)).len(), 1);
        data["evidence"][0]["result"]["response"]["request"]["url"] =
            json!("http://user:secret@asset.example/");
        assert!(extract(Some(&data)).is_empty());
    }
}

pub(crate) async fn annotate_web(
    pool: &deadpool_postgres::Pool,
    targets: &[(Vec<Indicator>, Option<i64>)],
) -> Vec<Option<WebIntel>> {
    let mut results = Vec::with_capacity(targets.len());
    for batch in targets.chunks(BATCH_ENDPOINTS) {
        let keys = batch
            .iter()
            .map(|(indicators, _)| {
                indicators
                    .iter()
                    .take(MAX_INDICATORS)
                    .map(|indicator| (indicator.basis.kind().to_owned(), indicator.value.clone()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        if keys.iter().all(Vec::is_empty) {
            results.extend(batch.iter().map(|_| None));
            continue;
        }
        for ((indicators, observed_at), mut annotation) in
            batch.iter().zip(annotate(pool, &keys).await)
        {
            let Some(observed_at) = observed_at.filter(|_| !indicators.is_empty()) else {
                results.push(None);
                continue;
            };
            for record in annotation
                .matches
                .iter_mut()
                .chain(&mut annotation.expired_matches)
            {
                if let Some(indicator) = indicators.iter().find(|indicator| {
                    record["type"] == indicator.basis.kind() && record["value"] == indicator.value
                }) {
                    record["observation_basis"] = serde_json::json!(indicator.basis);
                }
            }
            results.push(Some(WebIntel {
                observed_at,
                annotation,
            }));
        }
    }
    results
}
