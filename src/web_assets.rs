//! Web asset facts (favicon / external JS) derived from scanner `web_assets`
//! evidence at projection time. Favicon MD5 is computed here from the stored
//! bytes so an algorithm fix can be re-projected without re-scanning; JS MD5
//! arrives pre-computed from the scanner (JS content is never uploaded).
//!
//! Observations without `web_assets` evidence (older scanners) fall back to
//! passive extraction of favicon URLs and JS paths from the stored body, so
//! `js_name` search works for historical data without hashes or images.

use base64::Engine as _;
use md5::{Digest, Md5};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::LazyLock;

const MAX_JS_NAMES: usize = 64;
const MAX_PATH_CHARS: usize = 512;
const MAX_URL_CHARS: usize = 2048;
/// Defensive decode cap; the scanner already bounds favicon bytes (default 64KB).
const MAX_FAVICON_DECODE_BYTES: usize = 1_048_576;
const MAX_BODY: usize = 256 * 1024;

static LINK_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("link[rel][href]").expect("link selector is valid"));
static SCRIPT_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("script[src]").expect("script selector is valid"));

/// Stored favicon payload (indexed disabled; served through the favicon API).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct FaviconStored {
    #[serde(default)]
    pub data_base64: String,
    #[serde(default)]
    pub content_type: String,
    #[serde(default)]
    pub size: usize,
}

/// Search/display view without the base64 payload.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct FaviconView {
    pub content_type: String,
    pub size: usize,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct WebAssets {
    pub icon_md5: Option<String>,
    pub favicon_url: Option<String>,
    pub favicon: Option<FaviconStored>,
    pub js_names: Vec<String>,
    pub js_md5s: Vec<String>,
}

pub(crate) fn md5_hex(bytes: &[u8]) -> String {
    format!("{:x}", Md5::digest(bytes))
}

fn web_assets_result(data: &Value) -> Option<&Value> {
    data.get("evidence")
        .and_then(Value::as_array)?
        .iter()
        .filter(|item| item.get("module").and_then(Value::as_str) == Some("web_assets"))
        .find_map(|item| item.get("result"))
}

/// Landing-page body captured by the enrichment pass when the probe hit a
/// redirect or empty body; used by `search_content` as the http_body fallback.
pub(crate) fn landing(data: &Value) -> Option<(String, bool)> {
    let landing = web_assets_result(data)?.get("landing")?;
    let body = landing.get("body").and_then(Value::as_str)?;
    if body.trim().is_empty() {
        return None;
    }
    let truncated = landing
        .get("body_truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Some((body.to_owned(), truncated))
}

fn bounded_text(value: &str, chars: usize) -> String {
    value.chars().take(chars).collect()
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !value.is_empty() && values.len() < MAX_JS_NAMES && !values.contains(&value) {
        values.push(value);
    }
}

/// Normalize a favicon/JS reference to a path for searching. Relative refs are
/// resolved against a placeholder base; absolute URLs contribute their path.
fn reference_path(reference: &str) -> Option<String> {
    let reference = reference.trim();
    if reference.is_empty() || reference.len() > MAX_URL_CHARS {
        return None;
    }
    let lower = reference.to_ascii_lowercase();
    if lower.starts_with("data:") || lower.starts_with("javascript:") || lower.starts_with("blob:")
    {
        return None;
    }
    let base = reqwest::Url::parse("http://placeholder.local/").ok()?;
    let url = base.join(reference).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let path = bounded_text(url.path(), MAX_PATH_CHARS);
    (!path.is_empty()).then_some(path)
}

/// Passive fallback for observations without enrichment evidence.
fn passive_from_body(data: &Value) -> WebAssets {
    let mut assets = WebAssets::default();
    let Some(body) = crate::search_content::find_string_by_key(data, &["body"], 0) else {
        return assets;
    };
    let body = &body[..body.len().min(MAX_BODY)];
    let document = Html::parse_document(body);
    for element in document.select(&LINK_SELECTOR) {
        let rel = element
            .value()
            .attr("rel")
            .unwrap_or("")
            .to_ascii_lowercase();
        if !rel.contains("icon") {
            continue;
        }
        if let Some(href) = element.value().attr("href")
            && let Some(path) = reference_path(href)
        {
            assets.favicon_url = Some(bounded_text(href, MAX_URL_CHARS));
            let _ = path;
            break;
        }
    }
    for element in document.select(&SCRIPT_SELECTOR) {
        if let Some(src) = element.value().attr("src")
            && let Some(path) = reference_path(src)
        {
            push_unique(&mut assets.js_names, path);
        }
    }
    assets
}

pub(crate) fn extract(data: Option<&Value>) -> WebAssets {
    let Some(data) = data else {
        return WebAssets::default();
    };
    let Some(result) = web_assets_result(data) else {
        return passive_from_body(data);
    };
    let mut assets = WebAssets::default();
    if let Some(favicon) = result.get("favicon").filter(|value| value.is_object()) {
        let stored: FaviconStored = serde_json::from_value(favicon.clone()).unwrap_or_default();
        assets.favicon_url = favicon
            .get("url")
            .and_then(Value::as_str)
            .map(|url| bounded_text(url, MAX_URL_CHARS));
        if !stored.data_base64.is_empty()
            && stored.data_base64.len() <= MAX_FAVICON_DECODE_BYTES * 4 / 3 + 4
            && let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&stored.data_base64)
            && !bytes.is_empty()
            && bytes.len() <= MAX_FAVICON_DECODE_BYTES
        {
            assets.icon_md5 = Some(md5_hex(&bytes));
            assets.favicon = Some(FaviconStored {
                size: bytes.len(),
                content_type: bounded_text(&stored.content_type, 128),
                data_base64: stored.data_base64,
            });
        }
    }
    if let Some(js) = result.get("js").and_then(Value::as_array) {
        for entry in js.iter().take(MAX_JS_NAMES) {
            if let Some(path) = entry.get("path").and_then(Value::as_str) {
                push_unique(&mut assets.js_names, bounded_text(path, MAX_PATH_CHARS));
            }
            if entry.get("status").and_then(Value::as_str) == Some("success")
                && let Some(hash) = entry.get("hash_md5").and_then(Value::as_str)
                && hash.len() == 32
                && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                push_unique(&mut assets.js_md5s, hash.to_ascii_lowercase());
            }
        }
    }
    if assets.favicon.is_none() && assets.js_names.is_empty() {
        // Enrichment ran but found nothing useful; keep passive paths searchable.
        let passive = passive_from_body(data);
        assets.favicon_url = assets.favicon_url.or(passive.favicon_url);
        assets.js_names = passive.js_names;
    }
    assets
}

/// Additive endpoint-index mapping entries (merged into both the index
/// definition and the startup mapping update).
pub(crate) fn mapping() -> Value {
    json!({
        "icon_md5": {"type": "keyword", "normalizer": "lowercase_normalizer", "ignore_above": 64},
        "favicon_url": {"type": "keyword", "ignore_above": 512},
        "favicon": {"type": "object", "enabled": false},
        "js_name": {"type": "wildcard", "copy_to": "js_name_text"},
        "js_name_text": {"type": "text"},
        "js_md5": {"type": "keyword", "normalizer": "lowercase_normalizer", "ignore_above": 64}
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_matches_known_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    fn evidence_with(result: Value) -> Value {
        json!({"schema_version": 2, "evidence": [
            {"module": "https", "result": {"response": {"body": "<html></html>"}}},
            {"module": "web_assets", "status": "success", "result": result}
        ]})
    }

    #[test]
    fn extracts_favicon_hash_and_js_from_evidence() {
        let bytes = b"icon-bytes";
        let data = evidence_with(json!({
            "favicon": {
                "url": "https://192.0.2.1/favicon.ico",
                "content_type": "image/x-icon",
                "size": bytes.len(),
                "data_base64": base64::engine::general_purpose::STANDARD.encode(bytes),
            },
            "js": [
                {"path": "/app.js", "status": "success", "hash_md5": md5_hex(b"js")},
                {"path": "/failed.js", "status": "http_404"},
                {"path": "/app.js", "status": "success", "hash_md5": md5_hex(b"js")}
            ]
        }));
        let assets = extract(Some(&data));
        assert_eq!(assets.icon_md5.as_deref(), Some(md5_hex(bytes).as_str()));
        assert_eq!(assets.favicon.as_ref().unwrap().size, bytes.len());
        assert_eq!(assets.js_names, vec!["/app.js", "/failed.js"]);
        assert_eq!(assets.js_md5s, vec![md5_hex(b"js")]);
    }

    #[test]
    fn invalid_base64_or_hash_is_dropped() {
        let data = evidence_with(json!({
            "favicon": {"url": "u", "content_type": "image/png", "size": 3, "data_base64": "!!!"},
            "js": [{"path": "/a.js", "status": "success", "hash_md5": "not-a-hash"}]
        }));
        let assets = extract(Some(&data));
        assert!(assets.icon_md5.is_none());
        assert!(assets.favicon.is_none());
        assert!(assets.js_md5s.is_empty());
        assert_eq!(assets.js_names, vec!["/a.js"]);
    }

    #[test]
    fn passive_fallback_extracts_paths_without_evidence() {
        let data = json!({"schema_version": 2, "evidence": [
            {"module": "http", "result": {"response": {"body":
                "<html><head><link rel='shortcut icon' href='/old.ico'></head>\
                 <body><script src='/static/jquery.js'></script><script>inline</script></body></html>"}}}
        ]});
        let assets = extract(Some(&data));
        assert!(assets.icon_md5.is_none());
        assert_eq!(assets.favicon_url.as_deref(), Some("/old.ico"));
        assert_eq!(assets.js_names, vec!["/static/jquery.js"]);
    }

    #[test]
    fn landing_body_is_exposed_for_search_content() {
        let data = evidence_with(
            json!({"landing": {"body": "<title>Hi</title>", "body_truncated": true}}),
        );
        let (body, truncated) = landing(&data).unwrap();
        assert!(body.contains("Hi"));
        assert!(truncated);
        assert!(landing(&json!({})).is_none());
    }

    #[test]
    fn reference_paths_skip_data_and_keep_path_only() {
        assert_eq!(reference_path("/a/b.js").as_deref(), Some("/a/b.js"));
        assert_eq!(
            reference_path("https://cdn.example.com/lib/x.js").as_deref(),
            Some("/lib/x.js")
        );
        assert!(reference_path("data:text/javascript,x").is_none());
        assert!(reference_path("").is_none());
    }
}
