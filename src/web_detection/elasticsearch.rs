//! Bounded Elasticsearch REST markers; no cluster names, IDs or error bodies leave this parser.
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct RootInfo {
    version: VersionInfo,
    tagline: String,
}

#[derive(Deserialize)]
struct VersionInfo {
    number: String,
    lucene_version: String,
    build_hash: String,
    distribution: Option<String>,
}

fn release_number(value: &str) -> bool {
    let numeric = value.strip_suffix("-SNAPSHOT").unwrap_or(value);
    let parts: Vec<_> = numeric.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
}

pub(super) fn root_feature(body: &str) -> Option<String> {
    let root: RootInfo = serde_json::from_str(body).ok()?;
    let version = root.version;
    if root.tagline != "You Know, for Search"
        || version
            .distribution
            .as_deref()
            .is_some_and(|v| v != "elasticsearch")
        || !release_number(&version.number)
        || !release_number(&version.lucene_version)
        || !(7..=64).contains(&version.build_hash.len())
        || !version.build_hash.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    Some(format!("Elasticsearch {}", version.number))
}

pub(super) fn explicitly_opensearch(body: &str) -> bool {
    let Ok(root) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    root.pointer("/version/distribution")
        .and_then(Value::as_str)
        == Some("opensearch")
        || root.get("tagline").and_then(Value::as_str)
            == Some("The OpenSearch Project: https://opensearch.org/")
}
