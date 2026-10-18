//! Passive technology identification from bounded, protocol-owned HTTP evidence.
use regex::Regex;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

pub(crate) const RULESET_REVISION: i64 = 2;
pub(crate) const RULESET_VERSION: &str = "2026-10-18.2";
const MAX_BODY: usize = 256 * 1024;
const MAX_FEATURES: usize = 512;
const MAX_TEXT: usize = 4096;
const MAX_TECHNOLOGIES: usize = 64;
const MAX_EVIDENCE: usize = 8;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct WebEvidence {
    pub rule_id: String,
    pub module: String,
    pub field_path: String,
    pub excerpt: String,
    pub observation_ref: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct Technology {
    pub id: String,
    pub name: String,
    pub category: String,
    pub version: Option<String>,
    pub version_conflict: bool,
    pub confidence: String,
    pub basis: String,
    pub usage: String,
    pub evidence: Vec<WebEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct WebInference {
    pub status: String,
    pub inference_scope: String,
    pub technologies: Vec<Technology>,
    pub truncated: bool,
    pub ruleset_revision: i64,
    pub ruleset_version: String,
    pub observed_at: Option<i64>,
    pub stale: bool,
}

impl WebInference {
    pub(crate) fn pending(at: i64) -> Self {
        Self {
            status: "pending".into(),
            inference_scope: "ip_endpoint".into(),
            technologies: vec![],
            truncated: false,
            ruleset_revision: RULESET_REVISION,
            ruleset_version: RULESET_VERSION.into(),
            observed_at: Some(at),
            stale: false,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    id: String,
    technology: String,
    name: String,
    category: String,
    source: String,
    #[serde(default)]
    field: String,
    #[serde(default)]
    selector: String,
    #[serde(default)]
    attribute: String,
    pattern: String,
    #[serde(default)]
    version_group: Option<usize>,
    confidence: String,
    usage: String,
}

struct CompiledRule {
    rule: Rule,
    pattern: Regex,
    selector: Option<Selector>,
}

static RULES: LazyLock<Vec<CompiledRule>> = LazyLock::new(|| {
    let rules: Vec<Rule> = serde_json::from_str(include_str!("web_detection/rules.json"))
        .expect("embedded Web rules must be valid");
    let mut ids = BTreeSet::new();
    rules
        .into_iter()
        .map(|rule| {
            assert!(ids.insert(rule.id.clone()), "duplicate Web rule ID");
            assert!(matches!(
                rule.source.as_str(),
                "header" | "cookie_name" | "selector"
            ));
            assert!(matches!(rule.confidence.as_str(), "medium" | "high"));
            let pattern = Regex::new(&rule.pattern).expect("embedded Web regex");
            assert!(
                rule.version_group
                    .is_none_or(|g| g > 0 && g < pattern.captures_len())
            );
            let selector = (rule.source == "selector")
                .then(|| Selector::parse(&rule.selector).expect("embedded CSS selector"));
            CompiledRule {
                rule,
                pattern,
                selector,
            }
        })
        .collect()
});

#[derive(Default)]
struct Accumulator {
    technologies: BTreeMap<String, Technology>,
    versions: BTreeMap<String, BTreeSet<String>>,
    truncated: bool,
}

impl Accumulator {
    fn apply(
        &mut self,
        compiled: &CompiledRule,
        text: &str,
        module: &str,
        path: &str,
        reference: Option<&str>,
    ) {
        let rule = &compiled.rule;
        let (text, truncated) = bounded(text, MAX_TEXT);
        self.truncated |= truncated;
        let Some(captures) = compiled.pattern.captures(text) else {
            return;
        };
        if !self.technologies.contains_key(&rule.technology)
            && self.technologies.len() >= MAX_TECHNOLOGIES
        {
            self.truncated = true;
            return;
        }
        let item = self
            .technologies
            .entry(rule.technology.clone())
            .or_insert_with(|| Technology {
                id: rule.technology.clone(),
                name: rule.name.clone(),
                category: rule.category.clone(),
                version: None,
                version_conflict: false,
                confidence: rule.confidence.clone(),
                basis: "direct".into(),
                usage: rule.usage.clone(),
                evidence: vec![],
            });
        if rule.confidence == "high" {
            item.confidence = "high".into();
        }
        if rule.usage != item.usage {
            item.usage = "multiple_evidence_types".into();
        }
        if let Some(version) = rule.version_group.and_then(|g| captures.get(g)) {
            let version = version.as_str();
            if version.len() <= 64
                && version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_+".contains(&b))
            {
                self.versions
                    .entry(rule.technology.clone())
                    .or_default()
                    .insert(version.into());
            }
        }
        // Store only the matching feature, never the full header, Cookie value,
        // resource query string or raw page contents.
        let excerpt = if rule.attribute.is_empty() && rule.source == "selector" {
            rule.selector.clone()
        } else {
            captures
                .get(0)
                .map(|m| m.as_str())
                .unwrap_or("")
                .chars()
                .take(160)
                .collect()
        };
        let evidence = WebEvidence {
            rule_id: rule.id.clone(),
            module: module.into(),
            field_path: path.into(),
            excerpt,
            observation_ref: reference.map(str::to_owned),
        };
        if !item.evidence.contains(&evidence) {
            if item.evidence.len() < MAX_EVIDENCE {
                item.evidence.push(evidence);
            } else {
                self.truncated = true;
            }
        }
    }
}

fn bounded(text: &str, bytes: usize) -> (&str, bool) {
    let mut end = text.len().min(bytes);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], end < text.len())
}

fn extract(
    out: &mut Accumulator,
    module: &str,
    result: &Value,
    prefix: &str,
    reference: Option<&str>,
) -> bool {
    if !matches!(module, "http" | "https") {
        return false;
    }
    let Some(response) = result.get("response").and_then(Value::as_object) else {
        out.truncated = true;
        return true;
    };
    out.truncated |= response.get("body_truncated").and_then(Value::as_bool) == Some(true);
    if let Some(headers) = response.get("headers").and_then(Value::as_object) {
        out.truncated |= headers.len() > MAX_FEATURES;
        for (header_name, values) in headers.iter().take(MAX_FEATURES) {
            let name = header_name.to_ascii_lowercase().replace('_', "-");
            // Whitelist names first: unknown header values are never scanned.
            let relevant: Vec<_> = RULES
                .iter()
                .filter(|r| r.rule.source == "header" && r.rule.field == name)
                .collect();
            if relevant.is_empty() && name != "set-cookie" {
                continue;
            }
            let values: Vec<_> = if let Some(text) = values.as_str() {
                vec![text]
            } else {
                out.truncated |= values.as_array().is_some_and(|items| items.len() > 16);
                values
                    .as_array()
                    .into_iter()
                    .flatten()
                    .take(16)
                    .filter_map(Value::as_str)
                    .collect()
            };
            for text in values {
                let (text, truncated) = bounded(text, MAX_TEXT);
                out.truncated |= truncated;
                let path = format!(
                    "{prefix}/response/headers/{}",
                    header_name.replace('~', "~0").replace('/', "~1")
                );
                for rule in &relevant {
                    out.apply(rule, text, module, &path, reference);
                }
                if name == "set-cookie"
                    && let Some((cookie, _)) = text.split(';').next().unwrap_or("").split_once('=')
                {
                    for rule in RULES.iter().filter(|r| r.rule.source == "cookie_name") {
                        out.apply(rule, cookie.trim(), module, &path, reference);
                    }
                }
            }
        }
    }
    if let Some(body) = response.get("body").and_then(Value::as_str) {
        let (body, truncated) = bounded(body, MAX_BODY);
        out.truncated |= truncated;
        let html = Html::parse_document(body);
        // A fixed rule set and body budget bound parsing and selector work.
        for rule in RULES.iter().filter(|r| r.selector.is_some()) {
            for (index, element) in html
                .select(rule.selector.as_ref().unwrap())
                .take(MAX_FEATURES + 1)
                .enumerate()
            {
                if index == MAX_FEATURES {
                    out.truncated = true;
                    break;
                }
                let value = if rule.rule.attribute.is_empty() {
                    Some("")
                } else {
                    element.value().attr(&rule.rule.attribute)
                };
                if let Some(value) = value {
                    // Resource rules operate on the URL path only. A library name
                    // in a hostname, query or fragment is not a resource identity.
                    let resource = rule.rule.usage == "referenced_resource";
                    let clean;
                    let value = if resource {
                        clean = reqwest::Url::parse(value)
                            .or_else(|_| {
                                reqwest::Url::parse("https://evidence.invalid/")
                                    .unwrap()
                                    .join(value)
                            })
                            .ok();
                        let Some(url) = clean.as_ref() else { continue };
                        if !matches!(url.scheme(), "http" | "https") {
                            continue;
                        }
                        url.path()
                    } else {
                        value
                    };
                    out.apply(
                        rule,
                        value,
                        module,
                        &format!(
                            "{prefix}/response/body:{}@{}",
                            rule.rule.selector, rule.rule.attribute
                        ),
                        reference,
                    );
                }
            }
        }
    }
    true
}

pub(crate) fn infer(
    service: Option<&str>,
    _banner: Option<&str>,
    data: Option<&Value>,
    _port: u16,
    at: i64,
    reference: Option<&str>,
) -> WebInference {
    let mut inference = WebInference::pending(at);
    inference.status = "not_web".into();
    let Some(data) = data else {
        if matches!(service, Some("http" | "https")) {
            inference.status = "unknown".into();
        }
        return inference;
    };
    if data
        .get("schema_version")
        .is_some_and(|v| v.as_u64() != Some(2))
    {
        inference.status = "unsupported".into();
        return inference;
    }
    let mut out = Accumulator::default();
    let mut found = false;
    if let Some(items) = data.get("evidence").and_then(Value::as_array) {
        out.truncated |= items.len() > 32;
        for (i, item) in items.iter().take(32).enumerate() {
            let module = item.get("module").and_then(Value::as_str).unwrap_or("");
            if let Some(result) = item.get("result") {
                found |= extract(
                    &mut out,
                    module,
                    result,
                    &format!("/data/evidence/{i}/result"),
                    reference,
                );
                if matches!(module, "http" | "https") {
                    out.truncated |= item.get("truncated").and_then(Value::as_bool) == Some(true);
                }
            }
        }
    }
    if data.get("schema_version").is_none()
        && let Some(result) = data.get("result")
    {
        found |= extract(
            &mut out,
            service.unwrap_or(""),
            result,
            "/data/result",
            reference,
        );
    }
    for (id, item) in &mut out.technologies {
        if let Some(versions) = out.versions.get(id) {
            item.version_conflict = versions.len() > 1;
            if versions.len() == 1 {
                item.version = versions.first().cloned();
            }
        }
    }
    inference.status = if !found {
        if matches!(service, Some("http" | "https")) {
            "unknown"
        } else {
            "not_web"
        }
    } else if out.truncated {
        "partial"
    } else if out.technologies.is_empty() {
        "unknown"
    } else {
        "identified"
    }
    .into();
    inference.technologies = out.technologies.into_values().collect();
    inference.truncated = out.truncated;
    inference
}

pub(crate) fn endpoint_view(
    value: Option<WebInference>,
    last_seen: i64,
    now: i64,
) -> Option<WebInference> {
    value.map(|mut web| {
        web.stale = web
            .observed_at
            .is_none_or(|at| at < last_seen || now.saturating_sub(at) > 30 * 86_400_000);
        web
    })
}

pub(crate) fn mapping() -> Value {
    json!({"type":"object","dynamic":"strict","properties":{
        "status":{"type":"keyword"},"inference_scope":{"type":"keyword"},"truncated":{"type":"boolean"},
        "ruleset_revision":{"type":"long"},"ruleset_version":{"type":"keyword"},"observed_at":{"type":"long"},"stale":{"type":"boolean"},
        "technologies":{"type":"nested","dynamic":"strict","properties":{
            "id":{"type":"keyword"},"name":{"type":"keyword"},"category":{"type":"keyword"},"version":{"type":"keyword"},
            "version_conflict":{"type":"boolean"},"confidence":{"type":"keyword"},"basis":{"type":"keyword"},"usage":{"type":"keyword"},
            "evidence":{"type":"object","enabled":false}
        }}
    }})
}

#[cfg(test)]
mod tests;
