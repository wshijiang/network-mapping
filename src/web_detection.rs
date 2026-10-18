//! Passive technology identification from bounded, protocol-owned HTTP evidence.
use regex::Regex;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

pub(crate) const RULESET_REVISION: i64 = 5;
pub(crate) const RULESET_VERSION: &str = "2026-10-18.5";
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

mod protocol;

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Condition {
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
    #[serde(default)]
    pattern: String,
    #[serde(default)]
    version_group: Option<usize>,
    confidence: String,
    usage: String,
    #[serde(default)]
    all: Vec<Condition>,
    #[serde(default)]
    any: Vec<Condition>,
    #[serde(default, rename = "not")]
    exclusions: Vec<Condition>,
}

struct CompiledCondition {
    condition: Condition,
    pattern: Regex,
    selector: Option<Selector>,
    resource: bool,
}

struct CompiledRule {
    rule: Rule,
    primary: Option<CompiledCondition>,
    all: Vec<CompiledCondition>,
    any: Vec<CompiledCondition>,
    exclusions: Vec<CompiledCondition>,
}

fn compile_condition(condition: Condition, usage: &str) -> Result<CompiledCondition, String> {
    if condition.pattern.is_empty() {
        return Err("condition pattern must be explicit".into());
    }
    let header = matches!(condition.source.as_str(), "header" | "header_name");
    let dom = matches!(condition.source.as_str(), "selector" | "resource");
    if (!header && !condition.field.is_empty())
        || (!dom && (!condition.selector.is_empty() || !condition.attribute.is_empty()))
    {
        return Err("condition fields do not match its source".into());
    }
    if !matches!(
        condition.source.as_str(),
        "header"
            | "header_name"
            | "cookie_name"
            | "selector"
            | "resource"
            | "title"
            | "s3_xml"
            | "git_advertisement"
    ) {
        return Err("unsupported condition source".into());
    }
    if condition.pattern.len() > MAX_TEXT {
        return Err("condition pattern too long".into());
    }
    if matches!(condition.source.as_str(), "header" | "header_name")
        && (condition.field.is_empty()
            || !condition
                .field
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
    {
        return Err("header condition requires a normalized field".into());
    }
    if condition.source == "header" && condition.field == "set-cookie" {
        return Err("Cookie values cannot be fingerprint evidence".into());
    }
    let resource = condition.source == "resource"
        || (condition.source == "selector" && usage == "referenced_resource");
    if resource && !matches!(condition.attribute.as_str(), "src" | "href") {
        return Err("resource condition needs src or href".into());
    }
    let selector = match condition.source.as_str() {
        "selector" | "resource" => {
            Some(Selector::parse(&condition.selector).map_err(|_| "invalid CSS selector")?)
        }
        "title" => {
            if !condition.selector.is_empty() || !condition.attribute.is_empty() {
                return Err("title source has a fixed selector".into());
            }
            Some(Selector::parse("title").expect("fixed title selector"))
        }
        _ => None,
    };
    let pattern = Regex::new(&condition.pattern).map_err(|e| e.to_string())?;
    if condition
        .version_group
        .is_some_and(|g| g == 0 || g >= pattern.captures_len())
    {
        return Err("invalid version capture group".into());
    }
    if matches!(
        condition.source.as_str(),
        "header_name" | "s3_xml" | "git_advertisement"
    ) && condition.version_group.is_some()
    {
        return Err("protocol markers do not establish software versions".into());
    }
    Ok(CompiledCondition {
        condition,
        pattern,
        selector,
        resource,
    })
}

fn compile_rules(input: &str) -> Result<Vec<CompiledRule>, String> {
    let rules: Vec<Rule> = serde_json::from_str(input).map_err(|e| e.to_string())?;
    if rules.len() > 512 {
        return Err("too many embedded rules".into());
    }
    let mut ids = BTreeSet::new();
    rules
        .into_iter()
        .map(|rule| {
            if !ids.insert(rule.id.clone()) {
                return Err("duplicate Web rule ID".into());
            }
            if rule.technology.is_empty()
                || !rule
                    .technology
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err("invalid technology ID".into());
            }
            if !matches!(rule.confidence.as_str(), "medium" | "high")
                || !matches!(
                    rule.usage.as_str(),
                    "response_marker" | "referenced_resource"
                )
            {
                return Err("invalid rule metadata".into());
            }
            let composite = rule.source == "composite";
            if rule.all.len() + rule.any.len() + rule.exclusions.len() + usize::from(!composite) > 8
            {
                return Err("at most eight conditions per rule".into());
            }
            if composite && (rule.all.is_empty() && rule.any.is_empty()) {
                return Err("composite rule needs positive evidence".into());
            }
            if composite
                && (!rule.pattern.is_empty()
                    || !rule.field.is_empty()
                    || !rule.selector.is_empty()
                    || !rule.attribute.is_empty()
                    || rule.version_group.is_some())
            {
                return Err("composite rules use condition groups".into());
            }
            let primary = if composite {
                None
            } else {
                Some(compile_condition(
                    Condition {
                        source: rule.source.clone(),
                        field: rule.field.clone(),
                        selector: rule.selector.clone(),
                        attribute: rule.attribute.clone(),
                        pattern: rule.pattern.clone(),
                        version_group: rule.version_group,
                    },
                    &rule.usage,
                )?)
            };
            if rule.exclusions.iter().any(|condition| {
                matches!(condition.source.as_str(), "s3_xml" | "git_advertisement")
            }) {
                return Err("protocol parse failure cannot prove a negative condition".into());
            }
            let compile = |items: &[Condition]| {
                items
                    .iter()
                    .cloned()
                    .map(|c| compile_condition(c, &rule.usage))
                    .collect::<Result<Vec<_>, String>>()
            };
            Ok(CompiledRule {
                primary,
                all: compile(&rule.all)?,
                any: compile(&rule.any)?,
                exclusions: compile(&rule.exclusions)?,
                rule,
            })
        })
        .collect()
}

static RULES: LazyLock<Vec<CompiledRule>> = LazyLock::new(|| {
    compile_rules(include_str!("web_detection/rules.json"))
        .expect("embedded Web rules must be valid")
});

struct Hit {
    path: String,
    excerpt: String,
    version: Option<String>,
    usage: &'static str,
}

struct Matches {
    hits: Vec<Hit>,
    complete: bool,
}

#[derive(Default)]
struct Accumulator {
    technologies: BTreeMap<String, Technology>,
    versions: BTreeMap<String, BTreeSet<String>>,
    truncated: bool,
}

impl Accumulator {
    fn apply(&mut self, rule: &Rule, hit: Hit, module: &str, reference: Option<&str>) {
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
                usage: hit.usage.into(),
                evidence: vec![],
            });
        if rule.confidence == "high" {
            item.confidence = "high".into();
        }
        if hit.usage != item.usage {
            item.usage = "multiple_evidence_types".into();
        }
        if let Some(version) = hit.version {
            self.versions
                .entry(rule.technology.clone())
                .or_default()
                .insert(version);
        }
        let evidence = WebEvidence {
            rule_id: rule.id.clone(),
            module: module.into(),
            field_path: hit.path,
            excerpt: hit.excerpt,
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

struct Header<'a> {
    name: String,
    path: String,
    values: Vec<&'a str>,
}

struct ResponseView<'a> {
    headers: Vec<Header<'a>>,
    html: Option<Html>,
    s3_xml: Option<String>,
    git_advertisement: Option<&'static str>,
    complete: bool,
}

impl<'a> ResponseView<'a> {
    fn new(
        response: &'a serde_json::Map<String, Value>,
        prefix: &str,
        upstream_truncated: bool,
    ) -> Self {
        let mut complete = !upstream_truncated
            && response.get("body_truncated").and_then(Value::as_bool) != Some(true);
        let mut headers = Vec::new();
        let mut count = 0;
        if let Some(fields) = response.get("headers").and_then(Value::as_object) {
            complete &= fields.len() <= MAX_FEATURES;
            for (name, value) in fields.iter().take(MAX_FEATURES) {
                if name.len() > MAX_TEXT {
                    complete = false;
                    continue;
                }
                let raw: Vec<_> = if let Some(text) = value.as_str() {
                    vec![text]
                } else {
                    complete &= value
                        .as_array()
                        .is_some_and(|v| v.len() <= 16 && v.iter().all(Value::is_string));
                    value
                        .as_array()
                        .into_iter()
                        .flatten()
                        .take(16)
                        .filter_map(Value::as_str)
                        .collect()
                };
                let mut values = Vec::new();
                for text in raw {
                    if count == MAX_FEATURES {
                        complete = false;
                        break;
                    }
                    count += 1;
                    let (text, truncated) = bounded(text, MAX_TEXT);
                    complete &= !truncated;
                    if truncated {
                        continue;
                    }
                    values.push(text);
                }
                if !values.is_empty() {
                    headers.push(Header {
                        name: name.to_ascii_lowercase().replace('_', "-"),
                        path: format!(
                            "{prefix}/response/headers/{}",
                            name.replace('~', "~0").replace('/', "~1")
                        ),
                        values,
                    });
                }
            }
        } else {
            complete = false;
        }
        let body = response.get("body").and_then(Value::as_str).map(|text| {
            let (text, truncated) = bounded(text, MAX_BODY);
            complete &= !truncated;
            text
        });
        if body.is_none() {
            complete = false;
        }
        let content_types: Vec<_> = headers
            .iter()
            .filter(|h| h.name == "content-type")
            .flat_map(|h| h.values.iter().copied())
            .collect();
        let media_types: BTreeSet<_> = content_types
            .iter()
            .map(|t| {
                t.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase()
            })
            .collect();
        let xml_type = media_types.len() == 1
            && media_types
                .first()
                .is_some_and(|t| matches!(t.as_str(), "application/xml" | "text/xml"));
        let s3_xml = if xml_type {
            body.and_then(protocol::s3_xml_feature)
        } else {
            None
        };
        let git_advertisement =
            body.and_then(|body| protocol::git_advertisement_feature(&content_types, body));
        Self {
            headers,
            html: body.map(Html::parse_document),
            s3_xml,
            git_advertisement,
            complete,
        }
    }
}

fn capture(
    out: &mut Matches,
    compiled: &CompiledCondition,
    text: &str,
    path: String,
    existence: bool,
) {
    let (text, truncated) = bounded(text, MAX_TEXT);
    out.complete &= !truncated;
    if truncated {
        return;
    }
    let Some(captures) = compiled.pattern.captures(text) else {
        return;
    };
    let version = compiled
        .condition
        .version_group
        .and_then(|g| captures.get(g))
        .map(|m| m.as_str())
        .filter(|v| {
            !v.is_empty()
                && v.len() <= 64
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_+".contains(&b))
        })
        .map(str::to_owned);
    let excerpt = if existence {
        compiled.condition.selector.chars().take(160).collect()
    } else {
        captures
            .get(0)
            .map(|m| m.as_str())
            .unwrap_or("")
            .chars()
            .take(160)
            .collect()
    };
    out.hits.push(Hit {
        path,
        excerpt,
        version,
        usage: if compiled.resource {
            "referenced_resource"
        } else {
            "response_marker"
        },
    });
}

fn find_matches(compiled: &CompiledCondition, view: &ResponseView<'_>, prefix: &str) -> Matches {
    let condition = &compiled.condition;
    let mut out = Matches {
        hits: vec![],
        complete: view.complete,
    };
    match condition.source.as_str() {
        "header" | "header_name" | "cookie_name" => {
            for header in &view.headers {
                let relevant = if condition.source == "cookie_name" {
                    header.name == "set-cookie"
                } else {
                    header.name == condition.field
                };
                if !relevant {
                    continue;
                }
                if condition.source == "header_name" {
                    capture(&mut out, compiled, &header.name, header.path.clone(), false);
                    continue;
                }
                for value in &header.values {
                    let text = if condition.source == "cookie_name" {
                        let Some((name, _)) = value.split(';').next().unwrap_or("").split_once('=')
                        else {
                            continue;
                        };
                        name.trim()
                    } else {
                        value.trim()
                    };
                    capture(&mut out, compiled, text, header.path.clone(), false);
                }
            }
        }
        "selector" | "resource" | "title" => {
            if let Some(html) = &view.html {
                for (index, element) in html
                    .select(compiled.selector.as_ref().expect("compiled selector"))
                    .take(MAX_FEATURES + 1)
                    .enumerate()
                {
                    if index == MAX_FEATURES {
                        out.complete = false;
                        break;
                    }
                    if condition.source == "title" {
                        let text: String = element
                            .text()
                            .flat_map(str::chars)
                            .take(MAX_TEXT + 1)
                            .collect();
                        if text.chars().count() > MAX_TEXT {
                            out.complete = false;
                            continue;
                        }
                        capture(
                            &mut out,
                            compiled,
                            text.trim(),
                            format!("{prefix}/response/body:title"),
                            false,
                        );
                        continue;
                    }
                    let Some(value) = (if condition.attribute.is_empty() {
                        Some("")
                    } else {
                        element.value().attr(&condition.attribute)
                    }) else {
                        continue;
                    };
                    let clean;
                    let value = if compiled.resource {
                        clean = reqwest::Url::parse(value)
                            .or_else(|_| {
                                reqwest::Url::parse("https://evidence.invalid/")
                                    .expect("fixed base URL")
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
                    capture(
                        &mut out,
                        compiled,
                        value,
                        format!(
                            "{prefix}/response/body:{}@{}",
                            condition.selector, condition.attribute
                        ),
                        condition.attribute.is_empty(),
                    );
                }
            }
        }
        "s3_xml" | "git_advertisement" => {
            let feature = if condition.source == "s3_xml" {
                view.s3_xml.as_deref()
            } else {
                view.git_advertisement
            };
            if let Some(feature) = feature {
                capture(
                    &mut out,
                    compiled,
                    feature,
                    format!("{prefix}/response/body:{}", condition.source),
                    false,
                );
            }
        }
        _ => unreachable!("compiled source whitelist"),
    }
    out
}

fn apply_rules(
    out: &mut Accumulator,
    rules: &[CompiledRule],
    view: &ResponseView<'_>,
    module: &str,
    prefix: &str,
    reference: Option<&str>,
) {
    out.truncated |= !view.complete;
    for compiled in rules {
        let mut positive = Vec::new();
        if let Some(primary) = &compiled.primary {
            let matches = find_matches(primary, view, prefix);
            out.truncated |= !matches.complete;
            if matches.hits.is_empty() {
                continue;
            }
            positive.extend(matches.hits);
        }
        let mut eligible = true;
        for condition in &compiled.all {
            let matches = find_matches(condition, view, prefix);
            out.truncated |= !matches.complete;
            if matches.hits.is_empty() {
                eligible = false;
                break;
            }
            positive.extend(matches.hits);
        }
        if !eligible {
            continue;
        }
        if !compiled.any.is_empty() {
            let mut matched = false;
            for condition in &compiled.any {
                let matches = find_matches(condition, view, prefix);
                out.truncated |= !matches.complete;
                matched |= !matches.hits.is_empty();
                positive.extend(matches.hits);
            }
            if !matched {
                continue;
            }
        }
        for condition in &compiled.exclusions {
            let matches = find_matches(condition, view, prefix);
            out.truncated |= !matches.complete;
            // Truncated or missing input cannot establish a negative condition.
            if !matches.complete || !matches.hits.is_empty() {
                eligible = false;
                break;
            }
        }
        if eligible {
            for hit in positive {
                out.apply(&compiled.rule, hit, module, reference);
            }
        }
    }
}

fn extract(
    out: &mut Accumulator,
    module: &str,
    result: &Value,
    prefix: &str,
    reference: Option<&str>,
    upstream_truncated: bool,
) -> bool {
    if !matches!(module, "http" | "https") {
        return false;
    }
    let Some(response) = result.get("response").and_then(Value::as_object) else {
        out.truncated = true;
        return true;
    };
    let upstream_truncated =
        upstream_truncated || result.get("truncated").and_then(Value::as_bool) == Some(true);
    let view = ResponseView::new(response, prefix, upstream_truncated);
    apply_rules(out, &RULES, &view, module, prefix, reference);
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
                    item.get("truncated").and_then(Value::as_bool) == Some(true),
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
            false,
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
