//! Typed predicates over a single verified evidence scope.
use std::sync::LazyLock;

use regex::{Regex, RegexBuilder};
use scraper::{Html, Selector};
use serde::Deserialize;
use serde_json::Value;

use super::{Source, bounded, identifier, short_text};

const MAX_DEPTH: usize = 8;
const MAX_NODES: usize = 2048;
const MAX_DETAILS: usize = 16;
static TITLE: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("head > title").expect("valid title selector"));

pub(super) enum Expression {
    All(Vec<Self>),
    Any(Vec<Self>),
    None(Vec<Self>),
    Test(Box<Test>),
}

pub(super) struct Test {
    field: Field,
    selector: Option<Selector>,
    attribute: Option<String>,
    comparison: Comparison,
    evidence_key: String,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Field {
    SubjectDn,
    IssuerDn,
    SelfSigned,
    SignatureAlgorithm,
    FingerprintSha256,
    ValidityEnd,
    Title,
    Element,
    ElementText,
    ElementAttribute,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTest {
    field: Field,
    selector: Option<String>,
    attribute: Option<String>,
    op: Op,
    value: Option<Scalar>,
    values: Option<Vec<Scalar>>,
    evidence_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Op {
    Eq,
    EqIgnoreAsciiCase,
    In,
    Contains,
    Regex,
    Exists,
}

#[derive(Deserialize, PartialEq)]
#[serde(untagged)]
enum Scalar {
    Text(String),
    Bool(bool),
}

enum Comparison {
    Eq(Scalar),
    EqIgnoreAsciiCase(String),
    In(Vec<Scalar>),
    Contains(String),
    Regex(Regex),
    Exists,
}

#[derive(PartialEq, Eq)]
pub(super) enum Truth {
    True,
    False,
    Unknown,
}

impl Truth {
    fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }
}

pub(super) enum Input<'a> {
    Tls(&'a Value),
    Http(&'a Html),
}

struct Fact {
    value: Scalar,
    excerpt: String,
}

impl Fact {
    fn text(value: &str) -> Self {
        Self {
            value: Scalar::Text(value.into()),
            excerpt: bounded(value),
        }
    }
}

impl Expression {
    pub(super) fn compile(
        raw: Value,
        source: Source,
        path: &str,
        depth: usize,
        nodes: &mut usize,
    ) -> Result<Self, String> {
        *nodes += 1;
        if *nodes > MAX_NODES || depth > MAX_DEPTH {
            return Err(format!("{path}: 超过规则包条件数量或嵌套层数限制"));
        }
        let object = raw
            .as_object()
            .ok_or_else(|| format!("{path}: 条件必须为对象"))?;
        for (group, build) in [
            ("all", Self::All as fn(Vec<Self>) -> Self),
            ("any", Self::Any),
            ("none", Self::None),
        ] {
            if let Some(entries) = object.get(group) {
                if object.len() != 1 {
                    return Err(format!("{path}: 分组节点只允许一个 all、any 或 none 键"));
                }
                let entries = entries
                    .as_array()
                    .filter(|entries| !entries.is_empty())
                    .ok_or_else(|| format!("{path}.{group}: 必须是非空数组"))?;
                let children = entries
                    .iter()
                    .cloned()
                    .enumerate()
                    .map(|(i, child)| {
                        Self::compile(
                            child,
                            source,
                            &format!("{path}.{group}[{i}]"),
                            depth + 1,
                            nodes,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                return Ok(build(children));
            }
        }
        let test: RawTest = serde_json::from_value(raw).map_err(|e| format!("{path}: {e}"))?;
        test.compile(source, path)
            .map(|test| Self::Test(Box::new(test)))
    }

    pub(super) fn evaluate(&self, input: &Input<'_>, details: &mut Vec<(String, String)>) -> Truth {
        let before = details.len();
        let truth = match self {
            Self::All(children) => {
                let mut result = Truth::True;
                for child in children {
                    match child.evaluate(input, details) {
                        Truth::False => {
                            result = Truth::False;
                            break;
                        }
                        Truth::Unknown => result = Truth::Unknown,
                        Truth::True => {}
                    }
                }
                result
            }
            Self::Any(children) => evaluate_any(children, input, details),
            Self::None(children) => {
                let truth = evaluate_any(children, input, details);
                details.truncate(before);
                truth.not()
            }
            Self::Test(test) => test.evaluate(input, details),
        };
        if truth != Truth::True {
            details.truncate(before);
        }
        truth
    }
}

fn evaluate_any(
    children: &[Expression],
    input: &Input<'_>,
    details: &mut Vec<(String, String)>,
) -> Truth {
    let mut result = Truth::False;
    for child in children {
        match child.evaluate(input, details) {
            Truth::True => return Truth::True,
            Truth::Unknown => result = Truth::Unknown,
            Truth::False => {}
        }
    }
    result
}

impl Field {
    fn is_http(self) -> bool {
        matches!(
            self,
            Self::Title | Self::Element | Self::ElementText | Self::ElementAttribute
        )
    }

    fn accepts(self, scalar: &Scalar) -> bool {
        match self {
            Self::SelfSigned => matches!(scalar, Scalar::Bool(_)),
            Self::Element => false,
            _ => matches!(scalar, Scalar::Text(text) if short_text(text, 1024)),
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::SubjectDn => "subject_dn",
            Self::IssuerDn => "issuer_dn",
            Self::SelfSigned => "self_signed",
            Self::SignatureAlgorithm => "signature_algorithm",
            Self::FingerprintSha256 => "fingerprint_sha256",
            Self::ValidityEnd => "validity_end",
            Self::Title => "title",
            Self::Element => "element",
            Self::ElementText => "element_text",
            Self::ElementAttribute => "element_attribute",
        }
    }
}

impl RawTest {
    fn compile(self, source: Source, path: &str) -> Result<Test, String> {
        let field = self.field;
        if field.is_http() != (source == Source::HttpManagementPage) {
            return Err(format!("{path}.field: 与 source 不兼容"));
        }
        let needs_selector = matches!(
            field,
            Field::Element | Field::ElementText | Field::ElementAttribute
        );
        if needs_selector != self.selector.is_some() {
            return Err(format!("{path}.selector: 仅 DOM 元素条件须提供选择器"));
        }
        let selector = self
            .selector
            .as_ref()
            .map(|selector| {
                if !short_text(selector, 512) {
                    return Err(format!("{path}.selector: 选择器为空或超长"));
                }
                Selector::parse(selector).map_err(|_| format!("{path}.selector: 无效选择器"))
            })
            .transpose()?;
        if (field == Field::ElementAttribute) != self.attribute.is_some()
            || self
                .attribute
                .as_ref()
                .is_some_and(|value| !identifier(value))
        {
            return Err(format!("{path}.attribute: 必须是有效的 DOM 属性名"));
        }
        let comparison = match (self.op, self.value, self.values) {
            (Op::Eq, Some(value), None) if field.accepts(&value) => Comparison::Eq(value),
            (Op::In, None, Some(values))
                if (1..=64).contains(&values.len())
                    && values.iter().all(|value| field.accepts(value)) =>
            {
                Comparison::In(values)
            }
            (Op::EqIgnoreAsciiCase, Some(Scalar::Text(value)), None)
                if field.accepts(&Scalar::Text(value.clone())) =>
            {
                Comparison::EqIgnoreAsciiCase(value)
            }
            (Op::Contains, Some(Scalar::Text(value)), None)
                if field.accepts(&Scalar::Text(value.clone())) =>
            {
                Comparison::Contains(value)
            }
            (Op::Regex, Some(Scalar::Text(pattern)), None)
                if field.accepts(&Scalar::Text(pattern.clone())) && pattern.len() <= 256 =>
            {
                Comparison::Regex(
                    RegexBuilder::new(&pattern)
                        .size_limit(64 * 1024)
                        .dfa_size_limit(64 * 1024)
                        .build()
                        .map_err(|error| format!("{path}.value: 正则无效或超限：{error}"))?,
                )
            }
            (Op::Exists, None, None) if field == Field::Element => Comparison::Exists,
            _ => return Err(format!("{path}: 操作符、value 或 values 与字段类型不兼容")),
        };
        if self
            .evidence_key
            .as_ref()
            .is_some_and(|key| !identifier(key))
        {
            return Err(format!("{path}.evidence_key: 无效证据名称"));
        }
        Ok(Test {
            field,
            selector,
            attribute: self.attribute,
            comparison,
            evidence_key: self.evidence_key.unwrap_or_else(|| field.key().into()),
        })
    }
}

impl Comparison {
    fn matches(&self, value: &Scalar) -> bool {
        match self {
            Self::Eq(expected) => value == expected,
            Self::In(expected) => expected.contains(value),
            Self::EqIgnoreAsciiCase(expected) => {
                matches!(value, Scalar::Text(text) if text.eq_ignore_ascii_case(expected))
            }
            Self::Contains(expected) => {
                matches!(value, Scalar::Text(text) if text.contains(expected))
            }
            Self::Regex(pattern) => matches!(value, Scalar::Text(text) if pattern.is_match(text)),
            Self::Exists => matches!(value, Scalar::Bool(true)),
        }
    }
}

impl Test {
    fn record(&self, fact: Fact, details: &mut Vec<(String, String)>) {
        if details.len() < MAX_DETAILS {
            let excerpt = match &self.comparison {
                Comparison::Contains(part) => bounded(part),
                _ => fact.excerpt,
            };
            details.push((self.evidence_key.clone(), excerpt));
        }
    }

    fn evaluate(&self, input: &Input<'_>, details: &mut Vec<(String, String)>) -> Truth {
        if let Input::Http(page) = input
            && let Some(selector) = &self.selector
        {
            if self.field == Field::Element {
                if page.select(selector).next().is_none() {
                    return Truth::False;
                }
                self.record(
                    Fact {
                        value: Scalar::Bool(true),
                        excerpt: "present".into(),
                    },
                    details,
                );
                return Truth::True;
            }
            let mut evaluated = false;
            let mut missing = false;
            for element in page.select(selector) {
                let fact = if self.field == Field::ElementText {
                    Some(Fact::text(
                        &element
                            .text()
                            .flat_map(str::split_whitespace)
                            .collect::<Vec<_>>()
                            .join(" "),
                    ))
                } else {
                    self.attribute
                        .as_ref()
                        .and_then(|name| element.value().attr(name))
                        .map(Fact::text)
                };
                if let Some(fact) = fact {
                    evaluated = true;
                    if self.comparison.matches(&fact.value) {
                        self.record(fact, details);
                        return Truth::True;
                    }
                } else {
                    missing = true;
                }
            }
            return if evaluated && !missing {
                Truth::False
            } else {
                Truth::Unknown
            };
        }
        let fact = match input {
            Input::Tls(leaf) => tls_fact(self.field, leaf),
            Input::Http(page) => {
                let mut titles = page.select(&TITLE);
                titles
                    .next()
                    .filter(|_| titles.next().is_none())
                    .map(|title| Fact::text(title.text().collect::<String>().trim()))
            }
        };
        let Some(fact) = fact else {
            return Truth::Unknown;
        };
        if self.comparison.matches(&fact.value) {
            self.record(fact, details);
            Truth::True
        } else {
            Truth::False
        }
    }
}

fn tls_fact(field: Field, leaf: &Value) -> Option<Fact> {
    let text = match field {
        Field::SubjectDn | Field::IssuerDn => leaf[field.key()]
            .as_str()
            .filter(|text| !text.is_empty() && text.len() <= 1024)?,
        Field::SelfSigned => {
            let signed = leaf.pointer("/signature/self_signed")?.as_bool()?;
            return Some(Fact {
                value: Scalar::Bool(signed),
                excerpt: signed.to_string(),
            });
        }
        Field::SignatureAlgorithm => {
            let raw = leaf
                .pointer("/signature/signature_algorithm/name")
                .or_else(|| leaf.pointer("/signature_algorithm/name"))?
                .as_str()?;
            let normalized = match raw.to_ascii_lowercase().as_str() {
                "ecdsa-sha256" | "ecdsawithsha256" => "ecdsa_sha256",
                "ecdsa-sha384" | "ecdsawithsha384" => "ecdsa_sha384",
                "ecdsa-sha512" | "ecdsawithsha512" => "ecdsa_sha512",
                _ => raw,
            };
            return Some(Fact {
                value: Scalar::Text(normalized.into()),
                excerpt: bounded(raw),
            });
        }
        Field::FingerprintSha256 => {
            let raw = leaf["fingerprint_sha256"].as_str().filter(|text| {
                text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
            })?;
            return Some(Fact::text(&raw.to_ascii_lowercase()));
        }
        Field::ValidityEnd => leaf.pointer("/validity/end")?.as_str()?,
        _ => return None,
    };
    Some(Fact::text(text))
}
