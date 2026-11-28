//! Compiled, read-only rules over evidence whose provenance was checked by the caller.
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::{LazyLock, OnceLock};

use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{EVALUATOR_REVISION, Evidence, Product, ProductCategory, RETIRED_PRODUCT_IDS, bounded};

mod expression;
mod json;
use expression::{Expression, Input, Truth};

pub(super) const BUILTIN: &[u8] = include_bytes!("rules.json");
const MAX_FILE_BYTES: usize = 512 * 1024;
const MAX_RULES: usize = 256;
const MIN_REVISION: u32 = 6;

static DEFAULT: LazyLock<RuleSet> =
    LazyLock::new(|| RuleSet::compile(BUILTIN).expect("embedded product rules must be valid"));
static ACTIVE: OnceLock<RuleSet> = OnceLock::new();

pub(super) fn active() -> &'static RuleSet {
    ACTIVE.get().unwrap_or(&DEFAULT)
}

pub(super) fn initialize(path: Option<&Path>) -> io::Result<()> {
    if let Some(path) = path {
        let rules = RuleSet::read(path)?;
        ACTIVE
            .set(rules)
            .map_err(|_| io::Error::other("产品规则已初始化"))?;
    }
    let rules = active();
    tracing::info!(
        target: "server::startup",
        event = "ProductRulesLoaded",
        source = %path.map_or_else(|| "embedded".into(), |path| path.display().to_string()),
        ruleset_revision = rules.stamp.revision,
        evaluator_revision = rules.stamp.evaluator_revision,
        ruleset_sha256 = %rules.stamp.sha256,
        rules = rules.count(),
        "服务产品规则已加载"
    );
    Ok(())
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(crate) struct Stamp {
    pub revision: u32,
    #[serde(default)]
    pub evaluator_revision: u32,
    pub sha256: String,
}

pub(super) struct RuleSet {
    pub stamp: Stamp,
    tls: Vec<Rule>,
    http: Vec<Rule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileFormat {
    schema_version: u32,
    ruleset_revision: u32,
    rules: Vec<json::UniqueJson>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    product: Identity,
    source: Source,
    basis: Basis,
    #[serde(rename = "match")]
    expression: Value,
    references: Vec<String>,
    prefilter: Option<String>,
}

#[derive(Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
struct Identity {
    id: String,
    name: String,
    component: Option<String>,
}

#[derive(Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Source {
    TlsLeaf,
    HttpManagementPage,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Basis {
    CertificateTemplate,
    HistoricalCertificateHeuristic,
    HttpManagementFingerprint,
}

impl Basis {
    fn name(&self) -> &'static str {
        match self {
            Self::CertificateTemplate => "certificate_template",
            Self::HistoricalCertificateHeuristic => "historical_certificate_heuristic",
            Self::HttpManagementFingerprint => "http_management_fingerprint",
        }
    }
}

struct Rule {
    id: String,
    product: Identity,
    basis: Basis,
    expression: Expression,
    source_url: String,
    prefilter: Option<String>,
}

pub(super) struct Context<'a> {
    pub probe: &'a str,
    pub field_path: &'a str,
    pub sni: Option<&'a str>,
    pub http_host: Option<&'a str>,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn short_text(text: &str, max: usize) -> bool {
    !text.trim().is_empty() && text.len() <= max && !text.chars().any(char::is_control)
}

fn reserved_product(id: &str) -> bool {
    matches!(id, "cobalt_strike" | "asyncrat_family" | "qakbot" | "xmrig")
        || RETIRED_PRODUCT_IDS.contains(&id)
}

impl RuleSet {
    pub fn read(path: &Path) -> io::Result<Self> {
        let bytes = read_limited(path, MAX_FILE_BYTES)?;
        Self::compile(&bytes).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {error}", path.display()),
            )
        })
    }

    fn compile(bytes: &[u8]) -> Result<Self, String> {
        let file: FileFormat = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if file.schema_version != 1 {
            return Err("schema_version: 只支持版本 1".into());
        }
        if file.ruleset_revision < MIN_REVISION {
            return Err(format!("ruleset_revision: 必须至少为 {MIN_REVISION}"));
        }
        if file.rules.len() > MAX_RULES {
            return Err(format!("rules: 最多允许 {MAX_RULES} 条规则"));
        }
        let mut ids = std::collections::HashSet::new();
        let mut products = HashMap::new();
        let mut nodes = 0;
        let mut rules = Self {
            stamp: Stamp {
                revision: file.ruleset_revision,
                evaluator_revision: EVALUATOR_REVISION,
                sha256: format!("{:x}", Sha256::digest(bytes)),
            },
            tls: Vec::new(),
            http: Vec::new(),
        };
        for (index, json::UniqueJson(raw)) in file.rules.into_iter().enumerate() {
            let id = raw["id"].as_str().filter(|id| identifier(id));
            let location = id.map_or_else(
                || format!("rules[{index}]"),
                |id| format!("rules[{index}] ({id})"),
            );
            let rule: RawRule =
                serde_json::from_value(raw).map_err(|e| format!("{location}: {e}"))?;
            let (source, rule) = rule.compile(&location, &mut nodes)?;
            if !ids.insert(rule.id.clone()) {
                return Err(format!("{location}.id: 规则 ID 重复"));
            }
            if products
                .insert(rule.product.id.clone(), rule.product.clone())
                .is_some_and(|previous| previous != rule.product)
            {
                return Err(format!(
                    "{location}.product: 同一产品 ID 的名称及组件必须一致"
                ));
            }
            match source {
                Source::TlsLeaf => rules.tls.push(rule),
                Source::HttpManagementPage => rules.http.push(rule),
            }
        }
        Ok(rules)
    }

    pub fn count(&self) -> usize {
        self.tls.len() + self.http.len()
    }

    pub fn tls_products(&self, leaf: &Value, context: &Context<'_>) -> Vec<Product> {
        self.tls
            .iter()
            .filter_map(|rule| rule.evaluate(&Input::Tls(leaf), context, "tls_certificate"))
            .collect()
    }

    pub fn http_products(&self, body: &str, context: &Context<'_>) -> Vec<Product> {
        let rules = self.http.iter().filter(|rule| {
            rule.prefilter
                .as_deref()
                .is_none_or(|hint| body.contains(hint))
        });
        let mut rules = rules.peekable();
        if rules.peek().is_none() {
            return Vec::new();
        }
        static BASE_HREF: LazyLock<Selector> =
            LazyLock::new(|| Selector::parse("base[href]").expect("valid base selector"));
        let page = Html::parse_document(body);
        if page.select(&BASE_HREF).next().is_some() {
            return Vec::new();
        }
        rules
            .filter_map(|rule| rule.evaluate(&Input::Http(&page), context, "http_fingerprint"))
            .collect()
    }
}

pub(super) fn default_rules() -> &'static RuleSet {
    &DEFAULT
}

pub(super) fn read_limited(path: &Path, max: usize) -> io::Result<Vec<u8>> {
    let read = || {
        let file = File::open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "必须是常规文件",
            ));
        }
        let mut bytes = Vec::new();
        file.take(max as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("文件超过 {max} 字节"),
            ));
        }
        Ok(bytes)
    };
    read().map_err(|error: io::Error| {
        io::Error::new(error.kind(), format!("{}: {error}", path.display()))
    })
}

impl RawRule {
    fn compile(self, path: &str, nodes: &mut usize) -> Result<(Source, Rule), String> {
        if !identifier(&self.id)
            || !identifier(&self.product.id)
            || reserved_product(&self.product.id)
        {
            return Err(format!(
                "{path}: 规则或产品 ID 无效，或产品 ID 由既有规则保留"
            ));
        }
        if !short_text(&self.product.name, 160)
            || self
                .product
                .component
                .as_ref()
                .is_some_and(|value| !short_text(value, 160))
        {
            return Err(format!("{path}.product: 产品名或组件名无效"));
        }
        if (self.source == Source::HttpManagementPage)
            != (self.basis == Basis::HttpManagementFingerprint)
        {
            return Err(format!("{path}.basis: 与 source 不兼容"));
        }
        if self.prefilter.as_ref().is_some_and(|value| {
            self.source != Source::HttpManagementPage || !short_text(value, 160)
        }) {
            return Err(format!(
                "{path}.prefilter: 只允许非空的 HTTP 正文预筛选文本"
            ));
        }
        if self.references.is_empty()
            || self.references.len() > 8
            || self.references.iter().any(|reference| {
                !short_text(reference, 2048)
                    || !reqwest::Url::parse(reference).is_ok_and(|url| {
                        url.scheme() == "https"
                            && url.has_host()
                            && url.username().is_empty()
                            && url.password().is_none()
                    })
            })
        {
            return Err(format!(
                "{path}.references: 必须提供 1 至 8 个 HTTPS 参考链接"
            ));
        }
        let expression = Expression::compile(
            self.expression,
            self.source,
            &format!("{path}.match"),
            1,
            nodes,
        )?;
        Ok((
            self.source,
            Rule {
                id: self.id,
                product: self.product,
                basis: self.basis,
                expression,
                source_url: self
                    .references
                    .into_iter()
                    .next()
                    .expect("reference count was checked"),
                prefilter: self.prefilter,
            },
        ))
    }
}

impl Rule {
    fn evaluate(&self, input: &Input<'_>, context: &Context<'_>, method: &str) -> Option<Product> {
        let mut details = Vec::new();
        if self.expression.evaluate(input, &mut details) != Truth::True {
            return None;
        }
        Some(Product {
            id: self.product.id.clone(),
            name: self.product.name.clone(),
            category: ProductCategory::C2,
            component: self.product.component.clone(),
            version: None,
            assessment: "suspected".into(),
            basis: self.basis.name().into(),
            observation: None,
            evidence: vec![Evidence {
                detection_method: Some(method.into()),
                rule_id: self.id.clone(),
                probe: context.probe.into(),
                field_path: context.field_path.into(),
                details,
                sni: context.sni.map(bounded),
                http_host: context.http_host.map(bounded),
                source_url: Some(self.source_url.clone()),
            }],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn package(expression: Value) -> Value {
        json!({"schema_version":1, "ruleset_revision":7, "rules":[{
            "id":"example_console_test",
            "product":{"id":"example_console","name":"Example Console","component":"Management"},
            "source":"tls_leaf","basis":"certificate_template",
            "match":expression,"references":["https://example.invalid/evidence"]
        }]})
    }

    fn compile(package: &Value) -> Result<RuleSet, String> {
        RuleSet::compile(&serde_json::to_vec(package).unwrap())
    }

    fn match_leaf(pack: &RuleSet, mut leaf: Value) -> Vec<Product> {
        if leaf.get("subject_dn").is_none() {
            leaf["subject_dn"] = json!("CN=Example Console");
        }
        let data = json!({"schema_version":2,"evidence":[{"module":"tls","status":"success","result":{
            "handshake_log":{"server_certificates":{"certificate":{"parsed":leaf}}}
        }}]});
        let result = crate::service_products::infer_with_rules(Some(&data), 500, None, pack);
        assert_eq!(result.product_identification.ruleset_revision, 7);
        assert_eq!(
            result.product_identification.ruleset_sha256.as_ref(),
            Some(&pack.stamp.sha256)
        );
        if let Some(product) = result.products.first() {
            assert_eq!(product.id, "example_console");
            assert_eq!(product.assessment, "suspected");
            assert_eq!(data.pointer(&product.evidence[0].field_path), Some(&leaf));
        }
        result.products
    }

    #[test]
    fn nested_groups_evaluate_missing_evidence_as_unknown() {
        let package = package(json!({"all":[
            {"field":"subject_dn","op":"eq","value":"CN=Example Console"},
            {"any":[
                {"field":"issuer_dn","op":"eq","value":"CN=Example CA"},
                {"all":[
                    {"field":"self_signed","op":"eq","value":false},
                    {"field":"signature_algorithm","op":"eq","value":"ecdsa_sha256"}
                ]}
            ]},
            {"none":[
                {"field":"issuer_dn","op":"eq","value":"CN=Test CA"},
                {"field":"subject_dn","op":"contains","value":"Demo"}
            ]}
        ]}));
        let pack = compile(&package).unwrap();
        let matches_issuer = match_leaf(&pack, json!({"issuer_dn":"CN=Example CA"}));
        assert_eq!(matches_issuer.len(), 1);
        assert_eq!(matches_issuer[0].evidence[0].details.len(), 2);

        let positive = json!({
            "issuer_dn":"CN=Another CA",
            "signature":{"self_signed":false,"signature_algorithm":{"name":"ECDSAWithSHA256"}}
        });
        let matches_algorithm = match_leaf(&pack, positive.clone());
        assert_eq!(matches_algorithm.len(), 1);
        assert_eq!(matches_algorithm[0].evidence[0].details.len(), 3);
        for issuer in [Value::Null, json!("CN=Test CA")] {
            let mut negative = positive.clone();
            negative["issuer_dn"] = issuer;
            assert!(match_leaf(&pack, negative).is_empty());
        }
        assert!(match_leaf(&pack, json!({"issuer_dn":"CN=Another CA"})).is_empty());
    }

    #[test]
    fn compiler_rejects_ambiguous_groups_and_conflicting_or_untyped_rules() {
        let condition = json!({"field":"self_signed","op":"eq","value":false});
        for expression in [
            json!({"all":[]}),
            json!({"all":[condition],"none":[condition]}),
            json!({"field":"self_signed","op":"contains","value":"false"}),
            json!({"field":"subject_dn","op":"regex","value":"["}),
            json!({"field":"title","op":"eq","value":"Sample"}),
            json!({"field":"subject_dn","op":"eq","waarde":"Sample"}),
        ] {
            assert!(
                compile(&package(expression))
                    .err()
                    .expect("invalid rule package was accepted")
                    .contains("rules[0] (example_console_test).match")
            );
        }
        let mut repeated = package(condition.clone());
        let rule = repeated["rules"][0].clone();
        repeated["rules"].as_array_mut().unwrap().push(rule);
        assert!(
            compile(&repeated)
                .err()
                .expect("invalid rule package was accepted")
                .contains("规则 ID 重复")
        );
        let duplicate = serde_json::to_string(&package(json!({"all":[condition]})))
            .unwrap()
            .replace(r#""all":["#, r#""all":[],"all":["#);
        assert!(
            RuleSet::compile(duplicate.as_bytes())
                .err()
                .expect("duplicate JSON key was accepted")
                .contains("重复的 JSON 键")
        );
    }
}
