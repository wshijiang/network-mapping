//! Bounded, offline deployment candidates from the observed leaf certificate.
//! Sliver scope: its default multiplayer operator service, not implant listeners.
//! QakBot scope: a historical certificate heuristic, never family confirmation.
use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

use crate::service_fingerprint::{Match, leaf_certificate, probe_tls};

use super::{
    Product,
    rules::{Context, RuleSet},
};

pub(super) const QAKBOT: &str = "qakbot";
const MAX_DN_BYTES: usize = 1024;
const QAKBOT_SOURCE: &str = "https://www.embeeresearch.io/advanced-threat-intel-queries-catching-83-qakbot-servers-with-regex-censys-and-tls-certificates/";

// Deliberately narrower than the published hunting query: full DN shapes must
// match, and the subject/issuer country and CN must agree on the same leaf.
static QAKBOT_SUBJECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\AC=([A-Z]{2}), OU=([A-Za-z0-9.]+(?: [A-Za-z0-9.]+)*), CN=([a-z]+\.[a-z]+)\z")
        .expect("valid QakBot subject pattern")
});
static QAKBOT_ISSUER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
    r"\AC=([A-Z]{2}), ST=[A-Za-z]{2}, L=[A-Za-z]+, O=[A-Za-z0-9.]+(?: [A-Za-z0-9.]+)*, CN=([a-z]+\.[a-z]+)\z"
).expect("valid QakBot issuer pattern")
});

fn dn<'a>(leaf: &'a Value, field: &str) -> Option<&'a str> {
    leaf[field]
        .as_str()
        .filter(|value| !value.is_empty() && value.len() <= MAX_DN_BYTES)
}

fn qakbot(leaf: &Value) -> Option<Vec<(&'static str, String)>> {
    let subject = dn(leaf, "subject_dn")?;
    let issuer = dn(leaf, "issuer_dn")?;
    let subject_fields = QAKBOT_SUBJECT.captures(subject)?;
    let issuer_fields = QAKBOT_ISSUER.captures(issuer)?;
    if subject_fields[1] != issuer_fields[1]
        || subject_fields[3] != issuer_fields[2]
        || subject_fields[2].eq_ignore_ascii_case("Domain Control Validated")
    {
        return None;
    }
    Some(vec![
        ("subject_dn", subject.into()),
        ("issuer_dn", issuer.into()),
    ])
}

pub(super) fn matches(data: Option<&Value>) -> Vec<Match<'_>> {
    let Some(evidence) = data
        .filter(|value| value["schema_version"] == 2)
        .and_then(|value| value["evidence"].as_array())
    else {
        return Vec::new();
    };
    let mut matches = Vec::new();
    for (index, probe) in evidence.iter().take(64).enumerate() {
        let module = probe["module"].as_str().unwrap_or_default();
        if !matches!(module, "tls" | "https") {
            continue;
        }
        let Some((tls, response, path)) = probe_tls(probe, module) else {
            continue;
        };
        let Some((leaf, leaf_path)) = leaf_certificate(tls) else {
            continue;
        };
        if let Some(evidence) = qakbot(leaf) {
            matches.push(Match {
                family: QAKBOT,
                rule_id: "qakbot_historical_certificate_shape",
                source_url: QAKBOT_SOURCE,
                probe: module,
                evidence_path: format!("/evidence/{index}/result{path}{leaf_path}"),
                sni: tls
                    .pointer("/handshake_log/client_hello/server_name")
                    .and_then(Value::as_str),
                http_host: response
                    .and_then(|value| {
                        value
                            .pointer("/request/host")
                            .or_else(|| value.pointer("/request/url/host"))
                    })
                    .and_then(Value::as_str),
                evidence,
            });
        }
    }
    matches
}

pub(super) fn candidates(
    probe: &Value,
    module: &str,
    index: usize,
    rules: &RuleSet,
) -> Vec<Product> {
    let Some((tls, response, path)) = probe_tls(probe, module) else {
        return Vec::new();
    };
    let Some((leaf, leaf_path)) = leaf_certificate(tls) else {
        return Vec::new();
    };
    let field_path = format!("/evidence/{index}/result{path}{leaf_path}");
    let context = Context {
        probe: module,
        field_path: &field_path,
        sni: tls
            .pointer("/handshake_log/client_hello/server_name")
            .and_then(Value::as_str),
        http_host: response.and_then(|response| {
            response
                .pointer("/request/host")
                .or_else(|| response.pointer("/request/url/host"))
                .and_then(Value::as_str)
        }),
    };
    rules.tls_products(leaf, &context)
}
