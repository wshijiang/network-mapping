use chrono::{DateTime, Datelike};
use serde::Serialize;
use serde_json::Value;

pub(crate) const COBALT_STRIKE: &str = "cobalt_strike";
pub(crate) const ASYNCRAT_FAMILY: &str = "asyncrat_family";
const DEFAULT_TEAM_SERVER_SHA256: &str =
    "87f2085c32b6a2cc709b365f55873e207a9caa10bffecf2fd16d3cf9d94d390c";
const RULESET_VERSION: u32 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    Matched,
    NotMatched,
    InsufficientEvidence,
}

#[derive(Serialize)]
pub(crate) struct Assessment<'a> {
    pub(crate) status: Status,
    ruleset_version: u32,
    observed_at: i64,
    task_id: &'a str,
    execution_id: &'a str,
    pub(crate) matches: Vec<Match<'a>>,
}

#[derive(Serialize)]
pub(crate) struct Match<'a> {
    pub(crate) family: &'static str,
    pub(crate) rule_id: &'static str,
    pub(crate) source_url: &'static str,
    pub(crate) probe: &'a str,
    pub(crate) evidence_path: String,
    pub(crate) sni: Option<&'a str>,
    pub(crate) http_host: Option<&'a str>,
    pub(crate) evidence: Vec<(&'static str, String)>,
}

pub(crate) fn assess<'a>(
    data: Option<&'a Value>,
    observed_at: i64,
    task_id: &'a str,
    execution_id: &'a str,
) -> Assessment<'a> {
    let mut status = Status::InsufficientEvidence;
    let mut matches = Vec::new();
    if let Some(data) = data.filter(|v| v["schema_version"] == 2)
        && let Some(probes) = data["evidence"].as_array()
    {
        let mut incomplete_tls = false;
        for (index, probe) in probes.iter().enumerate() {
            let module = probe["module"].as_str().unwrap_or_default();
            if !matches!(module, "tls" | "https") {
                continue;
            }
            let Some((tls, response, path)) = probe_tls(probe, module) else {
                incomplete_tls = true;
                continue;
            };
            let Some((leaf, leaf_path)) = leaf_certificate(tls) else {
                incomplete_tls = true;
                continue;
            };
            let hash = leaf["fingerprint_sha256"].as_str().filter(|hash| {
                hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
            let matched = if hash
                .is_some_and(|h| h.eq_ignore_ascii_case(DEFAULT_TEAM_SERVER_SHA256))
            {
                let mut evidence = vec![("sha256", DEFAULT_TEAM_SERVER_SHA256.to_owned())];
                if response.is_some_and(default_http_response) {
                    evidence.push(("http_response", "404 · text/plain · 0 bytes".to_owned()));
                }
                Some((
                    COBALT_STRIKE,
                    "cobalt_strike_default_certificate",
                    "https://www.recordedfuture.com/research/cobalt-strike-servers",
                    evidence,
                ))
            } else {
                rat_template(leaf).map(|evidence| {
                    (
                        ASYNCRAT_FAMILY,
                        "asyncrat_family_certificate_template",
                        "https://www.trendmicro.com/content/dam/trendmicro/global/en/research/21/i/ssl-tls-technical-brief/ssl-tls-technical-brief.pdf",
                        evidence,
                    )
                })
            };
            if let Some((family, rule_id, source_url, evidence)) = matched {
                matches.push(Match {
                    family,
                    rule_id,
                    source_url,
                    probe: module,
                    evidence_path: format!("/evidence/{index}/result{path}{leaf_path}"),
                    sni: tls
                        .pointer("/handshake_log/client_hello/server_name")
                        .and_then(Value::as_str),
                    http_host: response.and_then(|r| {
                        r.pointer("/request/host")
                            .or_else(|| r.pointer("/request/url/host"))
                            .and_then(Value::as_str)
                    }),
                    evidence,
                });
            } else if hash.is_some() && rat_template_observable(leaf) {
                status = Status::NotMatched;
            } else {
                incomplete_tls = true;
            }
        }
        if incomplete_tls {
            status = Status::InsufficientEvidence;
        }
    }
    if !matches.is_empty() {
        status = Status::Matched;
    }
    Assessment {
        status,
        ruleset_version: RULESET_VERSION,
        observed_at,
        task_id,
        execution_id,
        matches,
    }
}

pub(crate) fn probe_tls<'a>(
    probe: &'a Value,
    module: &str,
) -> Option<(&'a Value, Option<&'a Value>, &'static str)> {
    let result = &probe["result"];
    if module == "tls" {
        return result
            .get("tls")
            .map(|tls| (tls, None, "/tls"))
            .or_else(|| result.get("handshake_log").map(|_| (result, None, "")));
    }
    if let Some(first) = result["redirect_response_chain"]
        .as_array()
        .and_then(|chain| chain.first())
    {
        return first.pointer("/request/tls_log").map(|tls| {
            (
                tls,
                Some(first),
                "/redirect_response_chain/0/request/tls_log",
            )
        });
    }
    let response = result.get("response");
    response
        .and_then(|r| r.pointer("/request/tls_log"))
        .map(|tls| (tls, response, "/response/request/tls_log"))
        .or_else(|| result.get("tls").map(|tls| (tls, None, "/tls")))
}

pub(crate) fn leaf_certificate(tls: &Value) -> Option<(&Value, &'static str)> {
    // zgrab2 TLS logs have used both a single certificate message and a list.
    [
        "/handshake_log/server_certificates/certificate/parsed",
        "/handshake_log/server_certificates/0/certificate/parsed",
        "/handshake_log/server_certificates/certificate",
        "/handshake_log/server_certificates/0/certificate",
    ]
    .into_iter()
    .find_map(|path| {
        tls.pointer(path)
            .filter(|leaf| leaf.is_object())
            .map(|leaf| (leaf, path))
    })
}

fn default_http_response(response: &Value) -> bool {
    let root_request = response["request"]["url"]
        .as_str()
        .and_then(|url| reqwest::Url::parse(url).ok())
        .is_some_and(|url| url.path() == "/" && url.query().is_none())
        || (response["request"]["url"]["path"] == "/"
            && response["request"]["url"]["raw_query"]
                .as_str()
                .is_none_or(str::is_empty));
    let content_type = &response["headers"]["content_type"];
    root_request
        && response["status_code"] == 404
        && response["body_truncated"] != true
        && response["content_length"] == 0
        && content_type.as_str().or_else(|| content_type[0].as_str()) == Some("text/plain")
}

fn rat_template_observable(leaf: &Value) -> bool {
    let fields = ["subject_dn", "issuer_dn"];
    fields.iter().all(|field| {
        leaf[*field]
            .as_str()
            .is_some_and(|text| !text.trim().is_empty())
    }) && (!fields
        .iter()
        .any(|field| leaf[*field].as_str().is_some_and(default_rat_dn))
        || (leaf
            .pointer("/signature/self_signed")
            .and_then(Value::as_bool)
            .is_some()
            && certificate_expiry(leaf).is_some()
            && signature_algorithm(leaf).is_some()))
}

fn default_rat_dn(dn: &str) -> bool {
    ["CN=AsyncRAT Server", "CN=DcRat Server"]
        .iter()
        .any(|expected| dn.trim().eq_ignore_ascii_case(expected))
}

fn certificate_expiry(leaf: &Value) -> Option<&str> {
    leaf.pointer("/validity/end").and_then(Value::as_str)
}

fn signature_algorithm(leaf: &Value) -> Option<&str> {
    leaf.pointer("/signature/signature_algorithm/name")
        .and_then(Value::as_str)
        .or_else(|| {
            leaf.pointer("/signature_algorithm/name")
                .and_then(Value::as_str)
        })
}

fn rat_template(leaf: &Value) -> Option<Vec<(&'static str, String)>> {
    let subject = leaf["subject_dn"].as_str()?.trim();
    let issuer = leaf["issuer_dn"].as_str()?.trim();
    let expiry = certificate_expiry(leaf)?;
    let algorithm = signature_algorithm(leaf)?;
    if !default_rat_dn(subject)
        || !subject.eq_ignore_ascii_case(issuer)
        || leaf.pointer("/signature/self_signed")?.as_bool() != Some(true)
        || DateTime::parse_from_rfc3339(expiry).ok()?.year() != 9999
        || !["SHA512-RSA", "SHA512WithRSAEncryption", "SHA512WithRSA"]
            .iter()
            .any(|name| algorithm.eq_ignore_ascii_case(name))
    {
        return None;
    }
    Some(vec![
        ("subject_dn", subject.to_owned()),
        ("issuer_dn", issuer.to_owned()),
        ("self_signed", "true".to_owned()),
        ("not_after", expiry.to_owned()),
        ("signature_algorithm", algorithm.to_owned()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn leaf(hash: &str, dn: &str) -> Value {
        json!({
            "fingerprint_sha256": hash,
            "subject_dn": dn,
            "issuer_dn": dn,
            "validity": {"end": "9999-12-31T23:59:59Z"},
            "signature": {"self_signed": true, "signature_algorithm": {"name": "SHA512-RSA"}}
        })
    }

    fn tls(certificate: Value) -> Value {
        json!({"handshake_log": {
            "client_hello": {"server_name": "asset.example"},
            "server_certificates": {"certificate": {"parsed": certificate}}
        }})
    }

    fn envelope(module: &str, result: Value) -> Value {
        json!({"schema_version": 2, "evidence": [{"module": module, "result": result}]})
    }

    fn assessment(data: &Value) -> Value {
        json!(assess(Some(data), 1234, "task-1", "execution-1"))
    }

    #[test]
    fn matches_the_default_leaf_and_not_the_other_ports_self_signed_certificate() {
        let expected = DEFAULT_TEAM_SERVER_SHA256.to_uppercase();
        let target = envelope(
            "tls",
            json!({"tls": tls(leaf(&expected, "CN=Major Cobalt Strike"))}),
        );
        let ordinary = envelope(
            "tls",
            json!({"tls": tls(leaf(&"a".repeat(64), "CN=intranet"))}),
        );
        let matched = assessment(&target);
        assert_eq!(matched["status"], "matched");
        assert_eq!(matched["matches"][0]["family"], COBALT_STRIKE);
        assert_eq!(matched["matches"][0]["sni"], "asset.example");
        assert_eq!(matched["observed_at"], 1234);
        assert_eq!(matched["execution_id"], "execution-1");
        assert_eq!(assessment(&ordinary)["status"], "not_matched");

        // A match in the certificate chain or the SPKI hash is not a leaf match.
        let mut ordinary = ordinary;
        let cert =
            &mut ordinary["evidence"][0]["result"]["tls"]["handshake_log"]["server_certificates"];
        cert["chain"] = json!([{"parsed": leaf(&expected, "CN=Major Cobalt Strike")}]);
        cert["certificate"]["parsed"]["subject_key_info"]["fingerprint_sha256"] = json!(expected);
        assert_eq!(assessment(&ordinary)["status"], "not_matched");
    }

    #[test]
    fn requires_multiple_certificate_fields_for_the_rat_family() {
        for dn in ["CN=AsyncRAT Server", "CN=DcRat Server"] {
            let certificate = leaf(&"b".repeat(64), dn);
            let mut data = envelope("tls", json!({"tls": tls(certificate.clone())}));
            let stored =
                &mut data["evidence"][0]["result"]["tls"]["handshake_log"]["server_certificates"];
            *stored = json!([{"certificate":{"parsed":certificate}}]);
            assert_eq!(assessment(&data)["matches"][0]["family"], ASYNCRAT_FAMILY);

            let cert = &mut data["evidence"][0]["result"]["tls"]["handshake_log"]["server_certificates"]
                [0]["certificate"]["parsed"];
            cert["validity"]["end"] = json!("2030-01-01T00:00:00Z");
            assert_eq!(assessment(&data)["status"], "not_matched");
        }
        let partial = envelope(
            "tls",
            json!({"tls": tls(json!({"subject_dn":"CN=AsyncRAT Server"}))}),
        );
        assert_eq!(assessment(&partial)["status"], "insufficient_evidence");
    }

    #[test]
    fn http_corroboration_comes_only_from_the_response_with_the_matching_leaf() {
        let server = tls(leaf(DEFAULT_TEAM_SERVER_SHA256, "CN=Major Cobalt Strike"));
        let response = json!({
            "request": {"host": "asset.example", "url": "https://asset.example/", "tls_log": server},
            "status_code": 404,
            "headers": {"content_type": ["text/plain"]},
            "content_length": 0
        });
        let result = assessment(&envelope("https", json!({"response": response})));
        assert_eq!(result["matches"][0]["http_host"], "asset.example");
        assert_eq!(result["matches"][0]["evidence"][1][0], "http_response");

        let ordinary = tls(leaf(&"c".repeat(64), "CN=intranet"));
        let redirect = json!({"request": {"tls_log": ordinary}, "status_code": 302});
        let result = assessment(&envelope(
            "https",
            json!({
                "redirect_response_chain": [redirect], "response": response,
            }),
        ));
        assert_eq!(result["status"], "not_matched");

        let result = assessment(&envelope(
            "https",
            json!({
                "redirect_response_chain": [{"request": {"tls_log": server}, "status_code": 302}],
                "response": response,
            }),
        ));
        assert_eq!(
            result["matches"][0]["evidence"].as_array().unwrap().len(),
            1
        );
    }

    #[test]
    fn ignores_unknown_envelopes_and_generic_http_responses() {
        let server = tls(leaf(DEFAULT_TEAM_SERVER_SHA256, "CN=Major Cobalt Strike"));
        let mut data = envelope("tls", json!({"tls": server}));
        data["schema_version"] = json!(99);
        assert_eq!(assessment(&data)["status"], "insufficient_evidence");
        let data = envelope(
            "http",
            json!({"response": {"status_code": 404, "content_length": 0}}),
        );
        assert_eq!(assessment(&data)["status"], "insufficient_evidence");
    }
}
