//! Product identity from protocol-owned observations. No IOC lookups or network I/O.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod certificate_templates;
mod detection_methods;
use detection_methods::{DetectionMethod, JarmObservation};

pub(crate) const RULESET_REVISION: u32 = 4;
const MAX_EVIDENCE: usize = 8;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Evidence {
    #[serde(default)]
    pub detection_method: Option<String>,
    pub rule_id: String,
    pub probe: String,
    pub field_path: String,
    pub details: Vec<(String, String)>,
    pub sni: Option<String>,
    pub http_host: Option<String>,
    pub source_url: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Product {
    pub id: String,
    pub name: String,
    pub component: Option<String>,
    pub version: Option<String>,
    pub assessment: String,
    pub basis: String,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Identification {
    pub status: String,
    pub coverage: String,
    pub ruleset_revision: u32,
    pub observed_at: i64,
    pub stale: bool,
    pub observation_ref: Option<Value>,
    #[serde(default)]
    pub detection_methods: Vec<DetectionMethod>,
    #[serde(default)]
    pub jarm: Option<JarmObservation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Products {
    pub products: Vec<Product>,
    pub product_identification: Identification,
}

fn bounded(text: &str) -> String {
    text.chars().take(1024).collect()
}

fn push(products: &mut Vec<Product>, mut product: Product) {
    if let Some(previous) = products
        .iter_mut()
        .find(|item| item.id == product.id && item.version == product.version)
    {
        for evidence in product.evidence.drain(..) {
            if previous.evidence.len() < MAX_EVIDENCE {
                previous.evidence.push(evidence);
            }
        }
    } else if products.len() < 32 {
        products.push(product);
    }
}

pub(crate) fn infer(
    data: Option<&Value>,
    observed_at: i64,
    observation_ref: Option<Value>,
) -> Products {
    let mut result = Products {
        products: Vec::new(),
        product_identification: Identification {
            status: "insufficient_evidence".into(),
            coverage: "partial".into(),
            ruleset_revision: RULESET_REVISION,
            observed_at,
            stale: false,
            observation_ref,
            detection_methods: Vec::new(),
            jarm: None,
        },
    };
    let Some(evidence) = data
        .filter(|data| data["schema_version"] == 2)
        .and_then(|data| data["evidence"].as_array())
    else {
        return result;
    };

    result.product_identification.detection_methods = detection_methods::catalog(evidence);
    result.product_identification.jarm = detection_methods::jarm(evidence);

    // Existing certificate rules are local product rules, independent of intel storage.
    // Their observations establish deployment candidates, never malicious intent.
    let certificate = crate::service_fingerprint::assess(data, observed_at, "", "");
    for hit in certificate
        .matches
        .into_iter()
        .chain(certificate_templates::matches(data))
    {
        let (name, component) = match hit.family {
            crate::service_fingerprint::COBALT_STRIKE => ("Cobalt Strike", Some("Team Server")),
            crate::service_fingerprint::ASYNCRAT_FAMILY => ("AsyncRAT / DcRAT", None),
            certificate_templates::SLIVER => ("Sliver", Some("Multiplayer")),
            certificate_templates::QAKBOT => ("QakBot", None),
            _ => continue,
        };
        push(
            &mut result.products,
            Product {
                id: hit.family.into(),
                name: name.into(),
                component: component.map(str::to_owned),
                version: None,
                assessment: "suspected".into(),
                basis: if hit.family == certificate_templates::QAKBOT {
                    "historical_certificate_heuristic"
                } else {
                    "certificate_template"
                }
                .into(),
                evidence: vec![Evidence {
                    detection_method: Some("tls_certificate".into()),
                    rule_id: hit.rule_id.into(),
                    probe: hit.probe.into(),
                    field_path: hit.evidence_path,
                    details: hit
                        .evidence
                        .into_iter()
                        .map(|(key, value)| (key.into(), bounded(&value)))
                        .collect(),
                    sni: hit.sni.map(bounded),
                    http_host: hit.http_host.map(bounded),
                    source_url: Some(hit.source_url.into()),
                }],
            },
        );
    }

    let mut inspected = false;
    let mut incomplete = data.is_some_and(|data| data["product_evidence_truncated"] == true);
    incomplete |= evidence.len() > 64;
    incomplete |= evidence
        .iter()
        .any(|item| matches!(item["module"].as_str(), Some("tls" | "https")))
        && certificate.status == crate::service_fingerprint::Status::InsufficientEvidence;
    for (index, item) in evidence.iter().take(64).enumerate() {
        let module = item["module"].as_str().unwrap_or_default();
        if !matches!(module, "http" | "https" | "ssh" | "tls") {
            continue;
        }
        inspected = true;
        incomplete |=
            item["truncated"] == true || item["status"].as_str().is_some_and(|s| s != "success");
        let (value, field) = if module == "ssh" {
            (
                &item["result"]["server_id"]["software"],
                "/server_id/software",
            )
        } else if matches!(module, "http" | "https") {
            let response = item["result"]["redirect_response_chain"]
                .as_array()
                .and_then(|chain| chain.first());
            let field = if response.is_some() {
                "/redirect_response_chain/0/headers/server"
            } else {
                "/response/headers/server"
            };
            (item["result"].pointer(field).unwrap_or(&Value::Null), field)
        } else {
            continue;
        };
        let Some(text) = value
            .as_str()
            .or_else(|| value.as_array().filter(|values| values.len() == 1)?[0].as_str())
        else {
            continue;
        };
        // Explicit product declarations only; bodies, names and IOC payloads are excluded.
        let declaration = text.split_whitespace().next().unwrap_or_default();
        let (token, version) = declaration
            .split_once('/')
            .map_or((declaration, None), |(name, version)| (name, Some(version)));
        let (id, name) = match (module, token) {
            ("http" | "https", "nginx") => ("nginx", "nginx"),
            ("http" | "https", "Apache") => ("apache_http_server", "Apache HTTP Server"),
            ("ssh", token) if token.starts_with("OpenSSH_") => ("openssh", "OpenSSH"),
            _ => continue,
        };
        let version = if id == "openssh" {
            token
                .strip_prefix("OpenSSH_for_Windows_")
                .or_else(|| token.strip_prefix("OpenSSH_"))
        } else {
            version
        };
        push(
            &mut result.products,
            Product {
                id: id.into(),
                name: name.into(),
                component: None,
                version: version
                    .filter(|v| {
                        !v.is_empty()
                            && v.len() <= 80
                            && v.chars().all(|c| {
                                c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+')
                            })
                    })
                    .map(str::to_owned),
                assessment: "identified".into(),
                basis: "service_declaration".into(),
                evidence: vec![Evidence {
                    detection_method: Some(
                        if module == "ssh" {
                            "protocol_fingerprint"
                        } else {
                            "http_fingerprint"
                        }
                        .into(),
                    ),
                    rule_id: format!("{id}_service_declaration"),
                    probe: module.into(),
                    field_path: format!("/evidence/{index}/result{field}"),
                    details: vec![("declaration".into(), bounded(text))],
                    sni: None,
                    http_host: None,
                    source_url: None,
                }],
            },
        );
    }
    result.product_identification.status = if result
        .products
        .iter()
        .any(|product| product.assessment == "suspected")
    {
        "suspected"
    } else if !result.products.is_empty() {
        "identified"
    } else if inspected && !incomplete {
        "not_matched"
    } else {
        "insufficient_evidence"
    }
    .into();
    result.product_identification.coverage = if inspected && !incomplete {
        "complete"
    } else {
        "partial"
    }
    .into();
    result
}

/// Raw fallback is allowed only when it belongs to this exact service observation.
pub(crate) fn view(source: &Value, observed_at: i64, use_raw_data: bool) -> Products {
    let identification = source
        .get("product_identification")
        .cloned()
        .and_then(|value| serde_json::from_value::<Identification>(value).ok());
    let identification =
        identification.filter(|value| value.ruleset_revision == RULESET_REVISION || !use_raw_data);
    let mut result = if let Some(identification) = identification {
        Products {
            products: source
                .get("products")
                .cloned()
                .and_then(|value| serde_json::from_value(value).ok())
                .unwrap_or_default(),
            product_identification: identification,
        }
    } else {
        infer(
            source.get("data").filter(|_| use_raw_data),
            observed_at,
            source.get("service_observation_ref").cloned(),
        )
    };
    result.product_identification.stale = result.product_identification.observed_at < observed_at
        || result.product_identification.ruleset_revision != RULESET_REVISION;
    result
}

pub(crate) fn mapping() -> Value {
    json!({"type":"nested", "dynamic":"strict", "properties": {
        "id":{"type":"keyword"}, "name":{"type":"keyword"}, "component":{"type":"keyword"},
        "version":{"type":"keyword"}, "assessment":{"type":"keyword"}, "basis":{"type":"keyword"},
        "evidence":{"type":"object", "enabled":false}
    }})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_sliver_leaf() -> Value {
        json!({"fingerprint_sha256":"a".repeat(64), "subject_dn":"CN=multiplayer", "issuer_dn":"CN=operators",
            "signature":{"self_signed":false,"signature_algorithm":{"name":"ECDSA-SHA256"}}})
    }

    fn synthetic_qakbot_leaf() -> Value {
        // Anonymized DN fields shaped like the historical research examples.
        json!({"fingerprint_sha256":"b".repeat(64),
            "subject_dn":"C=US, OU=Random Research Fixture, CN=sampletest.invalid",
            "issuer_dn":"C=US, ST=CA, L=Samplecity, O=Example Research LLC., CN=sampletest.invalid",
            "signature":{"self_signed":false,"signature_algorithm":{"name":"SHA256-RSA"}}})
    }

    fn tls_observation(leaf: Value) -> Value {
        json!({"schema_version":2,"evidence":[{"module":"tls","status":"success","result":{
            "handshake_log":{"server_certificates":{"certificate":{"parsed":leaf}}}
        }}]})
    }

    #[test]
    fn sliver_and_qakbot_are_scoped_candidates_from_the_same_protocol_product_pipeline() {
        for (leaf, id, component, basis) in [
            (
                synthetic_sliver_leaf(),
                "sliver",
                Some("Multiplayer"),
                "certificate_template",
            ),
            (
                synthetic_qakbot_leaf(),
                "qakbot",
                None,
                "historical_certificate_heuristic",
            ),
        ] {
            let data = tls_observation(leaf);
            let result = infer(Some(&data), 1234, Some(json!({"id":"observation"})));
            assert_eq!(result.products.len(), 1);
            let product = &result.products[0];
            assert_eq!(product.id, id);
            assert_eq!(product.component.as_deref(), component);
            assert_eq!(product.basis, basis);
            assert_eq!(product.assessment, "suspected");
            assert!(product.version.is_none());
            assert!(data.pointer(&product.evidence[0].field_path).is_some());
            assert!(
                product.evidence[0]
                    .source_url
                    .as_ref()
                    .unwrap()
                    .starts_with("https://")
            );
            assert_eq!(
                result.product_identification.ruleset_revision,
                RULESET_REVISION
            );
        }
    }

    #[test]
    fn generic_mtls_partial_or_contradictory_sliver_fields_do_not_identify_sliver() {
        for (path, value) in [
            ("/issuer_dn", json!("CN=Example CA")),
            ("/subject_dn", json!("CN=multiplayer.example")),
            ("/signature/self_signed", json!(true)),
            ("/signature/self_signed", Value::Null),
            ("/signature/signature_algorithm/name", json!("SHA256-RSA")),
        ] {
            let mut leaf = synthetic_sliver_leaf();
            *leaf.pointer_mut(path).unwrap() = value;
            assert!(
                infer(Some(&tls_observation(leaf)), 1234, None)
                    .products
                    .is_empty(),
                "accepted {path}"
            );
        }
        let data = tls_observation(
            json!({"subject_dn":"CN=localhost", "issuer_dn":"CN=Example CA",
            "signature":{"self_signed":false,"signature_algorithm":{"name":"ECDSA-SHA256"}}}),
        );
        assert!(infer(Some(&data), 1234, None).products.is_empty());
    }

    #[test]
    fn qakbot_requires_both_complete_dn_shapes_and_correlated_identity_fields() {
        for (field, value) in [
            (
                "subject_dn",
                "C=US, OU=Domain Control Validated, CN=sampletest.invalid",
            ),
            (
                "subject_dn",
                "C=US, O=Example Corp, OU=Random Research Fixture, CN=sampletest.invalid",
            ),
            (
                "issuer_dn",
                "C=US, ST=CA, L=Samplecity, O=Example Research LLC., CN=other.invalid",
            ),
            (
                "issuer_dn",
                "C=GB, ST=CA, L=Samplecity, O=Example Research LLC., CN=sampletest.invalid",
            ),
            (
                "issuer_dn",
                "C=US, ST=CA, L=Samplecity, O=Example Research LLC., CN=sampletest.invalid, OU=extra",
            ),
            ("issuer_dn", "CN=Trusted Public CA"),
        ] {
            let mut leaf = synthetic_qakbot_leaf();
            leaf[field] = json!(value);
            assert!(
                infer(Some(&tls_observation(leaf)), 1234, None)
                    .products
                    .is_empty(),
                "accepted {field}: {value}"
            );
        }
        let mut incomplete = synthetic_qakbot_leaf();
        incomplete["issuer_dn"] = Value::Null;
        assert!(
            infer(Some(&tls_observation(incomplete)), 1234, None)
                .products
                .is_empty()
        );
        let mut oversized = synthetic_qakbot_leaf();
        oversized["subject_dn"] = json!(format!(
            "C=US, OU={}, CN=sampletest.invalid",
            "a".repeat(2048)
        ));
        assert!(
            infer(Some(&tls_observation(oversized)), 1234, None)
                .products
                .is_empty()
        );
    }

    #[test]
    fn new_candidates_use_the_leaf_and_first_https_response_even_when_a_handshake_fails() {
        let mut failed = tls_observation(synthetic_sliver_leaf());
        failed["evidence"][0]["status"] = json!("handshake-error");
        let result = infer(Some(&failed), 1234, None);
        assert_eq!(result.products[0].id, "sliver");
        assert_eq!(result.product_identification.coverage, "partial");
        for leaf in [synthetic_sliver_leaf(), synthetic_qakbot_leaf()] {
            let ordinary = json!({"fingerprint_sha256":"c".repeat(64), "subject_dn":"CN=ordinary", "issuer_dn":"CN=ordinary"});
            let mut data = tls_observation(ordinary.clone());
            data["evidence"][0]["result"]["handshake_log"]["server_certificates"]["chain"] =
                json!([{"parsed":leaf.clone()}]);
            assert!(infer(Some(&data), 1234, None).products.is_empty());
            let tls = json!({"handshake_log":{"server_certificates":{"certificate":{"parsed":leaf.clone()}}}});
            let mut data = json!({"schema_version":2,"evidence":[{"module":"https","status":"success","result":{
                "redirect_response_chain":[{"request":{"tls_log":{"handshake_log":{"server_certificates":{"certificate":{"parsed":ordinary}}}}}}],
                "response":{"request":{"tls_log":tls}}
            }}]});
            assert!(infer(Some(&data), 1234, None).products.is_empty());
            data["evidence"][0]["result"]["redirect_response_chain"][0]["request"]["tls_log"]["handshake_log"]
                ["server_certificates"]["certificate"]["parsed"] = leaf;
            let result = infer(Some(&data), 1234, None);
            assert_eq!(result.products.len(), 1);
            assert!(
                result.products[0].evidence[0]
                    .field_path
                    .contains("redirect_response_chain/0")
            );
        }
    }

    #[test]
    fn revision_two_recomputes_matching_raw_observations_without_renewing_old_unrelated_evidence() {
        let data = tls_observation(synthetic_sliver_leaf());
        let mut source = json!(infer(Some(&data), 1000, None));
        source["product_identification"]["ruleset_revision"] = json!(1);
        source["products"] = json!([]);
        source["data"] = data;
        assert_eq!(view(&source, 1000, true).products[0].id, "sliver");
        let old = view(&source, 2000, false);
        assert!(old.products.is_empty());
        assert!(old.product_identification.stale);
        assert_eq!(old.product_identification.observed_at, 1000);
    }

    #[test]
    fn ordinary_product_and_c2_candidate_share_the_contract_without_iocs() {
        let data = json!({"schema_version":2,"evidence":[
            {"module":"https","status":"success","result":{"response":{"headers":{"server":["nginx/1.26.2"]}}}},
            {"module":"tls","status":"success","result":{"handshake_log":{"server_certificates":{"certificate":{"parsed":{
                "fingerprint_sha256":"87f2085c32b6a2cc709b365f55873e207a9caa10bffecf2fd16d3cf9d94d390c"
            }}}}}}
        ]});
        let result = infer(Some(&data), 1234, None);
        assert_eq!(result.products.len(), 2);
        assert_eq!(result.products[0].assessment, "suspected");
        assert_eq!(result.products[1].id, "nginx");
        assert_eq!(result.products[1].version.as_deref(), Some("1.26.2"));
        assert_eq!(result.product_identification.status, "suspected");
    }

    #[test]
    fn bodies_redirect_destinations_and_partial_observations_do_not_establish_products() {
        let data = json!({"schema_version":2,"evidence":[{"module":"https","status":"success","truncated":true,"result":{
            "redirect_response_chain":[{"headers":{"server":["unrelated"]}}],
            "response":{"headers":{"server":["nginx/1.26.2"]},"body":"Cobalt Strike AsyncRAT nginx"}
        }}]});
        let result = infer(Some(&data), 1234, None);
        assert!(result.products.is_empty());
        assert_eq!(result.product_identification.coverage, "partial");
        assert_eq!(
            result.product_identification.status,
            "insufficient_evidence"
        );
    }

    #[test]
    fn openssh_release_versions_exclude_windows_platform_markers() {
        for (software, version) in [
            ("OpenSSH_for_Windows_9.5", "9.5"),
            ("OpenSSH_for_Windows_9.5.0.0", "9.5.0.0"),
            ("OpenSSH_9.5p1 Ubuntu-3", "9.5p1"),
            ("OpenSSH_9.6", "9.6"),
        ] {
            let data = json!({"schema_version":2,"evidence":[{"module":"ssh","status":"success","result":{"server_id":{"software":software}}}]});
            let inferred = infer(Some(&data), 1234, None);
            assert_eq!(inferred.products[0].id, "openssh");
            assert_eq!(inferred.products[0].version.as_deref(), Some(version));
            assert_eq!(inferred.products[0].evidence[0].details[0].1, software);
            let mut stored = json!(inferred);
            stored["data"] = data;
            stored["product_identification"]["ruleset_revision"] = json!(3);
            stored["products"][0]["version"] = json!("for_Windows_9.5");
            let refreshed = view(&stored, 1234, true);
            assert_eq!(refreshed.products[0].version.as_deref(), Some(version));
            assert_eq!(refreshed.product_identification.observed_at, 1234);
            assert_eq!(
                refreshed.product_identification.ruleset_revision,
                RULESET_REVISION
            );
            assert!(!refreshed.product_identification.stale);
            let without_matching_raw = view(&stored, 1234, false);
            assert!(without_matching_raw.product_identification.stale);
            assert_eq!(
                without_matching_raw.products[0].version.as_deref(),
                Some("for_Windows_9.5")
            );
        }
    }

    #[test]
    fn port_only_updates_preserve_product_time_and_do_not_use_unrelated_raw_data() {
        let raw = json!({"data":{"schema_version":2,"evidence":[{"module":"ssh","result":{"server_id":{"software":"OpenSSH_9.6"}}}]}});
        assert!(view(&raw, 2000, false).products.is_empty());
        let mut stored = json!(view(&raw, 1000, true));
        stored["data"] = Value::Null;
        let result = view(&stored, 2000, false);
        assert_eq!(result.products[0].id, "openssh");
        assert!(result.product_identification.stale);
    }
}
