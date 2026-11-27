//! Product identity from protocol-owned observations. No IOC lookups or network I/O.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub(crate) const RULESET_REVISION: u32 = 1;
const MAX_EVIDENCE: usize = 8;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Evidence {
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
        },
    };
    let Some(evidence) = data
        .filter(|data| data["schema_version"] == 2)
        .and_then(|data| data["evidence"].as_array())
    else {
        return result;
    };

    // Existing certificate rules are local product rules, independent of intel storage.
    // Their observations establish deployment candidates, never malicious intent.
    let certificate = crate::service_fingerprint::assess(data, observed_at, "", "");
    for hit in certificate.matches {
        let (name, component) = match hit.family {
            crate::service_fingerprint::COBALT_STRIKE => ("Cobalt Strike", Some("Team Server")),
            crate::service_fingerprint::ASYNCRAT_FAMILY => ("AsyncRAT / DcRAT", None),
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
                basis: "certificate_template".into(),
                evidence: vec![Evidence {
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
            token.strip_prefix("OpenSSH_")
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
