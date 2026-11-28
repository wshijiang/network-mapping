//! Collection metadata is separate from product attribution. JARM alone never
//! creates a product candidate or a malware assertion.
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct DetectionMethod {
    pub id: String,
    pub name: String,
    /// Describes how scanner observations are acquired. Analysis is local.
    pub active_probe: bool,
    pub additional_probe: bool,
    pub observed: bool,
    /// Stable key; clients may translate it without parsing human prose.
    pub principle: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct JarmObservation {
    pub status: String,
    pub fingerprint: Option<String>,
    pub expected_probes: u64,
    pub attempted_probes: u64,
    pub completed_probes: u64,
    pub sni: Option<String>,
    pub field_path: String,
}

pub(super) fn catalog(evidence: &[Value]) -> Vec<DetectionMethod> {
    [
        ("jarm", "JARM", true, "tls_server_response"),
        (
            "tls_certificate",
            "TLS Certificate",
            false,
            "certificate_metadata",
        ),
        (
            "http_fingerprint",
            "HTTP Fingerprint",
            false,
            "http_response",
        ),
        (
            "protocol_fingerprint",
            "Protocol Fingerprint",
            false,
            "application_protocol",
        ),
    ]
    .into_iter()
    .map(|(id, name, additional, principle)| {
        let observed = evidence.iter().take(64).any(|item| {
            let module = item["module"].as_str().unwrap_or_default();
            match id {
                "jarm" => {
                    module == "jarm"
                        && item["result"]["attempted_probes"]
                            .as_u64()
                            .is_some_and(|n| n > 0)
                }
                "tls_certificate" => {
                    matches!(module, "tls" | "https")
                        && crate::service_fingerprint::probe_tls(item, module)
                            .and_then(|(tls, _, _)| {
                                crate::service_fingerprint::leaf_certificate(tls)
                            })
                            .is_some()
                }
                "http_fingerprint" => {
                    (module == "web_assets" && item.pointer("/result/xmrig_summary").is_some())
                        || (matches!(module, "http" | "https")
                            && (item["result"]["response"].is_object()
                                || item["result"]["redirect_response_chain"]
                                    .as_array()
                                    .is_some_and(|chain| !chain.is_empty())))
                }
                _ => {
                    !matches!(module, "jarm" | "web_assets" | "tls" | "")
                        && item["status"] == "success"
                }
            }
        });
        let active_probe = id != "protocol_fingerprint"
            || !observed
            || evidence.iter().take(64).any(|item| {
                !matches!(
                    item["module"].as_str().unwrap_or_default(),
                    "jarm" | "web_assets" | "tls" | "opcua_pubsub" | "enip_io" | ""
                ) && item["status"] == "success"
            });
        DetectionMethod {
            id: id.into(),
            name: name.into(),
            active_probe,
            additional_probe: additional
                || (id == "http_fingerprint"
                    && evidence.iter().take(64).any(|item| {
                        item["module"] == "web_assets"
                            && item.pointer("/result/xmrig_summary").is_some()
                    })),
            observed,
            principle: principle.into(),
        }
    })
    .collect()
}

pub(super) fn jarm(evidence: &[Value]) -> Option<JarmObservation> {
    evidence
        .iter()
        .take(64)
        .enumerate()
        .find_map(|(index, item)| {
            if item["module"] != "jarm" || item["truncated"] == true {
                return None;
            }
            let result = &item["result"];
            if result["profile"] != "salesforce-jarm"
                || result["active_probe"] != true
                || result["expected_probes"] != 10
            {
                return None;
            }
            let attempted = result["attempted_probes"].as_u64()?;
            let completed = result["completed_probes"].as_u64()?;
            if attempted > 10 || completed > attempted {
                return None;
            }
            let status = item["status"].as_str()?;
            if !matches!(status, "success" | "partial" | "no_response") {
                return None;
            }
            let statuses = result["probe_statuses"].as_array()?;
            if statuses.len() != attempted as usize {
                return None;
            }
            let valid = statuses
                .iter()
                .filter(|s| matches!(s.as_str(), Some("server_hello" | "rejected")))
                .count();
            if valid != completed as usize {
                return None;
            }
            let fingerprint = if status == "success" {
                let fingerprint = result["fingerprint"].as_str()?;
                if completed != 10
                    || !statuses.iter().any(|s| s == "server_hello")
                    || fingerprint.len() != 62
                    || !fingerprint
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || fingerprint.bytes().all(|b| b == b'0')
                {
                    return None;
                }
                Some(fingerprint.to_owned())
            } else {
                if !result["fingerprint"].is_null()
                    || (status == "no_response"
                        && (completed != 10 || statuses.iter().any(|s| s != "rejected")))
                    || (status == "partial" && completed == 10)
                {
                    return None;
                }
                None
            };
            Some(JarmObservation {
                status: status.into(),
                fingerprint,
                expected_probes: 10,
                attempted_probes: attempted,
                completed_probes: completed,
                sni: result["sni"]
                    .as_str()
                    .filter(|s| s.len() <= 253 && !s.bytes().any(|b| b.is_ascii_control()))
                    .map(str::to_owned),
                field_path: format!("/evidence/{index}/result"),
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn observation() -> Value {
        json!({"module":"jarm","status":"success","result":{
            "profile":"salesforce-jarm","active_probe":true,"expected_probes":10,
            "attempted_probes":10,"completed_probes":10,
            "probe_statuses":vec!["server_hello";10],"sni":"asset.example",
            "fingerprint":"41d41d41d41d41d41d41d41d41d41da0bfb9dc5a7a50dfa51c2a70be11dda8"
        }})
    }
    #[test]
    fn fingerprint_is_an_observation_without_product_or_malware_attribution() {
        let data = json!({"schema_version":2,"evidence":[observation()]});
        let result = crate::service_products::infer(Some(&data), 1234, None);
        assert!(result.products.is_empty());
        let metadata = result.product_identification;
        assert_eq!(metadata.status, "insufficient_evidence");
        assert_eq!(metadata.jarm.unwrap().completed_probes, 10);
        assert!(metadata.detection_methods[0].observed);
        assert!(metadata.detection_methods[0].additional_probe);
        assert!(!metadata.detection_methods[1].observed);
        assert!(!metadata.detection_methods[1].additional_probe);
    }
    #[test]
    fn rejects_incomplete_zero_malformed_and_inconsistent_success_hashes() {
        let base = observation();
        for (path, value) in [
            ("/result/completed_probes", json!(9)),
            ("/result/expected_probes", json!(9)),
            ("/result/active_probe", json!(false)),
            ("/result/fingerprint", json!("0".repeat(62))),
            ("/result/fingerprint", json!("A".repeat(62))),
            ("/result/fingerprint", json!("f".repeat(63))),
            ("/result/probe_statuses", json!(vec!["rejected"; 10])),
            ("/status", json!("partial")),
            ("/truncated", json!(true)),
        ] {
            let mut item = base.clone();
            if path == "/truncated" {
                item["truncated"] = value;
            } else {
                *item.pointer_mut(path).unwrap() = value;
            }
            assert!(jarm(&[item]).is_none(), "{path}");
        }
    }
    #[test]
    fn partial_and_rejected_observations_never_publish_a_hash() {
        let mut item = observation();
        item["result"]["fingerprint"] = Value::Null;
        item["status"] = json!("partial");
        item["result"]["completed_probes"] = json!(9);
        item["result"]["probe_statuses"][9] = json!("timeout");
        let partial = jarm(&[item.clone()]).unwrap();
        assert_eq!(partial.status, "partial");
        assert!(partial.fingerprint.is_none());
        item["status"] = json!("no_response");
        item["result"]["completed_probes"] = json!(10);
        item["result"]["probe_statuses"] = json!(vec!["rejected"; 10]);
        assert!(jarm(&[item]).unwrap().fingerprint.is_none());
    }
    #[test]
    fn passive_protocol_observations_are_not_described_as_active_probes() {
        let evidence = vec![json!({"module":"opcua_pubsub","status":"success"})];
        let methods = catalog(&evidence);
        let protocol = methods
            .iter()
            .find(|m| m.id == "protocol_fingerprint")
            .unwrap();
        assert!(protocol.observed);
        assert!(!protocol.active_probe);
        let mut mixed = evidence;
        mixed.push(json!({"module":"ssh","status":"success"}));
        assert!(
            catalog(&mixed)
                .iter()
                .find(|m| m.id == "protocol_fingerprint")
                .unwrap()
                .active_probe
        );
    }
    #[test]
    fn legacy_serialized_metadata_defaults_without_claiming_collection() {
        let legacy = json!({"status":"not_matched","coverage":"complete","ruleset_revision":2,"observed_at":1234,"stale":false,"observation_ref":null});
        let restored: crate::service_products::Identification =
            serde_json::from_value(legacy).unwrap();
        assert!(restored.jarm.is_none());
        assert!(restored.detection_methods.is_empty());
    }
}
