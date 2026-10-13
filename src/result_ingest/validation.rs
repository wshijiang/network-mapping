//! result_ingest / validation domain implementation, migrated from the library root.

use serde_json::Value;

use super::model::*;

/// PostgreSQL 的 text/jsonb 类型不接受 NUL 字节，写入会报
/// 22P05 unsupported Unicode escape sequence。zgrab2 抓取的服务数据
/// （banner、响应体等）常含 NUL，写库前必须剔除。
pub(crate) fn sanitize_text(value: &str) -> String {
    if value.contains('\0') {
        value.replace('\0', "")
    } else {
        value.to_owned()
    }
}

pub(crate) fn sanitize_json_value(value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(sanitize_text(&text)),
        Value::Array(items) => Value::Array(items.into_iter().map(sanitize_json_value).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (sanitize_text(&key), sanitize_json_value(value)))
                .collect(),
        ),
        other => other,
    }
}

pub(crate) fn sanitize_result_item(item: ScannerResultItem) -> ScannerResultItem {
    ScannerResultItem {
        protocol: item.protocol.map(|value| sanitize_text(&value)),
        service: item.service.map(|value| sanitize_text(&value)),
        banner: item.banner.map(|value| sanitize_text(&value)),
        other: item.other.map(sanitize_json_value),
        ..item
    }
}

pub(crate) fn normalize_upload_observations(
    upload: &ScannerResultUpload,
) -> Result<Vec<NormalizedObservation>, SaveScannerResultsError> {
    let is_typed = matches!(upload.protocol_version, 2 | 3);
    let observations: Vec<NormalizedObservation> = if is_typed {
        upload
            .observations
            .iter()
            .map(|observation| match observation {
                ScannerObservation::Port {
                    ip,
                    port,
                    protocol,
                    state,
                    source,
                    observed_at,
                } => {
                    let state = sanitize_text(state);
                    let source = sanitize_text(source);
                    NormalizedObservation {
                        kind: "port",
                        ip: ip.clone(),
                        port: *port,
                        protocol: Some(sanitize_text(protocol)),
                        service: None,
                        banner: None,
                        source,
                        data: Some(serde_json::json!({"state": state})),
                        observed_at: *observed_at,
                    }
                }
                ScannerObservation::Service {
                    ip,
                    port,
                    protocol,
                    service,
                    banner,
                    source,
                    data,
                    observed_at,
                } => {
                    let source = sanitize_text(source);
                    let data = data.clone().map(sanitize_json_value);
                    NormalizedObservation {
                        kind: "service",
                        ip: ip.clone(),
                        port: *port,
                        protocol: Some(sanitize_text(protocol)),
                        service: service.as_deref().map(sanitize_text),
                        banner: banner.as_deref().map(sanitize_text),
                        source,
                        data,
                        observed_at: *observed_at,
                    }
                }
                ScannerObservation::Dns { .. } => {
                    unreachable!("DNS observations are handled before endpoint normalization")
                }
                ScannerObservation::Vulnerability {
                    ip,
                    port,
                    protocol,
                    template_id,
                    name,
                    severity,
                    matcher_name,
                    matched_at,
                    description,
                    remediation,
                    tags,
                    references,
                    classification,
                    extracted_results,
                    source,
                    observed_at,
                } => NormalizedObservation {
                    kind: "vulnerability",
                    ip: ip.clone(),
                    port: *port,
                    protocol: Some(sanitize_text(protocol)),
                    service: None,
                    banner: None,
                    source: sanitize_text(source),
                    data: Some(sanitize_json_value(serde_json::json!({
                        "template_id": template_id,
                        "name": name,
                        "severity": severity.to_ascii_lowercase(),
                        "matcher_name": matcher_name,
                        "matched_at": matched_at,
                        "description": description,
                        "remediation": remediation,
                        "tags": tags,
                        "references": references,
                        "classification": classification,
                        "extracted_results": extracted_results,
                    }))),
                    observed_at: *observed_at,
                },
            })
            .collect()
    } else {
        upload
            .results
            .iter()
            .cloned()
            .map(sanitize_result_item)
            .map(|item| {
                let kind = if item
                    .service
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
                    || item
                        .banner
                        .as_deref()
                        .is_some_and(|value| !value.is_empty())
                {
                    "service"
                } else {
                    "port"
                };
                let source = item
                    .other
                    .as_ref()
                    .and_then(|value| value.get("source"))
                    .and_then(Value::as_str)
                    .map(sanitize_text)
                    .filter(|value| !value.is_empty() && value.len() <= 64)
                    .unwrap_or_else(|| "legacy".to_owned());
                let data = Some(serde_json::json!({
                    "state": "open",
                    "legacy_other": item.other.clone(),
                }));
                NormalizedObservation {
                    kind,
                    ip: item.ip,
                    port: item.port,
                    protocol: item.protocol.filter(|value| !value.is_empty()),
                    service: item.service,
                    banner: item.banner,
                    source,
                    data,
                    observed_at: None,
                }
            })
            .collect()
    };

    for observation in &observations {
        if observation.port == 0
            || observation
                .protocol
                .as_ref()
                .is_some_and(|value| value.len() > 16)
            || (is_typed
                && observation
                    .protocol
                    .as_ref()
                    .is_none_or(|value| value.is_empty()))
            || observation.source.is_empty()
            || observation.source.len() > 64
            || observation
                .service
                .as_ref()
                .is_some_and(|value| value.len() > 128)
            || observation
                .banner
                .as_ref()
                .is_some_and(|value| value.len() > 4096)
            || (observation.kind == "port"
                && observation
                    .data
                    .as_ref()
                    .and_then(|value| value["state"].as_str())
                    != Some("open"))
            || observation
                .data
                .as_ref()
                .is_some_and(|value| value.to_string().len() > 1_048_576)
            || (observation.kind == "vulnerability"
                && !valid_vulnerability_data(observation.data.as_ref()))
        {
            return Err(SaveScannerResultsError::InvalidUpload(
                "observation fields exceed allowed values or sizes".into(),
            ));
        }
    }

    Ok(observations)
}

pub(crate) fn valid_vulnerability_data(data: Option<&Value>) -> bool {
    let Some(data) = data else { return false };
    let text = |field: &str, max: usize| {
        data.get(field)
            .and_then(Value::as_str)
            .is_some_and(|value| {
                !value.trim().is_empty() && !value.contains('\0') && value.len() <= max
            })
    };
    let optional_text = |field: &str, max: usize| {
        data.get(field).is_none_or(|value| {
            value.is_null()
                || value
                    .as_str()
                    .is_some_and(|value| !value.contains('\0') && value.len() <= max)
        })
    };
    let string_array = |field: &str, max_items: usize, max_len: usize| {
        data.get(field)
            .and_then(Value::as_array)
            .is_some_and(|values| {
                values.len() <= max_items
                    && values.iter().all(|value| {
                        value
                            .as_str()
                            .is_some_and(|value| !value.contains('\0') && value.len() <= max_len)
                    })
            })
    };
    text("template_id", 256)
        && text("name", 512)
        && text("matched_at", 4_096)
        && optional_text("matcher_name", 256)
        && optional_text("description", 8_192)
        && optional_text("remediation", 8_192)
        && data
            .get("severity")
            .and_then(Value::as_str)
            .is_some_and(|value| matches!(value, "info" | "low" | "medium" | "high" | "critical"))
        && string_array("tags", 128, 128)
        && string_array("references", 64, 2_048)
        && data
            .get("references")
            .and_then(Value::as_array)
            .is_some_and(|values| {
                values.iter().all(|value| {
                    value.as_str().is_some_and(|value| {
                        value.starts_with("https://") || value.starts_with("http://")
                    })
                })
            })
        && string_array("extracted_results", 64, 2_048)
}

#[cfg(test)]
mod sanitize_nul_tests {
    use super::{
        ScannerResultItem, ScannerResultUpload, normalize_upload_observations, sanitize_json_value,
        sanitize_result_item, sanitize_text,
    };

    #[test]
    fn strips_nul_from_plain_text() {
        assert_eq!(sanitize_text("a\u{0}b\u{0}c"), "abc");
        assert_eq!(sanitize_text("no nul"), "no nul");
    }

    #[test]
    fn strips_nul_from_nested_json_values() {
        let value = serde_json::json!({
            "module": "http\u{0}",
            "data": {
                "response": {"body": "bin\u{0}ary"},
                "tags": ["a\u{0}", "b"],
            }
        });
        let sanitized = sanitize_json_value(value);
        assert_eq!(sanitized["module"], "http");
        assert_eq!(sanitized["data"]["response"]["body"], "binary");
        assert_eq!(sanitized["data"]["tags"][0], "a");
        assert_eq!(sanitized["data"]["tags"][1], "b");
    }

    #[test]
    fn strips_nul_from_result_item() {
        let item = ScannerResultItem {
            ip: "192.0.2.1".into(),
            port: 80,
            protocol: Some("tcp\u{0}".into()),
            service: Some("http\u{0}".into()),
            banner: Some("banner\u{0}".into()),
            other: Some(serde_json::json!({"data": "x\u{0}y"})),
        };
        let sanitized = sanitize_result_item(item);
        assert_eq!(sanitized.protocol.as_deref(), Some("tcp"));
        assert_eq!(sanitized.service.as_deref(), Some("http"));
        assert_eq!(sanitized.banner.as_deref(), Some("banner"));
        assert_eq!(sanitized.other.unwrap()["data"], "xy");
    }

    #[test]
    fn normalizes_legacy_results_into_observations() {
        let upload: ScannerResultUpload = serde_json::from_value(serde_json::json!({
            "scanner_id": "00000000-0000-0000-0000-000000000001",
            "task_id": "00000000-0000-0000-0000-000000000002",
            "results": [{
                "ip": "192.0.2.1",
                "port": 443,
                "protocol": null,
                "service": "https",
                "banner": null,
                "other": {"source": "legacy-probe", "tls": true}
            }]
        }))
        .unwrap();

        let observations = normalize_upload_observations(&upload).unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].kind, "service");
        assert_eq!(observations[0].protocol, None);
        assert_eq!(observations[0].source, "legacy-probe");
        assert_eq!(observations[0].data.as_ref().unwrap()["state"], "open");
    }

    #[test]
    fn rejects_typed_observations_without_protocol() {
        let upload: ScannerResultUpload = serde_json::from_value(serde_json::json!({
            "protocol_version": 2,
            "scanner_id": "00000000-0000-0000-0000-000000000001",
            "task_id": "00000000-0000-0000-0000-000000000002",
            "upload_id": "00000000-0000-0000-0000-000000000003",
            "batch_index": 0,
            "is_final": true,
            "observations": [{
                "kind": "port",
                "ip": "192.0.2.1",
                "port": 80,
                "protocol": "",
                "state": "open",
                "source": "masscan"
            }]
        }))
        .unwrap();

        assert!(normalize_upload_observations(&upload).is_err());
    }
}
