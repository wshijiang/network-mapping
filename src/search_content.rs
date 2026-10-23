use std::collections::BTreeSet;
use std::sync::LazyLock;

use chrono::DateTime;
use regex::Regex;
use serde_json::Value;

const MAX_TITLE_CHARS: usize = 512;
const MAX_HTTP_BODY_BYTES: usize = 256 * 1024;
const MAX_TLS_SUBJECT_CHARS: usize = 4_096;
const MAX_TLS_NAMES: usize = 256;
const MAX_TLS_NAME_CHARS: usize = 512;
const MAX_JSON_DEPTH: usize = 16;

static TITLE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<title(?:\s[^>]*)?>(.*?)</title>").expect("title regex is valid")
});
static HTML_TAG_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<[^>]+>").expect("html tag regex is valid"));

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct SearchContent {
    pub(crate) title: Option<String>,
    pub(crate) http_body: Option<String>,
    pub(crate) http_body_truncated: bool,
    pub(crate) tls_mode: Option<String>,
    pub(crate) tls_version: Option<String>,
    pub(crate) tls_cipher_suite: Option<String>,
    pub(crate) tls_subject: Option<String>,
    pub(crate) tls_issuer: Option<String>,
    pub(crate) tls_names: Vec<String>,
    pub(crate) tls_serial_number: Option<String>,
    pub(crate) tls_not_before: Option<String>,
    pub(crate) tls_not_after: Option<String>,
    pub(crate) tls_fingerprint_sha256: Option<String>,
    pub(crate) tls_self_signed: Option<bool>,
}

pub(crate) fn extract_search_content(data: Option<&Value>) -> SearchContent {
    let Some(data) = data else {
        return SearchContent::default();
    };
    let body = find_string_by_key(data, &["body"], 0).map(|value| value.to_owned());
    let (http_body, http_body_truncated) = body
        .map(|value| truncate_utf8_bytes(&value, MAX_HTTP_BODY_BYTES))
        .map(|(value, truncated)| (Some(value), truncated))
        .unwrap_or((None, false));
    let http_body_truncated = http_body_truncated || has_truncated_http_evidence(data);
    let title = http_body
        .as_deref()
        .and_then(extract_html_title)
        .or_else(|| find_string_by_key(data, &["title"], 0).map(clean_text))
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(MAX_TITLE_CHARS).collect());
    let tls_evidence = find_tls_evidence(data);
    let tls_result = tls_evidence.map(|(_, result)| result).unwrap_or(data);
    let handshake = find_value_by_key(tls_result, &["handshake_log"], 0).unwrap_or(tls_result);
    let server_hello = find_value_by_key(handshake, &["server_hello"], 0);
    let leaf_certificate =
        find_value_by_key(handshake, &["server_certificates"], 0).and_then(|certificates| {
            certificates
                .pointer("/certificate/parsed")
                .or_else(|| certificates.get("certificate"))
                .or(Some(certificates))
        });
    let tls_subject = leaf_certificate
        .and_then(|certificate| {
            find_value_by_key(certificate, &["subject_dn", "subjectDN", "subject"], 0)
        })
        .and_then(value_as_text)
        .map(|value| value.chars().take(MAX_TLS_SUBJECT_CHARS).collect())
        .filter(|value: &String| !value.is_empty());
    let tls_issuer = leaf_certificate
        .and_then(|certificate| {
            find_value_by_key(certificate, &["issuer_dn", "issuerDN", "issuer"], 0)
        })
        .and_then(value_as_text)
        .map(|value| value.chars().take(MAX_TLS_SUBJECT_CHARS).collect())
        .filter(|value: &String| !value.is_empty());
    let tls_names = leaf_certificate
        .map(tls_certificate_names)
        .unwrap_or_default();
    let tls_serial_number = leaf_certificate
        .and_then(|certificate| find_string_by_key(certificate, &["serial_number"], 0))
        .map(clean_text)
        .filter(|value| !value.is_empty());
    let tls_not_before = leaf_certificate
        .and_then(|certificate| certificate.pointer("/validity/start"))
        .and_then(Value::as_str)
        .and_then(normalize_rfc3339);
    let tls_not_after = leaf_certificate
        .and_then(|certificate| certificate.pointer("/validity/end"))
        .and_then(Value::as_str)
        .and_then(normalize_rfc3339);
    let tls_fingerprint_sha256 = leaf_certificate
        .and_then(|certificate| find_string_by_key(certificate, &["fingerprint_sha256"], 0))
        .map(clean_text)
        .filter(|value| !value.is_empty());
    let tls_self_signed = leaf_certificate
        .and_then(|certificate| certificate.pointer("/signature/self_signed"))
        .and_then(Value::as_bool);
    let tls_version = server_hello
        .and_then(|hello| hello.pointer("/version/name"))
        .and_then(Value::as_str)
        .map(clean_text)
        .filter(|value| !value.is_empty());
    let tls_cipher_suite = server_hello
        .and_then(|hello| hello.pointer("/cipher_suite/name"))
        .and_then(Value::as_str)
        .map(clean_text)
        .filter(|value| !value.is_empty());
    let tls_mode = tls_evidence
        .map(|(module, result)| classify_tls_mode(module, result).to_owned())
        .or_else(|| {
            (find_value_by_key(data, &["handshake_log"], 0).is_some())
                .then(|| classify_tls_mode("", data).to_owned())
        });

    SearchContent {
        title,
        http_body,
        http_body_truncated,
        tls_mode,
        tls_version,
        tls_cipher_suite,
        tls_subject,
        tls_issuer,
        tls_names,
        tls_serial_number,
        tls_not_before,
        tls_not_after,
        tls_fingerprint_sha256,
        tls_self_signed,
    }
}

// New scanners mark the retained response body. Older scanners replaced the
// entire HTTP result with a truncation summary; keep that loss visible too.
fn has_truncated_http_evidence(data: &Value) -> bool {
    fn marked(value: &Value, depth: usize) -> bool {
        if depth > MAX_JSON_DEPTH {
            return false;
        }
        match value {
            Value::Object(map) => {
                map.get("body_truncated").and_then(Value::as_bool) == Some(true)
                    || map.values().any(|child| marked(child, depth + 1))
            }
            Value::Array(items) => items.iter().any(|child| marked(child, depth + 1)),
            _ => false,
        }
    }
    marked(data, 0)
        || data
            .get("evidence")
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items.iter().any(|item| {
                    matches!(
                        item.get("module").and_then(Value::as_str),
                        Some("http" | "https" | "doh")
                    ) && item.pointer("/result/truncated").and_then(Value::as_bool) == Some(true)
                })
            })
}

fn find_tls_evidence(data: &Value) -> Option<(&str, &Value)> {
    data.get("evidence")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(|evidence| {
            let module = evidence.get("module").and_then(Value::as_str).unwrap_or("");
            let result = evidence.get("result")?;
            (find_value_by_key(result, &["handshake_log"], 0).is_some()).then_some((module, result))
        })
        .next()
}

fn classify_tls_mode(module: &str, result: &Value) -> &'static str {
    if find_value_by_key(result, &["implicit_tls"], 0).and_then(Value::as_bool) == Some(true)
        || matches!(
            module,
            "https" | "dot" | "doh" | "smtps" | "imaps" | "pop3s" | "ftps" | "mqtts"
        )
    {
        "implicit"
    } else if find_value_by_key(result, &["starttls"], 0).is_some()
        || matches!(module, "smtp" | "imap" | "pop3" | "ftp")
    {
        "starttls"
    } else {
        "direct"
    }
}

fn tls_certificate_names(certificate: &Value) -> Vec<String> {
    let mut names = BTreeSet::new();
    for pointer in [
        "/names",
        "/extensions/subject_alt_name/dns_names",
        "/extensions/subject_alt_name/ip_addresses",
    ] {
        let Some(values) = certificate.pointer(pointer).and_then(Value::as_array) else {
            continue;
        };
        for value in values.iter().filter_map(Value::as_str) {
            let value = clean_text(value);
            if !value.is_empty() {
                names.insert(value.chars().take(MAX_TLS_NAME_CHARS).collect());
            }
            if names.len() >= MAX_TLS_NAMES {
                break;
            }
        }
    }
    names.into_iter().collect()
}

fn normalize_rfc3339(value: &str) -> Option<String> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.to_rfc3339())
}

fn find_string_by_key<'a>(value: &'a Value, keys: &[&str], depth: usize) -> Option<&'a str> {
    find_value_by_key(value, keys, depth).and_then(Value::as_str)
}

fn find_value_by_key<'a>(value: &'a Value, keys: &[&str], depth: usize) -> Option<&'a Value> {
    if depth > MAX_JSON_DEPTH {
        return None;
    }
    match value {
        Value::Object(map) => {
            for key in keys {
                if let Some(found) = map.get(*key)
                    && !found.is_null()
                {
                    return Some(found);
                }
            }
            map.values()
                .find_map(|child| find_value_by_key(child, keys, depth + 1))
        }
        Value::Array(items) => items
            .iter()
            .find_map(|child| find_value_by_key(child, keys, depth + 1)),
        _ => None,
    }
}

fn value_as_text(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(clean_text(value)),
        Value::Object(_) | Value::Array(_) => serde_json::to_string(value).ok(),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null => None,
    }
}

fn extract_html_title(body: &str) -> Option<String> {
    let captures = TITLE_PATTERN.captures(body)?;
    let inner = captures.get(1)?.as_str();
    let without_tags = HTML_TAG_PATTERN.replace_all(inner, " ");
    let title = clean_text(&without_tags);
    (!title.is_empty()).then_some(title)
}

fn clean_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_utf8_bytes(value: &str, max_bytes: usize) -> (String, bool) {
    if value.len() <= max_bytes {
        return (value.to_owned(), false);
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), true)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{MAX_HTTP_BODY_BYTES, extract_search_content};

    #[test]
    fn extracts_http_title_body_and_tls_subject_from_probe_evidence() {
        let data = json!({
            "evidence": [
                {
                    "module": "https",
                    "result": {
                        "response": {"body": "<html><title> Hikvision  Camera </title></html>"}
                    }
                },
                {
                    "module": "tls",
                    "result": {"handshake_log": {"server_certificates": {"subject_dn": "CN=camera.example"}}}
                }
            ]
        });

        let content = extract_search_content(Some(&data));
        assert_eq!(content.title.as_deref(), Some("Hikvision Camera"));
        assert!(content.http_body.as_deref().unwrap().contains("<html>"));
        assert_eq!(content.tls_subject.as_deref(), Some("CN=camera.example"));
        assert!(!content.http_body_truncated);
    }

    #[test]
    fn scanner_truncation_survives_search_extraction() {
        let data = json!({"evidence": [{"module": "https", "result": {
            "response": {"body": "<title>Camera</title>partial", "body_truncated": true}
        }}]});
        let content = extract_search_content(Some(&data));
        assert_eq!(content.title.as_deref(), Some("Camera"));
        assert_eq!(
            content.http_body.as_deref(),
            Some("<title>Camera</title>partial")
        );
        assert!(content.http_body_truncated);
        let legacy = json!({"evidence": [{"module": "http", "result": {
            "status": "success", "truncated": true, "original_bytes": 65588
        }}]});
        let content = extract_search_content(Some(&legacy));
        assert!(content.http_body_truncated);
        assert!(content.http_body.is_none());
        let non_http = json!({"evidence": [{"module": "ssh", "result": {"truncated": true}}]});
        assert!(!extract_search_content(Some(&non_http)).http_body_truncated);
    }

    #[test]
    fn extracts_structured_tls_fields_from_smtps_evidence() {
        let data = json!({
            "evidence": [{
                "module": "smtps",
                "result": {
                    "implicit_tls": true,
                    "tls": {"handshake_log": {
                        "server_hello": {
                            "version": {"name": "TLSv1.3"},
                            "cipher_suite": {"name": "TLS_AES_256_GCM_SHA384"}
                        },
                        "server_certificates": {"certificate": {"parsed": {
                            "subject_dn": "CN=mail.example.com",
                            "issuer_dn": "CN=Example Issuing CA",
                            "serial_number": "123456789",
                            "fingerprint_sha256": "AABBCCDD",
                            "names": ["mail.example.com"],
                            "validity": {
                                "start": "2026-01-01T00:00:00Z",
                                "end": "2027-01-01T00:00:00Z"
                            },
                            "extensions": {"subject_alt_name": {
                                "dns_names": ["smtp.example.com", "mail.example.com"],
                                "ip_addresses": ["192.0.2.25"]
                            }},
                            "signature": {"self_signed": false}
                        }}}
                    }}
                }
            }]
        });

        let content = extract_search_content(Some(&data));
        assert_eq!(content.tls_mode.as_deref(), Some("implicit"));
        assert_eq!(content.tls_version.as_deref(), Some("TLSv1.3"));
        assert_eq!(
            content.tls_cipher_suite.as_deref(),
            Some("TLS_AES_256_GCM_SHA384")
        );
        assert_eq!(content.tls_subject.as_deref(), Some("CN=mail.example.com"));
        assert_eq!(content.tls_issuer.as_deref(), Some("CN=Example Issuing CA"));
        assert_eq!(
            content.tls_names,
            ["192.0.2.25", "mail.example.com", "smtp.example.com"]
        );
        assert_eq!(content.tls_serial_number.as_deref(), Some("123456789"));
        assert_eq!(content.tls_fingerprint_sha256.as_deref(), Some("AABBCCDD"));
        assert_eq!(content.tls_self_signed, Some(false));
        assert_eq!(
            content.tls_not_after.as_deref(),
            Some("2027-01-01T00:00:00+00:00")
        );
    }

    #[test]
    fn identifies_smtp_starttls_evidence() {
        let data = json!({
            "evidence": [{
                "module": "smtp",
                "result": {
                    "starttls": "220 Ready to start TLS",
                    "tls": {"handshake_log": {"server_certificates": {
                        "certificate": {"parsed": {"subject_dn": "CN=mx.example.com"}}
                    }}}
                }
            }]
        });

        let content = extract_search_content(Some(&data));
        assert_eq!(content.tls_mode.as_deref(), Some("starttls"));
        assert_eq!(content.tls_subject.as_deref(), Some("CN=mx.example.com"));
    }

    #[test]
    fn truncates_large_bodies_on_a_utf8_boundary() {
        let body = format!("{}界", "a".repeat(MAX_HTTP_BODY_BYTES));
        let data = json!({"response": {"body": body}});
        let content = extract_search_content(Some(&data));

        assert_eq!(content.http_body.unwrap().len(), MAX_HTTP_BODY_BYTES);
        assert!(content.http_body_truncated);
    }

    #[test]
    fn empty_or_unrelated_data_yields_no_search_content() {
        assert_eq!(extract_search_content(None), Default::default());
        assert_eq!(
            extract_search_content(Some(&json!({"status": "success"}))),
            Default::default()
        );
    }
}

#[cfg(test)]
mod encrypted_dns_tests {
    use super::*;
    #[test]
    fn doh_keeps_http_headers_and_verified_tls_fingerprint_without_dns_body() {
        let d = serde_json::json!({"schema_version":2,"evidence":[{"module":"doh","result":{"tls":{"implicit_tls":true,"certificate_verified":true,"handshake_log":{"server_certificates":{"certificate":{"parsed":{"fingerprint_sha256":"abcd"}}}}},"response":{"status_line":"HTTP 200 OK","headers":{"server":["resolver"],"content_type":["application/dns-message"]}}}}]});
        let v = extract_search_content(Some(&d));
        assert_eq!(v.tls_mode.as_deref(), Some("implicit"));
        assert_eq!(v.tls_fingerprint_sha256.as_deref(), Some("abcd"));
        assert!(v.http_body.is_none());
    }
}
