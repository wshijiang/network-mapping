//! Operating-system hints derived from protocol fields, never from port numbers.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const RULESET_REVISION: i64 = 1;
pub(crate) const RULESET_VERSION: &str = "2026-10-17.1";
const MAX_EVIDENCE: usize = 32;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct OsEvidence {
    pub rule_id: String,
    pub module: String,
    pub field_path: String,
    pub excerpt: String,
    pub family: String,
    pub distribution: Option<String>,
    pub version: Option<String>,
    pub port: u16,
    pub observation_ref: Option<String>,
    #[serde(default)]
    pub scanner_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct OsCandidate {
    pub family: String,
    pub score: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct OsInference {
    pub status: String,
    pub inference_scope: String,
    pub family: Option<String>,
    pub distribution: Option<String>,
    pub version: Option<String>,
    pub confidence: String,
    /// An explainable rule score, not a calibrated probability.
    pub score: u16,
    pub candidates: Vec<OsCandidate>,
    pub evidence: Vec<OsEvidence>,
    pub ruleset_revision: i64,
    pub ruleset_version: String,
    pub observed_at: Option<i64>,
    pub stale: bool,
}

impl Default for OsInference {
    fn default() -> Self {
        Self {
            status: "unknown".into(),
            inference_scope: "service_environment".into(),
            family: None,
            distribution: None,
            version: None,
            confidence: "none".into(),
            score: 0,
            candidates: Vec::new(),
            evidence: Vec::new(),
            ruleset_revision: RULESET_REVISION,
            ruleset_version: RULESET_VERSION.into(),
            observed_at: None,
            stale: false,
        }
    }
}

fn explicit_version(text: &str, marker: &str, path: &str) -> Option<String> {
    // Version strings from package banners (Ubuntu-3ubuntu0.11, IIS/10.0,
    // OpenSSH_9.6) are intentionally never interpreted as OS releases.
    if !path.ends_with("/native_os") && !path.ends_with("/server_os") {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    let offset = lower.find(marker)? + marker.len();
    let tail = text.get(offset..)?;
    if tail.chars().next().is_none_or(|c| !c.is_whitespace()) {
        return None;
    }
    let suffix = tail.trim();
    if marker == "windows" && suffix.chars().any(|c| c.is_ascii_digit()) {
        return Some(suffix.chars().take(120).collect());
    }
    let release = suffix.split_whitespace().next()?;
    if release.len() <= 24
        && release
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    {
        Some(release.into())
    } else {
        None
    }
}

impl OsInference {
    pub(crate) fn pending(observed_at: i64) -> Self {
        Self {
            status: "pending".into(),
            observed_at: Some(observed_at),
            ..Self::default()
        }
    }
}

// Deliberately examine protocol-owned fields, not arbitrary page bodies, names,
// certificates, JSON strings, or the service detection confidence score.
pub(crate) fn infer(
    service: Option<&str>,
    banner: Option<&str>,
    data: Option<&Value>,
    port: u16,
    observed_at: i64,
    observation_ref: Option<&str>,
) -> OsInference {
    let mut evidence = Vec::new();
    if let Some(banner) = banner {
        let module = if banner.starts_with("SSH-") {
            "ssh"
        } else {
            service.unwrap_or("")
        };
        if matches!(module, "ssh" | "ftp" | "smtp" | "smb" | "rdp") {
            add_text(
                &mut evidence,
                module,
                "/banner",
                banner,
                port,
                observation_ref,
            );
        }
    }
    if let Some(data) = data {
        if data.get("schema_version").and_then(Value::as_u64) == Some(2) {
            if let Some(items) = data.get("evidence").and_then(Value::as_array) {
                for (index, item) in items.iter().take(MAX_EVIDENCE).enumerate() {
                    let module = item.get("module").and_then(Value::as_str).unwrap_or("");
                    if let Some(result) = item.get("result") {
                        extract(
                            &mut evidence,
                            module,
                            result,
                            &format!("/data/evidence/{index}/result"),
                            port,
                            observation_ref,
                        );
                    }
                }
            }
        } else if data.get("schema_version").is_none() {
            // Older nodes retained the zgrab module envelope directly.
            if let Some(result) = data.get("result") {
                extract(
                    &mut evidence,
                    service.unwrap_or(""),
                    result,
                    "/data/result",
                    port,
                    observation_ref,
                );
            }
        }
    }
    let mut result = decide(evidence, "service_environment");
    result.observed_at = Some(observed_at);
    result
}

fn extract(
    out: &mut Vec<OsEvidence>,
    module: &str,
    result: &Value,
    prefix: &str,
    port: u16,
    reference: Option<&str>,
) {
    let paths: &[&str] = match module {
        "ssh" => &["/server_id/raw", "/server_id/software"],
        "smb" => &["/native_os", "/smb/native_os", "/session_setup/native_os"],
        "rdp" => &["/native_os", "/server_os"],
        "ftp" | "smtp" | "banner" => &["/banner"],
        _ => &[],
    };
    for path in paths {
        if let Some(text) = result.pointer(path).and_then(Value::as_str) {
            // Generic banner probes only establish an SSH system hint when
            // their content is an actual SSH identification string.
            let effective = if module == "banner" && text.starts_with("SSH-") {
                "ssh"
            } else {
                module
            };
            if effective != "banner" {
                add_text(
                    out,
                    effective,
                    &format!("{prefix}{path}"),
                    text,
                    port,
                    reference,
                );
            }
        }
    }
    if matches!(module, "http" | "https")
        && let Some(headers) = result
            .pointer("/response/headers")
            .and_then(Value::as_object)
    {
        for (name, values) in headers.iter().take(256) {
            if !name.eq_ignore_ascii_case("server") {
                continue;
            }
            let path = format!(
                "{prefix}/response/headers/{}",
                name.replace('~', "~0").replace('/', "~1")
            );
            if let Some(value) = values.as_str() {
                add_text(out, "http", &path, value, port, reference);
            } else if let Some(values) = values.as_array() {
                for value in values.iter().take(8).filter_map(Value::as_str) {
                    add_text(out, "http", &path, value, port, reference);
                }
            }
        }
    }
}

fn token(text: &str, needle: &str) -> bool {
    text.match_indices(needle).any(|(start, _)| {
        let end = start + needle.len();
        (start == 0 || !text.as_bytes()[start - 1].is_ascii_alphanumeric())
            && (end == text.len() || !text.as_bytes()[end].is_ascii_alphanumeric())
    })
}

fn add_text(
    out: &mut Vec<OsEvidence>,
    module: &str,
    path: &str,
    text: &str,
    port: u16,
    reference: Option<&str>,
) {
    if out.len() >= MAX_EVIDENCE {
        return;
    }
    let text: String = text
        .chars()
        .take(4096)
        .filter(|c| !c.is_control())
        .collect();
    let lower = text.to_ascii_lowercase();
    let signatures = [
        ("openssh_for_windows", "windows", None, "ssh_windows"),
        ("microsoft-iis", "windows", None, "http_iis"),
        ("windows", "windows", None, "explicit_windows"),
        ("ubuntu", "linux", Some("ubuntu"), "explicit_ubuntu"),
        ("debian", "linux", Some("debian"), "explicit_debian"),
        ("centos", "linux", Some("centos"), "explicit_centos"),
        ("freebsd", "bsd", Some("freebsd"), "explicit_freebsd"),
        ("openbsd", "bsd", Some("openbsd"), "explicit_openbsd"),
        ("netbsd", "bsd", Some("netbsd"), "explicit_netbsd"),
        ("darwin", "macos", None, "explicit_darwin"),
        ("macos", "macos", None, "explicit_macos"),
        ("linux", "linux", None, "explicit_linux"),
        ("unix", "unix", None, "explicit_unix"),
    ];
    for (needle, family, distribution, rule) in signatures {
        if !token(&lower, needle) {
            continue;
        }
        if rule == "ssh_windows" && module != "ssh" {
            continue;
        }
        if rule == "http_iis" && module != "http" {
            continue;
        }
        // Explicit family names are hints, not proof of the host kernel. Do
        // not infer Linux from Samba/OpenSSH or Windows from SMB/RDP alone.
        if out.iter().any(|e| {
            e.module == module
                && e.port == port
                && e.family == family
                && e.distribution.as_deref() == distribution
        }) {
            continue;
        }
        out.push(OsEvidence {
            rule_id: rule.into(),
            module: module.into(),
            field_path: path.into(),
            excerpt: text.chars().take(180).collect(),
            family: family.into(),
            distribution: distribution.map(str::to_owned),
            version: explicit_version(&text, needle, path),
            port,
            observation_ref: reference.map(str::to_owned),
            scanner_id: None,
        });
        if out.len() == MAX_EVIDENCE {
            break;
        }
    }
}

fn decide(evidence: Vec<OsEvidence>, scope: &str) -> OsInference {
    let mut groups: BTreeMap<String, BTreeSet<(String, u16)>> = BTreeMap::new();
    for e in &evidence {
        groups
            .entry(e.family.clone())
            .or_default()
            .insert((e.module.clone(), e.port));
    }
    // "Unix" is a broad family hint and does not contradict a more specific
    // Unix-like family. Windows with Unix remains a real conflict.
    if groups.len() > 1 && !groups.contains_key("windows") {
        groups.remove("unix");
    }
    let candidates: Vec<_> = groups
        .iter()
        .map(|(family, groups)| OsCandidate {
            family: family.clone(),
            score: groups.len().saturating_mul(60).min(100) as u16,
        })
        .collect();
    let mut result = OsInference {
        inference_scope: scope.into(),
        candidates,
        evidence,
        ..OsInference::default()
    };
    if groups.len() > 1 {
        result.status = "conflict".into();
        return result;
    }
    let Some((family, groups)) = groups.first_key_value() else {
        return result;
    };
    result.status = "identified".into();
    result.family = Some(family.clone());
    result.score = groups.len().saturating_mul(60).min(100) as u16;
    let modules: BTreeSet<_> = groups.iter().map(|(module, _)| module).collect();
    result.confidence = if modules.len() > 1 { "high" } else { "medium" }.into();
    let distributions: BTreeSet<_> = result
        .evidence
        .iter()
        .filter(|e| &e.family == family)
        .filter_map(|e| e.distribution.clone())
        .collect();
    if distributions.len() == 1 {
        result.distribution = distributions.into_iter().next();
    }
    let versions: BTreeSet<_> = result
        .evidence
        .iter()
        .filter(|e| &e.family == family)
        .filter_map(|e| e.version.clone())
        .collect();
    if versions.len() == 1 {
        result.version = versions.into_iter().next();
    }
    result
}

/// Aggregate only endpoint results already selected by the caller's access
/// scope. Callers must include every family, even when evidence is sampled.
pub(crate) fn summarize(sources: &[Value], now_ms: i64) -> OsInference {
    let mut evidence = Vec::new();
    let mut scanners = BTreeSet::new();
    let mut latest = None;
    let mut pending = false;
    let mut stale = false;
    for source in sources {
        let Some(value) = source.get("os") else {
            continue;
        };
        let Ok(os) = serde_json::from_value::<OsInference>(value.clone()) else {
            continue;
        };
        let expired = os
            .observed_at
            .is_none_or(|at| now_ms.saturating_sub(at) > 30 * 86_400_000);
        stale |= expired || source.get("observed_at_ms").and_then(Value::as_i64) > os.observed_at;
        if expired {
            continue;
        }
        pending |= os.status == "pending";
        if !os.evidence.is_empty() {
            for item in &os.evidence {
                scanners.insert(item.scanner_id.as_deref().unwrap_or("unknown").to_owned());
            }
            latest = latest.max(os.observed_at);
            evidence.extend(os.evidence);
        }
    }
    // Number of endpoint samples is bounded by the ES aggregation. Deduplication
    // keeps correlated fields from counting as independent sources.
    evidence.sort_by(|a, b| {
        (&a.family, &a.module, a.port, &a.rule_id).cmp(&(&b.family, &b.module, b.port, &b.rule_id))
    });
    evidence.dedup_by(|a, b| {
        a.family == b.family && a.module == b.module && a.port == b.port && a.rule_id == b.rule_id
    });
    let mut result = decide(evidence, "host_estimate");
    result.version = None; // Service releases do not establish a host release.
    result.evidence.truncate(MAX_EVIDENCE);
    result.observed_at = latest;
    result.stale = stale;
    if result.status == "unknown" && pending {
        result.status = "pending".into();
    }
    if (scanners.len() > 1 || scanners.contains("unknown")) && result.confidence == "high" {
        result.confidence = "medium".into();
    }
    result
}

pub(crate) fn mapping() -> Value {
    json!({"type":"object", "dynamic":"strict", "properties": {
        "status":{"type":"keyword","normalizer":"lowercase_normalizer"}, "inference_scope":{"type":"keyword","normalizer":"lowercase_normalizer"},
        "family":{"type":"keyword","normalizer":"lowercase_normalizer"}, "distribution":{"type":"keyword","normalizer":"lowercase_normalizer"}, "version":{"type":"keyword","normalizer":"lowercase_normalizer"},
        "confidence":{"type":"keyword","normalizer":"lowercase_normalizer"}, "score":{"type":"integer"},
        "candidates":{"type":"object","enabled":false}, "evidence":{"type":"object","enabled":false},
        "ruleset_revision":{"type":"long"}, "ruleset_version":{"type":"keyword","normalizer":"lowercase_normalizer"},
        "observed_at":{"type":"long"}, "stale":{"type":"boolean"}
    }})
}

pub(crate) fn endpoint_view(
    os: Option<OsInference>,
    last_seen: i64,
    now_ms: i64,
) -> Option<OsInference> {
    os.map(|mut os| {
        os.stale = os
            .observed_at
            .is_none_or(|at| last_seen > at || now_ms.saturating_sub(at) > 30 * 86_400_000);
        os
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn detect(service: &str, banner: &str, module: &str, result: Value) -> OsInference {
        infer(
            Some(service),
            Some(banner),
            Some(
                &json!({"schema_version":2,"confidence":100,"evidence":[{"module":module,"result":result}]}),
            ),
            2222,
            1000,
            Some("observation-1"),
        )
    }
    #[test]
    fn protocol_success_and_generic_software_do_not_identify_an_os() {
        for (service, banner) in [
            ("smb", ""),
            ("rdp", ""),
            ("ssh", "SSH-2.0-OpenSSH_9.6"),
            ("http", "HTTP/1.1 200 OK"),
            ("smb", "Samba 4.20"),
        ] {
            assert_eq!(
                detect(service, banner, service, json!({})).status,
                "unknown"
            );
        }
        assert_eq!(
            detect(
                "http",
                "",
                "http",
                json!({"response":{"headers":{"server":["nginx"]},"body":"Windows Ubuntu Debian"}})
            )
            .status,
            "unknown"
        );
    }
    #[test]
    fn nonstandard_ssh_ports_and_http_header_arrays_keep_evidence() {
        let ssh = detect(
            "ssh",
            "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu0.11",
            "ssh",
            json!({}),
        );
        assert_eq!(ssh.family.as_deref(), Some("linux"));
        assert_eq!(ssh.distribution.as_deref(), Some("ubuntu"));
        assert_eq!(ssh.version, None); // package version is not OS release
        assert_eq!(ssh.confidence, "medium");
        let http = detect(
            "https",
            "HTTP/1.1 200 OK",
            "https",
            json!({"response":{"headers":{"Server":["Microsoft-IIS/10.0"]}}}),
        );
        assert_eq!(http.family.as_deref(), Some("windows"));
        assert_eq!(http.version, None);
        assert!(http.evidence[0].field_path.contains("headers/Server"));
    }
    #[test]
    fn arbitrary_json_and_unknown_schema_are_not_scanned() {
        let data = json!({"schema_version":999,"evidence":[{"module":"ssh","result":{"server_id":{"raw":"SSH-2.0-OpenSSH_for_Windows_9.5"}}}]});
        assert_eq!(
            infer(None, None, Some(&data), 22, 1, None).status,
            "unknown"
        );
        assert_eq!(
            detect(
                "rdp",
                "",
                "rdp",
                json!({"certificate":{"subject":"Windows"},"protocol":"rdp"})
            )
            .status,
            "unknown"
        );
    }
    #[test]
    fn conflict_and_correlated_fields_are_preserved() {
        let os = detect(
            "ssh",
            "SSH-2.0-OpenSSH_for_Windows_9.5",
            "ssh",
            json!({"server_id":{"raw":"SSH-2.0-Ubuntu"}}),
        );
        assert_eq!(os.status, "conflict");
        assert_eq!(os.family, None);
        let os = detect(
            "ssh",
            "SSH-2.0-OpenSSH_9.6 Ubuntu",
            "ssh",
            json!({"server_id":{"raw":"SSH-2.0-OpenSSH_9.6 Ubuntu"}}),
        );
        assert_eq!(os.score, 60);
        assert_eq!(os.evidence.len(), 1);
    }
    #[test]
    fn host_merge_requires_consistent_fresh_evidence_and_limits_multiple_views() {
        let linux = detect("ssh", "SSH-2.0-OpenSSH_9.6 Ubuntu", "ssh", json!({}));
        let windows = detect(
            "http",
            "",
            "http",
            json!({"response":{"headers":{"server":"Microsoft-IIS/10.0"}}}),
        );
        let sources = vec![
            json!({"os":linux,"scanner_id":"a","observed_at_ms":2000}),
            json!({"os":windows,"scanner_id":"a","observed_at_ms":1000}),
        ];
        let os = summarize(&sources, 3000);
        assert_eq!(os.status, "conflict");
        assert!(os.stale);
        assert_eq!(summarize(&sources, 31 * 86_400_000).status, "unknown");
    }
    #[test]
    fn banner_parsing_is_bounded_and_uses_word_boundaries() {
        assert_eq!(
            detect("ssh", "SSH-2.0-notubuntu", "ssh", json!({})).status,
            "unknown"
        );
        assert_eq!(
            detect(
                "ssh",
                &format!("SSH-{}Windows", "x".repeat(5000)),
                "ssh",
                json!({})
            )
            .status,
            "unknown"
        );
    }
    #[test]
    fn native_os_releases_are_not_confused_with_protocol_versions() {
        let os = detect("smb", "", "smb", json!({"native_os":"Windows Server 2019"}));
        assert_eq!(os.family.as_deref(), Some("windows"));
        assert_eq!(os.version.as_deref(), Some("Server 2019"));
        let os = detect("smb", "", "smb", json!({"native_os":"Ubuntu 22.04.3 LTS"}));
        assert_eq!(os.version.as_deref(), Some("22.04.3"));
        assert_eq!(
            detect(
                "rdp",
                "",
                "rdp",
                json!({"protocol_version":10,"ntlm":{"version":{"build":20348}}})
            )
            .status,
            "unknown"
        );
    }
    #[test]
    fn host_confidence_uses_service_origins_instead_of_the_latest_port_scanner() {
        let mut ssh = detect("ssh", "SSH-2.0-OpenSSH_9.6 Ubuntu", "ssh", json!({}));
        let mut http = detect(
            "http",
            "",
            "http",
            json!({"response":{"headers":{"server":"Apache (Ubuntu)"}}}),
        );
        for e in &mut ssh.evidence {
            e.scanner_id = Some("origin-a".into());
        }
        for e in &mut http.evidence {
            e.scanner_id = Some("origin-b".into());
        }
        let sources = vec![
            json!({"os":ssh,"scanner_id":"latest-port-observer"}),
            json!({"os":http,"scanner_id":"latest-port-observer"}),
        ];
        assert_eq!(summarize(&sources, 2000).confidence, "medium");
        for e in &mut http.evidence {
            e.scanner_id = Some("origin-a".into());
        }
        let sources = vec![json!({"os":ssh}), json!({"os":http})];
        assert_eq!(summarize(&sources, 2000).confidence, "high");
        let pending = OsInference::pending(1000);
        assert_eq!(
            summarize(&[json!({"os":pending})], 31 * 86_400_000).status,
            "unknown"
        );
    }
}
