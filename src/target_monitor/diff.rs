//! 纯函数基线 diff：IP 端点快照与域名解析集合。不依赖数据库与网络，重点单测覆盖。
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// 单规则快照端口条目上限；超限截断并在 summary 标注。
pub const MAX_SNAPSHOT_PORTS: usize = 1024;
/// 单条事件携带的变化明细上限。
pub const MAX_EVENT_CHANGES: usize = 20;
/// 域名解析变化明细中 before/after 地址列表上限。
pub const MAX_DNS_ADDRESSES: usize = 50;
/// 单次运行变化总数上限（防通知风暴，超出聚合进 summary）。
pub const MAX_RUN_CHANGES: usize = 200;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EndpointState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<i64>,
}

pub type IpSnapshot = BTreeMap<String, BTreeMap<u16, EndpointState>>;
pub type DnsSnapshot = BTreeMap<String, BTreeSet<String>>;

#[derive(Clone, Debug, PartialEq)]
pub struct Change {
    pub kind: &'static str,
    pub severity: &'static str,
    pub target: String,
    pub port: Option<u16>,
    pub detail: Value,
}

fn text(source: &Value, key: &str) -> Option<String> {
    source
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn epoch_ms(source: &Value, key: &str) -> Option<i64> {
    match source.get(key) {
        Some(Value::Number(number)) => number.as_i64(),
        Some(Value::String(text)) => chrono::DateTime::parse_from_rfc3339(text)
            .ok()
            .map(|at| at.timestamp_millis()),
        _ => None,
    }
}

fn endpoint_state(source: &Value) -> Option<(String, u16, EndpointState)> {
    let ip = text(source, "ip")?;
    let port = u16::try_from(source.get("port").and_then(Value::as_u64)?).unwrap_or(0);
    Some((
        ip,
        port,
        EndpointState {
            service: text(source, "service"),
            product: text(source, "product"),
            version: text(source, "version"),
            title: text(source, "title"),
            cert_sha256: text(source, "tls_fingerprint_sha256"),
            not_after: epoch_ms(source, "tls_not_after"),
        },
    ))
}

/// 从执行端点索引的 collapse 查询命中构建快照：每个 endpoint_key 取
/// `inner_hits.latest` 的最新一条观测，避免同一任务多次执行时旧观测覆盖新值。
pub fn snapshot_from_collapsed_hits(hits: &Value) -> IpSnapshot {
    let mut snapshot = IpSnapshot::new();
    let entries = hits
        .pointer("/hits/hits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    for entry in entries.take(MAX_SNAPSHOT_PORTS) {
        let Some(source) = entry.pointer("/inner_hits/latest/hits/hits/0/_source") else {
            continue;
        };
        if let Some((ip, port, state)) = endpoint_state(source) {
            snapshot.entry(ip).or_default().insert(port, state);
        }
    }
    snapshot
}

/// collapse 查询按上限 +1 取组；返回组数超过上限即表示快照不完整。
pub fn hits_exceed_capacity(hits: &Value) -> bool {
    hits.pointer("/hits/hits")
        .and_then(Value::as_array)
        .is_some_and(|entries| entries.len() > MAX_SNAPSHOT_PORTS)
}

/// 从 DNS 任务观察命中构建解析集合（仅 A/AAAA）。
pub fn dns_snapshot_from_hits(hits: &Value) -> DnsSnapshot {
    let mut snapshot = DnsSnapshot::new();
    let entries = hits
        .pointer("/hits/hits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    for entry in entries {
        let Some(source) = entry.get("_source") else {
            continue;
        };
        // DNS 观察文档为嵌套结构：观察载荷在 _source.dns，任务归属在 _source.scan。
        let Some(dns) = source.get("dns") else {
            continue;
        };
        let mut value = dns.clone();
        let observed_at = source
            .get("@timestamp")
            .and_then(Value::as_str)
            .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
            .map(|at| at.timestamp_millis())
            .unwrap_or(1);
        value["observed_at"] = json!(observed_at);
        let Ok(observation) = serde_json::from_value::<crate::dns::DnsObservation>(value) else {
            continue;
        };
        let domain = observation.question.name;
        for answer in observation.answers {
            if matches!(answer.record_type.as_str(), "A" | "AAAA")
                && answer.value.parse::<std::net::IpAddr>().is_ok()
            {
                snapshot
                    .entry(domain.clone())
                    .or_default()
                    .insert(answer.value);
            }
        }
    }
    snapshot
}

fn field_change(
    kind: &'static str,
    severity: &'static str,
    target: &str,
    port: u16,
    field: &str,
    before: &Option<String>,
    after: &Option<String>,
) -> Change {
    Change {
        kind,
        severity,
        target: target.to_owned(),
        port: Some(port),
        detail: json!({"field": field, "before": before, "after": after}),
    }
}

/// 证书到期分桶：≤7 天 critical，≤14 天 warning；返回（级别，桶标签）。
pub fn cert_expiry_severity(
    not_after_ms: i64,
    now_ms: i64,
) -> Option<(&'static str, &'static str)> {
    let days = (not_after_ms - now_ms) / 86_400_000;
    if days < 0 {
        Some(("critical", "expired"))
    } else if days <= 7 {
        Some(("critical", "7d"))
    } else if days <= 14 {
        Some(("warning", "14d"))
    } else {
        None
    }
}

fn compare_endpoint(
    ip: &str,
    port: u16,
    previous: &EndpointState,
    state: &EndpointState,
    now_ms: i64,
    changes: &mut Vec<Change>,
) {
    for (field, before, after) in [
        ("service", &previous.service, &state.service),
        ("product", &previous.product, &state.product),
        ("version", &previous.version, &state.version),
    ] {
        if before != after {
            changes.push(field_change(
                "service_changed",
                "warning",
                ip,
                port,
                field,
                before,
                after,
            ));
        }
    }
    if previous.title != state.title {
        changes.push(field_change(
            "title_changed",
            "info",
            ip,
            port,
            "title",
            &previous.title,
            &state.title,
        ));
    }
    if previous.cert_sha256 != state.cert_sha256 {
        changes.push(field_change(
            "cert_changed",
            "warning",
            ip,
            port,
            "cert_sha256",
            &previous.cert_sha256,
            &state.cert_sha256,
        ));
    }
    if let Some(not_after) = state.not_after
        && let Some((severity, bucket)) = cert_expiry_severity(not_after, now_ms)
    {
        changes.push(Change {
            kind: "cert_expiring",
            severity,
            target: ip.to_owned(),
            port: Some(port),
            detail: json!({"not_after": not_after, "bucket": bucket}),
        });
    }
}

/// IP 快照 diff。首次运行（baseline=None）只建基线，抑制端口变化噪声；
/// 证书到期不依赖基线，首跑即在阈值窗口内告警（长周期规则不会漏报到过期之后）。
pub fn diff_ip(baseline: Option<&IpSnapshot>, current: &IpSnapshot, now_ms: i64) -> Vec<Change> {
    let Some(baseline) = baseline else {
        let mut changes = Vec::new();
        for (ip, ports) in current {
            for (port, state) in ports {
                if let Some(not_after) = state.not_after
                    && let Some((severity, bucket)) = cert_expiry_severity(not_after, now_ms)
                {
                    changes.push(Change {
                        kind: "cert_expiring",
                        severity,
                        target: ip.clone(),
                        port: Some(*port),
                        detail: json!({"not_after": not_after, "bucket": bucket}),
                    });
                }
            }
        }
        changes.sort_by(|a, b| (&a.target, a.port, a.kind).cmp(&(&b.target, b.port, b.kind)));
        return changes;
    };
    let mut changes = Vec::new();
    for (ip, ports) in current {
        let Some(previous_ports) = baseline.get(ip) else {
            if !ports.is_empty() {
                changes.push(Change {
                    kind: "target_up",
                    severity: "warning",
                    target: ip.clone(),
                    port: None,
                    detail: json!({"open_ports": ports.keys().collect::<Vec<_>>()}),
                });
            }
            continue;
        };
        for (port, state) in ports {
            let Some(previous) = previous_ports.get(port) else {
                changes.push(Change {
                    kind: "port_opened",
                    severity: "warning",
                    target: ip.clone(),
                    port: Some(*port),
                    detail: json!({"after": state}),
                });
                continue;
            };
            compare_endpoint(ip, *port, previous, state, now_ms, &mut changes);
        }
        for port in previous_ports.keys() {
            if !ports.contains_key(port) {
                changes.push(Change {
                    kind: "port_closed",
                    severity: "info",
                    target: ip.clone(),
                    port: Some(*port),
                    detail: json!({"before": previous_ports.get(port)}),
                });
            }
        }
    }
    for (ip, previous_ports) in baseline {
        if !current.contains_key(ip) && !previous_ports.is_empty() {
            changes.push(Change {
                kind: "target_down",
                severity: "critical",
                target: ip.clone(),
                port: None,
                detail: json!({"last_open_ports": previous_ports.keys().collect::<Vec<_>>()}),
            });
        }
    }
    changes.sort_by(|a, b| (&a.target, a.port, a.kind).cmp(&(&b.target, b.port, b.kind)));
    changes
}

/// 截断快照的部分 diff：只比较本次观测到的端点，绝不从缺失端点推断
/// 端口关闭或目标离线——截断集合不具备完整性，缺失不代表不存在。
/// 新出现（或此前基线缺失）的端点仍按 port_opened / target_up 正常上报。
pub fn diff_ip_partial(
    baseline: Option<&IpSnapshot>,
    current: &IpSnapshot,
    now_ms: i64,
) -> Vec<Change> {
    let Some(baseline) = baseline else {
        return diff_ip(None, current, now_ms);
    };
    let mut changes = Vec::new();
    for (ip, ports) in current {
        let Some(previous_ports) = baseline.get(ip) else {
            if !ports.is_empty() {
                changes.push(Change {
                    kind: "target_up",
                    severity: "warning",
                    target: ip.clone(),
                    port: None,
                    detail: json!({"open_ports": ports.keys().collect::<Vec<_>>()}),
                });
            }
            continue;
        };
        for (port, state) in ports {
            match previous_ports.get(port) {
                None => changes.push(Change {
                    kind: "port_opened",
                    severity: "warning",
                    target: ip.clone(),
                    port: Some(*port),
                    detail: json!({"after": state}),
                }),
                Some(previous) => {
                    compare_endpoint(ip, *port, previous, state, now_ms, &mut changes)
                }
            }
        }
    }
    changes.sort_by(|a, b| (&a.target, a.port, a.kind).cmp(&(&b.target, b.port, b.kind)));
    changes
}

/// 域名解析集合 diff。首次运行只建基线。
pub fn diff_dns(baseline: Option<&DnsSnapshot>, current: &DnsSnapshot) -> Vec<Change> {
    let Some(baseline) = baseline else {
        return Vec::new();
    };
    let mut changes = Vec::new();
    let domains: BTreeSet<&String> = baseline.keys().chain(current.keys()).collect();
    for domain in domains {
        let before = baseline.get(domain).cloned().unwrap_or_default();
        let after = current.get(domain).cloned().unwrap_or_default();
        if before != after {
            changes.push(Change {
                kind: "dns_changed",
                severity: "warning",
                target: domain.clone(),
                port: None,
                detail: json!({
                    "before": before.iter().take(MAX_DNS_ADDRESSES).collect::<Vec<_>>(),
                    "after": after.iter().take(MAX_DNS_ADDRESSES).collect::<Vec<_>>(),
                    "added": after.difference(&before).take(MAX_DNS_ADDRESSES).collect::<Vec<_>>(),
                    "removed": before.difference(&after).take(MAX_DNS_ADDRESSES).collect::<Vec<_>>(),
                }),
            });
        }
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(service: &str, title: &str, cert: &str, not_after: Option<i64>) -> EndpointState {
        EndpointState {
            service: Some(service.into()),
            product: None,
            version: None,
            title: Some(title.into()),
            cert_sha256: Some(cert.into()),
            not_after,
        }
    }

    fn snapshot(entries: &[(&str, u16, EndpointState)]) -> IpSnapshot {
        let mut map = IpSnapshot::new();
        for (ip, port, state) in entries {
            map.entry(ip.to_string())
                .or_default()
                .insert(*port, state.clone());
        }
        map
    }

    const NOW: i64 = 1_800_000_000_000;
    const DAY: i64 = 86_400_000;

    #[test]
    fn first_run_builds_baseline_without_port_noise_but_reports_expiring_certs() {
        let current = snapshot(&[("192.0.2.1", 443, state("https", "t", "c", None))]);
        assert!(diff_ip(None, &current, NOW).is_empty());
        let dns = DnsSnapshot::from([("example.com".into(), BTreeSet::from(["192.0.2.1".into()]))]);
        assert!(diff_dns(None, &dns).is_empty());
        let expiring = snapshot(&[
            (
                "192.0.2.1",
                443,
                state("https", "t", "c", Some(NOW + 3 * DAY)),
            ),
            (
                "192.0.2.1",
                80,
                state("http", "t", "c", Some(NOW + 30 * DAY)),
            ),
        ]);
        let changes = diff_ip(None, &expiring, NOW);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, "cert_expiring");
        assert_eq!(changes[0].severity, "critical");
        assert_eq!(changes[0].port, Some(443));
    }

    #[test]
    fn port_open_close_and_service_title_cert_changes_are_classified() {
        let baseline = snapshot(&[
            ("192.0.2.1", 80, state("http", "old", "c1", None)),
            ("192.0.2.1", 8080, state("http-proxy", "p", "c2", None)),
        ]);
        let current = snapshot(&[
            ("192.0.2.1", 80, state("https", "new", "c3", None)),
            ("192.0.2.1", 443, state("https", "n", "c4", None)),
        ]);
        let changes = diff_ip(Some(&baseline), &current, NOW);
        let kinds: Vec<(&str, Option<u16>)> = changes.iter().map(|c| (c.kind, c.port)).collect();
        assert!(kinds.contains(&("port_opened", Some(443))));
        assert!(kinds.contains(&("port_closed", Some(8080))));
        assert!(kinds.contains(&("service_changed", Some(80))));
        assert!(kinds.contains(&("title_changed", Some(80))));
        assert!(kinds.contains(&("cert_changed", Some(80))));
        let service = changes
            .iter()
            .find(|c| c.kind == "service_changed")
            .unwrap();
        assert_eq!(service.detail["before"], "http");
        assert_eq!(service.detail["after"], "https");
        assert_eq!(service.severity, "warning");
        let title = changes.iter().find(|c| c.kind == "title_changed").unwrap();
        assert_eq!(title.severity, "info");
    }

    #[test]
    fn whole_host_disappearance_is_down_and_reappearance_is_up() {
        let baseline = snapshot(&[("192.0.2.1", 80, state("http", "t", "c", None))]);
        let empty = IpSnapshot::new();
        let down = diff_ip(Some(&baseline), &empty, NOW);
        assert_eq!(down.len(), 1);
        assert_eq!(down[0].kind, "target_down");
        assert_eq!(down[0].severity, "critical");
        let up = diff_ip(Some(&empty), &baseline, NOW);
        assert_eq!(up.len(), 1);
        assert_eq!(up[0].kind, "target_up");
    }

    #[test]
    fn certificate_expiry_uses_7_and_14_day_buckets() {
        assert_eq!(
            cert_expiry_severity(NOW + 3 * DAY, NOW),
            Some(("critical", "7d"))
        );
        assert_eq!(
            cert_expiry_severity(NOW + 10 * DAY, NOW),
            Some(("warning", "14d"))
        );
        assert_eq!(cert_expiry_severity(NOW + 30 * DAY, NOW), None);
        assert_eq!(
            cert_expiry_severity(NOW - DAY, NOW),
            Some(("critical", "expired"))
        );
        let baseline = snapshot(&[(
            "192.0.2.1",
            443,
            state("https", "t", "c", Some(NOW + 30 * DAY)),
        )]);
        let current = snapshot(&[(
            "192.0.2.1",
            443,
            state("https", "t", "c", Some(NOW + 3 * DAY)),
        )]);
        let changes = diff_ip(Some(&baseline), &current, NOW);
        assert!(
            changes
                .iter()
                .any(|c| c.kind == "cert_expiring" && c.severity == "critical")
        );
    }

    #[test]
    fn dns_drift_reports_added_and_removed_addresses_with_caps() {
        let baseline =
            DnsSnapshot::from([("example.com".into(), BTreeSet::from(["192.0.2.1".into()]))]);
        let current = DnsSnapshot::from([(
            "example.com".into(),
            BTreeSet::from(["192.0.2.2".into(), "192.0.2.3".into()]),
        )]);
        let changes = diff_dns(Some(&baseline), &current);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, "dns_changed");
        assert_eq!(
            changes[0].detail["added"],
            json!(["192.0.2.2", "192.0.2.3"])
        );
        assert_eq!(changes[0].detail["removed"], json!(["192.0.2.1"]));
        assert!(diff_dns(Some(&baseline), &baseline).is_empty());
    }

    #[test]
    fn collapsed_snapshot_parses_latest_endpoint_hits() {
        let hits = json!({"hits": {"hits": [
            {"inner_hits": {"latest": {"hits": {"hits": [
                {"_source": {"ip": "192.0.2.1", "port": 443, "service": "https", "title": "t", "tls_fingerprint_sha256": "abc", "tls_not_after": NOW + DAY}}
            ]}}}},
            {"inner_hits": {"latest": {"hits": {"hits": [
                {"_source": {"ip": "192.0.2.1", "port": 80}}
            ]}}}},
            {"inner_hits": {"latest": {"hits": {"hits": []}}}}
        ]}});
        let snapshot = snapshot_from_collapsed_hits(&hits);
        assert_eq!(
            snapshot["192.0.2.1"][&443].service.as_deref(),
            Some("https")
        );
        assert_eq!(snapshot["192.0.2.1"][&443].not_after, Some(NOW + DAY));
        assert_eq!(snapshot["192.0.2.1"][&80], EndpointState::default());
        assert!(!hits_exceed_capacity(&hits));
        let groups: Vec<Value> = (0..=MAX_SNAPSHOT_PORTS)
            .map(|i| {
                json!({"inner_hits": {"latest": {"hits": {"hits": [
                    {"_source": {"ip": "192.0.2.1", "port": i + 1}}
                ]}}}})
            })
            .collect();
        assert!(hits_exceed_capacity(&json!({"hits": {"hits": groups}})));
    }

    #[test]
    fn partial_diff_ignores_endpoints_missing_from_truncated_snapshot() {
        let baseline = snapshot(&[
            ("192.0.2.1", 80, state("http", "t", "c", None)),
            ("192.0.2.2", 443, state("https", "t", "c", None)),
        ]);
        let current = snapshot(&[("192.0.2.1", 80, state("http", "t2", "c", None))]);
        let changes = diff_ip_partial(Some(&baseline), &current, NOW);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, "title_changed");
        // 缺失端点不会被推断为关闭或离线。
        assert!(diff_ip_partial(Some(&baseline), &IpSnapshot::new(), NOW).is_empty());
        // 新观测到的端点仍正常上报。
        let added = snapshot(&[("192.0.2.3", 22, state("ssh", "", "", None))]);
        let changes = diff_ip_partial(Some(&baseline), &added, NOW);
        assert_eq!(changes[0].kind, "target_up");
        // 首跑（无基线）保持只报证书到期的行为。
        assert!(diff_ip_partial(None, &current, NOW).is_empty());
    }

    #[test]
    fn dns_snapshot_keeps_only_a_and_aaaa_answers() {
        let hits = json!({"hits": {"hits": [{"_source": {
            "@timestamp": "2026-11-23T10:00:00Z",
            "scan": {"task_id": "t1"},
            "dns": {
                "question": {"name": "example.com", "type": "A", "class": "IN"},
                "response_code": "NOERROR",
                "answers": [
                    {"type": "A", "value": "192.0.2.1", "ttl": 60},
                    {"type": "AAAA", "value": "2001:db8::1", "ttl": 60},
                    {"type": "CNAME", "value": "other.example.com", "ttl": 60}
                ]
            }
        }}]}});
        let snapshot = dns_snapshot_from_hits(&hits);
        assert_eq!(
            snapshot["example.com"],
            BTreeSet::from(["192.0.2.1".to_string(), "2001:db8::1".to_string()])
        );
    }
}
