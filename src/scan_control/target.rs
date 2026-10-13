//! scan_control / target domain implementation, migrated from the library root.

use ipnet::{AddrParseError, IpNet};
use regex::Regex;
use std::net::IpAddr;
use tracing::error;

/// 用于存储目标 IP ，适配 IpAddr 和 str
pub enum TargetIP<'a> {
    S(&'a str),
    I(IpNet),
}

pub enum TargetPort<'a> {
    S(&'a str),
    I(u16),
}

/// Parse either a host IP address or an IP network.
///
/// `IpNet` requires an explicit prefix length, while scanner results contain
/// host addresses. Normalize host addresses to their single-host networks so
/// both upload formats share the same validated representation.
pub(crate) fn parse_ip_or_cidr(value: &str) -> Result<IpNet, AddrParseError> {
    let value = value.trim();
    if value.contains('/') {
        value.parse()
    } else {
        let prefix = if value.contains(':') { 128 } else { 32 };
        format!("{value}/{prefix}").parse()
    }
}

/// Returns the two Elasticsearch representations used by scan observations.
///
/// Elasticsearch's `ip` type accepts only an address literal, while `ip_range`
/// accepts CIDR. Keeping both values lets callers submit either form without
/// discarding the original network prefix.
pub(crate) fn scan_observation_addresses(
    value: &str,
) -> Result<(String, String, IpAddr), AddrParseError> {
    let network = parse_ip_or_cidr(value)?;
    let address = network.addr();
    Ok((address.to_string(), network.to_string(), address))
}

/// 该函数用于解析ip地址，
/// 可以接收传入字符串IP，会自动解析，然后返回一个向量
pub(crate) fn parsing_target(ip: TargetIP) -> Result<Vec<IpNet>, AddrParseError> {
    let mut n_v: Vec<IpNet> = Vec::new();
    match ip {
        TargetIP::S(i_str) => {
            for tmp in i_str.split(",") {
                match parse_ip_or_cidr(tmp) {
                    Ok(o) => n_v.push(o),
                    Err(e) => {
                        error!(
                            event = "ScanTargetParseError",
                            operation = "parse_scan_target",
                            error_kind = "validation",
                            error_code = "scan_target_parse_failed",
                            error_message = %e,
                            retryable = false,
                            outcome = "task_validation_failed",
                        );
                        return Err(e);
                    }
                }
            }
            Ok(n_v)
        }
        TargetIP::I(ipadd) => {
            n_v.push(ipadd);
            Ok(n_v)
        }
    }
}

/// 该函数用于检查传入的 端口 是否合法
/// 返回 布尔 值，如果含有不合法字符就会返回 false
pub(crate) fn check_port(port: &str) -> bool {
    let re = Regex::new(r"^[0-9,\-]+$");
    match re {
        Ok(o) => o.is_match(port),
        Err(e) => {
            error!(
                event = "PortValidationRegexError",
                operation = "compile_port_validation_regex",
                error_kind = "configuration",
                error_code = "port_validation_regex_compile_failed",
                error_message = %e,
                retryable = false,
                outcome = "port_validation_failed_closed",
            );
            false
        }
    }
}

#[cfg(test)]
mod parse_ip_or_cidr_tests {
    use super::{TargetIP, parse_ip_or_cidr, scan_observation_addresses};
    use crate::result_ingest::validation::normalize_upload_observations;
    use crate::result_ingest::{ScannerObservation, ScannerResultUpload};
    use crate::scan_control::creation::{
        CreateTask, STask, build_scan_plan, display_scan_profile, is_ip_scan_profile,
    };

    #[test]
    fn accepts_plain_ipv4_as_single_host_network() {
        let parsed = parse_ip_or_cidr("221.233.151.58").unwrap();

        assert_eq!(parsed.to_string(), "221.233.151.58/32");
    }

    #[test]
    fn accepts_plain_ipv6_as_single_host_network() {
        let parsed = parse_ip_or_cidr("2001:db8::1").unwrap();

        assert_eq!(parsed.to_string(), "2001:db8::1/128");
    }

    #[test]
    fn accepts_ipv4_and_ipv6_cidr() {
        assert_eq!(
            parse_ip_or_cidr("192.0.2.0/24").unwrap().to_string(),
            "192.0.2.0/24"
        );
        assert_eq!(
            parse_ip_or_cidr("2001:db8::/48").unwrap().to_string(),
            "2001:db8::/48"
        );
    }

    #[test]
    fn rejects_invalid_ip() {
        assert!(parse_ip_or_cidr("not-an-ip").is_err());
        assert!(parse_ip_or_cidr("192.0.2.1/99").is_err());
    }

    #[test]
    fn builds_compatible_host_and_network_representations() {
        let (address, network, parsed) = scan_observation_addresses("192.0.2.10").unwrap();
        assert_eq!(address, "192.0.2.10");
        assert_eq!(network, "192.0.2.10/32");
        assert_eq!(parsed.to_string(), address);

        let (address, network, _) = scan_observation_addresses("192.0.2.0/24").unwrap();
        assert_eq!(address, "192.0.2.0");
        assert_eq!(network, "192.0.2.0/24");

        let (address, network, _) = scan_observation_addresses("2001:db8::1/128").unwrap();
        assert_eq!(address, "2001:db8::1");
        assert_eq!(network, "2001:db8::1/128");
    }

    #[test]
    fn tasks_must_use_one_address_family() {
        let ipv4 =
            STask::new(TargetIP::S("192.0.2.1,198.51.100.0/24"), "test", None, None).unwrap();
        assert_eq!(ipv4.address_family(), Ok("ipv4"));

        let ipv6 = STask::new(TargetIP::S("2001:db8::1"), "test", None, None).unwrap();
        assert_eq!(ipv6.address_family(), Ok("ipv6"));

        let mixed = STask::new(TargetIP::S("192.0.2.1,2001:db8::1"), "test", None, None).unwrap();
        assert!(mixed.address_family().is_err());
    }

    #[test]
    fn scan_profiles_expand_to_allowlisted_plans() {
        let ports = build_scan_plan("port_only").unwrap();
        assert_eq!(ports["version"], 1);
        assert_eq!(ports["stages"].as_array().unwrap().len(), 1);

        let inventory = build_scan_plan("service_inventory").unwrap();
        assert_eq!(inventory["stages"].as_array().unwrap().len(), 2);
        let vulnerabilities = build_scan_plan("vulnerability_scan").unwrap();
        assert_eq!(vulnerabilities["stages"].as_array().unwrap().len(), 3);
        assert_eq!(
            vulnerabilities["stages"][2]["type"],
            "vulnerability_detection"
        );
        let dns = build_scan_plan("dns_records").unwrap();
        assert_eq!(dns["stages"][0]["type"], "dns_lookup");
        let dns_ports = build_scan_plan("dns_ports").unwrap();
        assert_eq!(dns_ports["stages"][1]["type"], "port_discovery");
        let dns_full = build_scan_plan("dns_full").unwrap();
        assert_eq!(dns_full["stages"][0]["type"], "dns_lookup");
        assert!(build_scan_plan("arbitrary_command").is_err());
    }

    #[test]
    fn only_ip_profiles_can_be_used_as_the_system_default() {
        for profile in [
            "legacy",
            "port_only",
            "service_inventory",
            "vulnerability_scan",
        ] {
            assert!(is_ip_scan_profile(profile));
        }
        for profile in ["dns_records", "dns_ports", "dns_full"] {
            assert!(!is_ip_scan_profile(profile));
        }
    }

    #[test]
    fn domain_parent_displays_the_requested_follow_up_profile() {
        let metadata = serde_json::json!({
            "dns_follow_up": {"enabled": true, "scan_profile": "vulnerability_scan"}
        });
        assert_eq!(
            display_scan_profile("dns_records", Some(&metadata)),
            "vulnerability_scan"
        );
        assert_eq!(display_scan_profile("dns_records", None), "dns_records");
    }

    #[test]
    fn create_task_may_defer_scan_profile_to_system_settings() {
        let task: CreateTask = serde_json::from_value(serde_json::json!({
            "ip": "192.0.2.1",
            "port": "443",
            "level": 1,
            "remark": null
        }))
        .unwrap();

        assert!(task.scan_profile.is_none());
    }

    #[test]
    fn result_protocol_accepts_legacy_and_typed_payloads() {
        let legacy: ScannerResultUpload = serde_json::from_value(serde_json::json!({
            "scanner_id": "019c0000-0000-7000-8000-000000000001",
            "task_id": "019c0000-0000-7000-8000-000000000002",
            "results": []
        }))
        .unwrap();
        assert_eq!(legacy.protocol_version, 1);

        let typed: ScannerResultUpload = serde_json::from_value(serde_json::json!({
            "protocol_version": 2,
            "scanner_id": "019c0000-0000-7000-8000-000000000001",
            "task_id": "019c0000-0000-7000-8000-000000000002",
            "upload_id": "019c0000-0000-7000-8000-000000000003",
            "batch_index": 0,
            "is_final": true,
            "observations": [{
                "kind": "port",
                "ip": "192.0.2.1",
                "port": 443,
                "protocol": "tcp",
                "state": "open",
                "source": "masscan"
            }]
        }))
        .unwrap();
        assert_eq!(typed.protocol_version, 2);
        assert!(matches!(
            typed.observations[0],
            ScannerObservation::Port { .. }
        ));

        let vulnerability: ScannerResultUpload = serde_json::from_value(serde_json::json!({
            "protocol_version": 3,
            "scanner_id": "019c0000-0000-7000-8000-000000000001",
            "task_id": "019c0000-0000-7000-8000-000000000002",
            "upload_id": "019c0000-0000-7000-8000-000000000003",
            "batch_index": 0,
            "is_final": true,
            "observations": [{
                "kind": "vulnerability",
                "ip": "192.0.2.1",
                "port": 443,
                "protocol": "https",
                "template_id": "cve-test",
                "name": "Example vulnerability",
                "severity": "high",
                "matcher_name": "body",
                "matched_at": "https://192.0.2.1/",
                "tags": ["cve"],
                "references": ["https://example.test/advisory"],
                "extracted_results": [],
                "source": "nuclei",
                "observed_at": 1788393600000_i64
            }]
        }))
        .unwrap();
        assert_eq!(vulnerability.protocol_version, 3);
        let normalized = normalize_upload_observations(&vulnerability).unwrap();
        assert_eq!(normalized[0].kind, "vulnerability");
        assert_eq!(
            normalized[0].data.as_ref().unwrap()["template_id"],
            "cve-test"
        );
    }
}
