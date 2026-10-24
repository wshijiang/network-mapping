//! scan_control / creation domain implementation, migrated from the library root.

use deadpool_postgres::GenericClient;
use ipnet::{AddrParseError, IpNet};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::target::{TargetIP, check_port, parsing_target};
use crate::{admin, audit};

/// 该结构体用于接收用户创建任务时的数据
/// 仅有三个参数
#[derive(Deserialize)]
pub struct CreateTask {
    pub ip: String,
    pub port: String,
    pub level: i8,
    pub remark: Option<String>,
    #[serde(default = "default_dispatch_mode")]
    pub dispatch_mode: String,
    #[serde(default)]
    pub scanner_ids: Vec<Uuid>,
    #[serde(default)]
    pub scan_profile: Option<String>,
    #[serde(default)]
    pub required_services: Vec<String>,
    #[serde(default)]
    pub service_probe_options: ServiceProbeOptions,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServiceProbeOptions {
    pub modbus_unit_id: Option<u8>,
    pub s7_tsap: Option<u16>,
    pub mqtt_version: Option<u8>,
    pub server_name: Option<String>,
    pub doh_path: Option<String>,
    pub tls_ca_pem: Option<String>,
    pub passive_bind: Option<String>,
    pub passive_group: Option<String>,
    pub passive_interface: Option<String>,
    pub passive_window_seconds: Option<u16>,
}
impl ServiceProbeOptions {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.mqtt_version.is_some_and(|v| !matches!(v, 4 | 5)) {
            return Err("MQTT protocol version must be 4 (3.1.1) or 5");
        }
        if self.server_name.as_ref().is_some_and(|s| {
            s.is_empty()
                || s.len() > 253
                || !s.split('.').all(|l| {
                    !l.is_empty()
                        && l.len() <= 63
                        && !l.starts_with('-')
                        && !l.ends_with('-')
                        && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
        }) {
            return Err("invalid probe server name");
        }
        if self.doh_path.as_ref().is_some_and(|s| {
            s.len() > 256
                || !s.starts_with('/')
                || s.starts_with("//")
                || s.bytes()
                    .any(|b| b.is_ascii_control() || matches!(b, b'?' | b'#' | b' '))
        }) {
            return Err("invalid DNS-over-HTTPS path");
        }
        if self.tls_ca_pem.as_ref().is_some_and(|s| {
            s.is_empty()
                || s.len() > 65536
                || !s.contains("-----BEGIN CERTIFICATE-----")
                || s.contains("PRIVATE KEY")
        }) {
            return Err("invalid probe CA certificate");
        }
        Ok(())
    }
}
pub fn build_service_scan_plan_with_options(
    profile: &str,
    services: &[String],
    options: &ServiceProbeOptions,
) -> Result<Value, &'static str> {
    options.validate()?;
    let automatic_tcp =
        services.is_empty() && matches!(profile, "service_inventory" | "vulnerability_scan");
    let has_passive = options.passive_bind.is_some()
        || options.passive_group.is_some()
        || options.passive_interface.is_some()
        || options.passive_window_seconds.is_some();
    if profile == "udp_passive" {
        validate_passive_options(options)?;
    } else if has_passive {
        return Err("passive options require udp_passive profile");
    }

    if profile == "udp_inventory" && *options != ServiceProbeOptions::default() {
        return Err("UDP inventory does not accept TCP probe options");
    }
    if (options.server_name.is_some() || options.tls_ca_pem.is_some())
        && !automatic_tcp
        && !services
            .iter()
            .any(|s| matches!(s.as_str(), "dot" | "doh" | "mqtts"))
    {
        return Err("TLS options require an encrypted protocol");
    }
    if options.doh_path.is_some() && !automatic_tcp && !services.iter().any(|s| s == "doh") {
        return Err("DoH path requires DoH selection");
    }
    if options.modbus_unit_id.is_some() && !automatic_tcp && !services.iter().any(|s| s == "modbus")
    {
        return Err("unit ID requires Modbus selection");
    }
    if options.s7_tsap.is_some() && !automatic_tcp && !services.iter().any(|s| s == "s7") {
        return Err("TSAP requires S7 selection");
    }
    if options.mqtt_version.is_some()
        && !automatic_tcp
        && !services
            .iter()
            .any(|s| matches!(s.as_str(), "mqtt" | "mqtts"))
    {
        return Err("MQTT version requires MQTT selection");
    }
    let mut plan = build_service_scan_plan(profile, services)?;
    if *options != ServiceProbeOptions::default() {
        plan["service_probe_options"] = serde_json::json!(options);
    }
    Ok(plan)
}

pub(crate) fn default_dispatch_mode() -> String {
    "automatic".into()
}

pub fn build_scan_plan(profile: &str) -> Result<Value, &'static str> {
    let stages = match profile {
        "legacy" => serde_json::json!([
            {"type": "port_discovery", "required": true},
            {"type": "service_detection", "required": false}
        ]),
        "port_only" => serde_json::json!([
            {"type": "port_discovery", "required": true}
        ]),
        "udp_inventory" | "udp_passive" => {
            serde_json::json!([{"type":"service_detection","required":true}])
        }
        "service_inventory" => serde_json::json!([
            {"type": "port_discovery", "required": true},
            {"type": "service_detection", "required": true}
        ]),
        "vulnerability_scan" => serde_json::json!([
            {"type": "port_discovery", "required": true},
            {"type": "service_detection", "required": false},
            {"type": "vulnerability_detection", "required": true}
        ]),
        "dns_records" => serde_json::json!([
            {"type": "dns_lookup", "required": true}
        ]),
        "dns_ports" => serde_json::json!([
            {"type": "dns_lookup", "required": true},
            {"type": "port_discovery", "required": true}
        ]),
        "dns_full" => serde_json::json!([
            {"type": "dns_lookup", "required": true},
            {"type": "port_discovery", "required": true}
        ]),
        _ => return Err("unsupported scan profile"),
    };
    Ok(serde_json::json!({
        "version": if matches!(profile,"udp_inventory"|"udp_passive") {2} else {1},
        "profile": profile,
        "stages": stages,
    }))
}

/// Empty TCP requirements enable automatic detection. UDP plans persist their
/// automatic protocol set so dispatch, recovery and workers share requirements.
pub fn build_service_scan_plan(profile: &str, services: &[String]) -> Result<Value, &'static str> {
    if matches!(profile, "udp_inventory" | "udp_passive") {
        let defaults = if profile == "udp_passive" {
            vec!["opcua_pubsub".into(), "enip_io".into()]
        } else {
            vec!["dns_udp".into(), "enip_udp".into(), "bacnet".into()]
        };
        let services = if services.is_empty() {
            &defaults
        } else {
            services
        };
        if services.len() > if profile == "udp_passive" { 2 } else { 3 }
            || services.iter().any(|s| {
                if profile == "udp_passive" {
                    !matches!(s.as_str(), "opcua_pubsub" | "enip_io")
                } else {
                    !matches!(s.as_str(), "dns_udp" | "enip_udp" | "bacnet")
                }
            })
            || services
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != services.len()
        {
            return Err("unsupported UDP service protocols");
        }
        let mut plan = build_scan_plan(profile)?;
        plan["required_services"] = serde_json::json!(services);
        return Ok(plan);
    }
    if services.len() > 10
        || services.iter().any(|s| {
            !matches!(
                s.as_str(),
                "dns"
                    | "vnc"
                    | "dot"
                    | "doh"
                    | "modbus"
                    | "enip"
                    | "s7"
                    | "opcua"
                    | "mqtt"
                    | "mqtts"
            )
        })
        || services
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != services.len()
        || (!services.is_empty() && !matches!(profile, "service_inventory" | "vulnerability_scan"))
    {
        return Err("unsupported required service protocols or scan profile");
    }
    let mut plan = build_scan_plan(profile)?;
    if !services.is_empty() {
        plan["required_services"] = serde_json::json!(services);
        for stage in plan["stages"].as_array_mut().unwrap() {
            if stage["type"] == "service_detection" {
                stage["required"] = Value::Bool(true);
            }
        }
    }
    Ok(plan)
}

#[cfg(test)]
mod service_plan_tests {
    use super::*;
    #[test]
    fn explicit_service_requirements_are_bounded_and_need_a_service_stage() {
        let plan =
            build_service_scan_plan("vulnerability_scan", &["dns".into(), "vnc".into()]).unwrap();
        assert_eq!(plan["required_services"], serde_json::json!(["dns", "vnc"]));
        assert_eq!(plan["stages"][1]["required"], true);
        assert!(build_service_scan_plan("port_only", &["dns".into()]).is_err());
        assert!(build_service_scan_plan("dns_records", &["dns".into()]).is_err());
        assert!(
            build_service_scan_plan("service_inventory", &["unknown-protocol".into()]).is_err()
        );
        assert!(
            build_service_scan_plan("service_inventory", &["dns".into(), "dns".into()]).is_err()
        );
        assert_eq!(
            build_service_scan_plan("port_only", &[]).unwrap(),
            build_scan_plan("port_only").unwrap()
        );
    }
}

/// Profiles valid for IP/CIDR tasks and the system-wide default. DNS profiles
/// require the dedicated domain-task endpoint and must never be inherited by
/// an IP task.
pub fn is_ip_scan_profile(profile: &str) -> bool {
    matches!(
        profile,
        "legacy" | "port_only" | "service_inventory" | "vulnerability_scan"
    )
}

/// Returns the profile selected by the user for display purposes. A domain
/// follow-up request keeps `dns_records` as its executable parent profile and
/// stores the requested IP profile in generation metadata.
pub fn display_scan_profile(stored_profile: &str, generation_metadata: Option<&Value>) -> String {
    generation_metadata
        .and_then(|metadata| metadata.pointer("/dns_follow_up/scan_profile"))
        .and_then(Value::as_str)
        .filter(|profile| is_ip_scan_profile(profile))
        .unwrap_or(stored_profile)
        .to_owned()
}

/// 该结构体用于表示一个任务，该结构体不适合直接接收用户创建任务时的数据
#[derive(Serialize)]
pub struct CreatedTasks {
    pub task_ids: Vec<String>,
    pub task_group_id: Option<Uuid>,
}

pub struct STask<'a> {
    pub task_id: Option<uuid::Uuid>,
    pub task_initiator: &'a str,
    pub ip: Vec<IpNet>,
    // u16 刚好 0~65535，如果不提供则默认为全端口，当然可以在配置文件中配置默认端口
    pub port: Option<&'a str>,
    pub start_at: Option<i64>,
    pub end_at: Option<i64>,
    pub remark: Option<&'a str>,
}

impl STask<'_> {
    pub fn address_family(&self) -> Result<&'static str, &'static str> {
        let has_ipv4 = self.ip.iter().any(|target| matches!(target, IpNet::V4(_)));
        let has_ipv6 = self.ip.iter().any(|target| matches!(target, IpNet::V6(_)));
        match (has_ipv4, has_ipv6) {
            (true, false) => Ok("ipv4"),
            (false, true) => Ok("ipv6"),
            (true, true) => Err("同一扫描任务不能混合 IPv4 和 IPv6 目标"),
            (false, false) => Err("扫描目标不能为空"),
        }
    }
}

impl<'a> STask<'a> {
    pub fn new(
        ip: TargetIP,
        initiator: &'a str,
        port: Option<&'a str>,
        remark: Option<&'a str>,
    ) -> Result<Self, AddrParseError> {
        let t_ip = parsing_target(ip)?;

        let t_port = match port {
            Some(p) if check_port(p) => p,
            Some(_) => "1-65535",
            None => "1-65535",
        };
        Ok(Self {
            task_id: Some(Uuid::now_v7()),
            task_initiator: initiator,
            ip: t_ip,
            port: Some(t_port),
            start_at: None,
            end_at: None,
            remark,
        })
    }

    /// 用于向数据库中添加一条扫描任务条目
    /// 返回一个 Result，当执行成功时返回 OK
    #[allow(clippy::too_many_arguments)]
    pub async fn add(
        &self,
        pool: &deadpool_postgres::Pool,
        level: i32,
        user_id: i32,
        dispatch_mode: &str,
        requested_scanners: &[Option<String>],
        scan_profile: &str,
        scan_plan: &Value,
        audit_context: &audit::AuditContext,
        actor: &admin::UserBaseI,
        maxmind: &crate::maxmind::MaxMindState,
    ) -> Result<CreatedTasks, Box<dyn std::error::Error>> {
        let mut p = pool.get().await?;
        let client = p.transaction().await?;
        let t_id = self
            .task_id
            .map(|task_id| task_id.to_string())
            .ok_or("task_id 为 None")?;

        let address_family = self.address_family()?;
        let groups = if dispatch_mode == "automatic"
            && super::routing::config(&client)
                .await
                .map_err(std::io::Error::other)?
                .enabled
        {
            super::routing::group_targets(&self.ip, |net| {
                super::routing::target_geo(&[net.to_string()], maxmind)
            })
        } else {
            vec![self.ip.clone()]
        };
        let group_id = (groups.len() > 1).then(Uuid::now_v7);
        let mut task_ids = Vec::new();
        for (index, group) in groups.iter().enumerate() {
            let public_id = if index == 0 {
                t_id.clone()
            } else {
                Uuid::now_v7().to_string()
            };
            task_ids.push(public_id.clone());
            let targets: Vec<String> = group.iter().map(ToString::to_string).collect();
            let task_db_id:i32 = client.query_one(
                "INSERT INTO scan_task (user_id, task_id, task_initiator, task_target, task_port, task_level, remarks, dispatch_mode, address_family, scan_profile, scan_plan, task_group_id) \
                 VALUES ($1,$2,$3,ARRAY(SELECT inet(unnest($4::text[]))),$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id",
                &[&user_id,&public_id,&self.task_initiator,&targets,&self.port,&level,&self.remark,&dispatch_mode,&address_family,&scan_profile,&scan_plan,&group_id]
            ).await?.get("id");
            for requested_scanner in requested_scanners {
                client.execute("INSERT INTO scan_task_execution(execution_id,task_id,requested_scanner_id) VALUES($1,$2,$3)", &[&Uuid::now_v7().to_string(),&task_db_id,requested_scanner]).await?;
            }
            let mut event = audit::AuditEvent::user("task", "task.create", "success", actor)
                .resource("task", public_id);
            event.response_status = Some(200);
            event.metadata = serde_json::json!({"dispatch_mode":dispatch_mode,"scanner_count":requested_scanners.len(),"target_count":group.len(),"scan_profile":scan_profile,"task_group_id":group_id,"group_task_count":groups.len()});
            audit::write(&client, audit_context, &event).await?;
        }

        client.commit().await?;
        Ok(CreatedTasks {
            task_ids,
            task_group_id: group_id,
        })
    }
}

pub fn validate_udp_targets(
    profile: &str,
    targets: &[String],
    ports: &str,
) -> Result<(), &'static str> {
    if !matches!(profile, "udp_inventory" | "udp_passive") {
        return Ok(());
    }
    let mut count = 0u128;
    for target in targets {
        let net: IpNet = target
            .parse()
            .or_else(|_| target.parse::<std::net::IpAddr>().map(Into::into))
            .map_err(|_| "invalid UDP IP target")?;
        if profile == "udp_passive" && !net.addr().is_ipv4() {
            return Err("passive receiver currently supports IPv4 only");
        }
        let bits = match net {
            IpNet::V4(n) => 32 - n.prefix_len(),
            IpNet::V6(n) => 128 - n.prefix_len(),
        };
        count = count.saturating_add(1u128.checked_shl(bits as u32).unwrap_or(u128::MAX));
        if count > 256 || net.addr().is_multicast() || net.addr().is_unspecified() {
            return Err("UDP inventory supports at most 256 unicast addresses");
        }
    }
    let mut selected = std::collections::HashSet::new();
    for part in ports.split(',') {
        let mut pair = part.trim().split('-');
        let first: u16 = pair
            .next()
            .unwrap_or("")
            .parse()
            .map_err(|_| "explicit UDP ports required")?;
        let last: u16 = pair
            .next()
            .map(str::parse)
            .transpose()
            .map_err(|_| "invalid UDP range")?
            .unwrap_or(first);
        if first == 0 || last < first || last - first > 31 || pair.next().is_some() {
            return Err("UDP inventory supports at most 32 explicit ports");
        }
        selected.extend(first..=last);
        if selected.len() > 32 {
            return Err("UDP inventory supports at most 32 explicit ports");
        }
    }
    if profile == "udp_passive" && selected.len() != 1 {
        return Err("passive receiver requires exactly one listening port");
    }
    if count == 0 || selected.is_empty() {
        return Err("empty UDP targets");
    }
    Ok(())
}

fn validate_passive_options(o: &ServiceProbeOptions) -> Result<(), &'static str> {
    let bind: std::net::Ipv4Addr = o
        .passive_bind
        .as_ref()
        .ok_or("explicit local receiver IP required")?
        .parse()
        .map_err(|_| "invalid receiver IPv4")?;
    if bind.is_unspecified()
        || bind.is_multicast()
        || bind.is_broadcast()
        || o.passive_window_seconds
            .is_some_and(|s| !(1..=60).contains(&s))
    {
        return Err("invalid receiver address or observation window");
    }
    if let Some(group) = &o.passive_group {
        let group: std::net::Ipv4Addr = group.parse().map_err(|_| "invalid multicast group")?;
        if !group.is_multicast() || o.passive_interface.as_deref() != o.passive_bind.as_deref() {
            return Err("multicast requires explicit matching IPv4 interface");
        }
    } else if o.passive_interface.is_some() {
        return Err("multicast interface requires group");
    }
    if o.modbus_unit_id.is_some()
        || o.s7_tsap.is_some()
        || o.mqtt_version.is_some()
        || o.server_name.is_some()
        || o.doh_path.is_some()
        || o.tls_ca_pem.is_some()
    {
        return Err("TCP options are not valid for passive UDP");
    }
    Ok(())
}

#[cfg(test)]
mod protocol_options_tests {
    use super::*;
    #[test]
    fn automatic_detection_accepts_protocol_options_without_restricting_services() {
        let options = ServiceProbeOptions {
            server_name: Some("probe.internal".into()),
            doh_path: Some("/custom-dns".into()),
            modbus_unit_id: Some(7),
            s7_tsap: Some(258),
            mqtt_version: Some(5),
            ..Default::default()
        };
        for profile in ["service_inventory", "vulnerability_scan"] {
            let plan = build_service_scan_plan_with_options(profile, &[], &options).unwrap();
            assert!(plan.get("required_services").is_none());
            assert_eq!(plan["service_probe_options"]["mqtt_version"], 5);
        }
        for profile in ["port_only", "dns_records", "udp_inventory"] {
            assert!(build_service_scan_plan_with_options(profile, &[], &options).is_err());
        }
    }

    #[test]
    fn automatic_udp_requirements_are_persisted_for_dispatch_and_recovery() {
        let plan = build_service_scan_plan("udp_inventory", &[]).unwrap();
        assert_eq!(
            plan["required_services"],
            serde_json::json!(["dns_udp", "enip_udp", "bacnet"])
        );
        let options = ServiceProbeOptions {
            passive_bind: Some("192.0.2.1".into()),
            ..Default::default()
        };
        let plan = build_service_scan_plan_with_options("udp_passive", &[], &options).unwrap();
        assert_eq!(
            plan["required_services"],
            serde_json::json!(["opcua_pubsub", "enip_io"])
        );
    }

    #[test]
    fn encrypted_and_industrial_options_are_scoped_and_roundtrip() {
        let options = ServiceProbeOptions {
            server_name: Some("dns.internal".into()),
            doh_path: Some("/dns-query".into()),
            ..Default::default()
        };
        let plan =
            build_service_scan_plan_with_options("service_inventory", &["doh".into()], &options)
                .unwrap();
        assert_eq!(plan["service_probe_options"]["server_name"], "dns.internal");
        assert!(
            build_service_scan_plan_with_options("service_inventory", &["vnc".into()], &options)
                .is_err()
        );
        for path in [
            "https://other.test/dns-query",
            "//other.test/dns-query",
            "/dns?other=1",
            "/dns\r\n",
        ] {
            assert!(
                ServiceProbeOptions {
                    doh_path: Some(path.into()),
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            ServiceProbeOptions {
                mqtt_version: Some(3),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            ServiceProbeOptions {
                tls_ca_pem: Some("-----BEGIN CERTIFICATE-----\nPRIVATE KEY".into()),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        let industrial = ServiceProbeOptions {
            modbus_unit_id: Some(7),
            s7_tsap: Some(258),
            mqtt_version: Some(5),
            ..Default::default()
        };
        assert!(
            build_service_scan_plan_with_options(
                "service_inventory",
                &["modbus".into(), "s7".into(), "mqtt".into()],
                &industrial
            )
            .is_ok()
        );
    }
    #[test]
    fn udp_profiles_support_automatic_protocols_and_remain_version_two_and_bounded() {
        let plan = build_service_scan_plan_with_options(
            "udp_inventory",
            &["dns_udp".into(), "enip_udp".into()],
            &Default::default(),
        )
        .unwrap();
        assert_eq!(plan["version"], 2);
        assert_eq!(plan["stages"].as_array().unwrap().len(), 1);
        assert!(build_service_scan_plan("udp_inventory", &[]).is_ok());
        assert!(build_service_scan_plan("udp_inventory", &["dns".into()]).is_err());
        assert!(build_service_scan_plan("service_inventory", &["dns_udp".into()]).is_err());
        assert!(
            validate_udp_targets("udp_inventory", &["192.0.2.1".into()], "53,44818,47808").is_ok()
        );
        assert!(validate_udp_targets("udp_inventory", &["10.0.0.0/16".into()], "53").is_err());
        assert!(validate_udp_targets("udp_inventory", &["192.0.2.1".into()], "1-65535").is_err());
        let options = ServiceProbeOptions {
            passive_bind: Some("127.0.0.1".into()),
            passive_window_seconds: Some(1),
            ..Default::default()
        };
        let plan =
            build_service_scan_plan_with_options("udp_passive", &["opcua_pubsub".into()], &options)
                .unwrap();
        assert_eq!(plan["version"], 2);
        assert!(validate_udp_targets("udp_passive", &["192.0.2.1".into()], "2222,4840").is_err());
        assert!(
            build_service_scan_plan_with_options("service_inventory", &["opcua".into()], &options)
                .is_err()
        );
    }
}
