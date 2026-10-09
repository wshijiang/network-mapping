#![recursion_limit = "256"]

pub mod admin;
pub mod analytics_snapshot;
pub mod api_response;
pub mod audit;
pub mod backup;
pub mod cli_progress;
pub mod cli_user;
pub mod client_ip;
pub mod config;
pub mod config_check;
pub mod db;
pub mod dns;
pub mod dns_follow_up;
pub mod dns_resolvers;
pub mod elasticsearch;
pub mod frontend;
pub mod handlers;
pub mod login;
pub mod login_allowlist;
pub mod logs;
pub mod mail_template;
pub mod maxmind;
pub mod monitor;
pub mod target_generated;
pub mod tls;
pub mod trusted_proxy;

#[cfg(feature = "rir")]
pub mod rir; // 该模块用于从五大 RIR 获取 ASN 和组织等信息

// 自己的中间件
pub mod middlewares;
pub mod open_source;
pub mod reports;
pub mod request_log;
pub mod runtime_config;
pub mod scan_migration;
pub mod scanner_config;
pub mod scanner_diagnostics;
pub mod scanner_health;
pub mod scanner_latency;
pub mod scanner_outage;
mod search_content;
pub mod search_projection;
pub mod statistics;
pub mod system_maintenance;
pub mod system_resource_cache;
pub mod system_time;

#[cfg(test)]
pub mod test; // 测试模块

use actix_web::{HttpRequest, web};
use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use deadpool_postgres::GenericClient;
use ipnet::{AddrParseError, IpNet};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rand;
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};
use password_hash::rand_core::OsRng;
use password_hash::{PasswordHash, SaltString};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tera::{Context, Tera};
use tokio_postgres::Row;
use tokio_postgres::types::ToSql;
use tracing::{error, info, warn};
use uuid::Uuid;

use admin::TotpInfo;
use config::PasswordHashConfig;
use db::get_sql_from_file;
use elasticsearch::{
    DnsWriteMode, ElasticsearchService, ScanBatchContext, scan_batch_payload_checksum,
};
use logs::write::error_diagnostics;
use maxmind::MaxMindState;

//常量
pub const TEXT_HTML_UTF_8: &str = "text/html; charset=utf-8";
pub const TEXT_CSS_UTF_8: &str = "text/css; charset=utf-8";
pub const APPLICATION_JAVASCRIPT_UTF_8: &str = "application/javascript; charset=utf-8";
pub const IMAGE_PNG: &str = "image/png";
pub const APPLICATION_OCTET_STREAM: &str = "application/octet-stream";
pub const APPLICATION_JSON: &str = "application/json";

pub const TASK_LEASE_MS: i64 = 90_000;
const DNS_BATCH_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const DNS_BATCH_WRITE_LEASE_SECONDS: i64 = 45;

pub fn generate_scanner_token(prefix: &str) -> Result<String, io::Error> {
    let mut token_buffer = [0u8; 36];
    rand::rand_bytes(&mut token_buffer).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(format!(
        "{}_{}",
        prefix,
        openssl::base64::encode_block(&token_buffer)
    ))
}

pub fn hash_scanner_token(token: &str, pepper: &str) -> Result<String, io::Error> {
    let key = PKey::hmac(pepper.as_bytes()).map_err(|e| io::Error::other(e.to_string()))?;
    let mut signer =
        Signer::new(MessageDigest::sha256(), &key).map_err(|e| io::Error::other(e.to_string()))?;
    signer
        .update(token.as_bytes())
        .map_err(|e| io::Error::other(e.to_string()))?;
    let digest = signer
        .sign_to_vec()
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(openssl::base64::encode_block(&digest))
}

struct FrontEndErrorInfo<'a> {
    status_code: u16,
    error_title: &'a str,
    error_message: &'a str,
    request_id: String,
}

pub struct _ProxySetting {
    _status: bool,
    _headers: String,
}

pub struct UserLoginInfo {
    pub username: String,
    pub role: i32,
    pub email_address: Option<String>,
    pub twofa: Option<TotpInfo>,
    pub login_ip_allowlist: Vec<cidr::IpCidr>,
}

pub struct ReadFile {
    pub file_name: String,
    pub file_root_directory: String,
}

#[derive(Clone)]
pub struct TemplatesInit {
    pub templates_directory: String,
    pub templates_name: String,
}

//以下存储的数据都为约值，会自动舍弃精度
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DbResource {
    pub db_library_size: String,
    pub db_table_size: BTreeMap<String, DbTableSizeInfo>,
    pub db_conn: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DbTableSizeInfo {
    pub total: i64,
    pub data: i64,
    pub index: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemCPU {
    pub cpu_usage: f32,            //cpu总体使用率
    pub cpu: HashMap<String, f32>, //单个cpu使用率
}

//系统缓存大小，包括swap
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemRAM {
    pub total_ram: u64,
    pub used_ram: u64,
    pub ram_usage: f32,
    pub total_swap: u64,
    pub use_swap: u64,
    pub swap_usage: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemDisk {
    pub disk_total_space: u64,
    pub disk_total_usage: u64,
    pub disk: HashMap<String, Vec<u64>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemNetInfo {
    pub send: String,
    pub receive: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemNetwork {
    pub net: BTreeMap<String, SystemNetInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemResource {
    pub server_run_time: i64,
    pub cpu: SystemCPU,
    pub ram: SystemRAM,
    pub disk: SystemDisk,
    pub db_postgresql: DbResource,
    pub network: SystemNetwork,
    pub create_at: Option<i64>,
}

pub fn get_unix_epoch_ms() -> i64 {
    //todo 添加一个获取普通utc时间的函数，考虑用结构体还是权举
    // 当获取时间戳失败时会返回默认值-1
    // SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis() as i64,
        Err(e) => {
            error!(
                event = "UnixEpochGenerateError",
                operation = "read_system_time",
                error_kind = "system_clock",
                error_code = "system_clock_before_unix_epoch",
                error_message = %e,
                retryable = false,
                outcome = "sentinel_timestamp_returned",
                fallback_timestamp_ms = -1_i64,
            );
            -1_i64
        }
    }
}

//用于存储sysinfo 下必要的
#[derive(Clone)]
pub struct Systems {
    pub sys: Arc<Mutex<sysinfo::System>>,
    pub disk: Arc<Mutex<sysinfo::Disks>>,
    pub network: Arc<Mutex<sysinfo::Networks>>,
}

#[derive(Serialize, Deserialize)]
pub struct SystemDetails {
    pub host_name: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub kernel_version: Option<String>,
    pub architecture: String,
    pub cpu_model: Option<String>,
    pub cpu_vendor: Option<String>,
    pub cpu_frequency_mhz: Option<u64>,
    pub physical_core_count: Option<usize>,
    pub logical_cpu_count: usize,
}

impl Systems {
    pub fn new() -> Self {
        Self {
            sys: Arc::new(Mutex::new(sysinfo::System::new_all())),
            disk: Arc::new(Mutex::new(sysinfo::Disks::new_with_refreshed_list())),
            network: Arc::new(Mutex::new(sysinfo::Networks::new_with_refreshed_list())),
        }
    }
}

impl Default for Systems {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemDetails {
    pub fn new(systems: &Systems) -> Self {
        let sys = systems
            .sys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let first_cpu = sys.cpus().first();

        Self {
            host_name: sysinfo::System::host_name(),
            os_name: sysinfo::System::name(),
            os_version: sysinfo::System::long_os_version(),
            kernel_version: sysinfo::System::kernel_version(),
            architecture: sysinfo::System::cpu_arch(),
            cpu_model: first_cpu
                .map(|cpu| cpu.brand().trim().to_string())
                .filter(|value| !value.is_empty()),
            cpu_vendor: first_cpu
                .map(|cpu| cpu.vendor_id().trim().to_string())
                .filter(|value| !value.is_empty()),
            cpu_frequency_mhz: first_cpu.map(sysinfo::Cpu::frequency),
            physical_core_count: sysinfo::System::physical_core_count(),
            logical_cpu_count: sys.cpus().len(),
        }
    }
}

impl SystemCPU {
    pub fn new(sys: Arc<Mutex<sysinfo::System>>) -> Self {
        let mut cpu_usages = sys.lock().unwrap();
        cpu_usages.refresh_cpu_all();
        // let mut c_hash: HashMap<&str, f32> = HashMap::new();
        // cpu_usages.cpus().iter().map(|cpu| c_hash.insert(cpu.name(), cpu.cpu_usage()));

        let c_hash: HashMap<String, f32> = cpu_usages
            .cpus()
            .iter()
            .map(|cpu| (cpu.name().to_string(), cpu.cpu_usage()))
            .collect();

        Self {
            cpu_usage: cpu_usages.global_cpu_usage(),
            cpu: c_hash,
        }
    }
}

fn usage_percentage(used: u64, total: u64) -> f32 {
    if total == 0 {
        return 0.0;
    }

    (used as f64 / total as f64 * 100.0) as f32
}

impl SystemRAM {
    pub fn new(sys: Arc<Mutex<sysinfo::System>>) -> Self {
        let mut sys = sys.lock().unwrap();
        sys.refresh_memory();
        let total_m = sys.total_memory();
        let used_m = sys.used_memory();
        let total_s = sys.total_swap();
        let used_s = sys.used_swap();
        Self {
            ram_usage: usage_percentage(used_m, total_m),
            total_ram: total_m,
            used_ram: used_m,
            total_swap: total_s,
            use_swap: used_s,
            swap_usage: usage_percentage(used_s, total_s),
        }
    }
}

#[cfg(test)]
mod system_ram_tests {
    use super::usage_percentage;

    #[test]
    fn zero_total_has_zero_usage() {
        assert_eq!(usage_percentage(128, 0), 0.0);
    }

    #[test]
    fn usage_preserves_fractional_values() {
        assert_eq!(usage_percentage(1, 4), 25.0);
    }
}

impl SystemDisk {
    pub fn new(disk: Arc<Mutex<sysinfo::Disks>>) -> Self {
        let mut disk = disk.lock().unwrap();
        disk.refresh(true);
        let mut disk_total: u64 = 0;
        let mut disk_total_usage: u64 = 0;
        let mut d_h: HashMap<String, Vec<u64>> = HashMap::new();
        // disk.list().iter().map( |disk|
        //     disk_w(&mut disk_total, &mut disk_total_usage, &mut d_h, disk)
        // );
        // let d_h: HashMap<&str, Vec<u64>> = disk.list().iter().map( |disk|
        //     (disk.name(), ver!<disk.total_space(), disk.available_space()>)

        // )
        for d in disk.list() {
            disk_total += d.total_space();
            disk_total_usage += d.total_space() - d.available_space();
            d_h.insert(
                d.name().to_string_lossy().to_string(),
                vec![d.total_space(), d.available_space()],
            );
        }

        Self {
            disk_total_space: disk_total,
            disk_total_usage,
            disk: d_h,
        }
    }
}

impl SystemNetwork {
    pub fn new(net: Arc<Mutex<sysinfo::Networks>>) -> Self {
        let mut net = net.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        net.refresh(true);
        // The dashboard displays counters accumulated since system boot. The
        // received/transmitted methods only contain the latest refresh delta.
        let n_h: BTreeMap<String, SystemNetInfo> = net
            .list()
            .iter()
            .map(|(net_name, net_data)| {
                (
                    net_name.to_string(),
                    SystemNetInfo {
                        send: net_data.total_transmitted().to_string(),
                        receive: net_data.total_received().to_string(),
                    },
                )
            })
            .collect();

        Self { net: n_h }
    }
}

impl DbResource {
    pub async fn new(pool: &deadpool_postgres::Pool, sql_file_path: &str, db_name: &str) -> Self {
        let client = pool.get().await;
        // let mut db_h: HashMap<String, String> = HashMap::new();

        // let default_dbresource = DbResource {
        //     db_library_size: "null".to_string(),
        //     db_table_size: db_h.clone(),
        //     db_conn: "null".to_string()
        // };
        match client {
            Ok(o) => {
                //返回值的单位均为字节

                let db_table_size_sql =
                    get_sql_from_file(sql_file_path, "get_table_size.sql").await;
                let db_conn_sql = "SELECT COUNT(*) AS db_conn FROM pg_stat_activity;";
                let db_table_size = match db_table_size_sql {
                    Ok(sql) => get_db_table_size_byte(&o, &sql, &[]).await,
                    Err(e) => {
                        let diagnostics = error_diagnostics(e.as_ref());
                        error!(
                            event = "DatabaseMetricsSqlLoadError",
                            operation = "load_table_size_query",
                            error_kind = "filesystem",
                            error_code = "database_metrics_sql_load_failed",
                            error_message = %diagnostics.error_message,
                            error_chain = %diagnostics.error_chain,
                            root_cause = %diagnostics.root_cause,
                            error_truncated = diagnostics.error_truncated,
                            retryable = true,
                            outcome = "table_metrics_unavailable",
                            sql_file = "get_table_size.sql",
                        );
                        BTreeMap::from([("error".to_owned(), DbTableSizeInfo::default())])
                    }
                };

                Self {
                    db_library_size: get_db_library_size_byte(&o, db_name).await,
                    db_table_size,
                    db_conn: get_db_conn(&o, db_conn_sql, &[]).await,
                }
            }
            Err(e) => {
                let diagnostics = error_diagnostics(&e);
                error!(
                    event = "DatabaseMetricsPoolError",
                    operation = "acquire_metrics_connection",
                    error_kind = "database",
                    error_code = "database_metrics_pool_failed",
                    error_message = %diagnostics.error_message,
                    error_chain = %diagnostics.error_chain,
                    root_cause = %diagnostics.root_cause,
                    error_truncated = diagnostics.error_truncated,
                    retryable = true,
                    outcome = "database_metrics_unavailable",
                );
                //返回默认值
                DbResource::default()
            }
        }
    }
}

impl Default for DbResource {
    fn default() -> Self {
        let tmp = vec![("error".to_string(), DbTableSizeInfo::default())];
        let h: BTreeMap<String, DbTableSizeInfo> = tmp.into_iter().collect();
        Self {
            db_library_size: "none".to_string(),
            db_table_size: h,
            db_conn: "none".to_string(),
        }
    }
}

impl Default for DbTableSizeInfo {
    fn default() -> Self {
        Self {
            total: -1,
            data: -1,
            index: -1,
        }
    }
}

impl SystemResource {
    pub async fn new(sys: Systems, pool: &deadpool_postgres::Pool, db_name: &str) -> Self {
        Self {
            server_run_time: get_server_uptime() as i64,
            cpu: SystemCPU::new(sys.sys.clone()),
            ram: SystemRAM::new(sys.sys.clone()),
            disk: SystemDisk::new(sys.disk.clone()),
            db_postgresql: DbResource::new(pool, "source/database/", db_name).await,
            network: SystemNetwork::new(sys.network.clone()),
            create_at: None,
        }
    }
}

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
fn parse_ip_or_cidr(value: &str) -> Result<IpNet, AddrParseError> {
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
fn scan_observation_addresses(value: &str) -> Result<(String, String, IpAddr), AddrParseError> {
    let network = parse_ip_or_cidr(value)?;
    let address = network.addr();
    Ok((address.to_string(), network.to_string(), address))
}

#[cfg(test)]
mod parse_ip_or_cidr_tests {
    use super::{
        CreateTask, STask, ScannerObservation, ScannerResultUpload, TargetIP, build_scan_plan,
        display_scan_profile, is_ip_scan_profile, normalize_upload_observations, parse_ip_or_cidr,
        scan_observation_addresses,
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

/// 该函数用于解析ip地址，
/// 可以接收传入字符串IP，会自动解析，然后返回一个向量
fn parsing_target(ip: TargetIP) -> Result<Vec<IpNet>, AddrParseError> {
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
fn check_port(port: &str) -> bool {
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
}

fn default_dispatch_mode() -> String {
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
        "version": 1,
        "profile": profile,
        "stages": stages,
    }))
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut p = pool.get().await?;
        let client = p.transaction().await?;
        let t_id = self
            .task_id
            .map(|task_id| task_id.to_string())
            .ok_or("task_id 为 None")?;

        // 将 ipnet转换为 String
        let tmp_ip: Vec<String> = self.ip.iter().map(|i| i.to_string()).collect();
        let address_family = self.address_family()?;

        let task_row = client.query_one(
            "INSERT INTO scan_task (user_id, task_id, task_initiator, task_target, task_port, task_level, remarks, dispatch_mode, address_family, scan_profile, scan_plan) \
             VALUES ($1, $2, $3, ARRAY(SELECT inet(unnest($4::text[]))), $5, $6, $7, $8, $9, $10, $11) RETURNING id;",
            &[&user_id, &t_id, &self.task_initiator, &tmp_ip, &self.port, &level, &self.remark, &dispatch_mode, &address_family, &scan_profile, &scan_plan]
        ).await?;
        let task_db_id: i32 = task_row.get("id");
        for requested_scanner in requested_scanners {
            client.execute(
                "INSERT INTO scan_task_execution (execution_id, task_id, requested_scanner_id) VALUES ($1, $2, $3);",
                &[&Uuid::now_v7().to_string(), &task_db_id, requested_scanner],
            ).await?;
        }

        let mut audit_event =
            audit::AuditEvent::user("task", "task.create", "success", actor).resource("task", t_id);
        audit_event.response_status = Some(200);
        audit_event.metadata = serde_json::json!({
            "dispatch_mode": dispatch_mode,
            "scanner_count": requested_scanners.len(),
            "target_count": self.ip.len()
            ,"scan_profile": scan_profile
        });
        audit::write(&client, audit_context, &audit_event).await?;

        client.commit().await?;
        Ok(())
    }
}

///获取数据库表的大小，单位为字节
async fn get_db_table_size_byte(
    pool: &deadpool::managed::Object<deadpool_postgres::Manager>,
    // db_h: &mut HashMap<String, DbTableSizeInfo>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> BTreeMap<String, DbTableSizeInfo> {
    let result = pool.query(sql, params).await;
    match result {
        Ok(rows) => {
            rows.iter()
                .map(|row| {
                    (
                        row.get("table_name"),
                        DbTableSizeInfo {
                            total: row.get("total_size"),
                            data: row.get("data_size"),
                            index: row.get("index_size"),
                        },
                    )
                })
                .collect()
            // for row in rows {
            //     let key = row.get("table_name");
            //     let value: i64 = row.get("total_size");
            //     // let value = values.to_s
            //     db_h.insert(key, value.to_string());
            // }
        }
        Err(e) => {
            let diagnostics = error_diagnostics(&e);
            let database = diagnostics.database.as_ref();
            error!(
                event = "DatabaseMetricsQueryError",
                operation = "query_table_sizes",
                error_kind = "database",
                error_code = "database_table_metrics_query_failed",
                error_message = %diagnostics.error_message,
                error_chain = %diagnostics.error_chain,
                root_cause = %diagnostics.root_cause,
                error_truncated = diagnostics.error_truncated,
                retryable = true,
                outcome = "table_metrics_unavailable",
                sqlstate = ?database.map(|value| value.sqlstate.as_str()),
                db_constraint = ?database.and_then(|value| value.constraint.as_deref()),
            );
            vec![("error".to_string(), DbTableSizeInfo::default())]
                .into_iter()
                .collect()
        }
    }
}

///获取数据库的大小，单位为字节
async fn get_db_library_size_byte(
    pool: &deadpool::managed::Object<deadpool_postgres::Manager>,
    db_name: &str,
) -> String {
    let sql = "SELECT pg_database_size($1::text::name) AS db_size;";
    match pool.query_opt(sql, &[&db_name]).await {
        Ok(Some(row)) => {
            let r: i64 = row.get("db_size");
            r.to_string()
        }
        Ok(None) => {
            warn!(
                event = "DatabaseMetricsEmptyResult",
                operation = "query_database_size",
                database = db_name,
                "database size query returned no row"
            );
            "null".to_string()
        }
        Err(error_value) => {
            let diagnostics = error_diagnostics(&error_value);
            let database = diagnostics.database.as_ref();
            error!(
                event = "DatabaseMetricsQueryError",
                operation = "query_database_size",
                error_kind = "database",
                error_code = "database_size_query_failed",
                error_message = %diagnostics.error_message,
                error_chain = %diagnostics.error_chain,
                root_cause = %diagnostics.root_cause,
                error_truncated = diagnostics.error_truncated,
                retryable = true,
                outcome = "database_size_metric_unavailable",
                sqlstate = ?database.map(|value| value.sqlstate.as_str()),
                db_constraint = ?database.and_then(|value| value.constraint.as_deref()),
            );
            "null".to_string()
        }
    }
}

///获取数据库的连接数
async fn get_db_conn(
    pool: &deadpool::managed::Object<deadpool_postgres::Manager>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> String {
    match pool.query_opt(sql, params).await {
        Ok(Some(row)) => {
            let r: i64 = row.get("db_conn");
            r.to_string()
        }
        Ok(None) => {
            warn!(
                event = "DatabaseMetricsEmptyResult",
                operation = "query_connection_count",
                "database connection count query returned no row"
            );
            "null".to_string()
        }
        Err(error_value) => {
            let diagnostics = error_diagnostics(&error_value);
            let database = diagnostics.database.as_ref();
            error!(
                event = "DatabaseMetricsQueryError",
                operation = "query_connection_count",
                error_kind = "database",
                error_code = "database_connection_count_query_failed",
                error_message = %diagnostics.error_message,
                error_chain = %diagnostics.error_chain,
                root_cause = %diagnostics.root_cause,
                error_truncated = diagnostics.error_truncated,
                retryable = true,
                outcome = "connection_count_metric_unavailable",
                sqlstate = ?database.map(|value| value.sqlstate.as_str()),
                db_constraint = ?database.and_then(|value| value.constraint.as_deref()),
            );
            "null".to_string()
        }
    }
}

///获取服务器运行时间
fn get_server_uptime() -> u64 {
    sysinfo::System::uptime()
}

/// 生成 Argon2id 哈希
///
/// 用于添加用户
pub fn generate_hash_password(
    password: &str,
    config: PasswordHashConfig,
) -> Result<String, password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(config.m * 1024, config.t, config.p, None)?; // 配置文件中默认 64 MiB, 2 次迭代, 2 并行
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

/// 用于从数据库中获得用户的密码哈希值和在表中的 ID ，返回一个 Result<(i32, String), Error>
pub async fn get_password_and_id_from_database(
    pool: &deadpool_postgres::Pool,
    username: &str,
) -> Result<Option<(i32, String, UserLoginInfo)>, Box<dyn std::error::Error>> {
    let client = pool.get().await?;
    if let Some(row) = client.query_opt(
        "SELECT id, username, password, role, email, enable_2fa, totp_secret, login_ip_allowlist FROM users \
         WHERE limit_login = FALSE AND disabled_at IS NULL AND deleted_at IS NULL AND username = $1",
        &[&username]
    ).await? {
        // TODO 需要改进，避免闭包获得所有权
        let get_twofa_info = |row: Row| -> Option<TotpInfo> {
            if row.get::<_, bool>("enable_2fa") {
                Some(TotpInfo {
                    username: row.get::<_, String>("username"),
                    // email_address: row.get::<_, String>("email"),
                    totp_secret: row.get::<_, String>("totp_secret")
                })
            } else {
                None
            }
        };

        let u_id = row.get::<_, i32>("id");
        let u_pwd = row.get::<_, String>("password");

        let userinfo = UserLoginInfo {
            username: username.to_string(),
            role: row.get::<_, i32>("role"),
            email_address: row.get::<_, Option<String>>("email"),
            login_ip_allowlist: row.get("login_ip_allowlist"),
            twofa: get_twofa_info(row),
        };

        Ok(Some((u_id, u_pwd, userinfo)))
    }
    else {
        Ok(None)
    }
}

/// 校验密码
pub fn verify_password(password: &str, hash: &str) -> bool {
    let start = Instant::now();

    match PasswordHash::new(hash) {
        Ok(parsed_hash) => {
            let argon2 = Argon2::default();
            let result = argon2
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok();
            tracing::debug!(
                event = "PasswordHashVerified",
                duration_ms = start.elapsed().as_millis() as u64
            );
            result
        }
        Err(e) => {
            error!(
                event = "ParsedHashError",
                operation = "parse_password_hash",
                error_kind = "credential_storage",
                error_code = "stored_password_hash_invalid",
                error_message = %e,
                retryable = false,
                outcome = "authentication_failed_closed",
            );
            tracing::debug!(
                event = "PasswordHashVerificationFailed",
                duration_ms = start.elapsed().as_millis() as u64
            );
            false
        }
    }
}

///自实现MIME系统。接受一个&str类型的文件后缀，返回一个&str。
#[allow(dead_code)]
fn mime_system(file_suffix: &str) -> &str {
    match file_suffix.to_lowercase().as_str() {
        "html" => TEXT_HTML_UTF_8,
        "css" => TEXT_CSS_UTF_8,
        "png" => IMAGE_PNG,
        "js" => APPLICATION_JAVASCRIPT_UTF_8,
        _ => APPLICATION_OCTET_STREAM,
    }
}

///获取文件后缀，可以输入文件名或者是带路径的文件名 e.g example.png 、 directory/example.png
#[allow(dead_code)]
fn get_file_suffix(path_or_file_name: &Path) -> Result<&str, &str> {
    match path_or_file_name.extension().and_then(|s| s.to_str()) {
        Some(ext) => Ok(ext),
        None => {
            warn!("没有扩展名或无法获取扩展名");
            Err("没有扩展名或无法获取扩展名")
        }
    }
}

///# 前端错误页面
///
/// 该函数主要接受错误信息并根据模板返回错误页的HTML
fn front_end_error_page(info: &FrontEndErrorInfo, templates: &TemplatesInit) -> String {
    //在初始化模板时必须用相对路径
    let tera = match Tera::new(&templates.templates_directory) {
        Ok(t) => t,
        Err(e) => {
            error!(
                event = "FrontendTemplateInitializationError",
                operation = "initialize_frontend_templates",
                error_kind = "template",
                error_code = "frontend_template_initialization_failed",
                error_message = %e,
                retryable = false,
                outcome = "process_panicking",
            );
            panic!("tera初始化错误");
        }
    };

    let mut context = Context::new();
    context.insert("status_code", &info.status_code);
    context.insert("error_title", &info.error_title);
    context.insert("error_message", &info.error_message);
    context.insert("request_id", &info.request_id);

    match tera.render(&templates.templates_name, &context) {
        Ok(body) => body,
        Err(e) => {
            error!(
                event = "FrontendErrorPageRenderError",
                operation = "render_frontend_error_page",
                error_kind = "template",
                error_code = "frontend_error_page_render_failed",
                error_message = %e,
                retryable = false,
                outcome = "fallback_error_page_returned",
                http_status = info.status_code,
            );
            eprintln!("Render error: {}", e);
            "<h1>系统故障</h1><p>故障组件：模板系统</p>".to_string()
        }
    }
}

//获取系统状态
// async fn get_system_info(sys: System, pool: deadpool_postgres::Pool, get_timer: u16) {
//     let mut client = pool.get().await;
//     match client {
//         Ok(o) => {
//             let
//         },
//         Err(e) => {

//         }
//     };
// }

///系统信息api基准测试
pub async fn benchmark(
    sys: web::Data<Systems>,
    pool: web::Data<&deadpool_postgres::Pool>,
    db_name: String,
) {
    let total_start = Instant::now();
    let pool = pool.get_ref();

    // CPU
    let start = Instant::now();
    let cpu = SystemCPU::new(sys.sys.clone());
    let cpu_elapsed = start.elapsed();

    // RAM
    let start = Instant::now();
    let ram = SystemRAM::new(sys.sys.clone());
    let ram_elapsed = start.elapsed();

    // Disk
    let start = Instant::now();
    let disk = SystemDisk::new(sys.disk.clone());
    let disk_elapsed = start.elapsed();

    // DB
    let start = Instant::now();
    let db = DbResource::new(pool, "source/database/", &db_name).await;
    let db_elapsed = start.elapsed();

    //Network
    let start = Instant::now();
    let net = SystemNetwork::new(sys.network.clone());
    let net_elapsed = start.elapsed();

    let total_elapsed = total_start.elapsed();

    println!("================= Benchmark =================");
    println!("CPU   : {:>6} µs", cpu_elapsed.as_micros());
    println!("RAM   : {:>6} µs", ram_elapsed.as_micros());
    println!("Disk  : {:>6} µs", disk_elapsed.as_micros());
    println!("DB    : {:>6} µs", db_elapsed.as_micros());
    println!("Net   : {:>6} µs", net_elapsed.as_micros());
    println!("---------------------------------------------");
    println!("Total : {:>6} µs", total_elapsed.as_micros());
    println!("=============================================");

    // 防止编译器优化掉
    let _ = (cpu, ram, disk, db, net);
}

///调用者应当按照实际情况处理None值
/// 目前我感觉无需使用泛型 AsRef<Path>
pub fn path_secure_join(root: &str, input: &str) -> Option<PathBuf> {
    let root = Path::new(root);
    let full_path = root.join(input);
    let canonical = full_path.canonicalize().ok()?;

    if canonical.starts_with(root.canonicalize().ok()?) {
        Some(canonical)
    } else {
        None
    }
}

///向数据库插入系统数据
pub async fn insert_system_status(
    pool: &deadpool_postgres::Pool,
    db_name: String,
    sys: Systems,
    elasticsearch: &ElasticsearchService,
    cache: &system_resource_cache::SystemResourceCache,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 数据库指标是系统快照的附加信息，最多等待 3 秒；不能让其拖住 CPU/RAM 等
    // 实时数据的发布。连接池自身还有更短的 wait timeout 作为第一层保护。
    let mut s = match tokio::time::timeout(
        Duration::from_secs(3),
        SystemResource::new(sys.clone(), pool, &db_name),
    )
    .await
    {
        Ok(resource) => resource,
        Err(_) => {
            warn!(
                event = "SystemDatabaseMetricsTimeout",
                timeout_seconds = 3,
                "PostgreSQL 指标采集超时，本周期使用默认数据库指标"
            );
            SystemResource {
                server_run_time: get_server_uptime() as i64,
                cpu: SystemCPU::new(sys.sys.clone()),
                ram: SystemRAM::new(sys.sys.clone()),
                disk: SystemDisk::new(sys.disk.clone()),
                db_postgresql: DbResource::default(),
                network: SystemNetwork::new(sys.network.clone()),
                create_at: None,
            }
        }
    };
    s.create_at = Some(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
    );
    // 发布内存快照早于持久化。即使数据库正忙，仪表盘仍能读取本周期采集结果；
    // 随后的 INSERT 继续作为重启恢复和长期审计的权威数据源。
    cache.record(s.clone());
    // Elasticsearch 容量采集可能触发网络超时，必须发生在内存快照发布之后，且不能
    // 推迟 PostgreSQL 持久化。失败只使本周期 ES 容量字段标记为 unavailable。
    let elasticsearch_metrics =
        match tokio::time::timeout(Duration::from_secs(3), elasticsearch.storage_metrics()).await {
            Ok(metrics) => metrics,
            Err(_) => {
                warn!(
                    event = "ElasticsearchStorageMetricsTimeout",
                    timeout_seconds = 3,
                    "Elasticsearch 容量指标采集超时"
                );
                elasticsearch::ElasticsearchStorageMetrics::unavailable(elasticsearch.enabled())
            }
        };
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    let sql = get_sql_from_file("source/database/", "insert_system_status.sql").await?;
    let statement = transaction.prepare(&sql).await?;
    let server_run_time = s.server_run_time;
    let cpu = serde_json::to_value(&s.cpu).unwrap();
    let ram = serde_json::to_value(&s.ram).unwrap();
    let disk = serde_json::to_value(&s.disk).unwrap();
    let db_postgresql = serde_json::to_value(&s.db_postgresql).unwrap();
    let db_elasticsearch = serde_json::to_value(elasticsearch_metrics).unwrap();
    let network = serde_json::to_value(&s.network).unwrap();
    let raw = transaction
        .execute(
            &statement,
            &[
                &server_run_time,
                &cpu,
                &ram,
                &disk,
                &db_postgresql,
                &db_elasticsearch,
                &network,
            ],
        )
        .await?;
    if raw == 1 {
        transaction.commit().await?;
        Ok(())
    } else {
        let message = format!("插入表影响行数为 {}", raw);
        transaction.rollback().await?;
        warn!(
            event = "DATABASE-WARNING",
            path = "fn insert_system_status",
            message
        );
        Err(message.into())
    }
}

///通过该函数获取到访问者的ip，如果失败则会返回一个字符串
pub fn get_conn_ip(req: &HttpRequest) -> String {
    match crate::client_ip::request_ip(req) {
        Some(value) => value.to_string(),
        None => {
            warn!(
                event = "GetHTTPClientIPError",
                message = "无法获取到访问者IP"
            );
            "Unknown".to_string()
        }
    }
}

///通过该函数获取收到的http请求头，如果获取失败则会返回一个字符串
pub fn get_user_agent(req: &HttpRequest) -> String {
    // req.headers().get("User-Agent").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string()
    match req.headers().get("User-Agent") {
        Some(o) => match o.to_str() {
            Ok(o) => o.to_string(),
            Err(e) => {
                warn!(event = "GetHTTPHeadersError", message = e.to_string());
                "Unknown".to_string()
            }
        },
        None => {
            warn!(
                event = "UserAgentMissing",
                operation = "read_user_agent_header",
                reason = "request has no User-Agent header",
                outcome = "unknown_user_agent_used",
            );
            "Unknown".to_string()
        }
    }
}

#[derive(Serialize, Debug)]
pub struct ApplyTask {
    pub user_id: i32,
    pub task_id: Uuid,
    pub task_target: Vec<String>,
    pub task_port: String,
    pub address_family: String,
    pub scan_plan: Value,
    pub dns_resolvers: Value,
    pub lease_expires_at_ms: i64,
    pub lease_ttl_ms: i64,
}

#[derive(Clone, Deserialize)]
pub struct ScannerResultUpload {
    #[serde(default = "default_result_protocol_version")]
    pub protocol_version: u16,
    pub scanner_id: Uuid,
    pub task_id: Uuid,
    pub upload_id: Option<Uuid>,
    pub batch_index: Option<u32>,
    pub is_final: Option<bool>,
    #[serde(default)]
    pub observations: Vec<ScannerObservation>,
    #[serde(default)]
    pub results: Vec<ScannerResultItem>,
}

fn default_result_protocol_version() -> u16 {
    1
}

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScannerObservation {
    Port {
        ip: String,
        port: u16,
        protocol: String,
        state: String,
        source: String,
        #[serde(default)]
        observed_at: Option<i64>,
    },
    Service {
        ip: String,
        port: u16,
        protocol: String,
        service: Option<String>,
        banner: Option<String>,
        source: String,
        data: Option<Value>,
        #[serde(default)]
        observed_at: Option<i64>,
    },
    Dns {
        #[serde(flatten)]
        observation: dns::DnsObservation,
    },
    Vulnerability {
        ip: String,
        port: u16,
        protocol: String,
        template_id: String,
        name: String,
        severity: String,
        matcher_name: Option<String>,
        matched_at: String,
        description: Option<String>,
        remediation: Option<String>,
        #[serde(default)]
        tags: Vec<String>,
        #[serde(default)]
        references: Vec<String>,
        classification: Option<Value>,
        #[serde(default)]
        extracted_results: Vec<String>,
        source: String,
        #[serde(default)]
        observed_at: Option<i64>,
    },
}

#[derive(Clone, Deserialize)]
pub struct ScannerResultItem {
    pub ip: String,
    pub port: u16,
    pub protocol: Option<String>,
    pub service: Option<String>,
    pub banner: Option<String>,
    pub other: Option<Value>,
}

#[derive(Clone, Debug)]
struct NormalizedObservation {
    kind: &'static str,
    ip: String,
    port: u16,
    protocol: Option<String>,
    service: Option<String>,
    banner: Option<String>,
    source: String,
    data: Option<Value>,
    observed_at: Option<i64>,
}

#[derive(Debug)]
pub enum SaveScannerResultsError {
    Database(Box<dyn std::error::Error + Send + Sync>),
    Storage(String),
    BatchBusy {
        retry_after_seconds: u64,
    },
    InvalidIp {
        ip: String,
        source: AddrParseError,
    },
    ScannerUnauthorized,
    TaskNotFound,
    TaskNotOwned,
    UnsupportedProtocolVersion {
        received: u16,
    },
    InvalidBatchEnvelope {
        protocol_version: u16,
        reason: &'static str,
    },
    UploadIdentityConflict {
        execution_id: i32,
        received_upload_id: String,
        conflicting_upload_id: String,
        conflicting_upload_count: i64,
    },
    BatchPayloadConflict {
        execution_id: i32,
        upload_id: String,
        batch_index: i32,
        content_kind: &'static str,
        expected_checksum: Option<String>,
        received_checksum: String,
    },
    NonContiguousFinalBatch {
        execution_id: i32,
        upload_id: String,
        batch_index: i32,
        content_kind: &'static str,
    },
    CompletedExecutionNewBatch {
        execution_id: i32,
        upload_id: String,
        batch_index: i32,
    },
    ObservationLimitExceeded {
        actual: usize,
        limit: usize,
    },
    InvalidUpload(String),
}

#[derive(Debug)]
pub enum ApplyTaskError {
    Database(Box<dyn std::error::Error + Send + Sync>),
    ScannerUnauthorized,
    UnfinishedTask(Uuid),
    NoTask,
}

pub async fn validate_scanner_credentials(
    pool: &deadpool_postgres::Pool,
    scanner_id: Uuid,
    token: &str,
    token_pepper: &str,
) -> Result<(), ApplyTaskError> {
    let token_hash = hash_scanner_token(token, token_pepper).map_err(apply_task_database_error)?;
    let p = pool.get().await.map_err(apply_task_database_error)?;
    validate_scanner_credentials_with_client(&p, scanner_id, &token_hash).await
}

pub(crate) async fn validate_scanner_credentials_with_client<C>(
    client: &C,
    scanner_id: Uuid,
    token_hash: &str,
) -> Result<(), ApplyTaskError>
where
    C: GenericClient + Sync,
{
    let scanner = client.query_opt(
        "SELECT id FROM scanner_info WHERE scanner_id = $1 AND runtime_token_hash = $2 AND is_enable = true;",
        &[&scanner_id.to_string(), &token_hash]
    ).await.map_err(apply_task_database_error)?;

    if scanner.is_some() {
        Ok(())
    } else {
        Err(ApplyTaskError::ScannerUnauthorized)
    }
}

impl fmt::Display for ApplyTaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(e) => write!(f, "{}", e),
            Self::ScannerUnauthorized => write!(f, "扫描器认证失败"),
            Self::UnfinishedTask(task_id) => write!(f, "扫描器仍有未完成任务 {task_id}"),
            Self::NoTask => write!(f, "没有可领取的任务"),
        }
    }
}

impl std::error::Error for ApplyTaskError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(e) => Some(e.as_ref()),
            Self::ScannerUnauthorized | Self::UnfinishedTask(_) | Self::NoTask => None,
        }
    }
}

fn apply_task_database_error<E>(value: E) -> ApplyTaskError
where
    E: std::error::Error + Send + Sync + 'static,
{
    ApplyTaskError::Database(Box::new(value))
}

impl fmt::Display for SaveScannerResultsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(e) => write!(f, "{}", e),
            Self::Storage(message) => write!(f, "扫描事实存储失败：{message}"),
            Self::BatchBusy {
                retry_after_seconds,
            } => write!(f, "DNS 批次正在写入，请在 {retry_after_seconds} 秒后重试"),
            Self::InvalidIp { ip, source } => write!(f, "无效 IP/CIDR: {} ({})", ip, source),
            Self::ScannerUnauthorized => write!(f, "扫描器认证失败"),
            Self::TaskNotFound => write!(f, "任务不存在"),
            Self::TaskNotOwned => write!(f, "任务不属于当前扫描器或租约已失效"),
            Self::UnsupportedProtocolVersion { received } => {
                write!(
                    f,
                    "无效扫描结果上传: unsupported protocol_version {received}"
                )
            }
            Self::InvalidBatchEnvelope { reason, .. } => {
                write!(f, "无效扫描结果上传: {reason}")
            }
            Self::UploadIdentityConflict { .. } => write!(
                f,
                "无效扫描结果上传: an execution cannot contain batches from multiple upload_id values"
            ),
            Self::BatchPayloadConflict { content_kind, .. } => write!(
                f,
                "无效扫描结果上传: batch identity was already used with different {content_kind} content"
            ),
            Self::NonContiguousFinalBatch { content_kind, .. } => write!(
                f,
                "无效扫描结果上传: final {content_kind} batch requires one contiguous sequence starting at batch_index 0"
            ),
            Self::CompletedExecutionNewBatch { .. } => write!(
                f,
                "无效扫描结果上传: completed execution cannot accept a new batch"
            ),
            Self::ObservationLimitExceeded { actual, limit } => write!(
                f,
                "无效扫描结果上传: observation count {actual} exceeds limit {limit}"
            ),
            Self::InvalidUpload(message) => write!(f, "无效扫描结果上传: {message}"),
        }
    }
}

impl SaveScannerResultsError {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Database(_) => "database",
            Self::Storage(_) => "storage",
            Self::BatchBusy { .. } => "concurrency",
            Self::ScannerUnauthorized => "authentication",
            Self::TaskNotFound | Self::TaskNotOwned => "task_state",
            Self::InvalidIp { .. }
            | Self::UnsupportedProtocolVersion { .. }
            | Self::InvalidBatchEnvelope { .. }
            | Self::UploadIdentityConflict { .. }
            | Self::BatchPayloadConflict { .. }
            | Self::NonContiguousFinalBatch { .. }
            | Self::CompletedExecutionNewBatch { .. }
            | Self::ObservationLimitExceeded { .. }
            | Self::InvalidUpload(_) => "validation",
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Database(_) => "scan_result_database_operation_failed",
            Self::Storage(_) => "scan_result_storage_operation_failed",
            Self::BatchBusy { .. } => "scan_result_batch_busy",
            Self::InvalidIp { .. } => "invalid_observation_ip",
            Self::ScannerUnauthorized => "scanner_unauthorized",
            Self::TaskNotFound => "scan_task_not_found",
            Self::TaskNotOwned => "scan_task_not_owned",
            Self::UnsupportedProtocolVersion { .. } => "unsupported_protocol_version",
            Self::InvalidBatchEnvelope { .. } => "invalid_batch_envelope",
            Self::UploadIdentityConflict { .. } => "execution_upload_id_conflict",
            Self::BatchPayloadConflict { .. } => "batch_payload_conflict",
            Self::NonContiguousFinalBatch { .. } => "non_contiguous_final_batch",
            Self::CompletedExecutionNewBatch { .. } => "completed_execution_new_batch",
            Self::ObservationLimitExceeded { .. } => "observation_limit_exceeded",
            Self::InvalidUpload(_) => "invalid_scan_result_upload",
        }
    }

    pub fn operation(&self) -> &'static str {
        match self {
            Self::Database(_) => "persist_scan_result_database_state",
            Self::Storage(_) => "persist_scan_result_elasticsearch_data",
            Self::BatchBusy { .. } => "claim_scan_result_batch",
            Self::InvalidIp { .. } => "normalize_scan_observation",
            Self::ScannerUnauthorized => "authenticate_scanner",
            Self::TaskNotFound | Self::TaskNotOwned => "validate_scan_task_lease",
            Self::UnsupportedProtocolVersion { .. } | Self::InvalidBatchEnvelope { .. } => {
                "validate_scan_result_envelope"
            }
            Self::UploadIdentityConflict { .. } => "validate_execution_upload_identity",
            Self::BatchPayloadConflict { .. } => "validate_scan_result_batch_identity",
            Self::NonContiguousFinalBatch { .. } => "validate_scan_result_batch_sequence",
            Self::CompletedExecutionNewBatch { .. } => "validate_execution_state",
            Self::ObservationLimitExceeded { .. } | Self::InvalidUpload(_) => {
                "validate_scan_result_payload"
            }
        }
    }

    pub fn retryable(&self) -> bool {
        matches!(self, Self::Storage(_) | Self::BatchBusy { .. })
            || matches!(self, Self::Database(error) if error.downcast_ref::<deadpool_postgres::PoolError>()
                .is_some_and(|error| matches!(error, deadpool_postgres::PoolError::Timeout(_))))
    }

    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidIp { .. }
            | Self::UnsupportedProtocolVersion { .. }
            | Self::InvalidBatchEnvelope { .. }
            | Self::UploadIdentityConflict { .. }
            | Self::BatchPayloadConflict { .. }
            | Self::NonContiguousFinalBatch { .. }
            | Self::CompletedExecutionNewBatch { .. }
            | Self::ObservationLimitExceeded { .. }
            | Self::InvalidUpload(_) => 400,
            Self::ScannerUnauthorized => 401,
            Self::TaskNotFound => 404,
            Self::TaskNotOwned => 409,
            Self::Database(_) if self.retryable() => 503,
            Self::Database(_) => 500,
            Self::Storage(_) | Self::BatchBusy { .. } => 503,
        }
    }

    pub fn execution_id(&self) -> Option<i32> {
        match self {
            Self::UploadIdentityConflict { execution_id, .. }
            | Self::BatchPayloadConflict { execution_id, .. }
            | Self::NonContiguousFinalBatch { execution_id, .. }
            | Self::CompletedExecutionNewBatch { execution_id, .. } => Some(*execution_id),
            _ => None,
        }
    }

    pub fn conflicting_upload(&self) -> Option<(&str, i64)> {
        match self {
            Self::UploadIdentityConflict {
                conflicting_upload_id,
                conflicting_upload_count,
                ..
            } => Some((conflicting_upload_id, *conflicting_upload_count)),
            _ => None,
        }
    }

    pub fn batch_conflict_checksums(&self) -> Option<(Option<&str>, &str)> {
        match self {
            Self::BatchPayloadConflict {
                expected_checksum,
                received_checksum,
                ..
            } => Some((expected_checksum.as_deref(), received_checksum)),
            _ => None,
        }
    }
}

impl std::error::Error for SaveScannerResultsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(e) => Some(e.as_ref()),
            Self::Storage(_) | Self::BatchBusy { .. } => None,
            Self::InvalidIp { source, .. } => Some(source),
            Self::ScannerUnauthorized
            | Self::TaskNotFound
            | Self::TaskNotOwned
            | Self::UnsupportedProtocolVersion { .. }
            | Self::InvalidBatchEnvelope { .. }
            | Self::UploadIdentityConflict { .. }
            | Self::BatchPayloadConflict { .. }
            | Self::NonContiguousFinalBatch { .. }
            | Self::CompletedExecutionNewBatch { .. }
            | Self::ObservationLimitExceeded { .. }
            | Self::InvalidUpload(_) => None,
        }
    }
}

#[cfg(test)]
mod save_scanner_results_error_tests {
    use super::SaveScannerResultsError;

    #[test]
    fn pool_timeout_is_retryable_but_other_database_errors_are_not() {
        let error = SaveScannerResultsError::Database(Box::new(
            deadpool_postgres::PoolError::Timeout(deadpool::managed::TimeoutType::Wait),
        ));
        assert!(error.retryable());
        assert_eq!(error.http_status(), 503);
        let other =
            SaveScannerResultsError::Database(Box::new(std::io::Error::other("database failure")));
        assert!(!other.retryable());
        assert_eq!(other.http_status(), 500);
    }

    #[test]
    fn upload_identity_conflict_has_stable_diagnostics() {
        let error = SaveScannerResultsError::UploadIdentityConflict {
            execution_id: 17,
            received_upload_id: "received".into(),
            conflicting_upload_id: "existing".into(),
            conflicting_upload_count: 2,
        };
        assert_eq!(error.kind(), "validation");
        assert_eq!(error.code(), "execution_upload_id_conflict");
        assert_eq!(error.operation(), "validate_execution_upload_identity");
        assert_eq!(error.http_status(), 400);
        assert!(!error.retryable());
        assert_eq!(error.execution_id(), Some(17));
        assert_eq!(error.conflicting_upload(), Some(("existing", 2)));
        assert!(error.to_string().contains("multiple upload_id values"));
    }

    #[test]
    fn busy_and_storage_errors_are_retryable() {
        let busy = SaveScannerResultsError::BatchBusy {
            retry_after_seconds: 3,
        };
        let storage = SaveScannerResultsError::Storage("temporarily unavailable".into());
        assert!(busy.retryable());
        assert!(storage.retryable());
        assert_eq!(busy.http_status(), 503);
        assert_eq!(storage.http_status(), 503);
    }
}

fn scanner_result_database_error<E>(value: E) -> SaveScannerResultsError
where
    E: std::error::Error + Send + Sync + 'static,
{
    SaveScannerResultsError::Database(Box::new(value))
}

async fn record_dns_batch_write_error(
    pool: &deadpool_postgres::Pool,
    execution_id: i32,
    upload_id: &str,
    batch_index: i32,
    write_token: Uuid,
    message: &str,
) {
    let message = message.chars().take(2_000).collect::<String>();
    let Ok(Ok(client)) = tokio::time::timeout(Duration::from_secs(1), pool.get()).await else {
        warn!(
            event = "DnsBatchWriteErrorNotRecorded",
            execution_id, upload_id, batch_index, "无法获取 PostgreSQL 连接记录 DNS 批次写入错误"
        );
        return;
    };
    if let Err(error) = client
        .execute(
            "UPDATE scan_result_batch SET last_write_error = $5 \
             WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3 \
               AND storage_backend = 'pending' AND write_token = $4;",
            &[
                &execution_id,
                &upload_id,
                &batch_index,
                &write_token,
                &message,
            ],
        )
        .await
    {
        warn!(
            event = "DnsBatchWriteErrorNotRecorded",
            execution_id,
            upload_id,
            batch_index,
            %error,
            "记录 DNS 批次写入错误失败"
        );
    }
}

/// PostgreSQL 的 text/jsonb 类型不接受 NUL 字节，写入会报
/// 22P05 unsupported Unicode escape sequence。zgrab2 抓取的服务数据
/// （banner、响应体等）常含 NUL，写库前必须剔除。
fn sanitize_text(value: &str) -> String {
    if value.contains('\0') {
        value.replace('\0', "")
    } else {
        value.to_owned()
    }
}

fn sanitize_json_value(value: Value) -> Value {
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

fn sanitize_result_item(item: ScannerResultItem) -> ScannerResultItem {
    ScannerResultItem {
        protocol: item.protocol.map(|value| sanitize_text(&value)),
        service: item.service.map(|value| sanitize_text(&value)),
        banner: item.banner.map(|value| sanitize_text(&value)),
        other: item.other.map(sanitize_json_value),
        ..item
    }
}

fn normalize_upload_observations(
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

fn valid_vulnerability_data(data: Option<&Value>) -> bool {
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

// DNS storage uses a deterministic child identity, while the scanner's original
// identity owns the contiguous batch sequence and execution completion.
fn dns_sidecar_upload_id(upload_id: Uuid) -> Uuid {
    let digest = openssl::sha::sha256(format!("dns-observations:{upload_id}").as_bytes());
    Uuid::from_slice(&digest[..16]).expect("SHA-256 prefix has UUID length")
}

async fn validate_execution_upload_ids(
    transaction: &tokio_postgres::Transaction<'_>,
    execution_id: i32,
    upload_ids: &[String],
) -> Result<(), SaveScannerResultsError> {
    let conflict = transaction
        .query_one(
            "SELECT COUNT(DISTINCT upload_id)::BIGINT AS conflicting_count, \
                    MIN(upload_id) AS conflicting_upload_id \
             FROM scan_result_batch \
             WHERE execution_id = $1 AND NOT (upload_id = ANY($2::TEXT[]));",
            &[&execution_id, &upload_ids],
        )
        .await
        .map_err(scanner_result_database_error)?;
    let conflicting_upload_count: i64 = conflict.get("conflicting_count");
    if let Some(conflicting_upload_id) = conflict.get("conflicting_upload_id") {
        return Err(SaveScannerResultsError::UploadIdentityConflict {
            execution_id,
            received_upload_id: upload_ids.first().cloned().unwrap_or_default(),
            conflicting_upload_id,
            conflicting_upload_count,
        });
    }
    Ok(())
}

fn dns_batch_payload_checksum(
    execution_id: &str,
    upload_id: &str,
    batch_index: i32,
    is_final: bool,
    observations: &[&dns::DnsObservation],
) -> Result<String, SaveScannerResultsError> {
    let content = serde_json::to_vec(&serde_json::json!({
        "execution_id": execution_id,
        "upload_id": upload_id,
        "batch_index": batch_index,
        "is_final": is_final,
        "observations": observations,
    }))
    .map_err(scanner_result_database_error)?;
    Ok(openssl::sha::sha256(&content)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

async fn save_dns_scanner_results(
    pool: &deadpool_postgres::Pool,
    elasticsearch: &ElasticsearchService,
    dns_follow_up: &dns_follow_up::DnsFollowUpConfig,
    upload: &ScannerResultUpload,
    token: &str,
    token_pepper: &str,
    parent_upload_id: Option<Uuid>,
) -> Result<usize, SaveScannerResultsError> {
    if !elasticsearch.enabled() {
        return Err(SaveScannerResultsError::Storage(
            "DNS observations require elasticsearch.enabled=true".into(),
        ));
    }
    let observations = upload
        .observations
        .iter()
        .map(|item| match item {
            ScannerObservation::Dns { observation } => observation.clone().normalize(),
            _ => Err("a DNS upload batch may contain only DNS observations".to_owned()),
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(SaveScannerResultsError::InvalidUpload)?;
    let observation_count = i32::try_from(observations.len()).map_err(|_| {
        SaveScannerResultsError::ObservationLimitExceeded {
            actual: observations.len(),
            limit: i32::MAX as usize,
        }
    })?;
    let upload_id = upload
        .upload_id
        .expect("protocol v2 upload ID was validated")
        .to_string();
    let batch_index = i32::try_from(upload.batch_index.expect("protocol v2 batch was validated"))
        .map_err(|_| {
        SaveScannerResultsError::InvalidUpload("batch_index is too large".into())
    })?;
    let is_final = upload
        .is_final
        .expect("protocol v2 final flag was validated");
    let mut client = pool.get().await.map_err(scanner_result_database_error)?;
    let transaction = client
        .transaction()
        .await
        .map_err(scanner_result_database_error)?;
    transaction
        .batch_execute("SET LOCAL lock_timeout = '1500ms'; SET LOCAL statement_timeout = '5s';")
        .await
        .map_err(scanner_result_database_error)?;
    let token_hash =
        hash_scanner_token(token, token_pepper).map_err(scanner_result_database_error)?;
    let scanner_id = upload.scanner_id.to_string();
    let scanner = transaction
        .query_opt(
            "SELECT id FROM scanner_info WHERE scanner_id = $1 AND runtime_token_hash = $2 AND is_enable = true;",
            &[&scanner_id, &token_hash],
        )
        .await
        .map_err(scanner_result_database_error)?;
    if scanner.is_none() {
        return Err(SaveScannerResultsError::ScannerUnauthorized);
    }
    let task = transaction
        .query_opt(
            "SELECT t.id AS task_id, t.user_id, t.task_port, t.task_level, t.remarks, t.generation_metadata, \
             e.id AS execution_id, e.execution_id AS public_execution_id, e.execution_status, t.task_source, \
             COALESCE(s.name, e.assigned_scanner_id) AS scanner_name \
             FROM scan_task t JOIN scan_task_execution e ON e.task_id = t.id \
             LEFT JOIN scanner_info s ON s.scanner_id = e.assigned_scanner_id \
             WHERE t.task_id = $1 AND e.assigned_scanner_id = $2 \
             AND e.execution_status IN ('running', 'succeeded') LIMIT 1 FOR UPDATE OF e;",
            &[&upload.task_id.to_string(), &scanner_id],
        )
        .await
        .map_err(scanner_result_database_error)?;
    let Some(task) = task else {
        return Err(SaveScannerResultsError::TaskNotFound);
    };
    let already_succeeded = task.get::<_, String>("execution_status") == "succeeded";

    let task_db_id: i32 = task.get("task_id");
    let execution_db_id: i32 = task.get("execution_id");
    let mut allowed_upload_ids = vec![upload_id.clone()];
    if let Some(parent) = parent_upload_id {
        debug_assert_eq!(upload.upload_id, Some(dns_sidecar_upload_id(parent)));
        debug_assert!(!is_final);
        allowed_upload_ids.push(parent.to_string());
    }
    validate_execution_upload_ids(&transaction, execution_db_id, &allowed_upload_ids).await?;
    let context = ScanBatchContext {
        task_id: upload.task_id.to_string(),
        execution_id: task.get("public_execution_id"),
        user_id: task.get("user_id"),
        task_source: task.get("task_source"),
        scanner_id: scanner_id.clone(),
        scanner_name: task.get("scanner_name"),
        upload_id: upload_id.clone(),
        batch_index,
        is_final,
    };
    let follow_up_enabled = task
        .get::<_, Option<Value>>("generation_metadata")
        .as_ref()
        .and_then(|metadata| metadata.pointer("/dns_follow_up/enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let payload_checksum = dns_batch_payload_checksum(
        &context.execution_id,
        &upload_id,
        batch_index,
        is_final,
        &observations.iter().collect::<Vec<_>>(),
    )?;
    if is_final {
        let sequence = transaction
            .query_one(
                "SELECT COUNT(*) FILTER (WHERE batch_index < $3 AND storage_backend <> 'pending')::BIGINT AS prior_count, \
                 MIN(batch_index) FILTER (WHERE batch_index < $3) AS first_prior, \
                 MAX(batch_index) FILTER (WHERE batch_index < $3) AS last_prior, \
                 COUNT(*) FILTER (WHERE batch_index > $3)::BIGINT AS later_count, \
                 COUNT(*) FILTER (WHERE is_final)::BIGINT AS final_count, \
                 BOOL_OR(is_final) FILTER (WHERE batch_index = $3) AS current_is_final \
                 FROM scan_result_batch WHERE execution_id = $1 AND upload_id = $2;",
                &[&execution_db_id, &upload_id, &batch_index],
            )
            .await
            .map_err(scanner_result_database_error)?;
        let prior_count: i64 = sequence.get("prior_count");
        let first_prior: Option<i32> = sequence.get("first_prior");
        let last_prior: Option<i32> = sequence.get("last_prior");
        let complete_prior_sequence = if batch_index == 0 {
            prior_count == 0 && first_prior.is_none() && last_prior.is_none()
        } else {
            prior_count == i64::from(batch_index)
                && first_prior == Some(0)
                && last_prior == Some(batch_index - 1)
        };
        let final_count: i64 = sequence.get("final_count");
        let current_is_final: Option<bool> = sequence.get("current_is_final");
        let existing_final_valid = match current_is_final {
            Some(true) => final_count == 1,
            Some(false) => false,
            None => final_count == 0,
        };
        if !complete_prior_sequence
            || sequence.get::<_, i64>("later_count") != 0
            || !existing_final_valid
        {
            return Err(SaveScannerResultsError::NonContiguousFinalBatch {
                execution_id: execution_db_id,
                upload_id: upload_id.clone(),
                batch_index,
                content_kind: "DNS",
            });
        }
    }
    let write_token = Uuid::new_v4();
    let (write_attempts, write_mode) = if let Some(existing) = transaction
        .query_opt(
            "SELECT is_final, observation_count, payload_checksum, storage_backend FROM scan_result_batch \
             WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3;",
            &[&execution_db_id, &upload_id, &batch_index],
        )
        .await
        .map_err(scanner_result_database_error)?
    {
        let existing_checksum: Option<String> = existing.get("payload_checksum");
        let matches = existing.get::<_, bool>("is_final") == is_final
            && existing.get::<_, i32>("observation_count") == observation_count
            && existing_checksum.as_deref() == Some(payload_checksum.as_str());
        if !matches {
            return Err(SaveScannerResultsError::BatchPayloadConflict {
                execution_id: execution_db_id,
                upload_id: upload_id.clone(),
                batch_index,
                content_kind: "DNS",
                expected_checksum: existing_checksum,
                received_checksum: payload_checksum.clone(),
            });
        }
        if existing.get::<_, String>("storage_backend") != "pending" {
            transaction
                .commit()
                .await
                .map_err(scanner_result_database_error)?;
            return Ok(0);
        }
        let claimed = transaction
            .query_opt(
                "UPDATE scan_result_batch SET write_token = $4, \
                 write_lease_expires_at = clock_timestamp() + ($5::BIGINT * INTERVAL '1 second'), \
                 write_started_at = clock_timestamp(), write_attempts = write_attempts + 1, \
                 last_write_error = NULL \
                 WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3 \
                   AND storage_backend = 'pending' \
                   AND (write_token IS NULL OR write_lease_expires_at IS NULL \
                        OR write_lease_expires_at <= clock_timestamp()) \
                 RETURNING write_attempts;",
                &[
                    &execution_db_id,
                    &upload_id,
                    &batch_index,
                    &write_token,
                    &DNS_BATCH_WRITE_LEASE_SECONDS,
                ],
            )
            .await
            .map_err(scanner_result_database_error)?;
        let Some(claimed) = claimed else {
            let retry_after: i64 = transaction
                .query_one(
                    "SELECT GREATEST(1, CEIL(EXTRACT(EPOCH FROM \
                     (write_lease_expires_at - clock_timestamp())))::BIGINT) \
                     FROM scan_result_batch \
                     WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3;",
                    &[&execution_db_id, &upload_id, &batch_index],
                )
                .await
                .map_err(scanner_result_database_error)?
                .get(0);
            return Err(SaveScannerResultsError::BatchBusy {
                retry_after_seconds: u64::try_from(retry_after).unwrap_or(1),
            });
        };
        (
            claimed.get::<_, i32>("write_attempts"),
            DnsWriteMode::Reconcile,
        )
    } else {
        if already_succeeded {
            return Err(SaveScannerResultsError::CompletedExecutionNewBatch {
                execution_id: execution_db_id,
                upload_id: upload_id.clone(),
                batch_index,
            });
        }
        let write_attempts = transaction
            .query_one(
                "INSERT INTO scan_result_batch (execution_id, upload_id, batch_index, is_final, observation_count, \
                 protocol_version, payload_checksum, storage_backend, storage_references, write_token, \
                 write_lease_expires_at, write_attempts, write_started_at) \
                 VALUES ($1, $2, $3, $4, $5, 2, $6, 'pending', '[]'::JSONB, $7, \
                         clock_timestamp() + ($8::BIGINT * INTERVAL '1 second'), 1, clock_timestamp()) \
                 RETURNING write_attempts;",
                &[
                    &execution_db_id,
                    &upload_id,
                    &batch_index,
                    &is_final,
                    &observation_count,
                    &payload_checksum,
                    &write_token,
                    &DNS_BATCH_WRITE_LEASE_SECONDS,
                ],
            )
            .await
            .map_err(scanner_result_database_error)?
            .get::<_, i32>("write_attempts");
        (write_attempts, DnsWriteMode::Fresh)
    };
    // `pending` 是持久化的上传占位符。先提交占位符再访问 ES，可以释放任务行锁和
    // PostgreSQL 连接；进程中断后，同一批次会从 pending 状态幂等重试。
    transaction
        .commit()
        .await
        .map_err(scanner_result_database_error)?;
    drop(client);
    info!(
        event = "DnsBatchWriteClaimed",
        execution_id = execution_db_id,
        upload_id,
        batch_index,
        write_attempts,
        mode = ?write_mode,
        "DNS 批次写入租约已领取"
    );
    let dns_references = match tokio::time::timeout(
        DNS_BATCH_WRITE_TIMEOUT,
        elasticsearch.persist_dns_observations(&context, "default", &observations, write_mode),
    )
    .await
    {
        Ok(Ok(references)) => references,
        Ok(Err(message)) => {
            record_dns_batch_write_error(
                pool,
                execution_db_id,
                &upload_id,
                batch_index,
                write_token,
                &message,
            )
            .await;
            return Err(SaveScannerResultsError::Storage(message));
        }
        Err(_) => {
            let message = "DNS Elasticsearch 持久化超过固定 30 秒时间预算".to_owned();
            record_dns_batch_write_error(
                pool,
                execution_db_id,
                &upload_id,
                batch_index,
                write_token,
                &message,
            )
            .await;
            return Err(SaveScannerResultsError::Storage(message));
        }
    };
    let mut client = pool.get().await.map_err(scanner_result_database_error)?;
    let transaction = client
        .transaction()
        .await
        .map_err(scanner_result_database_error)?;
    transaction
        .batch_execute("SET LOCAL lock_timeout = '1500ms'; SET LOCAL statement_timeout = '10s';")
        .await
        .map_err(scanner_result_database_error)?;
    let current_execution = transaction
        .query_one("SELECT execution_status, assigned_scanner_id FROM scan_task_execution WHERE id = $1 FOR UPDATE", &[&execution_db_id])
        .await.map_err(scanner_result_database_error)?;
    if !matches!(
        current_execution
            .get::<_, String>("execution_status")
            .as_str(),
        "running" | "succeeded"
    ) || current_execution
        .get::<_, Option<String>>("assigned_scanner_id")
        .as_deref()
        != Some(scanner_id.as_str())
    {
        return Err(SaveScannerResultsError::TaskNotOwned);
    }
    let receipt_updated = transaction
        .execute(
            "UPDATE scan_result_batch SET storage_backend = 'elasticsearch', storage_references = $4, \
             write_token = NULL, write_lease_expires_at = NULL, last_write_error = NULL \
             WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3 \
             AND storage_backend = 'pending' AND write_token = $5;",
            &[
                &execution_db_id,
                &upload_id,
                &batch_index,
                &serde_json::json!(dns_references),
                &write_token,
            ],
        )
        .await
        .map_err(scanner_result_database_error)?;
    if receipt_updated == 0 {
        let receipt = transaction
            .query_one(
                "SELECT storage_backend, GREATEST(1, COALESCE(CEIL(EXTRACT(EPOCH FROM \
                 (write_lease_expires_at - clock_timestamp())))::BIGINT, 1)) AS retry_after \
                 FROM scan_result_batch \
                 WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3;",
                &[&execution_db_id, &upload_id, &batch_index],
            )
            .await
            .map_err(scanner_result_database_error)?;
        if receipt.get::<_, String>("storage_backend") != "pending" {
            transaction
                .commit()
                .await
                .map_err(scanner_result_database_error)?;
            return Ok(0);
        }
        let retry_after: i64 = receipt.get("retry_after");
        return Err(SaveScannerResultsError::BatchBusy {
            retry_after_seconds: u64::try_from(retry_after).unwrap_or(1),
        });
    }
    if follow_up_enabled {
        let resolved_ips = resolved_dns_answer_ips(&observations);
        if !resolved_ips.is_empty() {
            let values = resolved_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            transaction
                .execute(
                    "INSERT INTO dns_resolved_address (execution_id, task_id, ip_address) \
                     SELECT $1, $2, value::INET FROM UNNEST($3::TEXT[]) AS value \
                     ON CONFLICT (execution_id, ip_address) DO NOTHING;",
                    &[&execution_db_id, &task_db_id, &values],
                )
                .await
                .map_err(scanner_result_database_error)?;
        }
    }
    if is_final {
        transaction
            .execute(
                "UPDATE scan_task_execution SET execution_status = 'succeeded', task_end_time = $1, \
                 lease_expires_at = NULL, failure_reason = NULL, cancel_requested = false, \
                 maintenance_hold = FALSE, maintenance_hold_until = NULL, \
                 result_ip_count = 0, result_port_count = 0, result_observation_count = (SELECT COALESCE(SUM(observation_count), 0) FROM scan_result_batch WHERE execution_id = $2) WHERE id = $2;",
                &[&get_unix_epoch_ms(), &execution_db_id],
            )
            .await
            .map_err(scanner_result_database_error)?;
        refresh_task_aggregate(&transaction, task_db_id)
            .await
            .map_err(scanner_result_database_error)?;
        if follow_up_enabled {
            create_dns_follow_up_tasks(
                &transaction,
                &task,
                dns_follow_up,
                task_db_id,
                execution_db_id,
            )
            .await
            .map_err(scanner_result_database_error)?;
        }
        target_generated::search::record_success(&transaction, task_db_id)
            .await
            .map_err(scanner_result_database_error)?;
    }
    transaction
        .commit()
        .await
        .map_err(scanner_result_database_error)?;
    Ok(usize::try_from(observation_count).expect("non-negative observation count"))
}

fn resolved_dns_answer_ips(observations: &[dns::DnsObservation]) -> Vec<IpAddr> {
    observations
        .iter()
        .flat_map(|observation| observation.answers.iter())
        .filter(|answer| matches!(answer.record_type.as_str(), "A" | "AAAA"))
        .filter_map(|answer| answer.value.parse::<IpAddr>().ok())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

async fn create_dns_follow_up_tasks(
    transaction: &deadpool_postgres::Transaction<'_>,
    parent: &Row,
    policy: &dns_follow_up::DnsFollowUpConfig,
    parent_task_id: i32,
    parent_execution_id: i32,
) -> Result<(), tokio_postgres::Error> {
    let metadata: Value = parent.get("generation_metadata");
    let Some(follow_up) = metadata.get("dns_follow_up") else {
        return Ok(());
    };
    if follow_up.get("enabled").and_then(Value::as_bool) != Some(true) {
        return Ok(());
    }
    let scan_profile = follow_up
        .get("scan_profile")
        .and_then(Value::as_str)
        .unwrap_or("port_only");
    let stored_addresses = transaction
        .query(
            "SELECT host(ip_address) AS ip FROM dns_resolved_address WHERE execution_id = $1 ORDER BY ip_address;",
            &[&parent_execution_id],
        )
        .await?;
    let mut targets = BTreeMap::<&str, Vec<String>>::new();
    for row in stored_addresses {
        let ip: String = row.get("ip");
        let Ok(parsed) = ip.parse::<IpAddr>() else {
            continue;
        };
        if policy.enabled && policy.allows(parsed) {
            targets
                .entry(if parsed.is_ipv4() { "ipv4" } else { "ipv6" })
                .or_default()
                .push(parsed.to_string());
        }
    }
    let eligible_ip_count = targets.values().map(Vec::len).sum::<usize>();
    if !policy.enabled {
        transaction
            .execute(
                "INSERT INTO dns_follow_up_generation (execution_id, status, eligible_ip_count, created_task_count) \
                 VALUES ($1, 'blocked_policy', 0, 0) ON CONFLICT (execution_id) DO NOTHING;",
                &[&parent_execution_id],
            )
            .await?;
        return Ok(());
    }
    if eligible_ip_count == 0 {
        transaction
            .execute(
                "INSERT INTO dns_follow_up_generation (execution_id, status, eligible_ip_count, created_task_count) \
                 VALUES ($1, 'no_eligible_ip', 0, 0) ON CONFLICT (execution_id) DO NOTHING;",
                &[&parent_execution_id],
            )
            .await?;
        return Ok(());
    }
    let claimed = transaction
        .execute(
            "INSERT INTO dns_follow_up_generation (execution_id, status, eligible_ip_count, created_task_count) \
             VALUES ($1, 'succeeded', $2, 0) ON CONFLICT (execution_id) DO NOTHING;",
            &[&parent_execution_id, &(eligible_ip_count as i32)],
        )
        .await?;
    if claimed == 0 {
        return Ok(());
    }

    let user_id: i32 = parent.get("user_id");
    let port: String = parent.get("task_port");
    let level: i32 = parent.get("task_level");
    let parent_public_execution_id: String = parent.get("public_execution_id");
    let scan_plan =
        build_scan_plan(scan_profile).expect("stored DNS follow-up profile was validated");
    let mut created_task_count = 0_i32;
    for (family, family_targets) in targets {
        for (chunk_index, chunk) in family_targets
            .chunks(usize::from(policy.max_targets_per_task))
            .enumerate()
        {
            let task_id = Uuid::now_v7().to_string();
            let metadata = serde_json::json!({
                "dns_follow_up": {
                    "parent_task_id": parent_task_id,
                    "parent_execution_id": parent_public_execution_id,
                    "source": "dns_a_aaaa_answer",
                }
            });
            let task_pk: i32 = transaction
                .query_one(
                    "INSERT INTO scan_task (user_id, task_id, task_initiator, task_target, task_port, task_level, remarks, \
                     dispatch_mode, task_source, generation_strategy, generation_key, generation_metadata, address_family, scan_profile, scan_plan) \
                     VALUES ($1, $2, 'system', ARRAY(SELECT value::INET FROM UNNEST($3::TEXT[]) AS value), $4, $5, \
                     'DNS 解析自动生成端口扫描任务', 'automatic', 'dns_follow_up', 'dns_resolution', $6, $7, $8, $9, $10) \
                     RETURNING id;",
                    &[
                        &user_id,
                        &task_id,
                        &chunk,
                        &port,
                        &level,
                        &format!("dns:{parent_public_execution_id}:{family}:{chunk_index}"),
                        &metadata,
                        &family,
                        &scan_profile,
                        &scan_plan,
                    ],
                )
                .await?
                .get("id");
            transaction
                .execute(
                    "INSERT INTO scan_task_execution (execution_id, task_id, requested_scanner_id) VALUES ($1, $2, NULL);",
                    &[&Uuid::now_v7().to_string(), &task_pk],
                )
                .await?;
            transaction
                .execute(
                    "INSERT INTO scan_task_lineage (parent_task_id, parent_execution_id, child_task_id, source_addresses) \
                     VALUES ($1, $2, $3, ARRAY(SELECT value::INET FROM UNNEST($4::TEXT[]) AS value));",
                    &[&parent_task_id, &parent_execution_id, &task_pk, &chunk],
                )
                .await?;
            created_task_count += 1;
        }
    }
    transaction
        .execute(
            "UPDATE dns_follow_up_generation SET created_task_count = $2 WHERE execution_id = $1;",
            &[&parent_execution_id, &created_task_count],
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod dns_follow_up_tests {
    use super::resolved_dns_answer_ips;
    use crate::dns::{DnsAnswer, DnsObservation, DnsQuestion};

    fn observation(answers: Vec<(&str, &str)>) -> DnsObservation {
        DnsObservation {
            observed_at: 1,
            question: DnsQuestion {
                name: "example.test".into(),
                record_type: "A".into(),
                class: "IN".into(),
            },
            response_code: "NOERROR".into(),
            authoritative: false,
            truncated: false,
            dnssec_authenticated: false,
            answers: answers
                .into_iter()
                .map(|(record_type, value)| DnsAnswer {
                    record_type: record_type.into(),
                    value: value.into(),
                    ttl: 60,
                    priority: None,
                    weight: None,
                    port: None,
                })
                .collect(),
            authority: Vec::new(),
            additional: Vec::new(),
            resolver_ip: None,
            resolver_id: None,
            resolver_label: None,
            resolver_port: None,
            resolver_transport: None,
            latency_ms: None,
        }
    }

    #[test]
    fn resolved_dns_addresses_include_only_unique_a_and_aaaa_answers() {
        let resolved = resolved_dns_answer_ips(&[
            observation(vec![
                ("A", "192.0.2.10"),
                ("AAAA", "2001:db8::10"),
                ("CNAME", "alias.example.test"),
            ]),
            observation(vec![("A", "192.0.2.10"), ("A", "not-an-ip")]),
        ]);
        assert_eq!(
            resolved
                .into_iter()
                .map(|address| address.to_string())
                .collect::<Vec<_>>(),
            vec!["192.0.2.10", "2001:db8::10"]
        );
    }
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

pub async fn save_scanner_results(
    pool: &deadpool_postgres::Pool,
    maxmind: &MaxMindState,
    elasticsearch: &ElasticsearchService,
    dns_follow_up: &dns_follow_up::DnsFollowUpConfig,
    upload: &ScannerResultUpload,
    token: &str,
    token_pepper: &str,
) -> Result<usize, SaveScannerResultsError> {
    let is_typed = matches!(upload.protocol_version, 2 | 3);
    if upload.protocol_version != 1 && !is_typed {
        return Err(SaveScannerResultsError::UnsupportedProtocolVersion {
            received: upload.protocol_version,
        });
    }
    if is_typed
        && (upload.upload_id.is_none()
            || upload.batch_index.is_none()
            || upload.is_final.is_none()
            || !upload.results.is_empty())
    {
        return Err(SaveScannerResultsError::InvalidBatchEnvelope {
            protocol_version: upload.protocol_version,
            reason: "typed result protocols require upload_id, batch_index and is_final, accept only observations, and limit each batch to 500 observations",
        });
    }
    if is_typed && upload.observations.len() > 500 {
        return Err(SaveScannerResultsError::ObservationLimitExceeded {
            actual: upload.observations.len(),
            limit: 500,
        });
    }
    if !is_typed && !upload.observations.is_empty() {
        return Err(SaveScannerResultsError::InvalidBatchEnvelope {
            protocol_version: upload.protocol_version,
            reason: "typed observations require protocol_version 2 or 3",
        });
    }
    if upload.protocol_version == 2
        && upload
            .observations
            .iter()
            .any(|item| matches!(item, ScannerObservation::Vulnerability { .. }))
    {
        return Err(SaveScannerResultsError::InvalidBatchEnvelope {
            protocol_version: upload.protocol_version,
            reason: "vulnerability observations require protocol_version 3",
        });
    }

    let mut regular_upload = upload.clone();
    regular_upload
        .observations
        .retain(|item| !matches!(item, ScannerObservation::Dns { .. }));
    let mut dns_upload = upload.clone();
    dns_upload
        .observations
        .retain(|item| matches!(item, ScannerObservation::Dns { .. }));
    // Route DNS-only tasks by their persisted profile, not by this batch's
    // contents: a dns_full upload can start or end with a DNS-only batch.
    if is_typed && regular_upload.observations.is_empty() {
        let client = db::acquire_write_connection(pool, "classify_scan_profile")
            .await
            .map_err(scanner_result_database_error)?;
        let dns_only = client
            .query_opt(
                "SELECT scan_profile FROM scan_task WHERE task_id = $1;",
                &[&upload.task_id.to_string()],
            )
            .await
            .map_err(scanner_result_database_error)?
            .is_some_and(|row| row.get::<_, String>("scan_profile") == "dns_records");
        drop(client);
        if dns_only {
            return save_dns_scanner_results(
                pool,
                elasticsearch,
                dns_follow_up,
                upload,
                token,
                token_pepper,
                None,
            )
            .await;
        }
    }
    let normalized_observations = normalize_upload_observations(&regular_upload)?;
    // Normalize before reserving a primary receipt, so invalid DNS cannot leave
    // a permanently pending batch behind.
    for item in &mut dns_upload.observations {
        if let ScannerObservation::Dns { observation } = item {
            *observation = observation
                .clone()
                .normalize()
                .map_err(SaveScannerResultsError::InvalidUpload)?;
        }
    }
    if !dns_upload.observations.is_empty() && !elasticsearch.enabled() {
        return Err(SaveScannerResultsError::Storage(
            "DNS observations require elasticsearch.enabled=true".into(),
        ));
    }

    let mut client = db::acquire_write_connection(pool, "reserve_scan_batch")
        .await
        .map_err(scanner_result_database_error)?;
    let transaction = client
        .transaction()
        .await
        .map_err(scanner_result_database_error)?;
    transaction
        .batch_execute("SET LOCAL lock_timeout = '1500ms'; SET LOCAL statement_timeout = '10s';")
        .await
        .map_err(scanner_result_database_error)?;
    let token_hash =
        hash_scanner_token(token, token_pepper).map_err(scanner_result_database_error)?;
    let scanner_id = upload.scanner_id.to_string();

    let scanner = transaction.query_opt(
        "SELECT id FROM scanner_info WHERE scanner_id = $1 AND runtime_token_hash = $2 AND is_enable = true;",
        &[&scanner_id, &token_hash]
    ).await.map_err(scanner_result_database_error)?;

    if scanner.is_none() {
        return Err(SaveScannerResultsError::ScannerUnauthorized);
    }

    let task_row = transaction
        .query_opt(
            "SELECT t.id AS task_id, t.user_id, e.id AS execution_id, e.execution_id AS public_execution_id, \
             e.execution_status, e.task_start_time, t.task_source, COALESCE(s.name, e.assigned_scanner_id) AS scanner_name \
             FROM scan_task t JOIN scan_task_execution e ON e.task_id = t.id \
             LEFT JOIN scanner_info s ON s.scanner_id = e.assigned_scanner_id \
             WHERE t.task_id = $1 AND e.assigned_scanner_id = $2 \
             AND e.execution_status IN ('running', 'succeeded') LIMIT 1 FOR UPDATE OF e;",
            &[&upload.task_id.to_string(), &scanner_id],
        )
        .await
        .map_err(scanner_result_database_error)?;

    let already_succeeded = task_row
        .as_ref()
        .is_some_and(|row| row.get::<_, String>("execution_status") == "succeeded");

    let (
        task_db_id,
        user_id,
        execution_db_id,
        public_execution_id,
        task_start_time,
        task_source,
        scanner_name,
    ): (i32, i32, i32, String, Option<i64>, String, Option<String>) = match task_row {
        Some(row) => (
            row.get("task_id"),
            row.get("user_id"),
            row.get("execution_id"),
            row.get("public_execution_id"),
            row.get("task_start_time"),
            row.get("task_source"),
            row.get("scanner_name"),
        ),
        None => return Err(SaveScannerResultsError::TaskNotFound),
    };

    let (upload_id, batch_index, is_final) = if is_typed {
        (
            upload.upload_id.expect("validated above").to_string(),
            i32::try_from(upload.batch_index.expect("validated above")).map_err(|_| {
                SaveScannerResultsError::InvalidUpload("batch_index is too large".into())
            })?,
            upload.is_final.expect("validated above"),
        )
    } else {
        (public_execution_id.clone(), 0, true)
    };
    let batch_context = ScanBatchContext {
        task_id: upload.task_id.to_string(),
        execution_id: public_execution_id.clone(),
        user_id,
        task_source: task_source.clone(),
        scanner_id: scanner_id.clone(),
        scanner_name: scanner_name.clone(),
        upload_id: upload_id.clone(),
        batch_index,
        is_final,
    };
    let sidecar_upload_id = if is_typed {
        upload.upload_id.map(dns_sidecar_upload_id)
    } else {
        None
    };
    let sidecar_identity = sidecar_upload_id.map(|id| id.to_string());
    let mut allowed_upload_ids = vec![upload_id.clone()];
    allowed_upload_ids.extend(sidecar_identity.iter().cloned());
    validate_execution_upload_ids(&transaction, execution_db_id, &allowed_upload_ids).await?;
    // Older servers may have committed the DNS child before creating the primary
    // receipt. Validate that child first so a changed retry cannot reserve (and
    // poison) the primary identity or silently drop already persisted DNS data.
    if let Some(sidecar) = &sidecar_identity
        && let Some(existing) = transaction
            .query_opt(
                "SELECT is_final, observation_count, payload_checksum FROM scan_result_batch \
             WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3;",
                &[&execution_db_id, sidecar, &batch_index],
            )
            .await
            .map_err(scanner_result_database_error)?
    {
        let observations = dns_upload
            .observations
            .iter()
            .filter_map(|item| match item {
                ScannerObservation::Dns { observation } => Some(observation),
                _ => None,
            })
            .collect::<Vec<_>>();
        let expected = dns_batch_payload_checksum(
            &public_execution_id,
            sidecar,
            batch_index,
            false,
            &observations,
        )?;
        let existing_checksum: Option<String> = existing.get("payload_checksum");
        if observations.is_empty()
            || existing.get::<_, bool>("is_final")
            || existing.get::<_, i32>("observation_count") as usize != observations.len()
            || existing_checksum.as_deref() != Some(expected.as_str())
        {
            return Err(SaveScannerResultsError::BatchPayloadConflict {
                execution_id: execution_db_id,
                upload_id: upload_id.clone(),
                batch_index,
                content_kind: "DNS",
                expected_checksum: existing_checksum,
                received_checksum: expected,
            });
        }
    }
    if is_final {
        let sequence = transaction
            .query_one(
                "SELECT COUNT(*) FILTER (WHERE batch_index < $3 AND storage_backend <> 'pending')::BIGINT AS prior_count, \
                    MIN(batch_index) FILTER (WHERE batch_index < $3) AS first_prior, \
                    MAX(batch_index) FILTER (WHERE batch_index < $3) AS last_prior, \
                    COUNT(*) FILTER (WHERE batch_index > $3)::BIGINT AS later_count, \
                    COUNT(*) FILTER (WHERE is_final)::BIGINT AS final_count, \
                    BOOL_OR(is_final) FILTER (WHERE batch_index = $3) AS current_is_final \
                 FROM scan_result_batch WHERE execution_id = $1 AND upload_id = $2;",
                &[&execution_db_id, &upload_id, &batch_index],
            )
            .await
            .map_err(scanner_result_database_error)?;
        let prior_count: i64 = sequence.get("prior_count");
        let first_prior: Option<i32> = sequence.get("first_prior");
        let last_prior: Option<i32> = sequence.get("last_prior");
        let later_count: i64 = sequence.get("later_count");
        let final_count: i64 = sequence.get("final_count");
        let current_is_final: Option<bool> = sequence.get("current_is_final");
        let prior_sequence_valid = if batch_index == 0 {
            prior_count == 0 && first_prior.is_none() && last_prior.is_none()
        } else {
            prior_count == i64::from(batch_index)
                && first_prior == Some(0)
                && last_prior == Some(batch_index - 1)
        };
        let existing_final_valid = match current_is_final {
            Some(true) => final_count == 1,
            Some(false) => false,
            None => final_count == 0,
        };
        if !prior_sequence_valid || later_count != 0 || !existing_final_valid {
            return Err(SaveScannerResultsError::NonContiguousFinalBatch {
                execution_id: execution_db_id,
                upload_id: upload_id.clone(),
                batch_index,
                content_kind: "scan result",
            });
        }
    }
    let observation_count = i32::try_from(normalized_observations.len()).map_err(|_| {
        SaveScannerResultsError::ObservationLimitExceeded {
            actual: normalized_observations.len(),
            limit: i32::MAX as usize,
        }
    })?;
    let protocol_version = i16::try_from(upload.protocol_version).expect("validated above");
    let mut observation_rows = Vec::with_capacity(normalized_observations.len());
    let mut ip_intel_cache = HashMap::new();
    let fallback_observed_at = task_start_time.unwrap_or_else(get_unix_epoch_ms);
    for observation in &normalized_observations {
        let (ip_address, ip_network, parsed_ip) = scan_observation_addresses(&observation.ip)
            .map_err(|source_error| SaveScannerResultsError::InvalidIp {
                ip: observation.ip.clone(),
                source: source_error,
            })?;
        let observation_key = serde_json::to_string(&serde_json::json!([
            observation.kind,
            ip_network,
            observation.port,
            observation.protocol,
            observation.service,
            observation.source,
            observation
                .data
                .as_ref()
                .and_then(|value| value.get("template_id")),
            observation
                .data
                .as_ref()
                .and_then(|value| value.get("matcher_name")),
            observation
                .data
                .as_ref()
                .and_then(|value| value.get("matched_at"))
        ]))
        .map_err(scanner_result_database_error)?;
        let endpoint_id = openssl::sha::sha256(
            format!(
                "{}\0{}\0{}",
                public_execution_id, ip_network, observation.port
            )
            .as_bytes(),
        )
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
        let intel = ip_intel_cache
            .entry(parsed_ip)
            .or_insert_with(|| maxmind.lookup(parsed_ip))
            .clone();
        let search_content = search_content::extract_search_content(observation.data.as_ref());
        let observed_at = observation.observed_at.unwrap_or(fallback_observed_at);
        if observed_at <= 0 || observed_at > get_unix_epoch_ms().saturating_add(86_400_000) {
            return Err(SaveScannerResultsError::InvalidUpload(
                "observed_at must be a Unix epoch millisecond value no more than 24 hours in the future".into(),
            ));
        }
        observation_rows.push(serde_json::json!({
            "observation_key": observation_key,
            "endpoint_id": endpoint_id,
            "kind": observation.kind,
            // `ip` fields reject CIDR strings. Preserve the network separately
            // as `ip_range`, including /32 and /128 single-host networks.
            "ip_address": ip_address,
            "ip_network": ip_network,
            "port": i32::from(observation.port),
            "protocol": observation.protocol,
            "service": observation.service,
            "banner": observation.banner,
            "title": search_content.title,
            "http_body": search_content.http_body,
            "http_body_truncated": search_content.http_body_truncated,
            "tls_mode": search_content.tls_mode,
            "tls_version": search_content.tls_version,
            "tls_cipher_suite": search_content.tls_cipher_suite,
            "tls_subject": search_content.tls_subject,
            "tls_issuer": search_content.tls_issuer,
            "tls_names": search_content.tls_names,
            "tls_serial_number": search_content.tls_serial_number,
            "tls_not_before": search_content.tls_not_before,
            "tls_not_after": search_content.tls_not_after,
            "tls_fingerprint_sha256": search_content.tls_fingerprint_sha256,
            "tls_self_signed": search_content.tls_self_signed,
            "search_content_extracted": true,
            "source": observation.source,
            "data": observation.data,
            "observed_at": observed_at,
            "asn": intel.asn,
            "isp": intel.isp,
            "as_org": intel.as_org,
            "country_code": intel.country_code,
            "country_name": intel.country_name,
            "region_name": intel.region_name,
            "city_name": intel.city_name,
            "latitude": intel.latitude,
            "longitude": intel.longitude,
        }));
    }
    if !observation_rows.is_empty() {
        let addresses = observation_rows
            .iter()
            .filter_map(|row| {
                row.get("ip_network")
                    .or_else(|| row.get("ip_address"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let tag_rows = transaction
            .query(
                "SELECT host(assignment.ip_address) AS ip, JSONB_AGG(JSONB_BUILD_OBJECT( \
                    'id', tag.id, 'name', tag.name, 'kind', tag.kind, 'description', tag.description, \
                    'category_id', category.id, 'category_name', category.name) \
                    ORDER BY category.sort_order, LOWER(category.name), tag.id) AS tags \
                 FROM asset_ip_tag assignment JOIN asset_tag tag ON tag.id = assignment.tag_id \
                 JOIN asset_tag_category category ON category.id = tag.category_id \
                 WHERE tag.is_active AND category.is_active AND assignment.ip_address IN \
                    (SELECT address::INET FROM UNNEST($1::TEXT[]) address) \
                 GROUP BY assignment.ip_address;",
                &[&addresses],
            )
            .await
            .map_err(scanner_result_database_error)?;
        let tags_by_ip = tag_rows
            .into_iter()
            .map(|row| (row.get::<_, String>("ip"), row.get::<_, Value>("tags")))
            .collect::<HashMap<_, _>>();
        for row in &mut observation_rows {
            let tags = row
                .get("ip_address")
                .and_then(Value::as_str)
                .and_then(|ip| tags_by_ip.get(ip))
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new()));
            row.as_object_mut()
                .expect("observation row is object")
                .insert("tags".to_owned(), tags);
        }
    }
    let storage_backend = "elasticsearch";
    let (transaction, es_execution_summary) = {
        let es_checksum = scan_batch_payload_checksum(&batch_context, &observation_rows)
            .map_err(SaveScannerResultsError::Storage)?;
        let expected_checksum = if dns_upload.observations.is_empty() {
            es_checksum.clone()
        } else {
            let content = serde_json::to_vec(&serde_json::json!({
                "endpoint_checksum": es_checksum,
                "dns_observations": dns_upload.observations.iter().filter_map(|item| match item {
                    ScannerObservation::Dns { observation } => Some(observation),
                    _ => None,
                }).collect::<Vec<_>>(),
            }))
            .map_err(scanner_result_database_error)?;
            openssl::sha::sha256(&content)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        };
        if let Some(existing) = transaction
            .query_opt(
                "SELECT is_final, observation_count, payload_checksum, storage_backend FROM scan_result_batch \
                 WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3;",
                &[&execution_db_id, &upload_id, &batch_index],
            )
            .await
            .map_err(scanner_result_database_error)?
        {
            let existing_checksum: Option<String> = existing.get("payload_checksum");
            if existing.get::<_, bool>("is_final") != is_final
                || existing.get::<_, i32>("observation_count") != observation_count
                || existing_checksum
                    .as_deref()
                    .is_none_or(|checksum| checksum != expected_checksum)
            {
                return Err(SaveScannerResultsError::BatchPayloadConflict {
                    execution_id: execution_db_id,
                    upload_id: upload_id.clone(),
                    batch_index,
                    content_kind: "scan result",
                    expected_checksum: existing_checksum,
                    received_checksum: expected_checksum.clone(),
                });
            }
            if existing.get::<_, String>("storage_backend") != "pending" {
                transaction
                    .commit()
                    .await
                    .map_err(scanner_result_database_error)?;
                drop(client);
                return Ok(0);
            }
        } else {
            if already_succeeded {
                return Err(SaveScannerResultsError::CompletedExecutionNewBatch {
                    execution_id: execution_db_id,
                    upload_id: upload_id.clone(),
                    batch_index,
                });
            }
            transaction
                .execute(
                    "INSERT INTO scan_result_batch (execution_id, upload_id, batch_index, is_final, observation_count, \
                     protocol_version, payload_checksum, storage_backend, storage_references) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', '[]'::JSONB);",
                    &[
                        &execution_db_id,
                        &upload_id,
                        &batch_index,
                        &is_final,
                        &observation_count,
                        &protocol_version,
                        &expected_checksum,
                    ],
                )
                .await
                .map_err(scanner_result_database_error)?;
        }
        // 关键边界：任务行锁和连接在任何 Elasticsearch await 之前释放。
        transaction
            .commit()
            .await
            .map_err(scanner_result_database_error)?;
        drop(client);
        if !dns_upload.observations.is_empty() {
            dns_upload.upload_id = sidecar_upload_id;
            dns_upload.is_final = Some(false);
            save_dns_scanner_results(
                pool,
                elasticsearch,
                dns_follow_up,
                &dns_upload,
                token,
                token_pepper,
                upload.upload_id,
            )
            .await?;
        }
        let result = elasticsearch
            .persist_scan_batch(&batch_context, &observation_rows)
            .await
            .map_err(SaveScannerResultsError::Storage)?;
        debug_assert_eq!(result.payload_checksum, es_checksum);
        let storage_references =
            Value::Array(result.indices.into_iter().map(Value::String).collect());
        client = db::acquire_write_connection(pool, "confirm_scan_batch")
            .await
            .map_err(scanner_result_database_error)?;
        let transaction = client
            .transaction()
            .await
            .map_err(scanner_result_database_error)?;
        transaction
            .batch_execute(
                "SET LOCAL lock_timeout = '1500ms'; SET LOCAL statement_timeout = '15s';",
            )
            .await
            .map_err(scanner_result_database_error)?;
        let current_execution = transaction
            .query_one("SELECT execution_status, assigned_scanner_id FROM scan_task_execution WHERE id = $1 FOR UPDATE", &[&execution_db_id])
            .await.map_err(scanner_result_database_error)?;
        if !matches!(
            current_execution
                .get::<_, String>("execution_status")
                .as_str(),
            "running" | "succeeded"
        ) || current_execution
            .get::<_, Option<String>>("assigned_scanner_id")
            .as_deref()
            != Some(scanner_id.as_str())
        {
            return Err(SaveScannerResultsError::TaskNotOwned);
        }
        let receipt = transaction
            .query_opt(
                "UPDATE scan_result_batch SET storage_backend = $4, storage_references = $5 \
                 WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3 \
                 AND storage_backend = 'pending' RETURNING id;",
                &[
                    &execution_db_id,
                    &upload_id,
                    &batch_index,
                    &storage_backend,
                    &storage_references,
                ],
            )
            .await
            .map_err(scanner_result_database_error)?;
        let Some(_) = receipt else {
            transaction
                .commit()
                .await
                .map_err(scanner_result_database_error)?;
            return Ok(0);
        };
        (transaction, result.execution_summary)
    };
    let saved = normalized_observations.len() + dns_upload.observations.len();

    if !is_typed || upload.is_final == Some(true) {
        let batch_sequence = transaction
            .query_one(
                "SELECT COUNT(*)::BIGINT AS count, MIN(batch_index) AS first_batch, \
                    MAX(batch_index) AS last_batch, \
                    COUNT(*) FILTER (WHERE is_final)::BIGINT AS final_count \
                 FROM scan_result_batch WHERE execution_id = $1 AND upload_id = $2;",
                &[&execution_db_id, &upload_id],
            )
            .await
            .map_err(scanner_result_database_error)?;
        let count: i64 = batch_sequence.get("count");
        let first_batch: Option<i32> = batch_sequence.get("first_batch");
        let last_batch: Option<i32> = batch_sequence.get("last_batch");
        let final_count: i64 = batch_sequence.get("final_count");
        if first_batch != Some(0)
            || last_batch != Some(batch_index)
            || count != i64::from(batch_index) + 1
            || final_count != 1
        {
            return Err(SaveScannerResultsError::NonContiguousFinalBatch {
                execution_id: execution_db_id,
                upload_id: upload_id.clone(),
                batch_index,
                content_kind: "scan result",
            });
        }
        let execution_summary = {
            es_execution_summary.ok_or_else(|| {
                SaveScannerResultsError::Storage(
                    "final batch did not produce execution counters".into(),
                )
            })?
        };
        let dns_summary = transaction.query_one(
            "SELECT COALESCE(SUM(d.observation_count), 0)::BIGINT AS count, \
             COUNT(*) FILTER (WHERE d.storage_backend = 'pending' OR d.is_final \
                 OR p.id IS NULL OR p.storage_backend = 'pending')::BIGINT AS incomplete \
             FROM scan_result_batch d LEFT JOIN scan_result_batch p \
                 ON p.execution_id = d.execution_id AND p.upload_id = $3 AND p.batch_index = d.batch_index \
             WHERE d.execution_id = $1 AND d.upload_id = $2;",
            &[&execution_db_id, &sidecar_identity, &upload_id],
        ).await.map_err(scanner_result_database_error)?;
        if dns_summary.get::<_, i64>("incomplete") != 0 {
            return Err(SaveScannerResultsError::InvalidUpload(
                "final batch requires completed DNS children with matching primary batches".into(),
            ));
        }
        let total_observation_count =
            execution_summary.observation_count + dns_summary.get::<_, i64>("count");
        transaction
            .execute(
                "UPDATE scan_task_execution SET execution_status = 'succeeded', task_end_time = $1, \
                 lease_expires_at = NULL, failure_reason = NULL, cancel_requested = false, \
                 maintenance_hold = FALSE, maintenance_hold_until = NULL, \
                 result_ip_count = $3, result_port_count = $4, result_observation_count = $5 WHERE id = $2;",
                &[
                    &get_unix_epoch_ms(),
                    &execution_db_id,
                    &execution_summary.ip_count,
                    &execution_summary.port_count,
                    &total_observation_count,
                ],
            )
            .await
            .map_err(scanner_result_database_error)?;
        // New servers enqueue analytics in the same transaction as successful completion.
        // The analytics worker still reconciles older completed executions during upgrades.
        transaction
            .execute(
                "INSERT INTO analytics_outbox (execution_id, status, available_at, locked_at, completed_at, last_error) \
                 VALUES ($1, 'pending', NOW(), NULL, NULL, NULL) \
                 ON CONFLICT (execution_id) DO UPDATE SET status = 'pending', available_at = NOW(), \
                    locked_at = NULL, completed_at = NULL, last_error = NULL, updated_at = NOW();",
                &[&execution_db_id],
            )
            .await
            .map_err(scanner_result_database_error)?;

        {
            transaction
                .execute(
                    "INSERT INTO scan_projection_outbox (execution_id, attempts, available_at, processed_at, last_error) \
                     VALUES ($1, 0, NOW(), NULL, NULL) ON CONFLICT (execution_id) DO NOTHING;",
                    &[&execution_db_id],
                )
                .await
                .map_err(scanner_result_database_error)?;
        }
        refresh_task_aggregate(&transaction, task_db_id)
            .await
            .map_err(scanner_result_database_error)?;
        target_generated::search::record_success(&transaction, task_db_id)
            .await
            .map_err(scanner_result_database_error)?;
    }

    transaction
        .commit()
        .await
        .map_err(scanner_result_database_error)?;
    drop(client);
    if is_final {
        elasticsearch.notify_projection_worker();
    }
    Ok(saved)
}

pub async fn refresh_task_aggregate(
    transaction: &tokio_postgres::Transaction<'_>,
    task_db_id: i32,
) -> Result<(), tokio_postgres::Error> {
    transaction.execute(
        "WITH aggregate AS (SELECT \
            COUNT(*)::INT AS total, \
            COUNT(*) FILTER (WHERE execution_status = 'pending')::INT AS pending, \
            COUNT(*) FILTER (WHERE execution_status = 'running')::INT AS running, \
            COUNT(*) FILTER (WHERE execution_status = 'succeeded')::INT AS succeeded, \
            COUNT(*) FILTER (WHERE execution_status = 'failed')::INT AS failed, \
            COUNT(*) FILTER (WHERE execution_status = 'cancelled')::INT AS cancelled, \
            MIN(task_start_time) AS started_at, MAX(task_end_time) AS ended_at, \
            SUM(attempt_count)::INT AS attempts, BOOL_OR(cancel_requested) AS cancelling, \
            CASE WHEN COUNT(*) = 1 THEN MAX(assigned_scanner_id) ELSE NULL END AS scanner_id, \
            STRING_AGG(CASE WHEN failure_reason IS NOT NULL THEN \
                COALESCE(assigned_scanner_id, requested_scanner_id, 'unassigned') || ': ' || failure_reason END, E'\\n') AS failures \
          FROM scan_task_execution WHERE task_id = $1 AND execution_status <> 'superseded') \
         UPDATE scan_task t SET \
           task_status = CASE WHEN a.running > 0 THEN 'running' WHEN a.pending > 0 THEN 'pending' \
             WHEN a.succeeded = a.total THEN 'succeeded' WHEN a.failed = a.total THEN 'failed' \
             WHEN a.cancelled = a.total THEN 'cancelled' ELSE 'partial' END, \
           task_start_time = a.started_at, \
           task_end_time = CASE WHEN a.pending = 0 AND a.running = 0 THEN a.ended_at ELSE NULL END, \
           attempt_count = a.attempts, assigned_scanner_id = a.scanner_id, \
           lease_expires_at = NULL, failure_reason = a.failures, cancel_requested = a.cancelling \
         FROM aggregate a WHERE t.id = $1;",
        &[&task_db_id],
    ).await?;
    Ok(())
}

fn assigned_task_from_row(
    row: &tokio_postgres::Row,
    lease_expires_at_ms: i64,
) -> Result<ApplyTask, ApplyTaskError> {
    let task_id = Uuid::parse_str(row.get::<_, String>("task_id").as_str())
        .map_err(apply_task_database_error)?;
    Ok(ApplyTask {
        user_id: row.get("user_id"),
        task_id,
        task_target: row.get("task_target"),
        task_port: row.get("task_port"),
        address_family: row.get("address_family"),
        scan_plan: row.get("scan_plan"),
        dns_resolvers: row.get("dns_resolvers"),
        lease_expires_at_ms,
        lease_ttl_ms: TASK_LEASE_MS,
    })
}

/// Return an execution that can safely accept the caller's next upload.
///
/// A scanner with a durable upload may continue only that upload (plus its
/// deterministic DNS sidecar). A scanner without a durable upload is starting
/// a fresh attempt, so any existing receipt makes the old execution immutable.
/// The caller must already hold a row lock for `execution_id`.
async fn execution_for_upload_attempt(
    transaction: &tokio_postgres::Transaction<'_>,
    execution_id: i32,
    expected_upload_id: Option<Uuid>,
    now: i64,
    scanner_id: &str,
    public_task_id: &str,
) -> Result<i32, ApplyTaskError> {
    let conflict = if let Some(upload_id) = expected_upload_id {
        let allowed_upload_ids = vec![
            upload_id.to_string(),
            dns_sidecar_upload_id(upload_id).to_string(),
        ];
        transaction
            .query_opt(
                "SELECT upload_id FROM scan_result_batch \
                 WHERE execution_id = $1 AND NOT (upload_id = ANY($2::TEXT[])) \
                 ORDER BY upload_id LIMIT 1;",
                &[&execution_id, &allowed_upload_ids],
            )
            .await
            .map_err(apply_task_database_error)?
    } else {
        transaction
            .query_opt(
                "SELECT upload_id FROM scan_result_batch \
                 WHERE execution_id = $1 ORDER BY upload_id LIMIT 1;",
                &[&execution_id],
            )
            .await
            .map_err(apply_task_database_error)?
    };
    let Some(conflict) = conflict else {
        return Ok(execution_id);
    };

    let conflicting_upload_id: String = conflict.get("upload_id");
    let execution = transaction
        .query_one(
            "SELECT task_id, requested_scanner_id, recovery_failure_count FROM scan_task_execution WHERE id = $1;",
            &[&execution_id],
        )
        .await
        .map_err(apply_task_database_error)?;
    let task_db_id: i32 = execution.get("task_id");
    let requested_scanner_id: Option<String> = execution.get("requested_scanner_id");
    let recovery_failure_count: i32 = execution.get("recovery_failure_count");
    let reason = if expected_upload_id.is_some() {
        "superseded after durable upload identity changed"
    } else {
        "superseded before a fresh upload attempt"
    };
    transaction
        .execute(
            "UPDATE scan_task_execution SET execution_status = 'superseded', \
             requested_scanner_id = NULL, lease_expires_at = NULL, task_end_time = $2, \
             cancel_requested = false, maintenance_hold = FALSE, maintenance_hold_until = NULL, \
             failure_reason = $3 WHERE id = $1;",
            &[&execution_id, &now, &reason],
        )
        .await
        .map_err(apply_task_database_error)?;
    let replacement_public_id = Uuid::now_v7().to_string();
    let replacement = transaction
        .query_one(
            "INSERT INTO scan_task_execution (execution_id, task_id, requested_scanner_id, recovery_failure_count) \
             VALUES ($1, $2, $3, $4) RETURNING id;",
            &[&replacement_public_id, &task_db_id, &requested_scanner_id, &recovery_failure_count],
        )
        .await
        .map_err(apply_task_database_error)?;
    let replacement_id: i32 = replacement.get("id");
    info!(
        event = "ROTATE-UPLOAD-EXECUTION",
        scanner_id,
        task_id = public_task_id,
        upload_id = ?expected_upload_id,
        conflicting_upload_id,
        retired_execution_id = execution_id,
        replacement_execution_id = replacement_id,
        replacement_public_execution_id = replacement_public_id,
        reason,
        "retired an execution that cannot accept the scanner's next upload"
    );
    Ok(replacement_id)
}

/// Return and renew a running task already owned by this scanner.
///
/// When `task_id` is supplied, only that exact task is considered. This is used
/// to reconcile a durable local upload before any new work is requested.
pub async fn recover_scanner_task(
    pool: &deadpool_postgres::Pool,
    scanner_id: Uuid,
    task_id: Option<Uuid>,
    upload_id: Option<Uuid>,
    token: &str,
    token_pepper: &str,
) -> Result<ApplyTask, ApplyTaskError> {
    recover_scanner_task_with_failure(
        pool,
        scanner_id,
        task_id,
        upload_id,
        None,
        token,
        token_pepper,
    )
    .await
}

#[derive(Debug, Clone, Copy)]
pub struct RecoveryFailureReport {
    pub task_id: Uuid,
    pub count: u32,
}

pub async fn recover_scanner_task_with_failure(
    pool: &deadpool_postgres::Pool,
    scanner_id: Uuid,
    task_id: Option<Uuid>,
    upload_id: Option<Uuid>,
    failure: Option<RecoveryFailureReport>,
    token: &str,
    token_pepper: &str,
) -> Result<ApplyTask, ApplyTaskError> {
    let mut connection = pool.get().await.map_err(apply_task_database_error)?;
    let transaction = connection
        .transaction()
        .await
        .map_err(apply_task_database_error)?;
    let token_hash = hash_scanner_token(token, token_pepper).map_err(apply_task_database_error)?;
    validate_scanner_credentials_with_client(&transaction, scanner_id, &token_hash).await?;

    let scanner_id = scanner_id.to_string();
    // Serialize recovery and claiming for one scanner so two requests cannot
    // assign different work to the same scanner concurrently.
    transaction
        .query_one(
            "SELECT id FROM scanner_info WHERE scanner_id = $1 FOR UPDATE;",
            &[&scanner_id],
        )
        .await
        .map_err(apply_task_database_error)?;

    if let Some(failure) = failure {
        // The client reports a durable cumulative count; repeated recovery requests
        // (including a lost HTTP response) must never count the same failure twice.
        let now = get_unix_epoch_ms();
        let count = i32::try_from(failure.count.min(3)).unwrap_or(3);
        let changed = transaction.query(
            "UPDATE scan_task_execution SET recovery_failure_count=GREATEST(recovery_failure_count,$1), \
             execution_status=CASE WHEN GREATEST(recovery_failure_count,$1)>=3 THEN 'failed' ELSE execution_status END, \
             task_end_time=CASE WHEN GREATEST(recovery_failure_count,$1)>=3 THEN $2 ELSE task_end_time END, \
             lease_expires_at=CASE WHEN GREATEST(recovery_failure_count,$1)>=3 THEN NULL ELSE lease_expires_at END, \
             failure_reason=CASE WHEN GREATEST(recovery_failure_count,$1)>=3 THEN 'scanner recovery limit exceeded' ELSE failure_reason END \
             WHERE task_id=(SELECT id FROM scan_task WHERE task_id=$3) AND assigned_scanner_id=$4 \
             AND execution_status='running' RETURNING task_id;",
            &[&count,&now,&failure.task_id.to_string(),&scanner_id]).await.map_err(apply_task_database_error)?;
        for row in changed {
            refresh_task_aggregate(&transaction, row.get("task_id"))
                .await
                .map_err(apply_task_database_error)?;
        }
        info!(event="RECOVERY-FAILURE-REPORTED",scanner_id,task_id=%failure.task_id,count,
            "recorded cumulative scanner recovery failures");
    }

    let requested_task_id = task_id.map(|value| value.to_string());
    let now = get_unix_epoch_ms();
    let cancelled = transaction
        .query(
            "UPDATE scan_task_execution e SET execution_status = 'cancelled', task_end_time = $1, \
             lease_expires_at = NULL, cancel_requested = false FROM scan_task t \
             WHERE e.task_id = t.id AND e.execution_status = 'running' \
               AND e.assigned_scanner_id = $2 AND e.cancel_requested = true \
               AND ($3::TEXT IS NULL OR t.task_id = $3) RETURNING e.task_id;",
            &[&now, &scanner_id, &requested_task_id],
        )
        .await
        .map_err(apply_task_database_error)?;
    for task_id in cancelled
        .iter()
        .map(|row| row.get::<_, i32>("task_id"))
        .collect::<std::collections::HashSet<_>>()
    {
        refresh_task_aggregate(&transaction, task_id)
            .await
            .map_err(apply_task_database_error)?;
    }

    let row = transaction
        .query_opt(
            "SELECT t.id AS task_pk, e.id AS execution_pk, e.execution_status, t.user_id, t.task_id, \
             CASE WHEN t.task_kind = 'dns' THEN t.dns_targets ELSE t.task_target::text[] END AS task_target, \
             t.task_port, t.address_family, t.scan_plan, t.dns_resolvers \
             FROM scan_task_execution e JOIN scan_task t ON t.id = e.task_id \
             JOIN scanner_info s ON s.scanner_id = $1 \
             WHERE e.cancel_requested = false AND ( \
                 (e.execution_status = 'running' AND e.assigned_scanner_id = $1 \
                  AND ($2::TEXT IS NULL OR t.task_id = $2)) \
                 OR ($2::TEXT IS NOT NULL AND t.task_id = $2 AND e.execution_status = 'pending' \
                     AND e.assigned_scanner_id IS NULL AND s.accepting_tasks \
                     AND (e.requested_scanner_id IS NULL OR e.requested_scanner_id = $1) \
                     AND ((t.address_family = 'ipv4' AND s.supports_ipv4 AND s.ipv4_ready) \
                       OR (t.address_family = 'ipv6' AND s.supports_ipv6 AND s.ipv6_ready)) \
                     AND (t.scan_profile = 'legacy' OR s.scan_capabilities->'profiles' ? t.scan_profile) \
                     AND (jsonb_array_length(t.dns_resolvers) = 0 \
                       OR COALESCE((s.scan_capabilities->>'explicit_dns_resolvers')::BOOLEAN, FALSE)))) \
             ORDER BY CASE WHEN e.execution_status = 'running' THEN 0 ELSE 1 END, \
                 e.task_start_time NULLS FIRST, e.id \
             FOR UPDATE OF e SKIP LOCKED LIMIT 1;",
            &[&scanner_id, &requested_task_id],
        )
        .await
        .map_err(apply_task_database_error)?;

    let Some(row) = row else {
        transaction
            .commit()
            .await
            .map_err(apply_task_database_error)?;
        return Err(ApplyTaskError::NoTask);
    };

    let execution_pk = execution_for_upload_attempt(
        &transaction,
        row.get("execution_pk"),
        upload_id,
        now,
        &scanner_id,
        row.get("task_id"),
    )
    .await?;
    let lease_expires_at = now + TASK_LEASE_MS;
    transaction
        .execute(
            "UPDATE scan_task_execution SET execution_status = 'running', assigned_scanner_id = $1, \
             task_start_time = COALESCE(task_start_time, $2::BIGINT), task_end_time = NULL, \
             lease_expires_at = CASE WHEN maintenance_hold THEN NULL ELSE $3::BIGINT END, \
             attempt_count = attempt_count + CASE WHEN execution_status = 'pending' THEN 1 ELSE 0 END, \
             failure_reason = NULL WHERE id = $4;",
            &[
                &scanner_id,
                &now,
                &lease_expires_at,
                &execution_pk,
            ],
        )
        .await
        .map_err(apply_task_database_error)?;
    refresh_task_aggregate(&transaction, row.get("task_pk"))
        .await
        .map_err(apply_task_database_error)?;
    let task = assigned_task_from_row(&row, lease_expires_at)?;
    transaction
        .commit()
        .await
        .map_err(apply_task_database_error)?;
    info!(
        event = "RECOVER-TASK",
        scanner_id,
        task_id = %task.task_id,
        "scanner recovered an unfinished task"
    );
    Ok(task)
}

/// 通过该函数实现扫描器申请任务。
/// 调用方必须先清空该扫描器的未完成任务；本函数也在事务内再次强制检查。
pub async fn apply_task(
    pool: &deadpool_postgres::Pool,
    scanner_id: Uuid,
    token: &str,
    token_pepper: &str,
) -> Result<ApplyTask, ApplyTaskError> {
    let mut p = pool.get().await.map_err(apply_task_database_error)?;
    let transaction = p.transaction().await.map_err(apply_task_database_error)?;
    let token_hash = hash_scanner_token(token, token_pepper).map_err(apply_task_database_error)?;
    validate_scanner_credentials_with_client(&transaction, scanner_id, &token_hash).await?;
    let scanner_id = scanner_id.to_string();

    let cancelled = transaction
        .query(
            "/* nm:reap_cancelled_executions */ \
             WITH candidates AS ( \
                 SELECT id FROM scan_task_execution \
                 WHERE execution_status = 'running' AND cancel_requested = true \
                   AND (lease_expires_at IS NULL OR lease_expires_at < $1) \
                 ORDER BY lease_expires_at NULLS FIRST, id \
                 FOR UPDATE SKIP LOCKED LIMIT 32 \
             ) \
             UPDATE scan_task_execution e \
             SET execution_status = 'cancelled', task_end_time = $1, \
                 lease_expires_at = NULL, cancel_requested = false \
             FROM candidates c WHERE e.id = c.id RETURNING e.task_id;",
            &[&get_unix_epoch_ms()],
        )
        .await
        .map_err(apply_task_database_error)?;
    let cancelled_tasks: std::collections::HashSet<i32> =
        cancelled.iter().map(|row| row.get("task_id")).collect();
    for task_id in cancelled_tasks {
        refresh_task_aggregate(&transaction, task_id)
            .await
            .map_err(apply_task_database_error)?;
    }

    transaction
        .query_one(
            "SELECT id FROM scanner_info WHERE scanner_id = $1 FOR UPDATE;",
            &[&scanner_id],
        )
        .await
        .map_err(apply_task_database_error)?;

    if let Some(row) = transaction
        .query_opt(
            "SELECT t.task_id FROM scan_task_execution e JOIN scan_task t ON t.id = e.task_id \
             WHERE e.execution_status = 'running' AND e.assigned_scanner_id = $1 \
             ORDER BY e.task_start_time NULLS FIRST, e.id FOR UPDATE OF e LIMIT 1;",
            &[&scanner_id],
        )
        .await
        .map_err(apply_task_database_error)?
    {
        let task_id = Uuid::parse_str(row.get::<_, String>("task_id").as_str())
            .map_err(apply_task_database_error)?;
        return Err(ApplyTaskError::UnfinishedTask(task_id));
    }

    let row = transaction
        .query_opt(
            "/* nm:claim_selected_pending */ \
             SELECT t.id AS task_pk, e.id AS execution_pk, t.user_id, t.task_id, \
             CASE WHEN t.task_kind = 'dns' THEN t.dns_targets ELSE t.task_target::text[] END AS task_target, \
             t.task_port, t.address_family, t.scan_plan, t.dns_resolvers \
         FROM scan_task_execution e \
         JOIN scan_task t ON t.id = e.task_id \
         JOIN scanner_info s ON s.scanner_id = $1 \
         WHERE s.accepting_tasks AND e.execution_status = 'pending' AND e.requested_scanner_id = $1 \
           AND t.task_status IN ('pending', 'running') \
           AND ((t.address_family = 'ipv4' AND s.supports_ipv4 AND s.ipv4_ready) \
             OR (t.address_family = 'ipv6' AND s.supports_ipv6 AND s.ipv6_ready)) \
           AND (t.scan_profile = 'legacy' OR s.scan_capabilities->'profiles' ? t.scan_profile) \
           AND (jsonb_array_length(t.dns_resolvers) = 0 \
             OR COALESCE((s.scan_capabilities->>'explicit_dns_resolvers')::BOOLEAN, FALSE)) \
         ORDER BY t.task_level DESC, t.task_create_time, t.id, e.id \
         FOR UPDATE OF e SKIP LOCKED LIMIT 1;",
            &[&scanner_id],
        )
        .await
        .map_err(apply_task_database_error)?;
    let row = if row.is_some() {
        row
    } else {
        transaction
            .query_opt(
                "/* nm:claim_general */ \
                 SELECT t.id AS task_pk, e.execution_pk, t.user_id, t.task_id, \
                     CASE WHEN t.task_kind = 'dns' THEN t.dns_targets ELSE t.task_target::text[] END AS task_target, \
                     t.task_port, t.address_family, t.scan_plan, t.dns_resolvers \
                 FROM scan_task t \
                 JOIN scanner_info s ON s.scanner_id = $2 \
                 JOIN LATERAL ( \
                     SELECT candidate.id AS execution_pk \
                     FROM scan_task_execution candidate \
                     WHERE candidate.task_id = t.id AND ( \
                         (candidate.execution_status = 'pending' AND candidate.requested_scanner_id IS NULL) \
                         OR (candidate.execution_status = 'running' \
                             AND candidate.maintenance_hold = FALSE \
                             AND candidate.cancel_requested = FALSE \
                             AND (candidate.lease_expires_at IS NULL OR candidate.lease_expires_at < $1) \
                             AND (candidate.requested_scanner_id IS NULL OR candidate.requested_scanner_id = $2)) \
                     ) \
                     ORDER BY candidate.id FOR UPDATE SKIP LOCKED LIMIT 1 \
                 ) e ON TRUE \
                 WHERE s.accepting_tasks AND t.task_status IN ('pending', 'running') \
                   AND ((t.address_family = 'ipv4' AND s.supports_ipv4 AND s.ipv4_ready) \
                     OR (t.address_family = 'ipv6' AND s.supports_ipv6 AND s.ipv6_ready)) \
                   AND (t.scan_profile = 'legacy' OR s.scan_capabilities->'profiles' ? t.scan_profile) \
                   AND (jsonb_array_length(t.dns_resolvers) = 0 \
                     OR COALESCE((s.scan_capabilities->>'explicit_dns_resolvers')::BOOLEAN, FALSE)) \
                 ORDER BY t.task_level DESC, t.task_create_time, t.id, e.execution_pk \
                 LIMIT 1;",
                &[&get_unix_epoch_ms(), &scanner_id],
            )
            .await
            .map_err(apply_task_database_error)?
    };

    let Some(row) = row else {
        info!(
            event = "NOTFOUND-TASK",
            path = "fn apply_task",
            message = "没有可领取的扫描任务"
        );
        transaction
            .commit()
            .await
            .map_err(apply_task_database_error)?;
        return Err(ApplyTaskError::NoTask);
    };

    let task_pk: i32 = row.get("task_pk");
    let execution_pk = execution_for_upload_attempt(
        &transaction,
        row.get("execution_pk"),
        None,
        get_unix_epoch_ms(),
        &scanner_id,
        row.get("task_id"),
    )
    .await?;
    let lease_expires_at = get_unix_epoch_ms() + TASK_LEASE_MS;
    transaction
        .execute(
            "UPDATE scan_task_execution SET task_start_time = COALESCE(task_start_time, $1::BIGINT), task_end_time = NULL, \
             execution_status = 'running', assigned_scanner_id = $2, lease_expires_at = $3::BIGINT, \
             maintenance_hold = FALSE, maintenance_hold_until = NULL, \
             attempt_count = attempt_count + 1, failure_reason = NULL WHERE id = $4;",
            &[
                &get_unix_epoch_ms(),
                &scanner_id,
                &lease_expires_at,
                &execution_pk,
            ],
        )
        .await
        .map_err(apply_task_database_error)?;
    refresh_task_aggregate(&transaction, task_pk)
        .await
        .map_err(apply_task_database_error)?;

    let apply_task = assigned_task_from_row(&row, lease_expires_at)?;

    transaction
        .commit()
        .await
        .map_err(apply_task_database_error)?;
    info!(
        event = "SEARCH-TASK",
        path = "fn apply_task",
        message = apply_task.task_id.to_string()
    );
    Ok(apply_task)
}

#[derive(Deserialize)]
pub struct ApplyTaskQuery {
    pub scannerid: Uuid,
    pub dryrun: Option<bool>,
}

#[derive(Deserialize)]
pub struct CurrentTaskQuery {
    pub scannerid: Uuid,
    pub taskid: Option<Uuid>,
    pub uploadid: Option<Uuid>,
    pub failure_taskid: Option<Uuid>,
    pub failure_count: Option<u32>,
}

/// 该函数用于退出登录
///
/// 返回一个 Result<bool> ，返回 true 代表该 token 已被正常销毁，返回 false 代表 token 本身就是无效的。
pub async fn log_out(
    session: &str,
    pool: &deadpool_postgres::Pool,
    reason: &str,
    deleted_by_user_id: Option<i32>,
) -> Result<bool, Box<dyn std::error::Error>> {
    let c = pool.get().await?;
    if let Some(tmp_r) = c
        .query_opt(
            "UPDATE session SET is_enable = FALSE, deleted_at = NOW(), \
             deletion_reason = $2, deleted_by_user_id = $3 \
             WHERE token = $1 AND is_enable = TRUE AND deleted_at IS NULL RETURNING id;",
            &[&session, &reason, &deleted_by_user_id],
        )
        .await?
    {
        info!(
            event = "UserLogout",
            path = "fn log_out",
            message = "用户已退出登录"
        );
        let t_l = tmp_r.len();
        if t_l != 1 {
            error!(
                event = "LogoutSessionShapeError",
                operation = "disable_login_session",
                error_kind = "data_integrity",
                error_code = "logout_session_return_shape_invalid",
                error_message = "logout update returned an unexpected column count",
                retryable = false,
                outcome = "session_disabled_with_unexpected_response",
                deleted_by_user_id = ?deleted_by_user_id,
                deletion_reason = reason,
                returned_column_count = t_l,
            );
        }
        Ok(true)
    } else {
        info!(
            event = "TokenInvaild",
            path = "fn log_out",
            message = "Token 无效"
        );
        Ok(false)
    }
}

/// 该枚举定义了权限，其中系统权限最高，该级别的用户由初始化数据库时创建，且该权限的用户无法查看其他用户的数据，该权限主要用于系统自动创建的扫描任务
/// Administrator 为管理员权限，该权限可以查看所有的任务
/// 使用枚举时需要传入一个用户id
pub enum Permission {
    Administrator(i32),
    Users(i32),
}

/// 表示单个任务条目
#[derive(Serialize)]
pub struct TaskItem {
    pub task_id: String,
    pub task_target: Vec<String>,
    pub task_kind: String,
    pub task_initiator: String,
    pub task_port: String,
    pub task_create_time: i64,
    pub task_level: i32,
    pub scanner_id: Option<String>,
    pub task_status: String,
    pub lease_expires_at: Option<i64>,
    pub attempt_count: i32,
    pub failure_reason: Option<String>,
    pub start_at: Option<i64>,
    pub end_at: Option<i64>,
    pub remarks: Option<String>,
    pub task_source: String,
    pub address_family: String,
    pub scan_profile: String,
    pub scan_plan: Value,
}

/// 表示 Json 格式的任务列表
#[derive(Serialize)]
pub struct TaskItemJson {
    pub total: i64,
    pub page_size: i64,
    pub next_cursor: Option<i32>,
    pub has_more: bool,
    pub items: Vec<TaskItem>,
}

/// 该结构体表示接收查询任务列表信息
#[derive(Deserialize)]
pub struct ReceiveTaskItemQueryInfo {
    #[serde(alias = "start")]
    pub cursor: Option<i32>,
    #[serde(alias = "count")]
    pub limit: Option<i64>,
    pub include_system: Option<bool>,
    pub task_id: Option<String>,
    pub target: Option<String>,
    pub status: Option<String>,
    pub operator: Option<String>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub scanner_id: Option<String>,
}

pub struct TaskListFilters {
    pub cursor: Option<i32>,
    pub limit: i64,
    pub include_system: bool,
    pub task_id: Option<String>,
    pub target: Option<String>,
    pub status: Option<String>,
    pub operator: Option<String>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub scanner_id: Option<String>,
}

pub struct TaskListPage {
    pub items: Vec<TaskItem>,
    pub total: i64,
    pub page_size: i64,
    pub next_cursor: Option<i32>,
    pub has_more: bool,
}

fn task_list_filter<'a>(
    filters: &'a TaskListFilters,
    owner_id: &'a Option<i32>,
    include_cursor: bool,
) -> (String, Vec<&'a (dyn ToSql + Sync)>) {
    let mut conditions = Vec::new();
    let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();

    if let Some(owner_id) = owner_id {
        params.push(owner_id);
        conditions.push(format!("t.user_id = ${}", params.len()));
    }
    if !filters.include_system {
        conditions.push("t.task_source <> 'automatic'".to_owned());
    }
    if let Some(task_id) = filters.task_id.as_ref() {
        params.push(task_id);
        conditions.push(format!("t.task_id ILIKE '%' || ${} || '%'", params.len()));
    }
    if let Some(target) = filters.target.as_ref() {
        params.push(target);
        conditions.push(format!(
            "(EXISTS (SELECT 1 FROM unnest(t.task_target) AS targets(target) \
                WHERE targets.target::TEXT ILIKE '%' || ${} || '%') \
              OR EXISTS (SELECT 1 FROM unnest(t.dns_targets) AS targets(target) \
                WHERE targets.target ILIKE '%' || ${} || '%'))",
            params.len(),
            params.len()
        ));
    }
    if let Some(status) = filters.status.as_ref() {
        params.push(status);
        conditions.push(format!("t.task_status = ${}", params.len()));
    }
    if let Some(operator) = filters.operator.as_ref() {
        params.push(operator);
        conditions.push(format!(
            "t.task_initiator ILIKE '%' || ${} || '%'",
            params.len()
        ));
    }
    if let Some(start_time) = filters.start_time.as_ref() {
        params.push(start_time);
        conditions.push(format!("t.task_create_time >= ${}", params.len()));
    }
    if let Some(end_time) = filters.end_time.as_ref() {
        params.push(end_time);
        conditions.push(format!("t.task_create_time <= ${}", params.len()));
    }
    if let Some(scanner_id) = filters.scanner_id.as_ref() {
        params.push(scanner_id);
        conditions.push(format!(
            "COALESCE(t.assigned_scanner_id, '') ILIKE '%' || ${} || '%'",
            params.len()
        ));
    }
    if include_cursor && let Some(cursor) = filters.cursor.as_ref() {
        params.push(cursor);
        conditions.push(format!("t.id < ${}", params.len()));
    }

    let clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };
    (clause, params)
}

#[cfg(test)]
mod task_list_filter_tests {
    use super::{TaskListFilters, task_list_filter};

    fn filters() -> TaskListFilters {
        TaskListFilters {
            cursor: None,
            limit: 20,
            include_system: true,
            task_id: None,
            target: None,
            status: None,
            operator: None,
            start_time: None,
            end_time: None,
            scanner_id: None,
        }
    }

    #[test]
    fn administrator_without_filters_has_no_where_clause() {
        let filters = filters();
        let owner_id = None;
        let (sql, params) = task_list_filter(&filters, &owner_id, false);
        assert!(sql.is_empty());
        assert!(params.is_empty());
    }

    #[test]
    fn user_filters_use_contiguous_parameters() {
        let mut filters = filters();
        filters.include_system = false;
        filters.status = Some("running".to_owned());
        filters.scanner_id = Some("scanner-a".to_owned());
        filters.cursor = Some(100);
        let owner_id = Some(7);

        let (sql, params) = task_list_filter(&filters, &owner_id, true);

        assert_eq!(params.len(), 4);
        assert!(sql.contains("t.user_id = $1"));
        assert!(sql.contains("t.task_source <> 'automatic'"));
        assert!(sql.contains("t.task_status = $2"));
        assert!(sql.contains("assigned_scanner_id, '') ILIKE '%' || $3 || '%'"));
        assert!(sql.contains("t.id < $4"));
        assert!(!sql.contains("OR"));
    }
}

/// 该函数用于获取所有的扫描任务记录，需要鉴权，普通用户只能获取到自己创建的任务，管理员则可以获取所有的
///
/// 接收多个参数，分别为
#[deprecated(note = "use get_filtered_task_page for stable pagination and server-side filters")]
pub async fn get_task_item(
    pool: &deadpool_postgres::Pool,
    s_count: i64,
    start_id: Option<i32>,
    include_system: bool,
    permissions: Permission,
) -> Result<(Vec<TaskItem>, i64, i64, i32), Box<dyn std::error::Error>> {
    let mut c = pool.get().await?;
    let s_count = s_count.clamp(1, 100);
    let transaction = c.transaction().await?;
    let expired = transaction.query(
        "UPDATE scan_task_execution SET execution_status = CASE WHEN cancel_requested THEN 'cancelled' ELSE 'pending' END, \
         assigned_scanner_id = CASE WHEN cancel_requested THEN assigned_scanner_id ELSE NULL END, lease_expires_at = NULL, \
         task_start_time = CASE WHEN cancel_requested THEN task_start_time ELSE NULL END, \
         task_end_time = CASE WHEN cancel_requested THEN (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT ELSE NULL END, \
         cancel_requested = false, failure_reason = CASE WHEN cancel_requested THEN NULL ELSE 'task lease expired' END \
         WHERE execution_status = 'running' AND lease_expires_at IS NOT NULL \
           AND lease_expires_at < (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT RETURNING task_id;", &[]).await?;
    let expired_tasks: std::collections::HashSet<i32> =
        expired.iter().map(|row| row.get("task_id")).collect();
    for task_id in expired_tasks {
        refresh_task_aggregate(&transaction, task_id).await?;
    }
    transaction.commit().await?;

    let row = match permissions {
        Permission::Administrator(_id) => {
            if let Some(st) = start_id {
                c.query(
                    "SELECT scan_task.*, CASE WHEN task_kind = 'dns' THEN dns_targets ELSE task_target::TEXT[] END AS display_targets, COUNT(*) OVER() AS total_count FROM scan_task \
                     WHERE id <= $1 AND ($2::boolean OR task_source <> 'automatic') \
                     ORDER BY id DESC LIMIT $3;",
                    &[&st, &include_system, &s_count],
                )
                .await?
            } else {
                c.query(
                    "SELECT scan_task.*, CASE WHEN task_kind = 'dns' THEN dns_targets ELSE task_target::TEXT[] END AS display_targets, COUNT(*) OVER() AS total_count FROM scan_task \
                     WHERE $1::boolean OR task_source <> 'automatic' ORDER BY id DESC LIMIT $2;",
                    &[&include_system, &s_count],
                )
                .await?
            }
        }
        Permission::Users(u_id) => {
            if let Some(st) = start_id {
                c.query(
                    "SELECT scan_task.*, CASE WHEN task_kind = 'dns' THEN dns_targets ELSE task_target::TEXT[] END AS display_targets, COUNT(*) OVER() AS total_count FROM scan_task \
                     WHERE user_id = $1 AND id <= $2 AND ($3::boolean OR task_source <> 'automatic') \
                     ORDER BY id DESC LIMIT $4;",
                    &[&u_id, &st, &include_system, &s_count]
                ).await?
            } else {
                c.query(
                    "SELECT scan_task.*, CASE WHEN task_kind = 'dns' THEN dns_targets ELSE task_target::TEXT[] END AS display_targets, COUNT(*) OVER() AS total_count FROM scan_task \
                     WHERE user_id = $1 AND ($2::boolean OR task_source <> 'automatic') \
                     ORDER BY id DESC LIMIT $3;",
                    &[&u_id, &include_system, &s_count],
                )
                .await?
            }
        }
    };

    let mut task_item_r: Vec<TaskItem> = Vec::new();
    let mut total_count_item: i64 = 0;
    let mut count: i64 = 0;
    let mut start_id: i32 = 0;

    for (index, r) in row.iter().enumerate() {
        if index == 0 {
            start_id = r.get::<_, i32>("id");
        }
        total_count_item = r.get::<_, i64>("total_count");
        let titem = TaskItem {
            task_id: r.get::<_, String>("task_id"),
            task_target: r.get("display_targets"),
            task_kind: r.get("task_kind"),
            task_initiator: r.get::<_, String>("task_initiator"),
            task_level: r.get::<_, i32>("task_level"),
            task_port: r.get::<_, String>("task_port"),
            task_create_time: r.get::<_, i64>("task_create_time"),
            scanner_id: r.get::<_, Option<String>>("assigned_scanner_id"),
            task_status: r.get::<_, String>("task_status"),
            lease_expires_at: r.get::<_, Option<i64>>("lease_expires_at"),
            attempt_count: r.get::<_, i32>("attempt_count"),
            failure_reason: r.get::<_, Option<String>>("failure_reason"),
            start_at: r.get::<_, Option<i64>>("task_start_time"),
            end_at: r.get::<_, Option<i64>>("task_end_time"),
            remarks: r.get::<_, Option<String>>("remarks"),
            task_source: r.get::<_, String>("task_source"),
            address_family: r.get::<_, String>("address_family"),
            scan_profile: r.get::<_, String>("scan_profile"),
            scan_plan: r.get::<_, Value>("scan_plan"),
        };
        task_item_r.push(titem);
        count += 1;
    }
    Ok((task_item_r, total_count_item, count, start_id))
}

/// 使用服务端筛选和排他游标分页获取任务，单次最多返回 100 条记录。
pub async fn get_filtered_task_page(
    pool: &deadpool_postgres::Pool,
    filters: &TaskListFilters,
    permissions: Permission,
) -> Result<TaskListPage, Box<dyn std::error::Error>> {
    let mut connection = pool.get().await?;
    let transaction = connection.transaction().await?;
    let expired = transaction
        .query(
            "UPDATE scan_task_execution SET execution_status = CASE WHEN cancel_requested THEN 'cancelled' ELSE 'pending' END, \
             assigned_scanner_id = CASE WHEN cancel_requested THEN assigned_scanner_id ELSE NULL END, lease_expires_at = NULL, \
             task_start_time = CASE WHEN cancel_requested THEN task_start_time ELSE NULL END, \
             task_end_time = CASE WHEN cancel_requested THEN (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT ELSE NULL END, \
             cancel_requested = false, failure_reason = CASE WHEN cancel_requested THEN NULL ELSE 'task lease expired' END \
             WHERE execution_status = 'running' AND lease_expires_at IS NOT NULL \
               AND lease_expires_at < (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT RETURNING task_id;",
            &[],
        )
        .await?;
    let expired_tasks: std::collections::HashSet<i32> =
        expired.iter().map(|row| row.get("task_id")).collect();
    for task_id in expired_tasks {
        refresh_task_aggregate(&transaction, task_id).await?;
    }
    transaction.commit().await?;

    let owner_id = match permissions {
        Permission::Administrator(_) => None,
        Permission::Users(id) => Some(id),
    };
    let (count_filter, count_params) = task_list_filter(filters, &owner_id, false);
    let count_sql = format!("SELECT COUNT(*)::BIGINT AS total FROM scan_task t{count_filter}");
    let total = connection
        .query_one(&count_sql, &count_params)
        .await?
        .get("total");

    let page_size = filters.limit.clamp(1, 100);
    let fetch_limit = page_size + 1;
    let (page_filter, mut page_params) = task_list_filter(filters, &owner_id, true);
    page_params.push(&fetch_limit);
    let page_sql = format!(
        "SELECT t.*, CASE WHEN t.task_kind = 'dns' THEN t.dns_targets ELSE t.task_target::TEXT[] END AS display_targets FROM scan_task t{page_filter} \
         ORDER BY t.id DESC LIMIT ${}",
        page_params.len()
    );
    let mut rows = connection.query(&page_sql, &page_params).await?;
    let has_more = rows.len() > page_size as usize;
    if has_more {
        rows.truncate(page_size as usize);
    }
    let next_cursor = if has_more {
        rows.last().map(|row| row.get::<_, i32>("id"))
    } else {
        None
    };
    let items = rows
        .into_iter()
        .map(|row| {
            let stored_profile: String = row.get("scan_profile");
            let generation_metadata: Option<Value> = row.get("generation_metadata");
            TaskItem {
                task_id: row.get("task_id"),
                task_target: row.get("display_targets"),
                task_kind: row.get("task_kind"),
                task_initiator: row.get("task_initiator"),
                task_port: row.get("task_port"),
                task_create_time: row.get("task_create_time"),
                task_level: row.get("task_level"),
                scanner_id: row.get("assigned_scanner_id"),
                task_status: row.get("task_status"),
                lease_expires_at: row.get("lease_expires_at"),
                attempt_count: row.get("attempt_count"),
                failure_reason: row.get("failure_reason"),
                start_at: row.get("task_start_time"),
                end_at: row.get("task_end_time"),
                remarks: row.get("remarks"),
                task_source: row.get("task_source"),
                address_family: row.get("address_family"),
                scan_profile: display_scan_profile(&stored_profile, generation_metadata.as_ref()),
                scan_plan: row.get("scan_plan"),
            }
        })
        .collect();
    Ok(TaskListPage {
        items,
        total,
        page_size,
        next_cursor,
        has_more,
    })
}

#[derive(Serialize, Deserialize)]
pub struct SystemStatusJson {
    pub total_c: i32,
    pub status_item: Vec<SystemResource>,
    pub system_info: SystemDetails,
}

/// 获取系统状态信息
pub async fn get_system_status_info(
    start_at: Option<i64>,
    end_at: Option<i64>,
    count: i64,
    pool: &deadpool_postgres::Pool,
) -> Result<(Vec<SystemResource>, i32), Box<dyn std::error::Error>> {
    let connect = pool.get().await?;

    let row = if start_at.is_some() || end_at.is_some() {
        connect
            .query(
                "SELECT *
                        FROM system_status
                        WHERE create_time BETWEEN
                            COALESCE($1::BIGINT, (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT)
                            AND
                            COALESCE($2::BIGINT, (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT)
                        ORDER BY id DESC
                        LIMIT $3;",
                &[&start_at, &end_at, &count],
            )
            .await?
    } else {
        connect
            .query(
                "SELECT * FROM system_status ORDER BY id DESC LIMIT $1;",
                &[&count],
            )
            .await?
    };

    let mut vec_status: Vec<SystemResource> = Vec::new();
    let mut tmp_count: i32 = 0;

    for r in row {
        let tmp = SystemResource {
            server_run_time: r.get::<_, i64>("server_run_time"),
            cpu: serde_json::from_value(r.get::<_, Value>("cpu"))?,
            ram: serde_json::from_value(r.get::<_, Value>("ram"))?,
            disk: serde_json::from_value(r.get::<_, Value>("disk"))?,
            db_postgresql: serde_json::from_value(r.get::<_, Value>("db_postgresql"))?,
            network: serde_json::from_value(r.get::<_, Value>("network"))?,
            create_at: Some(r.get::<_, i64>("create_time")),
        };
        tmp_count += 1;
        vec_status.push(tmp);
    }
    Ok((vec_status, tmp_count))
}

/// 加密关键数据
///
/// 该函数接受一个参数 明文。返回三个参数，分别为 nonce、tag、密文
type EncryptedData = (Vec<u8>, Vec<u8>, Vec<u8>);

pub fn encrypt_data(
    plaintext: &[u8],
    key: &[u8],
) -> Result<EncryptedData, openssl::error::ErrorStack> {
    // 32 字节密钥，且初始化为 1
    // let mut key = [1u8; 32];
    // rand::rand_bytes(&mut key)?;

    // 12 字节nonce ，初始化为 0
    let mut nonce = [0u8; 12];
    rand::rand_bytes(&mut nonce)?;

    let cipher = Cipher::aes_256_gcm();

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(&nonce))?;

    // GCM 不需要 padding
    crypter.pad(false);

    let mut ciphertext = vec![0u8; plaintext.len() + cipher.block_size()];

    let count = crypter.update(plaintext, &mut ciphertext)?;

    let rest = crypter.finalize(&mut ciphertext[count..])?;

    ciphertext.truncate(count + rest);

    let mut tag = [0u8; 16];
    crypter.get_tag(&mut tag)?;

    Ok((nonce.to_vec(), tag.to_vec(), ciphertext))
}

/// 解密
///
pub fn decrypt_data(
    // value: &[u8],
    value: &[u8],
    // ciphertext: &[u8],
    key: &[u8],
    // nonce: &[u8],
    // tag: &[u8],
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let nonce = &value[..12];
    let tag = &value[12..28];
    let ciphertext = &value[28..];

    let cipher = Cipher::aes_256_gcm();

    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(nonce))?;

    crypter.pad(false);

    crypter.set_tag(tag)?;

    let mut plaintext = vec![0u8; ciphertext.len() + cipher.block_size()];

    let count = crypter.update(ciphertext, &mut plaintext)?;

    let rest = crypter.finalize(&mut plaintext[count..])?;

    plaintext.truncate(count + rest);

    Ok(plaintext)
}
