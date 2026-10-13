use crate::admin::{UserBaseI, get_default_scan_profile_from_database};
use crate::audit::{self, AuditContext};
use crate::client_ip::{normalize_ip, request_ip};
use crate::config::SecurityConfig;
use crate::dns_follow_up::DnsFollowUpConfig;
use crate::elasticsearch::{ElasticsearchService, ScanQueryIndex};
use crate::logs::write::{error_diagnostics, error_logs, error_logs_error, info_logs};
use crate::maxmind::MaxMindState;
use crate::runtime_config::RuntimeConfig;
use crate::scanner_latency::{ScannerLatencyHistory, ScannerLatencyHistoryEntry};
use crate::system_maintenance::{
    MaintenanceSnapshot, SystemMaintenanceState, maintenance_response,
};
use crate::{identity::Permission, web_support::TEXT_HTML_UTF_8};
use crate::{
    result_ingest::model::SaveScannerResultsError, result_ingest::model::ScannerResultUpload,
    result_ingest::storage::save_scanner_results,
};
use crate::{
    scan_control::creation::CreateTask, scan_control::creation::STask,
    scan_control::creation::build_scan_plan, scan_control::dispatch::ApplyTaskError,
    scan_control::dispatch::ApplyTaskQuery, scan_control::dispatch::CurrentTaskQuery,
    scan_control::dispatch::apply_task, scan_control::dispatch::validate_scanner_credentials,
    scan_control::query::ReceiveTaskItemQueryInfo, scan_control::query::TaskItemJson,
    scan_control::query::TaskListFilters, scan_control::query::get_filtered_task_page,
    scan_control::target::TargetIP,
};
use actix_web::{HttpRequest, HttpResponse, Responder, get, http::header, post, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::IpAddr;
use tracing::error;
use uuid::Uuid;

fn log_scanner_result_error(
    req: &HttpRequest,
    upload: &ScannerResultUpload,
    error_value: &SaveScannerResultsError,
) {
    let diagnostics = error_diagnostics(error_value);
    let mut port_count = 0usize;
    let mut service_count = 0usize;
    let mut dns_count = 0usize;
    let mut vulnerability_count = 0usize;
    for observation in &upload.observations {
        match observation {
            crate::result_ingest::model::ScannerObservation::Port { .. } => port_count += 1,
            crate::result_ingest::model::ScannerObservation::Service { .. } => service_count += 1,
            crate::result_ingest::model::ScannerObservation::Dns { .. } => dns_count += 1,
            crate::result_ingest::model::ScannerObservation::Vulnerability { .. } => {
                vulnerability_count += 1
            }
        }
    }
    let outcome = match error_value {
        SaveScannerResultsError::Storage(_) | SaveScannerResultsError::BatchBusy { .. } => {
            "batch_retained_for_retry"
        }
        SaveScannerResultsError::Database(_) if error_value.retryable() => {
            "batch_retained_for_retry"
        }
        SaveScannerResultsError::Database(_) => "server_error",
        _ => "request_rejected",
    };
    let (conflicting_upload_id, conflicting_upload_count) = error_value
        .conflicting_upload()
        .map_or((None, None), |(id, count)| (Some(id), Some(count)));
    let (expected_checksum, received_checksum) = error_value
        .batch_conflict_checksums()
        .map_or((None, None), |(expected, received)| {
            (expected, Some(received))
        });
    error!(
        event = "SaveScannerResultError",
        operation = error_value.operation(),
        error_kind = error_value.kind(),
        error_code = error_value.code(),
        error_message = %diagnostics.error_message,
        error_chain = %diagnostics.error_chain,
        root_cause = %diagnostics.root_cause,
        error_truncated = diagnostics.error_truncated,
        retryable = error_value.retryable(),
        outcome,
        http_status = error_value.http_status(),
        client_ip = crate::web_support::get_conn_ip(req),
        method = %req.method(),
        user_agent = crate::web_support::get_user_agent(req),
        path = req.path(),
        scanner_id = %upload.scanner_id,
        task_id = %upload.task_id,
        execution_id = error_value.execution_id(),
        upload_id = ?upload.upload_id,
        conflicting_upload_id,
        conflicting_upload_count,
        expected_checksum,
        received_checksum,
        batch_index = upload.batch_index,
        is_final = upload.is_final,
        protocol_version = upload.protocol_version,
        observation_count = upload.observations.len(),
        legacy_result_count = upload.results.len(),
        port_observation_count = port_count,
        service_observation_count = service_count,
        dns_observation_count = dns_count,
        vulnerability_observation_count = vulnerability_count,
        "scanner result upload failed"
    );
}

#[derive(Serialize)]
struct ScannerHeartbeatLease {
    task_id: Uuid,
    status: &'static str,
    expires_at_ms: Option<i64>,
    ttl_ms: i64,
    maintenance_hold: bool,
}

#[derive(Deserialize)]
struct CreateDnsTask {
    domains: Vec<String>,
    #[serde(default)]
    dns_resolvers: Vec<CreateDnsResolver>,
    level: i8,
    remark: Option<String>,
    #[serde(default = "default_dns_scan_profile")]
    scan_profile: String,
    #[serde(default = "crate::scan_control::creation::default_dispatch_mode")]
    dispatch_mode: String,
    #[serde(default)]
    scanner_ids: Vec<Uuid>,
    port: Option<String>,
    #[serde(default)]
    follow_up_port_scan: bool,
    #[serde(default = "default_follow_up_scan_profile")]
    follow_up_scan_profile: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CreateDnsResolver {
    id: String,
    label: String,
    ip: String,
    port: u16,
    transport: String,
}

impl CreateDnsResolver {
    fn normalize(mut self) -> Result<Self, &'static str> {
        self.id = self.id.trim().to_ascii_lowercase();
        self.label = self.label.trim().to_owned();
        self.ip = self
            .ip
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| "DNS server IP is invalid")?
            .to_string();
        self.transport = self.transport.trim().to_ascii_lowercase();
        if self.id.is_empty()
            || self.id.len() > 64
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err("DNS server ID must contain 1 to 64 letters, numbers, - or _");
        }
        if self.label.is_empty() || self.label.len() > 128 {
            return Err("DNS server name must contain 1 to 128 characters");
        }
        if self.port == 0 {
            return Err("DNS server port must be between 1 and 65535");
        }
        if !matches!(self.transport.as_str(), "udp" | "tcp") {
            return Err("DNS server transport must be udp or tcp");
        }
        Ok(self)
    }
}

fn default_dns_scan_profile() -> String {
    "dns_records".into()
}

fn default_follow_up_scan_profile() -> String {
    "port_only".into()
}

#[get("/api/dns/resolvers")]
async fn get_dns_resolver_presets(
    settings: web::Data<crate::runtime_config::RuntimeSettings>,
    _user: UserBaseI,
) -> impl Responder {
    let presets = settings
        .dns_resolvers
        .get()
        .await
        .value
        .resolvers
        .into_iter()
        .filter(|resolver| resolver.enabled)
        .collect::<Vec<_>>();
    HttpResponse::Ok().json(json!({"success": true, "data": presets}))
}

fn resolve_dns_task_port(
    scan_profile: &str,
    follow_up_port_scan: bool,
    port: Option<&str>,
) -> Result<String, &'static str> {
    if scan_profile == "dns_records" && !follow_up_port_scan {
        if port.is_some_and(|value| !value.trim().is_empty()) {
            return Err("port must be omitted for DNS-only tasks");
        }
        return Ok("53".to_owned());
    }

    let port = port
        .map(str::trim)
        .filter(|port| !port.is_empty())
        .unwrap_or("1-65535");
    if !crate::scan_control::target::check_port(port) {
        return Err("invalid port range");
    }
    Ok(port.to_owned())
}

#[derive(Debug, PartialEq, Eq)]
struct ResolvedDnsScanRequest {
    task_profile: String,
    follow_up_profile: Option<String>,
}

fn resolve_dns_scan_request(
    scan_profile: &str,
    legacy_follow_up_enabled: bool,
    legacy_follow_up_profile: &str,
) -> Result<ResolvedDnsScanRequest, &'static str> {
    match scan_profile {
        "dns_records" if legacy_follow_up_enabled => {
            if !crate::scan_control::creation::is_ip_scan_profile(legacy_follow_up_profile) {
                return Err("invalid DNS follow-up scan profile");
            }
            Ok(ResolvedDnsScanRequest {
                task_profile: "dns_records".into(),
                follow_up_profile: Some(legacy_follow_up_profile.into()),
            })
        }
        "dns_records" => Ok(ResolvedDnsScanRequest {
            task_profile: "dns_records".into(),
            follow_up_profile: None,
        }),
        // Unified domain modes always run DNS first. The server then creates
        // address-family-specific child tasks from authorized A/AAAA answers.
        "legacy" | "port_only" | "service_inventory" | "vulnerability_scan" => {
            if legacy_follow_up_enabled {
                return Err("follow_up_port_scan must not be combined with a unified scan profile");
            }
            Ok(ResolvedDnsScanRequest {
                task_profile: "dns_records".into(),
                follow_up_profile: Some(scan_profile.into()),
            })
        }
        // Retain the original in-scanner DNS profiles for rolling upgrades and
        // existing API clients. The web UI no longer creates these profiles.
        "dns_ports" | "dns_full" if !legacy_follow_up_enabled => Ok(ResolvedDnsScanRequest {
            task_profile: scan_profile.into(),
            follow_up_profile: None,
        }),
        "dns_ports" | "dns_full" => {
            Err("follow_up_port_scan is not valid for legacy DNS scan profiles")
        }
        _ => Err("invalid DNS scan profile"),
    }
}

#[derive(Serialize)]
struct ScannerHeartbeatCommand {
    #[serde(rename = "type")]
    command_type: &'static str,
    task_id: Uuid,
}

#[derive(Serialize)]
struct ScannerHeartbeatResponse {
    diagnostics_enabled: bool,
    diagnostic_requests: Vec<crate::scanner_diagnostics::protocol::Job>,
    success: bool,
    lease: Option<ScannerHeartbeatLease>,
    command: Option<ScannerHeartbeatCommand>,
    maintenance: Option<MaintenanceSnapshot>,
    configuration: Option<crate::scanner_config::ScannerConfigurationNotice>,
}

#[derive(Default, Deserialize)]
struct ScannerConfigurationState {
    #[serde(default)]
    supported_schema_versions: Vec<i32>,
    applied_revision: Option<i64>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct ScannerSystemInfo {
    os_name: String,
    os_version: String,
    cpu_model: String,
    cpu_cores: u32,
    ram_total_mb: u64,
    uptime_seconds: u64,
}

#[derive(Deserialize)]
pub struct ScannerHeartbeat {
    #[serde(default)]
    diagnostics: crate::scanner_diagnostics::protocol::Capabilities,
    #[serde(default)]
    diagnostic_health: Option<crate::scanner_diagnostics::Health>,
    scanner_id: Uuid,
    state: String,
    active_task_id: Option<Uuid>,
    scanner_version: String,
    system: ScannerSystemInfo,
    #[serde(default)]
    network_capabilities: ScannerNetworkCapabilities,
    #[serde(default)]
    scan_capabilities: ScannerScanCapabilities,
    #[serde(default)]
    latency_report: Option<ScannerLatencyReport>,
    #[serde(default)]
    config_state: ScannerConfigurationState,
}

const LATENCY_PROTOCOL_VERSION: u16 = 1;
const MAX_LATENCY_US: i64 = 120_000_000;

#[derive(Deserialize)]
pub struct ScannerLatencyReport {
    version: u16,
    probe_id: Uuid,
    rtt_us: i64,
    server_processing_us: i64,
    network_rtt_us: i64,
    server_sent_at_ms: i64,
}

#[derive(Clone, Debug)]
struct ValidatedScannerLatency {
    probe_id: Uuid,
    measured_at: DateTime<Utc>,
    rtt_us: i64,
    server_processing_us: i64,
    network_rtt_us: i64,
}

fn validate_latency_report(
    report: &ScannerLatencyReport,
) -> Result<ValidatedScannerLatency, &'static str> {
    if report.version != LATENCY_PROTOCOL_VERSION {
        return Err("unsupported latency protocol version");
    }
    if !(0..=MAX_LATENCY_US).contains(&report.rtt_us)
        || !(0..=MAX_LATENCY_US).contains(&report.server_processing_us)
        || !(0..=MAX_LATENCY_US).contains(&report.network_rtt_us)
    {
        return Err("latency value is out of range");
    }
    if report.server_processing_us > report.rtt_us {
        return Err("server processing time exceeds total RTT");
    }
    let network_rtt_us = report.rtt_us.saturating_sub(report.server_processing_us);
    let now = Utc::now();
    let measured_at = DateTime::from_timestamp_millis(report.server_sent_at_ms)
        .filter(|value| (*value - now).num_seconds().abs() <= 24 * 60 * 60)
        .unwrap_or(now);

    Ok(ValidatedScannerLatency {
        probe_id: report.probe_id,
        measured_at,
        rtt_us: report.rtt_us,
        server_processing_us: report.server_processing_us,
        network_rtt_us,
    })
}

#[derive(Deserialize, Serialize)]
pub struct ScannerScanCapabilities {
    plan_versions: Vec<u16>,
    profiles: Vec<String>,
    stages: Vec<String>,
    #[serde(default)]
    explicit_dns_resolvers: bool,
}

impl Default for ScannerScanCapabilities {
    fn default() -> Self {
        Self {
            plan_versions: Vec::new(),
            profiles: vec!["legacy".into()],
            stages: vec!["port_discovery".into()],
            explicit_dns_resolvers: false,
        }
    }
}

impl ScannerScanCapabilities {
    fn validate(&self) -> Result<(), &'static str> {
        if self.plan_versions.len() > 8 || self.profiles.len() > 8 || self.stages.len() > 16 {
            return Err("too many scan capabilities");
        }
        if self.profiles.iter().any(|value| {
            !matches!(
                value.as_str(),
                "legacy"
                    | "port_only"
                    | "service_inventory"
                    | "vulnerability_scan"
                    | "dns_records"
                    | "dns_ports"
                    | "dns_full"
            )
        }) || self.stages.iter().any(|value| {
            !matches!(
                value.as_str(),
                "port_discovery" | "service_detection" | "dns_lookup" | "vulnerability_detection"
            )
        }) {
            return Err("unsupported scan capability");
        }
        Ok(())
    }
}

#[derive(Deserialize)]
pub struct ScannerNetworkCapabilities {
    ipv4: ScannerNetworkFamily,
    ipv6: ScannerNetworkFamily,
}

impl Default for ScannerNetworkCapabilities {
    fn default() -> Self {
        Self {
            ipv4: ScannerNetworkFamily {
                supported: true,
                ready: true,
                public_ip: None,
                reason: Some("legacy_scanner".to_owned()),
            },
            ipv6: ScannerNetworkFamily::default(),
        }
    }
}

#[derive(Default, Deserialize)]
pub struct ScannerNetworkFamily {
    supported: bool,
    ready: bool,
    public_ip: Option<String>,
    reason: Option<String>,
}

#[derive(Deserialize)]
pub struct ScannerTaskFailure {
    scanner_id: Uuid,
    task_id: Uuid,
    error: String,
    #[serde(default = "default_retryable")]
    retryable: bool,
}

#[derive(Deserialize)]
pub struct ScannerTaskCancelled {
    scanner_id: Uuid,
    task_id: Uuid,
}

fn default_retryable() -> bool {
    true
}

fn validate_public_ip(value: Option<&str>, expect_ipv6: bool) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let address = normalize_ip(
        value
            .parse::<IpAddr>()
            .map_err(|_| "network capability contains an invalid public IP".to_owned())?,
    );
    if address.is_ipv6() != expect_ipv6 {
        return Err("network capability public IP has the wrong address family".to_owned());
    }
    Ok(Some(address.to_string()))
}

fn bearer_token(req: &HttpRequest) -> Option<&str> {
    req.headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

async fn maintenance_gate_for_runtime_scanner(
    pool: &Pool,
    security: &SecurityConfig,
    scanner_id: Uuid,
    token: &str,
    snapshot: MaintenanceSnapshot,
    should_block: bool,
) -> Option<HttpResponse> {
    if !should_block {
        return None;
    }
    match validate_scanner_credentials(pool, scanner_id, token, &security.scanner_token_pepper)
        .await
    {
        Ok(()) => Some(maintenance_response(&snapshot)),
        Err(ApplyTaskError::ScannerUnauthorized) => {
            Some(HttpResponse::Unauthorized().body("unauthorized"))
        }
        Err(error) => {
            tracing::error!(event = "ScannerMaintenanceCredentialError", operation = "validate_scanner_credentials", error = ?error, scanner_id = %scanner_id);
            Some(HttpResponse::InternalServerError().finish())
        }
    }
}

#[derive(Deserialize)]
pub struct ScannerPublicIpQuery {
    scannerid: Uuid,
}

#[derive(Serialize)]
struct ScannerPublicIpResponse {
    ip: String,
}

/// Returns the source address observed by the server to an authenticated scanner.
#[get("/api/scanner/network/public-ip")]
pub(crate) async fn scanner_public_ip_handler(
    req: HttpRequest,
    query: web::Query<ScannerPublicIpQuery>,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
) -> impl Responder {
    let Some(token) = bearer_token(&req) else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };
    if let Err(error) = validate_scanner_credentials(
        pool.get_ref(),
        query.scannerid,
        token,
        &security.scanner_token_pepper,
    )
    .await
    {
        return match error {
            ApplyTaskError::ScannerUnauthorized => {
                HttpResponse::Unauthorized().body("unauthorized")
            }
            error => {
                error_logs_error(
                    &req,
                    "ScannerPublicIpCredentialCheckError",
                    "validate_scanner_credentials",
                    &error,
                );
                HttpResponse::InternalServerError().finish()
            }
        };
    }

    let snapshot = maintenance.snapshot().await;
    if snapshot.blocks_all_scanner_requests() {
        return maintenance_response(&snapshot);
    }

    let Some(address) = request_ip(&req) else {
        error!(
            event = "ScannerPublicIpUnavailable",
            operation = "resolve_scanner_public_ip",
            error_kind = "request_context",
            error_code = "scanner_peer_address_unavailable",
            error_message = "authenticated scanner request has no resolved peer address",
            retryable = true,
            outcome = "request_failed",
            http_status = 503_u16,
            scanner_id = %query.scannerid,
            "authenticated scanner request had no peer address"
        );
        return HttpResponse::ServiceUnavailable().body("client address unavailable");
    };
    HttpResponse::Ok()
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(ScannerPublicIpResponse {
            ip: address.to_string(),
        })
}

#[derive(Deserialize)]
pub struct TaskDetailQuery {
    page: Option<i64>,
    page_size: Option<i64>,
    execution_id: Option<Uuid>,
}

#[derive(Serialize)]
struct TaskResultPort {
    port: i32,
    protocol: Option<String>,
    service: Option<String>,
    banner: Option<String>,
    other: Option<Value>,
    scan_time: Option<i64>,
}

#[derive(Serialize)]
struct TaskResultIp {
    ip: String,
    asn: Option<String>,
    isp: Option<String>,
    as_org: Option<String>,
    country_code: Option<String>,
    country_name: Option<String>,
    region_name: Option<String>,
    city_name: Option<String>,
    ports: Vec<TaskResultPort>,
}

fn task_result_pagination(page: Option<i64>, page_size: Option<i64>) -> (i64, i64, i64) {
    let page = page.unwrap_or(1).max(1);
    let page_size = page_size.unwrap_or(20).clamp(1, 100);
    (page, page_size, (page - 1) * page_size)
}

fn should_load_endpoint_results(task_kind: &str, result_count: i64) -> bool {
    task_kind == "ip" && result_count > 0
}

fn should_load_vulnerabilities(task_kind: &str, scan_profile: &str, result_count: i64) -> bool {
    task_kind == "ip" && scan_profile == "vulnerability_scan" && result_count > 0
}

async fn load_execution_results_from_elasticsearch(
    elasticsearch: &ElasticsearchService,
    execution_id: &str,
    offset: i64,
    page_size: i64,
) -> Result<Vec<TaskResultIp>, String> {
    let mut search_after: Option<Value> = None;
    let mut skipped_ips = 0_i64;
    let mut results: Vec<TaskResultIp> = Vec::new();
    let mut current_ip: Option<String> = None;
    let mut collect_current = false;
    loop {
        let mut body = json!({
            "size": 1000,
            "query": {"term": {"execution_id": execution_id}},
            "sort": [{"ip": "asc"}, {"port": "asc"}]
        });
        if let Some(value) = search_after.clone() {
            body.as_object_mut()
                .expect("query body is object")
                .insert("search_after".to_owned(), value);
        }
        let response = elasticsearch
            .scan_query(ScanQueryIndex::ExecutionEndpoints, &body)
            .await?;
        let hits = response
            .pointer("/hits/hits")
            .and_then(Value::as_array)
            .ok_or_else(|| "Elasticsearch execution query response is missing hits".to_owned())?;
        if hits.is_empty() {
            break;
        }
        for hit in hits {
            let source = hit
                .get("_source")
                .ok_or_else(|| "Elasticsearch execution hit is missing _source".to_owned())?;
            let ip = source
                .get("ip")
                .and_then(Value::as_str)
                .ok_or_else(|| "Elasticsearch execution hit is missing ip".to_owned())?;
            let is_new_ip = current_ip.as_deref() != Some(ip);
            if is_new_ip {
                current_ip = Some(ip.to_owned());
                if skipped_ips < offset {
                    skipped_ips += 1;
                    collect_current = false;
                    continue;
                }
                if results.len() >= page_size as usize {
                    return Ok(results);
                }
                collect_current = true;
                let text =
                    |field: &str| source.get(field).and_then(Value::as_str).map(str::to_owned);
                results.push(TaskResultIp {
                    ip: ip.to_owned(),
                    asn: text("asn"),
                    isp: text("isp"),
                    as_org: text("as_org"),
                    country_code: text("country_code"),
                    country_name: text("country_name"),
                    region_name: text("region_name"),
                    city_name: text("city_name"),
                    ports: Vec::new(),
                });
            } else if !collect_current {
                continue;
            }
            if let Some(asset) = results.last_mut().filter(|asset| asset.ip == ip) {
                let kind = source.get("kind").and_then(Value::as_str).unwrap_or("port");
                let other = if kind == "service" {
                    json!({
                        "observation_kind": kind,
                        "source": source.get("source"),
                        "data": source.get("data")
                    })
                } else {
                    json!({
                        "observation_kind": kind,
                        "state": source.pointer("/data/state").and_then(Value::as_str).unwrap_or("open"),
                        "source": source.get("source")
                    })
                };
                asset.ports.push(TaskResultPort {
                    port: source.get("port").and_then(Value::as_i64).unwrap_or(0) as i32,
                    protocol: source
                        .get("protocol")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    service: source
                        .get("service")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    banner: source
                        .get("banner")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    other: Some(other),
                    scan_time: source.get("observed_at_ms").and_then(Value::as_i64),
                });
            }
        }
        search_after = hits.last().and_then(|hit| hit.get("sort")).cloned();
        if hits.len() < 1000 || search_after.is_none() {
            break;
        }
    }
    Ok(results)
}

async fn load_vulnerabilities_from_elasticsearch(
    elasticsearch: &ElasticsearchService,
    execution_id: &str,
) -> Result<(Vec<Value>, i64), String> {
    let response = elasticsearch
        .scan_query(
            ScanQueryIndex::Observations,
            &vulnerability_search_body(execution_id),
        )
        .await?;
    let total = response
        .pointer("/hits/total/value")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let findings = response
        .pointer("/hits/hits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|hit| hit.get("_source"))
        .map(vulnerability_response)
        .collect();
    Ok((findings, total))
}

fn vulnerability_search_body(execution_id: &str) -> Value {
    json!({
        "size": 500,
        "track_total_hits": true,
        "query": {"bool": {"filter": [
            {"term": {"execution_id": execution_id}},
            {"term": {"kind": "vulnerability"}}
        ]}},
        "sort": [
            {"observed_at": {"order": "desc", "format": "epoch_millis"}},
            {"observation_key": "asc"}
        ]
    })
}

fn vulnerability_response(source: &Value) -> Value {
    let data = source.get("data").cloned().unwrap_or_else(|| json!({}));
    let mut finding = data.as_object().cloned().unwrap_or_default();
    finding.insert(
        "ip".into(),
        source.get("ip_address").cloned().unwrap_or(Value::Null),
    );
    finding.insert(
        "port".into(),
        source.get("port").cloned().unwrap_or(Value::Null),
    );
    finding.insert(
        "protocol".into(),
        source.get("protocol").cloned().unwrap_or(Value::Null),
    );
    finding.insert(
        "observed_at".into(),
        source.get("observed_at").cloned().unwrap_or(Value::Null),
    );
    Value::Object(finding)
}

#[post("/api/scanner/heartbeat")]
pub(crate) async fn scanner_heartbeat_handler(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    latency_history: web::Data<ScannerLatencyHistory>,
    maintenance: web::Data<SystemMaintenanceState>,
    heartbeat: web::Json<ScannerHeartbeat>,
    diagnostics: Option<web::Data<std::sync::Arc<crate::scanner_diagnostics::Diagnostics>>>,
) -> impl Responder {
    let Some(token) = bearer_token(&req) else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };
    let maintenance_snapshot = maintenance.snapshot().await;
    let should_block = maintenance_snapshot.blocks_new_work() && heartbeat.active_task_id.is_none();
    if let Some(response) = maintenance_gate_for_runtime_scanner(
        pool.get_ref(),
        security.get_ref(),
        heartbeat.scanner_id,
        token,
        maintenance_snapshot.clone(),
        should_block,
    )
    .await
    {
        return response;
    }
    if !matches!(heartbeat.state.as_str(), "idle" | "scanning" | "stopping") {
        return HttpResponse::BadRequest().body("invalid scanner state");
    }
    if let Err(message) = heartbeat.scan_capabilities.validate() {
        return HttpResponse::BadRequest().body(message);
    }
    if heartbeat.config_state.supported_schema_versions.len() > 8
        || heartbeat
            .config_state
            .supported_schema_versions
            .iter()
            .any(|value| *value <= 0)
        || heartbeat
            .config_state
            .applied_revision
            .is_some_and(|value| value <= 0)
        || heartbeat
            .config_state
            .error
            .as_ref()
            .is_some_and(|value| value.len() > 500)
        || heartbeat
            .config_state
            .status
            .as_deref()
            .is_some_and(|value| !matches!(value, "local" | "staged" | "applied" | "rejected"))
    {
        return HttpResponse::BadRequest().body("invalid scanner configuration state");
    }
    if heartbeat.diagnostics.supported_versions.len() > 8
        || heartbeat
            .diagnostic_health
            .as_ref()
            .is_some_and(|h| !matches!(h.status.as_str(), "healthy" | "error" | "degraded"))
    {
        return HttpResponse::BadRequest().body("invalid diagnostics capabilities");
    }
    let token_hash =
        match crate::identity::hash_scanner_token(token, &security.scanner_token_pepper) {
            Ok(value) => value,
            Err(error) => {
                error_logs_error(
                    &req,
                    "ScannerHeartbeatCredentialHashError",
                    "hash_scanner_token",
                    &error,
                );
                return HttpResponse::InternalServerError().finish();
            }
        };

    let ip_address = request_ip(&req).map(|address| address.to_string());
    let mut connection = match pool.get().await {
        Ok(connection) => connection,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerHeartbeatPoolError",
                "acquire_connection",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let scanner_transaction = match connection.transaction().await {
        Ok(transaction) => transaction,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerHeartbeatTransactionError",
                "begin_transaction",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    if let Err(error) = scanner_transaction
        .batch_execute("SET LOCAL lock_timeout = '1500ms'; SET LOCAL statement_timeout = '5s';")
        .await
    {
        error_logs_error(
            &req,
            "ScannerHeartbeatTimeoutSetupError",
            "set_local_timeouts",
            &error,
        );
        return HttpResponse::ServiceUnavailable().finish();
    }
    let scanner_id = heartbeat.scanner_id.to_string();
    let system_version = format!(
        "{} {}",
        heartbeat.system.os_name, heartbeat.system.os_version
    );
    let cpu_cores = i32::try_from(heartbeat.system.cpu_cores).unwrap_or(i32::MAX);
    let ram_mb = i32::try_from(heartbeat.system.ram_total_mb).unwrap_or(i32::MAX);
    let uptime = i32::try_from(heartbeat.system.uptime_seconds).unwrap_or(i32::MAX);
    let public_ipv4 = match validate_public_ip(
        heartbeat.network_capabilities.ipv4.public_ip.as_deref(),
        false,
    ) {
        Ok(value) => value,
        Err(message) => return HttpResponse::BadRequest().body(message),
    };
    let public_ipv6 = match validate_public_ip(
        heartbeat.network_capabilities.ipv6.public_ip.as_deref(),
        true,
    ) {
        Ok(value) => value,
        Err(message) => return HttpResponse::BadRequest().body(message),
    };
    let network_status_reason = serde_json::json!({
        "ipv4": heartbeat.network_capabilities.ipv4.reason,
        "ipv6": heartbeat.network_capabilities.ipv6.reason,
    });
    let scan_capabilities = match serde_json::to_value(&heartbeat.scan_capabilities) {
        Ok(value) => value,
        Err(_) => return HttpResponse::BadRequest().body("invalid scan capabilities"),
    };
    let latency =
        heartbeat.latency_report.as_ref().and_then(|report| {
            match validate_latency_report(report) {
                Ok(latency) => Some(latency),
                Err(reason) => {
                    tracing::warn!(
                        scanner_id = %heartbeat.scanner_id,
                        reason,
                        "ignored invalid scanner latency report"
                    );
                    None
                }
            }
        });
    let latency_rtt_us = latency.as_ref().map(|value| value.rtt_us);
    let latency_network_rtt_us = latency.as_ref().map(|value| value.network_rtt_us);
    let latency_server_processing_us = latency.as_ref().map(|value| value.server_processing_us);
    let latency_measured_at = latency.as_ref().map(|value| value.measured_at);
    let latency_probe_id = latency.as_ref().map(|value| value.probe_id);
    let update = scanner_transaction
        .query_opt(
            "UPDATE scanner_info SET system_version = $1, scanner_version = $2, cpu_model = $3, \
             cpus = $4, ram = $5, uptime = $6, runtime_state = $7, last_seen_at = NOW(), \
             update_time = NOW(), outage_monitored_at = NOW(), is_run = ($7 <> 'stopping'), \
             ip_address = COALESCE($8::text::inet, ip_address), supports_ipv4 = $9, \
             supports_ipv6 = $10, ipv4_ready = $11, ipv6_ready = $12, \
             public_ipv4 = $13::text::inet, public_ipv6 = $14::text::inet, \
             network_status_reason = $15, network_capabilities_updated_at = NOW(), \
             scan_capabilities = $16, scan_capabilities_updated_at = NOW(), \
             latency_rtt_us = CASE WHEN $20::TIMESTAMPTZ IS NOT NULL \
                 AND (latency_measured_at IS NULL OR $20 >= latency_measured_at) \
                 THEN $17::BIGINT ELSE latency_rtt_us END, \
             latency_network_rtt_us = CASE WHEN $20::TIMESTAMPTZ IS NOT NULL \
                 AND (latency_measured_at IS NULL OR $20 >= latency_measured_at) \
                 THEN $18::BIGINT ELSE latency_network_rtt_us END, \
             latency_server_processing_us = CASE WHEN $20::TIMESTAMPTZ IS NOT NULL \
                 AND (latency_measured_at IS NULL OR $20 >= latency_measured_at) \
                 THEN $19::BIGINT ELSE latency_server_processing_us END, \
             latency_probe_id = CASE WHEN $20::TIMESTAMPTZ IS NOT NULL \
                 AND (latency_measured_at IS NULL OR $20 >= latency_measured_at) \
                 THEN $21::UUID ELSE latency_probe_id END, \
             latency_measured_at = CASE WHEN $20::TIMESTAMPTZ IS NOT NULL \
                 AND (latency_measured_at IS NULL OR $20 >= latency_measured_at) \
                 THEN $20::TIMESTAMPTZ ELSE latency_measured_at END \
             WHERE scanner_id = $22 AND runtime_token_hash = $23 AND is_enable = TRUE \
             RETURNING id;",
            &[
                &system_version,
                &heartbeat.scanner_version,
                &heartbeat.system.cpu_model,
                &cpu_cores,
                &ram_mb,
                &uptime,
                &heartbeat.state,
                &ip_address,
                &heartbeat.network_capabilities.ipv4.supported,
                &heartbeat.network_capabilities.ipv6.supported,
                &heartbeat.network_capabilities.ipv4.ready,
                &heartbeat.network_capabilities.ipv6.ready,
                &public_ipv4.as_deref(),
                &public_ipv6.as_deref(),
                &network_status_reason,
                &scan_capabilities,
                &latency_rtt_us,
                &latency_network_rtt_us,
                &latency_server_processing_us,
                &latency_measured_at,
                &latency_probe_id,
                &scanner_id,
                &token_hash,
            ],
        )
        .await;
    match update {
        Ok(Some(_)) => {}
        Ok(None) => return HttpResponse::Unauthorized().body("unauthorized"),
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerHeartbeatUpdateError",
                "update_scanner_state",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    }
    let diagnostic_health = heartbeat
        .diagnostic_health
        .as_ref()
        .map(|h| h.status.as_str())
        .unwrap_or("unknown");
    let accepting_tasks = heartbeat
        .diagnostic_health
        .as_ref()
        .map(|h| h.accepting_tasks)
        .unwrap_or(true);
    if let Err(error) = scanner_transaction.execute(
        "UPDATE scanner_info SET diagnostics_capabilities=$2, accepting_tasks=$3, diagnostic_health=$4, diagnostic_dropped_events=$5 WHERE scanner_id=$1",
        &[&scanner_id, &serde_json::json!(heartbeat.diagnostics), &accepting_tasks, &diagnostic_health, &(heartbeat.diagnostic_health.as_ref().map(|h| h.dropped_events).unwrap_or(0).min(i64::MAX as u64) as i64)],
    ).await {
        error_logs_error(&req, "ScannerDiagnosticHealthError", "update_diagnostic_health", &error);
        return HttpResponse::InternalServerError().finish();
    }
    let configuration =
        match crate::scanner_config::load_configuration(&scanner_transaction, &scanner_id).await {
            Ok(Some(value)) => value,
            Ok(None) => return HttpResponse::Unauthorized().finish(),
            Err(error) => {
                error_logs_error(
                    &req,
                    "ScannerConfigurationHeartbeatError",
                    "load_configuration",
                    error.as_ref(),
                );
                return HttpResponse::InternalServerError().finish();
            }
        };
    if !heartbeat.config_state.supported_schema_versions.is_empty()
        && let Err(error) = scanner_transaction
            .execute(
                "UPDATE scanner_info SET applied_config_revision = $1, config_status = $2, \
                 config_error = $3, config_reported_at = NOW() WHERE scanner_id = $4;",
                &[
                    &heartbeat.config_state.applied_revision,
                    &heartbeat.config_state.status,
                    &heartbeat.config_state.error,
                    &scanner_id,
                ],
            )
            .await
    {
        error_logs_error(
            &req,
            "ScannerConfigurationStateError",
            "update_configuration_state",
            &error,
        );
        return HttpResponse::InternalServerError().finish();
    }
    let configuration_notice = heartbeat
        .config_state
        .supported_schema_versions
        .contains(&configuration.schema_version)
        .then_some(configuration)
        .filter(|value| heartbeat.config_state.applied_revision != Some(value.revision))
        .map(|value| crate::scanner_config::ScannerConfigurationNotice {
            revision: value.revision,
            schema_version: value.schema_version,
        });
    if let Err(error) =
        crate::scanner_outage::record_recovery(&scanner_transaction, &scanner_id).await
    {
        error_logs_error(
            &req,
            "ScannerRecoveryError",
            "record_scanner_recovery",
            &error,
        );
        return HttpResponse::InternalServerError().finish();
    }
    // 扫描器状态行与任务执行行使用两个短事务。过去这里会在等待任务租约锁时一直
    // 持有 scanner_info 行锁，导致同一扫描器后续心跳形成分钟级锁队列。
    if let Err(error) = scanner_transaction.commit().await {
        error_logs_error(
            &req,
            "ScannerHeartbeatCommitError",
            "commit_scanner_state",
            &error,
        );
        return HttpResponse::InternalServerError().finish();
    }
    let lease_started = std::time::Instant::now();
    let mut lease = None;
    let mut cancel_task_id = None;
    if let Some(task_id) = heartbeat.active_task_id {
        let transaction = match connection.transaction().await {
            Ok(transaction) => transaction,
            Err(error) => {
                error_logs_error(
                    &req,
                    "ScannerLeaseTransactionError",
                    "begin_transaction",
                    &error,
                );
                return HttpResponse::ServiceUnavailable().finish();
            }
        };
        if let Err(error) = transaction
            .batch_execute("SET LOCAL lock_timeout = '1500ms'; SET LOCAL statement_timeout = '5s';")
            .await
        {
            error_logs_error(
                &req,
                "ScannerLeaseTimeoutSetupError",
                "set_local_timeouts",
                &error,
            );
            return HttpResponse::ServiceUnavailable().finish();
        }
        let lease_expires_at =
            crate::clock::get_unix_epoch_ms() + crate::scan_control::dispatch::TASK_LEASE_MS;
        let renewed = match transaction
            .query_opt(
                "UPDATE scan_task_execution e SET lease_expires_at = CASE \
                 WHEN e.maintenance_hold THEN NULL ELSE $1::bigint END FROM scan_task t \
                 WHERE e.task_id = t.id AND t.task_id = $2 AND e.assigned_scanner_id = $3 \
                 AND e.execution_status = 'running' RETURNING e.maintenance_hold, e.lease_expires_at;",
                &[&lease_expires_at, &task_id.to_string(), &scanner_id],
            )
            .await
        {
            Err(error) => {
                error_logs_error(&req, "ScannerLeaseRenewError", "renew_task_lease", &error);
                return HttpResponse::ServiceUnavailable().finish();
            }
            Ok(row) => row,
        };
        if let Some(renewed) = renewed {
            let maintenance_hold: bool = renewed.get("maintenance_hold");
            lease = Some(ScannerHeartbeatLease {
                task_id,
                status: "renewed",
                expires_at_ms: renewed.get("lease_expires_at"),
                ttl_ms: if maintenance_hold {
                    crate::system_maintenance::RESULT_UPLOAD_GRACE_TTL_MS
                } else {
                    crate::scan_control::dispatch::TASK_LEASE_MS
                },
                maintenance_hold,
            });
            match transaction
                .query_opt(
                    "SELECT t.task_id FROM scan_task_execution e JOIN scan_task t ON t.id = e.task_id \
                     WHERE t.task_id = $1 AND e.assigned_scanner_id = $2 \
                     AND e.execution_status = 'running' AND e.cancel_requested = true LIMIT 1;",
                    &[&task_id.to_string(), &scanner_id],
                )
                .await
            {
                Ok(Some(_)) => cancel_task_id = Some(task_id),
                Ok(None) => {}
                Err(error) => {
                    error_logs_error(
                        &req,
                        "ScannerCancelCommandError",
                        "read_cancel_command",
                        &error,
                    );
                    return HttpResponse::ServiceUnavailable().finish();
                }
            }
        } else {
            lease = Some(ScannerHeartbeatLease {
                task_id,
                status: "lost",
                expires_at_ms: None,
                ttl_ms: crate::scan_control::dispatch::TASK_LEASE_MS,
                maintenance_hold: false,
            });
        }
        if let Err(error) = transaction.commit().await {
            error_logs_error(&req, "ScannerLeaseCommitError", "commit_task_lease", &error);
            return HttpResponse::ServiceUnavailable().finish();
        }
    }
    tracing::debug!(event="ScannerLeaseRenewCompleted", scanner_id, task_id=?heartbeat.active_task_id,
        elapsed_ms=lease_started.elapsed().as_millis() as u64, "scanner lease transaction completed");
    if let Some(latency) = latency {
        latency_history.record(ScannerLatencyHistoryEntry {
            scanner_id,
            probe_id: latency.probe_id,
            measured_at: latency.measured_at,
            rtt_us: latency.rtt_us,
            server_processing_us: latency.server_processing_us,
            network_rtt_us: latency.network_rtt_us,
        });
    }
    let diagnostic_requests = if diagnostics.as_ref().is_some_and(|d| d.config.enabled)
        && !maintenance_snapshot.blocks_new_work()
        && heartbeat
            .diagnostics
            .supported_versions
            .contains(&crate::scanner_diagnostics::protocol::VERSION)
    {
        match crate::scanner_diagnostics::pending_jobs(pool.get_ref(), heartbeat.scanner_id).await {
            Ok(jobs) => jobs,
            Err(error) => {
                tracing::warn!(event="ScannerDiagnosticDispatchFailed", %error);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    HttpResponse::Ok().json(ScannerHeartbeatResponse {
        diagnostics_enabled: diagnostics.as_ref().is_some_and(|d| d.config.enabled),
        diagnostic_requests,
        success: true,
        lease,
        command: cancel_task_id.map(|task_id| ScannerHeartbeatCommand {
            command_type: "cancel_task",
            task_id,
        }),
        maintenance: maintenance_snapshot.enabled.then_some(maintenance_snapshot),
        configuration: configuration_notice,
    })
}

#[post("/api/scanner/task/fail")]
pub(crate) async fn scanner_task_failure_handler(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
    failure: web::Json<ScannerTaskFailure>,
) -> impl Responder {
    let Some(token) = bearer_token(&req) else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };
    let maintenance_snapshot = maintenance.snapshot().await;
    if let Some(response) = maintenance_gate_for_runtime_scanner(
        pool.get_ref(),
        security.get_ref(),
        failure.scanner_id,
        token,
        maintenance_snapshot.clone(),
        maintenance_snapshot.blocks_all_scanner_requests(),
    )
    .await
    {
        return response;
    }
    let token_hash =
        match crate::identity::hash_scanner_token(token, &security.scanner_token_pepper) {
            Ok(value) => value,
            Err(error) => {
                error_logs_error(
                    &req,
                    "ScannerTaskFailureCredentialHashError",
                    "hash_scanner_token",
                    &error,
                );
                return HttpResponse::InternalServerError().finish();
            }
        };
    let mut connection = match pool.get().await {
        Ok(connection) => connection,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerTaskFailurePoolError",
                "acquire_connection",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let scanner_id = failure.scanner_id.to_string();
    let task_id = failure.task_id.to_string();
    let reason: String = failure.error.chars().take(1000).collect();
    let force_terminal = !failure.retryable;
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerTaskFailureTransactionError",
                "begin_transaction",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    match crate::scan_control::dispatch::validate_scanner_credentials_with_client(
        &transaction,
        failure.scanner_id,
        &token_hash,
    )
    .await
    {
        Ok(()) => {}
        Err(ApplyTaskError::ScannerUnauthorized) => {
            return HttpResponse::Unauthorized().body("unauthorized");
        }
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerTaskFailureCredentialCheckError",
                "validate_scanner_credentials",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    }
    let changed = transaction
        .query(
            "UPDATE scan_task_execution SET execution_status = CASE WHEN $1::boolean OR attempt_count >= 3 THEN 'failed' ELSE 'pending' END, \
             task_end_time = CASE WHEN $1::boolean OR attempt_count >= 3 THEN $2::bigint ELSE NULL::bigint END, task_start_time = NULL, \
             assigned_scanner_id = CASE WHEN $1::boolean OR attempt_count >= 3 THEN assigned_scanner_id ELSE NULL END, \
             lease_expires_at = NULL, maintenance_hold = FALSE, maintenance_hold_until = NULL, \
             failure_reason = $3, cancel_requested = false \
             WHERE task_id = (SELECT id FROM scan_task WHERE task_id = $4) AND assigned_scanner_id = $5 \
             AND execution_status = 'running' RETURNING execution_status, task_id;",
            &[
                &force_terminal,
                &crate::clock::get_unix_epoch_ms(),
                &reason,
                &task_id,
                &scanner_id,
            ],
        )
        .await;
    match changed {
        Ok(rows) if !rows.is_empty() => {
            let task_db_id: i32 = rows[0].get("task_id");
            let retryable = rows
                .iter()
                .any(|row| row.get::<_, String>("execution_status") == "pending");
            let status = if retryable { "pending" } else { "failed" };
            if rows.len() > 1 {
                error_logs(
                    &req,
                    "ScannerTaskDuplicateExecutions",
                    &format!(
                        "task_id={task_id} scanner_id={scanner_id} updated_executions={}",
                        rows.len()
                    ),
                );
            }
            if let Err(error) =
                crate::scan_control::dispatch::refresh_task_aggregate(&transaction, task_db_id)
                    .await
            {
                error_logs_error(
                    &req,
                    "ScannerTaskFailureAggregateError",
                    "refresh_task_aggregate",
                    &error,
                );
                return HttpResponse::InternalServerError().finish();
            }
            if let Err(error) = transaction.commit().await {
                error_logs_error(
                    &req,
                    "ScannerTaskFailureCommitError",
                    "commit_task_failure",
                    &error,
                );
                return HttpResponse::InternalServerError().finish();
            }
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "retryable": retryable,
                "status": status,
            }))
        }
        Ok(_) => HttpResponse::Conflict().body("task is not owned by scanner"),
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerTaskFailureUpdateError",
                "record_task_failure",
                &error,
            );
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[post("/api/scanner/task/cancelled")]
pub(crate) async fn scanner_task_cancelled_handler(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
    cancelled: web::Json<ScannerTaskCancelled>,
) -> impl Responder {
    let Some(token) = bearer_token(&req) else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };
    let maintenance_snapshot = maintenance.snapshot().await;
    if let Some(response) = maintenance_gate_for_runtime_scanner(
        pool.get_ref(),
        security.get_ref(),
        cancelled.scanner_id,
        token,
        maintenance_snapshot.clone(),
        maintenance_snapshot.blocks_all_scanner_requests(),
    )
    .await
    {
        return response;
    }
    let token_hash =
        match crate::identity::hash_scanner_token(token, &security.scanner_token_pepper) {
            Ok(value) => value,
            Err(error) => {
                error_logs_error(
                    &req,
                    "ScannerTaskCancelledCredentialHashError",
                    "hash_scanner_token",
                    &error,
                );
                return HttpResponse::InternalServerError().finish();
            }
        };
    let mut connection = match pool.get().await {
        Ok(connection) => connection,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerTaskCancelledPoolError",
                "acquire_connection",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerTaskCancelledTransactionError",
                "begin_transaction",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    match crate::scan_control::dispatch::validate_scanner_credentials_with_client(
        &transaction,
        cancelled.scanner_id,
        &token_hash,
    )
    .await
    {
        Ok(()) => {}
        Err(ApplyTaskError::ScannerUnauthorized) => {
            return HttpResponse::Unauthorized().body("unauthorized");
        }
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerTaskCancelledCredentialCheckError",
                "validate_scanner_credentials",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    }
    let changed = transaction
        .query(
            "UPDATE scan_task_execution e SET execution_status = 'cancelled', task_end_time = $1, \
             lease_expires_at = NULL, maintenance_hold = FALSE, maintenance_hold_until = NULL, \
             cancel_requested = false, failure_reason = NULL FROM scan_task t \
             WHERE e.task_id = t.id AND t.task_id = $2 AND e.assigned_scanner_id = $3 \
             AND e.execution_status = 'running' AND e.cancel_requested = true RETURNING e.task_id;",
            &[
                &crate::clock::get_unix_epoch_ms(),
                &cancelled.task_id.to_string(),
                &cancelled.scanner_id.to_string(),
            ],
        )
        .await;
    match changed {
        Ok(rows) if !rows.is_empty() => {
            if let Err(error) = crate::scan_control::dispatch::refresh_task_aggregate(
                &transaction,
                rows[0].get("task_id"),
            )
            .await
            {
                error_logs_error(
                    &req,
                    "ScannerTaskCancelledAggregateError",
                    "refresh_task_aggregate",
                    &error,
                );
                return HttpResponse::InternalServerError().finish();
            }
            if let Err(error) = transaction.commit().await {
                error_logs_error(
                    &req,
                    "ScannerTaskCancelledCommitError",
                    "commit_task_cancellation",
                    &error,
                );
                return HttpResponse::InternalServerError().finish();
            }
            HttpResponse::Ok().json(serde_json::json!({"success": true}))
        }
        Ok(_) => HttpResponse::Conflict().body("task cancellation was not requested"),
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerTaskCancelledUpdateError",
                "mark_task_cancelled",
                &error,
            );
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/api/task/{task_id}")]
async fn get_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    task_id: web::Path<Uuid>,
    query: web::Query<TaskDetailQuery>,
    user: UserBaseI,
) -> impl Responder {
    let connection = match pool.get().await {
        Ok(connection) => connection,
        Err(error) => {
            error_logs_error(
                &req,
                "GetTaskDatabaseError",
                "acquire_database_connection",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let task_id = task_id.into_inner().to_string();
    let task = match connection
        .query_opt(
            "SELECT t.id, t.task_id, CASE WHEN t.task_kind = 'dns' THEN t.dns_targets ELSE t.task_target::text[] END AS display_targets, \
             t.task_kind, t.task_port, t.task_initiator, \
             t.task_level, t.task_create_time, t.task_start_time, t.task_end_time, \
             t.task_status, t.lease_expires_at, t.attempt_count, t.failure_reason, t.cancel_requested, \
             t.retry_of_task_id, t.remarks, t.dispatch_mode, t.task_source, \
             t.generation_strategy, t.generation_metadata, t.address_family, t.scan_profile, t.scan_plan, t.dns_resolvers \
             FROM scan_task t \
             WHERE t.task_id = $1 AND ($2 = 1 OR t.user_id = $3) LIMIT 1;",
            &[&task_id, &user.role, &user.id],
        )
        .await
    {
        Ok(Some(task)) => task,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "success": false,
                "message": "task not found",
            }));
        }
        Err(error) => {
            error_logs_error(&req, "GetTaskDatabaseError", "load_task", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };

    let task_pk: i32 = task.get("id");
    let execution_rows = match connection.query(
        "SELECT e.id, e.execution_id, e.requested_scanner_id, e.assigned_scanner_id, \
         COALESCE(s.name, e.assigned_scanner_id, e.requested_scanner_id) AS scanner_name, s.location, \
         e.execution_status, e.attempt_count, e.task_start_time, e.task_end_time, e.lease_expires_at, \
         e.failure_reason, e.cancel_requested, COALESCE(e.result_ip_count, 0)::BIGINT AS ip_count, \
         COALESCE(e.result_port_count, 0)::BIGINT AS port_count, COALESCE(e.result_observation_count, 0)::BIGINT AS result_count, \
         CASE WHEN t.scan_profile = 'dns_records' THEN 'not_applicable' \
              WHEN e.execution_status <> 'succeeded' THEN 'not_started' \
              WHEN p.processed_at IS NOT NULL THEN 'ready' \
              WHEN p.claim_token IS NOT NULL AND p.lease_expires_at > clock_timestamp() THEN 'running' \
              WHEN p.last_error IS NOT NULL THEN 'retrying' ELSE 'pending' END AS projection_status \
         FROM scan_task_execution e JOIN scan_task t ON t.id = e.task_id \
         LEFT JOIN scan_projection_outbox p ON p.execution_id = e.id \
         LEFT JOIN scanner_info s ON s.scanner_id = COALESCE(e.assigned_scanner_id, e.requested_scanner_id) \
         WHERE e.task_id = $1 AND e.execution_status <> 'superseded' \
         ORDER BY e.id;", &[&task_pk]).await {
        Ok(rows) => rows,
        Err(error) => { error_logs_error(&req, "GetTaskExecutionsError", "load_task_executions", &error); return HttpResponse::InternalServerError().finish(); }
    };
    let selected_execution = query
        .execution_id
        .and_then(|id| {
            execution_rows
                .iter()
                .find(|row| row.get::<_, String>("execution_id") == id.to_string())
        })
        .or_else(|| execution_rows.first());
    let Some(selected_execution) = selected_execution else {
        error_logs(
            &req,
            "GetTaskExecutionsError",
            "task has no execution records",
        );
        return HttpResponse::InternalServerError().finish();
    };
    let executions: Vec<Value> = execution_rows.iter().map(|row| serde_json::json!({
        "execution_id": row.get::<_, String>("execution_id"),
        "requested_scanner_id": row.get::<_, Option<String>>("requested_scanner_id"),
        "scanner_id": row.get::<_, Option<String>>("assigned_scanner_id"),
        "scanner_name": row.get::<_, Option<String>>("scanner_name"),
        "scanner_location": row.get::<_, Option<String>>("location"),
        "status": row.get::<_, String>("execution_status"),
        "projection_status": row.get::<_, String>("projection_status"),
        "attempt_count": row.get::<_, i32>("attempt_count"),
        "task_start_time": row.get::<_, Option<i64>>("task_start_time"),
        "task_end_time": row.get::<_, Option<i64>>("task_end_time"),
        "lease_expires_at": row.get::<_, Option<i64>>("lease_expires_at"),
        "failure_reason": row.get::<_, Option<String>>("failure_reason"),
        "cancel_requested": row.get::<_, bool>("cancel_requested"),
        "summary": {"ip_count": row.get::<_, i64>("ip_count"), "port_count": row.get::<_, i64>("port_count"), "result_count": row.get::<_, i64>("result_count")}
    })).collect();
    let (page, page_size, offset) = task_result_pagination(query.page, query.page_size);
    let ip_count = selected_execution.get::<_, i64>("ip_count");
    let port_count = selected_execution.get::<_, i64>("port_count");
    let result_count = selected_execution.get::<_, i64>("result_count");
    let task_kind = task.get::<_, String>("task_kind");
    let generation_metadata = task.get::<_, Option<Value>>("generation_metadata");
    let stored_scan_profile = task.get::<_, String>("scan_profile");
    // Rows own their values; permission checks and metadata loading are complete.
    drop(connection);
    let (results, endpoint_results_available) =
        if should_load_endpoint_results(&task_kind, result_count) {
            match load_execution_results_from_elasticsearch(
                elasticsearch.get_ref(),
                selected_execution.get::<_, String>("execution_id").as_str(),
                offset,
                page_size,
            )
            .await
            {
                Ok(results) => (results, true),
                Err(error) => {
                    error_logs(&req, "GetTaskResultsElasticsearchError", &error);
                    (Vec::new(), false)
                }
            }
        } else {
            (Vec::new(), true)
        };
    let (vulnerabilities, vulnerability_count, vulnerabilities_available) =
        if should_load_vulnerabilities(&task_kind, &stored_scan_profile, result_count) {
            match load_vulnerabilities_from_elasticsearch(
                elasticsearch.get_ref(),
                selected_execution.get::<_, String>("execution_id").as_str(),
            )
            .await
            {
                Ok((vulnerabilities, vulnerability_count)) => {
                    (vulnerabilities, Some(vulnerability_count), true)
                }
                Err(error) => {
                    error_logs(&req, "GetTaskVulnerabilitiesElasticsearchError", &error);
                    (Vec::new(), None, false)
                }
            }
        } else {
            (Vec::new(), Some(0), true)
        };
    let display_scan_profile = crate::scan_control::creation::display_scan_profile(
        &stored_scan_profile,
        generation_metadata.as_ref(),
    );
    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": {
            "task_id": task.get::<_, String>("task_id"),
            "task_target": task.get::<_, Vec<String>>("display_targets"),
            "task_kind": task_kind,
            "task_port": task.get::<_, String>("task_port"),
            "task_initiator": task.get::<_, String>("task_initiator"),
            "task_level": task.get::<_, i32>("task_level"),
            "task_create_time": task.get::<_, i64>("task_create_time"),
            "task_start_time": selected_execution.get::<_, Option<i64>>("task_start_time"),
            "task_end_time": selected_execution.get::<_, Option<i64>>("task_end_time"),
            "task_status": task.get::<_, String>("task_status"),
            "dispatch_mode": task.get::<_, String>("dispatch_mode"),
            "task_source": task.get::<_, String>("task_source"),
            "generation_strategy": task.get::<_, Option<String>>("generation_strategy"),
            "generation_metadata": generation_metadata,
            "address_family": task.get::<_, String>("address_family"),
            "scan_profile": display_scan_profile,
            "task_scan_profile": stored_scan_profile,
            "scan_plan": task.get::<_, Value>("scan_plan"),
            "dns_resolvers": task.get::<_, Value>("dns_resolvers"),
            "selected_execution_id": selected_execution.get::<_, String>("execution_id"),
            "projection_status": selected_execution.get::<_, String>("projection_status"),
            "executions": executions,
            "scanner_id": selected_execution.get::<_, Option<String>>("assigned_scanner_id"),
            "scanner_name": selected_execution.get::<_, Option<String>>("scanner_name"),
            "lease_expires_at": selected_execution.get::<_, Option<i64>>("lease_expires_at"),
            "attempt_count": selected_execution.get::<_, i32>("attempt_count"),
            "failure_reason": selected_execution.get::<_, Option<String>>("failure_reason"),
            "cancel_requested": selected_execution.get::<_, bool>("cancel_requested"),
            "retry_of_task_id": task.get::<_, Option<String>>("retry_of_task_id"),
            "remarks": task.get::<_, Option<String>>("remarks"),
            "summary": {
                "ip_count": ip_count,
                "port_count": port_count,
                "result_count": result_count,
                "vulnerability_count": vulnerability_count,
            },
            "results": results,
            "vulnerabilities": vulnerabilities,
            "result_availability": {
                "endpoints": endpoint_results_available,
                "vulnerabilities": vulnerabilities_available,
            },
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_items": ip_count,
                "total_pages": if ip_count == 0 { 1 } else { (ip_count + page_size - 1) / page_size },
            }
        }
    }))
}

#[derive(Clone, Debug, Serialize)]
struct DnsComparisonResolverResult {
    id: String,
    label: String,
    ip: Option<String>,
    port: Option<u16>,
    transport: Option<String>,
    response_code: String,
    latency_ms: Option<u32>,
    answers: Vec<Value>,
}

#[derive(Clone, Debug, Serialize)]
struct DnsComparisonRecord {
    name: String,
    record_type: String,
    resolvers: Vec<DnsComparisonResolverResult>,
    common_answers: Vec<Value>,
    differences: Vec<Value>,
    response_code_difference: bool,
}

fn build_dns_comparison(payload: &Value) -> Vec<DnsComparisonRecord> {
    let mut latest =
        BTreeMap::<(String, String, String), (String, DnsComparisonResolverResult)>::new();
    for hit in payload
        .pointer("/hits/hits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let source = hit.get("_source").unwrap_or(hit);
        let Some(name) = source.pointer("/dns/question/name").and_then(Value::as_str) else {
            continue;
        };
        let Some(record_type) = source.pointer("/dns/question/type").and_then(Value::as_str) else {
            continue;
        };
        let resolver_id = source
            .pointer("/resolver/id")
            .and_then(Value::as_str)
            .or_else(|| source.pointer("/dns_view/id").and_then(Value::as_str))
            .unwrap_or("system");
        let observed_at = source
            .get("@timestamp")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let answers = source
            .pointer("/dns/answers")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let item = DnsComparisonResolverResult {
            id: resolver_id.to_owned(),
            label: source
                .pointer("/resolver/label")
                .and_then(Value::as_str)
                .unwrap_or(resolver_id)
                .to_owned(),
            ip: source
                .pointer("/resolver/ip")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            port: source
                .pointer("/resolver/port")
                .and_then(Value::as_u64)
                .and_then(|value| u16::try_from(value).ok()),
            transport: source
                .pointer("/resolver/transport")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            response_code: source
                .pointer("/dns/response_code")
                .and_then(Value::as_str)
                .unwrap_or("SERVFAIL")
                .to_owned(),
            latency_ms: source
                .get("latency_ms")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok()),
            answers,
        };
        let key = (
            name.to_owned(),
            record_type.to_owned(),
            resolver_id.to_owned(),
        );
        if latest
            .get(&key)
            .is_none_or(|(current, _)| observed_at > *current)
        {
            latest.insert(key, (observed_at, item));
        }
    }
    let mut groups = BTreeMap::<(String, String), Vec<DnsComparisonResolverResult>>::new();
    for ((name, record_type, _), (_, resolver)) in latest {
        groups
            .entry((name, record_type))
            .or_default()
            .push(resolver);
    }
    groups.into_iter().map(|((name, record_type), mut resolvers)| {
        resolvers.sort_by(|left, right| left.id.cmp(&right.id));
        let resolver_count = resolvers.len();
        let response_code_difference = resolvers
            .iter()
            .map(|resolver| resolver.response_code.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            > 1;
        let mut occurrences = BTreeMap::<String, (Value, BTreeSet<String>)>::new();
        for resolver in &resolvers {
            for answer in &resolver.answers {
                let identity = format!("{}\u{0}{}", answer.get("type").and_then(Value::as_str).unwrap_or(""), answer.get("value").and_then(Value::as_str).unwrap_or(""));
                let entry = occurrences.entry(identity).or_insert_with(|| (answer.clone(), BTreeSet::new()));
                entry.1.insert(resolver.id.clone());
            }
        }
        let common_answers = occurrences.values()
            .filter(|(_, resolver_ids)| resolver_count > 0 && resolver_ids.len() == resolver_count)
            .map(|(answer, _)| answer.clone()).collect();
        let differences = occurrences.into_values()
            .filter(|(_, resolver_ids)| resolver_ids.len() != resolver_count)
            .map(|(answer, resolver_ids)| json!({"answer": answer, "resolver_ids": resolver_ids.into_iter().collect::<Vec<_>>() }))
            .collect();
        DnsComparisonRecord {
            name,
            record_type,
            resolvers,
            common_answers,
            differences,
            response_code_difference,
        }
    }).collect()
}

#[get("/api/task/{task_id}/dns-comparison")]
async fn get_dns_comparison(
    req: HttpRequest,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    task_id: web::Path<Uuid>,
    user: UserBaseI,
) -> impl Responder {
    let task_id = task_id.into_inner().to_string();
    let connection = match pool.get().await {
        Ok(connection) => connection,
        Err(error) => {
            error_logs_error(
                &req,
                "DnsComparisonPoolError",
                "acquire_dns_comparison_connection",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let task_kind = match connection.query_opt(
        "SELECT task_kind FROM scan_task WHERE task_id = $1 AND ($2 = 1 OR user_id = $3) LIMIT 1;",
        &[&task_id, &user.role, &user.id],
    ).await {
        Ok(Some(task)) => task.get::<_, String>("task_kind"),
        Ok(None) => return HttpResponse::NotFound().json(json!({"success": false, "message": "task not found"})),
        Err(error) => { error_logs_error(&req, "GetDnsComparisonDatabaseError", "load_dns_task", &error); return HttpResponse::InternalServerError().finish(); }
    };
    if task_kind != "dns" {
        return HttpResponse::BadRequest()
            .json(json!({"success": false, "message": "task is not a DNS task"}));
    }
    match elasticsearch.dns_task_observations(&task_id).await {
        Ok(payload) => {
            let records = build_dns_comparison(&payload);
            HttpResponse::Ok().json(json!({"success": true, "data": {"records": records}}))
        }
        Err(error) => {
            error_logs(&req, "GetDnsComparisonElasticsearchError", &error);
            HttpResponse::ServiceUnavailable().json(
                json!({"success": false, "message": "DNS comparison is temporarily unavailable"}),
            )
        }
    }
}

#[post("/api/task/create")]
async fn create_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    create_data: web::Json<CreateTask>,
    user_base_i: UserBaseI,
) -> impl Responder {
    match create_data.level {
        0..5 => (),
        _ => {
            info_logs(
                &req,
                "InvalidParams",
                format!("任务优先级level不符合要求{}", create_data.level).as_str(),
            );
            return HttpResponse::BadRequest().body("400 Bad Request");
        }
    }

    let database_conn = pool.get_ref();
    let user_id = user_base_i.id;
    let user_name = user_base_i.username.clone();

    let task_info = match STask::new(
        TargetIP::S(&create_data.ip),
        &user_name,
        Some(&create_data.port),
        create_data.remark.as_deref(),
    ) {
        Ok(task) => task,
        Err(error_value) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "message": error_value.to_string()
            }));
        }
    };
    let address_family = match task_info.address_family() {
        Ok(family) => family,
        Err(message) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"success": false, "message": message}));
        }
    };
    let scan_profile = match create_data
        .scan_profile
        .as_deref()
        .map(str::trim)
        .filter(|profile| !profile.is_empty())
    {
        Some(profile) => profile.to_lowercase(),
        None => match get_default_scan_profile_from_database(database_conn).await {
            Ok(profile) => profile,
            Err(error_value) => {
                error_logs(
                    &req,
                    "ReadDefaultScanProfileError",
                    &error_value.to_string(),
                );
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "success": false,
                    "message": "默认扫描模式暂时无法读取"
                }));
            }
        },
    };
    if !crate::scan_control::creation::is_ip_scan_profile(&scan_profile) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "message": "DNS scan profiles require the domain task endpoint"
        }));
    }
    let scan_plan = match build_scan_plan(&scan_profile) {
        Ok(plan) => plan,
        Err(message) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"success": false, "message": message}));
        }
    };
    let capability_filter = if address_family == "ipv6" {
        "supports_ipv6 AND ipv6_ready"
    } else {
        "supports_ipv4 AND ipv4_ready"
    };

    let dispatch_mode = create_data.dispatch_mode.trim().to_lowercase();
    let requested_scanners: Vec<Option<String>> = match dispatch_mode.as_str() {
        "automatic" if create_data.scanner_ids.is_empty() => vec![None],
        "selected" if !create_data.scanner_ids.is_empty() => {
            let ids: HashSet<String> = create_data.scanner_ids.iter().map(Uuid::to_string).collect();
            let connection = match database_conn.get().await {
                Ok(value) => value,
                Err(error) => {
                    error_logs_error(&req, "ResolveSelectedScannersPoolError", "acquire_scanner_connection", &error);
                    return HttpResponse::InternalServerError().finish();
                }
            };
            let values: Vec<String> = ids.into_iter().collect();
            let query = format!(
                "SELECT scanner_id FROM scanner_info WHERE scanner_id = ANY($1::text[]) \
                 AND is_enable = true AND deleted_at IS NULL AND {capability_filter} \
                 AND ($2 = 'legacy' OR scan_capabilities->'profiles' ? $2);"
            );
            let rows = match connection.query(&query, &[&values, &scan_profile]).await {
                Ok(rows) => rows,
                Err(error) => { error_logs_error(&req, "ResolveTaskScannersError", "resolve_selected_scanners", &error); return HttpResponse::InternalServerError().finish(); }
            };
            if rows.len() != values.len() {
                return HttpResponse::BadRequest().json(serde_json::json!({"success": false, "message": format!("selected scanner is unavailable or does not support {address_family}/{scan_profile}")}));
            }
            rows.into_iter().map(|row| Some(row.get("scanner_id"))).collect()
        }
        "all" if create_data.scanner_ids.is_empty() => {
            let connection = match database_conn.get().await {
                Ok(value) => value,
                Err(error) => {
                    error_logs_error(&req, "ResolveAllScannersPoolError", "acquire_scanner_connection", &error);
                    return HttpResponse::InternalServerError().finish();
                }
            };
            let query = format!(
                "SELECT scanner_id FROM scanner_info WHERE is_enable = true AND deleted_at IS NULL \
                 AND {capability_filter} \
                 AND ($1 = 'legacy' OR scan_capabilities->'profiles' ? $1) ORDER BY scanner_id;"
            );
            let rows = match connection.query(&query, &[&scan_profile]).await {
                Ok(rows) => rows,
                Err(error) => { error_logs_error(&req, "ResolveTaskScannersError", "resolve_all_scanners", &error); return HttpResponse::InternalServerError().finish(); }
            };
            if rows.is_empty() {
                return HttpResponse::Conflict().json(serde_json::json!({"success": false, "message": format!("no scanner supporting {address_family}/{scan_profile} is currently available")}));
            }
            rows.into_iter().map(|row| Some(row.get("scanner_id"))).collect()
        }
        _ => return HttpResponse::BadRequest().json(serde_json::json!({"success": false, "message": "invalid dispatch mode or scanner selection"})),
    };

    match task_info
        .add(
            database_conn,
            create_data.level as i32,
            user_id,
            &dispatch_mode,
            &requested_scanners,
            &scan_profile,
            &scan_plan,
            &AuditContext::from_request(&req),
            &user_base_i,
        )
        .await
    {
        Ok(()) => HttpResponse::Ok()
            .content_type(TEXT_HTML_UTF_8)
            .body("创建成功"),
        Err(error) => {
            error_logs_error(&req, "AddTaskError", "insert_scan_task", error.as_ref());
            HttpResponse::InternalServerError().body("500")
        }
    }
}

/// Creates the initial DNS task from an explicit domain list. DNS executions
/// use the same automatic, selected, or all-scanners dispatch contract as IP
/// tasks without inheriting the IP/CIDR target generator.
#[post("/api/task/create-dns")]
async fn create_dns_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    dns_follow_up: web::Data<RuntimeConfig<DnsFollowUpConfig>>,
    input: web::Json<CreateDnsTask>,
    user: UserBaseI,
) -> impl Responder {
    if !(0..=4).contains(&input.level) {
        return HttpResponse::BadRequest()
            .json(json!({"success": false, "message": "invalid task level"}));
    }
    if input.domains.is_empty() || input.domains.len() > 500 {
        return HttpResponse::BadRequest()
            .json(json!({"success": false, "message": "domains must contain 1 to 500 entries"}));
    }
    if input.dns_resolvers.len() > 8 {
        return HttpResponse::BadRequest().json(
            json!({"success": false, "message": "dns_resolvers must contain at most 8 entries"}),
        );
    }
    let mut dns_resolvers = match input
        .dns_resolvers
        .iter()
        .cloned()
        .map(CreateDnsResolver::normalize)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(resolvers) => resolvers,
        Err(error) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": error}));
        }
    };
    dns_resolvers.sort_by(|left, right| left.id.cmp(&right.id));
    if dns_resolvers
        .windows(2)
        .any(|pair| pair[0].id == pair[1].id)
    {
        return HttpResponse::BadRequest()
            .json(json!({"success": false, "message": "dns_resolvers contains duplicate IDs"}));
    }
    let requested_scan_profile = input.scan_profile.trim().to_ascii_lowercase();
    let resolved_scan = match resolve_dns_scan_request(
        &requested_scan_profile,
        input.follow_up_port_scan,
        input.follow_up_scan_profile.trim(),
    ) {
        Ok(resolved) => resolved,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    if resolved_scan.follow_up_profile.is_some() && !dns_follow_up.get().await.value.enabled {
        return HttpResponse::Conflict().json(json!({
            "success": false,
            "message": "DNS 解析后自动扫描未启用，请配置授权网段并启用 dns_follow_up"
        }));
    }
    let task_port = match resolve_dns_task_port(
        &resolved_scan.task_profile,
        resolved_scan.follow_up_profile.is_some(),
        input.port.as_deref(),
    ) {
        Ok(port) => port,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    let mut domains = match input
        .domains
        .iter()
        .map(|domain| crate::dns::canonical_scan_domain(domain))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(domains) => domains,
        Err(error) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": error}));
        }
    };
    domains.sort();
    domains.dedup();
    let mut connection = match pool.get().await {
        Ok(connection) => connection,
        Err(error) => {
            error_logs_error(
                &req,
                "CreateDnsTaskPoolError",
                "acquire_dns_task_connection",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let dispatch_mode = input.dispatch_mode.trim().to_ascii_lowercase();
    let requires_explicit_resolvers = !dns_resolvers.is_empty();
    let requires_ipv6_resolver = dns_resolvers.iter().any(|resolver| {
        resolver
            .ip
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_ipv6())
    });
    let requested_scanners: Vec<Option<String>> = match dispatch_mode.as_str() {
        "automatic" if input.scanner_ids.is_empty() => {
            match connection
                .query(
                    "SELECT 1 FROM scanner_info WHERE is_enable = true AND deleted_at IS NULL \
                     AND supports_ipv4 AND ipv4_ready AND scan_capabilities->'profiles' ? $1 \
                     AND ($2 = FALSE OR COALESCE((scan_capabilities->>'explicit_dns_resolvers')::BOOLEAN, FALSE)) \
                     AND ($3 = FALSE OR (supports_ipv6 AND ipv6_ready)) \
                     LIMIT 1;",
                    &[&resolved_scan.task_profile, &requires_explicit_resolvers, &requires_ipv6_resolver],
                )
                .await
            {
                Ok(rows) if !rows.is_empty() => {}
                Ok(_) => return HttpResponse::ServiceUnavailable().json(json!({
                    "success": false,
                    "message": "no DNS-capable scanner is currently available; enable DNS on a scanner and wait for its next heartbeat"
                })),
                Err(error) => {
                    error_logs_error(&req, "ResolveDnsTaskScannersError", "resolve_automatic_dns_scanner", &error);
                    return HttpResponse::InternalServerError().finish();
                }
            }
            vec![None]
        }
        "selected" if !input.scanner_ids.is_empty() => {
            let ids = input
                .scanner_ids
                .iter()
                .map(Uuid::to_string)
                .collect::<HashSet<_>>();
            let values = ids.into_iter().collect::<Vec<_>>();
            let rows = match connection
                .query(
                    "SELECT scanner_id FROM scanner_info WHERE scanner_id = ANY($1::text[]) \
                     AND is_enable = true AND deleted_at IS NULL AND supports_ipv4 AND ipv4_ready \
                     AND scan_capabilities->'profiles' ? $2 \
                     AND ($3 = FALSE OR COALESCE((scan_capabilities->>'explicit_dns_resolvers')::BOOLEAN, FALSE)) \
                     AND ($4 = FALSE OR (supports_ipv6 AND ipv6_ready)) \
                     ORDER BY scanner_id;",
                    &[&values, &resolved_scan.task_profile, &requires_explicit_resolvers, &requires_ipv6_resolver],
                )
                .await
            {
                Ok(rows) => rows,
                Err(error) => {
                    error_logs_error(&req, "ResolveDnsTaskScannersError", "resolve_selected_dns_scanners", &error);
                    return HttpResponse::InternalServerError().finish();
                }
            };
            if rows.len() != values.len() {
                return HttpResponse::BadRequest().json(json!({
                    "success": false,
                    "message": "selected scanner is unavailable or does not support the DNS task configuration"
                }));
            }
            rows.into_iter()
                .map(|row| Some(row.get("scanner_id")))
                .collect()
        }
        "all" if input.scanner_ids.is_empty() => {
            let rows = match connection
                .query(
                    "SELECT scanner_id FROM scanner_info WHERE is_enable = true AND deleted_at IS NULL \
                     AND supports_ipv4 AND ipv4_ready AND scan_capabilities->'profiles' ? $1 \
                     AND ($2 = FALSE OR COALESCE((scan_capabilities->>'explicit_dns_resolvers')::BOOLEAN, FALSE)) \
                     AND ($3 = FALSE OR (supports_ipv6 AND ipv6_ready)) \
                     ORDER BY scanner_id;",
                    &[&resolved_scan.task_profile, &requires_explicit_resolvers, &requires_ipv6_resolver],
                )
                .await
            {
                Ok(rows) => rows,
                Err(error) => {
                    error_logs_error(&req, "ResolveDnsTaskScannersError", "resolve_all_dns_scanners", &error);
                    return HttpResponse::InternalServerError().finish();
                }
            };
            if rows.is_empty() {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "success": false,
                    "message": "no DNS-capable scanner is currently available"
                }));
            }
            rows.into_iter()
                .map(|row| Some(row.get("scanner_id")))
                .collect()
        }
        _ => {
            return HttpResponse::BadRequest().json(json!({
                "success": false,
                "message": "invalid dispatch mode or scanner selection"
            }));
        }
    };
    let task_id = Uuid::now_v7().to_string();
    let generation_metadata = if let Some(follow_up_profile) = &resolved_scan.follow_up_profile {
        json!({"dns_follow_up": {
            "enabled": true,
            "scan_profile": follow_up_profile,
        }})
    } else {
        json!({})
    };
    let transaction = match connection.build_transaction().start().await {
        Ok(transaction) => transaction,
        Err(error) => {
            error_logs_error(
                &req,
                "CreateDnsTaskTransactionError",
                "start_transaction",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let task = match transaction
        .query_one(
            "INSERT INTO scan_task (user_id, task_id, task_initiator, task_target, task_port, task_level, remarks, \
             dispatch_mode, address_family, scan_profile, scan_plan, task_kind, dns_targets, dns_resolvers, generation_metadata) \
             VALUES ($1, $2, $3, ARRAY[]::INET[], $4, $5, $6, $7, 'ipv4', $8, \
             $9, 'dns', $10, $11, $12) RETURNING id;",
            &[
                &user.id,
                &task_id,
                &user.username,
                &task_port,
                &(i32::from(input.level)),
                &input.remark,
                &dispatch_mode,
                &resolved_scan.task_profile,
                &build_scan_plan(&resolved_scan.task_profile)
                    .expect("resolved DNS scan profile was validated"),
                &domains,
                &serde_json::to_value(&dns_resolvers).expect("DNS resolver input is serializable"),
                &generation_metadata,
            ],
        )
        .await
    {
        Ok(task) => task,
        Err(error) => {
            error_logs_error(&req, "CreateDnsTaskError", "insert_scan_task", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let task_db_id: i32 = task.get("id");
    for requested_scanner in &requested_scanners {
        if let Err(error) = transaction
            .execute(
                "INSERT INTO scan_task_execution (execution_id, task_id, requested_scanner_id) VALUES ($1, $2, $3);",
                &[&Uuid::now_v7().to_string(), &task_db_id, requested_scanner],
            )
            .await
        {
            error_logs_error(&req, "CreateDnsTaskExecutionError", "insert_task_execution", &error);
            return HttpResponse::InternalServerError().finish();
        }
    }
    let mut audit_event = audit::AuditEvent::user("task", "task.create_dns", "success", &user)
        .resource("task", task_id.clone());
    audit_event.response_status = Some(200);
    audit_event.metadata = json!({
        "target_count": domains.len(),
        "requested_scan_profile": requested_scan_profile,
        "task_scan_profile": resolved_scan.task_profile,
        "dispatch_mode": dispatch_mode,
        "scanner_count": requested_scanners.len(),
        "dns_resolver_count": dns_resolvers.len(),
        "follow_up_scan_profile": resolved_scan.follow_up_profile,
    });
    if let Err(error) = audit::write(
        &transaction,
        &AuditContext::from_request(&req),
        &audit_event,
    )
    .await
    {
        error_logs_error(&req, "CreateDnsTaskAuditError", "write_audit_event", &error);
        return HttpResponse::InternalServerError().finish();
    }
    if let Err(error) = transaction.commit().await {
        error_logs_error(
            &req,
            "CreateDnsTaskCommitError",
            "commit_transaction",
            &error,
        );
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().json(json!({
        "success": true,
        "task_id": task_id,
        "domains": domains,
        "dns_resolvers": dns_resolvers,
        "scan_profile": requested_scan_profile,
        "task_scan_profile": resolved_scan.task_profile,
        "dispatch_mode": dispatch_mode,
        "scanner_count": requested_scanners.len(),
        "follow_up_scan_profile": resolved_scan.follow_up_profile,
    }))
}

/// 返回并续租当前扫描器已经持有的未完成任务。
#[get("/api/task/current")]
async fn current_task_handler(
    req: HttpRequest,
    query: web::Query<CurrentTaskQuery>,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
) -> impl Responder {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let Some(token) = token else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };

    let maintenance_snapshot = maintenance.snapshot().await;
    let blocks_recovery = maintenance_snapshot.blocks_all_scanner_requests()
        || (query.taskid.is_none() && maintenance_snapshot.blocks_new_work());
    if let Some(response) = maintenance_gate_for_runtime_scanner(
        pool.get_ref(),
        security.get_ref(),
        query.scannerid,
        token,
        maintenance_snapshot,
        blocks_recovery,
    )
    .await
    {
        return response;
    }

    let recovery_failure = match (query.failure_taskid, query.failure_count) {
        (None, None) => None,
        (Some(task_id), Some(count)) if (1..=3).contains(&count) => {
            Some(crate::scan_control::dispatch::RecoveryFailureReport { task_id, count })
        }
        _ => {
            return HttpResponse::BadRequest()
                .body("failure_taskid and failure_count (1..=3) must be supplied together");
        }
    };
    match crate::scan_control::dispatch::recover_scanner_task_with_failure(
        pool.get_ref(),
        query.scannerid,
        query.taskid,
        query.uploadid,
        recovery_failure,
        token,
        &security.scanner_token_pepper,
    )
    .await
    {
        Ok(task) => HttpResponse::Ok().json(task),
        Err(ApplyTaskError::ScannerUnauthorized) => {
            HttpResponse::Unauthorized().body("unauthorized")
        }
        Err(ApplyTaskError::NoTask) => HttpResponse::NoContent().finish(),
        Err(ApplyTaskError::UnfinishedTask(_)) => unreachable!("recovery never claims new work"),
        Err(ApplyTaskError::Database(error)) => {
            error_logs_error(
                &req,
                "RecoverTaskDatabaseError",
                "recover_scanner_task",
                error.as_ref(),
            );
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// 用于扫描器申请一个扫描目标
#[get("/api/task/apply")]
async fn apply_task_handler(
    req: HttpRequest,
    scanner_id: web::Query<ApplyTaskQuery>,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
) -> impl Responder {
    let database_conn = pool.get_ref();
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let Some(token) = token else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };

    let maintenance_snapshot = maintenance.snapshot().await;
    if let Some(response) = maintenance_gate_for_runtime_scanner(
        database_conn,
        security.get_ref(),
        scanner_id.scannerid,
        token,
        maintenance_snapshot.clone(),
        maintenance_snapshot.blocks_new_work(),
    )
    .await
    {
        return response;
    }

    if scanner_id.dryrun.unwrap_or(false) {
        return match validate_scanner_credentials(
            database_conn,
            scanner_id.scannerid,
            token,
            &security.scanner_token_pepper,
        )
        .await
        {
            Ok(()) => HttpResponse::Ok().finish(),
            Err(ApplyTaskError::ScannerUnauthorized) => {
                HttpResponse::Unauthorized().body("unauthorized")
            }
            Err(ApplyTaskError::UnfinishedTask(task_id)) => HttpResponse::Conflict().json(json!({
                "success": false,
                "code": "unfinished_task_exists",
                "task_id": task_id,
            })),
            Err(ApplyTaskError::NoTask) => HttpResponse::NoContent().finish(),
            Err(ApplyTaskError::Database(e)) => {
                error_logs_error(
                    &req,
                    "ScannerCredentialCheckError",
                    "validate_scanner_credentials",
                    e.as_ref(),
                );
                HttpResponse::InternalServerError().finish()
            }
        };
    }

    match apply_task(
        database_conn,
        scanner_id.scannerid,
        token,
        &security.scanner_token_pepper,
    )
    .await
    {
        Ok(a_t) => HttpResponse::Ok().json(a_t),
        Err(ApplyTaskError::ScannerUnauthorized) => {
            HttpResponse::Unauthorized().body("unauthorized")
        }
        Err(ApplyTaskError::UnfinishedTask(task_id)) => HttpResponse::Conflict().json(json!({
            "success": false,
            "code": "unfinished_task_exists",
            "task_id": task_id,
        })),
        Err(ApplyTaskError::NoTask) => HttpResponse::NoContent().finish(),
        Err(ApplyTaskError::Database(e)) => {
            error_logs_error(
                &req,
                "ApplyTaskDatabaseError",
                "claim_scan_task",
                e.as_ref(),
            );
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// 用于扫描器上传扫描结果。
#[post("/api/scanner/result")]
#[allow(clippy::too_many_arguments)] // request-scoped dependencies supplied by Actix extractors
async fn upload_scanner_result_handler(
    req: HttpRequest,
    pool: web::Data<Pool>,
    maxmind: web::Data<MaxMindState>,
    elasticsearch: web::Data<crate::elasticsearch::ElasticsearchService>,
    dns_follow_up: web::Data<RuntimeConfig<DnsFollowUpConfig>>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
    upload_data: web::Json<ScannerResultUpload>,
) -> impl Responder {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let Some(token) = token else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };

    let maintenance_snapshot = maintenance.snapshot().await;
    if let Some(response) = maintenance_gate_for_runtime_scanner(
        pool.get_ref(),
        security.get_ref(),
        upload_data.scanner_id,
        token,
        maintenance_snapshot.clone(),
        maintenance_snapshot.blocks_all_scanner_requests(),
    )
    .await
    {
        return response;
    }

    let dns_follow_up = dns_follow_up.get().await.value;
    match save_scanner_results(
        pool.get_ref(),
        maxmind.get_ref(),
        elasticsearch.get_ref(),
        &dns_follow_up,
        &upload_data,
        token,
        &security.scanner_token_pepper,
    )
    .await
    {
        Ok(saved) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "saved": saved,
        })),
        Err(e) => {
            log_scanner_result_error(&req, &upload_data, &e);
            match e {
                SaveScannerResultsError::InvalidIp { .. } => {
                    HttpResponse::BadRequest().body("invalid ip")
                }
                SaveScannerResultsError::InvalidUpload(message) => {
                    HttpResponse::BadRequest().body(message)
                }
                SaveScannerResultsError::UnsupportedProtocolVersion { received } => {
                    HttpResponse::BadRequest()
                        .body(format!("unsupported protocol_version {received}"))
                }
                SaveScannerResultsError::InvalidBatchEnvelope { reason, .. } => {
                    HttpResponse::BadRequest().body(reason)
                }
                SaveScannerResultsError::UploadIdentityConflict {
                    execution_id,
                    ref conflicting_upload_id,
                    ..
                } => HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "code": "execution_upload_id_conflict",
                    "message": "an execution cannot contain batches from multiple upload_id values",
                    "retryable": false,
                    "action": "recover_execution",
                    "execution_id": execution_id,
                    "conflicting_upload_id": conflicting_upload_id,
                })),
                SaveScannerResultsError::BatchPayloadConflict { content_kind, .. } => {
                    HttpResponse::BadRequest().body(format!(
                        "batch identity was already used with different {content_kind} content"
                    ))
                }
                SaveScannerResultsError::NonContiguousFinalBatch { content_kind, .. } => {
                    HttpResponse::BadRequest().body(format!(
                        "final {content_kind} batch requires one contiguous sequence starting at batch_index 0"
                    ))
                }
                SaveScannerResultsError::CompletedExecutionNewBatch { .. } => {
                    HttpResponse::BadRequest()
                        .body("completed execution cannot accept a new batch")
                }
                SaveScannerResultsError::ObservationLimitExceeded { actual, limit } => {
                    HttpResponse::BadRequest()
                        .body(format!("observation count {actual} exceeds limit {limit}"))
                }
                SaveScannerResultsError::ScannerUnauthorized => {
                    HttpResponse::Unauthorized().body("unauthorized")
                }
                SaveScannerResultsError::TaskNotFound => {
                    HttpResponse::NotFound().body("task not found")
                }
                SaveScannerResultsError::TaskNotOwned => {
                    HttpResponse::Conflict().body("task is not owned by scanner")
                }
                SaveScannerResultsError::Database(_) if e.retryable() => {
                    HttpResponse::ServiceUnavailable()
                        .insert_header((header::RETRY_AFTER, "2"))
                        .body("scan database temporarily busy")
                }
                SaveScannerResultsError::Database(_) => {
                    HttpResponse::InternalServerError().body("500")
                }
                SaveScannerResultsError::Storage(_) => {
                    HttpResponse::ServiceUnavailable().body("scan storage unavailable")
                }
                SaveScannerResultsError::BatchBusy {
                    retry_after_seconds,
                } => HttpResponse::ServiceUnavailable()
                    .insert_header((header::RETRY_AFTER, retry_after_seconds.to_string()))
                    .body("scan result batch is already being written"),
            }
        }
    }
}

/// 获取所有任务接口
///
/// 分为管理员权限和普通用户权限
fn normalize_task_list_text(
    value: &Option<String>,
    max_length: usize,
    field_name: &str,
) -> Result<Option<String>, String> {
    let Some(value) = value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    if value.chars().count() > max_length {
        return Err(format!("{field_name}长度不能超过 {max_length} 个字符"));
    }
    Ok(Some(value.to_owned()))
}

fn normalize_task_list_query(query: &ReceiveTaskItemQueryInfo) -> Result<TaskListFilters, String> {
    let limit = query.limit.unwrap_or(20);
    if !(1..=100).contains(&limit) {
        return Err("limit 必须在 1 到 100 之间".to_owned());
    }
    if query.cursor.is_some_and(|cursor| cursor <= 0) {
        return Err("cursor 必须是正整数".to_owned());
    }
    if query.start_time.is_some_and(|value| value < 0)
        || query.end_time.is_some_and(|value| value < 0)
    {
        return Err("时间范围不能为负数".to_owned());
    }
    if matches!((query.start_time, query.end_time), (Some(start), Some(end)) if start > end) {
        return Err("开始时间不能晚于结束时间".to_owned());
    }
    let status = normalize_task_list_text(&query.status, 32, "状态")?;
    if status.as_deref().is_some_and(|value| {
        !matches!(
            value,
            "pending" | "running" | "succeeded" | "failed" | "cancelled" | "partial"
        )
    }) {
        return Err("任务状态无效".to_owned());
    }
    Ok(TaskListFilters {
        cursor: query.cursor,
        limit,
        include_system: query.include_system.unwrap_or(false),
        task_id: normalize_task_list_text(&query.task_id, 36, "任务 ID")?,
        target: normalize_task_list_text(&query.target, 128, "目标")?,
        status,
        operator: normalize_task_list_text(&query.operator, 64, "操作者")?,
        start_time: query.start_time,
        end_time: query.end_time,
        scanner_id: normalize_task_list_text(&query.scanner_id, 36, "扫描器 ID")?,
    })
}

#[get("/api/task/all")]
async fn get_all_task_handler(
    _req: HttpRequest,
    query_info: web::Query<ReceiveTaskItemQueryInfo>,
    pool: web::Data<Pool>,
    user_base_i: UserBaseI,
) -> impl Responder {
    let p = pool.get_ref();
    let filters = match normalize_task_list_query(&query_info) {
        Ok(value) => value,
        Err(message) => {
            return HttpResponse::BadRequest().json(serde_json::json!({"message": message}));
        }
    };

    let user_id = user_base_i.id;
    let user_role = user_base_i.role;

    let permi = match user_role {
        1 => Permission::Administrator(user_id),
        2 => Permission::Users(user_id),
        _ => {
            error!(
                event = "UserRoleValueInvalid",
                operation = "authorize_task_list",
                error_kind = "data_integrity",
                error_code = "user_role_invalid",
                error_message = "stored user role is outside the supported set",
                retryable = false,
                outcome = "request_failed",
                user_id,
                user_role,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    let page = match get_filtered_task_page(p, &filters, permi).await {
        Ok(o) => o,
        Err(e) => {
            let diagnostics = crate::logs::write::error_diagnostics(e.as_ref());
            error!(
                event = "GetTaskError",
                operation = "list_tasks",
                error_kind = "database",
                error_code = "task_list_query_failed",
                error_message = %diagnostics.error_message,
                error_chain = %diagnostics.error_chain,
                root_cause = %diagnostics.root_cause,
                error_truncated = diagnostics.error_truncated,
                retryable = false,
                outcome = "request_failed",
                user_id,
                user_role,
                cursor = ?filters.cursor,
                limit = filters.limit,
                include_system = filters.include_system,
            );
            return HttpResponse::InternalServerError().body("500");
        }
    };

    let tmp_json = TaskItemJson {
        total: page.total,
        page_size: page.page_size,
        next_cursor: page.next_cursor,
        has_more: page.has_more,
        items: page.items,
    };

    HttpResponse::Ok().json(tmp_json)
}

#[cfg(test)]
mod tests {
    use super::{
        CreateDnsTask, ScannerHeartbeatLease, ScannerHeartbeatResponse, ScannerLatencyReport,
        ScannerScanCapabilities, build_dns_comparison, normalize_task_list_query,
        resolve_dns_scan_request, resolve_dns_task_port, should_load_endpoint_results,
        should_load_vulnerabilities, task_result_pagination, validate_latency_report,
        validate_public_ip, vulnerability_search_body,
    };
    use crate::scan_control::query::ReceiveTaskItemQueryInfo;
    use actix_web::web;
    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn vulnerability_search_uses_sortable_stable_tie_breaker() {
        let body = vulnerability_search_body("019c0000-0000-7000-8000-000000000001");

        assert_eq!(
            body["sort"],
            json!([
                {"observed_at": {"order": "desc", "format": "epoch_millis"}},
                {"observation_key": "asc"}
            ])
        );
        assert!(!body.to_string().contains("\"_id\""));
    }

    #[test]
    fn dns_task_dispatch_defaults_to_automatic_and_accepts_selected_scanners() {
        let automatic: CreateDnsTask = serde_json::from_value(json!({
            "domains": ["example.com"],
            "level": 1
        }))
        .unwrap();
        assert_eq!(automatic.dispatch_mode, "automatic");
        assert!(automatic.scanner_ids.is_empty());

        let scanner_id = Uuid::now_v7();
        let selected: CreateDnsTask = serde_json::from_value(json!({
            "domains": ["example.com"],
            "level": 1,
            "dispatch_mode": "selected",
            "scanner_ids": [scanner_id]
        }))
        .unwrap();
        assert_eq!(selected.dispatch_mode, "selected");
        assert_eq!(selected.scanner_ids, vec![scanner_id]);
    }

    #[test]
    fn latency_reports_are_bounded_and_recomputed() {
        let report = ScannerLatencyReport {
            version: 1,
            probe_id: Uuid::now_v7(),
            rtt_us: 42_000,
            server_processing_us: 7_000,
            network_rtt_us: 1,
            server_sent_at_ms: Utc::now().timestamp_millis(),
        };
        let validated = validate_latency_report(&report).expect("valid latency report");
        assert_eq!(validated.network_rtt_us, 35_000);

        let invalid = ScannerLatencyReport {
            server_processing_us: 50_000,
            ..report
        };
        assert!(validate_latency_report(&invalid).is_err());
    }

    #[test]
    fn task_list_query_excludes_system_tasks_by_default() {
        let default_query =
            web::Query::<ReceiveTaskItemQueryInfo>::from_query("").expect("empty query is valid");
        assert!(!default_query.include_system.unwrap_or(false));
        let normalized = normalize_task_list_query(&default_query).expect("normalize defaults");
        assert_eq!(normalized.limit, 20);
        assert!(!normalized.include_system);

        let include_query =
            web::Query::<ReceiveTaskItemQueryInfo>::from_query("include_system=true&count=10")
                .expect("include_system query is valid");
        assert_eq!(include_query.include_system, Some(true));
        assert_eq!(include_query.limit, Some(10));
    }

    #[test]
    fn task_list_query_validates_filters_and_pagination() {
        let valid = web::Query::<ReceiveTaskItemQueryInfo>::from_query(
            "limit=20&status=running&operator=admin&start_time=10&end_time=20",
        )
        .expect("valid task query");
        let normalized = normalize_task_list_query(&valid).expect("normalize task query");
        assert_eq!(normalized.limit, 20);
        assert_eq!(normalized.status.as_deref(), Some("running"));
        assert_eq!(normalized.operator.as_deref(), Some("admin"));

        let invalid_status = web::Query::<ReceiveTaskItemQueryInfo>::from_query("status=unknown")
            .expect("deserialize invalid status");
        assert!(normalize_task_list_query(&invalid_status).is_err());

        let invalid_range =
            web::Query::<ReceiveTaskItemQueryInfo>::from_query("start_time=20&end_time=10")
                .expect("deserialize invalid range");
        assert!(normalize_task_list_query(&invalid_range).is_err());

        let invalid_cursor = web::Query::<ReceiveTaskItemQueryInfo>::from_query("cursor=0")
            .expect("deserialize invalid cursor");
        assert!(normalize_task_list_query(&invalid_cursor).is_err());
    }

    #[test]
    fn task_result_pagination_uses_safe_bounds() {
        assert_eq!(task_result_pagination(None, None), (1, 20, 0));
        assert_eq!(task_result_pagination(Some(-5), Some(0)), (1, 1, 0));
        assert_eq!(task_result_pagination(Some(3), Some(500)), (3, 100, 200));
    }

    #[test]
    fn task_detail_skips_elasticsearch_when_no_indexed_results_exist() {
        for task_kind in ["ip", "dns"] {
            assert!(!should_load_endpoint_results(task_kind, 0));
            assert!(!should_load_vulnerabilities(
                task_kind,
                "vulnerability_scan",
                0
            ));
        }
    }

    #[test]
    fn task_detail_only_loads_relevant_elasticsearch_results() {
        assert!(should_load_endpoint_results("ip", 1));
        assert!(!should_load_endpoint_results("dns", 1));
        assert!(should_load_vulnerabilities("ip", "vulnerability_scan", 1));
        assert!(!should_load_vulnerabilities("ip", "port_only", 1));
        assert!(!should_load_vulnerabilities("dns", "vulnerability_scan", 1));
    }

    #[test]
    fn public_probe_addresses_must_match_the_reported_family() {
        assert_eq!(
            validate_public_ip(Some("203.0.113.10"), false).unwrap(),
            Some("203.0.113.10".to_owned())
        );
        assert_eq!(
            validate_public_ip(Some("::ffff:64.81.116.137"), false).unwrap(),
            Some("64.81.116.137".to_owned())
        );
        assert!(validate_public_ip(Some("2001:db8::1"), false).is_err());
        assert!(validate_public_ip(Some("::ffff:64.81.116.137"), true).is_err());
        assert!(validate_public_ip(Some("not-an-ip"), true).is_err());
    }

    #[test]
    fn scan_capabilities_are_allowlisted() {
        let valid = ScannerScanCapabilities {
            plan_versions: vec![1],
            profiles: vec![
                "legacy".into(),
                "port_only".into(),
                "vulnerability_scan".into(),
            ],
            stages: vec!["port_discovery".into(), "vulnerability_detection".into()],
            explicit_dns_resolvers: false,
        };
        assert!(valid.validate().is_ok());

        let invalid = ScannerScanCapabilities {
            plan_versions: vec![1],
            profiles: vec!["run_arbitrary_command".into()],
            stages: vec!["port_discovery".into()],
            explicit_dns_resolvers: false,
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn database_schema_allows_all_scan_profiles() {
        let initialization_sql = include_str!("../../source/database/init.sql");

        for profile in [
            "legacy",
            "port_only",
            "service_inventory",
            "vulnerability_scan",
            "dns_records",
            "dns_ports",
            "dns_full",
        ] {
            assert!(
                initialization_sql.contains(&format!("'{profile}'")),
                "database schema must allow {profile}"
            );
        }
    }

    #[test]
    fn database_schema_indexes_running_execution_recovery() {
        let initialization_sql = include_str!("../../source/database/init.sql");
        assert!(initialization_sql.contains("idx_scan_task_execution_running_scanner"));
        assert!(initialization_sql.contains("ON scan_task_execution (assigned_scanner_id)"));
    }

    #[test]
    fn database_schema_indexes_bounded_task_claim_paths() {
        let initialization_sql = include_str!("../../source/database/init.sql");
        for index in [
            "idx_scan_task_claim_priority",
            "idx_scan_task_execution_selected_pending",
            "idx_scan_task_execution_public_pending",
            "idx_scan_task_execution_expired_running",
            "idx_scan_task_execution_cancel_reaper",
        ] {
            assert!(initialization_sql.contains(index));
        }
        let online_migration =
            include_str!("../../source/database/migrate_dns_lease_and_dispatch.sql");
        assert!(online_migration.contains("CREATE INDEX CONCURRENTLY"));
    }

    #[test]
    fn dns_port_scan_uses_all_ports_when_port_is_blank() {
        for port in [None, Some(""), Some("  ")] {
            assert_eq!(
                resolve_dns_task_port("dns_full", false, port).unwrap(),
                "1-65535"
            );
        }
        assert_eq!(
            resolve_dns_task_port("dns_ports", false, Some("80,443")).unwrap(),
            "80,443"
        );
        assert_eq!(
            resolve_dns_task_port("dns_ports", false, Some("80,abc")).unwrap_err(),
            "invalid port range"
        );
    }

    #[test]
    fn dns_only_mode_rejects_ports() {
        assert_eq!(
            resolve_dns_task_port("dns_records", false, Some("53")).unwrap_err(),
            "port must be omitted for DNS-only tasks"
        );
        assert_eq!(
            resolve_dns_task_port("dns_records", false, Some("  ")).unwrap(),
            "53"
        );
    }

    #[test]
    fn unified_domain_modes_resolve_to_dns_parent_and_ip_follow_up() {
        for profile in ["port_only", "service_inventory", "vulnerability_scan"] {
            let resolved = resolve_dns_scan_request(profile, false, "port_only").unwrap();
            assert_eq!(resolved.task_profile, "dns_records");
            assert_eq!(resolved.follow_up_profile.as_deref(), Some(profile));
        }

        let dns_only = resolve_dns_scan_request("dns_records", false, "port_only").unwrap();
        assert_eq!(dns_only.task_profile, "dns_records");
        assert_eq!(dns_only.follow_up_profile, None);
        assert!(resolve_dns_scan_request("unsupported", false, "port_only").is_err());
    }

    #[test]
    fn legacy_dns_follow_up_accepts_vulnerability_profile() {
        let resolved = resolve_dns_scan_request("dns_records", true, "vulnerability_scan").unwrap();
        assert_eq!(resolved.task_profile, "dns_records");
        assert_eq!(
            resolved.follow_up_profile.as_deref(),
            Some("vulnerability_scan")
        );
    }

    #[test]
    fn dns_comparison_groups_answers_by_resolver_and_question() {
        let comparison = build_dns_comparison(&json!({
            "hits": {"hits": [
                {"_source": {
                    "@timestamp": "2026-01-01T00:00:00Z", "dns_view": {"id": "dns-a"},
                    "resolver": {"id": "dns-a", "label": "DNS A", "ip": "192.0.2.53", "port": 53, "transport": "udp"},
                    "dns": {"question": {"name": "example.com", "type": "A"}, "response_code": "NOERROR", "answers": [{"type": "A", "value": "192.0.2.10", "ttl": 60}]}
                }},
                {"_source": {
                    "@timestamp": "2026-01-01T00:00:01Z", "dns_view": {"id": "dns-b"},
                    "resolver": {"id": "dns-b", "label": "DNS B", "ip": "192.0.2.54", "port": 53, "transport": "udp"},
                    "dns": {"question": {"name": "example.com", "type": "A"}, "response_code": "NOERROR", "answers": [{"type": "A", "value": "192.0.2.10", "ttl": 55}, {"type": "A", "value": "192.0.2.11", "ttl": 60}]}
                }}
            ]}
        }));
        assert_eq!(comparison.len(), 1);
        assert_eq!(comparison[0].resolvers.len(), 2);
        assert_eq!(comparison[0].common_answers.len(), 1);
        assert_eq!(comparison[0].differences.len(), 1);
    }

    #[test]
    fn heartbeat_reports_lost_task_lease_explicitly() {
        let task_id = uuid::Uuid::now_v7();
        let body = serde_json::to_value(ScannerHeartbeatResponse {
            diagnostics_enabled: false,
            diagnostic_requests: Vec::new(),
            success: true,
            lease: Some(ScannerHeartbeatLease {
                task_id,
                status: "lost",
                expires_at_ms: None,
                ttl_ms: crate::scan_control::dispatch::TASK_LEASE_MS,
                maintenance_hold: false,
            }),
            command: None,
            maintenance: None,
            configuration: None,
        })
        .unwrap();

        assert_eq!(body["lease"]["task_id"], task_id.to_string());
        assert_eq!(body["lease"]["status"], "lost");
        assert!(body["lease"]["expires_at_ms"].is_null());
        assert_eq!(
            body["lease"]["ttl_ms"],
            crate::scan_control::dispatch::TASK_LEASE_MS
        );
        assert_eq!(body["lease"]["maintenance_hold"], false);
    }
}
