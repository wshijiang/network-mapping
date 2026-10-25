use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use deadpool_postgres::{GenericClient, Pool};
use futures_util::{StreamExt, stream};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{Notify, Semaphore};

mod domain_discovery;
mod os_detection;
mod projection;
mod transport_rebuild;
mod web_detection;
use os_detection::service_observation_reference;
use tokio::time::{interval, sleep, timeout};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::cli_progress::{NoopProgressReporter, ProgressReporter, ProgressUpdate};
use crate::config::{ElasticsearchConfig, ScanStorageMode};
use crate::dns::DnsObservation;
use crate::handlers::tags::AssetTag;
use crate::monitor::{ElasticsearchObservation, ElasticsearchOperationKind, MonitorHandle};
use crate::result_ingest::telemetry::WriteStage;

#[derive(Default)]
struct BulkTiming {
    queue_wait_ms: u64,
    request_ms: u64,
    backoff_ms: u64,
    attempts: u32,
    acquired: bool,
    request_started: Option<Instant>,
    backoff_started: Option<Instant>,
}

const OUTBOX_LOCK_TIMEOUT_MINUTES: i64 = 5;
const SCAN_INDEX_SCHEMA_VERSION: &str = "5";
const ENDPOINT_INDEX_SCHEMA_VERSION: &str = "8";
// Leave headroom beneath Elasticsearch's default 4 KiB HTTP request-line limit.
const SCAN_REQUEST_LINE_BUDGET: usize = 3 * 1024;
const SCAN_INDEX_OPTIONS: &str = "allow_no_indices=true&ignore_unavailable=true";
const DNS_INDEX_SCHEMA_VERSION: &str = "2";
const MAX_DOMAIN_RECORDS: usize = 10_000;
const MAX_DOMAIN_NAMES: usize = 1_000;
const MAX_DOMAIN_CNAME_DEPTH: usize = 8;
const SCAN_MIGRATION_STATE_KEY: &str = "elasticsearch_scan_migration";
const ENSURE_SCAN_MIGRATION_INDEX_SQL: &str = "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_observation_batch_id_id \
     ON scan_observation(batch_id, id);";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SearchSort {
    field: SearchSortField,
    descending: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SearchSortField {
    LastSeen,
    FirstSeen,
    Ip,
    Port,
}

impl Default for SearchSort {
    fn default() -> Self {
        Self {
            field: SearchSortField::LastSeen,
            descending: true,
        }
    }
}

impl SearchSort {
    pub(crate) fn parse(field: Option<&str>, order: Option<&str>) -> Result<Self, &'static str> {
        let field = match field.unwrap_or("last_seen") {
            "last_seen" => SearchSortField::LastSeen,
            "first_seen" => SearchSortField::FirstSeen,
            "ip" => SearchSortField::Ip,
            "port" => SearchSortField::Port,
            _ => return Err("sort_field 不支持该字段"),
        };
        let descending = match order {
            Some("asc") => false,
            Some("desc") => true,
            None => matches!(
                field,
                SearchSortField::LastSeen | SearchSortField::FirstSeen
            ),
            _ => return Err("sort_order 必须是 asc 或 desc"),
        };
        Ok(Self { field, descending })
    }

    pub(crate) fn field_name(self) -> &'static str {
        match self.field {
            SearchSortField::LastSeen => "last_seen",
            SearchSortField::FirstSeen => "first_seen",
            SearchSortField::Ip => "ip",
            SearchSortField::Port => "port",
        }
    }

    pub(crate) fn order_name(self) -> &'static str {
        if self.descending { "desc" } else { "asc" }
    }

    fn clauses(self) -> Vec<Value> {
        let primary = match self.field {
            SearchSortField::LastSeen => {
                json!({"last_seen": {"order": self.order_name(), "missing": "_last"}})
            }
            SearchSortField::FirstSeen => {
                json!({"first_seen": {"order": self.order_name(), "missing": "_last"}})
            }
            SearchSortField::Ip => json!({"ip": {"order": self.order_name()}}),
            SearchSortField::Port => json!({"port": {"order": self.order_name()}}),
        };
        let mut clauses = vec![primary];
        if self.field != SearchSortField::LastSeen {
            clauses.push(json!({"last_seen": {"order": "desc", "missing": "_last"}}));
        }
        if self.field != SearchSortField::Ip {
            clauses.push(json!({"ip": {"order": "asc"}}));
        }
        if self.field != SearchSortField::Port {
            clauses.push(json!({"port": {"order": "asc"}}));
        }
        clauses.push(json!({"endpoint_key": {"order": "asc"}}));
        clauses
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ScanBatchContext {
    pub(crate) task_id: String,
    pub(crate) execution_id: String,
    pub(crate) user_id: i32,
    pub(crate) task_source: String,
    pub(crate) scanner_id: String,
    pub(crate) scanner_name: Option<String>,
    pub(crate) upload_id: String,
    pub(crate) batch_index: i32,
    pub(crate) is_final: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DnsWriteMode {
    Fresh,
    Reconcile,
}

#[derive(Clone, Debug)]
pub(crate) struct ScanBatchWriteResult {
    pub(crate) payload_checksum: String,
    pub(crate) indices: Vec<String>,
    pub(crate) execution_summary: Option<ScanExecutionSummary>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ScanExecutionSummary {
    pub(crate) ip_count: i64,
    pub(crate) port_count: i64,
    pub(crate) observation_count: i64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ScanMigrationReport {
    pub batches: u64,
    pub observations: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ScanQueryIndex {
    Observations,
    ExecutionEndpoints,
    CurrentEndpoints,
}

#[derive(Clone)]
pub struct ElasticsearchService {
    inner: Arc<ElasticsearchInner>,
}

struct ElasticsearchInner {
    config: ElasticsearchConfig,
    client: reqwest::Client,
    runtime: RwLock<ElasticsearchRuntime>,
    monitor: RwLock<Option<MonitorHandle>>,
    maintenance_run_id: RwLock<Option<String>>,
    bulk_semaphore: Semaphore,
    projection_notify: Notify,
    scan_indices_ready: AtomicBool,
    observation_compatibility_ready: AtomicBool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ElasticsearchRuntime {
    pub connected: bool,
    pub read_ready: bool,
    pub server_version: Option<String>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ElasticsearchStatus {
    pub enabled: bool,
    pub read_enabled: bool,
    pub fallback_to_postgres: bool,
    pub url: String,
    pub index: String,
    pub scan_storage: ScanStorageMode,
    pub observation_index_prefix: String,
    pub execution_endpoint_index: String,
    pub current_endpoint_index: String,
    pub dns_observation_data_stream: String,
    pub dns_record_index: String,
    pub expected_version: String,
    #[serde(flatten)]
    pub runtime: ElasticsearchRuntime,
    pub pending_events: i64,
    pub oldest_pending_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ElasticsearchIndexStorage {
    pub(crate) primary: i64,
    pub(crate) replica: i64,
    pub(crate) total: i64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ElasticsearchStorageMetrics {
    pub(crate) enabled: bool,
    pub(crate) available: bool,
    pub(crate) primary_size: Option<i64>,
    pub(crate) replica_size: Option<i64>,
    pub(crate) total_size: Option<i64>,
    pub(crate) indices: BTreeMap<String, ElasticsearchIndexStorage>,
}

impl ElasticsearchStorageMetrics {
    pub(crate) fn unavailable(enabled: bool) -> Self {
        Self {
            enabled,
            available: false,
            primary_size: None,
            replica_size: None,
            total_size: None,
            indices: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct SearchSource {
    ip: String,
    port: i32,
    protocol: Option<String>,
    service: Option<String>,
    banner: Option<String>,
    title: Option<String>,
    tls_mode: Option<String>,
    tls_version: Option<String>,
    tls_cipher_suite: Option<String>,
    tls_subject: Option<String>,
    tls_issuer: Option<String>,
    #[serde(default)]
    tls_names: Vec<String>,
    tls_serial_number: Option<String>,
    tls_not_before: Option<DateTime<Utc>>,
    tls_not_after: Option<DateTime<Utc>>,
    tls_fingerprint_sha256: Option<String>,
    tls_self_signed: Option<bool>,
    os: Option<crate::os_detection::OsInference>,
    web: Option<crate::web_detection::WebInference>,
    scanner_name: Option<String>,
    last_seen: DateTime<Utc>,
    asn: Option<String>,
    isp: Option<String>,
    as_org: Option<String>,
    country_code: Option<String>,
    country_name: Option<String>,
    region_name: Option<String>,
    city_name: Option<String>,
    #[serde(default)]
    tags: Vec<AssetTag>,
}

#[derive(Debug)]
pub(crate) struct ElasticsearchSearchItem {
    pub(crate) ip_address: String,
    pub(crate) port: i32,
    pub(crate) protocol: Option<String>,
    pub(crate) service: Option<String>,
    pub(crate) banner: Option<String>,
    pub(crate) title: Option<String>,
    pub(crate) tls_mode: Option<String>,
    pub(crate) tls_version: Option<String>,
    pub(crate) tls_cipher_suite: Option<String>,
    pub(crate) tls_subject: Option<String>,
    pub(crate) tls_issuer: Option<String>,
    pub(crate) tls_names: Vec<String>,
    pub(crate) tls_serial_number: Option<String>,
    pub(crate) tls_not_before: Option<i64>,
    pub(crate) tls_not_after: Option<i64>,
    pub(crate) tls_fingerprint_sha256: Option<String>,
    pub(crate) tls_self_signed: Option<bool>,
    pub(crate) os: Option<crate::os_detection::OsInference>,
    pub(crate) web: Option<crate::web_detection::WebInference>,
    pub(crate) scanner_name: Option<String>,
    pub(crate) scan_time: i64,
    pub(crate) asn: Option<String>,
    pub(crate) isp: Option<String>,
    pub(crate) as_org: Option<String>,
    pub(crate) country_code: Option<String>,
    pub(crate) country_name: Option<String>,
    pub(crate) region_name: Option<String>,
    pub(crate) city_name: Option<String>,
    pub(crate) tags: Vec<AssetTag>,
}

#[derive(Debug)]
pub(crate) struct ElasticsearchSearchPage {
    pub(crate) items: Vec<ElasticsearchSearchItem>,
    pub(crate) total: i64,
}

#[derive(Debug)]
struct OutboxEvent {
    id: i64,
    aggregate_key: String,
    attempts: i32,
}

#[derive(Clone, Copy, Debug)]
enum ElasticsearchOperation {
    StorageMetrics,
    ScanQuery,
    RefreshTags,
    BulkWrite,
    ClusterInfo,
    IndexAdmin,
    ExecutionSummary,
    ConflictCheck,
    ProjectionSearch,
    AssetSearch,
    EndpointFilter,
    DomainFilter,
}

impl ElasticsearchOperation {
    fn name(self) -> &'static str {
        match self {
            Self::StorageMetrics => "storage-metrics",
            Self::ScanQuery => "scan-query",
            Self::RefreshTags => "refresh-tags",
            Self::BulkWrite => "bulk-write",
            Self::ClusterInfo => "cluster-info",
            Self::IndexAdmin => "index-admin",
            Self::ExecutionSummary => "execution-summary",
            Self::ConflictCheck => "conflict-check",
            Self::ProjectionSearch => "projection-search",
            Self::AssetSearch => "asset-search",
            Self::EndpointFilter => "endpoint-filter",
            Self::DomainFilter => "domain-filter",
        }
    }

    fn kind(self) -> ElasticsearchOperationKind {
        match self {
            Self::ScanQuery
            | Self::ExecutionSummary
            | Self::ConflictCheck
            | Self::ProjectionSearch
            | Self::AssetSearch
            | Self::EndpointFilter
            | Self::DomainFilter => ElasticsearchOperationKind::Query,
            Self::RefreshTags | Self::BulkWrite => ElasticsearchOperationKind::Write,
            Self::StorageMetrics | Self::ClusterInfo | Self::IndexAdmin => {
                ElasticsearchOperationKind::Maintenance
            }
        }
    }
}

impl ElasticsearchService {
    /// External DNS queries use immutable observations and server-authorized task IDs,
    /// never the shared current DNS index (whose tenant is currently `default`).
    pub(crate) async fn open_api_dns_query(&self, body: &Value) -> Result<Value, String> {
        if !self.can_read() {
            return Err("DNS read path unavailable".into());
        }
        let result = self
            .send_json_request(
                ElasticsearchOperation::DomainFilter,
                Method::POST,
                &format!("/{}/_search", self.inner.config.dns_observation_data_stream),
                |r| r.json(body),
            )
            .await?;
        validate_scan_search_response(&result)?;
        Ok(result)
    }
    pub(crate) async fn open_api_endpoint_filter(
        &self,
        scope_type: &str,
        scope_id: i32,
        filter: Value,
    ) -> Result<Value, String> {
        self.resolve_has_endpoint_filters(scope_type, scope_id, filter)
            .await
    }
    pub fn new(config: ElasticsearchConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut builder =
            reqwest::Client::builder().timeout(Duration::from_secs(config.request_timeout_seconds));
        if config.enabled
            && let Some(path) = config.ca_certificate_file.as_deref()
        {
            let pem = std::fs::read(path)?;
            let certificate = reqwest::Certificate::from_pem(&pem)?;
            builder = builder.add_root_certificate(certificate);
        }
        let bulk_max_concurrency = config.bulk_max_concurrency;
        Ok(Self {
            inner: Arc::new(ElasticsearchInner {
                maintenance_run_id: RwLock::new(None),
                config,
                client: builder.build()?,
                runtime: RwLock::new(ElasticsearchRuntime::default()),
                monitor: RwLock::new(None),
                bulk_semaphore: Semaphore::new(bulk_max_concurrency),
                projection_notify: Notify::new(),
                scan_indices_ready: AtomicBool::new(false),
                observation_compatibility_ready: AtomicBool::new(false),
            }),
        })
    }

    pub fn set_monitor(&self, monitor: Option<MonitorHandle>) {
        *self
            .inner
            .monitor
            .write()
            .expect("elasticsearch monitor lock poisoned") = monitor;
    }

    pub fn enabled(&self) -> bool {
        self.inner.config.enabled
    }

    pub(crate) async fn health_check(&self) -> Result<(), String> {
        if !self.enabled() {
            return Err("required Elasticsearch storage is disabled".into());
        }
        let health = self
            .send_json_request(
                ElasticsearchOperation::ClusterInfo,
                Method::GET,
                "/_cluster/health?filter_path=status,timed_out",
                |request| request.timeout(Duration::from_secs(2)),
            )
            .await?;
        if matches!(
            health.get("status").and_then(Value::as_str),
            Some("green" | "yellow")
        ) && health.get("timed_out").and_then(Value::as_bool) == Some(false)
        {
            Ok(())
        } else {
            Err("Elasticsearch cluster is not ready".into())
        }
    }

    #[cfg(test)]
    pub(crate) fn open_api_test_ready(&self) {
        self.inner.runtime.write().unwrap().read_ready = true;
    }

    pub fn can_read(&self) -> bool {
        self.inner.config.enabled
            && self.inner.config.read_enabled
            && self
                .inner
                .runtime
                .read()
                .expect("elasticsearch runtime lock poisoned")
                .read_ready
    }

    pub(crate) async fn storage_metrics(&self) -> ElasticsearchStorageMetrics {
        if !self.enabled() {
            return ElasticsearchStorageMetrics::unavailable(false);
        }

        let mut targets = vec![
            format!("{}-*", self.inner.config.observation_index_prefix),
            self.inner.config.execution_endpoint_index.clone(),
            self.inner.config.current_endpoint_index.clone(),
            self.inner.config.dns_observation_data_stream.clone(),
            self.inner.config.dns_record_index.clone(),
        ];
        targets.sort();
        targets.dedup();
        let path = format!("/{}/_stats/store", targets.join(","));
        let response = match self
            .send_json_request(
                ElasticsearchOperation::StorageMetrics,
                Method::GET,
                &path,
                |request| {
                    request.query(&[
                ("level", "indices"),
                ("ignore_unavailable", "true"),
                ("allow_no_indices", "true"),
                ("expand_wildcards", "open"),
                (
                    "filter_path",
                    "indices.*.primaries.store.size_in_bytes,indices.*.total.store.size_in_bytes",
                ),
            ])
                },
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                warn!(event = "ElasticsearchStorageMetricsRequestError", message = %error);
                return ElasticsearchStorageMetrics::unavailable(true);
            }
        };
        match parse_storage_metrics(&response) {
            Ok(metrics) => metrics,
            Err(message) => {
                warn!(event = "ElasticsearchStorageMetricsParseError", message = %message);
                ElasticsearchStorageMetrics::unavailable(true)
            }
        }
    }

    pub(crate) async fn scan_query(
        &self,
        index: ScanQueryIndex,
        body: &Value,
    ) -> Result<Value, String> {
        if !self.can_read() {
            return Err("Elasticsearch 扫描事实读路径尚未就绪".to_owned());
        }
        let index = match index {
            ScanQueryIndex::Observations => {
                format!(
                    "{}-*/_search?allow_no_indices=true&ignore_unavailable=true",
                    self.inner.config.observation_index_prefix
                )
            }
            ScanQueryIndex::ExecutionEndpoints => {
                format!("{}/_search", self.inner.config.execution_endpoint_index)
            }
            ScanQueryIndex::CurrentEndpoints => {
                format!("{}/_search", self.inner.config.current_endpoint_index)
            }
        };
        let result = self
            .send_json_request(
                ElasticsearchOperation::ScanQuery,
                Method::POST,
                &format!("/{index}"),
                |request| request.json(body),
            )
            .await?;
        validate_scan_search_response(&result)?;
        self.mark_success();
        Ok(result)
    }

    pub(crate) async fn scan_observations(
        &self,
        indices: &[String],
        body: &Value,
    ) -> Result<Value, String> {
        if !self.can_read() {
            return Err("Elasticsearch 扫描事实读路径尚未就绪".to_owned());
        }
        let target =
            observation_search_target(&self.inner.config.observation_index_prefix, indices)?;
        let result = self
            .send_json_request(
                ElasticsearchOperation::ScanQuery,
                Method::POST,
                &format!("/{target}/_search?allow_no_indices=true&ignore_unavailable=true"),
                |request| request.json(body),
            )
            .await?;
        validate_scan_search_response(&result)?;
        self.mark_success();
        Ok(result)
    }

    /// Returns the immutable DNS observations for one task. Comparison is
    /// intentionally derived from these source observations, never from the
    /// mutable current-record projection.
    pub(crate) async fn dns_task_observations(&self, task_id: &str) -> Result<Value, String> {
        if !self.can_read() {
            return Err("Elasticsearch DNS 查询读路径尚未就绪".to_owned());
        }
        let body = dns_task_observations_search_body(task_id);
        let result = self
            .send_json_request(
                ElasticsearchOperation::ScanQuery,
                Method::POST,
                &format!("{}/_search", self.inner.config.dns_observation_data_stream),
                |request| request.json(&body),
            )
            .await?;
        self.mark_success();
        Ok(result)
    }

    pub(crate) async fn scan_asset_exists(&self, ip: &str) -> Result<bool, String> {
        let result = self
            .scan_query(
                ScanQueryIndex::CurrentEndpoints,
                &json!({
                    "size": 0, "track_total_hits": true,
                    "query": {"bool": {"filter": [
                        {"term": {"scope_type": "global"}},
                        {"term": {"scope_id": 0}},
                        {"term": {"ip": ip}}
                    ]}}
                }),
            )
            .await?;
        Ok(result
            .pointer("/hits/total/value")
            .and_then(Value::as_i64)
            .unwrap_or(0)
            > 0)
    }

    pub(crate) async fn refresh_scan_asset_tags(
        &self,
        ip: &str,
        tags: &[AssetTag],
    ) -> Result<(), String> {
        let tag_names = tags.iter().map(|tag| tag.name.clone()).collect::<Vec<_>>();
        let tag_ids = tags.iter().map(|tag| tag.id).collect::<Vec<_>>();
        let tag_kinds = tags.iter().map(|tag| tag.kind.clone()).collect::<Vec<_>>();
        let result = self
            .send_json_request(
                ElasticsearchOperation::RefreshTags,
                Method::POST,
                &format!(
                    "/{}/_update_by_query?conflicts=proceed&refresh=true&wait_for_completion=true",
                    self.inner.config.current_endpoint_index
                ),
                |request| request.json(&json!({
                    "query": {"term": {"ip": ip}},
                    "script": {"lang": "painless", "source":
                        "ctx._source.tags=params.tags; ctx._source.tag_names=params.names; ctx._source.tag_ids=params.ids; ctx._source.tag_kinds=params.kinds;",
                        "params": {"tags": tags, "names": tag_names, "ids": tag_ids, "kinds": tag_kinds}}
                })),
            )
            .await?;
        let failures = result
            .get("failures")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(format!("Elasticsearch 标签投影更新失败：{}", failures[0]))
        }
    }

    pub fn runtime(&self) -> ElasticsearchRuntime {
        self.inner
            .runtime
            .read()
            .expect("elasticsearch runtime lock poisoned")
            .clone()
    }

    fn endpoint(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.inner.config.url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    fn request(
        &self,
        method: Method,
        path: &str,
        operation: ElasticsearchOperation,
        traceparent: &str,
    ) -> reqwest::RequestBuilder {
        let request = self
            .inner
            .client
            .request(method, self.endpoint(path))
            .header(
                "x-opaque-id",
                self.inner
                    .maintenance_run_id
                    .read()
                    .expect("maintenance identity lock poisoned")
                    .as_ref()
                    .map(|id| format!("network-mapping:transport-rebuild:{id}"))
                    .unwrap_or_else(|| format!("network-mapping:{}", operation.name())),
            )
            .header("traceparent", traceparent);
        if let Some(api_key) = self.inner.config.api_key.as_deref() {
            request.header(reqwest::header::AUTHORIZATION, format!("ApiKey {api_key}"))
        } else if let (Some(username), Some(password)) = (
            self.inner.config.username.as_deref(),
            self.inner.config.password.as_deref(),
        ) {
            request.basic_auth(username, Some(password))
        } else {
            request
        }
    }

    async fn send_json_request<F>(
        &self,
        operation: ElasticsearchOperation,
        method: Method,
        path: &str,
        configure: F,
    ) -> Result<Value, String>
    where
        F: FnOnce(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    {
        let (trace_id, traceparent) = new_trace_context();
        let started = Instant::now();
        let response = configure(self.request(method.clone(), path, operation, &traceparent))
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                self.observe_elasticsearch(
                    operation,
                    started,
                    trace_id,
                    None,
                    None,
                    Some("network"),
                );
                return Err(elasticsearch_request_error(error, &method, path, started));
            }
        };
        let status = response.status();
        let result = response_json(response).await;
        let failure_kind = if !status.is_success() {
            Some("http")
        } else if result.is_err() {
            Some("response_decode")
        } else {
            None
        };
        self.observe_elasticsearch(
            operation,
            started,
            trace_id,
            Some(status.as_u16()),
            result.as_ref().ok(),
            failure_kind,
        );
        result
    }

    async fn send_request<F>(
        &self,
        operation: ElasticsearchOperation,
        method: Method,
        path: &str,
        configure: F,
    ) -> Result<reqwest::Response, String>
    where
        F: FnOnce(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    {
        let (trace_id, traceparent) = new_trace_context();
        let started = Instant::now();
        match configure(self.request(method.clone(), path, operation, &traceparent))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                self.observe_elasticsearch(
                    operation,
                    started,
                    trace_id,
                    Some(status.as_u16()),
                    None,
                    (!status.is_success()).then_some("http"),
                );
                Ok(response)
            }
            Err(error) => {
                self.observe_elasticsearch(
                    operation,
                    started,
                    trace_id,
                    None,
                    None,
                    Some("network"),
                );
                Err(elasticsearch_request_error(error, &method, path, started))
            }
        }
    }

    fn observe_elasticsearch(
        &self,
        operation: ElasticsearchOperation,
        started: Instant,
        trace_id: String,
        http_status: Option<u16>,
        response: Option<&Value>,
        failure_kind: Option<&'static str>,
    ) {
        let monitor = self
            .inner
            .monitor
            .read()
            .expect("elasticsearch monitor lock poisoned")
            .clone();
        let Some(monitor) = monitor else { return };
        let duration_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        monitor.observe_elasticsearch(ElasticsearchObservation {
            operation: operation.name(),
            kind: operation.kind(),
            duration_ms,
            es_took_ms: response
                .and_then(|value| value.get("took"))
                .and_then(Value::as_i64),
            http_status,
            timed_out: response
                .and_then(|value| value.get("timed_out"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
            failed_shards: response
                .and_then(|value| value.pointer("/_shards/failed"))
                .and_then(Value::as_i64)
                .unwrap_or(0),
            trace_id,
            failure_kind,
        });
    }

    async fn send_bulk_with_retry(
        &self,
        path: &str,
        body: &str,
        create_conflict_is_success: bool,
    ) -> Result<Value, String> {
        self.send_bulk(
            path,
            body,
            create_conflict_is_success,
            self.inner.config.bulk_max_retries,
        )
        .await
    }

    async fn send_bulk_once(
        &self,
        path: &str,
        body: &str,
        create_conflict_is_success: bool,
    ) -> Result<Value, String> {
        self.send_bulk(path, body, create_conflict_is_success, 0)
            .await
    }

    async fn send_bulk(
        &self,
        path: &str,
        body: &str,
        create_conflict_is_success: bool,
        max_retries: u32,
    ) -> Result<Value, String> {
        let (trace_id, traceparent) = new_trace_context();
        let started = Instant::now();
        let budget = Duration::from_secs(self.inner.config.bulk_total_timeout_seconds);
        let mut timing = BulkTiming::default();
        let result = match timeout(budget, async {
            let _permit = self
                .inner
                .bulk_semaphore
                .acquire()
                .await
                .map_err(|_| "Elasticsearch Bulk 并发控制器已关闭".to_owned())?;
            timing.queue_wait_ms = started.elapsed().as_millis() as u64;
            timing.acquired = true;
            self.send_bulk_with_retry_inner(
                path,
                body,
                create_conflict_is_success,
                max_retries,
                &traceparent,
                &mut timing,
            )
            .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(format!(
                "Elasticsearch Bulk 超过总时间预算 {} 秒",
                self.inner.config.bulk_total_timeout_seconds
            )),
        };
        // Include the interrupted phase when the total budget expires.
        if let Some(started) = timing.request_started.take() {
            timing.request_ms += started.elapsed().as_millis() as u64;
        }
        if let Some(started) = timing.backoff_started.take() {
            timing.backoff_ms += started.elapsed().as_millis() as u64;
        }
        info!(event = "ElasticsearchBulkCompleted", trace_id = %trace_id,
            duration_ms = started.elapsed().as_millis() as u64,
            queue_wait_ms = if timing.acquired { timing.queue_wait_ms } else { started.elapsed().as_millis() as u64 },
            request_ms = timing.request_ms, backoff_ms = timing.backoff_ms,
            attempts = timing.attempts, request_bytes = body.len(),
            operations = body.bytes().filter(|byte| *byte == b'\n').count() / 2,
            es_took_ms = result.as_ref().ok().and_then(|value| value.get("took")).and_then(serde_json::Value::as_i64),
            success = result.as_ref().is_ok_and(|value| value.get("errors").and_then(serde_json::Value::as_bool) == Some(false)));
        let failure_kind = match result.as_ref() {
            Ok(value) if value.get("errors").and_then(Value::as_bool) == Some(true) => {
                Some("bulk_items")
            }
            Ok(_) => None,
            Err(_) => Some("bulk_request"),
        };
        self.observe_elasticsearch(
            ElasticsearchOperation::BulkWrite,
            started,
            trace_id,
            result.as_ref().ok().map(|_| StatusCode::OK.as_u16()),
            result.as_ref().ok(),
            failure_kind,
        );
        result
    }

    #[allow(clippy::too_many_arguments)] // request identity and per-call timing
    async fn send_bulk_with_retry_inner(
        &self,
        path: &str,
        body: &str,
        create_conflict_is_success: bool,
        max_retries: u32,
        traceparent: &str,
        timing: &mut BulkTiming,
    ) -> Result<Value, String> {
        for attempt in 0..=max_retries {
            timing.attempts += 1;
            let request_started = Instant::now();
            timing.request_started = Some(request_started);
            let response = self
                .request(
                    Method::POST,
                    path,
                    ElasticsearchOperation::BulkWrite,
                    traceparent,
                )
                .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
                .body(body.to_owned())
                .send()
                .await;
            timing.request_ms += request_started.elapsed().as_millis() as u64;
            timing.request_started = None;
            match response {
                Ok(response) if is_retryable_bulk_status(response.status()) => {
                    let status = response.status();
                    if attempt == max_retries {
                        let parse_started = Instant::now();
                        timing.request_started = Some(parse_started);
                        let error = response_error(response).await;
                        timing.request_ms += parse_started.elapsed().as_millis() as u64;
                        timing.request_started = None;
                        return Err(error);
                    }
                    warn!(
                        event = "ElasticsearchBulkRetry",
                        attempt = attempt + 1,
                        max_retries,
                        %status,
                        "Bulk 请求收到临时 HTTP 状态，准备重试"
                    );
                }
                Ok(response) => {
                    let parse_started = Instant::now();
                    timing.request_started = Some(parse_started);
                    let result = response_json(response).await;
                    timing.request_ms += parse_started.elapsed().as_millis() as u64;
                    timing.request_started = None;
                    let result = result?;
                    if !bulk_response_is_retryable(&result, create_conflict_is_success) {
                        return Ok(result);
                    }
                    if attempt == max_retries {
                        return Ok(result);
                    }
                    warn!(
                        event = "ElasticsearchBulkRetry",
                        attempt = attempt + 1,
                        max_retries,
                        "Bulk 响应包含可重试条目，准备重试整个幂等请求"
                    );
                }
                Err(error) => {
                    if attempt == max_retries {
                        return Err(error.to_string());
                    }
                    warn!(
                        event = "ElasticsearchBulkRetry",
                        attempt = attempt + 1,
                        max_retries,
                        message = %error,
                        "Bulk 请求发生网络错误，准备重试"
                    );
                }
            }
            let backoff_started = Instant::now();
            timing.backoff_started = Some(backoff_started);
            sleep(bulk_retry_delay(
                self.inner.config.bulk_retry_initial_ms,
                attempt,
            ))
            .await;
            timing.backoff_ms += backoff_started.elapsed().as_millis() as u64;
            timing.backoff_started = None;
        }
        unreachable!("bulk retry loop always returns")
    }

    async fn initialize(&self, _pool: &Pool) -> Result<(), String> {
        if !self.enabled() {
            return Err("Elasticsearch 是必需的扫描结果存储".to_owned());
        }
        let root = self
            .send_json_request(
                ElasticsearchOperation::ClusterInfo,
                Method::GET,
                "/",
                |request| request,
            )
            .await?;
        let version = root
            .pointer("/version/number")
            .and_then(Value::as_str)
            .ok_or_else(|| "Elasticsearch 根响应缺少 version.number".to_owned())?;
        self.inner.config.validate_server_version(version)?;

        self.ensure_scan_indices().await?;
        // Domain search reads the current DNS RR index even before the first DNS
        // upload. Create its template, data stream, and empty current-record
        // index during startup so a valid no-result search is not a 404.
        self.ensure_dns_indices().await?;
        self.update_runtime(|runtime| {
            runtime.connected = true;
            runtime.read_ready = true;
            runtime.server_version = Some(version.to_owned());
            runtime.last_success_at = Some(Utc::now());
            runtime.last_error = None;
        });
        Ok(())
    }

    async fn ensure_scan_indices(&self) -> Result<(), String> {
        if self.inner.scan_indices_ready.load(Ordering::Acquire) {
            return Ok(());
        }
        let template_name = format!("{}-template", self.inner.config.observation_index_prefix);
        self.send_json_request(
            ElasticsearchOperation::IndexAdmin,
            Method::PUT,
            &format!("/_index_template/{template_name}"),
            |request| {
                request.json(&scan_observation_template(
                    &self.inner.config.observation_index_prefix,
                    self.inner.config.scan_number_of_replicas,
                ))
            },
        )
        .await?;
        // Templates only affect newly-created monthly indices. Existing strict
        // indices need this additive field before a dual IP/CIDR document lands.
        if !self
            .inner
            .observation_compatibility_ready
            .load(Ordering::Acquire)
        {
            let observation_pattern = format!("{}-*", self.inner.config.observation_index_prefix);
            let response = self
                .send_request(
                    ElasticsearchOperation::IndexAdmin,
                    Method::HEAD,
                    &observation_pattern,
                    |request| request,
                )
                .await?;
            if response.status().is_success() {
                // 索引通配符在节点状态切换或索引刚被删除时可能在 HEAD 与 PUT
                // 之间不再匹配任何索引。此时没有旧映射需要升级，不应阻断服务初始化。
                let response = self
                    .send_request(
                        ElasticsearchOperation::IndexAdmin,
                        Method::PUT,
                        &format!(
                            "{observation_pattern}/_mapping?allow_no_indices=true&ignore_unavailable=true"
                        ),
                        |request| request.json(&scan_observation_compatibility_mapping()),
                    )
                    .await?;
                if !response.status().is_success() && response.status() != StatusCode::NOT_FOUND {
                    return Err(response_error(response).await);
                }
            } else if response.status() != StatusCode::NOT_FOUND {
                return Err(response_error(response).await);
            }
            self.inner
                .observation_compatibility_ready
                .store(true, Ordering::Release);
        }
        self.ensure_named_index(
            &self.inner.config.execution_endpoint_index,
            &scan_endpoint_index_definition(self.inner.config.scan_number_of_replicas),
        )
        .await?;
        self.ensure_named_index_mapping(
            &self.inner.config.execution_endpoint_index,
            &index_mapping_update(),
        )
        .await?;
        self.ensure_named_index(
            &self.inner.config.current_endpoint_index,
            &scan_endpoint_index_definition(self.inner.config.scan_number_of_replicas),
        )
        .await?;
        self.ensure_named_index_mapping(
            &self.inner.config.current_endpoint_index,
            &index_mapping_update(),
        )
        .await?;
        self.inner.scan_indices_ready.store(true, Ordering::Release);
        Ok(())
    }

    async fn ensure_dns_indices(&self) -> Result<(), String> {
        let template_name = format!("{}-template", self.inner.config.dns_observation_data_stream);
        self.send_json_request(
            ElasticsearchOperation::IndexAdmin,
            Method::PUT,
            &format!("/_index_template/{template_name}"),
            |request| {
                request.json(&dns_observation_template(
                    &self.inner.config.dns_observation_data_stream,
                    self.inner.config.scan_number_of_replicas,
                    self.inner.config.dns_observation_retention_days,
                ))
            },
        )
        .await?;
        self.ensure_data_stream(&self.inner.config.dns_observation_data_stream)
            .await?;
        // Existing installations already have a strict mapping on the DNS data
        // stream. Additive mapping updates make the new resolver attribution
        // fields writable before the first explicit-resolver upload.
        self.send_json_request(
            ElasticsearchOperation::IndexAdmin,
            Method::PUT,
            &format!("{}/_mapping", self.inner.config.dns_observation_data_stream),
            |request| request.json(&json!({"properties": {"resolver": dns_resolver_mapping()}})),
        )
        .await?;
        self.ensure_named_index(
            &self.inner.config.dns_record_index,
            &dns_record_index_definition(self.inner.config.scan_number_of_replicas),
        )
        .await
    }

    async fn ensure_data_stream(&self, name: &str) -> Result<(), String> {
        let response = self
            .send_request(
                ElasticsearchOperation::IndexAdmin,
                // The data-stream API exposes existence through GET; unlike
                // index HEAD requests, HEAD /_data_stream/{name} is rejected
                // by Elasticsearch with 405.
                Method::GET,
                &format!("/_data_stream/{name}"),
                |request| request,
            )
            .await?;
        if response.status().is_success() {
            return Ok(());
        }
        if response.status() != StatusCode::NOT_FOUND {
            return Err(response_error(response).await);
        }
        self.send_json_request(
            ElasticsearchOperation::IndexAdmin,
            Method::PUT,
            &format!("/_data_stream/{name}"),
            |request| request,
        )
        .await
        .map(|_| ())
    }

    async fn ensure_named_index(&self, index: &str, definition: &Value) -> Result<(), String> {
        let response = self
            .send_request(
                ElasticsearchOperation::IndexAdmin,
                Method::HEAD,
                index,
                |request| request,
            )
            .await?;
        if response.status().is_success() {
            return Ok(());
        }
        if response.status() != StatusCode::NOT_FOUND {
            return Err(response_error(response).await);
        }
        self.send_json_request(
            ElasticsearchOperation::IndexAdmin,
            Method::PUT,
            index,
            |request| request.json(definition),
        )
        .await
        .map(|_| ())
    }

    async fn ensure_named_index_mapping(&self, index: &str, mapping: &Value) -> Result<(), String> {
        self.send_json_request(
            ElasticsearchOperation::IndexAdmin,
            Method::PUT,
            &format!("/{index}/_mapping"),
            |request| request.json(mapping),
        )
        .await
        .map(|_| ())
    }

    pub(crate) fn scan_batch_indices(&self, observations: &[Value]) -> Result<Vec<String>, String> {
        observations
            .iter()
            .map(|observation| {
                let observed_at = observation
                    .get("observed_at")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| "扫描观察缺少 observed_at".to_owned())?;
                scan_observation_index(&self.inner.config.observation_index_prefix, observed_at)
            })
            .collect::<Result<BTreeSet<_>, _>>()
            .map(|indices| indices.into_iter().collect())
    }

    // Some([]) is an execution with no endpoint observations. None is an explicit
    // compatibility path for old receipts/migrations whose index manifest is absent.
    pub(crate) async fn persist_scan_batch_scoped(
        &self,
        context: &ScanBatchContext,
        observations: &[Value],
        observation_indices: Option<&[String]>,
    ) -> Result<ScanBatchWriteResult, String> {
        self.ensure_scan_indices().await?;

        let result = self
            .persist_scan_batch_prepared(context, observations, observation_indices)
            .await;
        if result.is_err() {
            // The failure may be caused by an index being removed or replaced
            // after startup. Revalidate mappings on the next upload attempt.
            self.inner
                .scan_indices_ready
                .store(false, Ordering::Release);
        }
        result
    }

    async fn load_dns_batch_observations(
        &self,
        context: &ScanBatchContext,
        expected_ids: &BTreeSet<String>,
    ) -> Result<(BTreeSet<String>, BTreeSet<String>), String> {
        if expected_ids.is_empty() {
            return Ok((BTreeSet::new(), BTreeSet::new()));
        }
        let stream = &self.inner.config.dns_observation_data_stream;
        let refreshed = self
            .send_json_request(
                ElasticsearchOperation::IndexAdmin,
                Method::POST,
                &format!("/{stream}/_refresh"),
                |request| request,
            )
            .await?;
        validate_scan_refresh_response(&refreshed)?;
        let size = expected_ids
            .len()
            .checked_add(1)
            .ok_or("DNS 批次观察数量溢出")?;
        let result = self
            .send_json_request(
                ElasticsearchOperation::ScanQuery,
                Method::POST,
                &format!("/{stream}/_search"),
                |request| {
                    request.json(&json!({
                        "size": size,
                        "track_total_hits": true,
                        "_source": false,
                        "query": {"bool": {"filter": [
                            {"term": {"scan.execution_id": context.execution_id}},
                            {"term": {"scan.upload_id": context.upload_id}},
                            {"term": {"scan.batch_index": context.batch_index}}
                        ]}}
                    }))
                },
            )
            .await?;
        validate_scan_search_response(&result)?;
        let hits = result
            .pointer("/hits/hits")
            .and_then(Value::as_array)
            .ok_or("DNS 批次对账响应缺少 hits")?;
        let total = result
            .pointer("/hits/total/value")
            .and_then(Value::as_u64)
            .ok_or("DNS 批次对账响应缺少总数")?;
        if result
            .pointer("/hits/total/relation")
            .and_then(Value::as_str)
            != Some("eq")
            || total != hits.len() as u64
        {
            return Err("DNS 批次对账结果被截断".into());
        }
        let mut existing_ids = BTreeSet::new();
        let mut indices = BTreeSet::new();
        for hit in hits {
            let id = hit
                .get("_id")
                .and_then(Value::as_str)
                .ok_or("DNS 批次对账结果缺少 _id")?;
            let index = hit
                .get("_index")
                .and_then(Value::as_str)
                .ok_or("DNS 批次对账结果缺少 _index")?;
            if !expected_ids.contains(id) {
                return Err(format!("DNS 批次包含非预期事实：{id}"));
            }
            if !existing_ids.insert(id.to_owned()) {
                return Err(format!("DNS 事实跨 backing index 重复：{id}"));
            }
            indices.insert(index.to_owned());
        }
        Ok((existing_ids, indices))
    }

    async fn persist_dns_observation_documents(
        &self,
        context: &ScanBatchContext,
        documents: &BTreeMap<String, Value>,
        mode: DnsWriteMode,
    ) -> Result<Vec<String>, String> {
        let budget = Duration::from_secs(self.inner.config.bulk_total_timeout_seconds);
        match timeout(
            budget,
            self.persist_dns_observation_documents_inner(context, documents, mode),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(format!(
                "DNS Elasticsearch Bulk 超过总时间预算 {} 秒",
                self.inner.config.bulk_total_timeout_seconds
            )),
        }
    }

    async fn persist_dns_observation_documents_inner(
        &self,
        context: &ScanBatchContext,
        documents: &BTreeMap<String, Value>,
        mode: DnsWriteMode,
    ) -> Result<Vec<String>, String> {
        let stream = &self.inner.config.dns_observation_data_stream;
        if documents.is_empty() {
            return Ok(vec![stream.clone()]);
        }
        let expected_ids = documents.keys().cloned().collect::<BTreeSet<_>>();
        let max_writes = self.inner.config.bulk_max_retries as usize + 1;
        let mut write_attempts = 0_usize;
        let mut last_error = None;
        let mut reconcile = mode == DnsWriteMode::Reconcile;
        loop {
            let (existing_ids, mut indices) = if reconcile {
                self.load_dns_batch_observations(context, &expected_ids)
                    .await?
            } else {
                (BTreeSet::new(), BTreeSet::new())
            };
            if existing_ids.len() == documents.len() {
                return Ok(indices.into_iter().collect());
            }
            if write_attempts >= max_writes {
                return Err(last_error
                    .unwrap_or_else(|| "DNS Elasticsearch Bulk 未能持久化全部观察".into()));
            }
            let mut body = String::new();
            let mut submitted_ids = BTreeSet::new();
            for (id, document) in documents {
                if existing_ids.contains(id) {
                    continue;
                }
                submitted_ids.insert(id.clone());
                body.push_str(
                    &serde_json::to_string(&json!({"create": {"_index": stream, "_id": id}}))
                        .map_err(|error| error.to_string())?,
                );
                body.push('\n');
                body.push_str(&serde_json::to_string(document).map_err(|error| error.to_string())?);
                body.push('\n');
            }
            let result = self
                .send_bulk_once(
                    &format!(
                        "/_bulk?wait_for_active_shards={}",
                        self.inner.config.write_wait_for_active_shards
                    ),
                    &body,
                    true,
                )
                .await;
            write_attempts += 1;
            let retry_delay = match result {
                Ok(result) => match parse_dns_observation_bulk_result(&result, &submitted_ids) {
                    Ok(outcome) => {
                        indices.extend(outcome.indices);
                        if !outcome.requires_reconciliation {
                            return Ok(indices.into_iter().collect());
                        }
                        last_error = Some("DNS Elasticsearch Bulk 结果需要对账".into());
                        true
                    }
                    Err(error) => return Err(error),
                },
                Err(error) => {
                    last_error = Some(error);
                    true
                }
            };
            if retry_delay && write_attempts < max_writes {
                sleep(bulk_retry_delay(
                    self.inner.config.bulk_retry_initial_ms,
                    (write_attempts - 1) as u32,
                ))
                .await;
            }
            reconcile = true;
        }
    }

    /// Persists immutable DNS query observations and projects successful answer
    /// RRs into the mutable current-record index.  The caller supplies a DNS
    /// view because the same owner can legitimately resolve differently in
    /// distinct recursive or split-horizon views.
    pub(crate) async fn persist_dns_observations(
        &self,
        context: &ScanBatchContext,
        tenant_id: &str,
        observations: &[DnsObservation],
        mode: DnsWriteMode,
    ) -> Result<Vec<String>, String> {
        if !self.enabled() {
            return Err("Elasticsearch 未启用，无法保存 DNS 观察".to_owned());
        }
        if tenant_id.trim().is_empty() {
            return Err("tenant_id 不能为空".to_owned());
        }
        self.ensure_dns_indices().await?;

        let mut observation_documents = BTreeMap::new();
        let mut record_bulk = String::new();
        for (position, input) in observations.iter().cloned().enumerate() {
            let observation = input.normalize()?;
            let dns_view_id = observation.resolver_id.as_deref().unwrap_or("system");
            let timestamp = DateTime::<Utc>::from_timestamp_millis(observation.observed_at)
                .ok_or_else(|| format!("无效 DNS observed_at：{}", observation.observed_at))?;
            let immutable = serde_json::to_vec(&observation).map_err(|error| error.to_string())?;
            let document_id = sha256_hex(
                format!(
                    "dns-observation-v1\0{}\0{}\0{}\0{position}\0{}",
                    context.execution_id,
                    context.upload_id,
                    context.batch_index,
                    sha256_hex(&immutable),
                )
                .as_bytes(),
            );
            let observation_document = json!({
                "@timestamp": timestamp.to_rfc3339(),
                "event_id": document_id,
                "scan": {
                    "task_id": context.task_id, "execution_id": context.execution_id,
                    "scanner_id": context.scanner_id, "scanner_name": context.scanner_name,
                    "upload_id": context.upload_id, "batch_index": context.batch_index
                },
                "tenant_id": tenant_id,
                "dns_view": {"id": dns_view_id},
                "dns": {
                    "question": observation.question,
                    "response_code": observation.response_code,
                    "authoritative": observation.authoritative,
                    "truncated": observation.truncated,
                    "dnssec_authenticated": observation.dnssec_authenticated,
                    "answers": observation.answers,
                    "authority": observation.authority,
                    "additional": observation.additional
                },
                "resolver": {
                    "id": observation.resolver_id, "label": observation.resolver_label,
                    "ip": observation.resolver_ip, "port": observation.resolver_port,
                    "transport": observation.resolver_transport
                },
                "latency_ms": observation.latency_ms
            });
            observation_documents.insert(document_id, observation_document);

            if observation.response_code != "NOERROR" {
                continue;
            }
            for record in observation.answer_records(tenant_id, dns_view_id)? {
                append_dns_record_update(
                    &mut record_bulk,
                    &self.inner.config.dns_record_index,
                    &record.id,
                    &json!({
                        "tenant_id": tenant_id,
                        "dns_view_id": dns_view_id,
                        "domain": record.domain,
                        "record_type": record.record_type,
                        "value": record.value,
                        "canonical_rdata": record.canonical_rdata,
                        "ip": record.ip,
                        "target_domain": record.target_domain,
                        "ttl": record.ttl,
                        "priority": record.priority,
                        "weight": record.weight,
                        "port": record.port,
                        "state": "active",
                        "missing_completed_scans": 0,
                        "first_seen_at": timestamp.to_rfc3339(),
                        "first_seen_ms": observation.observed_at,
                        "last_seen_at": timestamp.to_rfc3339(),
                        "last_seen_ms": observation.observed_at,
                        "last_successful_query_at": timestamp.to_rfc3339(),
                        "last_successful_query_ms": observation.observed_at,
                        "last_response_code": "NOERROR",
                        "evidence_sources": ["dns"],
                        "last_scanner_id": context.scanner_id,
                        "last_task_id": context.task_id
                    }),
                )?;
            }
        }
        let mut storage_references = self
            .persist_dns_observation_documents(context, &observation_documents, mode)
            .await?;
        if !record_bulk.is_empty() {
            let response = self
                .send_bulk_with_retry(
                    &format!(
                        "/_bulk?wait_for_active_shards={}",
                        self.inner.config.write_wait_for_active_shards
                    ),
                    &record_bulk,
                    false,
                )
                .await?;
            validate_dns_bulk_result(&response)?;
        }
        if !storage_references.contains(&self.inner.config.dns_record_index) {
            storage_references.push(self.inner.config.dns_record_index.clone());
        }
        self.mark_success();
        Ok(storage_references)
    }

    async fn persist_scan_batch_prepared(
        &self,
        context: &ScanBatchContext,
        observations: &[Value],
        observation_indices: Option<&[String]>,
    ) -> Result<ScanBatchWriteResult, String> {
        // Validate and plan all final URLs before issuing any Elasticsearch writes.
        let final_plan = if context.is_final {
            let targets = match observation_indices {
                Some(indices) => validated_observation_indices(
                    &self.inner.config.observation_index_prefix,
                    indices,
                )?
                .into_iter()
                .collect::<Vec<_>>(),
                None => {
                    warn!(event = "ScanSummaryLegacyIndexScope", execution_id = %context.execution_id,
                        "旧回执或迁移缺少索引清单，使用兼容统计范围");
                    Vec::new()
                }
            };
            let legacy_target = format!("{}-*", self.inner.config.observation_index_prefix);
            let targets = if observation_indices.is_none() {
                vec![legacy_target.as_str()]
            } else {
                targets
            };
            let count_paths = bounded_scan_index_paths(&self.inner.config.url, &targets, "_count")?;
            let mut refresh_targets = targets;
            refresh_targets.push(&self.inner.config.execution_endpoint_index);
            let refresh_paths =
                bounded_scan_index_paths(&self.inner.config.url, &refresh_targets, "_refresh")?;
            let summary_path = format!("/{}/_search", self.inner.config.execution_endpoint_index);
            ensure_scan_request_line_fits(&self.inner.config.url, &summary_path)?;
            info!(event = "ScanFinalRequestPlan", execution_id = %context.execution_id,
                refresh_requests = refresh_paths.len(), count_requests = count_paths.len(),
                max_request_line_bytes = refresh_paths.iter().chain(&count_paths)
                    .map(|path| scan_request_line_length(&self.inner.config.url, path))
                    .collect::<Result<Vec<_>, _>>()?.into_iter().max().unwrap_or(0));
            Some((refresh_paths, count_paths))
        } else {
            None
        };
        let payload_checksum = scan_batch_payload_checksum(context, observations)?;
        let mut body = String::new();
        let mut expected = Vec::with_capacity(observations.len());
        let mut indices = std::collections::BTreeSet::new();
        for observation in observations {
            let observed_at_ms = observation
                .get("observed_at")
                .and_then(Value::as_i64)
                .ok_or_else(|| "扫描观察缺少 observed_at".to_owned())?;
            let observation_key = observation
                .get("observation_key")
                .and_then(Value::as_str)
                .ok_or_else(|| "扫描观察缺少 observation_key".to_owned())?;
            let index = scan_observation_index(
                &self.inner.config.observation_index_prefix,
                observed_at_ms,
            )?;
            let document_id =
                sha256_hex(format!("{}\0{observation_key}", context.execution_id).as_bytes());
            let mut document = observation.clone();
            {
                let object = document
                    .as_object_mut()
                    .ok_or_else(|| "扫描观察必须是 JSON object".to_owned())?;
                object.insert("task_id".to_owned(), json!(context.task_id));
                object.insert("execution_id".to_owned(), json!(context.execution_id));
                object.insert("user_id".to_owned(), json!(context.user_id));
                object.insert("task_source".to_owned(), json!(context.task_source));
                object.insert("scanner_id".to_owned(), json!(context.scanner_id));
                object.insert("scanner_name".to_owned(), json!(context.scanner_name));
                object.insert("upload_id".to_owned(), json!(context.upload_id));
                object.insert("batch_index".to_owned(), json!(context.batch_index));
                object.insert("payload_checksum".to_owned(), json!(payload_checksum));
            }
            let document_checksum = sha256_hex(
                &serde_json::to_vec(&immutable_scan_observation(observation))
                    .map_err(|error| error.to_string())?,
            );
            document
                .as_object_mut()
                .expect("scan observation is an object")
                .insert("document_checksum".to_owned(), json!(document_checksum));
            body.push_str(
                &serde_json::to_string(&json!({"create": {"_index": index, "_id": document_id}}))
                    .map_err(|error| error.to_string())?,
            );
            body.push('\n');
            body.push_str(&serde_json::to_string(&document).map_err(|error| error.to_string())?);
            body.push('\n');
            expected.push((
                index.clone(),
                document_id,
                document_checksum,
                payload_checksum.clone(),
            ));
            indices.insert(index);
        }

        if !body.is_empty() {
            let stage = WriteStage::new("write_observation_bulk");
            let result = self
                .send_bulk_with_retry(
                    &format!(
                        "/_bulk?wait_for_active_shards={}",
                        self.inner.config.write_wait_for_active_shards
                    ),
                    &body,
                    true,
                )
                .await?;
            self.validate_scan_bulk_result(&result, &expected).await?;
            stage.finish(true);
        }

        let stage = WriteStage::new("write_execution_endpoints");
        self.update_scan_endpoint_projections(context, observations)
            .await?;
        stage.finish(true);
        self.mark_success();
        let execution_summary = if let Some((refresh_paths, count_paths)) = final_plan {
            let stage = WriteStage::new("refresh_execution_indices");
            for path in refresh_paths {
                let chunk_stage = WriteStage::new("refresh_execution_index_chunk");
                let refreshed = self
                    .send_json_request(
                        ElasticsearchOperation::IndexAdmin,
                        Method::POST,
                        &path,
                        |request| request,
                    )
                    .await?;
                validate_scan_refresh_response(&refreshed)?;
                chunk_stage.finish(true);
            }
            stage.finish(true);
            let stage = WriteStage::new("execution_summary");
            let summary = self
                .execution_summary(&context.execution_id, &count_paths)
                .await?;
            stage.finish(true);
            Some(summary)
        } else {
            None
        };
        Ok(ScanBatchWriteResult {
            payload_checksum,
            indices: indices.into_iter().collect(),
            execution_summary,
        })
    }

    async fn execution_summary(
        &self,
        execution_id: &str,
        observation_count_paths: &[String],
    ) -> Result<ScanExecutionSummary, String> {
        let mut after = None;
        let mut ip_count = 0_i64;
        let mut port_count = 0_i64;
        loop {
            let first_page = after.is_none();
            let mut composite = json!({
                "size": 1000,
                "sources": [{"ip": {"terms": {"field": "ip"}}}]
            });
            if let Some(after) = after.take() {
                composite
                    .as_object_mut()
                    .expect("composite aggregation is an object")
                    .insert("after".to_owned(), after);
            }
            let endpoints = self
                .send_json_request(
                    ElasticsearchOperation::ExecutionSummary,
                    Method::POST,
                    &format!("/{}/_search", self.inner.config.execution_endpoint_index),
                    |request| {
                        request.json(&json!({
                            "size": 0, "track_total_hits": first_page,
                            "query": {"term": {"execution_id": execution_id}},
                            "aggs": {"ips": {"composite": composite}}
                        }))
                    },
                )
                .await?;
            validate_scan_search_response(&endpoints)?;
            if first_page {
                if endpoints
                    .pointer("/hits/total/relation")
                    .and_then(Value::as_str)
                    != Some("eq")
                {
                    return Err("Elasticsearch 执行端点总数必须是精确值".into());
                }
                port_count = endpoints
                    .pointer("/hits/total/value")
                    .and_then(Value::as_i64)
                    .ok_or("Elasticsearch 执行端点缺少总数")?;
            }
            let buckets = endpoints
                .pointer("/aggregations/ips/buckets")
                .and_then(Value::as_array)
                .ok_or_else(|| "Elasticsearch 执行 IP 聚合缺少 buckets".to_owned())?;
            ip_count += i64::try_from(buckets.len()).map_err(|error| error.to_string())?;
            after = endpoints.pointer("/aggregations/ips/after_key").cloned();
            if buckets.len() < 1000 || after.is_none() {
                break;
            }
        }
        let mut observation_count = 0_i64;
        for path in observation_count_paths {
            let stage = WriteStage::new("count_execution_observation_chunk");
            let observations = self
                .send_json_request(
                    ElasticsearchOperation::ExecutionSummary,
                    Method::POST,
                    path,
                    |request| {
                        request.json(&json!({"query": {"term": {"execution_id": execution_id}}}))
                    },
                )
                .await?;
            validate_scan_search_response(&observations)?;
            let count = observations
                .get("count")
                .and_then(Value::as_i64)
                .filter(|count| *count >= 0)
                .ok_or("Elasticsearch 执行观察缺少有效总数")?;
            observation_count = observation_count
                .checked_add(count)
                .ok_or("Elasticsearch 执行观察总数溢出")?;
            stage.finish(true);
        }
        Ok(ScanExecutionSummary {
            ip_count,
            port_count,
            observation_count,
        })
    }

    async fn validate_scan_bulk_result(
        &self,
        result: &Value,
        expected: &[(String, String, String, String)],
    ) -> Result<(), String> {
        let items = result
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(|| "Elasticsearch Bulk 响应缺少 items".to_owned())?;
        if items.len() != expected.len() {
            return Err("Elasticsearch Bulk 响应条目数不匹配".to_owned());
        }
        let mut conflicts = Vec::new();
        let mut failures = Vec::new();
        for (item, (index, id, checksum, payload_checksum)) in items.iter().zip(expected) {
            let action = item
                .get("create")
                .ok_or_else(|| "Elasticsearch Bulk 响应缺少 create".to_owned())?;
            match action.get("status").and_then(Value::as_u64) {
                Some(200..=299) => {}
                Some(409) => conflicts.push((index, id, checksum, payload_checksum)),
                _ => failures.push(action.to_string()),
            }
        }
        if !failures.is_empty() {
            return Err(format!(
                "Elasticsearch 扫描事实 Bulk 部分失败：{}",
                failures.into_iter().take(3).collect::<Vec<_>>().join("; ")
            ));
        }
        if conflicts.is_empty() {
            return Ok(());
        }
        let docs = conflicts
            .iter()
            .map(|(index, id, _, _)| json!({"_index": index, "_id": id}))
            .collect::<Vec<_>>();
        let result = self
            .send_json_request(
                ElasticsearchOperation::ConflictCheck,
                Method::POST,
                "/_mget",
                |request| request.json(&json!({"docs": docs})),
            )
            .await?;
        let actual = result
            .get("docs")
            .and_then(Value::as_array)
            .ok_or_else(|| "Elasticsearch _mget 响应缺少 docs".to_owned())?;
        if actual.len() != conflicts.len() {
            return Err("Elasticsearch _mget 响应条目数不匹配".to_owned());
        }
        for (document, (_, id, checksum, payload_checksum)) in actual.iter().zip(conflicts) {
            let actual_checksum = document
                .pointer("/_source/document_checksum")
                .and_then(Value::as_str);
            let actual_payload_checksum = document
                .pointer("/_source/payload_checksum")
                .and_then(Value::as_str);
            if document.get("found").and_then(Value::as_bool) != Some(true)
                || actual_checksum != Some(checksum)
                || actual_payload_checksum != Some(payload_checksum)
            {
                return Err(format!("扫描批次重试内容与已写入事实不一致：{id}"));
            }
        }
        Ok(())
    }

    async fn update_scan_endpoint_projections(
        &self,
        context: &ScanBatchContext,
        observations: &[Value],
    ) -> Result<(), String> {
        if observations.is_empty() {
            return Ok(());
        }
        let mut body = String::new();
        for observation in observations {
            if observation.get("kind").and_then(Value::as_str) == Some("vulnerability") {
                continue;
            }
            let ip = observation
                .get("ip_address")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let port = observation
                .get("port")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            let observed_at_ms = observation
                .get("observed_at")
                .and_then(Value::as_i64)
                .ok_or_else(|| "扫描观察缺少 observed_at".to_owned())?;
            let event = endpoint_projection_document(context, observation, observed_at_ms);
            let execution_id = sha256_hex(
                format!(
                    "{}\0{ip}\0{port}\0{}",
                    context.execution_id,
                    endpoint_protocol(observation)
                )
                .as_bytes(),
            );
            append_projection_update(
                &mut body,
                &self.inner.config.execution_endpoint_index,
                &execution_id,
                &event,
            )?;
        }
        // Vulnerability-only batches have no endpoint projection actions.
        if body.is_empty() {
            return Ok(());
        }
        let result = self
            .send_bulk_with_retry(
                &format!(
                    "/_bulk?wait_for_active_shards={}",
                    self.inner.config.write_wait_for_active_shards
                ),
                &body,
                false,
            )
            .await?;
        let failures = result
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|item| item.get("update"))
            .filter(|item| {
                item.get("status")
                    .and_then(Value::as_u64)
                    .is_none_or(|status| status >= 300)
            })
            .take(3)
            .map(Value::to_string)
            .collect::<Vec<_>>();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Elasticsearch 端点投影 Bulk 部分失败：{}",
                failures.join("; ")
            ))
        }
    }

    pub(crate) async fn search(
        &self,
        role: i32,
        user_id: i32,
        filter: Value,
        limit: i64,
        offset: i64,
        sort: SearchSort,
    ) -> Result<ElasticsearchSearchPage, String> {
        if !self.can_read() {
            return Err("Elasticsearch 搜索读路径尚未就绪".to_owned());
        }
        let (scope_type, scope_id) = if role == 1 {
            ("global", 0)
        } else {
            ("user", user_id)
        };
        let filter = self
            .resolve_has_endpoint_filters(scope_type, scope_id, filter)
            .await?;
        let filter = self.resolve_domain_filters(filter).await?;
        let body = json!({
            "from": offset,
            "size": limit,
            "track_total_hits": true,
            "_source": {"excludes": ["http_body"]},
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"scope_type": scope_type}},
                        {"term": {"scope_id": scope_id}},
                        filter
                    ]
                }
            },
            "sort": sort.clauses()
        });
        let search_index = { &self.inner.config.current_endpoint_index };
        let result = match self
            .send_json_request(
                ElasticsearchOperation::AssetSearch,
                Method::POST,
                &format!("{search_index}/_search"),
                |request| request.json(&body),
            )
            .await
        {
            Ok(result) => result,
            Err(message) => {
                self.mark_error(&message);
                return Err(message);
            }
        };
        let total = result
            .pointer("/hits/total/value")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let hits = result
            .pointer("/hits/hits")
            .and_then(Value::as_array)
            .ok_or_else(|| "Elasticsearch 搜索响应缺少 hits.hits".to_owned())?;
        let mut items = Vec::with_capacity(hits.len());
        for hit in hits {
            let source: SearchSource = serde_json::from_value(
                hit.get("_source")
                    .cloned()
                    .ok_or_else(|| "Elasticsearch hit 缺少 _source".to_owned())?,
            )
            .map_err(|error| format!("Elasticsearch hit 解析失败：{error}"))?;
            items.push(ElasticsearchSearchItem {
                ip_address: source.ip,
                port: source.port,
                protocol: source.protocol,
                service: source.service,
                banner: source.banner,
                title: source.title,
                tls_mode: source.tls_mode,
                tls_version: source.tls_version,
                tls_cipher_suite: source.tls_cipher_suite,
                tls_subject: source.tls_subject,
                tls_issuer: source.tls_issuer,
                tls_names: source.tls_names,
                tls_serial_number: source.tls_serial_number,
                tls_not_before: source.tls_not_before.map(|value| value.timestamp_millis()),
                tls_not_after: source.tls_not_after.map(|value| value.timestamp_millis()),
                tls_fingerprint_sha256: source.tls_fingerprint_sha256,
                tls_self_signed: source.tls_self_signed,
                os: crate::os_detection::endpoint_view(
                    source.os,
                    source.last_seen.timestamp_millis(),
                    Utc::now().timestamp_millis(),
                ),
                web: crate::web_detection::endpoint_view(
                    source.web,
                    source.last_seen.timestamp_millis(),
                    Utc::now().timestamp_millis(),
                ),
                scanner_name: source.scanner_name,
                scan_time: source.last_seen.timestamp_millis(),
                asn: source.asn,
                isp: source.isp,
                as_org: source.as_org,
                country_code: source.country_code,
                country_name: source.country_name,
                region_name: source.region_name,
                city_name: source.city_name,
                tags: source.tags,
            });
        }
        self.mark_success();
        Ok(ElasticsearchSearchPage { items, total })
    }

    async fn resolve_has_endpoint_filters(
        &self,
        scope_type: &str,
        scope_id: i32,
        filter: Value,
    ) -> Result<Value, String> {
        let mut endpoint_filters = Vec::new();
        collect_has_endpoint_filters(&filter, &mut endpoint_filters);
        if endpoint_filters.is_empty() {
            return Ok(filter);
        }
        let mut address_sets = Vec::with_capacity(endpoint_filters.len());
        for endpoint_filter in endpoint_filters {
            let mut addresses = Vec::new();
            let mut after: Option<Value> = None;
            loop {
                let mut composite = json!({
                    "size": 1000,
                    "sources": [{"ip": {"terms": {"field": "ip"}}}]
                });
                if let Some(after) = after.take() {
                    composite
                        .as_object_mut()
                        .expect("composite is object")
                        .insert("after".to_owned(), after);
                }
                let response = self
                    .send_json_request(
                        ElasticsearchOperation::EndpointFilter,
                        Method::POST,
                        &format!("/{}/_search", self.inner.config.current_endpoint_index),
                        |request| {
                            request.json(&json!({
                                "size": 0,
                                "query": {"bool": {"filter": [
                                    {"term": {"scope_type": scope_type}},
                                    {"term": {"scope_id": scope_id}},
                                    endpoint_filter
                                ]}},
                                "aggs": {"addresses": {"composite": composite}}
                            }))
                        },
                    )
                    .await?;
                let buckets = response
                    .pointer("/aggregations/addresses/buckets")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                addresses.extend(buckets.iter().filter_map(|bucket| {
                    bucket
                        .pointer("/key/ip")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                }));
                if addresses.len() > 65_536 {
                    return Err("has_endpoint 匹配的资产超过 65536 个，请增加限定条件".to_owned());
                }
                after = response
                    .pointer("/aggregations/addresses/after_key")
                    .cloned();
                if buckets.len() < 1000 || after.is_none() {
                    break;
                }
            }
            address_sets.push(addresses);
        }
        let mut iterator = address_sets.into_iter();
        Ok(replace_has_endpoint_filters(filter, &mut iterator))
    }

    async fn resolve_domain_filters(&self, filter: Value) -> Result<Value, String> {
        let mut domain_filters = Vec::new();
        collect_domain_filters(&filter, &mut domain_filters);
        if domain_filters.is_empty() {
            return Ok(filter);
        }

        let mut replacements = Vec::with_capacity(domain_filters.len());
        for domain_filter in domain_filters {
            replacements.push(self.resolve_domain_filter(&domain_filter).await?);
        }
        let mut iterator = replacements.into_iter();
        Ok(replace_domain_filters(filter, &mut iterator))
    }

    async fn resolve_domain_filter(&self, filter: &Value) -> Result<Value, String> {
        let operator = filter
            .get("operator")
            .and_then(Value::as_str)
            .ok_or_else(|| "domain 搜索条件无效".to_owned())?;
        let values = filter
            .get("values")
            .and_then(Value::as_array)
            .ok_or_else(|| "domain 搜索条件无效".to_owned())?
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| "domain 搜索条件无效".to_owned())?;
        let contains = matches!(operator, "contains" | "not_contains");
        let mut seen_names = BTreeSet::new();
        let mut pending_names = BTreeSet::new();
        for value in values {
            let normalized = value.trim_end_matches('.').to_ascii_lowercase();
            seen_names.insert(normalized.clone());
            pending_names.insert(normalized);
        }

        let mut addresses = BTreeSet::new();
        let mut processed_records = 0usize;
        for depth in 0..=MAX_DOMAIN_CNAME_DEPTH {
            if pending_names.is_empty() {
                break;
            }
            let names = pending_names.iter().cloned().collect::<Vec<_>>();
            pending_names.clear();
            let name_query = if depth == 0 && contains {
                let clauses = names
                    .iter()
                    .map(|name| {
                        json!({"wildcard": {"domain": {
                            "value": format!("*{}*", escape_es_wildcard(name)),
                            "case_insensitive": true
                        }}})
                    })
                    .collect::<Vec<_>>();
                if clauses.len() == 1 {
                    clauses
                        .into_iter()
                        .next()
                        .expect("one domain wildcard clause")
                } else {
                    json!({"bool": {"should": clauses, "minimum_should_match": 1}})
                }
            } else {
                json!({"terms": {"domain": names}})
            };
            let response = self
                .send_json_request(
                    ElasticsearchOperation::DomainFilter,
                    Method::POST,
                    &format!("/{}/_search", self.inner.config.dns_record_index),
                    |request| {
                        request.json(&json!({
                            "size": MAX_DOMAIN_RECORDS,
                            "track_total_hits": MAX_DOMAIN_RECORDS,
                            "_source": ["record_type", "ip", "target_domain"],
                            "query": {"bool": {"filter": [
                                {"term": {"tenant_id": "default"}},
                                {"term": {"state": "active"}},
                                {"terms": {"record_type": ["A", "AAAA", "CNAME"]}},
                                name_query
                            ]}}
                        }))
                    },
                )
                .await?;
            let hits = response
                .pointer("/hits/hits")
                .and_then(Value::as_array)
                .ok_or_else(|| "DNS 搜索响应缺少 hits.hits".to_owned())?;
            processed_records = processed_records.saturating_add(hits.len());
            let exceeded_result_limit = response
                .pointer("/hits/total/relation")
                .and_then(Value::as_str)
                == Some("gte");
            if exceeded_result_limit || processed_records > MAX_DOMAIN_RECORDS {
                return Err(
                    "DOMAIN_RESULT_TOO_BROAD: 域名匹配的 DNS 记录超过 10000 条，请增加限定条件"
                        .to_owned(),
                );
            }
            collect_domain_addresses(
                hits,
                depth < MAX_DOMAIN_CNAME_DEPTH,
                &mut addresses,
                &mut seen_names,
                &mut pending_names,
            )?;
        }

        let positive = if addresses.is_empty() {
            json!({"match_none": {}})
        } else {
            json!({"terms": {"ip": addresses.into_iter().collect::<Vec<_>>()}})
        };
        if matches!(operator, "not_eq" | "not_contains" | "not_in") {
            if positive.get("match_none").is_some() {
                Ok(json!({"match_all": {}}))
            } else {
                Ok(json!({"bool": {"must_not": [positive]}}))
            }
        } else {
            Ok(positive)
        }
    }

    fn update_runtime(&self, update: impl FnOnce(&mut ElasticsearchRuntime)) {
        let mut runtime = self
            .inner
            .runtime
            .write()
            .expect("elasticsearch runtime lock poisoned");
        update(&mut runtime);
    }

    fn mark_success(&self) {
        self.update_runtime(|runtime| {
            runtime.connected = true;
            runtime.last_success_at = Some(Utc::now());
            runtime.last_error = None;
        });
    }

    fn mark_error(&self, message: &str) {
        self.inner
            .scan_indices_ready
            .store(false, Ordering::Release);
        self.update_runtime(|runtime| {
            runtime.connected = false;
            runtime.read_ready = false;
            runtime.last_error = Some(message.chars().take(2_000).collect());
        });
    }

    pub(crate) async fn status(&self, pool: &Pool) -> Result<ElasticsearchStatus, String> {
        let connection = pool.get().await.map_err(|error| error.to_string())?;
        let row = connection
            .query_one(
                "SELECT COUNT(*)::BIGINT AS pending, MIN(created_at) AS oldest FROM ( \
                 SELECT created_at FROM search_index_outbox WHERE processed_at IS NULL AND event_kind = 'ip' \
                 UNION ALL SELECT created_at FROM scan_projection_outbox WHERE processed_at IS NULL) pending;",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok(ElasticsearchStatus {
            enabled: self.inner.config.enabled,
            read_enabled: self.inner.config.read_enabled,
            fallback_to_postgres: self.inner.config.fallback_to_postgres,
            url: self.inner.config.url.clone(),
            index: self.inner.config.current_endpoint_index.clone(),
            scan_storage: self.inner.config.scan_storage,
            observation_index_prefix: self.inner.config.observation_index_prefix.clone(),
            execution_endpoint_index: self.inner.config.execution_endpoint_index.clone(),
            current_endpoint_index: self.inner.config.current_endpoint_index.clone(),
            dns_observation_data_stream: self.inner.config.dns_observation_data_stream.clone(),
            dns_record_index: self.inner.config.dns_record_index.clone(),
            expected_version: self.inner.config.expected_version.clone(),
            runtime: self.runtime(),
            pending_events: row.get("pending"),
            oldest_pending_at: row.get("oldest"),
        })
    }

    pub async fn migrate_scan_data(&self, pool: &Pool) -> Result<ScanMigrationReport, String> {
        self.migrate_scan_data_with_progress(pool, &NoopProgressReporter)
            .await
    }

    pub async fn migrate_scan_data_with_progress(
        &self,
        pool: &Pool,
        reporter: &dyn ProgressReporter,
    ) -> Result<ScanMigrationReport, String> {
        let client = pool.get().await.map_err(|error| error.to_string())?;
        let pending: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM scan_result_batch WHERE storage_backend = 'pending'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        if pending > 0 {
            return Err(format!(
                "存在 {pending} 个 ES pending 上传，请先由原 ES 服务和扫描器完成重试；迁移不能把它们当作 PG 空批次"
            ));
        }
        drop(client);
        crate::scan_migration::prepare(pool, reporter).await?;
        reporter.report(ProgressUpdate::phase(
            "正在检查 Elasticsearch 并初始化扫描索引",
        ));
        self.initialize(pool).await?;
        reporter.report(ProgressUpdate::phase("正在在线创建扫描迁移读取索引"));
        let connection = pool.get().await.map_err(|error| error.to_string())?;
        connection
            .batch_execute(ENSURE_SCAN_MIGRATION_INDEX_SQL)
            .await
            .map_err(|error| error.to_string())?;
        drop(connection);

        let connection = pool.get().await.map_err(|error| error.to_string())?;
        let orphaned: i64 = connection
            .query_one(
                "SELECT COUNT(*) FROM ips i WHERE NOT EXISTS \
             (SELECT 1 FROM scan_result_batch b WHERE b.execution_id = i.execution_id)",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        if orphaned > 0 {
            return Err(format!(
                "存在 {orphaned} 条未关联迁移批次的 PG IP 结果，需先修复历史数据，不能标记迁移完成"
            ));
        }
        drop(connection);
        reporter.report(ProgressUpdate::phase("正在确定迁移高水位和恢复断点"));
        let (high_watermark, resume_execution_cursor, expected, mut report) =
            self.prepare_scan_migration(pool).await?;
        let expected_batches = reporter.is_enabled().then_some(expected.batches);
        let expected_observations = reporter.is_enabled().then_some(expected.observations);
        let mut execution_cursor = resume_execution_cursor;
        let mut confirmed_execution_cursor = resume_execution_cursor;
        let mut last_checkpoint_batches = report.batches;
        reporter.report(ProgressUpdate::count(
            "迁移扫描批次",
            report.batches,
            expected_batches,
            "批次",
            observation_progress(report.observations, expected_observations),
        ));
        loop {
            let connection = pool.get().await.map_err(|error| error.to_string())?;
            let rows = connection
                .query(
                    "SELECT e.id FROM scan_task_execution e \
                     WHERE e.id > $1 AND EXISTS (SELECT 1 FROM scan_result_batch b \
                        WHERE b.execution_id = e.id AND b.id <= $2 \
                          AND (b.payload_checksum IS NULL OR b.storage_backend = 'postgres')) \
                     ORDER BY e.id LIMIT $3;",
                    &[
                        &execution_cursor,
                        &high_watermark,
                        &i64::try_from(self.inner.config.scan_migration_page_size)
                            .map_err(|error| error.to_string())?,
                    ],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(connection);
            if rows.is_empty() {
                break;
            }
            let execution_ids = rows
                .into_iter()
                .map(|row| row.get::<_, i32>("id"))
                .collect::<Vec<_>>();
            execution_cursor = *execution_ids
                .last()
                .expect("non-empty execution page has a last id");
            let mut migrations = stream::iter(execution_ids.into_iter().map(|execution_db_id| {
                let service = self.clone();
                let pool = pool.clone();
                async move {
                    service
                        .migrate_scan_execution(&pool, execution_db_id, high_watermark)
                        .await
                }
            }))
            .buffer_unordered(self.inner.config.scan_migration_concurrency);
            while let Some(result) = migrations.next().await {
                let migrated = match result {
                    Ok(migrated) => migrated,
                    Err(error) => {
                        if let Err(checkpoint_error) = self
                            .write_scan_migration_state(
                                pool,
                                "in_progress",
                                high_watermark,
                                confirmed_execution_cursor,
                                report,
                            )
                            .await
                        {
                            warn!(
                                event = "ScanMigrationCheckpointError",
                                message = %checkpoint_error
                            );
                        }
                        return Err(error);
                    }
                };
                report.batches = report.batches.saturating_add(migrated.batches);
                report.observations = report.observations.saturating_add(migrated.observations);
                reporter.report(ProgressUpdate::count(
                    "迁移扫描批次",
                    report.batches,
                    expected_batches,
                    "批次",
                    format!(
                        "并发执行实例迁移中，最后调度 execution_db_id={execution_cursor}，{}",
                        observation_progress(report.observations, expected_observations)
                    ),
                ));
            }
            confirmed_execution_cursor = execution_cursor;
            if report.batches.saturating_sub(last_checkpoint_batches)
                < self.inner.config.scan_migration_checkpoint_batches
            {
                continue;
            }
            self.write_scan_migration_state(
                pool,
                "in_progress",
                high_watermark,
                confirmed_execution_cursor,
                report,
            )
            .await?;
            last_checkpoint_batches = report.batches;
        }
        reporter.report(ProgressUpdate::phase("正在写入扫描数据迁移完成标记"));
        let remaining: i64 = pool
            .get()
            .await
            .map_err(|error| error.to_string())?
            .query_one(
                "SELECT COUNT(*)::BIGINT AS remaining FROM scan_result_batch \
                 WHERE id <= $1 AND (payload_checksum IS NULL OR storage_backend = 'postgres');",
                &[&high_watermark],
            )
            .await
            .map_err(|error| error.to_string())?
            .get("remaining");
        if remaining > 0 {
            self.write_scan_migration_state(pool, "in_progress", high_watermark, 0, report)
                .await?;
            return Err(format!(
                "迁移高水位 {high_watermark} 以下仍有 {remaining} 个未完成批次，已重置执行游标以便重试"
            ));
        }
        report = expected;
        self.write_scan_migration_state(
            pool,
            "complete",
            high_watermark,
            confirmed_execution_cursor,
            report,
        )
        .await?;
        Ok(report)
    }

    async fn prepare_scan_migration(
        &self,
        pool: &Pool,
    ) -> Result<(i64, i32, ScanMigrationReport, ScanMigrationReport), String> {
        let connection = pool.get().await.map_err(|error| error.to_string())?;
        let previous = connection
            .query_opt(
                "SELECT state_value FROM scan_storage_state WHERE state_key = $1;",
                &[&SCAN_MIGRATION_STATE_KEY],
            )
            .await
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, Value>("state_value"));
        let resumable_high_watermark = previous
            .as_ref()
            .filter(|state| self.scan_migration_state_is_resumable(state))
            .and_then(|state| state.get("high_watermark").and_then(Value::as_i64));
        let high_watermark = match resumable_high_watermark {
            Some(high_watermark) => high_watermark,
            None => connection
                .query_one(
                    "SELECT COALESCE(MAX(id), 0)::BIGINT AS high_watermark FROM scan_result_batch;",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .get("high_watermark"),
        };
        let resume_execution_cursor = previous
            .as_ref()
            .filter(|state| self.scan_migration_state_is_resumable(state))
            .and_then(|state| state.get("execution_cursor").and_then(Value::as_i64))
            .and_then(|cursor| i32::try_from(cursor).ok())
            .unwrap_or(0);
        let totals = connection
            .query_one(
                "SELECT batch_counts.batches, batch_counts.completed_batches, \
                        observation_counts.observations, observation_counts.completed_observations \
                 FROM (SELECT COUNT(*)::BIGINT AS batches, \
                              COUNT(*) FILTER (WHERE payload_checksum IS NOT NULL AND storage_backend IN ('dual', 'elasticsearch'))::BIGINT AS completed_batches \
                       FROM scan_result_batch WHERE id <= $1) batch_counts \
                 CROSS JOIN (SELECT COUNT(*)::BIGINT AS observations, \
                                    COUNT(*) FILTER (WHERE b.payload_checksum IS NOT NULL AND b.storage_backend IN ('dual', 'elasticsearch'))::BIGINT AS completed_observations \
                             FROM scan_observation o JOIN scan_result_batch b ON b.id = o.batch_id \
                             WHERE b.id <= $1) observation_counts;",
                &[&high_watermark],
            )
            .await
            .map_err(|error| error.to_string())?;
        let expected = ScanMigrationReport {
            batches: u64::try_from(totals.get::<_, i64>("batches"))
                .map_err(|error| error.to_string())?,
            observations: u64::try_from(totals.get::<_, i64>("observations"))
                .map_err(|error| error.to_string())?,
        };
        let completed = ScanMigrationReport {
            batches: u64::try_from(totals.get::<_, i64>("completed_batches"))
                .map_err(|error| error.to_string())?,
            observations: u64::try_from(totals.get::<_, i64>("completed_observations"))
                .map_err(|error| error.to_string())?,
        };
        drop(connection);
        self.write_scan_migration_state(
            pool,
            "in_progress",
            high_watermark,
            resume_execution_cursor,
            completed,
        )
        .await?;
        Ok((high_watermark, resume_execution_cursor, expected, completed))
    }

    fn scan_migration_state_is_resumable(&self, state: &Value) -> bool {
        state.get("status").and_then(Value::as_str) == Some("in_progress")
            && state
                .get("observation_index_prefix")
                .and_then(Value::as_str)
                == Some(self.inner.config.observation_index_prefix.as_str())
            && state
                .get("execution_endpoint_index")
                .and_then(Value::as_str)
                == Some(self.inner.config.execution_endpoint_index.as_str())
            && state.get("current_endpoint_index").and_then(Value::as_str)
                == Some(self.inner.config.current_endpoint_index.as_str())
    }

    async fn write_scan_migration_state(
        &self,
        pool: &Pool,
        status: &str,
        high_watermark: i64,
        execution_cursor: i32,
        report: ScanMigrationReport,
    ) -> Result<(), String> {
        let value = json!({
            "status": status,
            "observation_index_prefix": self.inner.config.observation_index_prefix,
            "execution_endpoint_index": self.inner.config.execution_endpoint_index,
            "current_endpoint_index": self.inner.config.current_endpoint_index,
            "high_watermark": high_watermark,
            "execution_cursor": execution_cursor,
            "batches": report.batches,
            "observations": report.observations
        });
        pool.get()
            .await
            .map_err(|error| error.to_string())?
            .execute(
                "INSERT INTO scan_storage_state (state_key, state_value, updated_at) \
                 VALUES ($1, $2, NOW()) ON CONFLICT (state_key) DO UPDATE \
                 SET state_value = EXCLUDED.state_value, updated_at = NOW();",
                &[&SCAN_MIGRATION_STATE_KEY, &value],
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    async fn migrate_scan_execution(
        &self,
        pool: &Pool,
        execution_db_id: i32,
        high_watermark: i64,
    ) -> Result<ScanMigrationReport, String> {
        let mut connection = pool.get().await.map_err(|error| error.to_string())?;
        let batches = connection
            .query(
                "SELECT b.id, b.upload_id, b.batch_index, b.is_final, b.observation_count, t.task_id, t.user_id, \
                    t.task_source, e.execution_id, e.execution_status, \
                    COALESCE(e.assigned_scanner_id, e.requested_scanner_id, 'unknown') AS scanner_id, \
                    COALESCE(scanner.name, e.assigned_scanner_id, e.requested_scanner_id) AS scanner_name \
                 FROM scan_result_batch b JOIN scan_task_execution e ON e.id = b.execution_id \
                 JOIN scan_task t ON t.id = e.task_id \
                 LEFT JOIN scanner_info scanner ON scanner.scanner_id = \
                    COALESCE(e.assigned_scanner_id, e.requested_scanner_id) \
                 WHERE b.execution_id = $1 AND b.id <= $2 \
                   AND (b.payload_checksum IS NULL OR b.storage_backend = 'postgres') \
                 ORDER BY b.batch_index, b.id;",
                &[&execution_db_id, &high_watermark],
            )
            .await
            .map_err(|error| error.to_string())?;
        let mut report = ScanMigrationReport::default();
        for batch in batches {
            let batch_id: i64 = batch.get("id");
            let execution_id: String = batch.get("execution_id");
            let rows = connection
                .query(
                    "SELECT o.observation_key, o.kind, host(o.ip_address) AS ip_address, \
                        o.ip_address::TEXT AS ip_network, o.port, \
                        o.protocol, o.service, o.banner, o.title, o.http_body, o.http_body_truncated, \
                        o.tls_subject, o.search_content_extracted, o.source, o.data, \
                        FLOOR(EXTRACT(EPOCH FROM o.observed_at) * 1000)::BIGINT AS observed_at, \
                        i.asn, i.isp, i.as_org, i.country_code, i.country_name, i.region_name, i.city_name, \
                        COALESCE(tags.tags, '[]'::JSONB) AS tags \
                     FROM scan_observation o \
                     LEFT JOIN ips i ON i.execution_id = o.execution_id AND i.ip_address = o.ip_address \
                     LEFT JOIN LATERAL (SELECT JSONB_AGG(JSONB_BUILD_OBJECT( \
                        'id', tag.id, 'name', tag.name, 'kind', tag.kind, 'description', tag.description, \
                        'category_id', category.id, 'category_name', category.name) \
                        ORDER BY category.sort_order, LOWER(category.name), tag.id) AS tags FROM asset_ip_tag assignment \
                        JOIN asset_tag tag ON tag.id = assignment.tag_id \
                        JOIN asset_tag_category category ON category.id = tag.category_id \
                        WHERE assignment.ip_address = o.ip_address AND tag.is_active AND category.is_active) tags ON true \
                     WHERE o.batch_id = $1 ORDER BY o.id;",
                    &[&batch_id],
                )
                .await
                .map_err(|error| error.to_string())?;
            if rows.len()
                != usize::try_from(batch.get::<_, i32>("observation_count"))
                    .map_err(|error| error.to_string())?
            {
                return Err(format!(
                    "PG 批次 {batch_id} 的观察数量与回执不符，拒绝迁移不完整结果"
                ));
            }
            let observations = rows
                .into_iter()
                .map(|row| {
                    let ip: String = row.get("ip_address");
                    let network: String = row.get("ip_network");
                    let port: i32 = row.get("port");
                    let endpoint_id =
                        sha256_hex(format!("{execution_id}\0{network}\0{port}\0{}",row.get::<_,Option<String>>("protocol").as_deref().unwrap_or("unknown")).as_bytes());
                    let data = row.get::<_, Option<Value>>("data");
                    let extracted = crate::search_content::extract_search_content(data.as_ref());
                    let title = row.get::<_, Option<String>>("title").or(extracted.title);
                    let tls_subject = row
                        .get::<_, Option<String>>("tls_subject")
                        .or(extracted.tls_subject);
                    json!({
                        "observation_key": row.get::<_, String>("observation_key"),
                        "endpoint_id": endpoint_id,
                        "kind": row.get::<_, String>("kind"), "ip_address": ip,
                        "ip_network": network, "port": port,
                        "protocol": row.get::<_, Option<String>>("protocol"),
                        "service": row.get::<_, Option<String>>("service"),
                        "banner": row.get::<_, Option<String>>("banner"),
                        "title": title,
                        "http_body": row.get::<_, Option<String>>("http_body"),
                        "http_body_truncated": row.get::<_, bool>("http_body_truncated"),
                        "tls_mode": extracted.tls_mode,
                        "tls_version": extracted.tls_version,
                        "tls_cipher_suite": extracted.tls_cipher_suite,
                        "tls_subject": tls_subject,
                        "tls_issuer": extracted.tls_issuer,
                        "tls_names": extracted.tls_names,
                        "tls_serial_number": extracted.tls_serial_number,
                        "tls_not_before": extracted.tls_not_before,
                        "tls_not_after": extracted.tls_not_after,
                        "tls_fingerprint_sha256": extracted.tls_fingerprint_sha256,
                        "tls_self_signed": extracted.tls_self_signed,
                        "search_content_extracted": row.get::<_, bool>("search_content_extracted"),
                        "source": row.get::<_, String>("source"), "data": data,
                        "observed_at": row.get::<_, i64>("observed_at"),
                        "asn": row.get::<_, Option<String>>("asn"), "isp": row.get::<_, Option<String>>("isp"),
                        "as_org": row.get::<_, Option<String>>("as_org"),
                        "country_code": row.get::<_, Option<String>>("country_code"),
                        "country_name": row.get::<_, Option<String>>("country_name"),
                        "region_name": row.get::<_, Option<String>>("region_name"),
                        "city_name": row.get::<_, Option<String>>("city_name"),
                        "tags": row.get::<_, Value>("tags")
                    })
                })
                .collect::<Vec<_>>();
            let context = ScanBatchContext {
                task_id: batch.get("task_id"),
                execution_id,
                user_id: batch.get("user_id"),
                task_source: batch.get("task_source"),
                scanner_id: batch.get("scanner_id"),
                scanner_name: batch.get("scanner_name"),
                upload_id: batch.get("upload_id"),
                batch_index: batch.get("batch_index"),
                is_final: batch.get("is_final"),
            };
            let result = self
                .persist_scan_batch_prepared(&context, &observations, None)
                .await
                .map_err(|error| {
                    format!(
                        "迁移 execution_db_id={execution_db_id} batch_id={batch_id} 失败：{error}"
                    )
                })?;
            let storage_references = json!(result.indices);
            if context.is_final {
                if batch.get::<_, String>("execution_status") == "succeeded" {
                    self.promote_execution(&context).await.map_err(|error| {
                    format!(
                        "发布 execution_db_id={execution_db_id} batch_id={batch_id} 失败：{error}"
                    )
                })?;
                }
                let transaction = connection
                    .transaction()
                    .await
                    .map_err(|error| error.to_string())?;
                transaction
                    .execute(
                        "UPDATE scan_result_batch SET payload_checksum = $2, storage_backend = 'elasticsearch', \
                         storage_references = $3 WHERE id = $1;",
                        &[&batch_id, &result.payload_checksum, &storage_references],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let summary = result
                    .execution_summary
                    .ok_or_else(|| "最终扫描批次缺少执行汇总".to_owned())?;
                transaction
                    .execute(
                        "UPDATE scan_task_execution SET result_ip_count = $2, result_port_count = $3, \
                         result_observation_count = $4 WHERE id = $1;",
                        &[
                            &execution_db_id,
                            &summary.ip_count,
                            &summary.port_count,
                            &summary.observation_count,
                        ],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                transaction
                    .commit()
                    .await
                    .map_err(|error| error.to_string())?;
            } else {
                connection
                    .execute(
                    "UPDATE scan_result_batch SET payload_checksum = $2, storage_backend = 'elasticsearch', \
                     storage_references = $3 WHERE id = $1;",
                    &[&batch_id, &result.payload_checksum, &storage_references],
                )
                .await
                .map_err(|error| error.to_string())?;
            }
            report.batches = report.batches.saturating_add(1);
            report.observations = report
                .observations
                .saturating_add(observations.len() as u64);
        }
        Ok(report)
    }

    /// Fresh installs bootstrap directly into ES. Legacy data requires explicit migration;
    /// ordinary restarts must allow pending ES receipts and outbox retries to recover.
    pub async fn validate_scan_cutover(&self, pool: &Pool) -> Result<(), String> {
        let connection = pool.get().await.map_err(|error| error.to_string())?;
        let runtime = connection.query_opt(
            "SELECT state_value FROM scan_storage_state WHERE state_key = 'elasticsearch_runtime'", &[]
        ).await.map_err(|error| error.to_string())?.map(|row| row.get::<_, Value>(0));
        let migration = connection
            .query_opt(
                "SELECT state_value FROM scan_storage_state WHERE state_key = $1",
                &[&SCAN_MIGRATION_STATE_KEY],
            )
            .await
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, Value>(0));
        let target = json!({
            "observation_index_prefix": self.inner.config.observation_index_prefix,
            "execution_endpoint_index": self.inner.config.execution_endpoint_index,
            "current_endpoint_index": self.inner.config.current_endpoint_index,
            "dns_observation_data_stream": self.inner.config.dns_observation_data_stream,
            "dns_record_index": self.inner.config.dns_record_index,
            "endpoint_identity_version": 2,
        });
        if runtime.as_ref().is_some_and(|state| state != &target) {
            return Err(
                "ES 存储目标与已初始化的运行标记不符，禁止切换到空索引；请先完成受控迁移".into(),
            );
        }
        let legacy_batches: i64 = connection.query_one(
            "SELECT COUNT(*) FROM scan_result_batch WHERE storage_backend NOT IN ('elasticsearch', 'dual', 'pending') \
             OR (storage_backend <> 'pending' AND payload_checksum IS NULL)", &[]
        ).await.map_err(|error| error.to_string())?.get(0);
        if legacy_batches > 0 {
            return Err(format!(
                "存在 {legacy_batches} 个未迁移 PG 扫描批次；请停服运行 --migrate-scan-data-to-elasticsearch"
            ));
        }
        let incomplete: i64 = connection.query_one(
            "SELECT COUNT(*) FROM scan_task_execution WHERE execution_status = 'succeeded' \
             AND (result_ip_count IS NULL OR result_port_count IS NULL OR result_observation_count IS NULL)", &[]
        ).await.map_err(|error| error.to_string())?.get(0);
        if incomplete > 0 {
            return Err(format!(
                "存在 {incomplete} 个缺少结果计数的成功执行；请完成迁移/恢复对账"
            ));
        }
        if runtime.is_none() {
            let mut legacy_data = false;
            // Fixed identifiers only; never create or alter legacy result tables on startup.
            for table in [
                "scan_observation",
                "ips",
                "ports",
                "scaninfo",
                "asset_endpoint_current",
            ] {
                let exists: bool = connection
                    .query_one("SELECT to_regclass($1) IS NOT NULL", &[&table])
                    .await
                    .map_err(|error| error.to_string())?
                    .get(0);
                if exists {
                    let nonempty: bool = connection
                        .query_one(&format!("SELECT EXISTS (SELECT 1 FROM {table})"), &[])
                        .await
                        .map_err(|error| error.to_string())?
                        .get(0);
                    legacy_data |= nonempty;
                }
            }
            let migration_ready = migration.as_ref().is_some_and(|state| {
                state
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("complete")
                    == "complete"
                    && [
                        "observation_index_prefix",
                        "execution_endpoint_index",
                        "current_endpoint_index",
                    ]
                    .iter()
                    .all(|key| state.get(*key) == target.get(*key))
            });
            if legacy_data && !migration_ready {
                return Err(
                    "检测到 PG 历史扫描结果，请先停服运行 --migrate-scan-data-to-elasticsearch"
                        .into(),
                );
            }
            if migration.as_ref().is_some_and(|state| {
                state.get("status").and_then(Value::as_str) == Some("in_progress")
            }) {
                return Err("PG -> ES 迁移尚未完成，请继续运行迁移命令".into());
            }
        }
        // Check recorded facts before initialize can create missing projection containers.
        let references = connection
            .query(
                "SELECT DISTINCT ref #>> '{}' AS name FROM scan_result_batch b \
             CROSS JOIN LATERAL jsonb_array_elements(b.storage_references) ref \
             WHERE b.storage_backend IN ('elasticsearch', 'dual')",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
        for row in references {
            let index: String = row.get("name");
            let index = match index.as_str() {
                "dns-observations" => self.inner.config.dns_observation_data_stream.as_str(),
                "dns-records" => self.inner.config.dns_record_index.as_str(),
                _ => index.as_str(),
            };
            self.require_existing_index(index).await?;
        }
        if runtime.is_some() {
            for index in [
                &self.inner.config.execution_endpoint_index,
                &self.inner.config.current_endpoint_index,
                &self.inner.config.dns_observation_data_stream,
                &self.inner.config.dns_record_index,
            ] {
                self.require_existing_index(index).await?;
            }
        }
        drop(connection);
        self.initialize(pool).await?;
        let connection = pool.get().await.map_err(|error| error.to_string())?;
        connection.execute(
            "INSERT INTO scan_storage_state (state_key, state_value) VALUES ('elasticsearch_runtime', $1) \
             ON CONFLICT (state_key) DO NOTHING", &[&target]
        ).await.map_err(|error| error.to_string())?;
        Ok(())
    }

    async fn require_existing_index(&self, index: &str) -> Result<(), String> {
        if index.is_empty() || index.contains(['/', '?', '#', '*', ',']) {
            return Err("扫描回执包含无效索引引用".into());
        }
        let response = self
            .send_request(
                ElasticsearchOperation::IndexAdmin,
                Method::HEAD,
                &format!("/{index}"),
                |request| request,
            )
            .await?;
        if !response.status().is_success() {
            return Err(format!(
                "扫描索引 {index} 不可用（{}）；请恢复数据，不能按空库启动",
                response.status()
            ));
        }
        Ok(())
    }
}

fn elasticsearch_request_error(
    error: reqwest::Error,
    method: &Method,
    path: &str,
    started: Instant,
) -> String {
    let timed_out = error.is_timeout();
    let connect = error.is_connect();
    // A configured URL may contain credentials; diagnostics need the operation
    // and source chain, not the URL or query string.
    let error = error.without_url();
    let chain = crate::logs::write::error_chain_diagnostics(&error);
    format!(
        "Elasticsearch {method} {} 请求失败（timeout={timed_out}, connect={connect}, elapsed_ms={}）：{chain}",
        path.split('?').next().unwrap_or_default(),
        started.elapsed().as_millis()
    )
}

fn validate_scan_refresh_response(result: &Value) -> Result<(), String> {
    validate_scan_search_response(result)?;
    let total = result.pointer("/_shards/total").and_then(Value::as_u64);
    let successful = result
        .pointer("/_shards/successful")
        .and_then(Value::as_u64);
    match (total, successful) {
        (Some(total), Some(0)) if total > 0 => Err(format!(
            "Elasticsearch 刷新未成功处理任何分片（total={total}, successful=0）；请检查目标索引主分片分配与集群健康，不能将 failed=0 视为刷新完成"
        )),
        (Some(_), Some(_)) => Ok(()),
        _ => Err("Elasticsearch 刷新响应缺少分片计数，拒绝确认发布完成".into()),
    }
}

pub(crate) fn validate_scan_search_response(result: &Value) -> Result<(), String> {
    if result.get("timed_out").and_then(Value::as_bool) == Some(true) {
        return Err("Elasticsearch 扫描查询超时，拒绝使用不完整统计".to_owned());
    }
    if result
        .pointer("/_shards/failed")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        > 0
    {
        return Err("Elasticsearch 扫描查询存在失败分片，拒绝使用不完整统计".to_owned());
    }
    Ok(())
}

fn dns_task_observations_search_body(task_id: &str) -> Value {
    json!({
        "size": 10_000,
        "track_total_hits": false,
        "query": {"term": {"scan.task_id": task_id}},
        "sort": [
            {"@timestamp": {"order": "desc"}},
            {"event_id": "asc"}
        ]
    })
}

pub(crate) fn scan_batch_payload_checksum(
    context: &ScanBatchContext,
    observations: &[Value],
) -> Result<String, String> {
    let checksum_input = json!({
        "task_id": context.task_id,
        "execution_id": context.execution_id,
        "upload_id": context.upload_id,
        "batch_index": context.batch_index,
        "is_final": context.is_final,
        "observations": observations.iter().map(immutable_scan_observation).collect::<Vec<_>>(),
    });
    Ok(sha256_hex(
        &serde_json::to_vec(&checksum_input).map_err(|error| error.to_string())?,
    ))
}

pub async fn run_worker(service: ElasticsearchService, pool: Pool) {
    if !service.enabled() {
        return;
    }
    let mut ticker = interval(Duration::from_millis(service.inner.config.poll_interval_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut initialization_failures = 0_u32;
    loop {
        tokio::select! {
            _ = ticker.tick() => {},
            _ = service.inner.projection_notify.notified() => {},
        }
        if !service.can_read() {
            match service.validate_scan_cutover(&pool).await {
                Ok(_) => {
                    if initialization_failures > 0 {
                        info!(
                            event = "ElasticsearchInitializeRecovered",
                            failed_attempts = initialization_failures,
                            "Elasticsearch 初始化已恢复"
                        );
                    }
                    initialization_failures = 0;
                }
                Err(message) => {
                    service.mark_error(&message);
                    initialization_failures = initialization_failures.saturating_add(1);
                    let retry_after = initialization_retry_delay(
                        service.inner.config.poll_interval_ms,
                        initialization_failures,
                    );
                    // 首次失败和指数退避的边界都保留完整日志，避免配置错误时每个轮询
                    // 周期重复同一条错误。
                    if initialization_failures == 1 || initialization_failures.is_power_of_two() {
                        warn!(
                            event = "ElasticsearchInitializeError",
                            operation = "validate_elasticsearch_cutover",
                            reason = %message,
                            error_code = "elasticsearch_initialization_failed",
                            retryable = true,
                            outcome = "worker_retry_scheduled",
                            attempt = initialization_failures,
                            retry_after_ms = retry_after.as_millis(),
                            index_family = %service.inner.config.observation_index_prefix,
                            "Elasticsearch 初始化失败，稍后重试"
                        );
                    }
                    sleep(retry_after).await;
                    continue;
                }
            }
        }
        match service.process_scan_projection_outbox(&pool).await {
            Ok(_) => {}
            Err(message) => {
                warn!(event = "ScanProjectionWorkerError", error_message = %message,
                    retryable = true, outcome = "worker_retry_scheduled");
            }
        }

        if let Err(message) = service.process_os_detection_outbox(&pool).await {
            warn!(event = "OsDetectionWorkerError", error_message = %message, retryable = true);
        }

        if let Err(message) = service.process_web_detection_outbox(&pool).await {
            warn!(event = "WebDetectionWorkerError", error_message = %message, retryable = true);
        }

        let event = match claim_ip_event(&pool).await {
            Ok(value) => value,
            Err(message) => {
                service.mark_error(&message);
                error!(
                    event = "ElasticsearchTagOutboxClaimError",
                    operation = "claim_tag_outbox_event",
                    error_kind = "database",
                    error_code = "tag_outbox_claim_failed",
                    error_message = %message,
                    retryable = true,
                    outcome = "worker_retry_scheduled",
                    retry_after_ms = service.inner.config.poll_interval_ms,
                );
                continue;
            }
        };
        let Some(event) = event else {
            continue;
        };
        match process_scan_tag_event(&service, &pool, &event).await {
            Ok(()) => {
                if let Err(message) = complete_event(&pool, event.id).await {
                    error!(
                        event = "ElasticsearchTagOutboxCompleteError",
                        operation = "complete_tag_outbox_event",
                        error_kind = "database",
                        error_code = "tag_outbox_complete_failed",
                        error_message = %message,
                        retryable = true,
                        outcome = "outbox_event_pending",
                        outbox_id = event.id,
                        aggregate_key = %event.aggregate_key,
                        attempt = event.attempts,
                        retry_after_ms = service.inner.config.poll_interval_ms,
                    );
                }
            }
            Err(message) => {
                service.mark_error(&message);
                let retry_after_seconds =
                    i64::from(2_i32.saturating_pow(event.attempts.clamp(1, 8) as u32));
                warn!(
                    event = "ElasticsearchTagOutboxProcessError",
                    operation = "project_asset_tags",
                    reason = %message,
                    error_code = "tag_outbox_projection_failed",
                    retryable = true,
                    outcome = "outbox_retry_scheduled",
                    outbox_id = event.id,
                    aggregate_key = %event.aggregate_key,
                    attempt = event.attempts,
                    retry_after_ms = retry_after_seconds.saturating_mul(1_000),
                );
                if let Err(mark_error) = retry_event(&pool, &event, &message).await {
                    error!(
                        event = "ElasticsearchTagOutboxRetryError",
                        operation = "schedule_tag_outbox_retry",
                        error_kind = "database",
                        error_code = "tag_outbox_retry_schedule_failed",
                        error_message = %mark_error,
                        retryable = true,
                        outcome = "outbox_event_locked_until_timeout",
                        outbox_id = event.id,
                        aggregate_key = %event.aggregate_key,
                        attempt = event.attempts,
                        retry_after_ms = OUTBOX_LOCK_TIMEOUT_MINUTES.saturating_mul(60_000),
                    );
                }
            }
        }
        continue;
    }
}

async fn claim_ip_event(pool: &Pool) -> Result<Option<OutboxEvent>, String> {
    let connection = pool.get().await.map_err(|error| error.to_string())?;
    let row = connection
        .query_opt(
            "UPDATE search_index_outbox SET locked_at = NOW(), attempts = attempts + 1 \
             WHERE id = (SELECT id FROM search_index_outbox \
                 WHERE event_kind = 'ip' AND processed_at IS NULL AND available_at <= NOW() \
                   AND (locked_at IS NULL OR locked_at < NOW() - ($1::BIGINT * INTERVAL '1 minute')) \
                 ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1) \
             RETURNING id, event_kind, aggregate_key, attempts;",
            &[&OUTBOX_LOCK_TIMEOUT_MINUTES],
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(row.map(|row| OutboxEvent {
        id: row.get("id"),
        aggregate_key: row.get("aggregate_key"),
        attempts: row.get("attempts"),
    }))
}

async fn process_scan_tag_event(
    service: &ElasticsearchService,
    pool: &Pool,
    event: &OutboxEvent,
) -> Result<(), String> {
    let connection = pool.get().await.map_err(|error| error.to_string())?;
    let rows = connection
        .query(
            "SELECT tag.id, tag.name, tag.kind, tag.description, category.id AS category_id, \
                    category.name AS category_name \
             FROM asset_ip_tag assignment JOIN asset_tag tag ON tag.id = assignment.tag_id \
             JOIN asset_tag_category category ON category.id = tag.category_id \
             WHERE assignment.ip_address = $1::TEXT::INET AND tag.is_active AND category.is_active \
             ORDER BY category.sort_order, LOWER(category.name), tag.id;",
            &[&event.aggregate_key],
        )
        .await
        .map_err(|error| error.to_string())?;
    let tags = rows
        .into_iter()
        .map(|row| AssetTag {
            id: row.get("id"),
            name: row.get("name"),
            kind: row.get("kind"),
            description: row.get("description"),
            category_id: row.try_get("category_id").ok(),
            category_name: row.try_get("category_name").ok(),
        })
        .collect::<Vec<_>>();
    drop(connection);
    service
        .refresh_scan_asset_tags(&event.aggregate_key, &tags)
        .await
}

fn parse_asn(value: &str) -> Option<i64> {
    canonical_asn(value).parse().ok()
}

fn canonical_asn(value: &str) -> &str {
    value
        .strip_prefix("AS")
        .or_else(|| value.strip_prefix("as"))
        .unwrap_or(value)
}

async fn load_scan_batch_context<C>(
    connection: &C,
    execution_db_id: i32,
) -> Result<ScanBatchContext, String>
where
    C: GenericClient + Sync,
{
    let row = connection.query_one(
        "SELECT t.task_id, t.user_id, t.task_source, e.execution_id, e.execution_status, \
            COALESCE(e.assigned_scanner_id, e.requested_scanner_id, 'unknown') AS scanner_id, \
            COALESCE(scanner.name, e.assigned_scanner_id, e.requested_scanner_id) AS scanner_name, \
            batch.upload_id, batch.batch_index \
         FROM scan_task_execution e JOIN scan_task t ON t.id = e.task_id \
         LEFT JOIN scanner_info scanner ON scanner.scanner_id = \
            COALESCE(e.assigned_scanner_id, e.requested_scanner_id) \
         JOIN LATERAL (SELECT upload_id, batch_index FROM scan_result_batch \
            WHERE execution_id = e.id ORDER BY is_final DESC, batch_index DESC LIMIT 1) batch ON true \
         WHERE e.id = $1;",
        &[&execution_db_id],
    ).await.map_err(|error| error.to_string())?;
    Ok(ScanBatchContext {
        task_id: row.get("task_id"),
        execution_id: row.get("execution_id"),
        user_id: row.get("user_id"),
        task_source: row.get("task_source"),
        scanner_id: row.get("scanner_id"),
        scanner_name: row.get("scanner_name"),
        upload_id: row.get("upload_id"),
        batch_index: row.get("batch_index"),
        is_final: true,
    })
}

async fn complete_event(pool: &Pool, id: i64) -> Result<(), String> {
    let connection = pool.get().await.map_err(|error| error.to_string())?;
    connection
        .execute(
            "UPDATE search_index_outbox SET processed_at = NOW(), locked_at = NULL, last_error = NULL \
             WHERE id = $1;",
            &[&id],
        )
        .await
        .map_err(|error| error.to_string())?;
    connection
        .execute(
            "DELETE FROM search_index_outbox WHERE processed_at < NOW() - INTERVAL '7 days';",
            &[],
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn retry_event(pool: &Pool, event: &OutboxEvent, message: &str) -> Result<(), String> {
    let delay_seconds = i64::from(2_i32.saturating_pow(event.attempts.clamp(1, 8) as u32));
    let last_error: String = message.chars().take(2_000).collect();
    let connection = pool.get().await.map_err(|error| error.to_string())?;
    connection
        .execute(
            "UPDATE search_index_outbox SET locked_at = NULL, last_error = $2, \
             available_at = NOW() + ($3::BIGINT * INTERVAL '1 second') WHERE id = $1;",
            &[&event.id, &last_error, &delay_seconds],
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn parse_storage_metrics(response: &Value) -> Result<ElasticsearchStorageMetrics, String> {
    let response = response
        .as_object()
        .ok_or_else(|| "Elasticsearch 索引统计响应不是对象".to_owned())?;
    let empty_indices = serde_json::Map::new();
    let indices = match response.get("indices") {
        Some(value) => value
            .as_object()
            .ok_or_else(|| "Elasticsearch 索引统计响应的 indices 不是对象".to_owned())?,
        None => &empty_indices,
    };
    let mut parsed_indices = BTreeMap::new();
    let mut primary_size = 0_i64;
    let mut total_size = 0_i64;

    for (name, value) in indices {
        let Some(primary) = value
            .pointer("/primaries/store/size_in_bytes")
            .and_then(Value::as_u64)
            .and_then(|size| i64::try_from(size).ok())
        else {
            warn!(
                event = "ElasticsearchStorageMetricIndexSkipped",
                index = %name,
                reason = "missing_or_invalid_primary_size"
            );
            continue;
        };
        let Some(total) = value
            .pointer("/total/store/size_in_bytes")
            .and_then(Value::as_u64)
            .and_then(|size| i64::try_from(size).ok())
        else {
            warn!(
                event = "ElasticsearchStorageMetricIndexSkipped",
                index = %name,
                reason = "missing_or_invalid_total_size"
            );
            continue;
        };
        if total < primary {
            warn!(
                event = "ElasticsearchStorageMetricIndexSkipped",
                index = %name,
                primary,
                total,
                reason = "total_smaller_than_primary"
            );
            continue;
        }
        primary_size = primary_size
            .checked_add(primary)
            .ok_or_else(|| "Elasticsearch 主分片容量汇总溢出".to_owned())?;
        total_size = total_size
            .checked_add(total)
            .ok_or_else(|| "Elasticsearch 总容量汇总溢出".to_owned())?;
        parsed_indices.insert(
            name.clone(),
            ElasticsearchIndexStorage {
                primary,
                replica: total - primary,
                total,
            },
        );
    }

    if !indices.is_empty() && parsed_indices.is_empty() {
        return Err("Elasticsearch 索引统计不包含有效容量数据".to_owned());
    }
    Ok(ElasticsearchStorageMetrics {
        enabled: true,
        available: true,
        primary_size: Some(primary_size),
        replica_size: Some(total_size - primary_size),
        total_size: Some(total_size),
        indices: parsed_indices,
    })
}

async fn response_json(response: reqwest::Response) -> Result<Value, String> {
    if !response.status().is_success() {
        return Err(response_error(response).await);
    }
    response.json().await.map_err(|error| error.to_string())
}

fn new_trace_context() -> (String, String) {
    let trace_id = Uuid::new_v4().simple().to_string();
    let span_source = Uuid::new_v4().simple().to_string();
    let traceparent = format!("00-{trace_id}-{}-01", &span_source[..16]);
    (trace_id, traceparent)
}

fn is_retryable_bulk_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

fn bulk_response_is_retryable(result: &Value, create_conflict_is_success: bool) -> bool {
    if result.get("errors").and_then(Value::as_bool) != Some(true) {
        return false;
    }
    let mut saw_retryable = false;
    for action in result
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .flat_map(|item| item.values())
    {
        let Some(status) = action.get("status").and_then(Value::as_u64) else {
            return false;
        };
        if status < 300 || (create_conflict_is_success && status == 409) {
            continue;
        }
        let Ok(status) = u16::try_from(status) else {
            return false;
        };
        let Ok(status) = StatusCode::from_u16(status) else {
            return false;
        };
        if !is_retryable_bulk_status(status) {
            return false;
        }
        saw_retryable = true;
    }
    saw_retryable
}

fn bulk_retry_delay(initial_ms: u64, attempt: u32) -> Duration {
    let multiplier = 1_u64.checked_shl(attempt.min(16)).unwrap_or(u64::MAX);
    Duration::from_millis(initial_ms.saturating_mul(multiplier).min(30_000))
}

fn initialization_retry_delay(poll_interval_ms: u64, failures: u32) -> Duration {
    let initial_ms = poll_interval_ms.max(500);
    let exponent = failures.saturating_sub(1).min(6);
    let multiplier = 1_u64.checked_shl(exponent).unwrap_or(u64::MAX);
    Duration::from_millis(initial_ms.saturating_mul(multiplier).min(30_000))
}

async fn response_error(response: reqwest::Response) -> String {
    let status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_else(|error| error.to_string());
    format!(
        "Elasticsearch HTTP {status}: {}",
        body.chars().take(2_000).collect::<String>()
    )
}

fn collect_has_endpoint_filters(value: &Value, filters: &mut Vec<Value>) {
    match value {
        Value::Object(object) => {
            if let Some(filter) = object.get("network_mapping_has_endpoint") {
                filters.push(filter.clone());
                return;
            }
            for child in object.values() {
                collect_has_endpoint_filters(child, filters);
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_has_endpoint_filters(child, filters);
            }
        }
        _ => {}
    }
}

pub(crate) fn collect_domain_filters(value: &Value, filters: &mut Vec<Value>) {
    match value {
        Value::Object(object) => {
            if let Some(filter) = object.get("network_mapping_domain") {
                filters.push(filter.clone());
                return;
            }
            for child in object.values() {
                collect_domain_filters(child, filters);
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_domain_filters(child, filters);
            }
        }
        _ => {}
    }
}

fn replace_has_endpoint_filters(
    value: Value,
    addresses: &mut impl Iterator<Item = Vec<String>>,
) -> Value {
    match value {
        Value::Object(mut object) => {
            if object.contains_key("network_mapping_has_endpoint") {
                return json!({"terms": {"ip": addresses.next().unwrap_or_default()}});
            }
            for child in object.values_mut() {
                *child = replace_has_endpoint_filters(child.take(), addresses);
            }
            Value::Object(object)
        }
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|child| replace_has_endpoint_filters(child, addresses))
                .collect(),
        ),
        other => other,
    }
}

pub(crate) fn replace_domain_filters(
    value: Value,
    filters: &mut impl Iterator<Item = Value>,
) -> Value {
    match value {
        Value::Object(mut object) => {
            if object.contains_key("network_mapping_domain") {
                return filters.next().unwrap_or_else(|| json!({"match_none": {}}));
            }
            for child in object.values_mut() {
                *child = replace_domain_filters(child.take(), filters);
            }
            Value::Object(object)
        }
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|child| replace_domain_filters(child, filters))
                .collect(),
        ),
        other => other,
    }
}

fn escape_es_wildcard(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('*', "\\*")
        .replace('?', "\\?")
}

fn collect_domain_addresses(
    hits: &[Value],
    follow_cname: bool,
    addresses: &mut BTreeSet<String>,
    seen_names: &mut BTreeSet<String>,
    pending_names: &mut BTreeSet<String>,
) -> Result<(), String> {
    for hit in hits {
        let source = hit.get("_source").unwrap_or(hit);
        match source.get("record_type").and_then(Value::as_str) {
            Some("A") | Some("AAAA") => {
                if let Some(ip) = source.get("ip").and_then(Value::as_str) {
                    addresses.insert(ip.to_owned());
                }
            }
            Some("CNAME") if follow_cname => {
                if let Some(target) = source.get("target_domain").and_then(Value::as_str) {
                    let target = target.trim_end_matches('.').to_ascii_lowercase();
                    if seen_names.insert(target.clone()) {
                        if seen_names.len() > MAX_DOMAIN_NAMES {
                            return Err(
                                "DOMAIN_RESULT_TOO_BROAD: 域名 CNAME 链过宽，请使用更精确的域名"
                                    .to_owned(),
                            );
                        }
                        pending_names.insert(target);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn immutable_scan_observation(value: &Value) -> Value {
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        // Preserve checksums written by the legacy representation, which kept
        // CIDR (including /32 and /128) directly in `ip_address`.
        if let Some(network) = object.remove("ip_network") {
            object.insert("ip_address".to_owned(), network);
        }
        for field in [
            "asn",
            "isp",
            "as_org",
            "country_code",
            "country_name",
            "region_name",
            "city_name",
            "latitude",
            "longitude",
            "tags",
        ] {
            object.remove(field);
        }
    }
    value
}

fn sha256_hex(value: &[u8]) -> String {
    openssl::sha::sha256(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn scan_observation_index(prefix: &str, observed_at_ms: i64) -> Result<String, String> {
    let observed_at = DateTime::<Utc>::from_timestamp_millis(observed_at_ms)
        .ok_or_else(|| format!("无效 observed_at：{observed_at_ms}"))?;
    Ok(format!("{}-{}", prefix, observed_at.format("%Y.%m")))
}

fn observation_search_target(prefix: &str, indices: &[String]) -> Result<String, String> {
    if indices.is_empty() {
        return Ok(format!("{prefix}-*"));
    }
    Ok(validated_observation_indices(prefix, indices)?
        .into_iter()
        .collect::<Vec<_>>()
        .join(","))
}

fn validated_observation_indices<'a>(
    prefix: &str,
    indices: &'a [String],
) -> Result<BTreeSet<&'a str>, String> {
    let expected_prefix = format!("{prefix}-");
    let indices = indices.iter().map(String::as_str).collect::<BTreeSet<_>>();
    for index in &indices {
        if !index.starts_with(&expected_prefix)
            || !index.bytes().all(|value| {
                value.is_ascii_lowercase() || value.is_ascii_digit() || b"-_.".contains(&value)
            })
        {
            return Err(format!(
                "扫描批次记录了无效的 Elasticsearch 观察索引：{index}"
            ));
        }
    }
    Ok(indices)
}

fn scan_request_line_length(base_url: &str, path: &str) -> Result<usize, String> {
    let url = reqwest::Url::parse(&format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    ))
    .map_err(|error| format!("无效 Elasticsearch 请求地址：{error}"))?;
    // reqwest uses an encoded origin-form target. The hostname is not part of it.
    Ok(b"POST  HTTP/1.1".len() + url.path().len() + url.query().map_or(0, |query| 1 + query.len()))
}

fn ensure_scan_request_line_fits(base_url: &str, path: &str) -> Result<(), String> {
    if scan_request_line_length(base_url, path)? > SCAN_REQUEST_LINE_BUDGET {
        return Err(format!(
            "Elasticsearch 单个索引请求超过 {SCAN_REQUEST_LINE_BUDGET} 字节预算，请检查索引名称和 URL 路径前缀"
        ));
    }
    Ok(())
}

fn bounded_scan_index_paths(
    base_url: &str,
    indices: &[&str],
    operation: &str,
) -> Result<Vec<String>, String> {
    let path = |target: &str| format!("/{target}/{operation}?{SCAN_INDEX_OPTIONS}");
    let mut paths = Vec::new();
    let mut target = String::new();
    for index in indices {
        let candidate = if target.is_empty() {
            (*index).to_owned()
        } else {
            format!("{target},{index}")
        };
        if scan_request_line_length(base_url, &path(&candidate))? > SCAN_REQUEST_LINE_BUDGET {
            ensure_scan_request_line_fits(base_url, &path(index))?;
            if !target.is_empty() {
                paths.push(path(&target));
            }
            target = (*index).to_owned();
        } else {
            target = candidate;
        }
    }
    if !target.is_empty() {
        paths.push(path(&target));
    }
    Ok(paths)
}

fn observation_progress(completed: u64, total: Option<u64>) -> String {
    match total {
        Some(total) => format!("观察 {completed}/{total} 条"),
        None => format!("观察 {completed} 条"),
    }
}

fn scan_observation_template(prefix: &str, replicas: u32) -> Value {
    json!({
        "index_patterns": [format!("{prefix}-*")],
        "priority": 500,
        "_meta": {
            "application": "network-mapping",
            "schema_version": SCAN_INDEX_SCHEMA_VERSION,
            "purpose": "append-only scan observations"
        },
        "template": {
            "settings": scan_index_settings(replicas),
            "mappings": {
                "dynamic": "strict",
                "properties": {
                    "task_id": {"type": "keyword"},
                    "execution_id": {"type": "keyword"},
                    "user_id": {"type": "integer"},
                    "task_source": {"type": "keyword"},
                    "scanner_id": {"type": "keyword"},
                    "scanner_name": {"type": "keyword"},
                    "upload_id": {"type": "keyword"},
                    "batch_index": {"type": "integer"},
                    "payload_checksum": {"type": "keyword", "index": false},
                    "document_checksum": {"type": "keyword", "index": false},
                    "observation_key": {"type": "keyword", "ignore_above": 2048},
                    "endpoint_id": {"type": "keyword"},
                    "kind": {"type": "keyword"},
                    "ip_address": {"type": "ip"},
                    "ip_network": {"type": "ip_range"},
                    "port": {"type": "integer"},
                    "protocol": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                    "service": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                    "banner": {"type": "wildcard"},
                    "title": {"type": "text", "fields": {"raw": {"type": "keyword", "ignore_above": 512}}},
                    "http_body": {"type": "match_only_text"},
                    "http_body_truncated": {"type": "boolean"},
                    "tls_mode": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                    "tls_version": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                    "tls_cipher_suite": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                    "tls_subject": {"type": "wildcard"},
                    "tls_issuer": {"type": "wildcard"},
                    "tls_names": {"type": "keyword", "normalizer": "lowercase_normalizer", "ignore_above": 512},
                    "tls_serial_number": {"type": "keyword", "normalizer": "lowercase_normalizer", "ignore_above": 512},
                    "tls_not_before": {"type": "date"},
                    "tls_not_after": {"type": "date"},
                    "tls_fingerprint_sha256": {"type": "keyword", "normalizer": "lowercase_normalizer", "ignore_above": 128},
                    "tls_self_signed": {"type": "boolean"},
                    "search_content_extracted": {"type": "boolean", "index": false},
                    "source": {"type": "keyword"},
                    "data": {"type": "object", "enabled": false},
                    "observed_at": {"type": "date", "format": "epoch_millis||strict_date_optional_time"},
                    "asn": {"type": "keyword"},
                    "isp": {"type": "keyword"},
                    "as_org": {"type": "keyword"},
                    "country_code": {"type": "keyword"},
                    "country_name": {"type": "keyword"},
                    "region_name": {"type": "keyword"},
                    "city_name": {"type": "keyword"},
                    "latitude": {"type": "double"},
                    "longitude": {"type": "double"},
                    "tags": {"type": "object", "properties": scan_observation_tag_mapping_properties()}
                }
            }
        }
    })
}

fn scan_observation_compatibility_mapping() -> Value {
    json!({"properties": {
        "ip_network": {"type": "ip_range"},
        "latitude": {"type": "double"},
        "longitude": {"type": "double"},
        "tls_mode": {"type": "keyword", "normalizer": "lowercase_normalizer"},
        "tls_version": {"type": "keyword", "normalizer": "lowercase_normalizer"},
        "tls_cipher_suite": {"type": "keyword", "normalizer": "lowercase_normalizer"},
        "tls_issuer": {"type": "wildcard"},
        "tls_names": {"type": "keyword", "normalizer": "lowercase_normalizer", "ignore_above": 512},
        "tls_serial_number": {"type": "keyword", "normalizer": "lowercase_normalizer", "ignore_above": 512},
        "tls_not_before": {"type": "date"},
        "tls_not_after": {"type": "date"},
        "tls_fingerprint_sha256": {"type": "keyword", "normalizer": "lowercase_normalizer", "ignore_above": 128},
        "tls_self_signed": {"type": "boolean"},
        "tags": {"properties": scan_observation_tag_mapping_properties()}
    }})
}

fn scan_observation_tag_mapping_properties() -> Value {
    json!({
        "id": {"type": "long"},
        "name": {"type": "keyword"},
        "kind": {"type": "keyword"},
        "description": {"type": "text", "index": false},
        "category_id": {"type": "long"},
        "category_name": {"type": "keyword"}
    })
}

fn dns_observation_template(data_stream: &str, replicas: u32, retention_days: u16) -> Value {
    json!({
        "index_patterns": [data_stream],
        "priority": 600,
        "data_stream": {},
        "_meta": {
            "application": "network-mapping",
            "schema_version": DNS_INDEX_SCHEMA_VERSION,
            "purpose": "append-only DNS query observations"
        },
        "template": {
            "settings": scan_index_settings(replicas),
            "lifecycle": {"data_retention": format!("{retention_days}d")},
            "mappings": {
                "dynamic": "strict",
                "properties": {
                    "@timestamp": {"type": "date"},
                    "event_id": {"type": "keyword"},
                    "tenant_id": {"type": "keyword"},
                    "dns_view": {"properties": {"id": {"type": "keyword"}}},
                    "scan": {"properties": {
                        "task_id": {"type": "keyword"}, "execution_id": {"type": "keyword"},
                        "scanner_id": {"type": "keyword"}, "scanner_name": {"type": "keyword"},
                        "upload_id": {"type": "keyword"}, "batch_index": {"type": "integer"}
                    }},
                    "dns": {"properties": {
                        "question": {"properties": {
                            "name": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                            "type": {"type": "keyword"}, "class": {"type": "keyword"}
                        }},
                        "response_code": {"type": "keyword"}, "authoritative": {"type": "boolean"},
                        "truncated": {"type": "boolean"}, "dnssec_authenticated": {"type": "boolean"},
                        "answers": {"type": "object", "properties": {
                            "type": {"type": "keyword"}, "value": {"type": "keyword", "ignore_above": 4096},
                            "ttl": {"type": "integer"}, "priority": {"type": "integer"},
                            "weight": {"type": "integer"}, "port": {"type": "integer"}
                        }},
                        "authority": {"type": "object", "enabled": false},
                        "additional": {"type": "object", "enabled": false}
                    }},
                    "resolver": dns_resolver_mapping(),
                    "latency_ms": {"type": "integer"}
                }
            }
        }
    })
}

fn dns_resolver_mapping() -> Value {
    json!({"properties": {
        "id": {"type": "keyword"}, "label": {"type": "keyword", "ignore_above": 256},
        "ip": {"type": "ip"}, "port": {"type": "integer"}, "transport": {"type": "keyword"}
    }})
}

fn dns_record_index_definition(replicas: u32) -> Value {
    json!({
        "settings": scan_index_settings(replicas),
        "mappings": {
            "dynamic": "strict",
            "_meta": {
                "application": "network-mapping",
                "schema_version": DNS_INDEX_SCHEMA_VERSION,
                "purpose": "current DNS resource records"
            },
            "properties": {
                "tenant_id": {"type": "keyword"}, "dns_view_id": {"type": "keyword"},
                "domain": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "record_type": {"type": "keyword"}, "value": {"type": "keyword", "ignore_above": 4096},
                "canonical_rdata": {"type": "keyword", "index": false},
                "ip": {"type": "ip"}, "target_domain": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "ttl": {"type": "integer"}, "priority": {"type": "integer"},
                "weight": {"type": "integer"}, "port": {"type": "integer"},
                "state": {"type": "keyword"}, "missing_completed_scans": {"type": "short"},
                "first_seen_at": {"type": "date"}, "first_seen_ms": {"type": "long"},
                "last_seen_at": {"type": "date"}, "last_seen_ms": {"type": "long"},
                "last_successful_query_at": {"type": "date"}, "last_successful_query_ms": {"type": "long"},
                "last_response_code": {"type": "keyword"}, "evidence_sources": {"type": "keyword"},
                "last_scanner_id": {"type": "keyword"}, "last_task_id": {"type": "keyword"}
            }
        }
    })
}

fn append_dns_record_update(
    body: &mut String,
    index: &str,
    document_id: &str,
    document: &Value,
) -> Result<(), String> {
    const SCRIPT: &str = r#"
        if (ctx._source.last_seen_ms == null || params.doc.last_seen_ms >= ctx._source.last_seen_ms) {
            def firstSeenAt = ctx._source.first_seen_at;
            def firstSeenMs = ctx._source.first_seen_ms;
            ctx._source.putAll(params.doc);
            if (firstSeenMs != null) {
                ctx._source.first_seen_at = firstSeenAt;
                ctx._source.first_seen_ms = firstSeenMs;
            }
        }
        if (ctx._source.first_seen_ms == null || params.doc.first_seen_ms < ctx._source.first_seen_ms) {
            ctx._source.first_seen_at = params.doc.first_seen_at;
            ctx._source.first_seen_ms = params.doc.first_seen_ms;
        }
        ctx._source.state = 'active';
        ctx._source.missing_completed_scans = 0;
    "#;
    body.push_str(
        &serde_json::to_string(&json!({"update": {
            "_index": index, "_id": document_id, "retry_on_conflict": 5
        }}))
        .map_err(|error| error.to_string())?,
    );
    body.push('\n');
    body.push_str(
        &serde_json::to_string(&json!({
            "scripted_upsert": true,
            "script": {"lang": "painless", "source": SCRIPT, "params": {"doc": document}},
            "upsert": document
        }))
        .map_err(|error| error.to_string())?,
    );
    body.push('\n');
    Ok(())
}

struct DnsObservationBulkOutcome {
    indices: BTreeSet<String>,
    requires_reconciliation: bool,
}

fn parse_dns_observation_bulk_result(
    result: &Value,
    expected_ids: &BTreeSet<String>,
) -> Result<DnsObservationBulkOutcome, String> {
    let items = result
        .get("items")
        .and_then(Value::as_array)
        .ok_or("DNS Elasticsearch Bulk 响应缺少 items")?;
    if items.len() != expected_ids.len() {
        return Err(format!(
            "DNS Elasticsearch Bulk 响应条目数量不匹配：预期 {}，实际 {}",
            expected_ids.len(),
            items.len()
        ));
    }

    let mut seen_ids = BTreeSet::new();
    let mut indices = BTreeSet::new();
    let mut requires_reconciliation = false;
    for item in items {
        let action = item
            .get("create")
            .ok_or("DNS Elasticsearch Bulk 响应缺少 create 条目")?;
        let id = action
            .get("_id")
            .and_then(Value::as_str)
            .ok_or("DNS Elasticsearch Bulk create 条目缺少 _id")?;
        if !expected_ids.contains(id) {
            return Err(format!("DNS Elasticsearch Bulk 返回非预期事实：{id}"));
        }
        if !seen_ids.insert(id.to_owned()) {
            return Err(format!("DNS Elasticsearch Bulk 重复返回事实：{id}"));
        }
        let status = action
            .get("status")
            .and_then(Value::as_u64)
            .ok_or("DNS Elasticsearch Bulk create 条目缺少 status")?;
        if (200..300).contains(&status) {
            let index = action
                .get("_index")
                .and_then(Value::as_str)
                .ok_or("DNS Elasticsearch Bulk 成功条目缺少 _index")?;
            indices.insert(index.to_owned());
            continue;
        }
        let retryable = u16::try_from(status)
            .ok()
            .and_then(|status| StatusCode::from_u16(status).ok())
            .is_some_and(is_retryable_bulk_status);
        if status == 409 || retryable {
            requires_reconciliation = true;
            continue;
        }
        let reason = action
            .pointer("/error/reason")
            .and_then(Value::as_str)
            .unwrap_or("unknown Elasticsearch bulk error");
        return Err(format!(
            "DNS Elasticsearch bulk create failed with HTTP {status}: {reason}"
        ));
    }
    if seen_ids != *expected_ids {
        return Err("DNS Elasticsearch Bulk 响应未覆盖所有事实".into());
    }
    Ok(DnsObservationBulkOutcome {
        indices,
        requires_reconciliation,
    })
}

fn validate_dns_bulk_result(result: &Value) -> Result<(), String> {
    if result.get("errors").and_then(Value::as_bool) != Some(true) {
        return Ok(());
    }
    for item in result
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for operation in ["create", "update"] {
            let Some(status) = item
                .pointer(&format!("/{operation}/status"))
                .and_then(Value::as_u64)
            else {
                continue;
            };
            if (200..300).contains(&status) || (operation == "create" && status == 409) {
                continue;
            }
            let reason = item
                .pointer(&format!("/{operation}/error/reason"))
                .and_then(Value::as_str)
                .unwrap_or("unknown Elasticsearch bulk error");
            return Err(format!(
                "DNS Elasticsearch bulk {operation} failed with HTTP {status}: {reason}"
            ));
        }
    }
    Ok(())
}

fn scan_index_settings(replicas: u32) -> Value {
    json!({
        "number_of_replicas": replicas,
        "translog.durability": "request",
        "analysis": {"normalizer": {"lowercase_normalizer": {
            "type": "custom", "filter": ["lowercase"]
        }}}
    })
}

fn scan_endpoint_index_definition(replicas: u32) -> Value {
    json!({
        "settings": scan_index_settings(replicas),
        "mappings": {
            "dynamic": "strict",
            "_meta": {
                "application": "network-mapping",
                "schema_version": ENDPOINT_INDEX_SCHEMA_VERSION,
                "purpose": "scan endpoint projection"
            },
            "properties": {
                "scope_type": {"type": "keyword"},
                "scope_id": {"type": "integer"},
                "endpoint_key": {"type": "keyword"},
                "task_id": {"type": "keyword"},
                "execution_id": {"type": "keyword"},
                "user_id": {"type": "integer"},
                "task_source": {"type": "keyword"},
                "scanner_id": {"type": "keyword"},
                "scanner_name": {"type": "wildcard"},
                "ip": {"type": "ip"},
                "port": {"type": "integer"},
                "protocol": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "service": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "banner": {"type": "wildcard", "copy_to": "banner_text"},
                "banner_text": {"type": "text"},
                "title": {"type": "text", "copy_to": "title_contains", "fields": {"raw": {"type": "keyword", "normalizer": "lowercase_normalizer", "ignore_above": 512}}},
                "title_contains": {"type": "wildcard"},
                "http_body": {"type": "match_only_text", "copy_to": "http_body_contains"},
                "http_body_contains": {"type": "wildcard"},
                "http_body_truncated": {"type": "boolean"},
                "tls_mode": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "tls_version": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "tls_cipher_suite": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "tls_subject": {"type": "wildcard", "copy_to": "tls_subject_text"},
                "tls_subject_text": {"type": "text"},
                "tls_issuer": {"type": "wildcard", "copy_to": "tls_issuer_text"},
                "tls_issuer_text": {"type": "text"},
                "tls_names": {"type": "keyword", "normalizer": "lowercase_normalizer", "ignore_above": 512},
                "tls_serial_number": {"type": "keyword", "normalizer": "lowercase_normalizer", "ignore_above": 512},
                "tls_not_before": {"type": "date"},
                "tls_not_after": {"type": "date"},
                "tls_fingerprint_sha256": {"type": "keyword", "normalizer": "lowercase_normalizer", "ignore_above": 128},
                "tls_self_signed": {"type": "boolean"},
                "source": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "kind": {"type": "keyword"},
                "first_seen": {"type": "date"},
                "first_seen_ms": {"type": "long"},
                "last_seen": {"type": "date"},
                "observed_at_ms": {"type": "long"},
                "service_observed_at_ms": {"type": "long"},
                "service_observation_ref": {"type": "object", "enabled": false},
                "os": crate::os_detection::mapping(),
            "web": crate::web_detection::mapping(),
                "asn": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "asn_number": {"type": "long"},
                "isp": {"type": "wildcard"},
                "as_org": {"type": "wildcard"},
                "country_code": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "country_name": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "region_name": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "city_name": {"type": "wildcard"},
                "tags": {"type": "object", "properties": tag_mapping_properties()},
                "tag_names": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "tag_ids": {"type": "long"},
                "tag_kinds": {"type": "keyword"},
                "data": {"type": "object", "enabled": false}
            }
        }
    })
}

fn endpoint_protocol(observation: &Value) -> &str {
    match observation.get("protocol").and_then(Value::as_str) {
        Some("tcp") => "tcp",
        Some("udp") => "udp",
        _ => "unknown",
    }
}
fn endpoint_projection_document(
    context: &ScanBatchContext,
    observation: &Value,
    observed_at_ms: i64,
) -> Value {
    let ip = observation
        .get("ip_address")
        .cloned()
        .unwrap_or(Value::Null);
    let port = observation.get("port").cloned().unwrap_or(Value::Null);
    let kind = observation.get("kind").cloned().unwrap_or(Value::Null);
    // Failed/unidentified probes remain immutable observations, but do not
    // advance the successful-service clock or erase the last useful evidence.
    let is_service = kind.as_str() == Some("service")
        && [
            "service",
            "banner",
            "title",
            "http_body",
            "tls_subject",
            "tls_version",
        ]
        .iter()
        .any(|field| {
            observation
                .get(*field)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
        });
    let observed_at = DateTime::<Utc>::from_timestamp_millis(observed_at_ms)
        .expect("observed_at was validated")
        .to_rfc3339();
    let asn = observation.get("asn").cloned().unwrap_or(Value::Null);
    let asn_number = asn.as_str().and_then(parse_asn);
    let tags = observation
        .get("tags")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let tag_names = tags
        .iter()
        .filter_map(|tag| tag.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    let tag_ids = tags
        .iter()
        .filter_map(|tag| tag.get("id").and_then(Value::as_i64))
        .collect::<Vec<_>>();
    let tag_kinds = tags
        .iter()
        .filter_map(|tag| tag.get("kind").and_then(Value::as_str))
        .collect::<Vec<_>>();
    json!({
        "scope_type": "execution",
        "scope_id": 0,
        "endpoint_key": format!("{}|{}|{}", ip.as_str().unwrap_or_default(), port.as_i64().unwrap_or_default(), endpoint_protocol(observation)),
        "task_id": context.task_id,
        "execution_id": context.execution_id,
        "user_id": context.user_id,
        "task_source": context.task_source,
        "scanner_id": context.scanner_id,
        "scanner_name": context.scanner_name,
        "ip": ip,
        "port": port,
        "protocol": endpoint_protocol(observation),
        "service": observation.get("service").cloned().unwrap_or(Value::Null),
        "banner": observation.get("banner").cloned().unwrap_or(Value::Null),
        "title": observation.get("title").cloned().unwrap_or(Value::Null),
        "http_body": observation.get("http_body").cloned().unwrap_or(Value::Null),
        "http_body_truncated": observation.get("http_body_truncated").cloned().unwrap_or(json!(false)),
        "tls_mode": observation.get("tls_mode").cloned().unwrap_or(Value::Null),
        "tls_version": observation.get("tls_version").cloned().unwrap_or(Value::Null),
        "tls_cipher_suite": observation.get("tls_cipher_suite").cloned().unwrap_or(Value::Null),
        "tls_subject": observation.get("tls_subject").cloned().unwrap_or(Value::Null),
        "tls_issuer": observation.get("tls_issuer").cloned().unwrap_or(Value::Null),
        "tls_names": observation.get("tls_names").cloned().unwrap_or_else(|| json!([])),
        "tls_serial_number": observation.get("tls_serial_number").cloned().unwrap_or(Value::Null),
        "tls_not_before": observation.get("tls_not_before").cloned().unwrap_or(Value::Null),
        "tls_not_after": observation.get("tls_not_after").cloned().unwrap_or(Value::Null),
        "tls_fingerprint_sha256": observation.get("tls_fingerprint_sha256").cloned().unwrap_or(Value::Null),
        "tls_self_signed": observation.get("tls_self_signed").cloned().unwrap_or(Value::Null),
        "source": observation.get("source").cloned().unwrap_or(Value::Null),
        "kind": kind,
        "first_seen": observed_at,
        "first_seen_ms": observed_at_ms,
        "last_seen": observed_at,
        "observed_at_ms": observed_at_ms,
        "service_observed_at_ms": if is_service { json!(observed_at_ms) } else { Value::Null },
        "service_observation_ref": if is_service { service_observation_reference(context, observation, observed_at_ms) } else { Value::Null },
        "os": if is_service { json!(crate::os_detection::OsInference::pending(observed_at_ms)) } else { Value::Null },
        "web": if is_service { json!(crate::web_detection::WebInference::pending(observed_at_ms)) } else { Value::Null },
        "asn": asn,
        "asn_number": asn_number,
        "isp": observation.get("isp").cloned().unwrap_or(Value::Null),
        "as_org": observation.get("as_org").cloned().unwrap_or(Value::Null),
        "country_code": observation.get("country_code").cloned().unwrap_or(Value::Null),
        "country_name": observation.get("country_name").cloned().unwrap_or(Value::Null),
        "region_name": observation.get("region_name").cloned().unwrap_or(Value::Null),
        "city_name": observation.get("city_name").cloned().unwrap_or(Value::Null),
        "tags": tags, "tag_names": tag_names, "tag_ids": tag_ids, "tag_kinds": tag_kinds,
        "data": observation.get("data").cloned().unwrap_or(Value::Null)
    })
}

fn append_projection_update(
    body: &mut String,
    index: &str,
    document_id: &str,
    document: &Value,
) -> Result<(), String> {
    const SCRIPT: &str = r#"
        if (ctx._source.observed_at_ms == null) {
            ctx._source.putAll(params.doc);
        } else {
            def firstSeen = ctx._source.first_seen;
            def firstSeenMs = ctx._source.first_seen_ms;
            def service = ctx._source.service;
            def banner = ctx._source.banner;
            def title = ctx._source.title;
            def httpBody = ctx._source.http_body;
            def httpBodyTruncated = ctx._source.http_body_truncated;
            def tlsMode = ctx._source.tls_mode;
            def tlsVersion = ctx._source.tls_version;
            def tlsCipherSuite = ctx._source.tls_cipher_suite;
            def tlsSubject = ctx._source.tls_subject;
            def tlsIssuer = ctx._source.tls_issuer;
            def tlsNames = ctx._source.tls_names;
            def tlsSerialNumber = ctx._source.tls_serial_number;
            def tlsNotBefore = ctx._source.tls_not_before;
            def tlsNotAfter = ctx._source.tls_not_after;
            def tlsFingerprintSha256 = ctx._source.tls_fingerprint_sha256;
            def tlsSelfSigned = ctx._source.tls_self_signed;
            def serviceObserved = ctx._source.service_observed_at_ms;
            def serviceReference = ctx._source.service_observation_ref;
            def os = ctx._source.os;
            def web = ctx._source.web;
            def incomingServiceObserved = params.doc.service_observed_at_ms;
            boolean replaceService = incomingServiceObserved != null &&
                (serviceObserved == null || incomingServiceObserved >= serviceObserved);
            if (params.doc.observed_at_ms < ctx._source.observed_at_ms) {
                if (firstSeenMs == null || params.doc.observed_at_ms < firstSeenMs) {
                    ctx._source.first_seen = params.doc.first_seen;
                    ctx._source.first_seen_ms = params.doc.first_seen_ms;
                }
            } else {
                ctx._source.putAll(params.doc);
                ctx._source.first_seen = firstSeen;
                ctx._source.first_seen_ms = firstSeenMs;
                if (!replaceService) {
                    ctx._source.service = service;
                    ctx._source.banner = banner;
                    ctx._source.title = title;
                    ctx._source.http_body = httpBody;
                    ctx._source.http_body_truncated = httpBodyTruncated;
                    ctx._source.tls_mode = tlsMode;
                    ctx._source.tls_version = tlsVersion;
                    ctx._source.tls_cipher_suite = tlsCipherSuite;
                    ctx._source.tls_subject = tlsSubject;
                    ctx._source.tls_issuer = tlsIssuer;
                    ctx._source.tls_names = tlsNames;
                    ctx._source.tls_serial_number = tlsSerialNumber;
                    ctx._source.tls_not_before = tlsNotBefore;
                    ctx._source.tls_not_after = tlsNotAfter;
                    ctx._source.tls_fingerprint_sha256 = tlsFingerprintSha256;
                    ctx._source.tls_self_signed = tlsSelfSigned;
                    ctx._source.service_observed_at_ms = serviceObserved;
                    ctx._source.service_observation_ref = serviceReference;
                    ctx._source.os = os;
                    ctx._source.web = web;
                }
            }
            if (replaceService) {
                ctx._source.service = params.doc.service;
                ctx._source.banner = params.doc.banner;
                ctx._source.title = params.doc.title;
                ctx._source.http_body = params.doc.http_body;
                ctx._source.http_body_truncated = params.doc.http_body_truncated;
                ctx._source.tls_mode = params.doc.tls_mode;
                ctx._source.tls_version = params.doc.tls_version;
                ctx._source.tls_cipher_suite = params.doc.tls_cipher_suite;
                ctx._source.tls_subject = params.doc.tls_subject;
                ctx._source.tls_issuer = params.doc.tls_issuer;
                ctx._source.tls_names = params.doc.tls_names;
                ctx._source.tls_serial_number = params.doc.tls_serial_number;
                ctx._source.tls_not_before = params.doc.tls_not_before;
                ctx._source.tls_not_after = params.doc.tls_not_after;
                ctx._source.tls_fingerprint_sha256 = params.doc.tls_fingerprint_sha256;
                ctx._source.tls_self_signed = params.doc.tls_self_signed;
                ctx._source.service_observed_at_ms = incomingServiceObserved;
                ctx._source.service_observation_ref = params.doc.service_observation_ref;
                boolean sameEvidence = serviceReference != null && params.doc.service_observation_ref != null && serviceReference.id == params.doc.service_observation_ref.id;
                ctx._source.os = sameEvidence && os != null && os.status != 'pending' && (params.doc.os == null || params.doc.os.status == 'pending' || os.ruleset_revision >= params.doc.os.ruleset_revision) ? os : params.doc.os;
                ctx._source.web = sameEvidence && web != null && web.status != 'pending' && (params.doc.web == null || params.doc.web.status == 'pending' || web.ruleset_revision >= params.doc.web.ruleset_revision) ? web : params.doc.web;
            }
        }
    "#;
    body.push_str(
        &serde_json::to_string(&json!({"update": {
            "_index": index, "_id": document_id, "retry_on_conflict": 5
        }}))
        .map_err(|error| error.to_string())?,
    );
    body.push('\n');
    body.push_str(
        &serde_json::to_string(&json!({
            "scripted_upsert": true,
            "script": {"lang": "painless", "source": SCRIPT, "params": {"doc": document}},
            "upsert": document
        }))
        .map_err(|error| error.to_string())?,
    );
    body.push('\n');
    Ok(())
}

fn tag_mapping_properties() -> Value {
    json!({
        "id": {"type": "long"},
        "name": {"type": "keyword", "normalizer": "lowercase_normalizer"},
        "kind": {"type": "keyword"},
        "description": {"type": "text", "index": false},
        "category_id": {"type": "long"},
        "category_name": {"type": "keyword", "normalizer": "lowercase_normalizer"}
    })
}

fn index_mapping_update() -> Value {
    json!({
        "properties": {
            "service_observation_ref": {"type":"object", "enabled":false},
            "os": crate::os_detection::mapping(),
            "web": crate::web_detection::mapping(),
            "tls_mode": {"type": "keyword", "normalizer": "lowercase_normalizer"},
            "tls_version": {"type": "keyword", "normalizer": "lowercase_normalizer"},
            "tls_cipher_suite": {"type": "keyword", "normalizer": "lowercase_normalizer"},
            "tls_issuer": {"type": "wildcard", "copy_to": "tls_issuer_text"},
            "tls_issuer_text": {"type": "text"},
            "tls_names": {"type": "keyword", "normalizer": "lowercase_normalizer", "ignore_above": 512},
            "tls_serial_number": {"type": "keyword", "normalizer": "lowercase_normalizer", "ignore_above": 512},
            "tls_not_before": {"type": "date"},
            "tls_not_after": {"type": "date"},
            "tls_fingerprint_sha256": {"type": "keyword", "normalizer": "lowercase_normalizer", "ignore_above": 128},
            "tls_self_signed": {"type": "boolean"},
            "tags": {"properties": tag_mapping_properties()}
        }
    })
}

#[cfg(test)]
mod tests {
    #[actix_web::test]
    async fn readiness_checks_cluster_health_with_configured_authentication() {
        use super::*;
        use actix_web::{App, HttpRequest, HttpResponse, HttpServer, http::StatusCode, web};
        use std::net::TcpListener;
        let reply = web::Data::new(std::sync::Mutex::new((
            StatusCode::OK,
            json!({"status":"green","timed_out":false}),
        )));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_reply = reply.clone();
        let server = HttpServer::new(move || {
            App::new().app_data(server_reply.clone()).route(
                "/_cluster/health",
                web::get().to(
                    |request: HttpRequest,
                     reply: web::Data<std::sync::Mutex<(StatusCode, Value)>>| async move {
                        assert_eq!(
                            request.headers().get("authorization").unwrap(),
                            "ApiKey fixture-readiness-key"
                        );
                        assert_eq!(request.query_string(), "filter_path=status,timed_out");
                        let (status, body) = reply.lock().unwrap().clone();
                        HttpResponse::build(status).json(body)
                    },
                ),
            )
        })
        .workers(1)
        .listen(listener)
        .unwrap()
        .run();
        let handle = server.handle();
        actix_web::rt::spawn(server);
        let service = ElasticsearchService::new(ElasticsearchConfig {
            enabled: true,
            url: format!("http://{address}"),
            api_key: Some("fixture-readiness-key".into()),
            ..Default::default()
        })
        .unwrap();
        for (status, body, ready) in [
            (
                StatusCode::OK,
                json!({"status":"green","timed_out":false}),
                true,
            ),
            (
                StatusCode::OK,
                json!({"status":"yellow","timed_out":false}),
                true,
            ),
            (
                StatusCode::OK,
                json!({"status":"red","timed_out":false}),
                false,
            ),
            (
                StatusCode::OK,
                json!({"status":"green","timed_out":true}),
                false,
            ),
            (StatusCode::OK, json!({"status":"green"}), false),
            (
                StatusCode::OK,
                json!({"status":"green","timed_out":"false"}),
                false,
            ),
            (
                StatusCode::UNAUTHORIZED,
                json!({"error":"private authentication details"}),
                false,
            ),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"status":"green","timed_out":false}),
                false,
            ),
        ] {
            *reply.lock().unwrap() = (status, body);
            assert_eq!(service.health_check().await.is_ok(), ready);
        }
        handle.stop(true).await;
        assert!(service.health_check().await.is_err());
    }

    #[tokio::test]
    async fn readiness_requires_enabled_elasticsearch_storage() {
        let service = super::ElasticsearchService::new(crate::config::ElasticsearchConfig {
            enabled: false,
            ..Default::default()
        })
        .unwrap();
        assert!(service.health_check().await.is_err());
    }

    #[test]
    fn scan_index_paths_split_at_encoded_request_line_budget() {
        use super::*;
        let base = "http://localhost:9200/代理/";
        let overhead =
            scan_request_line_length(base, &format!("/x/_count?{SCAN_INDEX_OPTIONS}")).unwrap() - 1;
        let index = "a".repeat(SCAN_REQUEST_LINE_BUDGET - overhead);
        let paths = bounded_scan_index_paths(base, &[&index], "_count").unwrap();
        assert_eq!(
            scan_request_line_length(base, &paths[0]).unwrap(),
            SCAN_REQUEST_LINE_BUDGET
        );
        assert!(bounded_scan_index_paths(base, &[&format!("{index}a")], "_count").is_err());
        let paths = bounded_scan_index_paths(base, &[&index, "b"], "_count").unwrap();
        assert_eq!(paths.len(), 2);
        assert!(
            paths
                .iter()
                .all(|p| scan_request_line_length(base, p).unwrap() <= SCAN_REQUEST_LINE_BUDGET)
        );
    }

    #[test]
    fn scan_index_paths_keep_empty_and_legacy_scopes_distinct() {
        use super::*;
        assert!(
            bounded_scan_index_paths("http://localhost", &[], "_count")
                .unwrap()
                .is_empty()
        );
        let legacy = bounded_scan_index_paths("http://localhost", &["scan-*"], "_count").unwrap();
        assert_eq!(legacy, vec![format!("/scan-*/_count?{SCAN_INDEX_OPTIONS}")]);
        let paths = bounded_scan_index_paths(
            "http://localhost",
            &["scan-2026.01", "execution"],
            "_refresh",
        )
        .unwrap();
        assert_eq!(
            paths,
            vec![format!(
                "/scan-2026.01,execution/_refresh?{SCAN_INDEX_OPTIONS}"
            )]
        );
    }

    #[test]
    fn observation_search_uses_recorded_indices_and_validates_them() {
        let indices = vec![
            "scan-observations-2026.09".to_owned(),
            "scan-observations-2026.08".to_owned(),
            "scan-observations-2026.09".to_owned(),
        ];
        assert_eq!(
            observation_search_target("scan-observations", &indices).unwrap(),
            "scan-observations-2026.08,scan-observations-2026.09"
        );
        assert_eq!(
            observation_search_target("scan-observations", &[]).unwrap(),
            "scan-observations-*"
        );
        assert!(
            observation_search_target("scan-observations", &["other-index".to_owned()]).is_err()
        );
        assert!(
            observation_search_target(
                "scan-observations",
                &["scan-observations-2026.09/_search".to_owned()]
            )
            .is_err()
        );
    }

    #[test]
    fn refresh_rejects_unavailable_shards_even_without_reported_failures() {
        for shards in [
            serde_json::json!({"total":1,"successful":0,"failed":0}),
            serde_json::json!({"total":1,"successful":0,"failed":1}),
            serde_json::json!({"failed":0}),
        ] {
            assert!(
                super::validate_scan_refresh_response(&serde_json::json!({"_shards":shards}))
                    .is_err()
            );
        }
        // Unassigned replicas alone are allowed, as is an empty wildcard target.
        for shards in [
            serde_json::json!({"total":2,"successful":1,"failed":0}),
            serde_json::json!({"total":1,"successful":1,"failed":0}),
            serde_json::json!({"total":0,"successful":0,"failed":0}),
        ] {
            assert!(
                super::validate_scan_refresh_response(&serde_json::json!({"_shards":shards}))
                    .is_ok()
            );
        }
    }

    #[test]
    fn scan_search_rejects_partial_results_even_with_http_success() {
        assert!(
            super::validate_scan_search_response(&serde_json::json!({
                "timed_out": false, "_shards": {"failed": 0}
            }))
            .is_ok()
        );
        assert!(
            super::validate_scan_search_response(&serde_json::json!({
                "timed_out": true, "_shards": {"failed": 0}, "hits": {"hits": []}
            }))
            .is_err()
        );
        assert!(
            super::validate_scan_search_response(&serde_json::json!({
                "timed_out": false, "_shards": {"failed": 1}, "hits": {"hits": []}
            }))
            .is_err()
        );
    }
    use super::{
        ENSURE_SCAN_MIGRATION_INDEX_SQL, ElasticsearchOperation, ElasticsearchService,
        ScanBatchContext, SearchSort, bulk_response_is_retryable, bulk_retry_delay,
        collect_domain_addresses, dns_task_observations_search_body, endpoint_projection_document,
        index_mapping_update, initialization_retry_delay, new_trace_context,
        observation_search_target, parse_asn, parse_dns_observation_bulk_result,
        parse_storage_metrics, replace_domain_filters, scan_batch_payload_checksum,
        scan_endpoint_index_definition, scan_observation_compatibility_mapping,
        scan_observation_template,
    };
    use crate::config::ElasticsearchConfig;
    use std::collections::BTreeSet;
    use std::time::Duration;

    #[test]
    fn search_sort_uses_a_stable_tie_breaker_and_rejects_unknown_fields() {
        let default = SearchSort::default();
        assert_eq!(default.field_name(), "last_seen");
        assert_eq!(default.order_name(), "desc");
        assert_eq!(
            default.clauses(),
            vec![
                serde_json::json!({"last_seen": {"order": "desc", "missing": "_last"}}),
                serde_json::json!({"ip": {"order": "asc"}}),
                serde_json::json!({"port": {"order": "asc"}}),
                serde_json::json!({"endpoint_key": {"order": "asc"}}),
            ]
        );

        let first_seen = SearchSort::parse(Some("first_seen"), Some("asc")).unwrap();
        assert_eq!(
            first_seen.clauses()[0],
            serde_json::json!({"first_seen": {"order": "asc", "missing": "_last"}})
        );
        assert_eq!(first_seen.clauses().last(), default.clauses().last());
        assert_eq!(
            SearchSort::parse(Some("port"), None).unwrap().order_name(),
            "asc"
        );
        assert!(SearchSort::parse(Some("banner"), None).is_err());
        assert!(SearchSort::parse(None, Some("random")).is_err());
    }

    #[tokio::test]
    async fn bulk_requires_complete_items_even_when_errors_flag_is_false() {
        let service = ElasticsearchService::new(ElasticsearchConfig::default()).unwrap();
        let expected = vec![(
            "index".into(),
            "id".into(),
            "checksum".into(),
            "batch".into(),
        )];
        for response in [
            serde_json::json!({"errors": false}),
            serde_json::json!({"errors": false, "items": []}),
            serde_json::json!({"errors": false, "items": [{"create": {"status": 429}}]}),
        ] {
            assert!(
                service
                    .validate_scan_bulk_result(&response, &expected)
                    .await
                    .is_err()
            );
        }
        assert!(
            service
                .validate_scan_bulk_result(
                    &serde_json::json!({"errors": false,
            "items": [{"create": {"status": 201}}]}),
                    &expected
                )
                .await
                .is_ok()
        );
    }

    #[test]
    fn dns_task_observation_search_has_stable_tie_breaker() {
        let body = dns_task_observations_search_body("019c0000-0000-7000-8000-000000000001");

        assert_eq!(
            body["sort"],
            serde_json::json!([
                {"@timestamp": {"order": "desc"}},
                {"event_id": "asc"}
            ])
        );
    }

    #[test]
    fn scan_observation_mapping_declares_compatible_fields() {
        let template = scan_observation_template("observations", 0);
        assert_eq!(
            template.pointer("/_meta/schema_version"),
            Some(&serde_json::json!("5"))
        );
        assert_eq!(
            template.pointer("/template/mappings/properties/ip_address/type"),
            Some(&serde_json::json!("ip"))
        );
        assert_eq!(
            template.pointer("/template/mappings/properties/ip_network/type"),
            Some(&serde_json::json!("ip_range"))
        );
        assert_eq!(
            scan_observation_compatibility_mapping().pointer("/properties/ip_network/type"),
            Some(&serde_json::json!("ip_range"))
        );
        for field in ["latitude", "longitude"] {
            assert_eq!(
                template.pointer(&format!("/template/mappings/properties/{field}/type")),
                Some(&serde_json::json!("double"))
            );
            assert_eq!(
                scan_observation_compatibility_mapping()
                    .pointer(&format!("/properties/{field}/type")),
                Some(&serde_json::json!("double"))
            );
        }
        for field in ["tls_not_before", "tls_not_after"] {
            assert_eq!(
                template.pointer(&format!("/template/mappings/properties/{field}/type")),
                Some(&serde_json::json!("date"))
            );
            assert_eq!(
                scan_observation_compatibility_mapping()
                    .pointer(&format!("/properties/{field}/type")),
                Some(&serde_json::json!("date"))
            );
        }
        assert_eq!(
            scan_endpoint_index_definition(0).pointer("/mappings/properties/tls_names/type"),
            Some(&serde_json::json!("keyword"))
        );
        assert_eq!(
            index_mapping_update().pointer("/properties/tls_self_signed/type"),
            Some(&serde_json::json!("boolean"))
        );
        assert_eq!(
            scan_observation_compatibility_mapping()
                .pointer("/properties/tags/properties/category_id/type"),
            Some(&serde_json::json!("long"))
        );
        assert_eq!(
            scan_observation_compatibility_mapping()
                .pointer("/properties/tags/properties/category_name/type"),
            Some(&serde_json::json!("keyword"))
        );
    }

    #[test]
    fn correlation_headers_use_bounded_operation_and_valid_trace_context() {
        let service = ElasticsearchService::new(ElasticsearchConfig::default()).unwrap();
        let (trace_id, traceparent) = new_trace_context();
        let request = service
            .request(
                reqwest::Method::POST,
                "/index/_search",
                ElasticsearchOperation::AssetSearch,
                &traceparent,
            )
            .build()
            .unwrap();

        assert_eq!(trace_id.len(), 32);
        assert_eq!(traceparent.len(), 55);
        assert_eq!(
            request.headers().get("x-opaque-id").unwrap(),
            "network-mapping:asset-search"
        );
        assert_eq!(request.headers().get("traceparent").unwrap(), &traceparent);
    }

    #[test]
    fn parses_asn_with_or_without_prefix() {
        assert_eq!(parse_asn("AS4134"), Some(4134));
        assert_eq!(parse_asn("4134"), Some(4134));
        assert_eq!(parse_asn("unknown"), None);
    }

    #[test]
    fn replaces_domain_filter_markers_without_leaking_internal_dsl() {
        let filter = serde_json::json!({
            "bool": {"filter": [
                {"network_mapping_domain": {"operator": "eq", "values": ["www.example.com"]}},
                {"term": {"port": 443}}
            ]}
        });
        let mut replacements =
            vec![serde_json::json!({"terms": {"ip": ["192.0.2.10"]}})].into_iter();
        let replaced = replace_domain_filters(filter, &mut replacements);
        assert_eq!(
            replaced.pointer("/bool/filter/0/terms/ip/0"),
            Some(&serde_json::json!("192.0.2.10"))
        );
        assert!(!replaced.to_string().contains("network_mapping_domain"));
    }

    #[test]
    fn collects_a_aaaa_and_cname_targets_without_revisiting_a_cname_loop() {
        let hits = vec![
            serde_json::json!({"_source": {"record_type": "A", "ip": "192.0.2.10"}}),
            serde_json::json!({"_source": {"record_type": "AAAA", "ip": "2001:db8::10"}}),
            serde_json::json!({"_source": {"record_type": "CNAME", "target_domain": "edge.example.com."}}),
            serde_json::json!({"_source": {"record_type": "CNAME", "target_domain": "www.example.com"}}),
        ];
        let mut addresses = BTreeSet::new();
        let mut seen_names = BTreeSet::from(["www.example.com".to_owned()]);
        let mut pending_names = BTreeSet::new();

        collect_domain_addresses(
            &hits,
            true,
            &mut addresses,
            &mut seen_names,
            &mut pending_names,
        )
        .expect("DNS records should be collected");

        assert_eq!(
            addresses,
            BTreeSet::from(["192.0.2.10".to_owned(), "2001:db8::10".to_owned()])
        );
        assert_eq!(
            pending_names,
            BTreeSet::from(["edge.example.com".to_owned()])
        );
    }

    #[test]
    fn scan_migration_index_supports_ordered_batch_reads_online() {
        assert!(ENSURE_SCAN_MIGRATION_INDEX_SQL.contains("CREATE INDEX CONCURRENTLY"));
        assert!(ENSURE_SCAN_MIGRATION_INDEX_SQL.contains("scan_observation(batch_id, id)"));
    }

    #[test]
    fn scan_migration_only_resumes_matching_in_progress_window() {
        let service = ElasticsearchService::new(ElasticsearchConfig::default()).unwrap();
        let matching = serde_json::json!({
            "status": "in_progress",
            "observation_index_prefix": "network-mapping-scan-observations-v1",
            "execution_endpoint_index": "network-mapping-execution-endpoints-v2",
            "current_endpoint_index": "network-mapping-endpoints-current-v3",
            "high_watermark": 42
        });
        assert!(service.scan_migration_state_is_resumable(&matching));

        let mut complete = matching.clone();
        complete["status"] = serde_json::json!("complete");
        assert!(!service.scan_migration_state_is_resumable(&complete));

        let mut different_index = matching;
        different_index["current_endpoint_index"] = serde_json::json!("other-index");
        assert!(!service.scan_migration_state_is_resumable(&different_index));
    }

    #[test]
    fn bulk_retry_only_accepts_transient_item_failures() {
        let throttled = serde_json::json!({
            "errors": true,
            "items": [
                {"create": {"status": 201}},
                {"create": {"status": 429}}
            ]
        });
        assert!(bulk_response_is_retryable(&throttled, true));

        let permanent = serde_json::json!({
            "errors": true,
            "items": [
                {"create": {"status": 429}},
                {"create": {"status": 400}}
            ]
        });
        assert!(!bulk_response_is_retryable(&permanent, true));

        let existing = serde_json::json!({
            "errors": true,
            "items": [{"create": {"status": 409}}]
        });
        assert!(!bulk_response_is_retryable(&existing, true));
        assert!(!bulk_response_is_retryable(&existing, false));
    }

    #[test]
    fn dns_observation_bulk_collects_indices_without_reconciliation() {
        let expected = BTreeSet::from(["one".to_owned(), "two".to_owned()]);
        let response = serde_json::json!({
            "errors": false,
            "items": [
                {"create": {"status": 201, "_id": "one", "_index": ".ds-dns-1"}},
                {"create": {"status": 201, "_id": "two", "_index": ".ds-dns-1"}}
            ]
        });
        let outcome = parse_dns_observation_bulk_result(&response, &expected).unwrap();
        assert_eq!(outcome.indices, BTreeSet::from([".ds-dns-1".to_owned()]));
        assert!(!outcome.requires_reconciliation);
    }

    #[test]
    fn dns_observation_bulk_reconciles_conflicts_and_transient_items() {
        let expected = BTreeSet::from(["one".to_owned(), "two".to_owned()]);
        let response = serde_json::json!({
            "errors": true,
            "items": [
                {"create": {"status": 409, "_id": "one", "_index": ".ds-dns-1"}},
                {"create": {"status": 429, "_id": "two", "_index": ".ds-dns-1"}}
            ]
        });
        let outcome = parse_dns_observation_bulk_result(&response, &expected).unwrap();
        assert!(outcome.indices.is_empty());
        assert!(outcome.requires_reconciliation);
    }

    #[test]
    fn dns_observation_bulk_rejects_incomplete_or_unknown_items() {
        let expected = BTreeSet::from(["one".to_owned()]);
        for response in [
            serde_json::json!({"errors": false, "items": []}),
            serde_json::json!({
                "errors": false,
                "items": [{"create": {"status": 201, "_id": "other", "_index": ".ds-dns-1"}}]
            }),
        ] {
            assert!(parse_dns_observation_bulk_result(&response, &expected).is_err());
        }
    }

    #[test]
    fn bulk_retry_delay_is_exponential_and_capped() {
        assert_eq!(bulk_retry_delay(200, 0), Duration::from_millis(200));
        assert_eq!(bulk_retry_delay(200, 3), Duration::from_millis(1_600));
        assert_eq!(bulk_retry_delay(60_000, 10), Duration::from_secs(30));
    }

    #[test]
    fn initialization_retry_delay_is_exponential_and_capped() {
        assert_eq!(
            initialization_retry_delay(500, 1),
            Duration::from_millis(500)
        );
        assert_eq!(
            initialization_retry_delay(500, 2),
            Duration::from_millis(1_000)
        );
        assert_eq!(
            initialization_retry_delay(500, 20),
            Duration::from_millis(30_000)
        );
    }

    #[test]
    fn scan_batch_checksum_ignores_mutable_enrichment_but_not_evidence() {
        let context = ScanBatchContext {
            task_id: "task".into(),
            execution_id: "execution".into(),
            user_id: 7,
            task_source: "user".into(),
            scanner_id: "scanner".into(),
            scanner_name: Some("node".into()),
            upload_id: "upload".into(),
            batch_index: 0,
            is_final: true,
        };
        let tcp = endpoint_projection_document(
            &context,
            &serde_json::json!({"ip_address":"192.0.2.1","port":53,"protocol":"tcp"}),
            1,
        );
        let udp = endpoint_projection_document(
            &context,
            &serde_json::json!({"ip_address":"192.0.2.1","port":53,"protocol":"udp"}),
            1,
        );
        let unknown = endpoint_projection_document(
            &context,
            &serde_json::json!({"ip_address":"192.0.2.1","port":53}),
            1,
        );
        assert_ne!(tcp["endpoint_key"], udp["endpoint_key"]);
        assert_ne!(udp["endpoint_key"], unknown["endpoint_key"]);
        assert_eq!(unknown["protocol"], "unknown");
        let original = serde_json::json!({
            "observation_key": "key", "ip_address": "192.0.2.1", "port": 443,
            "banner": "first", "observed_at": 1, "asn": "4134", "tags": []
        });
        let mut enriched = original.clone();
        enriched["asn"] = serde_json::json!("AS4134");
        enriched["tags"] = serde_json::json!([{"id": 1, "name": "prod"}]);
        assert_eq!(
            scan_batch_payload_checksum(&context, std::slice::from_ref(&original)).unwrap(),
            scan_batch_payload_checksum(&context, &[enriched]).unwrap()
        );
        let legacy_cidr = serde_json::json!({
            "observation_key": "key", "ip_address": "192.0.2.1/32", "port": 443,
            "banner": "first", "observed_at": 1, "asn": "4134", "tags": []
        });
        let compatible_dual_fields = serde_json::json!({
            "observation_key": "key", "ip_address": "192.0.2.1",
            "ip_network": "192.0.2.1/32", "port": 443,
            "banner": "first", "observed_at": 1, "asn": "AS4134",
            "tags": [{"id": 1, "name": "prod"}]
        });
        assert_eq!(
            scan_batch_payload_checksum(&context, &[legacy_cidr]).unwrap(),
            scan_batch_payload_checksum(&context, &[compatible_dual_fields]).unwrap()
        );
        let mut changed = original.clone();
        changed["banner"] = serde_json::json!("different");
        assert_ne!(
            scan_batch_payload_checksum(&context, &[original]).unwrap(),
            scan_batch_payload_checksum(&context, &[changed]).unwrap()
        );
    }

    #[test]
    fn scan_endpoint_mapping_tracks_exact_first_seen_time() {
        let mapping = scan_endpoint_index_definition(1);
        assert_eq!(
            mapping.pointer("/mappings/properties/first_seen_ms/type"),
            Some(&serde_json::json!("long"))
        );
    }

    #[test]
    fn storage_metrics_aggregate_primary_and_replica_sizes() {
        let metrics = parse_storage_metrics(&serde_json::json!({
            "indices": {
                "network-mapping-assets-v1": {
                    "primaries": {"store": {"size_in_bytes": 100}},
                    "total": {"store": {"size_in_bytes": 200}}
                },
                "network-mapping-scan-observations-v1-2026.08": {
                    "primaries": {"store": {"size_in_bytes": 300}},
                    "total": {"store": {"size_in_bytes": 450}}
                }
            }
        }))
        .unwrap();

        assert!(metrics.enabled);
        assert!(metrics.available);
        assert_eq!(metrics.primary_size, Some(400));
        assert_eq!(metrics.replica_size, Some(250));
        assert_eq!(metrics.total_size, Some(650));
        assert_eq!(metrics.indices["network-mapping-assets-v1"].replica, 100);
    }

    #[test]
    fn storage_metrics_accept_empty_index_matches_and_reject_invalid_only_responses() {
        let empty = parse_storage_metrics(&serde_json::json!({})).unwrap();
        assert_eq!(empty.total_size, Some(0));
        assert!(empty.indices.is_empty());

        assert!(
            parse_storage_metrics(&serde_json::json!({
                "indices": {"broken": {"primaries": {}, "total": {}}}
            }))
            .is_err()
        );
    }
}

#[cfg(test)]
#[path = "elasticsearch_storage_tests.rs"]
mod storage_tests;

#[cfg(test)]
#[path = "elasticsearch/stress_tests.rs"]
mod stress_tests;
