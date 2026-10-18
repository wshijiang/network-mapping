use super::{ApiError, Result};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::IpAddr;
use uuid::Uuid;

pub const SCOPES: &[&str] = &[
    "metadata:read",
    "assets:read",
    "assets:refresh",
    "observations:read",
    "dns:read",
    "vulnerabilities:read",
    "vulnerabilities:evidence",
    "tags:read",
    "annotations:read",
    "annotations:write",
    "tasks:read",
    "tasks:create",
    "tasks:cancel",
    "tasks:retry",
    "analytics:read",
    "reports:read",
    "reports:create",
    "exports:read",
    "exports:create",
    "events:read",
    "webhooks:manage",
    "saved_searches:manage",
];
pub const FIELDS: &[&str] = &[
    "ip",
    "port",
    "protocol",
    "service",
    "title",
    "banner",
    "os",
    "web",
    "tls_mode",
    "tls_version",
    "tls_cipher_suite",
    "tls_subject",
    "tls_issuer",
    "tls_names",
    "tls_serial_number",
    "tls_not_before",
    "tls_not_after",
    "tls_fingerprint_sha256",
    "tls_self_signed",
    "first_seen",
    "last_seen",
    "service_observed_at_ms",
    "asn",
    "isp",
    "as_org",
    "country_code",
    "country_name",
    "region_name",
    "city_name",
    "tags",
];
pub const EVENT_TYPES: &[&str] = &[
    "task.succeeded",
    "task.failed",
    "task.partial",
    "task.cancelled",
    "asset.ready",
    "export.succeeded",
    "export.failed",
    "report.succeeded",
    "report.failed",
    "webhook.test",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Policy {
    pub scopes: Vec<String>,
    pub fields: Vec<String>,
    pub data_mode: String,
    pub cidrs: Vec<String>,
    pub excluded_cidrs: Vec<String>,
    #[serde(deserialize_with = "deserialize_domains")]
    pub domains: Vec<String>,
    pub tag_ids: Vec<i64>,
    pub profiles: Vec<String>,
    pub ip_allowlist: Vec<String>,
    pub from_at: Option<i64>,
    pub to_at: Option<i64>,
    pub requests_per_minute: i64,
    pub requests_per_day: i64,
    pub searches_per_minute: i64,
    pub statistics_per_minute: i64,
    pub tasks_per_minute: i64,
    pub tasks_per_day: i64,
    pub max_targets: usize,
    pub max_ports: usize,
    pub max_running_tasks: i64,
    pub exports_per_day: i64,
    pub max_export_rows: usize,
    pub max_webhooks: i64,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            scopes: [
                "metadata:read",
                "assets:read",
                "tasks:read",
                "tags:read",
                "analytics:read",
                "exports:read",
                "exports:create",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            fields: [
                "ip",
                "port",
                "protocol",
                "service",
                "title",
                "first_seen",
                "last_seen",
                "country_code",
                "country_name",
                "asn",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            data_mode: "application".into(),
            cidrs: vec![],
            excluded_cidrs: vec![],
            domains: vec![],
            tag_ids: vec![],
            profiles: vec![
                "port_only".into(),
                "service_inventory".into(),
                "dns_records".into(),
            ],
            ip_allowlist: vec![],
            from_at: None,
            to_at: None,
            requests_per_minute: 120,
            requests_per_day: 10_000,
            searches_per_minute: 30,
            statistics_per_minute: 12,
            tasks_per_minute: 6,
            tasks_per_day: 50,
            max_targets: 4096,
            max_ports: 100,
            max_running_tasks: 5,
            exports_per_day: 10,
            max_export_rows: 10_000,
            max_webhooks: 5,
        }
    }
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        if self.scopes.is_empty()
            || self.scopes.len() > SCOPES.len()
            || self.scopes.iter().any(|s| !SCOPES.contains(&s.as_str()))
        {
            return Err(ApiError::bad("权限列表无效，不支持通配符"));
        }
        if !matches!(self.data_mode.as_str(), "owner" | "application") {
            return Err(ApiError::bad("data_mode 必须为 owner 或 application"));
        }
        if self.fields.is_empty()
            || self.fields.len() > FIELDS.len()
            || self.fields.iter().any(|f| !FIELDS.contains(&f.as_str()))
        {
            return Err(ApiError::bad("字段白名单无效"));
        }
        for values in [&self.cidrs, &self.excluded_cidrs, &self.ip_allowlist] {
            if values.len() > 64 || values.iter().any(|s| s.parse::<IpNet>().is_err()) {
                return Err(ApiError::bad("CIDR 列表格式无效或超过 64 项"));
            }
        }
        if self.domains.len() > 100 || self.domains.iter().any(|s| normalize_domain(s).is_err()) {
            return Err(ApiError::bad("域名授权列表无效"));
        }
        if self.tag_ids.len() > 100 || self.tag_ids.iter().any(|id| *id <= 0) {
            return Err(ApiError::bad("标签授权列表无效"));
        }
        if self.profiles.is_empty()
            || self.profiles.iter().any(|s| {
                !matches!(
                    s.as_str(),
                    "port_only" | "service_inventory" | "dns_records" | "vulnerability_scan"
                )
            })
        {
            return Err(ApiError::bad("扫描模式无效"));
        }
        if self.from_at.zip(self.to_at).is_some_and(|(a, b)| a >= b) {
            return Err(ApiError::bad("时间范围无效"));
        }
        if [
            self.requests_per_minute,
            self.requests_per_day,
            self.searches_per_minute,
            self.statistics_per_minute,
            self.tasks_per_minute,
            self.tasks_per_day,
            self.max_running_tasks,
            self.exports_per_day,
            self.max_webhooks,
        ]
        .iter()
        .any(|v| !(1..=1_000_000).contains(v))
            || !(1..=65_536).contains(&self.max_targets)
            || !(1..=65_535).contains(&self.max_ports)
            || !(1..=50_000).contains(&self.max_export_rows)
        {
            return Err(ApiError::bad("配额超出允许范围"));
        }
        Ok(())
    }
    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        (self.cidrs.is_empty()
            || self
                .cidrs
                .iter()
                .filter_map(|s| s.parse::<IpNet>().ok())
                .any(|n| n.contains(&ip)))
            && !self
                .excluded_cidrs
                .iter()
                .filter_map(|s| s.parse::<IpNet>().ok())
                .any(|n| n.contains(&ip))
    }
    pub fn allows_network(&self, target: &IpNet) -> bool {
        !self.cidrs.is_empty()
            && self
                .cidrs
                .iter()
                .filter_map(|s| s.parse::<IpNet>().ok())
                .any(|n| n.contains(target))
            && !self
                .excluded_cidrs
                .iter()
                .filter_map(|s| s.parse::<IpNet>().ok())
                .any(|n| n.contains(&target.network()) || target.contains(&n.network()))
    }
    pub fn allows_domain(&self, domain: &str) -> bool {
        self.domains.is_empty()
            || self.domains.iter().any(|s| {
                let s = s.to_ascii_lowercase();
                domain == s || domain.strip_suffix(&s).is_some_and(|p| p.ends_with('.'))
            })
    }
    pub fn ip_filter(&self, field: &str) -> Value {
        let allowed = self
            .cidrs
            .iter()
            .map(|n| json!({"term":{field:n}}))
            .collect::<Vec<_>>();
        let excluded = self
            .excluded_cidrs
            .iter()
            .map(|n| json!({"term":{field:n}}))
            .collect::<Vec<_>>();
        let mut q = json!({"bool":{"must_not":excluded}});
        if !allowed.is_empty() {
            q["bool"]["should"] = json!(allowed);
            q["bool"]["minimum_should_match"] = json!(1);
        }
        q
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Principal {
    pub client_pk: i32,
    pub client_id: Uuid,
    pub credential_id: Uuid,
    pub owner_id: i32,
    pub name: String,
    pub environment: String,
    pub revision: i64,
    pub policy: Policy,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
}
impl Principal {
    pub fn has(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope) && self.policy.scopes.iter().any(|s| s == scope)
    }
    pub fn scope(&self) -> (&str, i32) {
        if self.policy.data_mode == "owner" {
            ("user", self.owner_id)
        } else {
            ("api_client", self.client_pk)
        }
    }
    pub fn project_endpoint(&self, source: &Value, requested: Option<&Vec<String>>) -> Value {
        let mut out = serde_json::Map::new();
        for field in &self.policy.fields {
            if requested.is_some_and(|f| !f.contains(field)) {
                continue;
            }
            if field == "tags" && !self.has("tags:read") {
                continue;
            }
            if let Some(v) = source.get(field) {
                let v = if field == "tags" {
                    json!(
                        v.as_array()
                            .into_iter()
                            .flatten()
                            .filter(|t| t
                                .get("id")
                                .and_then(Value::as_i64)
                                .is_some_and(|id| self.policy.tag_ids.contains(&id)))
                            .cloned()
                            .collect::<Vec<_>>()
                    )
                } else if field == "web" {
                    let web = crate::web_detection::endpoint_view(
                        serde_json::from_value(v.clone()).ok(),
                        source
                            .get("observed_at_ms")
                            .and_then(Value::as_i64)
                            .unwrap_or_default(),
                        Utc::now().timestamp_millis(),
                    );
                    let mut value = json!(web);
                    if let Some(items) = value.get_mut("technologies").and_then(Value::as_array_mut)
                    {
                        for item in items {
                            if let Some(obj) = item.as_object_mut() {
                                obj.remove("evidence");
                            }
                        }
                    }
                    value
                } else if field == "os" {
                    let os = serde_json::from_value(v.clone()).ok();
                    let os = crate::os_detection::endpoint_view(
                        os,
                        source
                            .get("observed_at_ms")
                            .and_then(Value::as_i64)
                            .unwrap_or_default(),
                        Utc::now().timestamp_millis(),
                    );
                    let mut value = json!(os);
                    if let Some(object) = value.as_object_mut() {
                        object.remove("evidence");
                        object.remove("candidates");
                    }
                    value
                } else {
                    v.clone()
                };
                out.insert(field.clone(), v);
            }
        }
        Value::Object(out)
    }
}
pub(crate) fn normalize_domain(s: &str) -> Result<String> {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.len() > 253
        || !s.contains('.')
        || s.split('.').any(|l| {
            l.is_empty()
                || l.len() > 63
                || l.starts_with('-')
                || l.ends_with('-')
                || !l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err(ApiError::bad("域名格式无效，国际化域名请使用 punycode"));
    }
    Ok(s)
}
fn deserialize_domains<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<String>, D::Error> {
    Vec::<String>::deserialize(d)?
        .iter()
        .map(|s| normalize_domain(s).map_err(|e| serde::de::Error::custom(e.message)))
        .collect()
}
pub(crate) fn parse_uuid(s: &str) -> Result<Uuid> {
    Uuid::parse_str(s).map_err(|_| ApiError::missing())
}
pub(crate) fn fingerprint(bytes: &[u8]) -> String {
    openssl::sha::sha256(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
