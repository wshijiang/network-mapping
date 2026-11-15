//! 联测统一数据模型：归一化记录、数据源能力、错误分类。

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::data_import::csv::TechEntry;

/// 可配置字段（ip/port 恒选，不在此列）。
pub const FIELD_NAMES: &[&str] = &["ip", "domain", "port", "service", "tech", "title", "banner"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    Hunter,
    Quake,
    Fofa,
    Shodan,
}

impl SourceKind {
    pub const ALL: [SourceKind; 4] = [
        SourceKind::Hunter,
        SourceKind::Quake,
        SourceKind::Fofa,
        SourceKind::Shodan,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hunter => "hunter",
            Self::Quake => "quake",
            Self::Fofa => "fofa",
            Self::Shodan => "shodan",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::Hunter => "奇安信 Hunter 鹰图",
            Self::Quake => "360 Quake",
            Self::Fofa => "FOFA",
            Self::Shodan => "Shodan",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "hunter" => Some(Self::Hunter),
            "quake" => Some(Self::Quake),
            "fofa" => Some(Self::Fofa),
            "shodan" => Some(Self::Shodan),
            _ => None,
        }
    }
}

/// 每源字段选择（ip/port 恒选）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldSelection {
    pub domain: bool,
    pub service: bool,
    pub tech: bool,
    pub title: bool,
    pub banner: bool,
}

impl Default for FieldSelection {
    fn default() -> Self {
        Self {
            domain: true,
            service: true,
            tech: true,
            title: false,
            banner: false,
        }
    }
}

impl FieldSelection {
    pub fn from_names(names: &[String]) -> Self {
        let has = |name: &str| names.iter().any(|n| n == name);
        Self {
            domain: has("domain"),
            service: has("service"),
            tech: has("tech"),
            title: has("title"),
            banner: has("banner"),
        }
    }

    pub fn to_names(&self) -> Vec<String> {
        let mut names = vec!["ip".to_owned(), "port".to_owned()];
        if self.domain {
            names.push("domain".into());
        }
        if self.service {
            names.push("service".into());
        }
        if self.tech {
            names.push("tech".into());
        }
        if self.title {
            names.push("title".into());
        }
        if self.banner {
            names.push("banner".into());
        }
        names
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WindowMode {
    /// 跟随 run 级默认窗口（策略或手动覆盖）。
    #[default]
    Follow,
    /// 不指定时间（平台默认范围，最划算默认）。
    None,
    /// 单独设置 window_days。
    Custom,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaginationMode {
    #[default]
    FollowLocal,
    Fixed,
}

/// 平台时间过滤能力（§8.6）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeFilterMode {
    /// 请求参数（Hunter start_time/end_time、Quake start_time/end_time）。
    NativeParam,
    /// 查询语法（FOFA after/before）。
    NativeSyntax,
    /// 无远端过滤（Shodan），只能本地按 timestamp 过滤。
    LocalOnly,
}

/// 适配器静态能力声明。
#[derive(Clone, Debug)]
pub struct Capabilities {
    pub default_qps: f64,
    pub max_page_size: u32,
    /// 平台仅接受特定档位时的合法值（Hunter {1,10,50,100}）。
    pub page_size_choices: Option<&'static [u32]>,
    pub time_filter: TimeFilterMode,
    /// 单 IP 查询是否有免费端点（Shodan /shodan/host/{ip}）。
    pub single_ip_free_endpoint: bool,
}

/// 分页请求：0-based 页索引 + 每页条数；适配器自行换算 page/start。
#[derive(Clone, Copy, Debug)]
pub struct PageRequest {
    pub index: u32,
    pub size: u32,
}

/// 一页原始结果。
#[derive(Clone, Debug, Default)]
pub struct RawPage {
    pub records: Vec<Value>,
    pub total: Option<i64>,
    /// 平台响应携带的配额信息（原样入 run 源明细）。
    pub quota: Option<Value>,
    /// 平台语法提示（Hunter syntax_prompt 等）。
    pub prompt: Option<String>,
}

/// 稳定错误码分类（沿用 domain_discovery 模式）；上游原始报文不外泄。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceError {
    pub code: &'static str,
    pub retryable: bool,
}

impl SourceError {
    pub const fn permanent(code: &'static str) -> Self {
        Self {
            code,
            retryable: false,
        }
    }
    pub const fn transient(code: &'static str) -> Self {
        Self {
            code,
            retryable: true,
        }
    }
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for SourceError {}

/// 跨源归一化后的端点记录（去重键 = ip|port|protocol）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NormalizedRecord {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tech: Vec<TechEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// 平台数据时间戳（epoch ms）；缺失/无权限时为拉取时间并置 timestamp_inferred。
    pub observed_at: i64,
    #[serde(default)]
    pub timestamp_inferred: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_org: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    /// 贡献该记录的平台（聚合后可能多个）。
    pub sources: Vec<String>,
}

impl NormalizedRecord {
    pub fn endpoint_key(&self) -> String {
        format!("{}|{}|{}", self.ip, self.port, self.protocol)
    }
}

// ---- 共享归一化辅助 ----

/// 文本卫生：trim、剔除 NUL 与控制字符、截断（字符数）。
pub fn clean_text(value: &str, max_chars: usize) -> Option<String> {
    let cleaned: String = value
        .trim()
        .chars()
        .filter(|c| *c != '\0' && !c.is_control())
        .take(max_chars)
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// tech id 归一化：小写字母/数字/连字符（同导入 tech 规则）；非法返回 None。
pub fn normalize_tech_id(name: &str) -> Option<String> {
    let lowered = name.trim().to_ascii_lowercase();
    let mut id = String::new();
    for ch in lowered.chars() {
        match ch {
            'a'..='z' | '0'..='9' => id.push(ch),
            ' ' | '_' | '.' | '/' => id.push('-'),
            '-' => id.push('-'),
            _ => return None,
        }
    }
    let id = id.trim_matches('-').to_owned();
    if id.is_empty() || id.len() > 64 {
        None
    } else {
        Some(id)
    }
}

/// 平台服务/产品名 → 本地服务词表（best-effort，未知原样小写保留）。
pub fn normalize_service(raw: &str) -> Option<String> {
    let value = raw.trim().to_ascii_lowercase();
    if value.is_empty() {
        return None;
    }
    let mapped = match value.as_str() {
        "http/ssl" | "https" | "ssl/http" => "https",
        "http" => "http",
        "microsoft-ds" | "netbios-ssn" => "smb",
        "ms-wbt-server" | "rdp" => "rdp",
        "domain" => "dns",
        "ntp" => "ntp",
        "snmp" => "snmp",
        "ssh" => "ssh",
        "ftp" | "ftp-data" => "ftp",
        "smtp" | "smtps" | "submission" => "smtp",
        "pop3" | "pop3s" => "pop3",
        "imap" | "imaps" => "imap",
        "mysql" | "mariadb" => "mysql",
        "postgresql" | "postgres" => "postgresql",
        "redis" => "redis",
        "mongodb" | "mongo" => "mongodb",
        "elasticsearch" => "elasticsearch",
        "telnet" => "telnet",
        "vnc" => "vnc",
        "mqtt" => "mqtt",
        "modbus" => "modbus",
        _ => return clean_text(&value, 128),
    };
    Some(mapped.to_owned())
}

/// 已知 UDP 服务（平台只给应用协议时推断传输层）。
pub fn infer_protocol(service: Option<&str>, platform_transport: Option<&str>) -> String {
    if let Some(transport) = platform_transport {
        let t = transport.trim().to_ascii_lowercase();
        if t == "udp" {
            return "udp".into();
        }
        if t == "tcp" {
            return "tcp".into();
        }
    }
    match service {
        Some("dns" | "ntp" | "snmp" | "mdns" | "ssdp") => "udp".into(),
        _ => "tcp".into(),
    }
}

/// ASN 归一化为纯数字字符串（同导入/MaxMind 存储）；接受 "AS15169"/"15169"/数字。
pub fn normalize_asn(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let digits = trimmed
        .strip_prefix("AS")
        .or_else(|| trimmed.strip_prefix("as"))
        .unwrap_or(trimmed);
    if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
        Some(digits.to_owned())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_selection_roundtrip() {
        let selection = FieldSelection::from_names(&[
            "ip".into(),
            "port".into(),
            "domain".into(),
            "tech".into(),
        ]);
        assert!(selection.domain && selection.tech && !selection.service);
        let names = selection.to_names();
        assert!(names.contains(&"ip".to_owned()) && names.contains(&"domain".to_owned()));
        assert!(!names.contains(&"banner".to_owned()));
    }

    #[test]
    fn tech_id_normalization() {
        assert_eq!(normalize_tech_id("jQuery"), Some("jquery".into()));
        assert_eq!(
            normalize_tech_id("Microsoft IIS"),
            Some("microsoft-iis".into())
        );
        assert_eq!(normalize_tech_id("nginx/1.2"), Some("nginx-1-2".into()));
        assert_eq!(normalize_tech_id("中文组件"), None);
        assert_eq!(normalize_tech_id("  "), None);
    }

    #[test]
    fn service_aliases_and_protocol_inference() {
        assert_eq!(normalize_service("http/ssl").as_deref(), Some("https"));
        assert_eq!(normalize_service("MySQL").as_deref(), Some("mysql"));
        assert_eq!(
            normalize_service("unknown-svc").as_deref(),
            Some("unknown-svc")
        );
        assert_eq!(infer_protocol(Some("dns"), None), "udp");
        assert_eq!(infer_protocol(Some("http"), None), "tcp");
        assert_eq!(infer_protocol(Some("http"), Some("udp")), "udp");
    }

    #[test]
    fn asn_normalization() {
        assert_eq!(normalize_asn("AS15169").as_deref(), Some("15169"));
        assert_eq!(normalize_asn("15169").as_deref(), Some("15169"));
        assert_eq!(normalize_asn("ASX"), None);
    }

    #[test]
    fn text_hygiene() {
        assert_eq!(clean_text("  a\0b\u{1}c  ", 10).as_deref(), Some("abc"));
        assert_eq!(clean_text("   ", 10), None);
        assert_eq!(clean_text("abcdef", 3).as_deref(), Some("abc"));
    }
}
