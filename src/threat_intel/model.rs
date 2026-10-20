use super::*;
use std::{net::IpAddr, path::Component};

pub(super) const MAX_ITEMS: usize = 50_000;
pub(super) const MAX_BYTES: usize = 96 * 1024 * 1024;
pub(super) const MAX_ARTICLE: usize = 100_000;
pub(super) const PROMPT_VERSION: &str = "ioc-evidence-v1";

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub(super) struct ValidationReport {
    pub rejected: i64,
    pub rejection_samples: Vec<Value>,
}
impl ValidationReport {
    pub fn merge(&mut self, other: Self, file: &str) {
        self.rejected += other.rejected;
        for mut sample in other
            .rejection_samples
            .into_iter()
            .take(100_usize.saturating_sub(self.rejection_samples.len()))
        {
            sample["file"] = json!(file.chars().take(512).collect::<String>());
            self.rejection_samples.push(sample);
        }
    }
    pub fn reject(
        &mut self,
        row: &Value,
        grouped_id: Option<&str>,
        record: i64,
        error: &Error,
    ) -> bool {
        // Only per-record data errors can be isolated. Syntax, size, disk and
        // transport errors still fail the entire document before publication.
        if !matches!(
            error.code,
            "intel_invalid_indicator"
                | "intel_invalid_domain"
                | "intel_invalid_ip"
                | "intel_invalid_endpoint"
                | "intel_invalid_indicator_url"
                | "intel_invalid_hash"
                | "intel_invalid_reference"
                | "intel_unsupported_indicator_type"
                | "intel_indicator_too_long"
        ) {
            return false;
        }
        self.rejected += 1;
        if self.rejection_samples.len() < 100 {
            let text = |key: &str, limit: usize| {
                row.get(key)
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .chars()
                    .take(limit)
                    .collect::<String>()
            };
            let id = row
                .get("id")
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string())
                })
                .unwrap_or_else(|| grouped_id.unwrap_or("").to_owned());
            self.rejection_samples.push(json!({"record":record,"external_id":id.chars().take(128).collect::<String>(),"type":text("ioc_type",64),"value":if row.get("ioc").and_then(Value::as_str).is_some(){text("ioc",4096)}else{text("ioc_value",4096)},"code":error.code}));
        }
        true
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceInput {
    pub name: String,
    pub kind: String,
    pub transport: String,
    pub location: String,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub auth_env: String,
    #[serde(default, skip_serializing)]
    pub credential: String,
    #[serde(default, skip_serializing)]
    pub clear_credential: bool,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub require_review: bool,
    #[serde(default)]
    pub interval_seconds: Option<i32>,
    #[serde(default = "default_expiry")]
    pub expiry_months: i32,
    pub expected_revision: Option<i64>,
}
fn yes() -> bool {
    true
}
fn default_expiry() -> i32 {
    6
}
pub(super) fn default_interval(kind: &str) -> i32 {
    match kind {
        "mitre_stix" => 86400,
        "threatfox_export" => 3600,
        "eset_github" => 3600,
        _ => 1800,
    }
}
impl SourceInput {
    pub fn validate(&mut self) -> Result<()> {
        self.name = self.name.trim().to_owned();
        if self.name.is_empty()
            || self.name.chars().count() > 100
            || !matches!(
                self.kind.as_str(),
                "json"
                    | "lines"
                    | "threatfox"
                    | "threatfox_export"
                    | "eset_github"
                    | "rss"
                    | "mitre_stix"
            )
        {
            return Err(Error::bad("intel_invalid_source"));
        }
        let interval = self
            .interval_seconds
            .get_or_insert(default_interval(&self.kind));
        if !(60..=2_592_000).contains(interval)
            || !(0..=120).contains(&self.expiry_months)
            || self.location.len() > 2048
            || !valid_key_ref(&self.auth_env)
        {
            return Err(Error::bad("intel_invalid_source"));
        }
        self.allowed_hosts.sort();
        self.allowed_hosts.dedup();
        if self.allowed_hosts.len() > 20 || self.allowed_hosts.iter().any(|host| !valid_host(host))
        {
            return Err(Error::bad("intel_invalid_hosts"));
        }
        match self.transport.as_str() {
            "upload" => {
                if !matches!(self.kind.as_str(), "json" | "lines" | "threatfox_export")
                    || !self.location.is_empty()
                    || !self.auth_env.is_empty()
                    || !self.credential.is_empty()
                {
                    return Err(Error::bad("intel_invalid_upload_source"));
                }
            }
            "local" => {
                if self.location.is_empty()
                    || std::path::Path::new(&self.location)
                        .components()
                        .any(|v| !matches!(v, Component::Normal(_)))
                    || !self.auth_env.is_empty()
                    || !self.credential.is_empty()
                {
                    return Err(Error::bad("intel_invalid_local_path"));
                }
                if self.kind == "eset_github" {
                    return Err(Error::bad("intel_remote_adapter_required"));
                }
            }
            "https" => {
                if self.kind == "threatfox_export" {
                    return Err(Error::bad("intel_offline_export_required"));
                }
                validate_url(&self.location, &self.allowed_hosts)?;
            }
            _ => return Err(Error::bad("intel_invalid_transport")),
        }
        if self.kind == "eset_github" {
            let u = reqwest::Url::parse(&self.location)
                .map_err(|_| Error::bad("intel_invalid_source"))?;
            if u.host_str() != Some("api.github.com")
                || !u.path().starts_with("/repos/")
                || !u.path().contains("/git/trees/")
            {
                return Err(Error::bad("intel_invalid_github_tree"));
            }
        }
        Ok(())
    }
}
pub(super) fn valid_key_ref(s: &str) -> bool {
    s.is_empty()
        || (s.starts_with("NM_INTEL_")
            && s.len() <= 100
            && s.bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'))
}
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host == host.to_ascii_lowercase()
        && host.split('.').all(|p| {
            !p.is_empty()
                && !p.starts_with('-')
                && !p.ends_with('-')
                && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
pub(super) fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            // Conservative outbound policy for IANA special-use networks,
            // matching the existing webhook policy. Prefixes must stay exact:
            // 192.0.1.0/24 is ordinary public space, unlike 192.0.0.0/24.
            ![
                "0.0.0.0/8",
                "10.0.0.0/8",
                "100.64.0.0/10",
                "127.0.0.0/8",
                "169.254.0.0/16",
                "172.16.0.0/12",
                "192.0.0.0/24",
                "192.0.2.0/24",
                "192.88.99.0/24",
                "192.168.0.0/16",
                "198.18.0.0/15",
                "198.51.100.0/24",
                "203.0.113.0/24",
                "224.0.0.0/3",
            ]
            .iter()
            .any(|prefix| {
                prefix
                    .parse::<ipnet::Ipv4Net>()
                    .expect("constant IPv4 prefix")
                    .contains(&v)
            })
        }
        IpAddr::V6(v) => v
            .to_ipv4_mapped()
            .map(|v| public_ip(IpAddr::V4(v)))
            .unwrap_or_else(|| {
                let b = v.octets();
                // Only global unicast. Excludes local, mapped, NAT64 and multicast.
                b[0] & 0xe0 == 0x20
                    && !(b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8)
            }),
    }
}
pub(super) fn validate_url(value: &str, hosts: &[String]) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).map_err(|_| Error::bad("intel_invalid_url"))?;
    let host = url
        .host_str()
        .ok_or_else(|| Error::bad("intel_invalid_url"))?;
    if value.len() > 4096
        || url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(443)
        || !hosts.iter().any(|h| h == host)
        || host.parse::<IpAddr>().is_ok_and(|ip| !public_ip(ip))
    {
        return Err(Error::bad("intel_url_not_allowed"));
    }
    Ok(url)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Settings {
    pub ai_enabled: bool,
    pub ai_endpoint: String,
    pub ai_model: String,
    pub ai_key_env: String,
    #[serde(default, skip_serializing)]
    pub credential: String,
    #[serde(default, skip_serializing)]
    pub clear_credential: bool,
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        let url = reqwest::Url::parse(&self.ai_endpoint)
            .map_err(|_| Error::bad("intel_invalid_ai_endpoint"))?;
        validate_url(
            &self.ai_endpoint,
            &[url.host_str().unwrap_or("").to_owned()],
        )?;
        if !valid_key_ref(&self.ai_key_env)
            || self.ai_model.len() > 100
            || (self.ai_enabled && self.ai_model.trim().is_empty())
        {
            return Err(Error::bad("intel_invalid_ai_settings"));
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(deny_unknown_fields)]
pub(super) struct Indicator {
    #[serde(rename = "type", alias = "ioc_type")]
    pub kind: String,
    #[serde(alias = "ioc")]
    pub value: String,
    #[serde(default = "malicious")]
    pub verdict: String,
    #[serde(default)]
    pub external_id: String,
    #[serde(default)]
    pub malware: String,
    #[serde(default)]
    pub actor_name: String,
    #[serde(default)]
    pub actor_id: Option<String>,
    #[serde(default)]
    pub techniques: Vec<String>,
    #[serde(default)]
    pub victim_industries: Vec<String>,
    #[serde(default)]
    pub victim_countries: Vec<String>,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub confidence: Option<i32>,
    #[serde(default)]
    pub first_seen: Option<String>,
    #[serde(default)]
    pub last_seen: Option<String>,
    #[serde(default)]
    pub valid_until: Option<chrono::DateTime<chrono::Utc>>,
}
fn malicious() -> String {
    "malicious".into()
}
impl Indicator {
    pub fn simple(kind: &str, value: &str) -> Self {
        serde_json::from_value(json!({"type":kind,"value":value})).expect("static indicator")
    }
    pub fn normalize(&mut self) -> Result<()> {
        let (kind, value) = normalize(&self.kind, &self.value)?;
        self.kind = kind;
        self.value = value;
        if !matches!(self.verdict.as_str(), "malicious" | "suspicious")
            || self.evidence.len() > 4000
            || self.external_id.len() > 2048
            || self.actor_name.len() > 200
            || self.malware.len() > 200
            || self.techniques.len() > 100
            || self.victim_industries.len() > 100
            || self.victim_countries.len() > 100
            || self
                .techniques
                .iter()
                .chain(&self.victim_industries)
                .chain(&self.victim_countries)
                .any(|s| s.len() > 200)
            || self.confidence.is_some_and(|v| !(0..=100).contains(&v))
        {
            return Err(Error::bad("intel_invalid_indicator"));
        }
        if self.reference.as_ref().is_some_and(|s| {
            s.len() > 4096
                || reqwest::Url::parse(s).map_or(true, |u| {
                    !matches!(u.scheme(), "http" | "https")
                        || !u.username().is_empty()
                        || u.password().is_some()
                })
        }) {
            return Err(Error::bad("intel_invalid_reference"));
        }
        Ok(())
    }
}
pub(super) fn normalize(kind: &str, raw: &str) -> Result<(String, String)> {
    let mut value = raw
        .trim()
        .replace("[.]", ".")
        .replace("[://]", "://")
        .replace("[:]", ":")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://");
    if value
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("hxxps://"))
    {
        value.replace_range(..5, "https");
    } else if value
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("hxxp://"))
    {
        value.replace_range(..4, "http");
    }
    let kind = match kind {
        "ip:port" => "ip_port",
        "ipv4" | "ipv6" => "ip",
        other => other,
    };
    let normalized = match kind {
        "ip" => value
            .parse::<IpAddr>()
            .map(|v| v.to_string())
            .map_err(|_| Error::bad("intel_invalid_ip"))?,
        "ip_port" => {
            let (host, port) = value
                .rsplit_once(':')
                .ok_or_else(|| Error::bad("intel_invalid_endpoint"))?;
            let ip = host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
                .map_err(|_| Error::bad("intel_invalid_endpoint"))?;
            let port = port
                .parse::<u16>()
                .ok()
                .ok_or_else(|| Error::bad("intel_invalid_endpoint"))?;
            match ip {
                IpAddr::V4(_) => format!("{ip}:{port}"),
                IpAddr::V6(_) => format!("[{ip}]:{port}"),
            }
        }
        "domain" => normalize_ioc_domain(&value)?,
        "url" => {
            // IOC values are data, never fetch destinations. Official reports
            // also publish SMB/FTP and scheme-less URLs, including userinfo.
            let has_scheme = value.contains("://");
            let input = if has_scheme {
                value.clone()
            } else {
                format!("ioc://{}", value.trim_start_matches("//"))
            };
            let mut u = reqwest::Url::parse(&input)
                .map_err(|_| Error::bad("intel_invalid_indicator_url"))?;
            if (has_scheme
                && !matches!(
                    u.scheme(),
                    "http" | "https" | "ftp" | "ftps" | "smb" | "tftp" | "tcp" | "ws" | "wss"
                ))
                || u.host_str().is_none_or(|host| host.is_empty())
            {
                return Err(Error::bad("intel_invalid_indicator_url"));
            }
            if !has_scheme {
                let host = u
                    .host_str()
                    .unwrap()
                    .trim_start_matches('[')
                    .trim_end_matches(']');
                if host.parse::<IpAddr>().is_err() && crate::dns::canonical_domain(host).is_err() {
                    return Err(Error::bad("intel_invalid_indicator_url"));
                }
            }
            u.set_fragment(None);
            if has_scheme {
                u.to_string()
            } else {
                u.to_string().strip_prefix("ioc://").unwrap().to_owned()
            }
        }
        "md5" | "sha1" | "sha256" => {
            let len = match kind {
                "md5" => 32,
                "sha1" => 40,
                _ => 64,
            };
            if value.len() != len || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::bad("intel_invalid_hash"));
            }
            value.to_ascii_lowercase()
        }
        _ => return Err(Error::bad("intel_unsupported_indicator_type")),
    };
    if normalized.len() > 4096 {
        return Err(Error::bad("intel_indicator_too_long"));
    }
    Ok((kind.to_owned(), normalized))
}

fn normalize_ioc_domain(value: &str) -> Result<String> {
    // IOC DNS names may contain underscores or IDNs. Do not weaken the stricter
    // hostname checks used by source fetching, scanners, or task creation.
    if value.chars().any(|c| {
        c.is_whitespace()
            || c.is_control()
            || matches!(c, '/' | '\\' | ':' | '?' | '#' | '@' | '%' | '[' | ']')
    }) {
        return Err(Error::bad("intel_invalid_domain"));
    }
    let ascii = if value.is_ascii() {
        value.to_ascii_lowercase()
    } else {
        reqwest::Url::parse(&format!("https://{value}/"))
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .ok_or_else(|| Error::bad("intel_invalid_domain"))?
    };
    let domain = ascii.strip_suffix('.').unwrap_or(&ascii);
    if domain.is_empty()
        || domain.len() > 253
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        })
    {
        return Err(Error::bad("intel_invalid_domain"));
    }
    Ok(domain.to_owned())
}
