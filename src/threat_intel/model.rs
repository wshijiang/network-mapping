use super::*;
use std::{net::IpAddr, path::Component};

pub(super) const MAX_ITEMS: usize = 50_000;
pub(super) const MAX_BYTES: usize = 96 * 1024 * 1024;
pub(super) const MAX_ARTICLE: usize = 100_000;
pub(super) const PROMPT_VERSION: &str = "ioc-evidence-v1";

#[derive(Clone, Debug, Deserialize, Serialize)]
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
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub require_review: bool,
    #[serde(default)]
    pub interval_seconds: Option<i32>,
    pub expected_revision: Option<i64>,
}
fn yes() -> bool {
    true
}
pub(super) fn default_interval(kind: &str) -> i32 {
    match kind {
        "mitre_stix" | "threatfox_export" => 86400,
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
            "local" => {
                if self.location.is_empty()
                    || std::path::Path::new(&self.location)
                        .components()
                        .any(|v| !matches!(v, Component::Normal(_)))
                    || !self.auth_env.is_empty()
                {
                    return Err(Error::bad("intel_invalid_local_path"));
                }
                if self.kind == "eset_github" {
                    return Err(Error::bad("intel_remote_adapter_required"));
                }
            }
            "https" => {
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
            let [a, b, _, _] = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_multicast()
                || v.is_unspecified()
                || a == 0
                || a >= 240
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0)
                || (a == 198 && (b == 18 || b == 19)))
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
            || self.ai_key_env.is_empty()
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
    let value = raw
        .trim()
        .replace("[.]", ".")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://");
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
                .filter(|p| *p > 0)
                .ok_or_else(|| Error::bad("intel_invalid_endpoint"))?;
            match ip {
                IpAddr::V4(_) => format!("{ip}:{port}"),
                IpAddr::V6(_) => format!("[{ip}]:{port}"),
            }
        }
        "domain" => {
            crate::dns::canonical_domain(&value).map_err(|_| Error::bad("intel_invalid_domain"))?
        }
        "url" => {
            let mut u = reqwest::Url::parse(&value)
                .map_err(|_| Error::bad("intel_invalid_indicator_url"))?;
            if !matches!(u.scheme(), "http" | "https")
                || u.host_str().is_none()
                || !u.username().is_empty()
                || u.password().is_some()
            {
                return Err(Error::bad("intel_invalid_indicator_url"));
            }
            u.set_fragment(None);
            u.to_string()
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
