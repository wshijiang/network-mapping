use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    #[default]
    None,
    Turnstile,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HumanVerificationConfig {
    pub provider: ProviderKind,
    pub actions: Vec<String>,
    pub timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub max_in_flight: usize,
    pub send_remote_ip: bool,
    pub turnstile: TurnstileConfig,
}

impl Default for HumanVerificationConfig {
    fn default() -> Self {
        Self {
            provider: ProviderKind::None,
            actions: vec!["login".into()],
            timeout_ms: 3000,
            connect_timeout_ms: 1000,
            max_in_flight: 32,
            send_remote_ip: false,
            turnstile: TurnstileConfig::default(),
        }
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TurnstileConfig {
    pub site_key: String,
    pub secret_key: String,
    pub allowed_hostnames: Vec<String>,
}

impl fmt::Debug for TurnstileConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnstileConfig")
            .field("site_key", &self.site_key)
            .field("secret_key", &"[REDACTED]")
            .field("allowed_hostnames", &self.allowed_hostnames)
            .finish()
    }
}

pub(super) fn hostname(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 253 || !value.is_ascii() {
        return None;
    }
    if !value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

impl HumanVerificationConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(500..=10_000).contains(&self.timeout_ms)
            || self.connect_timeout_ms == 0
            || self.connect_timeout_ms > self.timeout_ms
            || !(1..=256).contains(&self.max_in_flight)
        {
            return Err("human_verification 超时或并发限制无效".into());
        }
        if self.actions != ["login"] {
            return Err("human_verification.actions 当前必须为 [\"login\"]".into());
        }
        if self.provider == ProviderKind::Turnstile
            && (self.turnstile.site_key.trim().is_empty()
                || self.turnstile.secret_key.trim().is_empty()
                || self.turnstile.allowed_hostnames.is_empty()
                || self
                    .turnstile
                    .allowed_hostnames
                    .iter()
                    .any(|v| hostname(v).is_none()))
        {
            return Err(
                "启用 Turnstile 必须提供 site_key、secret_key 和有效 allowed_hostnames".into(),
            );
        }
        Ok(())
    }

    /// Deliberately separate from the private configuration: no secret is serialized.
    pub(crate) fn inspection_defaults() -> serde_json::Value {
        let value = Self::default();
        serde_json::json!({
            "provider": value.provider, "actions": value.actions,
            "timeout_ms": value.timeout_ms, "connect_timeout_ms": value.connect_timeout_ms,
            "max_in_flight": value.max_in_flight, "send_remote_ip": value.send_remote_ip,
            "turnstile": {"site_key":"", "allowed_hostnames":[]}
        })
    }
}
