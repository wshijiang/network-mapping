use futures_util::future::BoxFuture;
use serde::Deserialize;
use std::{net::IpAddr, time::Duration};

use super::{
    VerificationError,
    config::{HumanVerificationConfig, ProviderKind, hostname},
    provider::{PublicConfig, VerificationProvider, WidgetConfig},
};

const SITEVERIFY: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const MAX_RESPONSE_BYTES: usize = 16 * 1024;

pub(super) struct Turnstile {
    client: reqwest::Client,
    config: HumanVerificationConfig,
    endpoint: String,
}

#[derive(Deserialize)]
struct Response {
    success: bool,
    hostname: Option<String>,
    action: Option<String>,
    #[serde(default, rename = "error-codes")]
    error_codes: Vec<String>,
}

impl Turnstile {
    pub(super) fn new(config: HumanVerificationConfig) -> std::io::Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(config.connect_timeout_ms))
            .timeout(Duration::from_millis(config.timeout_ms))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| {
                std::io::Error::other("cannot initialize human verification HTTP client")
            })?;
        Ok(Self {
            client,
            config,
            endpoint: SITEVERIFY.into(),
        })
    }

    #[cfg(test)]
    pub(super) fn with_endpoint(config: HumanVerificationConfig, endpoint: String) -> Self {
        // Local mock requests must not depend on the developer's outbound proxy.
        Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            config,
            endpoint,
        }
    }

    async fn validate(
        &self,
        token: &str,
        action: &'static str,
        client_ip: Option<IpAddr>,
    ) -> Result<(), VerificationError> {
        let mut body =
            serde_json::json!({"secret": self.config.turnstile.secret_key, "response": token});
        if self.config.send_remote_ip
            && let Some(ip) = client_ip
        {
            body["remoteip"] = ip.to_string().into();
        }
        let mut response = self
            .client
            .post(&self.endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|_| VerificationError::Unavailable("transport"))?;
        if !response.status().is_success() {
            return Err(VerificationError::Unavailable("upstream_status"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| VerificationError::Unavailable("response_read"))?
        {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(VerificationError::Unavailable("response_size"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let result: Response = serde_json::from_slice(&bytes)
            .map_err(|_| VerificationError::Unavailable("invalid_response"))?;
        if !result.success {
            return if result.error_codes.iter().any(|v| {
                matches!(
                    v.as_str(),
                    "missing-input-secret"
                        | "invalid-input-secret"
                        | "internal-error"
                        | "bad-request"
                )
            }) {
                Err(VerificationError::Unavailable("provider_error"))
            } else {
                Err(VerificationError::Rejected("invalid_token"))
            };
        }
        let actual_hostname = result.hostname.as_deref().and_then(hostname);
        if actual_hostname.is_none()
            || !self
                .config
                .turnstile
                .allowed_hostnames
                .iter()
                .any(|allowed| hostname(allowed) == actual_hostname)
        {
            return Err(VerificationError::Rejected("hostname_mismatch"));
        }
        if result.action.as_deref() != Some(action) {
            return Err(VerificationError::Rejected("action_mismatch"));
        }
        Ok(())
    }
}

impl VerificationProvider for Turnstile {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Turnstile
    }

    fn public_config(&self) -> PublicConfig {
        PublicConfig {
            schema_version: 1,
            provider: self.kind(),
            actions: vec!["login"],
            widget: Some(WidgetConfig {
                site_key: self.config.turnstile.site_key.clone(),
                theme: "auto",
                size: "flexible",
            }),
        }
    }

    fn verify<'a>(
        &'a self,
        token: &'a str,
        action: &'static str,
        client_ip: Option<IpAddr>,
    ) -> BoxFuture<'a, Result<(), VerificationError>> {
        Box::pin(self.validate(token, action, client_ip))
    }
}
