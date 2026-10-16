use futures_util::future::BoxFuture;
use serde::Serialize;
use std::net::IpAddr;

use super::{VerificationError, config::ProviderKind};

#[derive(Serialize)]
pub struct PublicConfig {
    pub schema_version: u8,
    pub provider: ProviderKind,
    pub actions: Vec<&'static str>,
    pub widget: Option<WidgetConfig>,
}

#[derive(Serialize)]
pub struct WidgetConfig {
    pub site_key: String,
    pub theme: &'static str,
    pub size: &'static str,
}

/// Adapters own provider-specific response checks; callers only receive a decision.
pub(super) trait VerificationProvider: Send + Sync {
    fn kind(&self) -> ProviderKind;
    fn public_config(&self) -> PublicConfig;
    fn verify<'a>(
        &'a self,
        token: &'a str,
        action: &'static str,
        client_ip: Option<IpAddr>,
    ) -> BoxFuture<'a, Result<(), VerificationError>>;
}
