//! Optional browser proof validation. The server owns policy; clients only carry tokens.
pub mod config;
mod provider;
mod routes;
pub mod settings;
mod turnstile;

use actix_web::{
    HttpMessage, HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web,
};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::sync::Semaphore;

use config::{HumanVerificationConfig, ProviderKind};
use provider::{PublicConfig, VerificationProvider};

pub const CONFIG_PATH: &str = "/api/auth/human-verification";
pub const LOGIN_BODY_LIMIT: usize = 16 * 1024;

#[derive(Deserialize, Serialize)]
pub struct Proof {
    pub token: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationError {
    Required,
    InvalidInput,
    Rejected(&'static str),
    Unavailable(&'static str),
}

impl VerificationError {
    pub fn public_contract(self) -> (StatusCode, &'static str, &'static str) {
        match self {
            Self::Required => (
                StatusCode::BAD_REQUEST,
                "human_verification_required",
                "请完成人机验证",
            ),
            Self::InvalidInput => (
                StatusCode::BAD_REQUEST,
                "human_verification_invalid_input",
                "人机验证参数无效",
            ),
            Self::Rejected(_) => (
                StatusCode::FORBIDDEN,
                "human_verification_failed",
                "人机验证失败，请重试",
            ),
            Self::Unavailable(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "human_verification_unavailable",
                "验证服务暂不可用，请稍后重试",
            ),
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::Required => "proof_missing",
            Self::InvalidInput => "invalid_input",
            Self::Rejected(reason) | Self::Unavailable(reason) => reason,
        }
    }

    pub fn response(self, req: &HttpRequest) -> HttpResponse {
        let (status, code, message) = self.public_contract();
        let mut response = crate::api_response::error_response(req, status, code, message);
        if status == StatusCode::SERVICE_UNAVAILABLE {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, header::HeaderValue::from_static("2"));
        }
        response
    }
}

#[derive(Clone)]
pub struct HumanVerificationService {
    provider: Option<Arc<dyn VerificationProvider>>,
    permits: Arc<Semaphore>,
    timeout: Duration,
}

impl HumanVerificationService {
    pub fn new(config: HumanVerificationConfig) -> std::io::Result<Self> {
        config.validate().map_err(std::io::Error::other)?;
        let permits = Arc::new(Semaphore::new(config.max_in_flight));
        let timeout = Duration::from_millis(config.timeout_ms);
        let provider: Option<Arc<dyn VerificationProvider>> = match config.provider {
            ProviderKind::None => None,
            ProviderKind::Turnstile => Some(Arc::new(turnstile::Turnstile::new(config)?)),
        };
        Ok(Self {
            provider,
            permits,
            timeout,
        })
    }

    pub fn enabled(&self) -> bool {
        self.provider.is_some()
    }

    pub fn provider_kind(&self) -> ProviderKind {
        self.provider
            .as_ref()
            .map_or(ProviderKind::None, |provider| provider.kind())
    }

    pub fn public_config(&self) -> PublicConfig {
        self.provider
            .as_ref()
            .map(|p| p.public_config())
            .unwrap_or(PublicConfig {
                schema_version: 1,
                provider: ProviderKind::None,
                actions: vec![],
                widget: None,
            })
    }

    pub async fn verify_login(
        &self,
        proof: Option<&Proof>,
        client_ip: Option<IpAddr>,
    ) -> Result<(), VerificationError> {
        let Some(provider) = &self.provider else {
            return Ok(());
        };
        let proof = proof.ok_or(VerificationError::Required)?;
        if proof.token.trim().is_empty() || proof.token.len() > 2048 {
            return Err(VerificationError::InvalidInput);
        }
        let _permit = self
            .permits
            .try_acquire()
            .map_err(|_| VerificationError::Unavailable("busy"))?;
        tokio::time::timeout(
            self.timeout,
            provider.verify(&proof.token, "login", client_ip),
        )
        .await
        .map_err(|_| VerificationError::Unavailable("timeout"))?
    }
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.configure(routes::configure);
    cfg.service(
        web::resource(CONFIG_PATH)
            .route(web::get().to(public_config))
            .route(web::head().to(public_config)),
    );
}

async fn public_config(req: HttpRequest) -> HttpResponse {
    let service = match for_request(&req).await {
        Ok(service) => service,
        Err(error) => return error.response(&req),
    };
    let mut response = HttpResponse::Ok();
    response.insert_header((header::CACHE_CONTROL, "no-store"));
    if req.method() == actix_web::http::Method::HEAD {
        response.finish()
    } else {
        response.json(service.public_config())
    }
}

#[derive(Clone)]
struct RequestVerification(Arc<HumanVerificationService>);

/// Resolve once per request so a concurrent publication cannot split verification and CSP.
pub async fn for_request(
    req: &HttpRequest,
) -> Result<Arc<HumanVerificationService>, VerificationError> {
    if let Some(value) = req.extensions().get::<RequestVerification>() {
        return Ok(value.0.clone());
    }
    let service = if let Some(settings) = req.app_data::<web::Data<settings::ManagedVerification>>()
    {
        settings
            .fresh()
            .await
            .map_err(|_| VerificationError::Unavailable("configuration_unavailable"))?
    } else if let Some(service) = req.app_data::<web::Data<HumanVerificationService>>() {
        // Static embedding remains supported for isolated consumers and provider tests.
        Arc::new(service.get_ref().clone())
    } else {
        return Err(VerificationError::Unavailable("configuration_missing"));
    };
    req.extensions_mut()
        .insert(RequestVerification(service.clone()));
    Ok(service)
}

pub(crate) fn request_provider_kind(req: &HttpRequest) -> ProviderKind {
    if let Some(value) = req.extensions().get::<RequestVerification>() {
        return value.0.provider_kind();
    }
    if let Some(settings) = req.app_data::<web::Data<settings::ManagedVerification>>() {
        return settings.cached().provider_kind();
    }
    req.app_data::<web::Data<HumanVerificationService>>()
        .map_or(ProviderKind::None, |service| service.provider_kind())
}

pub fn is_public_request(method: &actix_web::http::Method, path: &str) -> bool {
    path == CONFIG_PATH
        && matches!(
            *method,
            actix_web::http::Method::GET | actix_web::http::Method::HEAD
        )
}

/// Only a fixed, route/status-specific contract survives error normalization.
pub(crate) fn public_error(
    status: StatusCode,
    path: &str,
    code: &str,
) -> Option<(&'static str, &'static str)> {
    if path != "/api/login" {
        return None;
    }
    [
        VerificationError::Required,
        VerificationError::InvalidInput,
        VerificationError::Rejected(""),
        VerificationError::Unavailable(""),
    ]
    .into_iter()
    .map(VerificationError::public_contract)
    .find(|(expected_status, expected_code, _)| {
        *expected_status == status && *expected_code == code
    })
    .map(|(_, code, message)| (code, message))
}

#[cfg(test)]
mod tests;
