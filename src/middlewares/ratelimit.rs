use std::collections::HashMap;
use std::future::{Ready, ready};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use actix_web::{
    Error, HttpResponse,
    body::EitherBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    http::header,
};
use futures::future::LocalBoxFuture;
use serde_json::json;
use tracing::warn;

use super::hmiddleware::content_security_policy;

const STALE_ENTRY_AGE: Duration = Duration::from_secs(10 * 60);

#[derive(Clone)]
pub struct RateLimitMiddleware {
    state: Arc<Mutex<HashMap<String, RateLimitEntry>>>,
}

impl Default for RateLimitMiddleware {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[derive(Clone, Copy)]
struct RateLimitPolicy {
    max_requests: u32,
    window: Duration,
    message: &'static str,
}

struct RateLimitEntry {
    window_started: Instant,
    requests: u32,
}

impl<S, B> Transform<S, ServiceRequest> for RateLimitMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = RateLimitService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitService {
            service: Arc::new(service),
            state: self.state.clone(),
        }))
    }
}

pub struct RateLimitService<S> {
    service: Arc<S>,
    state: Arc<Mutex<HashMap<String, RateLimitEntry>>>,
}

impl<S, B> Service<ServiceRequest> for RateLimitService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path().to_owned();
        let Some(policy) = policy_for_path(&path) else {
            let fut = self.service.call(req);
            return Box::pin(async move { Ok(fut.await?.map_into_left_body()) });
        };

        let client = client_identifier(&req);
        let key = rate_limit_key(&req, &path, &client);
        let retry_after = check_rate_limit(&self.state, key, policy);

        if let Some(retry_after) = retry_after {
            let retry_after_secs = retry_after.as_secs().max(1);
            warn!(
                event = "RateLimitExceeded",
                path = crate::reports::assets::redact_path(&path),
                client = client.as_str(),
                retry_after = retry_after_secs
            );

            let body = json!({
                "success": false,
                "message": policy.message,
                "retry_after": retry_after_secs
            });

            let response = HttpResponse::TooManyRequests()
                .insert_header((header::RETRY_AFTER, retry_after_secs.to_string()))
                .insert_header((header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
                .insert_header((header::X_FRAME_OPTIONS, "DENY"))
                .insert_header((header::STRICT_TRANSPORT_SECURITY, "max-age=315360000;"))
                .insert_header((
                    header::CONTENT_SECURITY_POLICY,
                    content_security_policy(req.request()),
                ))
                .json(body);

            return Box::pin(async move { Ok(req.into_response(response).map_into_right_body()) });
        }

        let fut = self.service.call(req);
        Box::pin(async move { Ok(fut.await?.map_into_left_body()) })
    }
}

fn policy_for_path(path: &str) -> Option<RateLimitPolicy> {
    if path.starts_with("/open-api/v1/") {
        return Some(RateLimitPolicy {
            max_requests: 600,
            window: Duration::from_secs(60),
            message: "开放接口请求过于频繁",
        });
    }
    if path.starts_with(crate::reports::assets::IMAGE_PREFIX) {
        return Some(RateLimitPolicy {
            max_requests: 600,
            window: Duration::from_secs(60),
            message: "报告图片请求过于频繁",
        });
    }
    match path {
        crate::human_verification::CONFIG_PATH => Some(RateLimitPolicy {
            max_requests: 60,
            window: Duration::from_secs(60),
            message: "验证配置请求过于频繁，请稍后再试",
        }),
        "/api/scanner/diagnostics/chunk"
        | "/api/scanner/diagnostics/upload-status"
        | "/api/scanner/diagnostics/ack"
        | "/api/scanner/diagnostics/manifest"
        | "/api/scanner/diagnostics/complete"
        | "/api/scanner/diagnostics/events" => Some(RateLimitPolicy {
            max_requests: 120,
            window: Duration::from_secs(60),
            message: "扫描器诊断请求过于频繁",
        }),
        "/api/login" => Some(RateLimitPolicy {
            max_requests: 10,
            window: Duration::from_secs(60),
            message: "登录尝试过于频繁，请稍后再试",
        }),
        "/api/totp/verify" => Some(RateLimitPolicy {
            max_requests: 10,
            window: Duration::from_secs(60),
            message: "验证码验证过于频繁，请稍后再试",
        }),
        "/api/scanner/register" => Some(RateLimitPolicy {
            max_requests: 10,
            window: Duration::from_secs(60),
            message: "扫描器注册过于频繁，请稍后再试",
        }),
        "/api/scanner/result" => Some(RateLimitPolicy {
            max_requests: 120,
            window: Duration::from_secs(60),
            message: "扫描器上报过于频繁，请稍后再试",
        }),
        "/api/scanner/heartbeat" => Some(RateLimitPolicy {
            max_requests: 120,
            window: Duration::from_secs(60),
            message: "扫描器心跳过于频繁，请稍后再试",
        }),
        "/api/scanner/network/public-ip" => Some(RateLimitPolicy {
            max_requests: 30,
            window: Duration::from_secs(60),
            message: "扫描器网络探测过于频繁，请稍后再试",
        }),
        "/api/scanner/maintenance" => Some(RateLimitPolicy {
            max_requests: 12,
            window: Duration::from_secs(60),
            message: "系统维护状态查询过于频繁，请稍后再试",
        }),
        "/api/scanner/task/performance"
        | "/api/scanner/task/fail"
        | "/api/scanner/task/cancelled" => Some(RateLimitPolicy {
            max_requests: 30,
            window: Duration::from_secs(60),
            message: "扫描器任务状态上报过于频繁，请稍后再试",
        }),
        _ => None,
    }
}

fn check_rate_limit(
    state: &Arc<Mutex<HashMap<String, RateLimitEntry>>>,
    key: String,
    policy: RateLimitPolicy,
) -> Option<Duration> {
    let now = Instant::now();
    let mut buckets = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    buckets.retain(|_, entry| now.duration_since(entry.window_started) <= STALE_ENTRY_AGE);

    let entry = buckets.entry(key).or_insert_with(|| RateLimitEntry {
        window_started: now,
        requests: 0,
    });

    let elapsed = now.duration_since(entry.window_started);
    if elapsed >= policy.window {
        entry.window_started = now;
        entry.requests = 0;
    }

    if entry.requests >= policy.max_requests {
        return Some(
            policy
                .window
                .checked_sub(elapsed)
                .unwrap_or(Duration::from_secs(1)),
        );
    }

    entry.requests += 1;
    None
}

fn rate_limit_key(req: &ServiceRequest, path: &str, client: &str) -> String {
    if crate::middlewares::is_scanner_api_request(req.method(), path)
        && path.starts_with("/api/scanner/diagnostics/")
        && let Some(fingerprint) = bearer_fingerprint(req)
    {
        return format!("scanner-diagnostics:{fingerprint}");
    }
    if matches!(
        path,
        "/api/scanner/result"
            | "/api/scanner/heartbeat"
            | "/api/scanner/network/public-ip"
            | "/api/scanner/maintenance"
            | "/api/scanner/task/performance"
            | "/api/scanner/task/fail"
            | "/api/scanner/task/cancelled"
    ) && let Some(token_fingerprint) = bearer_fingerprint(req)
    {
        return format!("scanner-result:{}", token_fingerprint);
    }

    format!(
        "{}:{}:{}",
        req.method(),
        crate::reports::assets::redact_path(path),
        client
    )
}

fn client_identifier(req: &ServiceRequest) -> String {
    crate::client_ip::request_ip(req.request())
        .map(|address| address.to_string())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn bearer_fingerprint(req: &ServiceRequest) -> Option<u64> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?;

    let mut hasher = DefaultHasher::new();
    token.hash(&mut hasher);
    Some(hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::{policy_for_path, rate_limit_key};
    use actix_web::{http::header, test as actix_test};

    #[test]
    fn public_ip_endpoint_has_a_bounded_rate_limit() {
        let policy = policy_for_path("/api/scanner/network/public-ip")
            .expect("public IP endpoint must be rate limited");
        assert_eq!(policy.max_requests, 30);
    }

    #[test]
    fn public_ip_endpoint_is_rate_limited_by_token() {
        let request = actix_test::TestRequest::get()
            .uri("/api/scanner/network/public-ip")
            .insert_header((header::AUTHORIZATION, "Bearer runtime-secret"))
            .to_srv_request();
        let key = rate_limit_key(&request, "/api/scanner/network/public-ip", "192.0.2.10");
        assert!(key.starts_with("scanner-result:"));
        assert!(!key.contains("runtime-secret"));
        assert!(!key.contains("192.0.2.10"));
    }
}
