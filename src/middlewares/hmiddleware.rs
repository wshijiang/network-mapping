use std::future::{Ready, ready};

use actix_web::{
    Error,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    http::header,
};
use futures_util::future::LocalBoxFuture;

// Browser update checks read public repository tags from the GitHub API.
// Keep this exception in connect-src so other resources remain same-origin.
pub(crate) const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; connect-src 'self' https://api.github.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:;";

// There are two steps in middleware processing.
// 1. Middleware initialization, middleware factory gets called with
//    next service in chain as parameter.
// 2. Middleware's call method gets called with normal request.
pub struct SHeaderM;

// Middleware factory is `Transform` trait
// `S` - type of the next service
// `B` - type of response's body
impl<S, B> Transform<S, ServiceRequest> for SHeaderM
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SHeaderMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SHeaderMiddleware { service }))
    }
}

pub struct SHeaderMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for SHeaderMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let immutable_asset = req.path().starts_with("/assets/");
        let fut = self.service.call(req);

        Box::pin(async move {
            // 可以在此之前拦截请求

            let mut res = fut.await?;

            // 在此拦截响应

            res.headers_mut().insert(
                header::CONTENT_SECURITY_POLICY,
                header::HeaderValue::from_static(CONTENT_SECURITY_POLICY), // 暂时允许内联css
            );
            if immutable_asset && res.status().is_success() {
                res.headers_mut().insert(
                    header::CACHE_CONTROL,
                    header::HeaderValue::from_static("public, max-age=31536000, immutable"),
                );
            }
            res.headers_mut().insert(
                header::X_FRAME_OPTIONS,
                header::HeaderValue::from_static("DENY"),
            );
            res.headers_mut().insert(
                header::STRICT_TRANSPORT_SECURITY,
                header::HeaderValue::from_static("max-age=315360000;"),
            );
            res.headers_mut().insert(
                header::X_CONTENT_TYPE_OPTIONS,
                header::HeaderValue::from_static("nosniff"),
            );

            // 通过 HTTP 响应标头下发 CSRF Token
            // 允许前端读取 X-CSRF-Token 头
            // res.headers_mut().insert(
            //     header::ACCESS_CONTROL_EXPOSE_HEADERS,
            //     header::HeaderValue::from_static("X-CSRF-Token")
            // );
            Ok(res)
        })
    }
}
