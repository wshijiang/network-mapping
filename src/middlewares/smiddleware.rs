use actix_web::{
    Error,
    body::EitherBody, // 可以参见 https://docs.rs/actix-web/latest/actix_web/body/enum.EitherBody.html
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
};
use actix_web::{HttpMessage, HttpResponse, http::header};
use std::future::{Ready, ready};
use std::sync::Arc;

use futures::future::LocalBoxFuture;

use crate::admin::UserSession;
use crate::login::get_session_from_req;
use crate::login::{LoginToken, SessionCheck};
use tracing::{debug, error, info};

use crate::api_response::error_response;
use crate::audit::{AuditContext, AuditEvent, RequestId, write_standalone};
use crate::frontend::{FrontendAssets, is_protected_frontend_path};
use crate::middlewares::{ExpectedCsrfToken, get_pool_from_app_data, is_scanner_api_request};
use crate::request_log::{RequestActor, set_reason};
use crate::web_support::get_conn_ip;
use uuid::Uuid;

/// 用于 session 检查的中间件的 Transform
pub struct AuthMiddleware;

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    // 在此使用 EitherBody<B> 是为了灵活处理中间件提前返回的情况，当一个请求在中间件中提前返回时返回的数据实现了 BoxBody（自己通过 HttpResponse 构造的页面） ,
    // 但是中间件返回原本要实现泛型B(这是请求正常走时返回的)这时候就不符合 Rust 的返回单一类型，
    // 所以利用 Actix-web 提供的权举 EitherBody 实现
    // 下同

    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService {
            service: Arc::new(service),
        }))
    }
}

/// 处理请求的 Service
pub struct AuthMiddlewareService<S> {
    service: Arc<S>,
}

fn unauthorized_response(req: &actix_web::HttpRequest, frontend_page: bool) -> HttpResponse {
    if frontend_page {
        HttpResponse::Found()
            .insert_header((header::LOCATION, "/login"))
            .finish()
    } else {
        error_response(
            req,
            actix_web::http::StatusCode::UNAUTHORIZED,
            "authentication_required",
            "身份验证失败或登录已过期",
        )
    }
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
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
        let request_id = req
            .extensions()
            .get::<RequestId>()
            .map(|value| value.0)
            .unwrap_or_else(Uuid::new_v4);
        req.extensions_mut().insert(RequestId(request_id));
        // 向量 path_list 定义了需要做权限校验的路径
        let path_list = ["/api", "/dashboard", "/logout"];
        let path = req.path().to_owned();
        let scanner_api_request = is_scanner_api_request(req.method(), &path);
        let svc = self.service.clone();

        let frontend_page =
            matches!(req.method().as_str(), "GET" | "HEAD") && is_protected_frontend_path(&path);
        let frontend_page_available = !frontend_page
            || req
                .app_data::<actix_web::web::Data<FrontendAssets>>()
                .map(|assets| assets.has_page_for_path(&path))
                .unwrap_or(true);
        let need_check = path != "/api/login"
            && !scanner_api_request
            && ((frontend_page && frontend_page_available)
                || path_list.iter().any(|prefix| path.starts_with(prefix)));

        info!(
            event = "received_requests",
            client_ip = get_conn_ip(req.request()),
            method = &req.method().to_string(),
            user_agent = &req
                .headers()
                .get("User-Agent")
                .map(|u| u.to_str().unwrap_or("Invalid UTF-8"))
                .unwrap_or("Unknown or None"),
            path = crate::reports::redact_mail_image_path(req.path()),
            request_id = %request_id,
        );

        Box::pin(async move {
            if !need_check {
                // 当请求不是以 path_list 开头则直接放行
                return Ok(svc.call(req).await?.map_into_left_body());
            }

            let session = match get_session_from_req(req.request(), "session") {
                Some(se) => se,
                None => {
                    set_reason(req.request(), "missing_session");
                    if let Ok(pool) = get_pool_from_app_data(&req) {
                        let mut audit_event = AuditEvent::anonymous(
                            "authentication",
                            "auth.session_rejected",
                            "denied",
                        );
                        audit_event.response_status = Some(401);
                        audit_event.reason_code = Some("missing_session".to_owned());
                        write_standalone(
                            pool,
                            &AuditContext::from_request(req.request()),
                            &audit_event,
                        )
                        .await;
                    }
                    debug!(
                        event = "InvalidSession",
                        reason = "missing_session_cookie",
                        method = %req.method(),
                        path = crate::reports::redact_mail_image_path(req.path()),
                        request_id = %request_id,
                        "request rejected because no session cookie was provided",
                    );
                    let resp = unauthorized_response(req.request(), frontend_page);
                    return Ok(req.into_response(resp).map_into_right_body());
                }
            };

            let g_pool = match get_pool_from_app_data(&req) {
                Ok(p) => p,
                Err(_) => {
                    set_reason(req.request(), "database_pool_app_data_missing");
                    let resp = HttpResponse::InternalServerError().finish();
                    return Ok(req.into_response(resp).map_into_right_body());
                }
            };
            let login_t = LoginToken {
                pool: g_pool.clone(),
            };

            let require_totp = path != "/api/totp/verify" && !scanner_api_request;

            match login_t.check_token(&session, require_totp).await {
                Ok(SessionCheck::Valid(authentication)) => {
                    let user = authentication.user;
                    // 将操作者写入最外层 wrap_fn 预置的槽位，供请求日志采集（request_log）。
                    // 槽位仅在采集开启且未被跳过的请求上存在；匿名/被拒绝请求保持 NULL。
                    if let Some(slot) = req.extensions().get::<RequestActor>() {
                        *slot
                            .0
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                            Some((user.id, user.username.clone()));
                    }

                    // 向通过检查的请求注入用户基础数据
                    req.extensions_mut().insert(user);

                    // 向通过检查的请求注入 session ，这样就不需要在每个 handler 中都读取一个 session 了
                    req.extensions_mut().insert(UserSession { session });
                    req.extensions_mut()
                        .insert(ExpectedCsrfToken::new(authentication.csrf_token));

                    Ok(svc.call(req).await?.map_into_left_body())
                }
                Ok(SessionCheck::Rejected(reason)) => {
                    set_reason(req.request(), reason);
                    let mut audit_event =
                        AuditEvent::anonymous("authentication", "auth.session_rejected", "denied");
                    audit_event.response_status = Some(401);
                    audit_event.reason_code = Some(reason.to_owned());
                    write_standalone(
                        g_pool,
                        &AuditContext::from_request(req.request()),
                        &audit_event,
                    )
                    .await;
                    debug!(
                        event = "InvalidSession",
                        reason,
                        method = %req.method(),
                        path = crate::reports::redact_mail_image_path(req.path()),
                        request_id = %request_id,
                        "request rejected because the session is invalid or expired",
                    );
                    let resp = unauthorized_response(req.request(), frontend_page);
                    Ok(req.into_response(resp).map_into_right_body())
                }
                Err(e) => {
                    set_reason(req.request(), "session_token_verification_failed");
                    let diagnostics = crate::logs::write::error_diagnostics(e.as_ref());
                    error!(
                        event = "TokenVerifyError",
                        operation = "verify_session_token",
                        error_kind = "database",
                        error_code = "session_token_verification_failed",
                        error_message = %diagnostics.error_message,
                        error_chain = %diagnostics.error_chain,
                        root_cause = %diagnostics.root_cause,
                        error_truncated = diagnostics.error_truncated,
                        retryable = false,
                        outcome = "request_failed",
                        middleware = "session_authentication",
                        http_status = 500_u16,
                        method = %req.method(),
                        path = crate::reports::redact_mail_image_path(req.path()),
                    );
                    let resp = HttpResponse::InternalServerError().finish();
                    Ok(req.into_response(resp).map_into_right_body())
                }
            }
        })
    }
}
