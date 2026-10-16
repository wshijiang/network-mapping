use actix_web::dev::ServiceRequest;
use actix_web::{
    Error, FromRequest, HttpMessage, HttpRequest, HttpResponse, dev::Payload,
    error::ErrorInternalServerError, http::Method, web,
};
use std::future::{Ready, ready};
use tracing::error;

use crate::admin::{UserBaseI, UserSession};
use crate::web_support::TEXT_HTML_UTF_8;
use crate::{FrontEndErrorInfo, front_end_error_page, logs, web_support::TemplatesInit};

// 该中间件用于检查用户是否拥有访问权
pub mod smiddleware;
// 该中间件用于处理 HTTP 标头
pub mod hmiddleware;
// 该中间件用于处理 CSRF TOKEN
pub mod csrfmiddleware;
// 该中间件用于限制公开入口请求频率
pub mod ratelimit;
// 该中间件用于按可信代理配置统一解析请求来源 IP
pub mod client_ip;

/// 认证中间件查询出的请求级 CSRF 预期值，由内层 CSRF 中间件直接校验，
/// 避免为同一请求再次查询 Session。
#[derive(Clone)]
pub(crate) struct ExpectedCsrfToken(String);

impl ExpectedCsrfToken {
    pub(crate) fn new(token: String) -> Self {
        Self(token)
    }

    pub(crate) fn matches(&self, candidate: &str) -> bool {
        self.0.len() == candidate.len()
            && openssl::memcmp::eq(self.0.as_bytes(), candidate.as_bytes())
    }
}

pub(crate) fn is_scanner_api_request(method: &Method, path: &str) -> bool {
    match path {
        "/api/task/apply"
        | "/api/task/current"
        | "/api/scanner/network/public-ip"
        | "/api/scanner/maintenance"
        | "/api/scanner/runtime-config" => method == Method::GET,
        "/api/scanner/diagnostics/upload-status" => method == Method::GET,
        "/api/scanner/diagnostics/chunk" => method == Method::PUT,
        "/api/scanner/register"
        | "/api/scanner/heartbeat"
        | "/api/scanner/result"
        | "/api/scanner/task/performance"
        | "/api/scanner/task/fail"
        | "/api/scanner/task/cancelled" => method == Method::POST,
        "/api/scanner/diagnostics/ack"
        | "/api/scanner/diagnostics/manifest"
        | "/api/scanner/diagnostics/complete"
        | "/api/scanner/diagnostics/events" => method == Method::POST,
        _ => false,
    }
}

/// 该函数用于从 app_data 中获取数据库连接池
///
/// 当从 app_data 中获取到 Some 时会自动从连接池中获取一个连接，然后返回这个连接（也有可能返回的是一个向上传递的错误）
/// 但获取到 None 值时会抛出错误并写入日志
pub fn get_pool_from_app_data(
    req: &ServiceRequest,
) -> Result<&deadpool_postgres::Pool, Box<dyn std::error::Error>> {
    match req.app_data::<web::Data<deadpool_postgres::Pool>>() {
        Some(p) => Ok(p.get_ref()),
        None => {
            error!(
                event = "GetDatabasePoolErrorFromAppData", // 从 app_data 中获取数据库连接池失败
                operation = "resolve_database_pool",
                error_kind = "configuration",
                error_code = "database_pool_app_data_missing",
                error_message = "database pool is missing from application data",
                retryable = false,
                outcome = "request_failed",
                middleware = "application_data",
                method = %req.method(),
                path = req.path(),
            );
            Err("从注入数据中提取失败 ".into())
        }
    }
}

/// 该函数用于生成 403 错误页面
pub fn render_403(req: &HttpRequest, page_template: &TemplatesInit, message: &str) -> HttpResponse {
    logs::write::warn_logs(req, "SessionAuthFailed", message);
    let error_info = FrontEndErrorInfo {
        status_code: 403,
        error_title: "Forbidden",
        error_message: "您已被屏蔽",
        request_id: logs::write::request_id(req).to_string(),
    };
    HttpResponse::Forbidden()
        .content_type(TEXT_HTML_UTF_8)
        .body(front_end_error_page(&error_info, page_template))
}

/// 该函数用于生成 500 错误页面
///
pub fn render_500(req: &HttpRequest, page_template: &TemplatesInit, message: &str) -> HttpResponse {
    logs::write::error_logs(req, "SystemError", message);
    let error_info = FrontEndErrorInfo {
        status_code: 500,
        error_title: "Internal Server Error",
        error_message: "服务器内部系统错误，别担心，这不是你的错误",
        request_id: logs::write::request_id(req).to_string(),
    };
    HttpResponse::InternalServerError()
        .content_type(TEXT_HTML_UTF_8)
        .body(front_end_error_page(&error_info, page_template))
}

/// 该函数用于生成一个简单的 500 错误页面，
/// 常用于模板系统无法正常从 app_data 中加载时
pub fn render_500_simple(req: &HttpRequest, message: &str) -> HttpResponse {
    logs::write::error_logs(req, "未能正确获取到模板系统", message);
    let request_id = logs::write::request_id(req);
    HttpResponse::InternalServerError().body(format!(
        "500 Internal Server Error\nRequest ID: {request_id}"
    ))
}

impl FromRequest for UserBaseI {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        if let Some(result) = req.extensions().get::<UserBaseI>().cloned() {
            ready(Ok(result))
        } else {
            ready(Err(ErrorInternalServerError("500")))
        }
    }
}

impl FromRequest for UserSession {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        if let Some(result) = req.extensions().get::<UserSession>().cloned() {
            ready(Ok(result))
        } else {
            ready(Err(ErrorInternalServerError("500")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ExpectedCsrfToken, is_scanner_api_request};
    use super::{
        csrfmiddleware::CsrfMiddleware, hmiddleware::SHeaderM, smiddleware::AuthMiddleware,
    };
    use crate::admin::UserBaseI;
    use crate::frontend::{self, FrontendAssets};
    use actix_web::{
        App, HttpMessage, HttpResponse, dev::Service, http::Method, http::StatusCode,
        test as actix_test, web,
    };
    use uuid::Uuid;

    #[test]
    fn csrf_expectation_matches_only_exact_token() {
        let expected = ExpectedCsrfToken::new("csrf-secret".to_owned());
        assert!(expected.matches("csrf-secret"));
        assert!(!expected.matches("csrf-secreu"));
        assert!(!expected.matches("csrf-secret-extra"));
    }

    #[actix_web::test]
    async fn csrf_uses_request_authentication_data_without_database_access() {
        let app = actix_test::init_service(
            App::new()
                .wrap(CsrfMiddleware)
                .wrap_fn(|req, service| {
                    req.extensions_mut()
                        .insert(ExpectedCsrfToken::new("csrf-secret".to_owned()));
                    req.extensions_mut().insert(UserBaseI {
                        id: 7,
                        username: "operator".to_owned(),
                        role: 1,
                        email: None,
                        limit_login: false,
                        enable_2fa: true,
                    });
                    service.call(req)
                })
                .route(
                    "/api/write",
                    web::post().to(|| async { HttpResponse::NoContent().finish() }),
                ),
        )
        .await;

        let valid = actix_test::TestRequest::post()
            .uri("/api/write")
            .insert_header(("X-CSRF-Token", "csrf-secret"))
            .to_request();
        assert_eq!(
            actix_test::call_service(&app, valid).await.status(),
            StatusCode::NO_CONTENT
        );

        let invalid = actix_test::TestRequest::post()
            .uri("/api/write")
            .insert_header(("X-CSRF-Token", "wrong"))
            .to_request();
        assert_eq!(
            actix_test::call_service(&app, invalid).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn scanner_api_requests_use_exact_method_and_path_matching() {
        assert!(is_scanner_api_request(
            &Method::POST,
            "/api/scanner/register"
        ));
        assert!(is_scanner_api_request(
            &Method::POST,
            "/api/scanner/heartbeat"
        ));
        assert!(is_scanner_api_request(&Method::POST, "/api/scanner/result"));
        assert!(is_scanner_api_request(
            &Method::POST,
            "/api/scanner/task/fail"
        ));
        assert!(is_scanner_api_request(
            &Method::POST,
            "/api/scanner/task/cancelled"
        ));
        assert!(is_scanner_api_request(&Method::GET, "/api/task/apply"));
        assert!(is_scanner_api_request(&Method::GET, "/api/task/current"));
        assert!(is_scanner_api_request(
            &Method::GET,
            "/api/scanner/network/public-ip"
        ));
        assert!(is_scanner_api_request(
            &Method::GET,
            "/api/scanner/maintenance"
        ));
        assert!(is_scanner_api_request(
            &Method::GET,
            "/api/scanner/runtime-config"
        ));

        assert!(!is_scanner_api_request(&Method::GET, "/api/scanner/result"));
        assert!(!is_scanner_api_request(&Method::PUT, "/api/scanner/result"));
        assert!(!is_scanner_api_request(&Method::POST, "/api/task/apply"));
        assert!(!is_scanner_api_request(&Method::POST, "/api/task/current"));
        assert!(!is_scanner_api_request(
            &Method::POST,
            "/api/scanner/network/public-ip"
        ));
        assert!(!is_scanner_api_request(
            &Method::POST,
            "/api/scanner/maintenance"
        ));
        assert!(!is_scanner_api_request(
            &Method::POST,
            "/api/scanner/runtime-config"
        ));
        assert!(!is_scanner_api_request(
            &Method::GET,
            "/api/task/apply-extra"
        ));
        assert!(!is_scanner_api_request(
            &Method::GET,
            "/api/task/apply/anything"
        ));
        assert!(!is_scanner_api_request(&Method::GET, "/api/task"));
        for path in [
            "/api/scanner/diagnostics/ack",
            "/api/scanner/diagnostics/manifest",
            "/api/scanner/diagnostics/complete",
            "/api/scanner/diagnostics/events",
        ] {
            assert!(is_scanner_api_request(&Method::POST, path));
            assert!(!is_scanner_api_request(&Method::GET, path));
            assert!(!is_scanner_api_request(
                &Method::POST,
                &format!("{path}/extra")
            ));
        }
        assert!(is_scanner_api_request(
            &Method::PUT,
            "/api/scanner/diagnostics/chunk"
        ));
        assert!(is_scanner_api_request(
            &Method::GET,
            "/api/scanner/diagnostics/upload-status"
        ));
        assert!(!is_scanner_api_request(
            &Method::POST,
            "/api/scanner/diagnostics/chunk"
        ));
        assert!(!is_scanner_api_request(
            &Method::POST,
            "/api/scanner/01952f0c-0000-7000-8000-000000000001/diagnostic-jobs"
        ));
    }

    #[actix_web::test]
    async fn scanner_task_reaches_handler_without_browser_session_or_csrf() {
        let app = actix_test::init_service(
            App::new()
                .wrap(CsrfMiddleware)
                .wrap(AuthMiddleware)
                .route(
                    "/api/task/apply",
                    web::get().to(|| async { HttpResponse::NoContent().finish() }),
                )
                .route(
                    "/api/task/current",
                    web::get().to(|| async { HttpResponse::NoContent().finish() }),
                )
                .route(
                    "/api/task/apply-extra",
                    web::get().to(|| async { HttpResponse::NoContent().finish() }),
                )
                .route(
                    "/api/scanner/network/public-ip",
                    web::get().to(|| async { HttpResponse::Ok().finish() }),
                ),
        )
        .await;

        let scanner_request = actix_test::TestRequest::get()
            .uri("/api/task/apply?scannerid=019fe6b8-1b2b-7720-91d2-132d8c0c724e")
            .to_request();
        let scanner_response = actix_test::call_service(&app, scanner_request).await;
        assert_eq!(scanner_response.status(), StatusCode::NO_CONTENT);

        let recovery_request = actix_test::TestRequest::get()
            .uri("/api/task/current?scannerid=019fe6b8-1b2b-7720-91d2-132d8c0c724e")
            .to_request();
        let recovery_response = actix_test::call_service(&app, recovery_request).await;
        assert_eq!(recovery_response.status(), StatusCode::NO_CONTENT);

        let public_ip_request = actix_test::TestRequest::get()
            .uri("/api/scanner/network/public-ip?scannerid=019fe6b8-1b2b-7720-91d2-132d8c0c724e")
            .to_request();
        let public_ip_response = actix_test::call_service(&app, public_ip_request).await;
        assert_eq!(public_ip_response.status(), StatusCode::OK);

        let similar_request = actix_test::TestRequest::get()
            .uri("/api/task/apply-extra")
            .to_request();
        let similar_response = actix_test::call_service(&app, similar_request).await;
        assert_eq!(similar_response.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn wrong_method_on_scanner_path_requires_browser_auth() {
        let app = actix_test::init_service(
            App::new()
                .wrap(CsrfMiddleware)
                .wrap(AuthMiddleware)
                .route(
                    "/api/scanner/result",
                    web::post().to(|| async { HttpResponse::NoContent().finish() }),
                )
                .route(
                    "/api/scanner/{scanner_id}",
                    web::get().to(|_user: UserBaseI, _scanner_id: web::Path<Uuid>| async {
                        HttpResponse::NoContent().finish()
                    }),
                ),
        )
        .await;

        for method in [Method::GET, Method::PUT, Method::DELETE] {
            let wrong_method = actix_test::TestRequest::default()
                .method(method)
                .uri("/api/scanner/result")
                .to_request();
            let wrong_method_response = actix_test::call_service(&app, wrong_method).await;
            assert_eq!(wrong_method_response.status(), StatusCode::UNAUTHORIZED);
        }

        let scanner_request = actix_test::TestRequest::post()
            .uri("/api/scanner/result")
            .to_request();
        let scanner_response = actix_test::call_service(&app, scanner_request).await;
        assert_eq!(scanner_response.status(), StatusCode::NO_CONTENT);
    }

    #[actix_web::test]
    async fn protected_frontend_navigation_redirects_to_login() {
        let app = actix_test::init_service(
            App::new()
                .wrap(AuthMiddleware)
                .route("/audit", web::get().to(HttpResponse::Ok)),
        )
        .await;

        let request = actix_test::TestRequest::get().uri("/audit").to_request();
        let response = actix_test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok()),
            Some("/login")
        );
    }

    #[actix_web::test]
    async fn missing_protected_frontend_entry_returns_404_before_authentication() {
        let directory = std::env::temp_dir().join(format!(
            "network-mapping-missing-auth-frontend-test-{}",
            uuid::Uuid::new_v4()
        ));
        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(FrontendAssets::new(directory)))
                .wrap(AuthMiddleware)
                .configure(frontend::configure),
        )
        .await;

        let request = actix_test::TestRequest::get()
            .uri("/audit")
            .insert_header(("Accept", "text/html"))
            .to_request();
        let response = actix_test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(response.headers().get("location").is_none());
    }

    #[actix_web::test]
    async fn successful_hashed_assets_receive_immutable_cache_headers() {
        let app = actix_test::init_service(
            App::new()
                .wrap(SHeaderM)
                .route("/assets/app-hash.js", web::get().to(HttpResponse::Ok)),
        )
        .await;

        let request = actix_test::TestRequest::get()
            .uri("/assets/app-hash.js")
            .to_request();
        let response = actix_test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("public, max-age=31536000, immutable")
        );
        assert_eq!(
            response
                .headers()
                .get("content-security-policy")
                .and_then(|value| value.to_str().ok()),
            Some(
                "default-src 'self'; connect-src 'self' https://api.github.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
            )
        );
    }

    #[actix_web::test]
    async fn html_pages_allow_github_update_connections_without_relaxing_other_resources() {
        let app = actix_test::init_service(App::new().wrap(SHeaderM).default_service(web::to(
            || async {
                HttpResponse::Ok()
                    .content_type("text/html")
                    .body("<!doctype html>")
            },
        )))
        .await;

        for path in ["/", "/login", "/search.html", "/asset.html", "/scanner"] {
            let request = actix_test::TestRequest::get().uri(path).to_request();
            let response = actix_test::call_service(&app, request).await;
            let policy = response
                .headers()
                .get("content-security-policy")
                .unwrap()
                .to_str()
                .unwrap();
            let directives: std::collections::HashMap<_, _> = policy
                .split(';')
                .filter_map(|directive| {
                    let mut parts = directive.split_whitespace();
                    Some((parts.next()?, parts.collect::<Vec<_>>()))
                })
                .collect();

            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                directives["connect-src"],
                ["'self'", "https://api.github.com"]
            );
            assert_eq!(directives["default-src"], ["'self'"]);
            assert_eq!(response.headers().get("x-frame-options").unwrap(), "DENY");
            assert_eq!(
                response.headers().get("x-content-type-options").unwrap(),
                "nosniff"
            );
        }
    }
}
