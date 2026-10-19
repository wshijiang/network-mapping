use super::*;
use actix_web::{App, HttpServer, dev::ServerHandle, test as http_test};
use serde_json::{Value, json};
use std::{net::TcpListener, sync::Mutex};

fn enabled_config() -> HumanVerificationConfig {
    HumanVerificationConfig {
        provider: ProviderKind::Turnstile,
        turnstile: config::TurnstileConfig {
            site_key: "public-fixture".into(),
            secret_key: "server-only-fixture".into(),
            allowed_hostnames: vec!["console.example.com".into()],
        },
        ..HumanVerificationConfig::default()
    }
}

struct Mock {
    url: String,
    handle: ServerHandle,
    requests: Arc<Mutex<Vec<Value>>>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        actix_web::rt::spawn(self.handle.stop(false));
    }
}

fn mock(status: StatusCode, body: String, delay: Duration) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/verify", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    let server = HttpServer::new(move || {
        let body = body.clone();
        let requests = recorded.clone();
        App::new().route(
            "/verify",
            web::post().to(move |request: web::Json<Value>| {
                let body = body.clone();
                requests.lock().unwrap().push(request.into_inner());
                async move {
                    tokio::time::sleep(delay).await;
                    HttpResponse::build(status).body(body)
                }
            }),
        )
    })
    .workers(1)
    .listen(listener)
    .unwrap()
    .run();
    let handle = server.handle();
    actix_web::rt::spawn(server);
    Mock {
        url,
        handle,
        requests,
    }
}

fn service(config: HumanVerificationConfig, url: String) -> HumanVerificationService {
    HumanVerificationService {
        permits: Arc::new(Semaphore::new(config.max_in_flight)),
        timeout: Duration::from_millis(config.timeout_ms),
        provider: Some(Arc::new(turnstile::Turnstile::with_endpoint(config, url))),
    }
}

fn proof() -> Proof {
    Proof {
        token: "opaque-proof".into(),
    }
}

#[actix_web::test]
async fn disabled_needs_neither_proof_nor_network_and_has_no_private_config() {
    let service = HumanVerificationService::new(HumanVerificationConfig::default()).unwrap();
    assert!(service.verify_login(None, None).await.is_ok());
    assert!(
        service
            .verify_login(Some(&Proof { token: "".into() }), None)
            .await
            .is_ok()
    );
    assert_eq!(
        serde_json::to_value(service.public_config()).unwrap(),
        json!({"schema_version":1,"provider":"none","actions":[],"widget":null})
    );
}

#[actix_web::test]
async fn validates_siteverify_and_sends_only_expected_fields() {
    let mock = mock(
        StatusCode::OK,
        json!({"success":true,"hostname":"CONSOLE.example.com","action":"login"}).to_string(),
        Duration::ZERO,
    );
    let service = service(enabled_config(), mock.url.clone());
    assert!(
        service
            .verify_login(Some(&proof()), Some("192.0.2.1".parse().unwrap()))
            .await
            .is_ok()
    );
    assert_eq!(
        mock.requests.lock().unwrap()[0],
        json!({"secret":"server-only-fixture","response":"opaque-proof"})
    );
    let public = serde_json::to_value(service.public_config()).unwrap();
    assert_eq!(public["widget"]["site_key"], "public-fixture");
    assert!(!public.to_string().contains("server-only-fixture"));
    assert!(!public.to_string().contains("allowed_hostnames"));

    let mut config = enabled_config();
    config.send_remote_ip = true;
    let service = self::service(config, mock.url.clone());
    assert!(
        service
            .verify_login(Some(&proof()), Some("192.0.2.1".parse().unwrap()))
            .await
            .is_ok()
    );
    assert_eq!(mock.requests.lock().unwrap()[1]["remoteip"], "192.0.2.1");
}

#[actix_web::test]
async fn hostnames_allow_descendants_with_label_boundaries_only() {
    for (actual, accepted) in [
        ("console.example.com", true),
        ("www.console.example.com", true),
        ("A.B.CONSOLE.EXAMPLE.COM", true),
        ("example.com", false),
        ("sibling.example.com", false),
        ("notconsole.example.com", false),
        ("console.example.com.evil.test", false),
        ("https://console.example.com", false),
        ("console.example.com:443", false),
        ("*.console.example.com", false),
    ] {
        let mock = mock(
            StatusCode::OK,
            json!({"success":true,"hostname":actual,"action":"login"}).to_string(),
            Duration::ZERO,
        );
        assert_eq!(
            service(enabled_config(), mock.url.clone())
                .verify_login(Some(&proof()), None)
                .await
                .is_ok(),
            accepted,
            "{actual}"
        );
    }
}

#[actix_web::test]
async fn rejected_or_malformed_responses_never_pass() {
    for (body, expected) in [
        (
            json!({"success":false,"error-codes":["timeout-or-duplicate"]}).to_string(),
            VerificationError::Rejected("invalid_token"),
        ),
        (
            json!({"success":false,"error-codes":["invalid-input-secret"]}).to_string(),
            VerificationError::Unavailable("provider_error"),
        ),
        (
            json!({"success":true,"hostname":"evil.example.com","action":"login"}).to_string(),
            VerificationError::Rejected("hostname_mismatch"),
        ),
        (
            json!({"success":true,"hostname":"console.example.com","action":"signup"}).to_string(),
            VerificationError::Rejected("action_mismatch"),
        ),
        (
            json!({"success":true,"hostname":"console.example.com"}).to_string(),
            VerificationError::Rejected("action_mismatch"),
        ),
        (
            json!({"success":true,"action":"login"}).to_string(),
            VerificationError::Rejected("hostname_mismatch"),
        ),
        (
            json!({"success":"true"}).to_string(),
            VerificationError::Unavailable("invalid_response"),
        ),
        (
            "{}".into(),
            VerificationError::Unavailable("invalid_response"),
        ),
        (
            "not JSON".into(),
            VerificationError::Unavailable("invalid_response"),
        ),
        (
            "x".repeat(16 * 1024 + 1),
            VerificationError::Unavailable("response_size"),
        ),
    ] {
        let mock = mock(StatusCode::OK, body, Duration::ZERO);
        let service = service(enabled_config(), mock.url.clone());
        assert_eq!(
            service.verify_login(Some(&proof()), None).await,
            Err(expected)
        );
        assert_eq!(
            mock.requests.lock().unwrap().len(),
            1,
            "verification must not retry"
        );
    }
}

#[actix_web::test]
async fn input_limits_and_concurrency_reject_without_outbound_calls() {
    let mock = mock(StatusCode::OK, "{}".into(), Duration::ZERO);
    let service = service(enabled_config(), mock.url.clone());
    assert_eq!(
        service.verify_login(None, None).await,
        Err(VerificationError::Required)
    );
    for token in [" ".into(), "x".repeat(2049)] {
        assert_eq!(
            service.verify_login(Some(&Proof { token }), None).await,
            Err(VerificationError::InvalidInput)
        );
    }
    let _all = service.permits.acquire_many(32).await.unwrap();
    assert_eq!(
        service.verify_login(Some(&proof()), None).await,
        Err(VerificationError::Unavailable("busy"))
    );
    assert!(mock.requests.lock().unwrap().is_empty());
}

#[actix_web::test]
async fn upstream_errors_and_total_timeout_fail_closed() {
    for status in [
        StatusCode::BAD_REQUEST,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::FOUND,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let mock = mock(status, "{}".into(), Duration::ZERO);
        let service = service(enabled_config(), mock.url.clone());
        assert_eq!(
            service.verify_login(Some(&proof()), None).await,
            Err(VerificationError::Unavailable("upstream_status"))
        );
    }
    let mock = mock(StatusCode::OK, "{}".into(), Duration::from_millis(150));
    let mut service = service(enabled_config(), mock.url.clone());
    service.timeout = Duration::from_millis(20);
    assert_eq!(
        service.verify_login(Some(&proof()), None).await,
        Err(VerificationError::Unavailable("timeout"))
    );
    assert_eq!(service.permits.available_permits(), 32);
}

fn pool_without_connections() -> deadpool_postgres::Pool {
    let mut config = tokio_postgres::Config::new();
    config
        .host("127.0.0.1")
        .port(1)
        .connect_timeout(Duration::from_millis(20));
    deadpool_postgres::Pool::builder(deadpool_postgres::Manager::new(
        config,
        tokio_postgres::NoTls,
    ))
    .max_size(1)
    .build()
    .unwrap()
}

#[actix_web::test]
async fn login_denials_survive_real_middleware_without_database_or_cookie_side_effects() {
    use crate::middlewares::{
        csrfmiddleware::CsrfMiddleware, hmiddleware::SHeaderM, ratelimit::RateLimitMiddleware,
        smiddleware::AuthMiddleware,
    };
    let mock = mock(
        StatusCode::OK,
        json!({"success":false}).to_string(),
        Duration::ZERO,
    );
    let verification = web::Data::new(service(enabled_config(), mock.url.clone()));
    let pool = pool_without_connections();
    let app = http_test::init_service(
        App::new()
            .app_data(verification.clone())
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(crate::config::ServerConfig {
                host: "127.0.0.1".into(),
                port: 9999,
                encrypt_key: String::new(),
                max_body_size: 1024 * 1024,
            }))
            .configure(crate::http::configure)
            .wrap(CsrfMiddleware)
            .wrap(SHeaderM)
            .wrap(AuthMiddleware)
            .wrap(RateLimitMiddleware::default())
            .wrap(crate::api_response::ApiErrorMiddleware),
    )
    .await;

    let response = http_test::call_service(
        &app,
        http_test::TestRequest::get().uri(CONFIG_PATH).to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert!(
        response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("frame-src https://challenges.cloudflare.com")
    );
    let public: Value = http_test::read_body_json(response).await;
    assert_eq!(public["provider"], "turnstile");
    assert!(!public.to_string().contains("server-only-fixture"));

    for (request, status, code) in [
        (
            json!({"username":"example","password":"wrong"}),
            StatusCode::BAD_REQUEST,
            "human_verification_required",
        ),
        (
            json!({"username":"example","password":"wrong","human_verification":{"token":"proof","enabled":false}}),
            StatusCode::FORBIDDEN,
            "human_verification_failed",
        ),
        (
            json!({"username":"example","password":"wrong","human_verification":{"token":""}}),
            StatusCode::BAD_REQUEST,
            "human_verification_invalid_input",
        ),
    ] {
        let response = http_test::call_service(
            &app,
            http_test::TestRequest::post()
                .uri("/api/login")
                .set_json(request)
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), status);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        let body: Value = http_test::read_body_json(response).await;
        assert_eq!(body["code"], code);
        assert_eq!(body["success"], false);
    }
    assert_eq!(
        pool.status().size,
        0,
        "denied proofs must not acquire a database connection"
    );
    assert_eq!(mock.requests.lock().unwrap().len(), 1);

    let _all = verification.permits.acquire_many(32).await.unwrap();
    let response = http_test::call_service(&app, http_test::TestRequest::post().uri("/api/login")
        .set_json(json!({"username":"example","password":"wrong","human_verification":{"token":"proof"}})).to_request()).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "2");
    let body: Value = http_test::read_body_json(response).await;
    assert_eq!(body["code"], "human_verification_unavailable");
    assert_eq!(body["message"], "验证服务暂不可用，请稍后重试");

    let response = http_test::call_service(
        &app,
        http_test::TestRequest::post()
            .uri("/api/login")
            .set_json(json!({"username":"example","password":"x".repeat(LOGIN_BODY_LIMIT)}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[actix_web::test]
async fn anonymous_allowlist_does_not_open_neighboring_routes() {
    let app = http_test::init_service(
        App::new()
            .app_data(web::Data::new(
                HumanVerificationService::new(HumanVerificationConfig::default()).unwrap(),
            ))
            .configure(configure)
            .wrap(crate::middlewares::smiddleware::AuthMiddleware)
            .wrap(crate::api_response::ApiErrorMiddleware),
    )
    .await;
    for path in [
        "/api/auth/other",
        "/api/auth/human-verification/other",
        "/api/config/runtime/general",
    ] {
        let response =
            http_test::call_service(&app, http_test::TestRequest::get().uri(path).to_request())
                .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::post().uri(CONFIG_PATH).to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::default()
            .method(actix_web::http::Method::HEAD)
            .uri(CONFIG_PATH)
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(http_test::read_body(response).await.is_empty());
}

#[actix_web::test]
async fn rate_limit_short_circuit_has_provider_csp_and_never_calls_provider() {
    let mock = mock(StatusCode::OK, "{}".into(), Duration::ZERO);
    let app = http_test::init_service(
        App::new()
            .app_data(web::Data::new(service(enabled_config(), mock.url.clone())))
            .configure(configure)
            .wrap(crate::middlewares::hmiddleware::SHeaderM)
            .wrap(crate::middlewares::ratelimit::RateLimitMiddleware::default()),
    )
    .await;
    for _ in 0..60 {
        let response = http_test::call_service(
            &app,
            http_test::TestRequest::get().uri(CONFIG_PATH).to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::get().uri(CONFIG_PATH).to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("challenges.cloudflare.com")
    );
    assert!(mock.requests.lock().unwrap().is_empty());
    let disabled = http_test::TestRequest::default().to_http_request();
    assert!(
        !crate::middlewares::hmiddleware::content_security_policy(&disabled)
            .contains("challenges.cloudflare.com")
    );
}

#[test]
fn config_rejects_incomplete_or_unsupported_policies_without_leaking_secret() {
    assert!(HumanVerificationConfig::default().validate().is_ok());
    let config = enabled_config();
    assert!(config.validate().is_ok());
    assert!(!format!("{config:?}").contains("server-only-fixture"));
    for value in [
        "https://console.example.com",
        "evil.example.com/path",
        "*.example.com",
        "x..com",
        "x.com:443",
        " x.com",
    ] {
        let mut config = enabled_config();
        config.turnstile.allowed_hostnames = vec![value.into()];
        assert!(config.validate().is_err());
    }
    let mut config = enabled_config();
    config.turnstile.secret_key.clear();
    assert!(config.validate().is_err());
    config = enabled_config();
    config.actions = vec!["signup".into()];
    assert!(config.validate().is_err());
    assert!(toml::from_str::<HumanVerificationConfig>("provider = 'unknown'").is_err());
}

#[actix_web::test]
async fn valid_proof_reaches_existing_password_handler_and_disabled_login_remains_compatible() {
    // No database is reachable: an HTTP 500 from the existing authentication path
    // distinguishes a passed proof from the verification gate's 400/403/503.
    let mock = mock(
        StatusCode::OK,
        json!({"success":true,"hostname":"console.example.com","action":"login"}).to_string(),
        Duration::ZERO,
    );
    for (verification, proof) in [
        (
            service(enabled_config(), mock.url.clone()),
            Some("opaque-proof"),
        ),
        (
            HumanVerificationService::new(HumanVerificationConfig::default()).unwrap(),
            None,
        ),
    ] {
        let app = http_test::init_service(
            App::new()
                .app_data(web::Data::new(verification))
                .app_data(web::Data::new(pool_without_connections()))
                .app_data(web::Data::new(crate::config::ServerConfig {
                    host: "127.0.0.1".into(),
                    port: 9999,
                    encrypt_key: String::new(),
                    max_body_size: 1024 * 1024,
                }))
                .configure(crate::http::configure)
                .wrap(crate::api_response::ApiErrorMiddleware),
        )
        .await;
        let mut body = json!({"username":"example","password":"wrong"});
        if let Some(proof) = proof {
            body["human_verification"] = json!({"token":proof});
        }
        let response = http_test::call_service(
            &app,
            http_test::TestRequest::post()
                .uri("/api/login")
                .set_json(body)
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }
    assert_eq!(
        mock.requests.lock().unwrap().len(),
        1,
        "disabled login must not make Siteverify calls"
    );
}
