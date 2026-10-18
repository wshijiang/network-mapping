use super::*;
use crate::human_verification::VerificationError;
use actix_web::{App, cookie::Cookie, http::header, test as http_test, web};
use serde_json::{Value, json};

fn encoded_key() -> String {
    openssl::base64::encode_block(&[11; 32])
}
fn bootstrap() -> HumanVerificationConfig {
    HumanVerificationConfig {
        turnstile: TurnstileConfig {
            site_key: "public-fixture".into(),
            secret_key: "bootstrap-secret-fixture".into(),
            allowed_hostnames: vec!["console.example.com".into()],
        },
        ..HumanVerificationConfig::default()
    }
}
fn input(document: Policy, revision: i64) -> SettingsInput {
    SettingsInput {
        expected_revision: revision,
        document,
        secret_key: String::new(),
        clear_secret: false,
        change_reason: "settings test".into(),
    }
}
fn admin() -> UserBaseI {
    UserBaseI {
        id: 1,
        username: "hv-admin".into(),
        role: 1,
        email: None,
        limit_login: false,
        enable_2fa: false,
    }
}

#[test]
fn stored_credentials_are_authenticated_encrypted_and_never_appear_in_admin_view() {
    let key = [11; 32];
    let ciphertext = encrypt("private-test-credential", &key).unwrap();
    assert!(!ciphertext.contains("private-test-credential"));
    assert_eq!(
        decrypt(&ciphertext, &key).unwrap(),
        "private-test-credential"
    );
    assert!(decrypt(&ciphertext, &[12; 32]).is_err());
    let mut bytes = openssl::base64::decode_block(&ciphertext).unwrap();
    bytes[0] ^= 1;
    assert!(decrypt(&openssl::base64::encode_block(&bytes), &key).is_err());
    for invalid in ["bad", "", "eA=="] {
        assert!(decrypt(invalid, &key).is_err());
    }
    let stored = StoredSettings {
        policy: Policy::from_config(&bootstrap()),
        secret_ciphertext: Some(ciphertext),
    };
    let view = serde_json::to_string(&stored.view(1)).unwrap();
    assert!(!view.contains("private-test-credential"));
    assert!(!view.contains("secret_ciphertext"));
    assert!(view.contains("\"secret_key_configured\":true"));
}

#[test]
fn blank_secret_preserves_and_explicit_clear_or_replace_have_distinct_semantics() {
    let key = [11; 32];
    let stored = StoredSettings {
        policy: Policy::from_config(&bootstrap()),
        secret_ciphertext: Some(encrypt("old-key", &key).unwrap()),
    };
    let mut enabled = input(stored.policy.clone(), 1);
    enabled.document.provider = ProviderKind::Turnstile;
    enabled.document.allowed_hostnames =
        vec!["CONSOLE.example.com".into(), " console.example.com ".into()];
    let updated = stored.update(enabled, &key).unwrap();
    assert_eq!(updated.secret_ciphertext, stored.secret_ciphertext);
    assert_eq!(
        updated.policy.allowed_hostnames,
        vec!["console.example.com"]
    );
    let mut clear = input(updated.policy.clone(), 2);
    clear.clear_secret = true;
    assert!(
        updated.update(clear, &key).is_err(),
        "enabled protection must retain a credential"
    );
    let mut clear = input(updated.policy.clone(), 2);
    clear.document.provider = ProviderKind::None;
    clear.clear_secret = true;
    assert!(
        updated
            .update(clear, &key)
            .unwrap()
            .secret_ciphertext
            .is_none()
    );
    let mut replace = input(updated.policy.clone(), 2);
    replace.secret_key = "new-key".into();
    let replaced = updated.update(replace, &key).unwrap();
    assert_eq!(
        replaced.config(&key).unwrap().turnstile.secret_key,
        "new-key"
    );
    let mut conflicting = input(replaced.policy.clone(), 3);
    conflicting.secret_key = "private-test-credential".into();
    conflicting.clear_secret = true;
    assert!(replaced.update(conflicting, &key).is_err());
}

#[test]
fn web_policy_and_write_only_inputs_are_bounded_without_echoing_invalid_values() {
    let policy = Policy::from_config(&bootstrap());
    for mut edit in [
        input(policy.clone(), 0),
        input(policy.clone(), 1),
        input(policy.clone(), 1),
    ] {
        if edit.expected_revision == 1 {
            edit.secret_key = "private-test-credential\n".into();
        }
        let error = edit.validate().unwrap_err();
        assert!(!error.message().contains("private-test-credential"));
        edit.secret_key = "x".repeat(2049);
        assert!(edit.validate().is_err());
    }
    let mut document = policy.clone();
    document.allowed_hostnames = vec!["*.example.com".into()];
    assert!(document.normalize_and_validate(true).is_err());
    document = policy.clone();
    document.max_in_flight = 0;
    assert!(document.normalize_and_validate(true).is_err());
    document = policy;
    document.provider = ProviderKind::Turnstile;
    assert!(document.normalize_and_validate(false).is_err());
}

async fn database() -> (Pool, String) {
    let mut config: tokio_postgres::Config = std::env::var("HUMAN_VERIFICATION_TEST_DATABASE_URL")
        .expect(
            "point HUMAN_VERIFICATION_TEST_DATABASE_URL at a disposable local PostgreSQL database",
        )
        .parse()
        .unwrap();
    let schema = format!("human_verification_{}", uuid::Uuid::new_v4().simple());
    config.options(format!("-c search_path={schema} -c timezone=UTC"));
    let pool = Pool::builder(deadpool_postgres::Manager::new(
        config,
        tokio_postgres::NoTls,
    ))
    .max_size(8)
    .build()
    .unwrap();
    let connection = pool.get().await.unwrap();
    // Generated identifiers contain only a fixed prefix and UUID hexadecimal characters.
    connection
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    connection
        .batch_execute(include_str!("../../../source/database/init.sql"))
        .await
        .unwrap();
    connection.batch_execute("INSERT INTO users(id,username,password,role) VALUES(1,'hv-admin','unused',1),(2,'hv-member','unused',2); INSERT INTO session(user_id,token,csrf_token,totp_verify_successful) VALUES(1,'hv-admin-session','hv-admin-csrf',TRUE),(2,'hv-member-session','hv-member-csrf',TRUE)").await.unwrap();
    drop(connection);
    (pool, schema)
}

#[actix_web::test]
#[ignore = "requires disposable HUMAN_VERIFICATION_TEST_DATABASE_URL"]
async fn web_configuration_lifecycle_is_atomic_private_and_authoritative() {
    use crate::middlewares::{
        csrfmiddleware::CsrfMiddleware, hmiddleware::SHeaderM, ratelimit::RateLimitMiddleware,
        smiddleware::AuthMiddleware,
    };
    let (pool, schema) = database().await;
    let settings = web::Data::new(
        ManagedVerification::initialize(pool.clone(), &encoded_key(), bootstrap())
            .await
            .unwrap(),
    );
    let peer = ManagedVerification::initialize(
        pool.clone(),
        &encoded_key(),
        HumanVerificationConfig::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        peer.read().await.unwrap().document.site_key,
        "public-fixture",
        "existing saved settings must win over deployment defaults"
    );
    assert!(!peer.cached().enabled());
    let directory = std::env::temp_dir().join(format!("hv-web-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("login.html"), "<main>login fixture</main>").unwrap();
    std::fs::write(
        directory.join("index.html"),
        "<main>settings fixture</main>",
    )
    .unwrap();
    let app = http_test::init_service(
        App::new()
            .app_data(settings.clone())
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(crate::config::ServerConfig {
                host: "127.0.0.1".into(),
                port: 9999,
                encrypt_key: encoded_key(),
                max_body_size: 1024 * 1024,
            }))
            .app_data(web::Data::new(crate::frontend::FrontendAssets::new(
                &directory,
            )))
            .configure(crate::http::configure)
            .configure(crate::frontend::configure)
            .wrap(CsrfMiddleware)
            .wrap(SHeaderM)
            .wrap(AuthMiddleware)
            .wrap(RateLimitMiddleware::default())
            .wrap(crate::api_response::ApiErrorMiddleware),
    )
    .await;
    let path = "/api/config/human-verification";
    for (token, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some("hv-member-session"), StatusCode::FORBIDDEN),
    ] {
        let mut request = http_test::TestRequest::get().uri(path);
        if let Some(token) = token {
            request = request.cookie(Cookie::new("session", token));
        }
        let response = http_test::call_service(&app, request.to_request()).await;
        assert_eq!(response.status(), expected);
    }
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::get()
            .uri(path)
            .cookie(Cookie::new("session", "hv-admin-session"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let body: Value = http_test::read_body_json(response).await;
    assert_eq!(body["data"]["secret_key_configured"], true);
    assert!(!body.to_string().contains("bootstrap-secret-fixture"));
    let mut document = body["data"]["document"].clone();
    document["provider"] = json!("turnstile");
    let payload = json!({"expected_revision":1,"document":document,"secret_key":"new-web-secret-fixture","change_reason":"enable"});
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::put()
            .uri(path)
            .cookie(Cookie::new("session", "hv-admin-session"))
            .set_json(&payload)
            .to_request(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "writes require CSRF"
    );
    assert_eq!(settings.read().await.unwrap().revision, 1);
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::put()
            .uri(path)
            .cookie(Cookie::new("session", "hv-member-session"))
            .insert_header(("X-CSRF-Token", "hv-member-csrf"))
            .set_json(&payload)
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::put()
            .uri(path)
            .cookie(Cookie::new("session", "hv-admin-session"))
            .insert_header(("X-CSRF-Token", "hv-admin-csrf"))
            .set_json(&payload)
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = http_test::read_body_json(response).await;
    assert_eq!(body["data"]["revision"], 2);
    assert!(!body.to_string().contains("new-web-secret-fixture"));
    let row = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT document FROM runtime_configuration WHERE namespace='human_verification'",
            &[],
        )
        .await
        .unwrap();
    assert!(
        !row.get::<_, Value>("document")
            .to_string()
            .contains("new-web-secret-fixture")
    );
    let audit_rows = pool.get().await.unwrap().query("SELECT metadata,changes FROM audit_event WHERE action='config.human_verification.update'", &[]).await.unwrap();
    assert_eq!(audit_rows.len(), 1);
    assert!(
        !audit_rows[0]
            .get::<_, Value>("metadata")
            .to_string()
            .contains("secret-fixture")
    );
    assert_eq!(
        peer.fresh().await.unwrap().verify_login(None, None).await,
        Err(VerificationError::Required),
        "a peer's stale disabled cache must not bypass newly enabled protection"
    );
    let restarted = ManagedVerification::initialize(
        pool.clone(),
        &encoded_key(),
        HumanVerificationConfig::default(),
    )
    .await
    .unwrap();
    assert!(restarted.cached().enabled());
    assert!(
        ManagedVerification::initialize(
            pool.clone(),
            &openssl::base64::encode_block(&[12; 32]),
            HumanVerificationConfig::default(),
        )
        .await
        .is_err(),
        "a different master key must not silently disable saved protection"
    );
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::get()
            .uri(crate::human_verification::CONFIG_PATH)
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = http_test::read_body_json(response).await;
    assert_eq!(body["provider"], "turnstile");
    assert!(!body.to_string().contains("secret"));
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::get().uri("/login").to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("challenges.cloudflare.com")
    );
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::post()
            .uri("/api/login")
            .set_json(json!({"username":"example","password":"unused"}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    let mut stale = input(settings.read().await.unwrap().document, 1);
    stale.secret_key = "must-not-persist".into();
    assert!(matches!(
        settings
            .save(stale, &admin(), &AuditContext::cli("stale"))
            .await,
        Err(SettingsError::Conflict)
    ));
    let latest = settings.read().await.unwrap();
    let first = input(latest.document.clone(), latest.revision);
    let second = input(latest.document, latest.revision);
    let user = admin();
    let context = AuditContext::cli("concurrent");
    let (a, b) = tokio::join!(
        settings.save(first, &user, &context),
        settings.save(second, &user, &context)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let latest = settings.read().await.unwrap();
    let mut clear = input(latest.document.clone(), latest.revision);
    clear.clear_secret = true;
    assert!(settings.save(clear, &user, &context).await.is_err());
    assert_eq!(
        settings.read().await.unwrap().revision,
        latest.revision,
        "invalid updates are atomic"
    );
    let mut clear = input(latest.document, latest.revision);
    clear.document.provider = ProviderKind::None;
    clear.clear_secret = true;
    let cleared = settings.save(clear, &user, &context).await.unwrap();
    assert!(!cleared.secret_key_configured);
    assert!(!peer.fresh().await.unwrap().enabled());
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::get().uri("/login").to_request(),
    )
    .await;
    assert!(
        !response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("challenges.cloudflare.com")
    );
    // Even a previously disabled instance fails closed when the authority record disappears.
    pool.get()
        .await
        .unwrap()
        .execute(
            "DELETE FROM runtime_configuration WHERE namespace='human_verification'",
            &[],
        )
        .await
        .unwrap();
    assert!(peer.fresh().await.is_err());
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::post()
            .uri("/api/login")
            .set_json(json!({"username":"example","password":"unused"}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop(app);
    std::fs::remove_dir_all(directory).unwrap();
    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
