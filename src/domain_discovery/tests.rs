use super::*;
use crate::outbound_proxy::settings;
use crate::outbound_proxy::settings::DOMAIN_DISCOVERY_SCOPE;
use crate::outbound_proxy::{ProxyConfig, ProxyMode};

#[test]
fn matching_identities_are_not_complete_sans_or_ownership_claims() {
    let mut evidence = Evidence::empty("example.com");
    client::parse_rows(br#"[{"id":1,"name_value":"api.example.com\n*.example.com\nnotexample.com\nexample.com.evil.test"},{"id":1,"name_value":"api.example.com\nsecond.example.com"},{"id":2,"name_value":"other.example.com"}]"#, &mut evidence).unwrap();
    evidence.rebuild(true);
    assert_eq!(evidence.certificates.len(), 2);
    assert!(evidence.certificates.iter().all(|c| !c.full_san));
    assert_eq!(evidence.candidates.len(), 4);
    assert!(
        evidence
            .candidates
            .iter()
            .any(|c| c.name == "*.example.com" && c.relation == "wildcard")
    );
    assert!(!evidence.candidates.iter().any(|c| c.name == "example.com"));
    assert!(!evidence.candidates.iter().any(|c| c.name.contains("evil")));
    assert!(client::parse_rows(b"<html>unavailable</html>", &mut evidence).is_err());
}

fn fixture_certificate() -> Vec<u8> {
    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509, X509NameBuilder, extension::SubjectAlternativeName},
    };
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "api.example.com").unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("api.example.com")
        .dns("api.other.test")
        .dns("*.example.com")
        .build(&cert.x509v3_context(None, None))
        .unwrap();
    cert.append_extension(san).unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    cert.build().to_pem().unwrap()
}
#[test]
fn full_san_enrichment_preserves_cross_domain_evidence_and_wildcards() {
    let mut evidence = Evidence::empty("example.com");
    client::parse_rows(
        br#"[{"id":7,"name_value":"api.example.com"}]"#,
        &mut evidence,
    )
    .unwrap();
    client::enrich(&mut evidence.certificates[0], &fixture_certificate()).unwrap();
    evidence.rebuild(true);
    let related = evidence
        .candidates
        .iter()
        .find(|c| c.name == "api.other.test")
        .unwrap();
    assert_eq!(related.relation, "certificate_related");
    assert_eq!(related.certificate_ids, vec![7]);
    assert_eq!(
        evidence.certificates[0]
            .fingerprint_sha256
            .as_ref()
            .unwrap()
            .len(),
        64
    );
    assert!(evidence.certificates[0].full_san);
    evidence.rebuild(false);
    assert!(
        !evidence
            .candidates
            .iter()
            .any(|c| c.name == "api.other.test")
    );
}
#[test]
fn large_sources_are_explicitly_truncated() {
    let mut evidence = Evidence::empty("example.com");
    let rows: Vec<_> = (1..=MAX_CERTIFICATES + 1)
        .map(|id| json!({"id":id,"name_value":format!("x{id}.example.com")}))
        .collect();
    client::parse_rows(&serde_json::to_vec(&rows).unwrap(), &mut evidence).unwrap();
    evidence.rebuild(false);
    assert!(evidence.truncated);
    assert_eq!(evidence.certificates.len(), MAX_CERTIFICATES);
    assert!(canonical_name("api-*.example.com").is_none());
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn discovery_schema_is_idempotent_and_job_ownership_is_enforced() {
    let (c, conn) = tokio_postgres::connect(
        &std::env::var("STORAGE_TEST_DATABASE_URL").unwrap(),
        tokio_postgres::NoTls,
    )
    .await
    .unwrap();
    tokio::spawn(async move { conn.await.unwrap() });
    let schema = format!("discovery_{}", Uuid::new_v4().simple());
    c.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema};"
    ))
    .await
    .unwrap();
    c.batch_execute(include_str!("../../source/database/init.sql"))
        .await
        .unwrap();
    c.batch_execute(include_str!(
        "../../source/database/migrate_domain_discovery.sql"
    ))
    .await
    .unwrap();
    c.batch_execute("INSERT INTO users(id,username,password,role) VALUES(1,'discovery-one','unused',2),(2,'discovery-two','unused',2)").await.unwrap();
    let id = Uuid::now_v7();
    c.execute(
        "INSERT INTO domain_discovery_job(id,owner_id,seed) VALUES($1,1,'example.com')",
        &[&id],
    )
    .await
    .unwrap();
    let mut config: tokio_postgres::Config = std::env::var("STORAGE_TEST_DATABASE_URL")
        .unwrap()
        .parse()
        .unwrap();
    config.options(format!("-c search_path={schema}"));
    let pool = Pool::builder(deadpool_postgres::Manager::new(
        config,
        tokio_postgres::NoTls,
    ))
    .max_size(2)
    .build()
    .unwrap();
    assert!(owned(&pool, 1, id).await.is_ok());
    assert!(owned(&pool, 2, id).await.is_err());
    c.execute("INSERT INTO scanner_info(scanner_id,name,create_user,is_enable,supports_ipv4,ipv4_ready,scan_capabilities) VALUES($1,'DNS fixture',1,TRUE,TRUE,TRUE,$2)", &[&Uuid::new_v4().to_string(),&json!({"profiles":["dns_records"]})]).await.unwrap();
    let mut evidence = Evidence::empty("example.com");
    client::parse_rows(
        br#"[{"id":7,"name_value":"api.example.com\nlater.example.com"}]"#,
        &mut evidence,
    )
    .unwrap();
    evidence.rebuild(false);
    let user = UserBaseI {
        id: 1,
        username: "discovery-one".into(),
        role: 2,
        email: None,
        limit_login: false,
        enable_2fa: false,
    };
    let context = AuditContext::cli("discovery-dns-test");
    let policy = crate::dns_follow_up::DnsFollowUpConfig::default();
    let first = queue_evidence(
        &pool,
        &policy,
        &user,
        id,
        &evidence,
        vec!["api.example.com".into()],
        &context,
    )
    .await
    .unwrap();
    let repeated = queue_evidence(
        &pool,
        &policy,
        &user,
        id,
        &evidence,
        vec!["API.EXAMPLE.COM.".into()],
        &context,
    )
    .await
    .unwrap();
    assert_eq!(first, repeated);
    let task=c.query_one("SELECT task_port,scan_profile,(SELECT COUNT(*) FROM scan_task_execution e WHERE e.task_id=t.id) AS executions FROM scan_task t WHERE task_id=$1", &[&first["task_ids"][0].as_str().unwrap()]).await.unwrap();
    assert_eq!(task.get::<_, String>("task_port"), "53");
    assert_eq!(task.get::<_, String>("scan_profile"), "dns_records");
    assert_eq!(task.get::<_, i64>("executions"), 1);
    assert!(
        queue_evidence(
            &pool,
            &policy,
            &user,
            id,
            &evidence,
            vec!["not-discovered.example.com".into()],
            &context
        )
        .await
        .is_err()
    );
    let blocked = crate::dns_follow_up::DnsFollowUpConfig {
        excluded_domains: vec!["*.example.com".into()],
        ..Default::default()
    };
    assert!(
        queue_evidence(
            &pool,
            &blocked,
            &user,
            id,
            &evidence,
            vec!["api.example.com".into()],
            &context
        )
        .await
        .is_err()
    );
    c.execute("UPDATE users SET access_policy='{}' WHERE id=1", &[])
        .await
        .unwrap();
    let denied = queue_evidence(
        &pool,
        &policy,
        &user,
        id,
        &evidence,
        vec!["later.example.com".into()],
        &context,
    )
    .await
    .unwrap_err();
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert_eq!(denied.code, "authorization_changed");
    let count: i64 = c
        .query_one("SELECT COUNT(*) FROM scan_task", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[actix_web::test]
async fn source_queries_merge_matching_names_and_fetch_full_certificates() {
    use actix_web::{App, HttpResponse, HttpServer, web};
    let pem = fixture_certificate();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/", listener.local_addr().unwrap());
    let server = HttpServer::new(move || {
        let pem = pem.clone();
        App::new().route(
            "/",
            web::get().to(
                move |q: web::Query<std::collections::HashMap<String, String>>| {
                    let pem = pem.clone();
                    async move {
                        if q.get("d").is_some_and(|s| s == "7") {
                            return HttpResponse::Ok().body(pem);
                        }
                        assert_eq!(q.get("output").map(String::as_str), Some("json"));
                        let name = if q.get("q").is_some_and(|s| s == "example.com") {
                            "example.com"
                        } else {
                            "api.example.com"
                        };
                        HttpResponse::Ok().json(json!([{"id":7,"name_value":name}]))
                    }
                },
            ),
        )
    })
    .workers(1)
    .listen(listener)
    .unwrap()
    .run();
    let handle = server.handle();
    actix_web::rt::spawn(server);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let basic = client::collect_from(&client, "example.com", false, &endpoint, ProxyMode::Direct)
        .await
        .unwrap();
    assert!(basic.candidates.iter().any(|c| c.name == "example.com"));
    assert!(basic.candidates.iter().any(|c| c.name == "api.example.com"));
    assert!(!basic.certificates[0].full_san);
    let complete = client::collect_from(&client, "example.com", true, &endpoint, ProxyMode::Direct)
        .await
        .unwrap();
    assert!(
        complete
            .candidates
            .iter()
            .any(|c| c.name == "api.other.test" && c.relation == "certificate_related")
    );
    assert!(complete.certificates[0].full_san);
    handle.stop(true).await;
}

#[test]
fn root_relationships_include_discovered_children_even_without_a_root_san() {
    let mut evidence = Evidence::empty("example.com");
    client::parse_rows(
        br#"[{"id":7,"name_value":"api.example.com"}]"#,
        &mut evidence,
    )
    .unwrap();
    client::enrich(&mut evidence.certificates[0], &fixture_certificate()).unwrap();
    evidence.rebuild(true);
    let view = routes::project_relations("example.com", vec![(Uuid::now_v7(), evidence)], false);
    let names = view["candidates"].as_array().unwrap();
    assert!(
        names
            .iter()
            .any(|n| n["name"] == "api.example.com" && n["relation"] == "subdomain")
    );
    assert!(
        names
            .iter()
            .any(|n| n["name"] == "api.other.test" && n["relation"] == "certificate_related")
    );
    assert!(
        view["certificates"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["full_san"] == true)
    );
}

#[test]
fn invalid_custom_proxy_url_is_rejected_before_any_request() {
    let error = client::http_client(&ProxyConfig {
        mode: ProxyMode::Custom,
        url: "ftp://proxy.example:21".into(),
    })
    .unwrap_err();
    assert_eq!(error.code, "proxy_invalid");
    assert!(!error.retryable);
}

#[tokio::test]
async fn proxy_authentication_failure_is_permanent_and_never_reaches_the_source() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let proxy = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut header = vec![];
                while !header.ends_with(b"\r\n\r\n") {
                    let mut byte = [0u8; 1];
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    header.push(byte[0]);
                }
                let _ = tx.send(header);
                let _ = stream
                    .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                    .await;
            });
        }
    });
    let proxy_config = ProxyConfig {
        mode: ProxyMode::Custom,
        url: format!("http://user:secret@127.0.0.1:{port}"),
    };
    let http = client::http_client(&proxy_config).unwrap();
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client::probe(&http, ProxyMode::Custom),
    )
    .await
    .expect("proxy response")
    .unwrap_err();
    assert_eq!(error.code, "proxy_authentication_failed");
    assert!(!error.retryable);
    assert!(rx.recv().await.unwrap().starts_with(b"CONNECT "));
    proxy.abort();
}

#[tokio::test]
async fn proxy_connection_failure_is_transient() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let proxy_config = ProxyConfig {
        mode: ProxyMode::Custom,
        url: format!("http://127.0.0.1:{port}"),
    };
    let http = client::http_client(&proxy_config).unwrap();
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client::probe(&http, ProxyMode::Custom),
    )
    .await
    .expect("proxy connect")
    .unwrap_err();
    assert_eq!(error.code, "proxy_connection_failed");
    assert!(error.retryable);
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn proxy_settings_encrypt_retain_and_reuse_credentials() {
    let (c, conn) = tokio_postgres::connect(
        &std::env::var("STORAGE_TEST_DATABASE_URL").unwrap(),
        tokio_postgres::NoTls,
    )
    .await
    .unwrap();
    tokio::spawn(async move { conn.await.unwrap() });
    let schema = format!("discovery_proxy_{}", Uuid::new_v4().simple());
    c.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema};"
    ))
    .await
    .unwrap();
    c.batch_execute(include_str!("../../source/database/init.sql"))
        .await
        .unwrap();
    c.batch_execute(include_str!(
        "../../source/database/migrate_domain_discovery.sql"
    ))
    .await
    .unwrap();
    c.batch_execute(include_str!(
        "../../source/database/migrate_outbound_proxy_settings.sql"
    ))
    .await
    .unwrap();
    c.batch_execute(
        "INSERT INTO users(id,username,password,role) VALUES(1,'proxy-admin','unused',1)",
    )
    .await
    .unwrap();
    let mut config: tokio_postgres::Config = std::env::var("STORAGE_TEST_DATABASE_URL")
        .unwrap()
        .parse()
        .unwrap();
    config.options(format!("-c search_path={schema}"));
    let pool = Pool::builder(deadpool_postgres::Manager::new(
        config,
        tokio_postgres::NoTls,
    ))
    .max_size(2)
    .build()
    .unwrap();
    let key = openssl::base64::encode_block(&[7u8; 32]);
    let other_key = openssl::base64::encode_block(&[9u8; 32]);
    let user = UserBaseI {
        id: 1,
        username: "proxy-admin".into(),
        role: 1,
        email: None,
        limit_login: false,
        enable_2fa: false,
    };
    let context = AuditContext::cli("proxy-settings-test");
    let url = "socks5h://user:secret@proxy.example.com:1080";
    let first = settings::save(
        &pool,
        DOMAIN_DISCOVERY_SCOPE,
        &key,
        settings::SettingsInput {
            expected_revision: 1,
            proxy_mode: ProxyMode::Custom,
            proxy_url: url.into(),
            change_reason: String::new(),
        },
        &user,
        &context,
        "domain.discovery_proxy_update",
    )
    .await
    .unwrap()
    .public();
    let first = serde_json::to_value(first).unwrap();
    assert_eq!(first["proxy_mode"], "custom");
    assert_eq!(first["proxy_configured"], true);
    assert_eq!(first["revision"], 2);
    assert!(!first["proxy_endpoint"].as_str().unwrap().contains("secret"));
    assert!(!first["proxy_endpoint"].as_str().unwrap().contains("user@"));
    assert!(!first.to_string().contains("secret"));
    let stored: Option<Vec<u8>> = c
        .query_one(
            "SELECT proxy_ciphertext FROM outbound_proxy_settings WHERE scope='domain_discovery'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!stored.unwrap().windows(6).any(|window| window == b"secret"));
    assert_eq!(
        settings::load(&pool, DOMAIN_DISCOVERY_SCOPE)
            .await
            .unwrap()
            .proxy_config(&key)
            .unwrap()
            .url,
        url
    );
    let direct = settings::save(
        &pool,
        DOMAIN_DISCOVERY_SCOPE,
        &key,
        settings::SettingsInput {
            expected_revision: 2,
            proxy_mode: ProxyMode::Direct,
            proxy_url: String::new(),
            change_reason: "pause".into(),
        },
        &user,
        &context,
        "domain.discovery_proxy_update",
    )
    .await
    .unwrap()
    .public();
    let direct = serde_json::to_value(direct).unwrap();
    assert_eq!(direct["proxy_mode"], "direct");
    assert_eq!(direct["proxy_configured"], true);
    assert_eq!(direct["revision"], 3);
    let loaded = settings::load(&pool, DOMAIN_DISCOVERY_SCOPE).await.unwrap();
    let config = loaded.proxy_config(&key).unwrap();
    assert_eq!(config.mode, ProxyMode::Direct);
    assert!(config.url.is_empty());
    let resumed = settings::save(
        &pool,
        DOMAIN_DISCOVERY_SCOPE,
        &key,
        settings::SettingsInput {
            expected_revision: 3,
            proxy_mode: ProxyMode::Custom,
            proxy_url: String::new(),
            change_reason: "resume".into(),
        },
        &user,
        &context,
        "domain.discovery_proxy_update",
    )
    .await
    .unwrap()
    .public();
    assert_eq!(serde_json::to_value(resumed).unwrap()["revision"], 4);
    assert_eq!(
        settings::load(&pool, DOMAIN_DISCOVERY_SCOPE)
            .await
            .unwrap()
            .proxy_config(&key)
            .unwrap()
            .url,
        url
    );
    assert_eq!(
        settings::load(&pool, DOMAIN_DISCOVERY_SCOPE)
            .await
            .unwrap()
            .proxy_config(&other_key)
            .unwrap_err()
            .code,
        "proxy_configuration_unavailable"
    );
    let conflict = settings::save(
        &pool,
        DOMAIN_DISCOVERY_SCOPE,
        &key,
        settings::SettingsInput {
            expected_revision: 1,
            proxy_mode: ProxyMode::System,
            proxy_url: String::new(),
            change_reason: String::new(),
        },
        &user,
        &context,
        "domain.discovery_proxy_update",
    )
    .await
    .unwrap_err();
    assert_eq!(conflict.code(), "settings_revision_conflict");
    c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
