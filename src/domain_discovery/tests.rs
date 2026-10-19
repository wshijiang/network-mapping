use super::*;

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
        br#"[{"id":7,"name_value":"api.example.com"}]"#,
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
    let basic = client::collect_from(&client, "example.com", false, &endpoint)
        .await
        .unwrap();
    assert!(basic.candidates.iter().any(|c| c.name == "example.com"));
    assert!(basic.candidates.iter().any(|c| c.name == "api.example.com"));
    assert!(!basic.certificates[0].full_san);
    let complete = client::collect_from(&client, "example.com", true, &endpoint)
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
