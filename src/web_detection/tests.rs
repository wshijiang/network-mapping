use super::*;

#[derive(Deserialize)]
struct TechnologyFixture {
    id: String,
    headers: Value,
    body: String,
    expected: BTreeMap<String, Option<String>>,
}

#[test]
fn catalog_fixtures_identify_each_new_technology_and_explicit_version() {
    // Synthetic protocol/HTML cases, not transcripts from scanned live targets.
    let fixtures: Vec<TechnologyFixture> =
        serde_json::from_str(include_str!("fixtures.json")).unwrap();
    let mut covered = BTreeSet::new();
    for fixture in fixtures {
        let web = identify(fixture.headers, &fixture.body);
        assert_eq!(web.status, "identified", "{}", fixture.id);
        let actual: BTreeMap<_, _> = web
            .technologies
            .iter()
            .map(|t| (t.id.clone(), t.version.clone()))
            .collect();
        assert_eq!(actual, fixture.expected, "{}", fixture.id);
        assert!(!serde_json::to_string(&web).unwrap().contains("PRIVATE"));
        covered.extend(actual.into_keys());
    }
    let initial: BTreeSet<_> = [
        "nginx",
        "apache",
        "openresty",
        "caddy",
        "microsoft-iis",
        "litespeed",
        "express",
        "php",
        "aspnet",
        "jenkins",
        "wordpress",
        "drupal",
        "joomla",
        "laravel",
        "nextjs",
        "nuxt",
        "angular",
        "vue",
        "react",
        "jquery",
        "bootstrap",
        "element-plus",
        "antd",
        "grafana",
    ]
    .into_iter()
    .collect();
    let additions: BTreeSet<_> = RULES
        .iter()
        .map(|r| r.rule.technology.as_str())
        .filter(|t| !initial.contains(t))
        .collect();
    assert_eq!(
        covered.iter().map(String::as_str).collect::<BTreeSet<_>>(),
        additions
    );
}

#[test]
fn minio_requires_its_product_identity_not_s3_compatibility_or_a_port() {
    for headers in [
        json!({"Server":"AmazonS3","X-Amz-Request-Id":"PRIVATE","X-Amz-Id-2":"PRIVATE"}),
        json!({"Server":"nginx","X-Amz-Bucket-Region":"us-east-1"}),
        json!({"Server":"NotMinIO"}),
    ] {
        let web = identify(
            headers,
            "<Error><Code>AccessDenied</Code><Message>MinIO S3 compatible storage</Message></Error>",
        );
        assert!(web.technologies.iter().all(|t| t.id != "minio"));
    }
    let web = infer(Some("http"), None, None, 9000, 1000, None);
    assert!(web.technologies.is_empty());
    assert_eq!(
        identify(json!({"server":"MinIO"}), "").technologies[0].version,
        None
    );
}

#[test]
fn new_technologies_are_not_guessed_from_text_queries_or_python_servers() {
    let web = identify(
        json!({}),
        r#"<p>MinIO Astro SvelteKit Ghost ECharts</p><script src="https://minio.example/app.js?name=echarts@5.6.0/dist/echarts.js"></script><div class="vuetify layui"></div>"#,
    );
    assert!(web.technologies.is_empty());
    for server in ["gunicorn", "uvicorn", "Werkzeug/3.1.3 Python/3.13.1"] {
        let web = identify(json!({"server":server}), "");
        assert_eq!(web.technologies.len(), 1);
        assert!(
            !web.technologies
                .iter()
                .any(|t| matches!(t.id.as_str(), "django" | "flask" | "fastapi"))
        );
    }
}

fn identify(headers: Value, body: &str) -> WebInference {
    infer(
        Some("https"),
        None,
        Some(
            &json!({"schema_version":2,"evidence":[{"module":"https","result":{"response":{"headers":headers,"body":body}}}]}),
        ),
        8443,
        1000,
        Some("index/observation"),
    )
}

#[test]
fn identifies_layers_versions_and_references_without_cookie_values() {
    let web = identify(
        json!({"Server":["nginx/1.26.2"],"X-Powered-By":"Express","Set-Cookie":["laravel_session=PRIVATE; Path=/; HttpOnly"]}),
        r#"<script id="__NEXT_DATA__" type="application/json">{}</script><script src="/jquery-3.7.1.min.js?secret=PRIVATE"></script><div ng-version="18.2.0"></div>"#,
    );
    assert_eq!(web.status, "identified");
    for (name, version) in [
        ("nginx", Some("1.26.2")),
        ("express", None),
        ("nextjs", None),
        ("jquery", Some("3.7.1")),
        ("angular", Some("18.2.0")),
    ] {
        let tech = web.technologies.iter().find(|t| t.id == name).unwrap();
        assert_eq!(tech.version.as_deref(), version);
        assert!(
            tech.evidence
                .iter()
                .all(|e| e.observation_ref.as_deref() == Some("index/observation"))
        );
    }
    assert!(!serde_json::to_string(&web).unwrap().contains("PRIVATE"));
    assert_eq!(
        web.technologies
            .iter()
            .find(|t| t.id == "laravel")
            .unwrap()
            .confidence,
        "medium"
    );
}

#[test]
fn ordinary_text_comments_unrelated_json_and_resource_queries_do_not_identify() {
    let web = identify(
        json!({"x-unrelated":"nginx/1.2"}),
        r#"<p>React Vue WordPress nginx/1.2</p><!-- <script src='/jquery-1.0.js'></script> --><script>const note='jquery Vue';</script><script src="https://jquery.example/app.js?file=jquery-3.7.1.min.js"></script><script src="data:text/javascript,/jquery.js"></script><script src="javascript:/jquery.js"></script>"#,
    );
    assert_eq!(web.status, "unknown");
    assert!(web.technologies.is_empty());
    let non_http = infer(
        Some("ssh"),
        Some("nginx"),
        Some(
            &json!({"schema_version":2,"evidence":[{"module":"ssh","result":{"response":{"body":"<script src='/jquery.js'>"}}}]}),
        ),
        22,
        1,
        None,
    );
    assert_eq!(non_http.status, "not_web");
}

#[test]
fn versions_conflict_and_duplicate_rules_do_not_accumulate_evidence() {
    let web = identify(
        json!({}),
        r#"<script src="/jquery-3.7.1.min.js"></script><script src="/jquery-3.7.1.min.js"></script><script src="/jquery-1.12.4.min.js"></script>"#,
    );
    let jquery = &web.technologies[0];
    assert_eq!(jquery.id, "jquery");
    assert!(jquery.version_conflict);
    assert!(jquery.version.is_none());
    assert_eq!(jquery.evidence.len(), 2);
}

#[test]
fn missing_unknown_schema_and_truncated_evidence_remain_explicit() {
    let unknown = infer(Some("https"), None, None, 443, 1, None);
    assert_eq!(unknown.status, "unknown");
    let unsupported = infer(
        Some("http"),
        None,
        Some(&json!({"schema_version":999,"result":{"response":{"headers":{"server":"nginx"}}}})),
        80,
        1,
        None,
    );
    assert_eq!(unsupported.status, "unsupported");
    assert!(unsupported.technologies.is_empty());
    let partial = infer(
        Some("http"),
        None,
        Some(
            &json!({"schema_version":2,"evidence":[{"module":"http","truncated":true,"result":{"response":{"headers":{"server":"nginx"},"body":""}}}]}),
        ),
        80,
        1,
        None,
    );
    assert_eq!(partial.status, "partial");
    assert_eq!(partial.technologies[0].id, "nginx");
    assert!(endpoint_view(Some(partial), 2, 2).unwrap().stale);
}

#[test]
fn legacy_http_envelopes_and_escaped_attributes_are_supported() {
    let web = infer(
        Some("http"),
        None,
        Some(
            &json!({"result":{"response":{"headers":{},"body":"<META CONTENT='WordPress 6.7' NAME='generator'><script src='/jquery-3.7.1.min.js?a=&amp;b='></script>"}}}),
        ),
        8080,
        1,
        None,
    );
    assert_eq!(web.technologies.len(), 2);
    assert_eq!(
        web.technologies
            .iter()
            .find(|t| t.id == "wordpress")
            .unwrap()
            .version
            .as_deref(),
        Some("6.7")
    );
}

#[test]
fn oversized_bodies_and_multibyte_values_are_bounded() {
    let body = format!(
        "{}<script src='/jquery.js'></script>",
        "界".repeat(MAX_BODY)
    );
    let web = identify(json!({"server":"nginx"}), &body);
    assert_eq!(web.status, "partial");
    assert_eq!(web.technologies.len(), 1);
    assert_eq!(web.technologies[0].id, "nginx");
    assert_eq!(mapping()["properties"]["technologies"]["type"], "nested");
}
