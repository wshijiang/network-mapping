use super::*;

fn elasticsearch_root(version: &str) -> String {
    json!({
        "name":"PRIVATE", "cluster_name":"PRIVATE", "cluster_uuid":"PRIVATE",
        "version":{"number":version,"lucene_version":"9.12.2","build_hash":"0123456789abcdef"},
        "tagline":"You Know, for Search"
    })
    .to_string()
}

#[test]
fn elasticsearch_http_and_https_keep_versions_and_only_sanitized_markers() {
    for module in ["http", "https"] {
        for version in ["7.17.28", "8.19.0", "9.5.0", "9.5.0-SNAPSHOT"] {
            let web = infer(
                Some(module),
                None,
                Some(&json!({"schema_version":2,
                    "evidence":[{"module":module,"result":{"response":{
                        "headers":{"Content-Type":["application/json"],"X-Elastic-Product":["Elasticsearch"]},
                        "body":elasticsearch_root(version)
                    }}}]
                })),
                19200,
                1,
                Some("index/observation"),
            );
            assert_eq!(web.status, "identified");
            assert_eq!(web.technologies.len(), 1);
            let tech = &web.technologies[0];
            assert_eq!(tech.id, "elasticsearch");
            assert_eq!(tech.version.as_deref(), Some(version));
            assert_eq!(tech.category, "database");
            assert_eq!(tech.evidence.len(), 2);
            assert!(!serde_json::to_string(&web).unwrap().contains("PRIVATE"));
        }
    }
}

#[test]
fn elasticsearch_rejects_unrelated_json_opensearch_and_conflicting_product_headers() {
    for body in [
        r#"{"version":{"number":"8.19.0"},"tagline":"You Know, for Search"}"#.to_owned(),
        r#"{"message":"Elasticsearch 8.19.0"}"#.to_owned(),
        elasticsearch_root("<script>"),
        elasticsearch_root("8.19.0").replace("0123456789abcdef", "PRIVATE"),
        elasticsearch_root("8.19.0").replace("\"number\":", "\"number\":\"9.0.0\",\"number\":"),
        format!("<html>{}</html>", elasticsearch_root("8.19.0")),
    ] {
        assert!(
            identify(json!({"content-type":"application/json"}), &body)
                .technologies
                .is_empty()
        );
    }
    let mut root: Value = serde_json::from_str(&elasticsearch_root("2.19.0")).unwrap();
    root["version"]["distribution"] = json!("opensearch");
    for body in [
        root.to_string(),
        r#"{"tagline":"The OpenSearch Project: https://opensearch.org/"}"#.into(),
    ] {
        assert!(
            identify(
                json!({"content-type":"application/json","x-elastic-product":"Elasticsearch"}),
                &body
            )
            .technologies
            .is_empty()
        );
    }
    assert!(identify(json!({"content-type":"application/json","x-elastic-product":["Elasticsearch","OpenSearch"]}), &elasticsearch_root("8.19.0")).technologies.is_empty());
    assert!(
        identify(
            json!({"content-type":"text/html"}),
            &elasticsearch_root("8.19.0")
        )
        .technologies
        .is_empty()
    );
}

#[test]
fn elasticsearch_auth_headers_do_not_guess_versions_and_truncation_is_explicit() {
    for status in [401, 403] {
        let web = infer(
            Some("https"),
            None,
            Some(&json!({"schema_version":2,"evidence":[{
                "module":"https","result":{"response":{"status_code":status,
                    "headers":{"x-elastic-product":"Elasticsearch"},"body":""}}
            }]})),
            9200,
            1,
            None,
        );
        assert_eq!(web.technologies[0].id, "elasticsearch");
        assert_eq!(web.technologies[0].version, None);
        assert!(
            identify(
                json!({"www-authenticate":"Basic realm=security"}),
                "Unauthorized"
            )
            .technologies
            .is_empty()
        );
    }
    let web = infer(
        Some("http"),
        None,
        Some(&json!({"schema_version":2,"evidence":[{
            "module":"http","truncated":true,"result":{"response":{
                "headers":{"content-type":"application/json","x-elastic-product":"Elasticsearch"},
                "body":elasticsearch_root("8.19.0")}}
        }]})),
        9200,
        1,
        None,
    );
    assert_eq!(web.status, "partial");
    assert_eq!(web.technologies[0].version, None);
}

#[test]
fn elasticsearch_keeps_version_conflicts_and_never_reads_tcp_as_http() {
    let evidence = ["8.19.0", "9.5.0"].map(|v| {
        json!({"module":"https","result":{"response":{
        "headers":{"content-type":"application/json"},"body":elasticsearch_root(v)}}})
    });
    let web = infer(
        Some("https"),
        None,
        Some(&json!({"schema_version":2,"evidence":evidence})),
        9200,
        1,
        None,
    );
    assert!(web.technologies[0].version_conflict);
    assert_eq!(web.technologies[0].version, None);
    let web = infer(
        Some("tls"),
        None,
        Some(&json!({"schema_version":2,"evidence":[{
            "module":"tls","result":{"response":{"headers":{"x-elastic-product":"Elasticsearch"},"body":elasticsearch_root("8.19.0")}}
        }]})),
        9300,
        1,
        None,
    );
    assert_eq!(web.status, "not_web");
    assert!(web.technologies.is_empty());
}

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

#[test]
fn composite_markers_require_both_product_structure_and_supporting_evidence() {
    for body in [
        "<title>MinIO Console</title>",
        "<meta name='description' content='MinIO Console'>",
        "<p>MinIO Console</p><meta name='description' content='MinIO Console'>",
        "<form id='login_form'><input name='pma_username'></form>",
        "<form id='login_form'><input name='pma_password'></form>",
        "<div id='swagger-ui'></div>",
        "<script src='/swagger-ui-bundle.js'></script>",
        "<div x-data='{}'></div>",
        "<div x-show='open'></div>",
        "<button hx-get='/search'></button>",
        "<div hx-target='#results'></div>",
        "<p>GitLab Git git-upload-pack https://host/project.git</p>",
    ] {
        assert!(identify(json!({}), body).technologies.is_empty(), "{body}");
    }
    let body = format!(
        "<meta name='description' content='MinIO Console'><title>MinIO Console{}OTHER</title>",
        " ".repeat(MAX_TEXT)
    );
    let web = identify(json!({}), &body);
    assert!(web.technologies.is_empty());
    assert_eq!(web.status, "partial");
}

#[test]
fn conditions_cannot_borrow_evidence_from_a_different_response_or_protocol() {
    for (first, second) in [
        (
            json!({"headers":{},"body":"<title>MinIO Console</title>"}),
            json!({"headers":{},"body":"<meta name='description' content='MinIO Console'>"}),
        ),
        (
            json!({"headers":{"content-type":"application/x-git-upload-pack-advertisement"},"body":""}),
            json!({"headers":{},"body":"001e# service=git-upload-pack\n0000"}),
        ),
        (
            json!({"headers":{"x-minio-deployment-id":"PRIVATE"},"body":""}),
            json!({"headers":{"x-amz-request-id":"PRIVATE"},"body":""}),
        ),
    ] {
        let web = infer(
            Some("http"),
            None,
            Some(
                &json!({"schema_version":2,"evidence":[{"module":"http","result":{"response":first}},{"module":"https","result":{"response":second}}]}),
            ),
            80,
            1000,
            None,
        );
        assert!(web.technologies.is_empty());
    }
    let web = infer(
        Some("ssh"),
        None,
        Some(
            &json!({"schema_version":2,"evidence":[{"module":"ssh","result":{"response":{"headers":{"server":"MinIO"},"body":""}}}]}),
        ),
        22,
        1000,
        None,
    );
    assert!(web.technologies.is_empty());
}

#[test]
fn s3_and_git_reject_generic_headers_and_malformed_or_mismatched_payloads() {
    let headers = json!({"Content-Type":"application/xml","X-Amz-Request-Id":"PRIVATE","X-Amz-Id-2":"PRIVATE"});
    for body in [
        "<Other><Code>AccessDenied</Code><RequestId>PRIVATE</RequestId></Other>",
        "<Error><Code>AccessDenied</Code></Error>",
        r#"<ListBucketResult xmlns="urn:other"><Name>bucket</Name><MaxKeys>1</MaxKeys></ListBucketResult>"#,
        r#"<!DOCTYPE Error [<!ENTITY leak SYSTEM "https://example.invalid/private">]><Error><Code>AccessDenied</Code><RequestId>&leak;</RequestId></Error>"#,
    ] {
        assert!(identify(headers.clone(), body).technologies.is_empty());
    }
    let xml = "<Error><Code>AccessDenied</Code><RequestId>PRIVATE</RequestId></Error>";
    assert!(
        identify(
            json!({"Content-Type":"application/xml","X-Amz-Request-Id":"PRIVATE"}),
            xml
        )
        .technologies
        .is_empty()
    );
    assert!(
        identify(
            json!({"Content-Type":"text/html","X-Amz-Request-Id":"PRIVATE","X-Amz-Id-2":"PRIVATE"}),
            xml
        )
        .technologies
        .is_empty()
    );
    let git_headers = json!({"Content-Type":"application/x-git-upload-pack-advertisement"});
    for body in [
        "",
        "001f# service=git-upload-pack\n0000",
        "001f# service=git-receive-pack\n0000",
        "# service=git-upload-pack\n",
        "<p>Git service</p>",
    ] {
        assert!(identify(git_headers.clone(), body).technologies.is_empty());
    }
}

#[test]
fn grouped_rules_apply_all_any_and_safe_negative_conditions() {
    let rule = json!([{"id":"grouped-fixture","technology":"fixture","name":"Fixture","category":"application","source":"composite","confidence":"high","usage":"response_marker",
        "all":[{"source":"selector","selector":"#app","pattern":"^$"}],
        "any":[{"source":"header_name","field":"x-product","pattern":"^x-product$"},{"source":"selector","selector":"meta[name=product]","attribute":"content","pattern":"^Fixture$"}],
        "not":[{"source":"selector","selector":"meta[name=preview]","pattern":"^$"}]}]);
    let rules = compile_rules(&rule.to_string()).unwrap();
    for (headers, body, truncated, expected) in [
        (
            json!({"X-Product":"PRIVATE"}),
            "<div id='app'></div>",
            false,
            true,
        ),
        (
            json!({}),
            "<div id='app'></div><meta name='product' content='Fixture'>",
            false,
            true,
        ),
        (json!({}), "<div id='app'></div>", false, false),
        (
            json!({"X-Product":"PRIVATE"}),
            "<div id='app'></div><meta name='preview'>",
            false,
            false,
        ),
        (
            json!({"X-Product":"PRIVATE"}),
            "<div id='app'></div>",
            true,
            false,
        ),
    ] {
        let response = json!({"headers":headers,"body":body});
        let view = ResponseView::new(response.as_object().unwrap(), "/data/result", truncated);
        let mut out = Accumulator::default();
        apply_rules(&mut out, &rules, &view, "http", "/data/result", None);
        assert_eq!(out.technologies.contains_key("fixture"), expected);
        assert!(
            !serde_json::to_string(&out.technologies)
                .unwrap()
                .contains("PRIVATE")
        );
    }
    // Invalid rules fail validation instead of silently weakening a composite.
    for invalid in [
        json!([{"id":"bad","technology":"bad","name":"Bad","category":"application","source":"composite","confidence":"high","usage":"response_marker","not":[{"source":"title","pattern":"^Bad$"}]}]),
        json!([{"id":"bad","technology":"bad","name":"Bad","category":"application","source":"header","field":"set-cookie","pattern":".*","confidence":"high","usage":"response_marker"}]),
    ] {
        assert!(compile_rules(&invalid.to_string()).is_err());
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
