use super::*;

use super::super::tests::{database, encryption_key, server_config, user};

#[test]
fn model_refresh_retains_missing_entries_and_restores_returning_models() {
    let provider = Provider {
        models: vec![
            Model {
                id: "missing".into(),
                name: "Saved label".into(),
                protocol: "responses".into(),
                available: true,
            },
            Model {
                id: "returned".into(),
                name: "Old label".into(),
                protocol: "responses".into(),
                available: false,
            },
            Model {
                id: "still-missing".into(),
                name: "Already unavailable".into(),
                protocol: "chat".into(),
                available: false,
            },
        ],
        ..Provider::default()
    };
    for catalog in [
        json!({"data":[{"id":"returned","name":"New label"},{"id":"new"}]}),
        json!({"models":[{"id":"returned","name":"New label"},{"id":"new"}]}),
        json!([{"id":"returned","name":"New label"},{"id":"new"}]),
    ] {
        let models = normalize_models(catalog, &provider).unwrap();
        assert_eq!(models.len(), 4);
        let missing = models.iter().find(|m| m.id == "missing").unwrap();
        assert!(!missing.available);
        assert_eq!(missing.name, "Saved label");
        assert_eq!(missing.protocol, "responses");
        assert!(
            !models
                .iter()
                .find(|m| m.id == "still-missing")
                .unwrap()
                .available
        );
        let returned = models.iter().find(|m| m.id == "returned").unwrap();
        assert!(returned.available);
        assert_eq!(returned.name, "New label");
        assert_eq!(returned.protocol, "responses");
        assert!(models.iter().find(|m| m.id == "new").unwrap().available);
    }
    let empty = normalize_models(json!([]), &provider).unwrap();
    assert_eq!(empty.len(), 3);
    assert!(empty.iter().all(|m| !m.available));
    assert!(provider.models[0].available);
    assert!(normalize_models(json!({}), &provider).is_err());
}

#[test]
fn local_overrides_are_explicit_and_headers_are_case_insensitive() {
    let mut global = Transport::global();
    global.stream = Some(true);
    global.headers = vec![Header {
        name: "X-Test".into(),
        value: "global".into(),
        ..Header::default()
    }];
    let mut local = Transport::default();
    local.proxy_mode = "direct".into();
    local.stream = Some(false);
    local.headers = vec![Header {
        name: "x-test".into(),
        value: "local".into(),
        ..Header::default()
    }];
    let resolved = resolve(&global, &local).unwrap();
    assert!(!resolved.stream);
    assert_eq!(resolved.proxy_mode, "direct");
    assert_eq!(resolved.headers["x-test"], "local");
    local.headers[0].remove = true;
    assert!(resolve(&global, &local).unwrap().headers.is_empty());
    local.headers_mode = "disabled".into();
    assert!(resolve(&global, &local).unwrap().headers.is_empty());
}

#[test]
fn sessions_do_not_replace_history_and_secrets_never_appear_in_previews() {
    let mut t = Transport::global();
    t.session_mode = "auto".into();
    t.proxy_url = "http://user:secret@proxy.example:8080".into();
    let resolved = resolve(&t, &Transport::default()).unwrap();
    assert_eq!(
        resolved
            .request_headers("secret-key", "conversation-1")
            .unwrap()["x-opencode-session"],
        "conversation-1"
    );
    assert!(
        !resolved
            .request_headers("secret-key", "")
            .unwrap()
            .contains_key("x-opencode-session")
    );
    assert!(!json!(t.redact()).to_string().contains("secret"));
    assert!(!resolved.preview().to_string().contains("secret"));
    let mut local = Transport::default();
    local.headers.push(Header {
        name: "X-OpenCode-Session".into(),
        value: "collision".into(),
        ..Header::default()
    });
    assert_eq!(
        resolve(&t, &local).err().unwrap().code,
        "llm_session_header_conflict"
    );
}

#[test]
fn stream_aggregation_rejects_partial_output_and_preserves_usage() {
    let mut stream = transport::Aggregate::new("chat");
    stream
        .push(json!({"choices":[{"delta":{"content":"hello"}}]}))
        .unwrap();
    assert!(stream.finish().is_err());
    let mut stream = transport::Aggregate::new("chat");
    for event in [
        json!({"choices":[{"delta":{"content":"hello"}}]}),
        json!({"choices":[{"finish_reason":"stop"}]}),
        json!({"choices":[],"usage":{"completion_tokens":1}}),
    ] {
        stream.push(event).unwrap();
    }
    let result = stream.finish().unwrap();
    assert_eq!(result["choices"][0]["message"]["content"], "hello");
    assert_eq!(result["usage"]["completion_tokens"], 1);
    let mut guard = transport::WireGuard::default();
    for part in [b"data: [DO".as_slice(), b"NE]\r", b"\n\n"] {
        guard.push(part).unwrap();
    }
    assert!(guard.done);
    assert!(transport::Aggregate::new("responses").finish().is_err());
    let mut stream = transport::Aggregate::new("responses");
    assert!(stream.push(json!({"type":"response.incomplete"})).is_err());
}

#[tokio::test]
async fn the_sdk_bridge_rejects_eof_without_done_even_after_a_finish_reason() {
    let service = tower::service_fn(
        |_factory: async_openai::middleware::HttpRequestFactory| async {
            let response: reqwest::Response = http::Response::builder().status(200)
            .body("data: {\"choices\":[{\"delta\":{\"content\":\"partial\"},\"finish_reason\":\"stop\"}]}\n\n").unwrap().into();
            transport::bridge(response, true, true)
        },
    );
    let sdk = async_openai::Client::with_config(
        async_openai::config::OpenAIConfig::new()
            .with_api_base("https://fixture.invalid/v1")
            .with_api_key("fixture"),
    )
    .with_http_service(service);
    assert!(
        transport::collect(&sdk, json!({"stream":true}), "chat", None)
            .await
            .is_err()
    );
}

#[test]
fn global_disabling_and_redacted_secret_updates_have_distinct_semantics() {
    let mut global = Transport::global();
    global.headers.push(Header {
        name: "X-Token".into(),
        value: "private-token".into(),
        ..Header::default()
    });
    global.headers_mode = "disabled".into();
    assert!(
        resolve(&global, &Transport::default())
            .unwrap()
            .headers
            .is_empty()
    );
    let mut edited = global.redact();
    edited.preserve(&global);
    assert_eq!(edited.headers[0].value, "private-token");
    edited.headers.clear();
    edited.preserve(&global);
    assert!(edited.headers.is_empty());
}

#[test]
fn streamed_refusals_keep_the_existing_validation_gate_without_retaining_private_text() {
    let mut stream = transport::Aggregate::new("chat");
    stream.push(json!({"choices":[{"delta":{"content":"{\"iocs\":[]}","refusal":"private refusal","reasoning_content":"private reasoning"},"finish_reason":"stop"}]})).unwrap();
    let value = stream.finish().unwrap();
    assert!(!value.to_string().contains("private"));
    let error = ai::response_content(value.to_string().as_bytes(), "chat")
        .err()
        .unwrap();
    assert_eq!(error.code, "intel_ai_refused");
    assert_eq!(error.diagnostic["reasoning_content_present"], true);
}

#[tokio::test]
async fn both_sdk_stream_protocols_handle_fragmentation_and_cancellation() {
    use async_openai::{Client, config::OpenAIConfig, error::OpenAIError};
    use futures_util::StreamExt;
    for protocol in ["chat", "responses"] {
        let wire = if protocol == "chat" {
            "data: {\"choices\":[{\"delta\":{\"content\":\"你好\"}}]}\n\ndata: {\"choices\":[{\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n".to_owned()
        } else {
            format!(
                "data: {}\n\ndata: {}\n\n",
                json!({"type":"response.output_text.delta","delta":"你好"}),
                json!({"type":"response.completed","response":{"status":"completed","output":[{"type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"你好"}]}]}})
            )
        };
        let service = tower::service_fn(
            move |_factory: async_openai::middleware::HttpRequestFactory| {
                let chunks = wire
                    .as_bytes()
                    .iter()
                    .map(|b| Ok::<_, std::io::Error>(actix_web::web::Bytes::from(vec![*b])))
                    .collect::<Vec<_>>();
                async move {
                    let response: reqwest::Response = http::Response::builder()
                        .status(200)
                        .header("content-type", "text/event-stream")
                        .body(reqwest::Body::wrap_stream(futures::stream::iter(chunks)))
                        .unwrap()
                        .into();
                    transport::bridge(response, true, protocol == "chat")
                }
            },
        );
        let sdk = Client::with_config(
            OpenAIConfig::new()
                .with_api_base("https://fixture.invalid/v1")
                .with_api_key("fixture"),
        )
        .with_http_service(service);
        let result = transport::collect(&sdk, json!({"stream":true}), protocol, None)
            .await
            .unwrap();
        assert_eq!(
            ai::response_content(result.to_string().as_bytes(), protocol)
                .unwrap()
                .0,
            "你好"
        );
    }
    // Dropping a browser consumer must also stop an idle upstream stream.
    let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    struct Guard(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let marker = dropped.clone();
    let service = tower::service_fn(
        move |_factory: async_openai::middleware::HttpRequestFactory| {
            let marker = marker.clone();
            async move {
                let guard = Guard(marker);
                let body = futures::stream::once(async {
                    Ok::<_, std::io::Error>(actix_web::web::Bytes::from_static(
                        b"data: {\"choices\":[]}\n\n",
                    ))
                })
                .chain(futures::stream::unfold(guard, |guard| async move {
                    std::future::pending::<()>().await;
                    Some((Ok::<_, std::io::Error>(actix_web::web::Bytes::new()), guard))
                }));
                Ok::<_, OpenAIError>(
                    http::Response::builder()
                        .status(200)
                        .header("content-type", "text/event-stream")
                        .body(reqwest_sdk::Body::wrap_stream(body))
                        .unwrap()
                        .into(),
                )
            }
        },
    );
    let sdk = Client::with_config(
        OpenAIConfig::new()
            .with_api_base("https://fixture.invalid/v1")
            .with_api_key("fixture"),
    )
    .with_http_service(service);
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(40),
        transport::collect(&sdk, json!({"stream":true}), "chat", None),
    )
    .await;
    assert!(result.is_err());
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while !dropped.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable INTEL_TEST_DATABASE_URL"]
async fn migration_crud_secret_retention_and_single_selection_share_the_ioc_fence() {
    let (pool, c, schema) = database().await;
    let key = encryption_key();
    let operator = user(1);
    let context = AuditContext::cli("llm-test");
    let mut settings:Settings=decode(json!({"ai_enabled":true,"ai_endpoint":"https://api.example/v1","ai_model":"legacy","ai_key_env":"","credential":"private-legacy-key"})).unwrap();
    super::super::storage::save_settings(&pool, settings.clone(), 1, &operator, &context, &key)
        .await
        .unwrap();
    for _ in 0..2 {
        c.batch_execute(include_str!("../../../source/database/migrate_llm.sql"))
            .await
            .unwrap();
    }
    let first = storage::read(&pool, &key).await.unwrap();
    assert!(first["enabled"].as_bool().unwrap());
    assert_eq!(first["providers"].as_array().unwrap().len(), 1);
    assert!(!first.to_string().contains("private-legacy-key"));
    let old_revision = first["revision"].as_i64().unwrap();
    assert_eq!(
        super::super::storage::save_settings(
            &pool,
            settings.clone(),
            old_revision,
            &operator,
            &context,
            &key
        )
        .await
        .err()
        .unwrap()
        .code,
        "llm_settings_moved"
    );
    let mut p = Provider {
        name: "new".into(),
        models: vec![Model {
            id: "new-model".into(),
            protocol: "chat".into(),
            ..Model::default()
        }],
        default_model: "new-model".into(),
        credential: "private-provider-key".into(),
        ..Provider::default()
    };
    p.transport.proxy_mode = "direct".into();
    p.transport.headers.push(Header {
        name: "X-Token".into(),
        value: "private-header".into(),
        ..Header::default()
    });
    let created = storage::save_provider(
        &pool,
        None,
        storage::ProviderInput {
            expected_revision: old_revision,
            provider: p,
        },
        &key,
        &operator,
        &context,
    )
    .await
    .unwrap();
    let id: Uuid = decode(created["id"].clone()).unwrap();
    let revision = created["revision"].as_i64().unwrap();
    assert!(runtime_transport(&pool, old_revision, &key).await.is_err());
    let mut global = Transport::global();
    global.stream = Some(true);
    storage::save_settings(
        &pool,
        storage::SettingsInput {
            expected_revision: revision,
            enabled: true,
            provider_id: Some(id),
            model_id: Some("new-model".into()),
            global,
        },
        &key,
        &operator,
        &context,
    )
    .await
    .unwrap();
    let state = storage::read(&pool, &key).await.unwrap();
    let revision = state["revision"].as_i64().unwrap();
    assert_eq!(state["effective"]["proxy_mode"], "direct");
    assert_eq!(state["effective"]["stream"], true);
    assert!(!state.to_string().contains("private-"));
    let (runtime, _) = super::super::storage::settings(&pool).await.unwrap();
    assert_eq!(runtime.ai_model, "new-model");
    assert_eq!(
        super::super::storage::ai_credential(&pool, &runtime, revision, &key)
            .await
            .unwrap(),
        "private-provider-key"
    );
    let mut edited: Provider = decode(
        state["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == json!(id))
            .unwrap()
            .clone(),
    )
    .unwrap();
    edited.name = "renamed".into();
    storage::save_provider(
        &pool,
        Some(id),
        storage::ProviderInput {
            expected_revision: revision,
            provider: edited,
        },
        &key,
        &operator,
        &context,
    )
    .await
    .unwrap();
    let revision = revision + 1;
    assert_eq!(
        runtime_transport(&pool, revision, &key)
            .await
            .unwrap()
            .headers["x-token"],
        "private-header"
    );
    assert_eq!(
        storage::delete(
            &pool,
            id,
            storage::DeleteInput {
                expected_revision: revision,
                pause_extraction: false
            },
            &key,
            &operator,
            &context
        )
        .await
        .err()
        .unwrap()
        .code,
        "llm_provider_in_use"
    );
    storage::delete(
        &pool,
        id,
        storage::DeleteInput {
            expected_revision: revision,
            pause_extraction: true,
        },
        &key,
        &operator,
        &context,
    )
    .await
    .unwrap();
    assert!(
        !super::super::storage::settings(&pool)
            .await
            .unwrap()
            .0
            .ai_enabled
    );
    let s = storage::read(&pool, &key).await.unwrap();
    assert!(s["provider_id"].is_null());
    settings.ai_enabled = false;
    c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[actix_web::test]
#[ignore = "requires disposable INTEL_TEST_DATABASE_URL"]
async fn management_endpoints_require_admin_and_enforce_model_ownership() {
    use actix_web::dev::Service;
    use actix_web::{App, HttpMessage, test as http_test, web};
    let (pool, c, schema) = database().await;
    let key = encryption_key();
    c.batch_execute(include_str!("../../../source/database/migrate_llm.sql"))
        .await
        .unwrap();
    let app = http_test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(server_config()))
            .wrap_fn(|req, srv| {
                req.extensions_mut().insert(user(0));
                srv.call(req)
            })
            .configure(configure),
    )
    .await;
    let denied = http_test::call_service(
        &app,
        http_test::TestRequest::get()
            .uri("/api/llm/settings")
            .to_request(),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let before = storage::read(&pool, &key).await.unwrap();
    let revision = before["revision"].as_i64().unwrap();
    let err = storage::save_settings(
        &pool,
        storage::SettingsInput {
            expected_revision: revision,
            enabled: true,
            provider_id: Some(Uuid::now_v7()),
            model_id: Some("foreign-model".into()),
            global: Transport::global(),
        },
        &key,
        &user(1),
        &AuditContext::cli("llm-test"),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err.status, StatusCode::NOT_FOUND);
    assert_eq!(
        storage::read(&pool, &key).await.unwrap()["revision"],
        revision
    );
    c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
