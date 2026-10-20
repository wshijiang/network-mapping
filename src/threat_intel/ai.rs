//! async-openai owns protocol dispatch/JSON decoding. Its custom transport uses
//! our bounded reqwest 0.12 path to preserve DNS, TLS, proxy and redirect policy.
use super::*;
use async_openai::{
    Client, config::OpenAIConfig, error::OpenAIError, middleware::HttpRequestFactory,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

fn payload(settings: &Settings, blocks: &Value, report_url: &str) -> Value {
    let input = json!({"report_url":report_url,"untrusted_report_blocks":blocks}).to_string();
    let messages = json!([{"role":"system","content":include_str!("ai_prompt.txt")},{"role":"user","content":input}]);
    let mut request = if settings.ai_protocol == "responses" {
        json!({"model":settings.ai_model,"input":messages,"text":{"format":{"type":"json_object"}},"max_output_tokens":settings.ai_max_output_tokens,"store":false,"stream":false})
    } else {
        json!({"model":settings.ai_model,"messages":messages,"response_format":{"type":"json_object"},"max_tokens":settings.ai_max_output_tokens,"stream":false})
    };
    if settings.ai_reasoning_effort != "default" {
        if settings.ai_protocol == "responses" {
            request["reasoning"] = json!({"effort":settings.ai_reasoning_effort});
        } else {
            request["reasoning_effort"] = json!(settings.ai_reasoning_effort);
        }
    }
    request
}

// Accept explicit endpoints and conventional /v1 SDK bases. Never guess a
// provider-specific prefix, and never append a route to an explicit endpoint.
pub(super) fn endpoint(settings: &Settings) -> Result<(String, &'static str, String)> {
    let mut url = reqwest::Url::parse(&settings.ai_endpoint)
        .map_err(|_| Error::bad("intel_invalid_ai_endpoint"))?;
    let path = url.path().trim_end_matches('/').to_owned();
    let route = if settings.ai_protocol == "responses" {
        "responses"
    } else {
        "chat/completions"
    };
    let kind = if path.ends_with("/chat/completions") {
        if settings.ai_protocol != "chat" {
            return Err(Error::bad("intel_ai_protocol_mismatch"));
        }
        "chat_completions"
    } else if path.ends_with("/responses") {
        if settings.ai_protocol != "responses" {
            return Err(Error::bad("intel_ai_protocol_mismatch"));
        }
        "responses"
    } else if path.ends_with("/v1") {
        url.set_path(&format!("{path}/{route}"));
        "base_url"
    } else {
        "custom"
    };
    validate_url(url.as_str(), &[url.host_str().unwrap_or("").into()])?;
    let full = url.to_string();
    let suffix = format!("/{route}");
    let base_path = url.path().strip_suffix(&suffix).unwrap_or("").to_owned();
    url.set_path(&base_path);
    url.set_query(None);
    Ok((full, kind, url.as_str().trim_end_matches('/').to_owned()))
}

pub(super) async fn request(
    settings: &Settings,
    key: &str,
    blocks: &Value,
    report_url: &str,
) -> Result<(Vec<u8>, Value)> {
    settings.validate()?;
    let (endpoint, endpoint_format, base) = endpoint(settings)?;
    let request = payload(settings, blocks, report_url);
    let mut input = json!({"request_bytes":request.to_string().len(),"system_prompt_bytes":include_str!("ai_prompt.txt").len(),"report_blocks_bytes":blocks.to_string().len(),"report_block_count":blocks.as_array().map_or(0,Vec::len),"actor_candidate_count":0,"ai_protocol":settings.ai_protocol,"max_output_tokens":settings.ai_max_output_tokens,"reasoning_effort":settings.ai_reasoning_effort,"prompt_version":PROMPT_VERSION});
    let transport_error = Arc::new(Mutex::new(None));
    let response_size = Arc::new(Mutex::new(0usize));
    input["endpoint_format"] = json!(endpoint_format);
    let timeout = settings.ai_timeout_seconds;
    let service = {
        let failure = transport_error.clone();
        let size = response_size.clone();
        tower::service_fn(move |factory: HttpRequestFactory| {
            let endpoint = endpoint.clone();
            let failure = failure.clone();
            let size = size.clone();
            async move {
                let request = factory.build().await?;
                let body = request
                    .body()
                    .and_then(|body| body.as_bytes())
                    .ok_or_else(|| OpenAIError::InvalidArgument("expected JSON body".into()))?;
                let body: Value = serde_json::from_slice(body)
                    .map_err(|_| OpenAIError::InvalidArgument("expected JSON body".into()))?;
                let authorization = request
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| OpenAIError::InvalidArgument("missing authorization".into()))?;
                let url = reqwest::Url::parse(&endpoint)
                    .map_err(|_| OpenAIError::InvalidArgument("invalid endpoint".into()))?;
                match client::request_bounded_with_timeout(
                    &endpoint,
                    &[url.host_str().unwrap_or("").into()],
                    Some(&body),
                    Some(("Authorization", authorization)),
                    MAX_AI_RESPONSE_BYTES,
                    Duration::from_secs(timeout),
                )
                .await
                {
                    Ok(bytes) => {
                        *size.lock().map_err(|_| {
                            OpenAIError::InvalidArgument("transport state".into())
                        })? = bytes.len();
                        let response = http::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(bytes)
                            .map_err(|_| OpenAIError::InvalidArgument("response headers".into()))?;
                        Ok(response.into())
                    }
                    Err(error) => {
                        *failure.lock().map_err(|_| {
                            OpenAIError::InvalidArgument("transport state".into())
                        })? = Some(worker::ai_request_error(error));
                        Err(OpenAIError::InvalidArgument(
                            "bounded transport failed".into(),
                        ))
                    }
                }
            }
        })
    };
    // A custom service replaces the SDK's retry service. One queue attempt makes
    // exactly one paid request; never silently replay a costly reasoning call.
    let sdk = Client::with_config(OpenAIConfig::new().with_api_base(base).with_api_key(key))
        .with_http_service(service);
    let result = dispatch(&sdk, request, &settings.ai_protocol).await;
    if let Some(error) = transport_error
        .lock()
        .map_err(|_| Error::unavailable())?
        .take()
    {
        return Err(error.context(input));
    }
    input["response_bytes"] = json!(*response_size.lock().map_err(|_| Error::unavailable())?);
    let value = result.map_err(|error| {
        let mut classified = Error::bad("intel_ai_invalid_response").context(input.clone());
        if let OpenAIError::JSONDeserialize(error, _) = error {
            classified = classified.context(parse::json_error_diagnostic(&error));
        }
        classified.context(json!({"response_bytes":response_size.lock().map(|v|*v).unwrap_or(0),"reason":"sdk_response_decode"})).stage("ai_response")
    })?;
    let bytes = serde_json::to_vec(&value).map_err(|_| Error::bad("intel_ai_invalid_response"))?;
    Ok((bytes, input))
}

async fn dispatch(
    sdk: &Client<OpenAIConfig>,
    request: Value,
    protocol: &str,
) -> std::result::Result<Value, OpenAIError> {
    if protocol == "responses" {
        sdk.responses().create_byot(request).await
    } else {
        sdk.chat().create_byot(request).await
    }
}

fn usage(value: &Value, protocol: &str) -> Value {
    let mut out = json!({});
    let paths = if protocol == "responses" {
        [
            ("input_tokens", "/usage/input_tokens"),
            ("output_tokens", "/usage/output_tokens"),
            (
                "reasoning_tokens",
                "/usage/output_tokens_details/reasoning_tokens",
            ),
            (
                "cached_input_tokens",
                "/usage/input_tokens_details/cached_tokens",
            ),
            ("total_tokens", "/usage/total_tokens"),
        ]
    } else {
        [
            ("input_tokens", "/usage/prompt_tokens"),
            ("output_tokens", "/usage/completion_tokens"),
            (
                "reasoning_tokens",
                "/usage/completion_tokens_details/reasoning_tokens",
            ),
            (
                "cached_input_tokens",
                "/usage/prompt_tokens_details/cached_tokens",
            ),
            ("total_tokens", "/usage/total_tokens"),
        ]
    };
    for (key, path) in paths {
        if let Some(n) = value.pointer(path).and_then(Value::as_u64) {
            out[key] = json!(n);
        }
    }
    out
}

pub(super) fn response_content(data: &[u8], protocol: &str) -> Result<(String, Value)> {
    let value: Value =
        serde_json::from_slice(data).map_err(|_| Error::bad("intel_ai_invalid_response"))?;
    let stats = usage(&value, protocol);
    if protocol == "chat" {
        return worker::ai_response_content(data)
            .map(|(content, mut diagnostic)| {
                diagnostic
                    .as_object_mut()
                    .unwrap()
                    .extend(stats.as_object().unwrap().clone());
                (content, diagnostic)
            })
            .map_err(|error| error.context(stats));
    }
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("missing");
    let mut diagnostic = stats;
    diagnostic["response_bytes"] = json!(data.len());
    diagnostic["reasoning_content_present"] = json!(
        value["output"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item["type"] == "reasoning"))
    );
    if status == "incomplete" {
        let limit = value
            .pointer("/incomplete_details/reason")
            .and_then(Value::as_str)
            == Some("max_output_tokens");
        return Err(Error::bad(if limit {
            "intel_ai_output_truncated"
        } else {
            "intel_ai_invalid_response"
        })
        .context(diagnostic)
        .context(json!({"reason":if limit {"output_limit"} else {"incomplete_response"}})));
    }
    if status != "completed" {
        return Err(Error::bad("intel_ai_invalid_response")
            .context(diagnostic)
            .context(json!({"reason":"response_not_completed"})));
    }
    let items = value["output"]
        .as_array()
        .ok_or_else(|| Error::bad("intel_ai_invalid_response").context(diagnostic.clone()))?;
    let mut content = String::new();
    for item in items {
        match item["type"].as_str() {
            Some("reasoning") => {}
            Some("message") if item["role"] == "assistant" && item["status"] == "completed" => {
                for part in item["content"]
                    .as_array()
                    .ok_or_else(|| Error::bad("intel_ai_invalid_response"))?
                {
                    if part["type"] == "refusal" {
                        return Err(Error::bad("intel_ai_refused").context(diagnostic));
                    }
                    if part["type"] != "output_text" {
                        return Err(Error::bad("intel_ai_invalid_response").context(diagnostic));
                    }
                    content.push_str(
                        part["text"]
                            .as_str()
                            .ok_or_else(|| Error::bad("intel_ai_invalid_response"))?,
                    );
                }
            }
            _ => {
                return Err(Error::bad("intel_ai_invalid_response")
                    .context(diagnostic)
                    .context(json!({"reason":"unexpected_response_item"})));
            }
        }
    }
    diagnostic["content_bytes"] = json!(content.len());
    diagnostic["content_format"] = json!(parse::ai_content_format(&content));
    if content.trim().is_empty() {
        return Err(Error::bad("intel_ai_empty_content").context(diagnostic));
    }
    Ok((content, diagnostic))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn settings(protocol: &str) -> Settings {
        serde_json::from_value(json!({"ai_enabled":true,"ai_endpoint":format!("https://api.example/v1/{}",if protocol=="responses" {"responses"}else{"chat/completions"}),"ai_model":"deepseek/test","ai_key_env":"NM_INTEL_TEST_KEY","ai_protocol":protocol})).unwrap()
    }
    #[test]
    fn both_protocols_preserve_the_full_model_output_budget() {
        for protocol in ["chat", "responses"] {
            let mut settings = settings(protocol);
            assert_eq!(settings.ai_max_output_tokens, 65_536);
            settings.ai_max_output_tokens = 393_216;
            settings.ai_reasoning_effort = "max".into();
            assert!(settings.validate().is_ok());
            let request = payload(&settings, &json!([]), "https://report.example");
            assert_eq!(
                request[if protocol == "chat" {
                    "max_tokens"
                } else {
                    "max_output_tokens"
                }],
                393_216
            );
        }
    }
    #[test]
    fn json_mode_explicitly_requests_json_without_relying_on_article_text() {
        for protocol in ["chat", "responses"] {
            let request = payload(
                &settings(protocol),
                &json!([{"block_id":1,"text":"恶意 DNS: 192[.]0[.]2[.]1"}]),
                "https://report.example",
            );
            let messages = if protocol == "chat" {
                &request["messages"]
            } else {
                &request["input"]
            };
            let system = messages[0]["content"].as_str().unwrap();
            let article = messages[1]["content"].as_str().unwrap();
            assert!(!article.to_ascii_lowercase().contains("json"));
            assert!(
                system.to_ascii_lowercase().contains("json"),
                "JSON mode requires an explicit JSON instruction in trusted messages"
            );
        }
    }
    #[tokio::test]
    async fn sdk_dispatch_preserves_both_protocols_extensions_and_makes_one_call() {
        for protocol in ["chat", "responses"] {
            let settings = settings(protocol);
            let request = payload(
                &settings,
                &json!([{"block_id":1,"text":"恶意 DNS: 192[.]0[.]2[.]1"}]),
                "https://report.example",
            );
            assert!(request.get("actor_candidates").is_none());
            let field = if protocol == "chat" {
                "messages"
            } else {
                "input"
            };
            assert_eq!(request[field].as_array().unwrap().len(), 2);
            assert!(
                !request[field][1]["content"]
                    .as_str()
                    .unwrap()
                    .contains("actor_candidates")
            );
            let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let calls = count.clone();
            let expected = request.clone();
            let route = protocol.to_owned();
            let service = tower::service_fn(move |factory: HttpRequestFactory| {
                let calls = calls.clone();
                let expected = expected.clone();
                let route = route.clone();
                async move {
                    let req = factory.build().await?;
                    assert_eq!(req.headers().get("authorization").unwrap(), "Bearer test");
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    assert_eq!(
                        serde_json::from_slice::<Value>(req.body().unwrap().as_bytes().unwrap())
                            .unwrap(),
                        expected
                    );
                    assert_eq!(
                        req.url().path(),
                        if route == "chat" {
                            "/v1/chat/completions"
                        } else {
                            "/v1/responses"
                        }
                    );
                    let value = json!({"usage":{"prompt_tokens":10589,"completion_tokens":8000,"completion_tokens_details":{"reasoning_tokens":8000}},"choices":[{"finish_reason":"length","message":{"content":null,"reasoning_content":"private reasoning"}}]});
                    Ok::<_, OpenAIError>(
                        http::Response::builder()
                            .status(200)
                            .body(value.to_string())
                            .unwrap()
                            .into(),
                    )
                }
            });
            let sdk = Client::with_config(
                OpenAIConfig::new()
                    .with_api_base("https://unused.invalid/v1")
                    .with_api_key("test"),
            )
            .with_http_service(service);
            let value = dispatch(&sdk, request, protocol).await.unwrap();
            assert_eq!(value["usage"]["completion_tokens"], 8000);
            assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
    }
    #[test]
    fn response_usage_survives_truncation_without_retaining_reasoning_or_content() {
        let value = json!({"usage":{"prompt_tokens":10589,"completion_tokens":8000,"completion_tokens_details":{"reasoning_tokens":8000}},"choices":[{"finish_reason":"length","message":{"content":null,"reasoning_content":"private reasoning"}}]});
        let error = response_content(value.to_string().as_bytes(), "chat").unwrap_err();
        assert_eq!(error.code, "intel_ai_output_truncated");
        assert_eq!(error.diagnostic["input_tokens"], 10589);
        assert_eq!(error.diagnostic["reasoning_tokens"], 8000);
        assert!(!error.diagnostic.to_string().contains("private reasoning"));
        let value = json!({"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"usage":{"input_tokens":100,"output_tokens":8000,"output_tokens_details":{"reasoning_tokens":7990}},"output":[]});
        let error = response_content(value.to_string().as_bytes(), "responses").unwrap_err();
        assert_eq!(error.code, "intel_ai_output_truncated");
        assert_eq!(error.diagnostic["reasoning_tokens"], 7990);
    }
    #[test]
    fn responses_accepts_only_completed_text_and_settings_control_reasoning_and_budget() {
        let value = json!({"status":"completed","usage":{"input_tokens":100,"output_tokens":20},"output":[{"type":"reasoning"},{"type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"{\"iocs\":[]}"}]}]});
        let (content, stats) = response_content(value.to_string().as_bytes(), "responses").unwrap();
        assert_eq!(content, "{\"iocs\":[]}");
        assert_eq!(stats["output_tokens"], 20);
        let mut settings = settings("responses");
        settings.ai_max_output_tokens = 16000;
        let request = payload(&settings, &json!([]), "https://report.example");
        assert_eq!(request["max_output_tokens"], 16000);
        assert_eq!(request["reasoning"]["effort"], "none");
        assert_eq!(request["store"], false);
        settings.ai_reasoning_effort = "default".into();
        assert!(
            payload(&settings, &json!([]), "https://report.example")
                .get("reasoning")
                .is_none()
        );
        settings.ai_max_output_tokens = MAX_AI_OUTPUT_TOKENS;
        settings.ai_reasoning_effort = "max".into();
        assert!(settings.validate().is_ok());
        settings.ai_max_output_tokens = MAX_AI_OUTPUT_TOKENS + 1;
        assert!(settings.validate().is_err());
    }
    #[test]
    fn sdk_bases_and_explicit_endpoints_are_resolved_once_without_guessing_provider_prefixes() {
        for protocol in ["chat", "responses"] {
            let mut settings = settings(protocol);
            let route = if protocol == "chat" {
                "chat/completions"
            } else {
                "responses"
            };
            settings.ai_endpoint = "https://api.commandcode.ai/provider/v1/".into();
            let (full, kind, base) = endpoint(&settings).unwrap();
            assert_eq!(
                full,
                format!("https://api.commandcode.ai/provider/v1/{route}")
            );
            assert_eq!(kind, "base_url");
            assert_eq!(base, "https://api.commandcode.ai/provider/v1");
            settings.ai_endpoint = full.clone();
            assert_eq!(endpoint(&settings).unwrap().0, full);
            settings.ai_endpoint = format!("https://api.commandcode.ai/v1/{route}");
            assert_eq!(endpoint(&settings).unwrap().0, settings.ai_endpoint);
        }
        let mut settings = settings("responses");
        settings.ai_endpoint = "https://api.example/v1/chat/completions".into();
        assert_eq!(
            endpoint(&settings).unwrap_err().code,
            "intel_ai_protocol_mismatch"
        );
    }
}
