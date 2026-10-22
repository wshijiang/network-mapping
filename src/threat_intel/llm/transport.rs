use super::*;
use async_openai::{
    Client, config::OpenAIConfig, error::OpenAIError, middleware::HttpRequestFactory,
};
use futures_util::StreamExt;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

fn builder(endpoint: &str, config: &Resolved) -> Result<reqwest::ClientBuilder> {
    let url = validate_endpoint(endpoint)?;
    let mut builder = client::http_builder(url.host_str().unwrap());
    match config.proxy_mode.as_str() {
        "direct" => builder = builder.no_proxy(),
        "custom" => {
            builder = builder
                .no_proxy()
                .proxy(reqwest::Proxy::all(&config.proxy_url).map_err(|_| invalid())?)
        }
        _ => {}
    }
    Ok(builder)
}
async fn check(response: &mut reqwest::Response) -> Result<()> {
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let details = client::response_error_diagnostic(response).await;
        return Err(Error::bad(if status == 429 {
            "intel_ai_rate_limited"
        } else {
            "intel_ai_http_status"
        })
        .context(json!({"http_status":status}))
        .context(details));
    }
    Ok(())
}
pub(super) async fn get(endpoint: &str, config: &Resolved, key: &str) -> Result<Vec<u8>> {
    let mut response = builder(endpoint, config)?
        .build()
        .map_err(client::transport_error)?
        .get(endpoint)
        .headers(config.request_headers(key, "")?)
        .send()
        .await
        .map_err(client::transport_error)?;
    check(&mut response).await?;
    let mut bytes = vec![];
    while let Some(chunk) = response.chunk().await.map_err(client::transport_error)? {
        if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
            return Err(Error::bad("llm_model_list_too_large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

// Inspect framing before SDK decoding: EOF is not Chat's [DONE]. Keep buffers bounded.
#[derive(Default)]
pub(super) struct WireGuard {
    pub bytes: usize,
    pending: Vec<u8>,
    pub done: bool,
}
impl WireGuard {
    pub fn push(&mut self, chunk: &[u8]) -> std::io::Result<()> {
        self.bytes += chunk.len();
        if self.bytes > MAX_AI_RESPONSE_BYTES {
            return Err(std::io::Error::other("llm_response_too_large"));
        }
        for b in chunk {
            if *b == b'\n' {
                let line = self.pending.strip_suffix(b"\r").unwrap_or(&self.pending);
                if line == b"data: [DONE]" || line == b"data:[DONE]" {
                    self.done = true;
                }
                self.pending.clear();
            } else {
                self.pending.push(*b);
                if self.pending.len() > 1024 * 1024 {
                    return Err(std::io::Error::other("llm_event_too_large"));
                }
            }
        }
        Ok(())
    }
}

pub(in crate::threat_intel) async fn execute(
    settings: &Settings,
    key: &str,
    config: &Resolved,
    mut payload: Value,
    session: &str,
    events: Option<tokio::sync::mpsc::Sender<Value>>,
) -> Result<Value> {
    let (endpoint, _, base) = ai::endpoint(settings)?;
    let headers = config.request_headers(key, session)?;
    if !headers.contains_key("authorization") {
        return Err(Error::bad("intel_credential_missing"));
    }
    let http = builder(&endpoint, config)?
        .timeout(Duration::from_secs(settings.ai_timeout_seconds))
        .build()
        .map_err(client::transport_error)?;
    let stream = config.stream;
    payload["stream"] = json!(stream);
    let chat = settings_protocol_is_chat(&payload);
    let failure = Arc::new(Mutex::new(None));
    let errors = failure.clone();
    let service = tower::service_fn(move |factory: HttpRequestFactory| {
        let endpoint = endpoint.clone();
        let headers = headers.clone();
        let http = http.clone();
        let errors = errors.clone();
        async move {
            let request = factory.build().await?;
            let body = request
                .body()
                .and_then(|b| b.as_bytes())
                .ok_or_else(|| OpenAIError::InvalidArgument("expected JSON".into()))?
                .to_vec();
            let result = async {
                let mut response = http
                    .post(endpoint)
                    .headers(headers)
                    .header("content-type", "application/json")
                    .body(body)
                    .send()
                    .await
                    .map_err(|error| worker::ai_request_error(client::transport_error(error)))?;
                check(&mut response).await?;
                if stream
                    && !response
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|v| v.starts_with("text/event-stream"))
                {
                    return Err(Error::bad("llm_invalid_stream"));
                }
                Ok(response)
            }
            .await;
            let response = match result {
                Ok(response) => response,
                Err(error) => {
                    *errors.lock().unwrap() = Some(error);
                    return Err(OpenAIError::InvalidArgument(
                        "bounded transport failed".into(),
                    ));
                }
            };
            bridge(response, stream, chat)
        }
    });
    let sdk = Client::with_config(OpenAIConfig::new().with_api_base(base).with_api_key(key))
        .with_http_service(service);
    let run = async {
        let value = if stream {
            collect(&sdk, payload.clone(), &settings.ai_protocol, events.clone()).await
        } else if settings.ai_protocol == "responses" {
            sdk.responses()
                .create_byot(payload.clone())
                .await
                .map_err(sdk_error)
        } else {
            sdk.chat()
                .create_byot(payload.clone())
                .await
                .map_err(sdk_error)
        };
        if let Some(error) = failure.lock().unwrap().take() {
            return Err(error);
        }
        value
    };
    tokio::time::timeout(Duration::from_secs(settings.ai_timeout_seconds), run)
        .await
        .map_err(|_| Error::bad("intel_ai_timeout"))?
}
pub(super) fn bridge(
    response: reqwest::Response,
    stream: bool,
    chat: bool,
) -> std::result::Result<reqwest_sdk::Response, OpenAIError> {
    let body = futures::stream::try_unfold(
        (response, WireGuard::default()),
        move |(mut response, mut guard)| async move {
            match response
                .chunk()
                .await
                .map_err(|_| std::io::Error::other("llm_stream_transport"))?
            {
                Some(bytes) => {
                    if stream {
                        guard.push(&bytes)?;
                    } else {
                        guard.bytes += bytes.len();
                        if guard.bytes > MAX_AI_RESPONSE_BYTES {
                            return Err(std::io::Error::other("llm_response_too_large"));
                        }
                    }
                    Ok(Some((bytes, (response, guard))))
                }
                None if stream && chat && !guard.done => {
                    Err(std::io::Error::other("llm_stream_incomplete"))
                }
                None => Ok(None),
            }
        },
    );
    Ok::<_, OpenAIError>(
        http::Response::builder()
            .status(200)
            .header(
                "content-type",
                if stream {
                    "text/event-stream"
                } else {
                    "application/json"
                },
            )
            .body(reqwest_sdk::Body::wrap_stream(body))
            .map_err(|_| OpenAIError::InvalidArgument("response framing".into()))?
            .into(),
    )
}

fn settings_protocol_is_chat(payload: &Value) -> bool {
    payload.get("messages").is_some()
}

fn sdk_error(error: OpenAIError) -> Error {
    let failure = Error::bad("intel_ai_invalid_response");
    if let OpenAIError::JSONDeserialize(error, _) = error {
        failure
            .context(parse::json_error_diagnostic(&error))
            .context(json!({"reason":"sdk_response_decode"}))
            .stage("ai_response")
    } else {
        failure
    }
}

async fn delta(
    events: &Option<tokio::sync::mpsc::Sender<Value>>,
    kind: &str,
    text: &str,
) -> Result<()> {
    if let Some(events) = events {
        events
            .send(json!({"type":kind,"text":text}))
            .await
            .map_err(|_| Error::bad("llm_cancelled"))?;
    }
    Ok(())
}
pub(super) async fn collect(
    sdk: &Client<OpenAIConfig>,
    payload: Value,
    protocol: &str,
    events: Option<tokio::sync::mpsc::Sender<Value>>,
) -> Result<Value> {
    let mut stream = if protocol == "responses" {
        sdk.responses()
            .create_stream_byot::<_, Value>(payload)
            .await
    } else {
        sdk.chat().create_stream_byot::<_, Value>(payload).await
    }
    .map_err(|_| Error::bad("llm_stream_failed"))?;
    let mut aggregate = Aggregate::new(protocol);
    aggregate.retain_reasoning = events.is_some();
    while let Some(event) = stream.next().await {
        let event = event.map_err(|_| Error::bad("llm_stream_failed"))?;
        let reasoning = events
            .as_ref()
            .and_then(|_| debug::reasoning_delta(&event, protocol))
            .map(str::to_owned);
        let text = aggregate.push(event)?;
        if let Some(reasoning) = reasoning {
            delta(&events, "reasoning", &reasoning).await?;
        }
        if let Some(text) = text {
            delta(&events, "delta", &text).await?;
        }
    }
    aggregate.finish()
}
pub(super) struct Aggregate {
    protocol: String,
    text: String,
    finish: Option<String>,
    usage: Value,
    response: Option<Value>,
    received: usize,
    refusal: bool,
    reasoning: bool,
    reasoning_text: String,
    retain_reasoning: bool,
}
impl Aggregate {
    pub fn new(protocol: &str) -> Self {
        Self {
            protocol: protocol.into(),
            text: String::new(),
            finish: None,
            usage: Value::Null,
            response: None,
            received: 0,
            refusal: false,
            reasoning: false,
            reasoning_text: String::new(),
            retain_reasoning: false,
        }
    }
    pub fn push(&mut self, event: Value) -> Result<Option<String>> {
        self.received += event.to_string().len();
        if self.received > MAX_AI_RESPONSE_BYTES {
            return Err(Error::bad("llm_response_too_large"));
        }
        if event.get("error").is_some() {
            return Err(Error::bad("llm_stream_failed"));
        }
        if let Some(text) = debug::reasoning_delta(&event, &self.protocol) {
            self.reasoning_text.push_str(text);
        }
        let text = if self.protocol == "responses" {
            match event.get("type").and_then(Value::as_str) {
                Some("response.output_text.delta") => event.get("delta").and_then(Value::as_str),
                Some("response.completed") => {
                    let response = event
                        .get("response")
                        .ok_or_else(|| Error::bad("llm_invalid_stream"))?;
                    if response["status"] != "completed" {
                        return Err(Error::bad("llm_stream_incomplete"));
                    }
                    self.response = Some(response.clone());
                    None
                }
                Some("response.incomplete") => return Err(Error::bad("intel_ai_output_truncated")),
                Some("response.failed" | "error") => return Err(Error::bad("llm_stream_failed")),
                _ => None,
            }
        } else {
            self.refusal |= event
                .pointer("/choices/0/delta/refusal")
                .and_then(Value::as_str)
                .is_some_and(|v| !v.is_empty());
            self.reasoning |= [
                "/choices/0/delta/reasoning_content",
                "/choices/0/delta/reasoning",
            ]
            .into_iter()
            .any(|path| {
                event
                    .pointer(path)
                    .and_then(Value::as_str)
                    .is_some_and(|v| !v.is_empty())
            });
            if let Some(usage) = event.get("usage").filter(|v| !v.is_null()) {
                self.usage = usage.clone();
            }
            if let Some(reason) = event
                .pointer("/choices/0/finish_reason")
                .and_then(Value::as_str)
            {
                self.finish = Some(reason.into());
            }
            event
                .pointer("/choices/0/delta/content")
                .and_then(Value::as_str)
        };
        if let Some(text) = text {
            if self.text.len() + text.len() > MAX_AI_RESPONSE_BYTES {
                return Err(Error::bad("llm_response_too_large"));
            }
            self.text.push_str(text);
            return Ok(Some(text.into()));
        }
        Ok(None)
    }
    pub fn finish(mut self) -> Result<Value> {
        if self.protocol == "responses" {
            let mut response = self
                .response
                .take()
                .ok_or_else(|| Error::bad("llm_stream_incomplete"))?;
            if debug::reasoning_text(&response, "responses").is_empty()
                && !self.reasoning_text.is_empty()
                && let Some(output) = response["output"].as_array_mut()
            {
                output.push(json!({"type":"reasoning","summary":[{"type":"summary_text","text":self.reasoning_text}]}));
            }
            Ok(response)
        } else {
            let reason = self
                .finish
                .ok_or_else(|| Error::bad("llm_stream_incomplete"))?;
            Ok(
                json!({"choices":[{"finish_reason":reason,"message":{"content":self.text,
                "refusal":if self.refusal {Some("present")}else{None},
                "reasoning_content":if self.reasoning {Some(if self.retain_reasoning {self.reasoning_text} else {"present".into()})}else{None}}}],"usage":self.usage}),
            )
        }
    }
}
