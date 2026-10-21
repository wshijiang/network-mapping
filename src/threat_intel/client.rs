use super::*;
use std::{path::PathBuf, time::Duration};

#[derive(Debug)]
struct ResolveError(&'static str);
impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ResolveError {}

// Resolve only when the connector needs it. HTTP CONNECT and socks5h proxies
// resolve the destination remotely; their own host may be on a private network.
struct DestinationResolver {
    host: String,
}
impl reqwest::dns::Resolve for DestinationResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let destination = name.as_str().eq_ignore_ascii_case(&self.host);
        Box::pin(async move {
            let code = if destination {
                "intel_dns_failed"
            } else {
                "intel_proxy_dns_failed"
            };
            let addresses = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((name.as_str(), 0)),
            )
            .await
            .map_err(|_| ResolveError(code))?
            .map_err(|_| ResolveError(code))?
            .collect::<Vec<_>>();
            if addresses.is_empty() {
                return Err(ResolveError(code).into());
            }
            if destination && addresses.iter().any(|v| !public_ip(v.ip())) {
                return Err(ResolveError("intel_private_address_forbidden").into());
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}
pub(super) fn http_builder(host: &str) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(std::sync::Arc::new(DestinationResolver {
            host: host.to_owned(),
        }))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .user_agent("NetworkMapping/1.0 threat-intelligence")
}
pub(super) fn transport_error(error: reqwest::Error) -> Error {
    use std::error::Error as _;
    let mut code = if error.is_timeout() {
        "intel_source_timeout"
    } else {
        "intel_source_transport"
    };
    let mut diagnostic = json!({
        "timeout":error.is_timeout(), "connect":error.is_connect(),
        "body_error":error.is_body(), "decode_error":error.is_decode(),
    });
    let mut current = error.source();
    while let Some(cause) = current {
        // Inspect locally, emit only fixed classifications: source strings can contain secrets.
        let message = cause.to_string().to_ascii_lowercase();
        if message.contains("certificate") {
            diagnostic["cause_hint"] = json!("tls_certificate");
        } else if message.contains("tls") && diagnostic.get("cause_hint").is_none() {
            diagnostic["cause_hint"] = json!("tls_handshake");
        } else if (message.contains("tunnel") || message.contains("proxy"))
            && diagnostic.get("cause_hint").is_none()
        {
            diagnostic["cause_hint"] = json!("proxy_tunnel");
        }
        if let Some(resolver) = cause.downcast_ref::<ResolveError>() {
            code = resolver.0;
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            diagnostic["io_kind"] = json!(format!("{:?}", io.kind()));
            diagnostic["os_error"] = json!(io.raw_os_error());
        }
        current = cause.source();
    }
    Error::bad(code).context(diagnostic)
}

pub(super) async fn local_bytes(location: &str) -> Result<Vec<u8>> {
    let mut file = local_file(location).await?;
    let mut data = Vec::new();
    use tokio::io::AsyncReadExt;
    (&mut file)
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut data)
        .await
        .map_err(|_| Error::bad("intel_local_read_failed"))?;
    if data.len() > MAX_BYTES {
        return Err(Error::bad("intel_source_too_large"));
    }
    Ok(data)
}
pub(super) async fn local_file(location: &str) -> Result<tokio::fs::File> {
    let root = PathBuf::from(
        std::env::var_os("NM_INTEL_LOCAL_ROOT")
            .unwrap_or_else(|| "/var/lib/network-mapping/intel".into()),
    );
    let root = tokio::fs::canonicalize(root)
        .await
        .map_err(|_| Error::bad("intel_local_root_unavailable"))?;
    let path = tokio::fs::canonicalize(root.join(location))
        .await
        .map_err(|_| Error::bad("intel_local_file_unavailable"))?;
    if !path.starts_with(&root) {
        return Err(Error::bad("intel_local_path_escape"));
    }
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| Error::bad("intel_local_file_unavailable"))?;
    if !file
        .metadata()
        .await
        .map_err(|_| Error::bad("intel_local_file_unavailable"))?
        .is_file()
    {
        return Err(Error::bad("intel_local_regular_file_required"));
    }
    Ok(file)
}
pub(super) fn secret(name: &str) -> Result<Option<String>> {
    if !valid_key_ref(name) {
        return Err(Error::bad("intel_invalid_key_reference"));
    }
    if name.is_empty() {
        return Ok(None);
    }
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .map(Some)
        .ok_or_else(|| Error::bad("intel_credential_missing"))
}
#[cfg(test)]
pub(super) async fn request_bounded(
    location: &str,
    hosts: &[String],
    post: Option<&Value>,
    auth: Option<(&str, &str)>,
    limit: usize,
) -> Result<Vec<u8>> {
    configured_request(
        &source_transport::RequestConfig::default(),
        location,
        hosts,
        post,
        auth,
        limit,
        Duration::from_secs(30),
    )
    .await
}
pub(super) async fn source_request(
    source: &storage::Source,
    location: &str,
    post: Option<&Value>,
    auth: Option<(&str, &str)>,
    limit: usize,
    timeout: Duration,
    encryption_key: &str,
) -> Result<Vec<u8>> {
    let mut config = source_transport::RequestConfig::decrypt(
        source.request_config_ciphertext.as_deref(),
        encryption_key,
    )?;
    config.validate()?;
    configured_request(
        &config,
        location,
        &source.input.allowed_hosts,
        post,
        auth,
        limit,
        timeout,
    )
    .await
}
async fn configured_request(
    config: &source_transport::RequestConfig,
    location: &str,
    hosts: &[String],
    post: Option<&Value>,
    auth: Option<(&str, &str)>,
    limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let started = std::time::Instant::now();
    let url = validate_url(location, hosts)?;
    let host = url.host_str().unwrap();
    let proxy_env_keys = [
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ]
    .into_iter()
    .filter(|key| std::env::var_os(key).is_some_and(|v| !v.is_empty()))
    .collect::<Vec<_>>()
    .join(", ");
    let context = json!({"host":host,"port":url.port_or_known_default(),
        "method":if post.is_some() {"POST"} else {"GET"},"limit_bytes":limit,
        "proxy_env_keys":proxy_env_keys,"timeout_seconds":timeout.as_secs()});
    let result = async {
        // Keep native TLS roots and the selected source proxy mode. Direct
        // destinations are validated by the resolver before returning pinned IPs.
        // Proxies must enforce the same public-egress boundary on their remote DNS.
        let mut current = url.clone();
        let mut forward_headers = true;
        let mut redirects = 0;
        let mut response = loop {
            let destination = current.host_str().ok_or_else(|| Error::bad("intel_invalid_url"))?;
            let client = config.builder(destination)?
                .build()
                .map_err(|e| transport_error(e).context(json!({"phase":"client_build"})))?;
            let mut request = if let Some(body) = post {
                client.post(current.clone()).json(body)
            } else {
                client.get(current.clone())
            };
            if forward_headers {
                request = request.headers(config.request_headers(auth)?);
            }
            let remaining = timeout.checked_sub(started.elapsed())
                .filter(|value| !value.is_zero())
                .ok_or_else(|| Error::bad("intel_source_timeout"))?;
            // Persist only fixed classifications, never URLs or header values.
            let response = request.timeout(remaining).send().await.map_err(|e| {
                transport_error(e).context(json!({"phase":"send"}))
            })?;
            if post.is_some() || !matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                break response;
            }
            if redirects >= 5 {
                return Err(Error::bad("intel_source_redirect_limit"));
            }
            let location = response.headers().get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| Error::bad("intel_url_not_allowed"))?;
            let next = current.join(location).map_err(|_| Error::bad("intel_url_not_allowed"))?;
            let next = validate_url(next.as_str(), hosts)?;
            // Unknown custom headers can contain secrets too. Once the origin
            // changes, never forward source headers or credentials again.
            forward_headers &= current.origin() == next.origin();
            current = next;
            redirects += 1;
        };
        let status = response.status().as_u16();
        if !response.status().is_success() {
            let code=if status==429 {"intel_source_rate_limited"}else{"intel_source_http_status"};
            let error=Error::bad(code).context(json!({"phase":"response_status","http_status":status}));
            // Only JSON POST errors are inspected; never persist upstream prose.
            let details=if post.is_some() {response_error_diagnostic(&mut response).await}else{json!({})};
            return Err(error.context(details));
        }
        if response
            .content_length()
            .is_some_and(|len| len > limit as u64)
        {
            return Err(Error::bad("intel_source_too_large").context(json!({
                "phase":"response_headers","http_status":status,"content_length":response.content_length()
            })));
        }
        let mut bytes = vec![];
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| transport_error(e).context(json!({
                "phase":"response_body","http_status":status,"received_bytes":bytes.len()
            })))?
        {
            if bytes.len() + chunk.len() > limit {
                return Err(Error::bad("intel_source_too_large").context(json!({
                    "phase":"response_body","http_status":status,"received_bytes":bytes.len() + chunk.len()
                })));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }.await;
    result.map_err(|e: Error| {
        let error = e
            .context(context)
            .context(json!({"elapsed_ms":started.elapsed().as_millis() as u64}));
        tracing::warn!(event="IntelHttpRequestFailed",code=error.code,diagnostic=%error.diagnostic);
        error
    })
}
pub(super) async fn response_error_diagnostic(response: &mut reqwest::Response) -> Value {
    let mut bytes = Vec::new();
    let mut complete = false;
    let mut read_failed = false;
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if bytes.len() + chunk.len() > 32768 {
                        break;
                    }
                    bytes.extend_from_slice(&chunk);
                }
                Ok(None) => {
                    complete = true;
                    break;
                }
                Err(_) => {
                    read_failed = true;
                    break;
                }
            }
        }
    })
    .await;
    let mut details = provider_error_diagnostic(&bytes);
    details["error_body_sample_bytes"] = json!(bytes.len());
    details["error_body_complete"] = json!(complete);
    details["error_body_read_failed"] = json!(read_failed || result.is_err());
    details
}

fn provider_error_diagnostic(bytes: &[u8]) -> Value {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return json!({"provider_error_category":"unclassified"});
    };
    let mut details = json!({"provider_error_category":"unclassified"});
    for (field, path, allowed) in [
        (
            "provider_error_code",
            "/error/code",
            &[
                "unsupported_model",
                "model_not_found",
                "not_found",
                "invalid_api_key",
                "insufficient_quota",
                "upgrade_required",
                "cmd_zdr_no_providers",
                "unsupported_parameter",
            ] as &[&str],
        ),
        (
            "provider_error_type",
            "/error/type",
            &[
                "invalid_request_error",
                "authentication_error",
                "permission_error",
                "rate_limit_error",
                "server_error",
                "api_error",
                "not_found_error",
            ] as &[&str],
        ),
    ] {
        if let Some(code) = value
            .pointer(path)
            .and_then(Value::as_str)
            .filter(|code| allowed.contains(code))
        {
            details[field] = json!(code);
        }
    }
    let code = value
        .pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or("");
    let message = value
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let category = if matches!(code, "unsupported_model" | "model_not_found") {
        "model_unavailable"
    } else if matches!(code, "invalid_api_key") {
        "authentication"
    } else if code == "insufficient_quota" {
        "quota"
    } else if code == "upgrade_required" {
        "permission"
    } else if code == "unsupported_parameter" {
        "unsupported_parameter"
    } else if (message.contains("model")
        && (message.contains("not found")
            || message.contains("does not exist")
            || message.contains("not available")))
        || message.contains("no endpoints found")
    {
        "model_unavailable"
    } else if (message.contains("route") || message.contains("endpoint"))
        && message.contains("not found")
    {
        "endpoint_not_found"
    } else if message.contains("json_object")
        && message.contains("must contain")
        && (message.contains("word 'json'") || message.contains("word \"json\""))
        && (message.contains("prompt") || message.contains("messages"))
    {
        "json_mode_prompt_missing"
    } else if message.contains("unsupported")
        && (message.contains("reasoning") || message.contains("parameter"))
    {
        "unsupported_parameter"
    } else {
        "unclassified"
    };
    details["provider_error_category"] = json!(category);
    for path in ["/trace_id", "/request_id", "/error/trace_id"] {
        if let Some(id) = value
            .pointer(path)
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
        {
            details["provider_trace_id"] = json!(id);
            break;
        }
    }
    details
}

pub(super) async fn source_bytes(
    source: &storage::Source,
    encryption_key: &str,
) -> Result<Vec<u8>> {
    if source.input.transport == "upload" || source.input.kind == "threatfox_export" {
        return Err(Error::bad("intel_offline_export_required"));
    }
    if source.input.transport == "local" {
        return local_bytes(&source.input.location).await;
    }
    let key = credentials::resolve(
        source.credential_ciphertext.as_deref(),
        &source.input.auth_env,
        encryption_key,
    )?;
    let post = (source.input.kind == "threatfox").then(|| json!({"query":"get_iocs","days":7}));
    let auth = key.as_deref().map(|k| {
        (
            if source.input.kind == "threatfox" {
                "Auth-Key"
            } else {
                "Authorization"
            },
            k,
        )
    });
    source_request(
        source,
        &source.input.location,
        post.as_ref(),
        auth,
        MAX_BYTES,
        // A seven-day ThreatFox response can take longer than the small-article
        // budget to download. Keep it within the 150-second source job deadline.
        Duration::from_secs(if source.input.kind == "threatfox" {
            120
        } else {
            30
        }),
        encryption_key,
    )
    .await
}

#[cfg(test)]
mod provider_error_tests {
    use super::*;
    #[test]
    fn classifies_json_mode_prompt_errors_without_retaining_upstream_text() {
        for message in [
            "Prompt must contain the word 'json' in some form to use 'response_format' of type 'json_object'.",
            "'messages' must contain the word 'json' in some form, to use 'response_format' of type 'json_object'.",
            "Messages must contain the word \"JSON\" to use response_format of type JSON_OBJECT.",
        ] {
            let raw = json!({"error":{"code":"invalid_request_error","type":"invalid_request_error","param":"messages","message":format!("{message} Bearer private-key https://private.example")}});
            let diagnostic = provider_error_diagnostic(raw.to_string().as_bytes());
            assert_eq!(
                diagnostic,
                json!({"provider_error_category":"json_mode_prompt_missing","provider_error_type":"invalid_request_error"})
            );
        }
        for message in [
            "response_format json_object is unsupported for this model",
            "Invalid JSON in messages",
            "Messages must contain an object matching the json_object schema",
        ] {
            let raw = json!({"error":{"type":"invalid_request_error","message":message}});
            assert_eq!(
                provider_error_diagnostic(raw.to_string().as_bytes())["provider_error_category"],
                "unclassified"
            );
        }
    }
    #[test]
    fn classifies_http_error_bodies_without_copying_upstream_text_or_unknown_codes() {
        let raw = json!({"error":{"code":"model_not_found","type":"invalid_request_error","message":"Private model and secret URL"}});
        let diagnostic = provider_error_diagnostic(raw.to_string().as_bytes());
        assert_eq!(diagnostic["provider_error_category"], "model_unavailable");
        assert_eq!(diagnostic["provider_error_code"], "model_not_found");
        assert!(!diagnostic.to_string().contains("Private"));
        let raw = json!({"error":{"code":"Bearer private-key","type":"private-type","message":"Route not found at private URL"},"trace_id":"private-key"});
        let diagnostic = provider_error_diagnostic(raw.to_string().as_bytes());
        assert_eq!(diagnostic["provider_error_category"], "endpoint_not_found");
        assert!(diagnostic.get("provider_error_code").is_none());
        assert!(diagnostic.get("provider_trace_id").is_none());
        assert!(!diagnostic.to_string().contains("private"));
        assert_eq!(
            provider_error_diagnostic(b"<html>secret</html>")["provider_error_category"],
            "unclassified"
        );
    }
}
