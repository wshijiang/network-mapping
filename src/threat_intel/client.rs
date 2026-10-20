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
pub(super) async fn request(
    location: &str,
    hosts: &[String],
    post: Option<&Value>,
    auth: Option<(&str, &str)>,
) -> Result<Vec<u8>> {
    request_bounded(location, hosts, post, auth, MAX_BYTES).await
}
pub(super) async fn request_bounded(
    location: &str,
    hosts: &[String],
    post: Option<&Value>,
    auth: Option<(&str, &str)>,
    limit: usize,
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
        "proxy_env_keys":proxy_env_keys});
    let result = async {
        // Keep reqwest's proxy / NO_PROXY selection and native TLS roots. Direct
        // destinations are validated by the resolver before returning pinned IPs.
        // Proxies must enforce the same public-egress boundary on their remote DNS.
        let client = http_builder(host)
            .build()
            .map_err(|e| transport_error(e).context(json!({"phase":"client_build"})))?;
        let mut request = if let Some(body) = post {
            client.post(url.clone()).json(body)
        } else {
            client.get(url.clone())
        };
        if let Some((header, key)) = auth {
            request = request.header(header, key);
        }
        // Never include reqwest errors or URLs: an upstream export may put a key in its path.
        let mut response = request.send().await.map_err(|e| {
            transport_error(e).context(json!({"phase":"send"}))
        })?;
        let status = response.status().as_u16();
        if !response.status().is_success() {
            return Err(Error::bad(if response.status().as_u16() == 429 {
                "intel_source_rate_limited"
            } else {
                "intel_source_http_status"
            }).context(json!({"phase":"response_status","http_status":status})));
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
    request(
        &source.input.location,
        &source.input.allowed_hosts,
        post.as_ref(),
        auth,
    )
    .await
}
