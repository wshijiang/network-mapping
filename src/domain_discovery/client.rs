use super::*;
use crate::outbound_proxy::{ProxyConfig, ProxyError, ProxyMode};
use reqwest::Client;
use std::time::Duration;
use tokio::time::{Instant, timeout_at};
const MAX_RESPONSE: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SourceError {
    pub code: &'static str,
    pub retryable: bool,
}

impl SourceError {
    const fn permanent(code: &'static str) -> Self {
        Self {
            code,
            retryable: false,
        }
    }
    const fn transient(code: &'static str) -> Self {
        Self {
            code,
            retryable: true,
        }
    }
}

impl From<ProxyError> for SourceError {
    fn from(error: ProxyError) -> Self {
        Self {
            code: error.code,
            retryable: error.retryable,
        }
    }
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}

/// Keep the source-specific timeout and user agent while sharing the
/// system/direct/custom proxy semantics of the rest of the server.
pub(super) fn http_client(proxy: &ProxyConfig) -> std::result::Result<Client, SourceError> {
    proxy
        .apply_to(
            Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(20))
                .user_agent("NetworkMapping/1.0 certificate-discovery"),
        )
        .map_err(SourceError::from)?
        .build()
        .map_err(|_| SourceError::permanent("proxy_invalid"))
}

/// reqwest does not expose typed proxy failures. Inspect the local cause chain
/// for stable classifications only; raw messages never leave this function.
fn classify_transport(error: &reqwest::Error, proxy_mode: ProxyMode) -> SourceError {
    use std::error::Error as _;

    if error.is_timeout() {
        return SourceError::transient("source_timeout");
    }
    let mut messages = Vec::new();
    let mut current = error.source();
    while let Some(cause) = current {
        messages.push(cause.to_string().to_ascii_lowercase());
        current = cause.source();
    }
    let chain = messages.join(" | ");
    let custom = proxy_mode == ProxyMode::Custom;
    if chain.contains("proxy authorization required")
        || (custom && chain.contains("authentication"))
    {
        return SourceError::permanent("proxy_authentication_failed");
    }
    if chain.contains("certificate") {
        if custom && (chain.contains("tunnel") || chain.contains("proxy")) {
            return SourceError::permanent("proxy_tls_error");
        }
        return SourceError::permanent("source_tls_error");
    }
    if custom {
        if chain.contains("dns") || chain.contains("resolve") || chain.contains("lookup") {
            return SourceError::transient("proxy_dns_failed");
        }
        if chain.contains("tunnel error") {
            return if chain.contains("unsuccessful") {
                SourceError::transient("proxy_connect_rejected")
            } else {
                SourceError::transient("proxy_connection_failed")
            };
        }
        return SourceError::transient("proxy_connection_failed");
    }
    SourceError::transient("source_transport")
}

async fn bytes(
    client: &Client,
    params: &[(&str, String)],
    max: usize,
    endpoint: &str,
    proxy_mode: ProxyMode,
) -> std::result::Result<Vec<u8>, SourceError> {
    let mut response = client
        .get(endpoint)
        .query(params)
        .send()
        .await
        .map_err(|error| classify_transport(&error, proxy_mode))?;
    let status = response.status();
    if !status.is_success() {
        return Err(if status.as_u16() == 429 {
            SourceError::transient("source_rate_limited")
        } else {
            SourceError::transient("source_status")
        });
    }
    let mut data = vec![];
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| SourceError::transient("source_read"))?
    {
        if data.len() + chunk.len() > max {
            return Err(SourceError::permanent("source_too_large"));
        }
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}
pub(super) fn parse_rows(data: &[u8], out: &mut Evidence) -> std::result::Result<(), SourceError> {
    let rows: Vec<Value> =
        serde_json::from_slice(data).map_err(|_| SourceError::transient("source_invalid_json"))?;
    if rows.len() > 20_000 {
        out.truncated = true;
    }
    for row in rows.into_iter().take(20_000) {
        let Some(id) = row["id"].as_i64().filter(|id| *id > 0) else {
            continue;
        };
        // Search JSON only contains matching identities, never claim a complete SAN.
        let mut names = BTreeSet::new();
        for value in row["name_value"]
            .as_str()
            .unwrap_or_default()
            .lines()
            .take(MAX_NAMES + 1)
        {
            if let Some(name) = canonical_name(value)
                && within_seed(name.strip_prefix("*.").unwrap_or(&name), &out.seed)
            {
                names.insert(name);
            }
            if names.len() >= MAX_NAMES {
                out.truncated = true;
                break;
            }
        }
        if names.is_empty() {
            continue;
        }
        let used: usize = out
            .certificates
            .iter()
            .filter(|c| c.crtsh_id != id)
            .map(|c| c.names.len())
            .sum();
        let budget = MAX_EVIDENCE_NAMES.saturating_sub(used);
        if budget == 0 {
            out.truncated = true;
            continue;
        }
        if names.len() > budget {
            out.truncated = true;
            names = names.into_iter().take(budget).collect();
        }
        if let Some(existing) = out.certificates.iter_mut().find(|c| c.crtsh_id == id) {
            names.extend(existing.names.iter().cloned());
            if names.len() > MAX_NAMES.min(budget) {
                out.truncated = true;
            }
            existing.names = names.into_iter().take(MAX_NAMES.min(budget)).collect();
            continue;
        }
        if out.certificates.len() >= MAX_CERTIFICATES {
            out.truncated = true;
            continue;
        }
        out.certificates.push(Certificate {
            crtsh_id: id,
            fingerprint_sha256: None,
            names: names.into_iter().collect(),
            full_san: false,
            not_before: row["not_before"].as_str().map(str::to_owned),
            not_after: row["not_after"].as_str().map(str::to_owned),
        });
    }
    Ok(())
}
pub(super) fn enrich(cert: &mut Certificate, data: &[u8]) -> std::result::Result<(), &'static str> {
    use openssl::x509::X509;
    let parsed = X509::from_pem(data)
        .or_else(|_| X509::from_der(data))
        .map_err(|_| "certificate_invalid")?;
    let mut names = BTreeSet::new();
    if let Some(sans) = parsed.subject_alt_names() {
        for san in sans {
            if let Some(value) = san.dnsname()
                && let Some(name) = canonical_name(value)
            {
                names.insert(name);
            }
        }
    }
    if names.len() > MAX_NAMES {
        return Err("certificate_too_large");
    }
    let der = parsed.to_der().map_err(|_| "certificate_invalid")?;
    cert.fingerprint_sha256 = Some(
        openssl::sha::sha256(&der)
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect(),
    );
    cert.names = names.into_iter().collect();
    cert.full_san = true;
    Ok(())
}
pub(super) async fn collect(
    client: &Client,
    seed: &str,
    related: bool,
    proxy_mode: ProxyMode,
) -> std::result::Result<Evidence, SourceError> {
    collect_from(client, seed, related, "https://crt.sh/", proxy_mode).await
}
pub(super) async fn collect_from(
    client: &Client,
    seed: &str,
    related: bool,
    endpoint: &str,
    proxy_mode: ProxyMode,
) -> std::result::Result<Evidence, SourceError> {
    let mut out = Evidence::empty(seed);
    let deadline = Instant::now() + Duration::from_secs(100);
    let mut successful = 0;
    let mut failures = Vec::new();
    for query in [seed.to_owned(), format!("%.{seed}")] {
        let result = match timeout_at(
            deadline,
            bytes(
                client,
                &[("q", query), ("output", "json".into())],
                MAX_RESPONSE,
                endpoint,
                proxy_mode,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(SourceError::transient("source_timeout")),
        };
        match result.and_then(|response| parse_rows(&response, &mut out)) {
            Ok(()) => successful += 1,
            Err(error) => {
                out.source_errors.push(error.code.to_owned());
                failures.push(error);
            }
        }
    }
    if successful == 0 {
        if let Some(permanent) = failures.iter().find(|error| !error.retryable) {
            return Err(*permanent);
        }
        if let Some(first) = failures.first().copied()
            && failures.iter().all(|error| error.code == first.code)
        {
            return Err(first);
        }
        return Err(SourceError::transient("source_unavailable"));
    }
    if related {
        for index in 0..out.certificates.len() {
            let id = out.certificates[index].crtsh_id;
            let response = timeout_at(
                deadline,
                bytes(
                    client,
                    &[("d", id.to_string())],
                    1024 * 1024,
                    endpoint,
                    proxy_mode,
                ),
            )
            .await;
            if let Ok(Ok(data)) = response {
                let mut complete = out.certificates[index].clone();
                if enrich(&mut complete, &data).is_ok() {
                    let used: usize = out
                        .certificates
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != index)
                        .map(|(_, c)| c.names.len())
                        .sum();
                    if used + complete.names.len() <= MAX_EVIDENCE_NAMES {
                        out.certificates[index] = complete;
                    } else {
                        out.truncated = true;
                    }
                }
            }
            if Instant::now() >= deadline {
                break;
            }
        }
        out.incomplete_certificates = out.certificates.iter().filter(|c| !c.full_san).count();
    }
    out.rebuild(related);
    Ok(out)
}

/// Exercise the exact production client and source endpoint without storing
/// evidence. Used by the admin settings card to validate a proxy change.
pub(super) async fn probe(
    client: &Client,
    proxy_mode: ProxyMode,
) -> std::result::Result<(), SourceError> {
    let data = bytes(
        client,
        &[
            ("q", "proxy-test.invalid".into()),
            ("output", "json".into()),
        ],
        64 * 1024,
        "https://crt.sh/",
        proxy_mode,
    )
    .await?;
    if !data.is_empty() && serde_json::from_slice::<Value>(&data).is_err() {
        return Err(SourceError::transient("source_invalid_json"));
    }
    Ok(())
}
