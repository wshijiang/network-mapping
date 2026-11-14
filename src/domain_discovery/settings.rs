use super::*;
use crate::outbound_proxy::{self, ProxyConfig, ProxyMode};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub(super) struct Settings {
    proxy_mode: ProxyMode,
    proxy_endpoint: String,
    proxy_ciphertext: Option<Vec<u8>>,
    revision: i64,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub(super) struct PublicSettings {
    proxy_mode: ProxyMode,
    proxy_endpoint: String,
    proxy_configured: bool,
    revision: i64,
    updated_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SettingsInput {
    pub expected_revision: i64,
    pub proxy_mode: ProxyMode,
    #[serde(default)]
    pub proxy_url: String,
    #[serde(default)]
    pub change_reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TestInput {
    pub proxy_mode: ProxyMode,
    #[serde(default)]
    pub proxy_url: String,
}

impl Settings {
    pub(super) fn public(&self) -> PublicSettings {
        PublicSettings {
            proxy_mode: self.proxy_mode,
            proxy_endpoint: self.proxy_endpoint.clone(),
            proxy_configured: self.proxy_ciphertext.is_some() || !self.proxy_endpoint.is_empty(),
            revision: self.revision,
            updated_at: self.updated_at,
        }
    }

    pub(super) fn proxy_config(&self, encryption_key: &str) -> Result<ProxyConfig> {
        if self.proxy_mode != ProxyMode::Custom {
            return Ok(ProxyConfig {
                mode: self.proxy_mode,
                url: String::new(),
            });
        }
        let url = match self.proxy_ciphertext.as_deref() {
            Some(ciphertext) => decrypt_secret(ciphertext, encryption_key)?,
            None => self.proxy_endpoint.clone(),
        };
        outbound_proxy::validate_url(&url).map_err(|_| Error::internal("proxy_invalid"))?;
        Ok(ProxyConfig {
            mode: ProxyMode::Custom,
            url,
        })
    }
}

pub(super) async fn load(pool: &Pool) -> Result<Settings> {
    let client = pool.get().await?;
    if let Some(row) = query(&client).await? {
        return settings_from_row(row);
    }
    client
        .execute(
            "INSERT INTO domain_discovery_settings (singleton) VALUES (TRUE) \
             ON CONFLICT (singleton) DO NOTHING",
            &[],
        )
        .await?;
    match query(&client).await? {
        Some(row) => settings_from_row(row),
        None => Ok(default_settings()),
    }
}

pub(super) async fn save(
    pool: &Pool,
    encryption_key: &str,
    input: SettingsInput,
    user: &UserBaseI,
    context: &AuditContext,
) -> Result<PublicSettings> {
    if input.expected_revision < 1
        || input.change_reason.len() > 500
        || input.change_reason.chars().any(char::is_control)
    {
        return Err(Error::bad("invalid_revision_or_change_reason"));
    }
    let current = load(pool).await?;
    let (proxy_endpoint, proxy_ciphertext) = match input.proxy_mode {
        ProxyMode::System | ProxyMode::Direct => {
            if !input.proxy_url.trim().is_empty() {
                return Err(Error::bad("proxy_url_not_allowed"));
            }
            // Keep the encrypted URL for a later switch back to custom, but do
            // not use it while the active mode is system/direct.
            (
                current.proxy_endpoint.clone(),
                current.proxy_ciphertext.clone(),
            )
        }
        ProxyMode::Custom => {
            let url = input.proxy_url.trim();
            if url.is_empty() {
                if current.proxy_ciphertext.is_none() && current.proxy_endpoint.is_empty() {
                    return Err(Error::bad("proxy_url_required"));
                }
                (
                    current.proxy_endpoint.clone(),
                    current.proxy_ciphertext.clone(),
                )
            } else {
                if input.proxy_url != url {
                    return Err(Error::bad("proxy_invalid"));
                }
                let endpoint =
                    outbound_proxy::endpoint(url).map_err(|_| Error::bad("proxy_invalid"))?;
                let ciphertext = encrypt_secret(url, encryption_key)?;
                (endpoint, Some(ciphertext))
            }
        }
    };
    if input.proxy_mode == ProxyMode::Custom && proxy_endpoint.is_empty() {
        return Err(Error::bad("proxy_url_required"));
    }
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let proxy_mode = input.proxy_mode.as_str();
    let row = tx
        .query_opt(
            "UPDATE domain_discovery_settings \
             SET proxy_mode=$1, proxy_endpoint=$2, proxy_ciphertext=$3, revision=revision+1, \
                 updated_at=NOW(), updated_by_user_id=$4 \
             WHERE singleton AND revision=$5 \
             RETURNING proxy_mode, proxy_endpoint, proxy_ciphertext, revision, updated_at",
            &[
                &proxy_mode,
                &proxy_endpoint,
                &proxy_ciphertext,
                &user.id,
                &input.expected_revision,
            ],
        )
        .await?;
    let Some(row) = row else {
        return Err(Error::conflict("settings_revision_conflict"));
    };
    let mut event = AuditEvent::user(
        "configuration",
        "domain.discovery_proxy_update",
        "success",
        user,
    )
    .resource("domain_discovery_settings", "singleton");
    event.metadata = json!({
        "proxy_mode": proxy_mode,
        "proxy_endpoint": proxy_endpoint,
        "revision": row.get::<_, i64>("revision"),
        "change_reason": input.change_reason,
    });
    crate::audit::write(&tx, context, &event).await?;
    tx.commit().await?;
    settings_from_row(row).map(|settings| settings.public())
}

/// Test the submitted transport without persisting it. A blank custom URL
/// reuses the saved encrypted URL so admins can verify before switching back.
pub(super) async fn test(pool: &Pool, encryption_key: &str, input: TestInput) -> Result<Value> {
    let (proxy_mode, url) = match input.proxy_mode {
        ProxyMode::System | ProxyMode::Direct => (input.proxy_mode, String::new()),
        ProxyMode::Custom => {
            let url = if input.proxy_url.trim().is_empty() {
                let saved = load(pool).await?;
                match saved.proxy_ciphertext.as_deref() {
                    Some(ciphertext) => decrypt_secret(ciphertext, encryption_key)?,
                    None if !saved.proxy_endpoint.is_empty() => saved.proxy_endpoint.clone(),
                    None => return Err(Error::bad("proxy_url_required")),
                }
            } else {
                input.proxy_url
            };
            (ProxyMode::Custom, url)
        }
    };
    if proxy_mode == ProxyMode::Custom {
        outbound_proxy::validate_url(&url).map_err(|_| Error::bad("proxy_invalid"))?;
    }
    let proxy = ProxyConfig {
        mode: proxy_mode,
        url,
    };
    let client = client::http_client(&proxy).map_err(|error| Error::bad(error.code))?;
    let started = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(10), client::probe(&client, proxy_mode))
        .await
        .map_err(|_| Error::bad("source_timeout"))
        .and_then(|result| result.map_err(|error| Error::bad(error.code)));
    let latency_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(()) => Ok(json!({"ok": true, "code": Value::Null, "latency_ms": latency_ms})),
        Err(error) => Ok(json!({
            "ok": false,
            "code": error.reason(),
            "latency_ms": latency_ms
        })),
    }
}

async fn query(client: &deadpool_postgres::Client) -> Result<Option<tokio_postgres::Row>> {
    Ok(client
        .query_opt(
            "SELECT proxy_mode, proxy_endpoint, proxy_ciphertext, revision, updated_at \
             FROM domain_discovery_settings WHERE singleton",
            &[],
        )
        .await?)
}

fn settings_from_row(row: tokio_postgres::Row) -> Result<Settings> {
    let proxy_mode = row
        .get::<_, String>("proxy_mode")
        .parse::<ProxyMode>()
        .map_err(|_| Error::internal("proxy_configuration_unavailable"))?;
    Ok(Settings {
        proxy_mode,
        proxy_endpoint: row.get("proxy_endpoint"),
        proxy_ciphertext: row.get("proxy_ciphertext"),
        revision: row.get("revision"),
        updated_at: row.get("updated_at"),
    })
}

fn default_settings() -> Settings {
    Settings {
        proxy_mode: ProxyMode::System,
        proxy_endpoint: String::new(),
        proxy_ciphertext: None,
        revision: 1,
        updated_at: Utc::now(),
    }
}

fn encryption_key(encoded_key: &str) -> Result<Vec<u8>> {
    let key = openssl::base64::decode_block(encoded_key)
        .map_err(|_| Error::internal("proxy_configuration_unavailable"))?;
    if key.len() != 32 {
        return Err(Error::internal("proxy_configuration_unavailable"));
    }
    Ok(key)
}

fn encrypt_secret(value: &str, encoded_key: &str) -> Result<Vec<u8>> {
    let key = encryption_key(encoded_key)?;
    let (nonce, tag, bytes) = crate::identity::encrypt_data(value.as_bytes(), &key)
        .map_err(|_| Error::internal("proxy_configuration_unavailable"))?;
    Ok([nonce, tag, bytes].concat())
}

fn decrypt_secret(bytes: &[u8], encoded_key: &str) -> Result<String> {
    if bytes.len() < 28 {
        return Err(Error::internal("proxy_configuration_unavailable"));
    }
    let key = encryption_key(encoded_key)?;
    let value = crate::identity::decrypt_data(bytes, &key)
        .map_err(|_| Error::internal("proxy_configuration_unavailable"))?;
    String::from_utf8(value).map_err(|_| Error::internal("proxy_configuration_unavailable"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> String {
        openssl::base64::encode_block(&[byte; 32])
    }

    fn custom_settings(url: &str, encryption_key: &str) -> Settings {
        Settings {
            proxy_mode: ProxyMode::Custom,
            proxy_endpoint: outbound_proxy::endpoint(url).unwrap(),
            proxy_ciphertext: Some(encrypt_secret(url, encryption_key).unwrap()),
            revision: 2,
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn custom_proxy_round_trips_and_public_view_omits_credentials() {
        let encryption_key = key(7);
        let url = "socks5h://user:secret@proxy.example.com:1080";
        let settings = custom_settings(url, &encryption_key);
        let public = settings.public();
        assert_eq!(public.proxy_mode, ProxyMode::Custom);
        assert!(public.proxy_configured);
        assert!(!public.proxy_endpoint.contains("secret"));
        assert!(!public.proxy_endpoint.contains("user@"));
        let config = settings.proxy_config(&encryption_key).unwrap();
        assert_eq!(config.mode, ProxyMode::Custom);
        assert_eq!(config.url, url);
    }

    #[test]
    fn inactive_modes_ignore_the_retained_proxy() {
        let encryption_key = key(7);
        let url = "http://user:secret@proxy.example.com:8080";
        for mode in [ProxyMode::System, ProxyMode::Direct] {
            let settings = Settings {
                proxy_mode: mode,
                ..custom_settings(url, &encryption_key)
            };
            let config = settings.proxy_config(&encryption_key).unwrap();
            assert_eq!(config.mode, mode);
            assert!(config.url.is_empty());
        }
    }

    #[test]
    fn undecryptable_or_tampered_credentials_fail_closed() {
        let encryption_key = key(7);
        let settings =
            custom_settings("http://user:secret@proxy.example.com:8080", &encryption_key);
        assert_eq!(
            settings.proxy_config(&key(9)).unwrap_err().reason(),
            "proxy_configuration_unavailable"
        );
        let mut tampered = settings;
        if let Some(ciphertext) = tampered.proxy_ciphertext.as_mut() {
            ciphertext[28] ^= 0xff;
        }
        assert_eq!(
            tampered.proxy_config(&encryption_key).unwrap_err().reason(),
            "proxy_configuration_unavailable"
        );
    }
}
