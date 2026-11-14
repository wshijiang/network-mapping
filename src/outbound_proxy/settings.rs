//! Shared persisted proxy settings for platform-wide and singleton module scopes.
use super::{ProxyConfig, ProxyError, ProxyMode};
use crate::{
    admin::UserBaseI,
    audit::{AuditContext, AuditEvent},
};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::json;

pub(crate) const GLOBAL_SCOPE: &str = "global";
pub(crate) const DOMAIN_DISCOVERY_SCOPE: &str = "domain_discovery";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoredSettings {
    pub(crate) proxy_mode: ProxyMode,
    pub(crate) proxy_endpoint: String,
    pub(crate) proxy_ciphertext: Option<Vec<u8>>,
    pub(crate) revision: i64,
    pub(crate) updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PublicSettings {
    pub(crate) proxy_mode: ProxyMode,
    pub(crate) proxy_endpoint: String,
    pub(crate) proxy_configured: bool,
    pub(crate) revision: i64,
    pub(crate) updated_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SettingsInput {
    pub expected_revision: i64,
    pub proxy_mode: ProxyMode,
    #[serde(default)]
    pub proxy_url: String,
    #[serde(default)]
    pub change_reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClearInput {
    pub expected_revision: i64,
    #[serde(default)]
    pub change_reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProxyTestInput {
    pub proxy_mode: ProxyMode,
    #[serde(default)]
    pub proxy_url: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SettingsError {
    Invalid(&'static str),
    Conflict,
    Unavailable(&'static str),
    Database,
}

impl SettingsError {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Invalid(code) => code,
            Self::Conflict => "settings_revision_conflict",
            Self::Unavailable(code) => code,
            Self::Database => "settings_unavailable",
        }
    }
}

impl StoredSettings {
    pub(crate) fn public(&self) -> PublicSettings {
        PublicSettings {
            proxy_mode: self.proxy_mode,
            proxy_endpoint: self.proxy_endpoint.clone(),
            proxy_configured: self.proxy_ciphertext.is_some() || !self.proxy_endpoint.is_empty(),
            revision: self.revision,
            updated_at: self.updated_at,
        }
    }

    pub(crate) fn proxy_config(&self, encryption_key: &str) -> Result<ProxyConfig, ProxyError> {
        if self.proxy_mode != ProxyMode::Custom {
            return Ok(ProxyConfig {
                mode: self.proxy_mode,
                url: String::new(),
            });
        }
        let url = match self.proxy_ciphertext.as_deref() {
            Some(ciphertext) => crate::secret::decrypt(ciphertext, encryption_key)
                .map_err(|_| ProxyError::permanent(crate::secret::UNAVAILABLE))?,
            None => self.proxy_endpoint.clone(),
        };
        super::validate_url(&url).map_err(|_| ProxyError::permanent("proxy_invalid"))?;
        Ok(ProxyConfig {
            mode: ProxyMode::Custom,
            url,
        })
    }
}

pub(crate) async fn load(
    pool: &Pool,
    scope: &'static str,
) -> Result<StoredSettings, SettingsError> {
    let client = pool.get().await.map_err(|_| SettingsError::Database)?;
    if let Some(row) = query(&client, scope)
        .await
        .map_err(|_| SettingsError::Database)?
    {
        return settings_from_row(row);
    }
    client
        .execute(
            "INSERT INTO outbound_proxy_settings (scope) VALUES ($1) \
             ON CONFLICT (scope) DO NOTHING",
            &[&scope],
        )
        .await
        .map_err(|_| SettingsError::Database)?;
    match query(&client, scope)
        .await
        .map_err(|_| SettingsError::Database)?
    {
        Some(row) => settings_from_row(row),
        None => Err(SettingsError::Database),
    }
}

pub(crate) async fn save(
    pool: &Pool,
    scope: &'static str,
    encryption_key: &str,
    input: SettingsInput,
    user: &UserBaseI,
    context: &AuditContext,
    audit_action: &'static str,
) -> Result<StoredSettings, SettingsError> {
    if input.expected_revision < 1
        || input.change_reason.len() > 500
        || input.change_reason.chars().any(char::is_control)
    {
        return Err(SettingsError::Invalid("invalid_revision_or_change_reason"));
    }
    let current = load(pool, scope).await?;
    let (proxy_endpoint, proxy_ciphertext) = match input.proxy_mode {
        ProxyMode::System | ProxyMode::Direct => {
            if !input.proxy_url.trim().is_empty() {
                return Err(SettingsError::Invalid("proxy_url_not_allowed"));
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
                    return Err(SettingsError::Invalid("proxy_url_required"));
                }
                (
                    current.proxy_endpoint.clone(),
                    current.proxy_ciphertext.clone(),
                )
            } else {
                if input.proxy_url != url {
                    return Err(SettingsError::Invalid("proxy_invalid"));
                }
                let endpoint =
                    super::endpoint(url).map_err(|_| SettingsError::Invalid("proxy_invalid"))?;
                let ciphertext = crate::secret::encrypt(url, encryption_key)
                    .map_err(SettingsError::Unavailable)?;
                (endpoint, Some(ciphertext))
            }
        }
    };
    if input.proxy_mode == ProxyMode::Custom && proxy_endpoint.is_empty() {
        return Err(SettingsError::Invalid("proxy_url_required"));
    }
    update(
        pool,
        scope,
        input.expected_revision,
        input.proxy_mode,
        proxy_endpoint,
        proxy_ciphertext,
        user,
        context,
        audit_action,
        &input.change_reason,
    )
    .await
}

pub(crate) async fn clear(
    pool: &Pool,
    scope: &'static str,
    input: ClearInput,
    user: &UserBaseI,
    context: &AuditContext,
    audit_action: &'static str,
) -> Result<StoredSettings, SettingsError> {
    if input.expected_revision < 1
        || input.change_reason.len() > 500
        || input.change_reason.chars().any(char::is_control)
    {
        return Err(SettingsError::Invalid("invalid_revision_or_change_reason"));
    }
    update(
        pool,
        scope,
        input.expected_revision,
        ProxyMode::System,
        String::new(),
        None,
        user,
        context,
        audit_action,
        &input.change_reason,
    )
    .await
}

pub(crate) async fn resolve_test_input(
    pool: &Pool,
    scope: &'static str,
    encryption_key: &str,
    input: &ProxyTestInput,
) -> Result<ProxyConfig, SettingsError> {
    match input.proxy_mode {
        ProxyMode::System | ProxyMode::Direct => Ok(ProxyConfig {
            mode: input.proxy_mode,
            url: String::new(),
        }),
        ProxyMode::Custom => {
            let url = input.proxy_url.trim();
            if url.is_empty() {
                let stored = load(pool, scope).await?;
                if stored.proxy_mode != ProxyMode::Custom {
                    return Err(SettingsError::Invalid("proxy_url_required"));
                }
                stored
                    .proxy_config(encryption_key)
                    .map_err(|error| SettingsError::Unavailable(error.code))
            } else {
                if input.proxy_url != url {
                    return Err(SettingsError::Invalid("proxy_invalid"));
                }
                super::validate_url(url).map_err(|_| SettingsError::Invalid("proxy_invalid"))?;
                Ok(ProxyConfig {
                    mode: ProxyMode::Custom,
                    url: url.to_owned(),
                })
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn update(
    pool: &Pool,
    scope: &'static str,
    expected_revision: i64,
    proxy_mode: ProxyMode,
    proxy_endpoint: String,
    proxy_ciphertext: Option<Vec<u8>>,
    user: &UserBaseI,
    context: &AuditContext,
    audit_action: &'static str,
    change_reason: &str,
) -> Result<StoredSettings, SettingsError> {
    let mut client = pool.get().await.map_err(|_| SettingsError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| SettingsError::Database)?;
    let mode = proxy_mode.as_str();
    let row = tx
        .query_opt(
            "UPDATE outbound_proxy_settings \
             SET proxy_mode=$1, proxy_endpoint=$2, proxy_ciphertext=$3, revision=revision+1, \
                 updated_at=NOW(), updated_by_user_id=$4 \
             WHERE scope=$5 AND revision=$6 \
             RETURNING proxy_mode, proxy_endpoint, proxy_ciphertext, revision, updated_at",
            &[
                &mode,
                &proxy_endpoint,
                &proxy_ciphertext,
                &user.id,
                &scope,
                &expected_revision,
            ],
        )
        .await
        .map_err(|_| SettingsError::Database)?;
    let Some(row) = row else {
        return Err(SettingsError::Conflict);
    };
    let revision: i64 = row.get("revision");
    let mut event = AuditEvent::user("configuration", audit_action, "success", user)
        .resource("outbound_proxy_settings", scope);
    event.metadata = json!({
        "scope": scope,
        "proxy_mode": mode,
        "proxy_endpoint": proxy_endpoint,
        "revision": revision,
        "change_reason": change_reason,
    });
    crate::audit::write(&tx, context, &event)
        .await
        .map_err(|_| SettingsError::Database)?;
    tx.commit().await.map_err(|_| SettingsError::Database)?;
    settings_from_row(row)
}

async fn query(
    client: &deadpool_postgres::Client,
    scope: &str,
) -> Result<Option<tokio_postgres::Row>, tokio_postgres::Error> {
    client
        .query_opt(
            "SELECT proxy_mode, proxy_endpoint, proxy_ciphertext, revision, updated_at \
             FROM outbound_proxy_settings WHERE scope=$1",
            &[&scope],
        )
        .await
}

fn settings_from_row(row: tokio_postgres::Row) -> Result<StoredSettings, SettingsError> {
    let proxy_mode = row
        .get::<_, String>("proxy_mode")
        .parse::<ProxyMode>()
        .map_err(|_| SettingsError::Unavailable(crate::secret::UNAVAILABLE))?;
    Ok(StoredSettings {
        proxy_mode,
        proxy_endpoint: row.get("proxy_endpoint"),
        proxy_ciphertext: row.get("proxy_ciphertext"),
        revision: row.get("revision"),
        updated_at: row.get("updated_at"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> String {
        openssl::base64::encode_block(&[byte; 32])
    }

    fn custom_settings(url: &str, encryption_key: &str) -> StoredSettings {
        StoredSettings {
            proxy_mode: ProxyMode::Custom,
            proxy_endpoint: super::super::endpoint(url).unwrap(),
            proxy_ciphertext: Some(crate::secret::encrypt(url, encryption_key).unwrap()),
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
            let settings = StoredSettings {
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
            settings.proxy_config(&key(9)).unwrap_err().code,
            crate::secret::UNAVAILABLE
        );
        let mut tampered = settings;
        if let Some(ciphertext) = tampered.proxy_ciphertext.as_mut() {
            ciphertext[28] ^= 0xff;
        }
        assert_eq!(
            tampered.proxy_config(&encryption_key).unwrap_err().code,
            crate::secret::UNAVAILABLE
        );
    }
}
