//! Administrator policy storage. Credentials never enter the public DTO or audit payload.
use super::{
    HumanVerificationService,
    config::{HumanVerificationConfig, ProviderKind, TurnstileConfig, hostname},
};
use crate::{
    admin::UserBaseI,
    audit::{AuditContext, AuditEvent},
};
use actix_web::http::StatusCode;
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::{Arc, RwLock};

const NAMESPACE: &str = "human_verification";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub provider: ProviderKind,
    pub site_key: String,
    pub allowed_hostnames: Vec<String>,
    pub timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub max_in_flight: usize,
    pub send_remote_ip: bool,
}

impl Policy {
    fn from_config(config: &HumanVerificationConfig) -> Self {
        Self {
            provider: config.provider,
            site_key: config.turnstile.site_key.clone(),
            allowed_hostnames: config.turnstile.allowed_hostnames.clone(),
            timeout_ms: config.timeout_ms,
            connect_timeout_ms: config.connect_timeout_ms,
            max_in_flight: config.max_in_flight,
            send_remote_ip: config.send_remote_ip,
        }
    }

    fn config(&self, secret_key: String) -> HumanVerificationConfig {
        HumanVerificationConfig {
            provider: self.provider,
            timeout_ms: self.timeout_ms,
            connect_timeout_ms: self.connect_timeout_ms,
            max_in_flight: self.max_in_flight,
            send_remote_ip: self.send_remote_ip,
            turnstile: TurnstileConfig {
                site_key: self.site_key.clone(),
                secret_key,
                allowed_hostnames: self.allowed_hostnames.clone(),
            },
            ..HumanVerificationConfig::default()
        }
    }

    fn normalize_and_validate(&mut self, secret_configured: bool) -> Result<(), SettingsError> {
        if self.site_key.len() > 256 || self.allowed_hostnames.len() > 32 {
            return Err(SettingsError::Invalid(
                "Site Key 过长或允许域名超过 32 项".into(),
            ));
        }
        self.site_key = self.site_key.trim().into();
        let mut hosts = Vec::new();
        for value in &self.allowed_hostnames {
            let value = hostname(value.trim()).ok_or_else(|| {
                SettingsError::Invalid("允许域名必须为不含协议、端口、路径或通配符的 DNS 名".into())
            })?;
            if !hosts.contains(&value) {
                hosts.push(value);
            }
        }
        self.allowed_hostnames = hosts;
        self.config(if secret_configured {
            "configured".into()
        } else {
            String::new()
        })
        .validate()
        .map_err(SettingsError::Invalid)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsInput {
    pub expected_revision: i64,
    pub document: Policy,
    #[serde(default)]
    pub secret_key: String,
    #[serde(default)]
    pub clear_secret: bool,
    #[serde(default)]
    pub change_reason: String,
}

impl SettingsInput {
    fn validate(&self) -> Result<(), SettingsError> {
        if self.expected_revision < 1
            || self.change_reason.len() > 500
            || self.change_reason.chars().any(char::is_control)
        {
            return Err(SettingsError::Invalid("配置版本或变更原因无效".into()));
        }
        if self.secret_key.len() > 2048
            || (!self.secret_key.is_empty()
                && (self.secret_key.trim() != self.secret_key
                    || self.secret_key.chars().any(char::is_control)))
        {
            return Err(SettingsError::Invalid(
                "Secret 不可包含首尾空白、控制字符或超过 2048 字节".into(),
            ));
        }
        if self.clear_secret && !self.secret_key.is_empty() {
            return Err(SettingsError::Invalid(
                "替换和清除 Secret 不能同时执行".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub struct AdminSettings {
    pub revision: i64,
    pub document: Policy,
    pub secret_key_configured: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSettings {
    policy: Policy,
    secret_ciphertext: Option<String>,
}

impl StoredSettings {
    fn config(&self, key: &[u8]) -> Result<HumanVerificationConfig, SettingsError> {
        let secret = match &self.secret_ciphertext {
            Some(value) => decrypt(value, key)?,
            None => String::new(),
        };
        let config = self.policy.config(secret);
        config.validate().map_err(|_| SettingsError::Unavailable)?;
        Ok(config)
    }

    fn view(&self, revision: i64) -> AdminSettings {
        AdminSettings {
            revision,
            document: self.policy.clone(),
            secret_key_configured: self.secret_ciphertext.is_some(),
        }
    }

    fn update(&self, mut input: SettingsInput, key: &[u8]) -> Result<Self, SettingsError> {
        input.validate()?;
        let secret_ciphertext = if input.clear_secret {
            None
        } else if input.secret_key.is_empty() {
            self.secret_ciphertext.clone()
        } else {
            Some(encrypt(&input.secret_key, key)?)
        };
        input
            .document
            .normalize_and_validate(secret_ciphertext.is_some())?;
        Ok(Self {
            policy: input.document,
            secret_ciphertext,
        })
    }
}

fn encrypt(value: &str, key: &[u8]) -> Result<String, SettingsError> {
    let (nonce, tag, ciphertext) = crate::identity::encrypt_data(value.as_bytes(), key)
        .map_err(|_| SettingsError::Unavailable)?;
    Ok(openssl::base64::encode_block(
        &[nonce, tag, ciphertext].concat(),
    ))
}

fn decrypt(value: &str, key: &[u8]) -> Result<String, SettingsError> {
    let bytes = openssl::base64::decode_block(value).map_err(|_| SettingsError::Unavailable)?;
    if bytes.len() < 28 {
        return Err(SettingsError::Unavailable);
    }
    let bytes =
        crate::identity::decrypt_data(&bytes, key).map_err(|_| SettingsError::Unavailable)?;
    String::from_utf8(bytes).map_err(|_| SettingsError::Unavailable)
}

#[derive(Debug)]
pub enum SettingsError {
    Invalid(String),
    Conflict,
    Unavailable,
}

impl SettingsError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Invalid(_) => StatusCode::BAD_REQUEST,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
    pub fn message(&self) -> &str {
        match self {
            Self::Invalid(message) => message,
            Self::Conflict => "配置已被其他管理员更新，请重新加载后保存",
            Self::Unavailable => "登录保护配置暂不可用，请稍后重试",
        }
    }
}

struct Snapshot {
    revision: i64,
    service: Arc<HumanVerificationService>,
}

pub struct ManagedVerification {
    pool: Pool,
    key: Vec<u8>,
    active: RwLock<Snapshot>,
}

impl ManagedVerification {
    pub async fn initialize(
        pool: Pool,
        encoded_key: &str,
        bootstrap: HumanVerificationConfig,
    ) -> Result<Self, SettingsError> {
        bootstrap.validate().map_err(SettingsError::Invalid)?;
        let key =
            openssl::base64::decode_block(encoded_key).map_err(|_| SettingsError::Unavailable)?;
        if key.len() != 32 {
            return Err(SettingsError::Unavailable);
        }
        let stored = StoredSettings {
            policy: Policy::from_config(&bootstrap),
            secret_ciphertext: if bootstrap.turnstile.secret_key.is_empty() {
                None
            } else {
                Some(encrypt(&bootstrap.turnstile.secret_key, &key)?)
            },
        };
        let document = serde_json::to_value(stored).map_err(|_| SettingsError::Unavailable)?;
        let mut connection = pool.get().await.map_err(|_| SettingsError::Unavailable)?;
        let tx = connection
            .transaction()
            .await
            .map_err(|_| SettingsError::Unavailable)?;
        tx.execute("INSERT INTO runtime_configuration(namespace, document) VALUES($1,$2) ON CONFLICT(namespace) DO NOTHING", &[&NAMESPACE, &document]).await.map_err(|_| SettingsError::Unavailable)?;
        tx.execute("INSERT INTO runtime_configuration_revision(namespace, revision, schema_version, document, change_reason) SELECT namespace, revision, schema_version, document, 'initial deployment configuration' FROM runtime_configuration WHERE namespace=$1 ON CONFLICT(namespace,revision) DO NOTHING", &[&NAMESPACE]).await.map_err(|_| SettingsError::Unavailable)?;
        let row = tx
            .query_one(
                "SELECT document,revision FROM runtime_configuration WHERE namespace=$1",
                &[&NAMESPACE],
            )
            .await
            .map_err(|_| SettingsError::Unavailable)?;
        let saved: StoredSettings =
            serde_json::from_value(row.get("document")).map_err(|_| SettingsError::Unavailable)?;
        let service = Arc::new(
            HumanVerificationService::new(saved.config(&key)?)
                .map_err(|_| SettingsError::Unavailable)?,
        );
        tx.commit().await.map_err(|_| SettingsError::Unavailable)?;
        drop(connection);
        Ok(Self {
            pool,
            key,
            active: RwLock::new(Snapshot {
                revision: row.get("revision"),
                service,
            }),
        })
    }

    pub fn cached(&self) -> Arc<HumanVerificationService> {
        self.active
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .service
            .clone()
    }

    fn install(
        &self,
        revision: i64,
        service: Arc<HumanVerificationService>,
    ) -> Arc<HumanVerificationService> {
        let mut active = self.active.write().unwrap_or_else(|e| e.into_inner());
        if revision > active.revision {
            *active = Snapshot { revision, service };
        }
        active.service.clone()
    }

    /// Every new login reads the authoritative revision. Database failure never bypasses protection.
    pub async fn fresh(&self) -> Result<Arc<HumanVerificationService>, SettingsError> {
        let connection = self
            .pool
            .get()
            .await
            .map_err(|_| SettingsError::Unavailable)?;
        let row = connection
            .query_one(
                "SELECT document,revision FROM runtime_configuration WHERE namespace=$1",
                &[&NAMESPACE],
            )
            .await
            .map_err(|_| SettingsError::Unavailable)?;
        let revision = row.get::<_, i64>("revision");
        {
            let active = self.active.read().unwrap_or_else(|e| e.into_inner());
            if revision == active.revision {
                return Ok(active.service.clone());
            }
            if revision < active.revision {
                return Err(SettingsError::Unavailable);
            }
        }
        let stored: StoredSettings =
            serde_json::from_value(row.get("document")).map_err(|_| SettingsError::Unavailable)?;
        let service = Arc::new(
            HumanVerificationService::new(stored.config(&self.key)?)
                .map_err(|_| SettingsError::Unavailable)?,
        );
        Ok(self.install(revision, service))
    }

    pub async fn read(&self) -> Result<AdminSettings, SettingsError> {
        let connection = self
            .pool
            .get()
            .await
            .map_err(|_| SettingsError::Unavailable)?;
        let row = connection
            .query_one(
                "SELECT document,revision FROM runtime_configuration WHERE namespace=$1",
                &[&NAMESPACE],
            )
            .await
            .map_err(|_| SettingsError::Unavailable)?;
        let stored: StoredSettings =
            serde_json::from_value(row.get("document")).map_err(|_| SettingsError::Unavailable)?;
        Ok(stored.view(row.get("revision")))
    }

    pub async fn save(
        &self,
        input: SettingsInput,
        user: &UserBaseI,
        context: &AuditContext,
    ) -> Result<AdminSettings, SettingsError> {
        input.validate()?;
        let expected = input.expected_revision;
        let reason = input.change_reason.clone();
        let secret_changed = input.clear_secret || !input.secret_key.is_empty();
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| SettingsError::Unavailable)?;
        let tx = connection
            .transaction()
            .await
            .map_err(|_| SettingsError::Unavailable)?;
        let row = tx
            .query_one(
                "SELECT document,revision FROM runtime_configuration WHERE namespace=$1 FOR UPDATE",
                &[&NAMESPACE],
            )
            .await
            .map_err(|_| SettingsError::Unavailable)?;
        if row.get::<_, i64>("revision") != expected {
            return Err(SettingsError::Conflict);
        }
        let stored: StoredSettings =
            serde_json::from_value(row.get("document")).map_err(|_| SettingsError::Unavailable)?;
        let updated = stored.update(input, &self.key)?;
        let service = Arc::new(
            HumanVerificationService::new(updated.config(&self.key)?)
                .map_err(|_| SettingsError::Unavailable)?,
        );
        let document = serde_json::to_value(&updated).map_err(|_| SettingsError::Unavailable)?;
        let row = tx.query_one("UPDATE runtime_configuration SET document=$2, revision=revision+1, updated_at=NOW(), updated_by_user_id=$3 WHERE namespace=$1 RETURNING revision", &[&NAMESPACE, &document, &user.id]).await.map_err(|_| SettingsError::Unavailable)?;
        let revision: i64 = row.get("revision");
        tx.execute("INSERT INTO runtime_configuration_revision(namespace,revision,schema_version,document,changed_by_user_id,change_reason) VALUES($1,$2,1,$3,$4,$5)", &[&NAMESPACE,&revision,&document,&user.id,&reason]).await.map_err(|_| SettingsError::Unavailable)?;
        let mut event = AuditEvent::user(
            "configuration",
            "config.human_verification.update",
            "success",
            user,
        )
        .resource("configuration", NAMESPACE);
        event.response_status = Some(200);
        event.metadata = json!({"revision":revision,"provider":updated.policy.provider,"secret_changed":secret_changed});
        crate::audit::write(&tx, context, &event)
            .await
            .map_err(|_| SettingsError::Unavailable)?;
        tx.commit().await.map_err(|_| SettingsError::Unavailable)?;
        self.install(revision, service);
        Ok(updated.view(revision))
    }
}

#[cfg(test)]
mod tests;
