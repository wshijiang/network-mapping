//! Process-wide outbound proxy snapshot. Local `system` settings follow this
//! value; explicit local `direct`/`custom` settings override it.
use crate::outbound_proxy::{self, ProxyConfig, ProxyError, ProxyMode, settings};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{RwLock, watch};
use tracing::{info, warn};

#[derive(Clone, Debug)]
pub(crate) enum ResolvedGlobalProxy {
    Ready(ProxyConfig),
    Unavailable(&'static str),
}

#[derive(Debug, Serialize)]
pub(crate) struct PublicGlobalProxy {
    pub proxy_mode: ProxyMode,
    pub proxy_endpoint: String,
    pub proxy_configured: bool,
    pub revision: i64,
    pub updated_at: DateTime<Utc>,
    pub available: bool,
    pub error: Option<&'static str>,
}

#[derive(Clone)]
pub struct GlobalProxyState {
    inner: Arc<Inner>,
}

struct Inner {
    snapshot: RwLock<Snapshot>,
    generation: AtomicU64,
    revisions: watch::Sender<u64>,
}

struct Snapshot {
    raw: Option<settings::StoredSettings>,
    resolved: ResolvedGlobalProxy,
}

impl GlobalProxyState {
    pub(crate) async fn initialize(pool: &Pool, encryption_key: &str) -> Self {
        let snapshot = match settings::load(pool, settings::GLOBAL_SCOPE).await {
            Ok(raw) => {
                let resolved = resolve_stored(&raw, encryption_key);
                match &resolved {
                    ResolvedGlobalProxy::Ready(_) => info!(
                        event = "NetworkProxyLoaded",
                        mode = raw.proxy_mode.as_str(),
                        revision = raw.revision,
                        "全局网络代理已加载"
                    ),
                    ResolvedGlobalProxy::Unavailable(code) => warn!(
                        event = "NetworkProxyUnavailable",
                        code = code,
                        revision = raw.revision,
                        "全局网络代理不可用，继承模块将失败关闭"
                    ),
                }
                Snapshot {
                    raw: Some(raw),
                    resolved,
                }
            }
            Err(error) => {
                warn!(
                    event = "NetworkProxyLoadFailed",
                    code = error.code(),
                    "全局网络代理读取失败，暂用系统代理"
                );
                Snapshot {
                    raw: None,
                    resolved: ResolvedGlobalProxy::Ready(ProxyConfig {
                        mode: ProxyMode::System,
                        url: String::new(),
                    }),
                }
            }
        };
        Self::from_snapshot(snapshot)
    }

    /// A safe default for tests and for callers that do not have a database.
    pub(crate) fn system() -> Self {
        Self::from_snapshot(Snapshot {
            raw: None,
            resolved: ResolvedGlobalProxy::Ready(ProxyConfig {
                mode: ProxyMode::System,
                url: String::new(),
            }),
        })
    }

    fn from_snapshot(snapshot: Snapshot) -> Self {
        let (revisions, _) = watch::channel(0);
        Self {
            inner: Arc::new(Inner {
                snapshot: RwLock::new(snapshot),
                generation: AtomicU64::new(0),
                revisions,
            }),
        }
    }

    /// Read the authoritative row and replace the snapshot only when the
    /// complete raw row differs. This catches direct SQL edits that do not
    /// advance revision.
    pub(crate) async fn refresh(&self, pool: &Pool, encryption_key: &str) -> Result<bool, String> {
        let raw = settings::load(pool, settings::GLOBAL_SCOPE)
            .await
            .map_err(|error| error.code().to_owned())?;
        let mut snapshot = self.inner.snapshot.write().await;
        if let Some(current) = snapshot.raw.as_ref() {
            if current.revision > raw.revision {
                return Ok(false);
            }
            if current == &raw {
                return Ok(false);
            }
        }
        let resolved = resolve_stored(&raw, encryption_key);
        let revision = raw.revision;
        let mode = raw.proxy_mode;
        let endpoint = raw.proxy_endpoint.clone();
        snapshot.raw = Some(raw);
        snapshot.resolved = resolved;
        drop(snapshot);
        self.notify();
        info!(
            event = "NetworkProxyChanged",
            mode = mode.as_str(),
            endpoint = endpoint,
            revision = revision,
            "全局网络代理已更新"
        );
        Ok(true)
    }

    /// Apply a row returned by the save endpoint without waiting for polling.
    pub(crate) async fn apply(&self, raw: settings::StoredSettings, encryption_key: &str) {
        let resolved = resolve_stored(&raw, encryption_key);
        let mut snapshot = self.inner.snapshot.write().await;
        if snapshot
            .raw
            .as_ref()
            .is_some_and(|current| current.revision > raw.revision)
        {
            return;
        }
        snapshot.raw = Some(raw);
        snapshot.resolved = resolved;
        drop(snapshot);
        self.notify();
    }

    pub(crate) async fn resolve(&self, local: &ProxyConfig) -> Result<ProxyConfig, ProxyError> {
        if local.mode != ProxyMode::System {
            return Ok(local.clone());
        }
        let snapshot = self.inner.snapshot.read().await;
        match &snapshot.resolved {
            ResolvedGlobalProxy::Ready(config) => Ok(config.clone()),
            ResolvedGlobalProxy::Unavailable(code) => Err(ProxyError::permanent(code)),
        }
    }

    pub(crate) async fn public(&self) -> Option<PublicGlobalProxy> {
        let snapshot = self.inner.snapshot.read().await;
        let raw = snapshot.raw.as_ref()?;
        let (available, error) = match &snapshot.resolved {
            ResolvedGlobalProxy::Ready(_) => (true, None),
            ResolvedGlobalProxy::Unavailable(code) => (false, Some(*code)),
        };
        Some(PublicGlobalProxy {
            proxy_mode: raw.proxy_mode,
            proxy_endpoint: raw.proxy_endpoint.clone(),
            proxy_configured: raw.proxy_ciphertext.is_some() || !raw.proxy_endpoint.is_empty(),
            revision: raw.revision,
            updated_at: raw.updated_at,
            available,
            error,
        })
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.inner.revisions.subscribe()
    }

    fn notify(&self) {
        let generation = self.inner.generation.fetch_add(1, Ordering::SeqCst) + 1;
        self.inner.revisions.send_replace(generation);
    }
}

fn resolve_stored(raw: &settings::StoredSettings, encryption_key: &str) -> ResolvedGlobalProxy {
    match raw.proxy_config(encryption_key) {
        Ok(config) => ResolvedGlobalProxy::Ready(config),
        Err(error) => ResolvedGlobalProxy::Unavailable(error.code),
    }
}

pub(crate) fn validate_test_url(value: &str) -> Result<reqwest::Url, &'static str> {
    if value.len() > 2048 || value.trim() != value || value.chars().any(char::is_control) {
        return Err("proxy_test_url_invalid");
    }
    let url = reqwest::Url::parse(value).map_err(|_| "proxy_test_url_invalid")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("proxy_test_url_invalid");
    }
    Ok(url)
}

/// Direct/system probes connect from this server, so reject private
/// destinations. A custom proxy owns its egress policy and may resolve
/// `socks5h` remotely.
pub(crate) async fn ensure_public_test_host(
    url: &reqwest::Url,
    proxy_mode: ProxyMode,
) -> Result<(), &'static str> {
    if proxy_mode == ProxyMode::Custom {
        return Ok(());
    }
    let host = url.host_str().ok_or("proxy_test_url_invalid")?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| "proxy_test_dns_failed")?
    .map_err(|_| "proxy_test_dns_failed")?
    .collect::<Vec<_>>();
    if addresses.is_empty() || addresses.iter().any(|address| !public_ip(address.ip())) {
        return Err("proxy_test_url_not_public");
    }
    Ok(())
}

pub(crate) async fn probe_url(proxy: &ProxyConfig, url: &str) -> Result<u16, ProxyError> {
    let client = proxy.http_client()?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| outbound_proxy::classify_request_error(&error, proxy.mode))?;
    Ok(response.status().as_u16())
}

fn public_ip(ip: std::net::IpAddr) -> bool {
    match crate::client_ip::normalize_ip(ip) {
        std::net::IpAddr::V4(ip) => {
            let n = u32::from(ip);
            ![
                "0.0.0.0/8",
                "10.0.0.0/8",
                "100.64.0.0/10",
                "127.0.0.0/8",
                "169.254.0.0/16",
                "172.16.0.0/12",
                "192.0.0.0/24",
                "192.0.2.0/24",
                "192.88.99.0/24",
                "192.168.0.0/16",
                "198.18.0.0/15",
                "198.51.100.0/24",
                "203.0.113.0/24",
                "224.0.0.0/3",
            ]
            .iter()
            .any(|s| {
                s.parse::<ipnet::Ipv4Net>()
                    .expect("constant subnet")
                    .contains(&std::net::Ipv4Addr::from(n))
            })
        }
        std::net::IpAddr::V6(ip) => "2000::/3"
            .parse::<ipnet::Ipv6Net>()
            .expect("constant subnet")
            .contains(&ip),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> String {
        openssl::base64::encode_block(&[byte; 32])
    }

    fn custom(url: &str, encryption_key: &str) -> settings::StoredSettings {
        settings::StoredSettings {
            proxy_mode: ProxyMode::Custom,
            proxy_endpoint: crate::outbound_proxy::endpoint(url).unwrap(),
            proxy_ciphertext: Some(crate::secret::encrypt(url, encryption_key).unwrap()),
            revision: 1,
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn local_custom_and_direct_override_the_global_proxy() {
        let encryption_key = key(7);
        let state = GlobalProxyState::system();
        state
            .apply(
                custom("socks5h://user:secret@proxy.example:1080", &encryption_key),
                &encryption_key,
            )
            .await;
        let local = ProxyConfig {
            mode: ProxyMode::Custom,
            url: "http://127.0.0.1:8080".into(),
        };
        let effective = state.resolve(&local).await.unwrap();
        assert_eq!(effective.mode, ProxyMode::Custom);
        assert_eq!(effective.url, local.url);
        let direct = state
            .resolve(&ProxyConfig {
                mode: ProxyMode::Direct,
                url: String::new(),
            })
            .await
            .unwrap();
        assert_eq!(direct.mode, ProxyMode::Direct);
        let inherited = state
            .resolve(&ProxyConfig {
                mode: ProxyMode::System,
                url: String::new(),
            })
            .await
            .unwrap();
        assert_eq!(inherited.mode, ProxyMode::Custom);
        assert_eq!(inherited.url, "socks5h://user:secret@proxy.example:1080");
        let public = state.public().await.unwrap();
        assert!(public.available);
        assert!(public.proxy_configured);
        assert!(!public.proxy_endpoint.contains("secret"));
    }

    #[tokio::test]
    async fn an_unusable_global_proxy_fails_closed_only_for_inheriting_locals() {
        let encryption_key = key(7);
        let state = GlobalProxyState::system();
        let mut raw = custom("http://user:secret@proxy.example:8080", &encryption_key);
        raw.proxy_ciphertext = Some(vec![1; 32]);
        state.apply(raw, &encryption_key).await;
        let error = state
            .resolve(&ProxyConfig {
                mode: ProxyMode::System,
                url: String::new(),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, crate::secret::UNAVAILABLE);
        assert!(!error.retryable);
        let direct = state
            .resolve(&ProxyConfig {
                mode: ProxyMode::Direct,
                url: String::new(),
            })
            .await
            .unwrap();
        assert_eq!(direct.mode, ProxyMode::Direct);
        let public = state.public().await.unwrap();
        assert!(!public.available);
        assert_eq!(public.error, Some(crate::secret::UNAVAILABLE));
    }

    #[tokio::test]
    async fn default_global_mode_is_the_environment_proxy() {
        let state = GlobalProxyState::system();
        let effective = state
            .resolve(&ProxyConfig {
                mode: ProxyMode::System,
                url: String::new(),
            })
            .await
            .unwrap();
        assert_eq!(effective.mode, ProxyMode::System);
        assert!(effective.url.is_empty());
    }

    #[test]
    fn test_urls_are_https_only_and_public_ip_classification_is_conservative() {
        assert!(validate_test_url("https://example.com/").is_ok());
        assert!(validate_test_url("http://example.com/").is_err());
        assert!(validate_test_url("https://user:secret@example.com/").is_err());
        assert!(validate_test_url("https://example.com/#fragment").is_err());
        assert!(!public_ip("127.0.0.1".parse().unwrap()));
        assert!(!public_ip("10.0.0.1".parse().unwrap()));
        assert!(public_ip("1.1.1.1".parse().unwrap()));
    }

    #[tokio::test]
    #[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
    async fn refresh_detects_direct_database_edits_and_other_instances() {
        let (c, conn) = tokio_postgres::connect(
            &std::env::var("STORAGE_TEST_DATABASE_URL").unwrap(),
            tokio_postgres::NoTls,
        )
        .await
        .unwrap();
        tokio::spawn(async move { conn.await.unwrap() });
        let schema = format!("network_proxy_{}", uuid::Uuid::new_v4().simple());
        c.batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema};"
        ))
        .await
        .unwrap();
        c.batch_execute(include_str!("../source/database/init.sql"))
            .await
            .unwrap();
        c.batch_execute(include_str!(
            "../source/database/migrate_domain_discovery.sql"
        ))
        .await
        .unwrap();
        c.batch_execute(include_str!(
            "../source/database/migrate_outbound_proxy_settings.sql"
        ))
        .await
        .unwrap();
        c.batch_execute(
            "INSERT INTO users(id,username,password,role) VALUES(1,'proxy-admin','unused',1)",
        )
        .await
        .unwrap();
        let mut config: tokio_postgres::Config = std::env::var("STORAGE_TEST_DATABASE_URL")
            .unwrap()
            .parse()
            .unwrap();
        config.options(format!("-c search_path={schema}"));
        let pool = Pool::builder(deadpool_postgres::Manager::new(
            config,
            tokio_postgres::NoTls,
        ))
        .max_size(2)
        .build()
        .unwrap();
        let encryption_key = key(7);
        let user = crate::admin::UserBaseI {
            id: 1,
            username: "proxy-admin".into(),
            role: 1,
            email: None,
            limit_login: false,
            enable_2fa: false,
        };
        let context = crate::audit::AuditContext::cli("network-proxy-test");
        let url = "socks5h://user:secret@proxy.example:1080";
        settings::save(
            &pool,
            settings::GLOBAL_SCOPE,
            &encryption_key,
            settings::SettingsInput {
                expected_revision: 1,
                proxy_mode: ProxyMode::Custom,
                proxy_url: url.into(),
                change_reason: String::new(),
            },
            &user,
            &context,
            "network.proxy_update",
        )
        .await
        .unwrap();
        let first = GlobalProxyState::initialize(&pool, &encryption_key).await;
        let peer = GlobalProxyState::initialize(&pool, &encryption_key).await;
        let system_local = ProxyConfig {
            mode: ProxyMode::System,
            url: String::new(),
        };
        assert_eq!(
            first.resolve(&system_local).await.unwrap().url,
            url,
            "startup loads the saved global proxy"
        );
        c.execute(
            "UPDATE outbound_proxy_settings SET proxy_mode='direct', revision=revision+1 \
             WHERE scope='global'",
            &[],
        )
        .await
        .unwrap();
        assert!(peer.refresh(&pool, &encryption_key).await.unwrap());
        assert_eq!(
            peer.resolve(&system_local).await.unwrap().mode,
            ProxyMode::Direct
        );
        settings::clear(
            &pool,
            settings::GLOBAL_SCOPE,
            settings::ClearInput {
                expected_revision: 3,
                change_reason: String::new(),
            },
            &user,
            &context,
            "network.proxy_clear",
        )
        .await
        .unwrap();
        assert!(first.refresh(&pool, &encryption_key).await.unwrap());
        assert_eq!(
            first.resolve(&system_local).await.unwrap().mode,
            ProxyMode::System
        );
        c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
