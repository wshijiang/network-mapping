//! 联测常驻 worker：认领 CLI 创建的 pending run 与租约过期的 running run（崩溃恢复），
//! 周期清理终态 run、刷新启用源的账号额度（§11.4）。
//!
//! 搜索/Web 触发的 run 在请求进程内 spawn 执行（低延迟），worker 只做兜底认领。

use std::time::Duration;

use deadpool_postgres::Pool;
use tokio::time::sleep;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::dns_follow_up::DnsFollowUpConfig;
use crate::elasticsearch::ElasticsearchService;
use crate::federation::FederationConfig;
use crate::federation::adapters::{self, Adapter};
use crate::federation::executor::{self, Services};
use crate::federation::policy::FederationPolicy;
use crate::federation::storage;
use crate::maxmind::MaxMindState;
use crate::network_proxy::GlobalProxyState;
use crate::outbound_proxy::{ProxyConfig, ProxyMode};
use crate::runtime_config::RuntimeConfig;
use crate::system_maintenance::SystemMaintenanceState;

#[allow(clippy::too_many_arguments)]
pub async fn run_worker(
    pool: Pool,
    config: FederationConfig,
    maxmind: actix_web::web::Data<MaxMindState>,
    elasticsearch: actix_web::web::Data<ElasticsearchService>,
    dns_follow_up: actix_web::web::Data<RuntimeConfig<DnsFollowUpConfig>>,
    policy: actix_web::web::Data<RuntimeConfig<FederationPolicy>>,
    maintenance: actix_web::web::Data<SystemMaintenanceState>,
    network_proxy: GlobalProxyState,
    encrypt_key: String,
    pepper: String,
) {
    if !config.enabled {
        info!(event = "FederationWorkerDisabled", "联测 worker 未启用");
        return;
    }
    let worker_id = Uuid::new_v4();
    let lease_ms = config.lease_seconds as i64 * 1000;
    info!(event = "FederationWorkerStarted", %worker_id, "联测 worker 已启动");
    let mut tick: u64 = 0;
    loop {
        tick += 1;
        // 周期维护：每 ~10 分钟清理过期 run；每 quota_refresh_hours 刷新额度。
        if tick.is_multiple_of(300) {
            match storage::purge_expired(&pool, config.run_retention_days).await {
                Ok(purged) if purged > 0 => {
                    info!(event = "FederationRunsPurged", purged, "已清理过期联测 run");
                }
                Err(error) => warn!(event = "FederationPurgeFailed", %error, "清理联测 run 失败"),
                _ => {}
            }
        }
        let quota_ticks = (config.quota_refresh_hours * 3600 / config.worker_poll_seconds).max(1);
        if tick.is_multiple_of(quota_ticks) {
            refresh_quotas(&pool, &network_proxy, &encrypt_key).await;
        }
        if maintenance.snapshot().await.blocks_new_work() {
            sleep(Duration::from_secs(5)).await;
            continue;
        }
        match storage::claim_next(&pool, worker_id, lease_ms).await {
            Ok(Some(run)) => {
                let services = Services {
                    pool: pool.clone(),
                    maxmind: maxmind.clone(),
                    elasticsearch: elasticsearch.clone(),
                    dns_follow_up: dns_follow_up.get().await.value.clone(),
                    network_proxy: network_proxy.clone(),
                    encrypt_key: encrypt_key.clone(),
                    pepper: pepper.clone(),
                    config: config.clone(),
                };
                let snapshot = policy.get().await.value;
                if let Err(error) =
                    executor::execute_run(&services, &run, worker_id, &snapshot).await
                {
                    warn!(event = "FederationRunFailed", run_id = %run.id, %error, "联测 run 执行失败");
                    let _ = storage::finish_run(
                        &pool,
                        run.id,
                        "failed",
                        &serde_json::json!([]),
                        0,
                        0,
                        0,
                        None,
                        None,
                        Some(&error.to_string()),
                    )
                    .await;
                }
            }
            Ok(None) => sleep(Duration::from_secs(config.worker_poll_seconds)).await,
            Err(error) => {
                error!(event = "FederationClaimFailed", %error, "认领联测 run 失败");
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

/// 刷新启用源的账号额度（免费账号接口；失败保留上次值）。
async fn refresh_quotas(pool: &Pool, network_proxy: &GlobalProxyState, encrypt_key: &str) {
    let Ok(sources) = storage::list_sources(pool).await else {
        return;
    };
    for source in sources.iter().filter(|s| s.enabled) {
        let Ok(Some(credential)) =
            storage::decrypt_json(source.credential_ciphertext.as_deref(), encrypt_key)
        else {
            continue;
        };
        let local_proxy = ProxyConfig {
            mode: source
                .proxy_mode
                .parse::<ProxyMode>()
                .unwrap_or(ProxyMode::System),
            url: storage::decrypt_json(source.proxy_ciphertext.as_deref(), encrypt_key)
                .ok()
                .flatten()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default(),
        };
        let Ok(effective) = network_proxy.resolve(&local_proxy).await else {
            continue;
        };
        let Ok(client) = adapters::http_client(&effective, Duration::from_secs(15)) else {
            continue;
        };
        let adapter = Adapter::for_kind(source.kind);
        match adapter.probe(&client, &credential).await {
            Ok(mut capabilities) => {
                capabilities["quota_updated_at"] =
                    serde_json::json!(chrono::Utc::now().timestamp_millis());
                let _ = storage::update_capabilities(pool, source.id, &capabilities).await;
            }
            Err(error) => {
                warn!(
                    event = "FederationQuotaRefreshFailed", source_id = %source.id,
                    error_code = error.code, "联测源额度刷新失败"
                );
            }
        }
    }
}
