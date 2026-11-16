//! 搜索路径联测集成（§7/§8）：触发评估、run 创建与进程内执行、异步/阻塞合流。
//!
//! 挂在 `respond_search_elasticsearch` 唯一收口处；仅管理员触发（决策 §3.5）。
//! 展示合并在 handlers/search.rs 的 SearchItem 层完成。

use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::Pool;
use futures_util::FutureExt;
use serde_json::Value;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::dns_follow_up::DnsFollowUpConfig;
use crate::elasticsearch::{ElasticsearchService, SearchSort};
use crate::federation::FederationConfig;
use crate::federation::executor::{self, Services};
use crate::federation::model::NormalizedRecord;
use crate::federation::policy::{FederationMode, FederationPolicy, FederationTrigger};
use crate::federation::storage::{self, Run};
use crate::federation::translate;
use crate::handlers::search_dsl::parse_query_ast;
use crate::maxmind::MaxMindState;
use crate::network_proxy::GlobalProxyState;
use crate::runtime_config::RuntimeConfig;
use crate::system_maintenance::SystemMaintenanceState;

/// 进程内联测服务（app_data 注册）。
#[derive(Clone)]
pub struct FederationService {
    pub pool: Pool,
    pub config: FederationConfig,
    pub policy: RuntimeConfig<FederationPolicy>,
    pub maxmind: actix_web::web::Data<MaxMindState>,
    pub elasticsearch: actix_web::web::Data<ElasticsearchService>,
    pub dns_follow_up: RuntimeConfig<DnsFollowUpConfig>,
    pub maintenance: actix_web::web::Data<SystemMaintenanceState>,
    pub network_proxy: GlobalProxyState,
    pub encrypt_key: String,
    pub pepper: String,
    /// 并发 run 闸门（上限 16；策略 max_concurrent_runs 在触发时校验）。
    pub run_gate: Arc<Semaphore>,
}

impl FederationService {
    async fn services(&self) -> Services {
        Services {
            pool: self.pool.clone(),
            maxmind: self.maxmind.clone(),
            elasticsearch: self.elasticsearch.clone(),
            dns_follow_up: self.dns_follow_up.get().await.value.clone(),
            network_proxy: self.network_proxy.clone(),
            encrypt_key: self.encrypt_key.clone(),
            pepper: self.pepper.clone(),
            config: self.config.clone(),
        }
    }
}

/// 触发评估结果（本地状态）。
pub fn evaluate_local_state(
    policy: &FederationPolicy,
    local_total: i64,
    max_last_seen_ms: Option<i64>,
    now_ms: i64,
) -> Option<&'static str> {
    if local_total == 0 {
        return Some("empty");
    }
    let cutoff = now_ms - i64::from(policy.stale_days) * 86_400_000;
    match max_last_seen_ms {
        Some(last_seen) if last_seen < cutoff => Some("stale"),
        _ => Some("fresh"),
    }
}

/// 字段触发判定（§5.4）：trigger_fields 为空 = 任意；否则交集非空。
pub fn fields_match(policy: &FederationPolicy, query: &str) -> bool {
    if policy.trigger_fields.is_empty() {
        return true;
    }
    let Ok(expr) = parse_query_ast(query) else {
        return false;
    };
    let fields = translate::collect_fields(&expr);
    fields
        .iter()
        .any(|field| policy.trigger_fields.iter().any(|f| f == field))
}

pub enum Prepared {
    NotTriggered,
    /// 新建 run，进程内执行中。
    Run {
        run_id: Uuid,
        mode: FederationMode,
        join: JoinHandle<()>,
        budget: Duration,
    },
    /// 冷却窗口内复用缓存。
    Cached {
        run_id: Uuid,
        records: Vec<NormalizedRecord>,
    },
    /// 在途去重：挂接已有 run。
    Attached {
        run_id: Uuid,
    },
}

pub struct FederationOutcome {
    pub run_id: Uuid,
    pub status: String,
    pub mode: String,
    pub records: Vec<NormalizedRecord>,
}

/// 搜索前触发评估 + 创建 run（与本地搜索并行）。
pub async fn prepare(
    service: &FederationService,
    user_id: i32,
    user_role: i32,
    query: &str,
    filter: Value,
    limit: u32,
    offset: u32,
) -> Prepared {
    if !service.config.enabled || user_role != 1 {
        return Prepared::NotTriggered;
    }
    let policy = service.policy.get().await.value;
    if !policy.enabled || !fields_match(&policy, query) {
        return Prepared::NotTriggered;
    }
    if service.maintenance.snapshot().await.blocks_new_work() {
        return Prepared::NotTriggered;
    }
    let Ok(sources) = storage::list_sources(&service.pool).await else {
        return Prepared::NotTriggered;
    };
    let enabled: Vec<_> = sources.into_iter().filter(|s| s.enabled).collect();
    if enabled.is_empty() {
        return Prepared::NotTriggered;
    }

    // 新鲜度探测（size=1，last_seen desc；与主搜索同 filter，本地 ES 代价可忽略）。
    let probe = service
        .elasticsearch
        .search(user_role, user_id, filter, 1, 0, SearchSort::default())
        .await;
    let Ok(page) = probe else {
        return Prepared::NotTriggered;
    };
    let now_ms = chrono::Utc::now().timestamp_millis();
    let max_last_seen = page.items.first().map(|item| item.scan_time);
    let Some(local_state) = evaluate_local_state(&policy, page.total, max_last_seen, now_ms) else {
        return Prepared::NotTriggered;
    };
    if policy.trigger == FederationTrigger::EmptyOrStale && local_state == "fresh" {
        return Prepared::NotTriggered;
    }

    // 查询哈希（含各源解析后时间窗 + 分页）。
    let resolved: Vec<(Uuid, Option<u32>)> = enabled
        .iter()
        .map(|source| {
            (
                source.id,
                executor::resolve_source_window(source, policy.query_window_days),
            )
        })
        .collect();
    let query_hash = executor::compute_query_hash(query, &resolved, limit, offset);

    // 在途去重 → 冷却复用 → 并发上限。
    if let Ok(Some(running)) = storage::running_run_by_hash(&service.pool, &query_hash).await {
        return Prepared::Attached { run_id: running.id };
    }
    if policy.cooldown_seconds > 0
        && let Ok(Some(recent)) =
            storage::recent_run_by_hash(&service.pool, &query_hash, policy.cooldown_seconds).await
    {
        return Prepared::Cached {
            run_id: recent.id,
            records: records_from_run(&recent),
        };
    }
    if let Ok(active) = storage::count_active_runs(&service.pool).await
        && active >= i64::from(policy.max_concurrent_runs)
    {
        return Prepared::NotTriggered;
    }
    let Ok(permit) = service.run_gate.clone().try_acquire_owned() else {
        return Prepared::NotTriggered;
    };

    let worker_id = Uuid::new_v4();
    let run = match storage::create_run(
        &service.pool,
        storage::NewRun {
            query_text: query,
            query_hash: &query_hash,
            trigger: "search",
            mode: match policy.mode {
                FederationMode::Async => "async",
                FederationMode::Blocking => "blocking",
            },
            requested_by: user_id,
            window_days: policy.query_window_days,
            local_state,
            selected_sources: None,
            local_limit: limit,
            local_offset: offset,
            persist_override: "auto",
            status: "running",
            worker_id: Some(worker_id),
            lease_ms: service.config.lease_seconds as i64 * 1000,
        },
    )
    .await
    {
        Ok(run) => run,
        Err(error) => {
            tracing::warn!(event = "FederationRunCreateFailed", %error, "创建联测 run 失败");
            return Prepared::NotTriggered;
        }
    };

    let services = service.services().await;
    let run_id = run.id;
    let run_policy = policy.clone();
    let join = tokio::spawn(async move {
        let _permit = permit;
        if let Err(error) = executor::execute_run(&services, &run, worker_id, &run_policy).await {
            tracing::warn!(event = "FederationRunFailed", run_id = %run_id, %error, "联测 run 执行失败");
            let _ = storage::finish_run(
                &services.pool,
                run_id,
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
    });
    Prepared::Run {
        run_id,
        mode: policy.mode,
        join,
        budget: Duration::from_secs(policy.blocking_timeout_seconds),
    }
}

/// 本地搜索完成后合流：async 立即返回（已完成则并入），blocking 等待预算。
pub async fn resolve(service: &FederationService, prepared: Prepared) -> Option<FederationOutcome> {
    match prepared {
        Prepared::NotTriggered => None,
        Prepared::Cached { run_id, records } => Some(FederationOutcome {
            run_id,
            status: "cached".into(),
            mode: "async".into(),
            records,
        }),
        Prepared::Attached { run_id } => Some(FederationOutcome {
            run_id,
            status: "running".into(),
            mode: "async".into(),
            records: Vec::new(),
        }),
        Prepared::Run {
            run_id,
            mode,
            join,
            budget,
        } => {
            let completed = match mode {
                FederationMode::Async => join.now_or_never().is_some(),
                FederationMode::Blocking => tokio::time::timeout(budget, join).await.is_ok(),
            };
            let run = storage::get_run(&service.pool, run_id).await.ok().flatten();
            let (status, records) = match run {
                Some(run) if completed => (run.status.clone(), records_from_run(&run)),
                // 终态（含 unsupported/failed/cancelled）即使 join 尚未完成也按持久化状态返回，
                // 避免异步竞态下把已结束的 run 报成 running/timeout。
                Some(run)
                    if matches!(
                        run.status.as_str(),
                        "completed" | "partial" | "unsupported" | "failed" | "cancelled"
                    ) =>
                {
                    (run.status.clone(), records_from_run(&run))
                }
                Some(_) if mode == FederationMode::Blocking => ("timeout".into(), Vec::new()),
                Some(_) => ("running".into(), Vec::new()),
                None => ("unknown".into(), Vec::new()),
            };
            Some(FederationOutcome {
                run_id,
                status,
                mode: match mode {
                    FederationMode::Async => "async".into(),
                    FederationMode::Blocking => "blocking".into(),
                },
                records,
            })
        }
    }
}

pub fn records_from_run(run: &Run) -> Vec<NormalizedRecord> {
    run.result_cache
        .as_ref()
        .and_then(|cache| serde_json::from_value(cache.clone()).ok())
        .unwrap_or_default()
}

/// 搜索响应 federation 状态字段。
pub fn outcome_json(outcome: &FederationOutcome, merged_new: usize) -> Value {
    serde_json::json!({
        "run_id": outcome.run_id,
        "status": outcome.status,
        "mode": outcome.mode,
        "merged_new": merged_new,
        "records_available": !outcome.records.is_empty(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_state_evaluation() {
        let policy = FederationPolicy::default(); // stale_days=60
        let now = 1_000_000_000_000i64;
        assert_eq!(evaluate_local_state(&policy, 0, None, now), Some("empty"));
        let old = now - 61 * 86_400_000;
        assert_eq!(
            evaluate_local_state(&policy, 5, Some(old), now),
            Some("stale")
        );
        let recent = now - 10 * 86_400_000;
        assert_eq!(
            evaluate_local_state(&policy, 5, Some(recent), now),
            Some("fresh")
        );
        // 边界：恰好 60 天视为新鲜
        let boundary = now - 60 * 86_400_000;
        assert_eq!(
            evaluate_local_state(&policy, 5, Some(boundary), now),
            Some("fresh")
        );
    }

    #[test]
    fn trigger_fields_matching() {
        let mut policy = FederationPolicy::default();
        assert!(fields_match(&policy, "tag = \"prod\"")); // 空 = 任意
        policy.trigger_fields = vec!["ip".into(), "domain".into()];
        assert!(fields_match(&policy, "ip = \"1.1.1.1\" AND tag = \"prod\""));
        assert!(!fields_match(&policy, "tag = \"prod\""));
        assert!(fields_match(&policy, "domain = \"example.com\""));
        assert!(!fields_match(&policy, "port = 443"));
    }
}
