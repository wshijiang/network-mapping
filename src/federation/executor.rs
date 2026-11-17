//! 联测执行器：唯一执行者（搜索/Web 触发进程内 spawn，CLI 触发由 worker 认领）。
//!
//! 流程：翻译 AST → 每源并发拉取（限速/重试/会员降级）→ 归一化 + 残余过滤
//! → 跨源聚合去重（新者胜 + COALESCE + tech 并集）→ 入库决策 → ingest 写入。

use std::collections::{BTreeMap, HashMap};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use deadpool_postgres::Pool;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::dns_follow_up::DnsFollowUpConfig;
use crate::elasticsearch::ElasticsearchService;
use crate::federation::adapters::{self, Adapter, SearchRequest};
use crate::federation::model::{
    FieldSelection, NormalizedRecord, PageRequest, PaginationMode, SourceKind, WindowMode,
};
use crate::federation::policy::FederationPolicy;
use crate::federation::storage::{self, Run, Source};
use crate::federation::translate::{self, PlatformQuery};
use crate::federation::{FederationConfig, ingest};
use crate::handlers::search_dsl::{Expr, Field, parse_query_ast};
use crate::maxmind::MaxMindState;
use crate::network_proxy::GlobalProxyState;
use crate::outbound_proxy::{ProxyConfig, ProxyMode};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// 跨并发 run 共享的每源限速槽（source id → 下次可请求时刻）。
static SOURCE_SLOTS: LazyLock<Mutex<HashMap<Uuid, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn reserve_source_slot(source_id: Uuid, interval: Duration) -> Instant {
    let mut slots = SOURCE_SLOTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = Instant::now();
    let slot = slots
        .get(&source_id)
        .copied()
        .map_or(now, |next| next.max(now));
    slots.insert(source_id, slot + interval);
    slot
}

/// 同一数据源在多个并发 run 之间也必须满足 1/QPS，避免同时打满平台限速。
async fn wait_for_source_slot(source_id: Uuid, interval: Duration) {
    let slot = reserve_source_slot(source_id, interval);
    let delay = slot.saturating_duration_since(Instant::now());
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
}

pub struct Services {
    pub pool: Pool,
    pub maxmind: actix_web::web::Data<MaxMindState>,
    pub elasticsearch: actix_web::web::Data<ElasticsearchService>,
    pub dns_follow_up: DnsFollowUpConfig,
    pub network_proxy: GlobalProxyState,
    pub encrypt_key: String,
    pub pepper: String,
    pub config: FederationConfig,
}

/// 查询哈希：归一化查询 + 各源解析后时间窗 + 分页（冷却/在途去重键）。
pub fn compute_query_hash(
    query: &str,
    resolved_windows: &[(Uuid, Option<u32>)],
    local_limit: u32,
    local_offset: u32,
) -> String {
    let mut payload = format!("{}\u{1}{}\u{1}{}", query.trim(), local_limit, local_offset);
    let mut windows: Vec<String> = resolved_windows
        .iter()
        .map(|(id, window)| {
            format!(
                "{id}:{}",
                window
                    .map(|w| w.to_string())
                    .unwrap_or_else(|| "none".into())
            )
        })
        .collect();
    windows.sort();
    payload.push('\u{1}');
    payload.push_str(&windows.join(","));
    let digest = openssl::sha::sha256(payload.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// 每源时间窗解析（§8.6）：custom > none > follow(run 级)。
pub fn resolve_source_window(source: &Source, run_window: u32) -> Option<u32> {
    match source.window_mode {
        WindowMode::Custom => Some(source.window_days),
        WindowMode::None => None,
        WindowMode::Follow => Some(run_window),
    }
}

/// 会员能力是否允许远端时间过滤（probe 结果未知时保守不传）。
fn membership_allows_time(kind: SourceKind, capabilities: Option<&Value>) -> bool {
    match kind {
        SourceKind::Quake => capabilities
            .and_then(|caps| caps.get("role"))
            .and_then(Value::as_array)
            .is_some_and(|roles| {
                roles.iter().any(|role| {
                    role.get("fullname")
                        .and_then(Value::as_str)
                        .is_some_and(|name| {
                            name.contains("高级") || name.contains("终身") || name.contains("白金")
                        })
                })
            }),
        SourceKind::Fofa => capabilities
            .and_then(|caps| caps.get("isvip"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        _ => true,
    }
}

/// 入库决策（§10）。
pub fn persist_decision(policy: &FederationPolicy, run: &Run) -> (bool, &'static str) {
    if run.persist_override == "skip" {
        return (false, "disabled");
    }
    if run.persist_override == "force" {
        return (policy.persist.enabled, "manual");
    }
    if !policy.persist.enabled {
        return (false, "disabled");
    }
    match run.local_state.as_str() {
        "empty" if policy.persist.on_empty => (true, "on_empty"),
        "stale" if policy.persist.on_stale => (true, "on_stale"),
        "fresh" if policy.persist.on_fresh => (true, "on_fresh"),
        "empty" | "stale" | "fresh" => (false, "skipped_fresh"),
        _ => (true, "manual"),
    }
}

/// 跨源聚合去重（§9.2）：新者胜 + 空字段 COALESCE + tech 并集 + 来源累加；
/// 时间戳平局保留先者（源配置顺序）。
pub fn merge_records(records: Vec<NormalizedRecord>, max_records: usize) -> Vec<NormalizedRecord> {
    let mut merged: BTreeMap<String, NormalizedRecord> = BTreeMap::new();
    for record in records {
        let key = record.endpoint_key();
        match merged.get_mut(&key) {
            None => {
                merged.insert(key, record);
            }
            Some(existing) => {
                if record.observed_at > existing.observed_at {
                    let mut newer = record;
                    coalesce(&mut newer, existing);
                    union_tech(&mut newer, existing);
                    union_sources(&mut newer, existing);
                    *existing = newer;
                } else {
                    coalesce(existing, &record);
                    union_tech(existing, &record);
                    union_sources(existing, &record);
                }
            }
        }
    }
    let mut values: Vec<NormalizedRecord> = merged.into_values().collect();
    values.sort_by_key(|record| std::cmp::Reverse(record.observed_at));
    values.truncate(max_records);
    values
}

/// 用 other 的非空字段补 target 的空字段。
fn coalesce(target: &mut NormalizedRecord, other: &NormalizedRecord) {
    target.domain = target.domain.take().or_else(|| other.domain.clone());
    target.service = target.service.take().or_else(|| other.service.clone());
    target.title = target.title.take().or_else(|| other.title.clone());
    target.banner = target.banner.take().or_else(|| other.banner.clone());
    target.asn = target.asn.take().or_else(|| other.asn.clone());
    target.as_org = target.as_org.take().or_else(|| other.as_org.clone());
    target.isp = target.isp.take().or_else(|| other.isp.clone());
    target.country_name = target
        .country_name
        .take()
        .or_else(|| other.country_name.clone());
    target.region_name = target
        .region_name
        .take()
        .or_else(|| other.region_name.clone());
    target.city_name = target.city_name.take().or_else(|| other.city_name.clone());
    target.latitude = target.latitude.or(other.latitude);
    target.longitude = target.longitude.or(other.longitude);
}

fn union_tech(target: &mut NormalizedRecord, other: &NormalizedRecord) {
    for entry in &other.tech {
        if let Some(existing) = target.tech.iter_mut().find(|t| t.id == entry.id) {
            if existing.version.is_none() {
                existing.version = entry.version.clone();
            }
        } else if target.tech.len() < 64 {
            target.tech.push(entry.clone());
        }
    }
}

fn union_sources(target: &mut NormalizedRecord, other: &NormalizedRecord) {
    for source in &other.sources {
        if !target.sources.contains(source) {
            target.sources.push(source.clone());
        }
    }
}

struct SourceOutcome {
    detail: Value,
    records: Vec<NormalizedRecord>,
    completed: bool,
}

fn error_detail(source: &Source, code: &str, started: Instant) -> SourceOutcome {
    SourceOutcome {
        detail: json!({
            "source_id": source.id, "kind": source.kind.as_str(), "status": "error",
            "error_code": code, "duration_ms": started.elapsed().as_millis() as i64,
            "fetched": 0, "normalized": 0, "filtered_out": 0, "pages": 0,
        }),
        records: Vec::new(),
        completed: false,
    }
}

/// Shodan 免费 host 端点一次返回该 IP 的全部服务，只能表达“仅该 IP”的查询；
/// 带其他过滤条件的查询必须走 search 端点，否则会把不匹配的记录带回来。
fn free_single_ip(query: &str) -> Option<String> {
    use crate::handlers::search_dsl::{Expr, Field, Operator, parse_query_ast};
    let Expr::Predicate(predicate) = parse_query_ast(query).ok()? else {
        return None;
    };
    if !matches!(predicate.field, Field::Ip)
        || !matches!(predicate.operator, Operator::Eq | Operator::Colon)
        || predicate.values.len() != 1
    {
        return None;
    }
    predicate.values[0]
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| ip.to_string())
}

/// 残余谓词依赖的字段即使未配置输出，也必须归一化后才能本地过滤。
fn include_residual_fields(expr: &Expr, fields: &mut FieldSelection) {
    match expr {
        Expr::Predicate(predicate) => match predicate.field {
            Field::Domain => fields.domain = true,
            Field::Service => fields.service = true,
            Field::Technology => fields.tech = true,
            Field::Title => fields.title = true,
            Field::Banner => fields.banner = true,
            _ => {}
        },
        Expr::And(left, right) | Expr::Or(left, right) => {
            include_residual_fields(left, fields);
            include_residual_fields(right, fields);
        }
        Expr::Not(inner) | Expr::HasEndpoint(inner) => include_residual_fields(inner, fields),
    }
}

/// 仅用于残余过滤的字段在合并前清除，保持数据源字段配置语义。
fn strip_unselected_fields(record: &mut NormalizedRecord, fields: &FieldSelection) {
    if !fields.domain {
        record.domain = None;
    }
    if !fields.service {
        record.service = None;
    }
    if !fields.tech {
        record.tech.clear();
    }
    if !fields.title {
        record.title = None;
    }
    if !fields.banner {
        record.banner = None;
    }
}

/// 期望页大小：固定分页用配置值；跟随本地搜索用本地页大小，
/// 但同样受数据源“每页条数”上限约束，避免单次请求消耗过多平台额度。
fn desired_page_size(
    mode: PaginationMode,
    local_limit: u32,
    configured: u32,
    max_size: u32,
) -> u32 {
    match mode {
        PaginationMode::FollowLocal => local_limit.min(configured).clamp(1, max_size),
        PaginationMode::Fixed => configured.clamp(1, max_size),
    }
}

/// follow-local 分页需裁掉 offset 前的整页记录，并限制在本页窗口内。
fn local_page_window(
    pagination_mode: PaginationMode,
    local_offset: u32,
    local_limit: u32,
    first_page: u32,
    page_size: u32,
) -> (usize, usize) {
    match pagination_mode {
        PaginationMode::FollowLocal => {
            let page_start = u64::from(first_page) * u64::from(page_size);
            let trim = u64::from(local_offset).saturating_sub(page_start) as usize;
            (trim, local_limit as usize)
        }
        PaginationMode::Fixed => (0, usize::MAX),
    }
}

#[allow(clippy::too_many_lines)]
async fn run_source(
    services: &Services,
    source: &Source,
    run: &Run,
    policy: &FederationPolicy,
    expr: &Expr,
    worker_id: Uuid,
) -> SourceOutcome {
    let started = Instant::now();
    let adapter = Adapter::for_kind(source.kind);
    let capabilities = adapter.capabilities();
    let output_fields = FieldSelection::from_names(&source.fields);

    // 1. 翻译（不支持 → 跳过，不请求）。
    let query: PlatformQuery = match translate::translate(source.kind, expr, &output_fields) {
        Ok(query) => query,
        Err(reason) => {
            return SourceOutcome {
                detail: json!({
                    "source_id": source.id, "kind": source.kind.as_str(), "status": "unsupported",
                    "reason": reason, "duration_ms": started.elapsed().as_millis() as i64,
                    "fetched": 0, "normalized": 0, "filtered_out": 0, "pages": 0,
                }),
                records: Vec::new(),
                completed: false,
            };
        }
    };

    // 残余谓词依赖的字段即使不输出，也要拉取并归一化后用于本地过滤。
    let mut fields = output_fields.clone();
    if let Some(residual) = &query.residual {
        include_residual_fields(residual, &mut fields);
    }

    // 2. 凭据解密。
    let credential = match storage::decrypt_json(
        source.credential_ciphertext.as_deref(),
        &services.encrypt_key,
    ) {
        Ok(Some(credential)) => credential,
        _ => return error_detail(source, "credential_missing", started),
    };

    // 3. 代理解析（跟随全局/单独；全局不可用失败关闭）。
    let local_proxy = ProxyConfig {
        mode: source
            .proxy_mode
            .parse::<ProxyMode>()
            .unwrap_or(ProxyMode::System),
        url: storage::decrypt_json(source.proxy_ciphertext.as_deref(), &services.encrypt_key)
            .ok()
            .flatten()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default(),
    };
    let effective_proxy = match services.network_proxy.resolve(&local_proxy).await {
        Ok(proxy) => proxy,
        Err(error) => return error_detail(source, error.code, started),
    };
    let client = match adapters::http_client(
        &effective_proxy,
        Duration::from_secs(u64::from(source.timeout_seconds)),
    ) {
        Ok(client) => client,
        Err(error) => return error_detail(source, error.code, started),
    };

    // 4. 时间窗解析 + 会员 gating。
    let mut window = resolve_source_window(source, run.window_days);
    let mut time_filter = if window.is_some() { "applied" } else { "none" };
    if window.is_some()
        && matches!(source.kind, SourceKind::Quake | SourceKind::Fofa)
        && !membership_allows_time(source.kind, source.detected_capabilities.as_ref())
    {
        window = None;
        time_filter = "unavailable_membership";
    }
    if source.kind == SourceKind::Shodan && window.is_some() {
        time_filter = "local_only";
    }

    // 5. 分页计划（先按平台允许的页大小收敛，再计算页区间）。
    let max_size = capabilities.max_page_size;
    let desired_size = desired_page_size(
        source.pagination_mode,
        run.local_limit,
        source.page_size,
        max_size,
    );
    let page_size = match capabilities.page_size_choices {
        Some(choices) => choices
            .iter()
            .copied()
            .filter(|c| *c <= desired_size)
            .max()
            .unwrap_or(1),
        None => desired_size,
    };
    let (first_page, page_count) = match source.pagination_mode {
        PaginationMode::FollowLocal => {
            let first = run.local_offset / page_size;
            let last = (run.local_offset + run.local_limit - 1) / page_size;
            (first, (last - first + 1).min(source.max_pages))
        }
        PaginationMode::Fixed => (0, source.max_pages),
    };
    let (trim_leading, take_limit) = local_page_window(
        source.pagination_mode,
        run.local_offset,
        run.local_limit,
        first_page,
        page_size,
    );

    // 6. 逐页拉取（源内串行 + QPS 限速 + 重试/降级）。
    let interval = Duration::from_secs_f64(1.0 / source.rate_limit_qps.max(0.01));
    let mut records = Vec::new();
    let mut fetched = 0usize;
    let mut filtered_out = 0usize;
    let mut pages_done = 0u32;
    let mut quota: Option<Value> = None;
    let mut prompt: Option<String> = None;
    let mut field_override: Option<Vec<String>> = None;
    let mut downgraded = false;
    let mut last_error: Option<String> = None;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let tolerance_ms = services.config.observed_at_future_tolerance_seconds as i64 * 1000;
    let time_cutoff = window.map(|days| now_ms - i64::from(days) * 86_400_000);
    let single_ip = if capabilities.single_ip_free_endpoint {
        free_single_ip(&run.query_text)
    } else {
        None
    };
    let mut skipped = 0usize;
    let mut consumed = 0usize;

    'pages: for page_index in first_page..first_page + page_count {
        // 取消检查点。
        if let Ok(Some(current)) = storage::get_run(&services.pool, run.id).await
            && current.status != "running"
        {
            break 'pages;
        }
        let _ = storage::renew_lease(
            &services.pool,
            run.id,
            worker_id,
            services.config.lease_seconds as i64 * 1000,
        )
        .await;
        wait_for_source_slot(source.id, interval).await;
        let request = SearchRequest {
            query: &query,
            page: PageRequest {
                index: page_index,
                size: page_size,
            },
            window_days: window,
            fields: &fields,
            single_ip: single_ip.clone(),
            field_override: field_override.clone(),
        };
        let mut attempt = 0u32;
        let page = loop {
            match adapter.search(&client, &credential, &request).await {
                Ok(page) => break page,
                Err(error) => {
                    // 会员字段权限 → 降级重试一次。
                    if error.code == "field_permission" && !downgraded {
                        downgraded = true;
                        field_override = Some(match source.kind {
                            SourceKind::Quake => adapters::quake::BASIC_INCLUDE
                                .iter()
                                .map(|s| (*s).to_owned())
                                .collect(),
                            SourceKind::Fofa => adapters::fofa::basic_fields(&fields),
                            _ => Vec::new(),
                        });
                        continue;
                    }
                    // FOFA 字段权限错误归类为 query_rejected：降级重试一次。
                    if error.code == "query_rejected"
                        && source.kind == SourceKind::Fofa
                        && !downgraded
                    {
                        downgraded = true;
                        field_override = Some(adapters::fofa::basic_fields(&fields));
                        continue;
                    }
                    if error.retryable && attempt < 2 {
                        attempt += 1;
                        let backoff =
                            if source.kind == SourceKind::Quake && error.code == "rate_limited" {
                                Duration::from_secs(15)
                            } else {
                                Duration::from_secs(2u64.pow(attempt))
                            };
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    last_error = Some(error.code.to_owned());
                    break 'pages;
                }
            }
        };
        pages_done += 1;
        fetched += page.records.len();
        if page.quota.is_some() {
            quota = page.quota;
        }
        if page.prompt.is_some() {
            prompt = page.prompt;
        }
        let empty = page.records.is_empty();
        for raw in &page.records {
            // follow-local：整页结果裁掉 offset 前的记录，并限制在本页窗口内。
            if skipped < trim_leading {
                skipped += 1;
                continue;
            }
            if consumed >= take_limit {
                break;
            }
            consumed += 1;
            let Some(mut record) = adapter.normalize(raw, &fields, now_ms, tolerance_ms) else {
                filtered_out += 1;
                continue;
            };
            // 残余谓词精过滤（§5.5）。
            if let Some(residual) = &query.residual
                && !translate::eval_residual(residual, &record)
            {
                filtered_out += 1;
                continue;
            }
            // Shodan 本地时间过滤（无远端过滤器）。
            if source.kind == SourceKind::Shodan
                && let Some(cutoff) = time_cutoff
                && !record.timestamp_inferred
                && record.observed_at < cutoff
            {
                filtered_out += 1;
                continue;
            }
            // 仅用于残余过滤的字段不参与合并。
            strip_unselected_fields(&mut record, &output_fields);
            records.push(record);
        }
        if consumed >= take_limit {
            break 'pages;
        }
        // 单 IP host 端点一次返回全部；空页即止。
        if single_ip.is_some() || empty {
            break 'pages;
        }
        if records.len() >= policy.max_records_per_run as usize {
            break 'pages;
        }
    }

    let status = if last_error.is_some() && pages_done == 0 {
        "error"
    } else if last_error.is_some() {
        "partial"
    } else {
        "completed"
    };
    SourceOutcome {
        detail: json!({
            "source_id": source.id, "kind": source.kind.as_str(), "status": status,
            "error_code": last_error, "duration_ms": started.elapsed().as_millis() as i64,
            "fetched": fetched, "normalized": records.len(), "filtered_out": filtered_out,
            "pages": pages_done, "platform_query": query.text,
            "version_ignored": query.version_ignored,
            "window_days": window, "window_mode": source.window_mode, "time_filter": time_filter,
            "quota": quota, "prompt": prompt,
        }),
        records,
        completed: status == "completed",
    }
}

/// run 终态判定：全部源均不支持该语句时记为“未查询”（unsupported），不是执行错误。
fn run_status(
    any_completed: bool,
    any_error: bool,
    all_unsupported: bool,
    total_persisted: usize,
    persist_failed: bool,
) -> &'static str {
    if any_completed && !any_error && !persist_failed {
        "completed"
    } else if any_completed || total_persisted > 0 {
        "partial"
    } else if all_unsupported && !persist_failed {
        "unsupported"
    } else {
        "failed"
    }
}

/// 执行一个 run（调用方已置 running + 租约）。
pub async fn execute_run(
    services: &Services,
    run: &Run,
    worker_id: Uuid,
    policy: &FederationPolicy,
) -> Result<()> {
    let sources = storage::list_sources(&services.pool).await?;
    let selected: Vec<Source> = sources
        .into_iter()
        .filter(|source| source.enabled)
        .filter(|source| {
            run.selected_sources
                .as_ref()
                .is_none_or(|ids| ids.contains(&source.id))
        })
        .collect();
    if selected.is_empty() {
        storage::finish_run(
            &services.pool,
            run.id,
            "failed",
            &json!([]),
            0,
            0,
            0,
            None,
            Some(&json!({"enabled": false, "reason": "no_sources"})),
            Some("没有可用的启用数据源"),
        )
        .await?;
        return Ok(());
    }
    let expr: Expr = match parse_query_ast(&run.query_text) {
        Ok(expr) => expr,
        Err(error) => {
            storage::finish_run(
                &services.pool,
                run.id,
                "failed",
                &json!([]),
                0,
                0,
                0,
                None,
                Some(&json!({"enabled": false, "reason": "invalid_query"})),
                Some(&error.message),
            )
            .await?;
            return Ok(());
        }
    };

    // 各源并发（源内串行限速）。
    let outcomes = futures_util::future::join_all(
        selected
            .iter()
            .map(|source| run_source(services, source, run, policy, &expr, worker_id)),
    )
    .await;

    let mut all_records = Vec::new();
    let mut details = Vec::new();
    let mut any_completed = false;
    let mut any_error = false;
    for outcome in outcomes {
        any_completed |= outcome.completed;
        any_error |= !outcome.completed
            && outcome.detail.get("status").and_then(Value::as_str) == Some("error");
        all_records.extend(outcome.records);
        details.push(outcome.detail);
    }
    let total_fetched: usize = details
        .iter()
        .filter_map(|d| d.get("fetched").and_then(Value::as_u64))
        .sum::<u64>() as usize;
    let merged = merge_records(all_records, policy.max_records_per_run as usize);
    let total_merged = merged.len();

    // 入库决策与写入。
    let (should_persist, reason) = persist_decision(policy, run);
    let decision = json!({"enabled": should_persist, "reason": reason});
    let mut total_persisted = 0usize;
    let mut persist_error: Option<String> = None;
    if should_persist && !merged.is_empty() {
        match persist_records(services, run, &merged).await {
            Ok(count) => total_persisted = count,
            Err(error) => {
                tracing::warn!(event = "FederationPersistFailed", run_id = %run.id, %error, "联测入库失败");
                persist_error = Some(error.to_string());
            }
        }
    }

    let all_unsupported = !details.is_empty()
        && details
            .iter()
            .all(|d| d.get("status").and_then(Value::as_str) == Some("unsupported"));
    let status = run_status(
        any_completed,
        any_error,
        all_unsupported,
        total_persisted,
        persist_error.is_some(),
    );
    let cache = serde_json::to_value(&merged)?;
    storage::finish_run(
        &services.pool,
        run.id,
        status,
        &Value::Array(details),
        total_fetched as i32,
        total_merged as i32,
        total_persisted as i32,
        Some(&cache),
        Some(&decision),
        persist_error.as_deref(),
    )
    .await?;
    tracing::info!(
        event = "FederationRunFinished", run_id = %run.id, status,
        total_fetched, total_merged, total_persisted, "联测 run 完成"
    );
    Ok(())
}

async fn persist_records(
    services: &Services,
    run: &Run,
    records: &[NormalizedRecord],
) -> Result<usize> {
    let token =
        ingest::ensure_federation_scanner(&services.pool, &services.encrypt_key, &services.pepper)
            .await?;
    let link = ingest::ensure_scan_task(&services.pool, run.id, run.requested_by).await?;
    let mut written = 0usize;
    let chunks: Vec<&[NormalizedRecord]> = records.chunks(ingest::ES_BATCH_MAX).collect();
    for (index, chunk) in chunks.iter().enumerate() {
        let observations: Vec<_> = chunk
            .iter()
            .map(|record| ingest::build_observation(&ingest::record_to_row(record)))
            .collect();
        let is_final = index == chunks.len() - 1;
        ingest::write_es_batch(
            &services.pool,
            &services.maxmind,
            &services.elasticsearch,
            &services.dns_follow_up,
            &link,
            index as i32,
            is_final,
            observations,
            &token,
            &services.pepper,
        )
        .await?;
        written += chunk.len();
    }
    storage::link_scan_task(
        &services.pool,
        run.id,
        link.scan_task_db_id,
        link.execution_db_id,
        link.upload_id,
    )
    .await?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_import::csv::TechEntry;
    use crate::federation::policy::{FederationPolicy, PersistPolicy};

    fn record(ip: &str, port: u16, observed_at: i64, source: &str) -> NormalizedRecord {
        NormalizedRecord {
            ip: ip.into(),
            port,
            protocol: "tcp".into(),
            domain: None,
            service: None,
            tech: vec![],
            title: None,
            banner: None,
            observed_at,
            timestamp_inferred: false,
            asn: None,
            as_org: None,
            isp: None,
            country_name: None,
            region_name: None,
            city_name: None,
            latitude: None,
            longitude: None,
            sources: vec![source.into()],
        }
    }

    #[test]
    fn free_single_ip_only_for_exact_ip_queries() {
        assert_eq!(
            free_single_ip("ip = \"1.1.1.1\"").as_deref(),
            Some("1.1.1.1")
        );
        assert_eq!(
            free_single_ip("ip = \"2001:0db8::1\"").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(free_single_ip("ip = \"1.1.1.1\" AND port = 443"), None);
        assert_eq!(free_single_ip("domain = \"example.com\""), None);
        assert_eq!(free_single_ip("ip IN (\"1.1.1.1\", \"1.1.1.2\")"), None);
    }

    #[test]
    fn source_slots_are_shared_and_spaced() {
        let source_id = Uuid::new_v4();
        let interval = Duration::from_millis(50);
        let first = reserve_source_slot(source_id, interval);
        let second = reserve_source_slot(source_id, interval);
        assert!(second.duration_since(first) >= interval);
    }

    #[test]
    fn residual_fields_are_normalized_then_stripped() {
        let expr = parse_query_ast("domain = \"example.com\" OR service = \"https\"").unwrap();
        let mut fields = FieldSelection {
            domain: false,
            service: false,
            tech: false,
            title: false,
            banner: false,
        };
        let output = fields.clone();
        include_residual_fields(&expr, &mut fields);
        assert!(fields.domain && fields.service);

        let mut record = record("1.1.1.1", 443, 100, "quake");
        record.domain = Some("example.com".into());
        record.service = Some("https".into());
        strip_unselected_fields(&mut record, &output);
        assert!(record.domain.is_none());
        assert!(record.service.is_none());
    }

    #[test]
    fn follow_local_window_trims_offset_and_limits_page() {
        assert_eq!(
            local_page_window(PaginationMode::FollowLocal, 25, 50, 0, 50),
            (25, 50)
        );
        assert_eq!(
            local_page_window(PaginationMode::FollowLocal, 50, 50, 1, 50),
            (0, 50)
        );
        assert_eq!(
            local_page_window(PaginationMode::Fixed, 25, 50, 0, 50),
            (0, usize::MAX)
        );
    }

    #[test]
    fn merge_latest_wins_with_coalesce_and_tech_union() {
        let mut older = record("1.1.1.1", 443, 100, "fofa");
        older.service = Some("https".into());
        older.tech = vec![TechEntry {
            id: "nginx".into(),
            version: Some("1.20".into()),
        }];
        let mut newer = record("1.1.1.1", 443, 200, "quake");
        newer.title = Some("New".into());
        newer.tech = vec![
            TechEntry {
                id: "nginx".into(),
                version: Some("1.25".into()),
            },
            TechEntry {
                id: "jquery".into(),
                version: None,
            },
        ];
        let merged = merge_records(vec![older, newer], 100);
        assert_eq!(merged.len(), 1);
        let item = &merged[0];
        assert_eq!(item.observed_at, 200);
        assert_eq!(item.service.as_deref(), Some("https")); // COALESCE from older
        assert_eq!(item.title.as_deref(), Some("New"));
        assert_eq!(item.tech.len(), 2);
        assert_eq!(item.sources, vec!["quake".to_owned(), "fofa".to_owned()]);
    }

    #[test]
    fn merge_tie_keeps_first_and_truncates() {
        let a = record("1.1.1.1", 80, 100, "hunter");
        let b = record("1.1.1.1", 80, 100, "fofa");
        let merged = merge_records(vec![a, b], 100);
        assert_eq!(
            merged[0].sources,
            vec!["hunter".to_owned(), "fofa".to_owned()]
        );
        let many: Vec<_> = (0..10i64)
            .map(|i| record("1.1.1.1", 80 + i as u16, i, "fofa"))
            .collect();
        assert_eq!(merge_records(many, 5).len(), 5);
    }

    #[test]
    fn persist_decision_table() {
        let policy = FederationPolicy::default();
        let mut run = Run {
            id: Uuid::now_v7(),
            query_text: String::new(),
            query_hash: String::new(),
            trigger: "search".into(),
            mode: "async".into(),
            status: "running".into(),
            requested_by: 1,
            window_days: 30,
            local_state: "empty".into(),
            selected_sources: None,
            local_limit: 50,
            local_offset: 0,
            persist_override: "auto".into(),
            sources: json!([]),
            total_fetched: 0,
            total_merged: 0,
            total_persisted: 0,
            result_cache: None,
            persist_decision: None,
            error_message: None,
            created_at: chrono::Utc::now(),
            started_at: None,
            finished_at: None,
        };
        assert_eq!(persist_decision(&policy, &run), (true, "on_empty"));
        run.local_state = "stale".into();
        assert_eq!(persist_decision(&policy, &run), (true, "on_stale"));
        run.local_state = "fresh".into();
        assert_eq!(persist_decision(&policy, &run), (false, "skipped_fresh"));
        run.persist_override = "force".into();
        assert_eq!(persist_decision(&policy, &run), (true, "manual"));
        run.persist_override = "skip".into();
        assert_eq!(persist_decision(&policy, &run), (false, "disabled"));
        let mut off = policy.clone();
        off.persist = PersistPolicy {
            enabled: false,
            on_empty: true,
            on_stale: true,
            on_fresh: true,
        };
        run.persist_override = "auto".into();
        run.local_state = "empty".into();
        assert_eq!(persist_decision(&off, &run), (false, "disabled"));
    }

    #[test]
    fn window_resolution_priority() {
        let mut source = Source {
            id: Uuid::now_v7(),
            kind: SourceKind::Hunter,
            name: "t".into(),
            enabled: true,
            credential_ciphertext: None,
            proxy_mode: "system".into(),
            proxy_ciphertext: None,
            fields: vec![],
            pagination_mode: crate::federation::model::PaginationMode::FollowLocal,
            page_size: 100,
            max_pages: 5,
            window_mode: WindowMode::Follow,
            window_days: 30,
            timeout_seconds: 15,
            rate_limit_qps: 1.0,
            detected_capabilities: None,
            revision: 1,
        };
        assert_eq!(resolve_source_window(&source, 45), Some(45));
        source.window_mode = WindowMode::None;
        assert_eq!(resolve_source_window(&source, 45), None);
        source.window_mode = WindowMode::Custom;
        source.window_days = 7;
        assert_eq!(resolve_source_window(&source, 45), Some(7));
    }

    #[test]
    fn membership_time_gating() {
        assert!(!membership_allows_time(SourceKind::Quake, None));
        let basic = json!({"role": [{"fullname": "注册用户"}]});
        assert!(!membership_allows_time(SourceKind::Quake, Some(&basic)));
        let advanced = json!({"role": [{"fullname": "高级会员"}]});
        assert!(membership_allows_time(SourceKind::Quake, Some(&advanced)));
        assert!(!membership_allows_time(
            SourceKind::Fofa,
            Some(&json!({"isvip": false}))
        ));
        assert!(membership_allows_time(
            SourceKind::Fofa,
            Some(&json!({"isvip": true}))
        ));
        assert!(membership_allows_time(SourceKind::Hunter, None));
    }

    #[test]
    fn follow_local_page_size_capped_by_source_config() {
        // 跟随本地搜索也受“每页条数”上限约束，避免一次拉满 100 条消耗额度。
        assert_eq!(
            desired_page_size(PaginationMode::FollowLocal, 100, 10, 100),
            10
        );
        assert_eq!(
            desired_page_size(PaginationMode::FollowLocal, 5, 10, 100),
            5
        );
        assert_eq!(desired_page_size(PaginationMode::Fixed, 100, 10, 100), 10);
        assert_eq!(desired_page_size(PaginationMode::Fixed, 100, 500, 100), 100);
    }

    #[test]
    fn unsupported_query_is_not_an_error() {
        // 全部源不支持 → 未查询；有真实错误或入库失败仍按原口径。
        assert_eq!(run_status(false, false, true, 0, false), "unsupported");
        assert_eq!(run_status(false, true, false, 0, false), "failed");
        assert_eq!(run_status(true, false, false, 0, false), "completed");
        assert_eq!(run_status(true, true, false, 0, false), "partial");
        assert_eq!(run_status(true, false, false, 3, true), "partial");
        assert_eq!(run_status(false, false, false, 0, false), "failed");
    }

    #[test]
    fn query_hash_includes_windows_and_pagination() {
        let id = Uuid::now_v7();
        let a = compute_query_hash("ip = \"1.1.1.1\"", &[(id, Some(30))], 50, 0);
        let b = compute_query_hash("ip = \"1.1.1.1\"", &[(id, Some(60))], 50, 0);
        let c = compute_query_hash("ip = \"1.1.1.1\"", &[(id, Some(30))], 50, 50);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
