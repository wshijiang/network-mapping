pub(crate) mod search;

use std::net::{Ipv4Addr, Ipv6Addr};

use actix_web::{HttpResponse, Responder, get, web};
use deadpool_postgres::Pool;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::Serialize;
use serde_json::{Value, json};
use tracing::{error, info};
use uuid::Uuid;

use crate::admin::get_default_scan_profile_from_database;
use crate::audit::{AuditContext, AuditEvent, write as write_audit};
use crate::config::AutomaticTargetConfig;
use crate::runtime_config::RuntimeConfig;
use crate::scan_control::creation::build_scan_plan;

const STRATEGY: &str = "sequential_subnet";
const SYSTEM_REQUEST_PATH: &str = "system://automatic-target-generator";
const MANDATORY_IPV4_EXCLUSIONS: &[&str] = &["0.0.0.0/8"];

#[derive(Clone, Debug)]
struct FamilyGenerator {
    family: &'static str,
    enabled: bool,
    pools: Vec<IpNet>,
    excluded: Vec<IpNet>,
    task_prefix: u8,
    low_watermark: u32,
    high_watermark: u32,
    total_subnets: u128,
    state_key: String,
    policy_hash: String,
}

#[derive(Clone, Debug)]
pub struct AutomaticTargetService {
    policy: AutomaticTargetConfig,
    generators: Vec<FamilyGenerator>,
}

#[derive(Debug, Default, Serialize)]
pub struct RefillReport {
    pub pending_before: i64,
    pub pending_after: i64,
    pub generated: usize,
    pub skipped_recent: usize,
    pub skipped_excluded: usize,
    pub scanner_available: bool,
    pub families: Vec<FamilyRefillReport>,
}

#[derive(Debug, Default, Serialize)]
pub struct FamilyRefillReport {
    address_family: String,
    pending_before: i64,
    pending_after: i64,
    generated: usize,
    skipped_recent: usize,
    skipped_excluded: usize,
    scanner_available: bool,
}

#[derive(Debug)]
struct GeneratedTarget {
    cidr: String,
    generation_key: String,
    pool: String,
    position: u128,
}

#[derive(Debug, Serialize)]
struct FamilyStatus {
    address_family: String,
    enabled: bool,
    authorized_cidrs: Vec<String>,
    excluded_cidrs: Vec<String>,
    task_prefix: u8,
    pending_low_watermark: u32,
    pending_high_watermark: u32,
    pending_tasks: i64,
    running_tasks: i64,
    ready_scanners: i64,
    cursor_position: Value,
    total_subnets: Value,
    last_generated_at: Option<String>,
    last_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AutomaticTargetStatus {
    enabled: bool,
    strategy: String,
    default_scan_profile: String,
    common_ports: String,
    repeat_after_seconds: u64,
    families: Vec<FamilyStatus>,
}

impl AutomaticTargetService {
    pub fn new(
        policy: AutomaticTargetConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        policy
            .validate()
            .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> {
                error.to_string().into()
            })?;
        let ipv4_pools = policy
            .authorized_cidrs
            .iter()
            .map(|value| value.parse::<Ipv4Net>().map(IpNet::V4))
            .collect::<Result<Vec<_>, _>>()?;
        let ipv6_pools = policy
            .ipv6_authorized_cidrs
            .iter()
            .map(|value| value.parse::<Ipv6Net>().map(IpNet::V6))
            .collect::<Result<Vec<_>, _>>()?;
        let mut ipv4_excluded = policy
            .excluded_cidrs
            .iter()
            .map(|value| value.parse::<Ipv4Net>().map(IpNet::V4))
            .collect::<Result<Vec<_>, _>>()?;
        for value in MANDATORY_IPV4_EXCLUSIONS {
            let network = IpNet::V4(
                value
                    .parse::<Ipv4Net>()
                    .expect("mandatory IPv4 exclusion is a valid CIDR"),
            );
            if !ipv4_excluded.contains(&network) {
                ipv4_excluded.push(network);
            }
        }
        let ipv6_excluded = policy
            .ipv6_excluded_cidrs
            .iter()
            .map(|value| value.parse::<Ipv6Net>().map(IpNet::V6))
            .collect::<Result<Vec<_>, _>>()?;
        let generators = vec![
            family_generator(
                "ipv4",
                policy.enabled,
                ipv4_pools,
                ipv4_excluded,
                policy.ipv4_task_prefix,
                policy.pending_low_watermark,
                policy.pending_high_watermark,
                &policy,
            ),
            family_generator(
                "ipv6",
                policy.ipv6_enabled,
                ipv6_pools,
                ipv6_excluded,
                policy.ipv6_task_prefix,
                policy.ipv6_pending_low_watermark,
                policy.ipv6_pending_high_watermark,
                &policy,
            ),
        ];
        Ok(Self { policy, generators })
    }

    pub fn enabled(&self) -> bool {
        self.generators.iter().any(|generator| generator.enabled)
    }

    pub fn interval_seconds(&self) -> u64 {
        self.policy.interval_seconds
    }

    pub async fn refill(
        &self,
        pool: &Pool,
    ) -> Result<RefillReport, Box<dyn std::error::Error + Send + Sync>> {
        let scan_profile = get_default_scan_profile_from_database(pool).await?;
        let scan_plan = build_scan_plan(&scan_profile)
            .map_err(|message| -> Box<dyn std::error::Error + Send + Sync> { message.into() })?;
        let mut report = RefillReport::default();
        for generator in &self.generators {
            let family = self
                .refill_family(pool, generator, &scan_profile, &scan_plan)
                .await?;
            report.pending_before += family.pending_before;
            report.pending_after += family.pending_after;
            report.generated += family.generated;
            report.skipped_recent += family.skipped_recent;
            report.skipped_excluded += family.skipped_excluded;
            report.scanner_available |= family.scanner_available;
            report.families.push(family);
        }
        Ok(report)
    }

    async fn refill_family(
        &self,
        pool: &Pool,
        generator: &FamilyGenerator,
        scan_profile: &str,
        scan_plan: &Value,
    ) -> Result<FamilyRefillReport, Box<dyn std::error::Error + Send + Sync>> {
        let mut client = pool.get().await?;
        let transaction = client.transaction().await?;
        transaction
            .execute(
                "INSERT INTO automatic_target_state (strategy, policy_hash) VALUES ($1, $2) \
                 ON CONFLICT (strategy) DO NOTHING;",
                &[&generator.state_key, &generator.policy_hash],
            )
            .await?;
        let state = transaction
            .query_one(
                "SELECT cursor, policy_hash FROM automatic_target_state \
                 WHERE strategy = $1 FOR UPDATE;",
                &[&generator.state_key],
            )
            .await?;
        let stored_policy_hash: String = state.get("policy_hash");
        let cursor: Value = state.get("cursor");
        let mut position = if stored_policy_hash == generator.policy_hash {
            parse_cursor_position(&cursor)
        } else {
            0
        };
        let scanner_available: bool = transaction
            .query_one(
                &ready_scanner_exists_query(generator.family),
                &[&scan_profile],
            )
            .await?
            .get("available");
        let pending_before: i64 = transaction
            .query_one(
                "SELECT COUNT(*)::BIGINT AS count FROM scan_task_execution e \
                 JOIN scan_task t ON t.id = e.task_id \
                 WHERE t.task_source = 'automatic' AND t.address_family = $1 \
                   AND t.scan_profile = $2 AND e.execution_status = 'pending';",
                &[&generator.family, &scan_profile],
            )
            .await?
            .get("count");
        let mut report = FamilyRefillReport {
            address_family: generator.family.to_owned(),
            pending_before,
            pending_after: pending_before,
            scanner_available,
            ..FamilyRefillReport::default()
        };
        if !generator.enabled
            || !scanner_available
            || generator.total_subnets == 0
            || pending_before >= i64::from(generator.low_watermark)
        {
            transaction.commit().await?;
            return Ok(report);
        }

        let to_generate = i64::from(generator.high_watermark) - pending_before;
        let mut attempts = 0_u128;
        while report.generated < to_generate as usize && attempts < generator.total_subnets {
            let target = target_at(generator, position);
            position = (position + 1) % generator.total_subnets;
            attempts += 1;
            if is_excluded(generator, &target.cidr) {
                report.skipped_excluded += 1;
                continue;
            }
            let recent_exists: bool = transaction
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM scan_task \
                     WHERE generation_key = $1 AND task_source = 'automatic' \
                       AND task_create_time >= (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT - $2::BIGINT) AS recent;",
                    &[&target.generation_key, &((self.policy.repeat_after_seconds as i64) * 1000)],
                )
                .await?
                .get("recent");
            if recent_exists {
                report.skipped_recent += 1;
                continue;
            }
            self.insert_task(
                &transaction,
                generator,
                &target,
                pending_before,
                scan_profile,
                scan_plan,
            )
            .await?;
            report.generated += 1;
        }
        report.pending_after = pending_before + report.generated as i64;
        transaction
            .execute(
                "UPDATE automatic_target_state SET cursor = $2, policy_hash = $3, \
                 last_generated_at = CASE WHEN $4::BIGINT > 0 THEN NOW() ELSE last_generated_at END, \
                 last_error = NULL, updated_at = NOW() WHERE strategy = $1;",
                &[&generator.state_key, &json!({"position": position.to_string()}), &generator.policy_hash, &(report.generated as i64)],
            )
            .await?;
        transaction.commit().await?;
        Ok(report)
    }

    async fn insert_task(
        &self,
        transaction: &deadpool_postgres::Transaction<'_>,
        generator: &FamilyGenerator,
        target: &GeneratedTarget,
        queue_depth_before: i64,
        scan_profile: &str,
        scan_plan: &Value,
    ) -> Result<(), tokio_postgres::Error> {
        let system_user_id: i32 = transaction
            .query_one("SELECT id FROM users WHERE role = 0 LIMIT 1;", &[])
            .await?
            .get("id");
        let task_id = Uuid::now_v7().to_string();
        let metadata = json!({
            "strategy": STRATEGY,
            "address_family": generator.family,
            "pool": target.pool,
            "position": target.position.to_string(),
            "policy_hash": generator.policy_hash,
            "queue_depth_before": queue_depth_before,
            "scan_profile": scan_profile,
        });
        let task_pk: i32 = transaction
            .query_one(
                "INSERT INTO scan_task (user_id, task_id, task_initiator, task_target, task_port, \
                 task_level, remarks, dispatch_mode, task_source, generation_strategy, generation_key, \
                 generation_metadata, address_family, scan_profile, scan_plan) \
                 VALUES ($1, $2, 'system', ARRAY[$3::text::inet], $4, $5, \
                 '系统自动生成扫描任务', 'automatic', 'automatic', $6, $7, $8, $9, $10, $11) RETURNING id;",
                &[&system_user_id, &task_id, &target.cidr, &self.policy.common_ports, &self.policy.priority,
                  &STRATEGY, &target.generation_key, &metadata, &generator.family, &scan_profile, &scan_plan],
            )
            .await?
            .get("id");
        transaction
            .execute(
                "INSERT INTO scan_task_execution (execution_id, task_id, requested_scanner_id) \
                 VALUES ($1, $2, NULL);",
                &[&Uuid::now_v7().to_string(), &task_pk],
            )
            .await?;
        let event = generated_target_audit_event(
            system_user_id,
            task_id,
            generator,
            target,
            &self.policy.common_ports,
            queue_depth_before,
            scan_profile,
        );
        write_audit(transaction, &system_audit_context(), &event).await
    }

    async fn status(
        &self,
        pool: &Pool,
    ) -> Result<AutomaticTargetStatus, Box<dyn std::error::Error + Send + Sync>> {
        let scan_profile = get_default_scan_profile_from_database(pool).await?;
        let client = pool.get().await?;
        let mut families = Vec::new();
        for generator in &self.generators {
            let counts = client
                .query_one(
                    "SELECT COUNT(*) FILTER (WHERE e.execution_status = 'pending')::BIGINT AS pending, \
                     COUNT(*) FILTER (WHERE e.execution_status = 'running')::BIGINT AS running \
                     FROM scan_task_execution e JOIN scan_task t ON t.id = e.task_id \
                     WHERE t.task_source = 'automatic' AND t.address_family = $1 \
                       AND t.scan_profile = $2;",
                    &[&generator.family, &scan_profile],
                )
                .await?;
            let ready_scanners: i64 = client
                .query_one(
                    &ready_scanner_count_query(generator.family),
                    &[&scan_profile],
                )
                .await?
                .get("count");
            let state = client
                .query_opt(
                    "SELECT cursor, last_generated_at::TEXT, last_error FROM automatic_target_state WHERE strategy = $1;",
                    &[&generator.state_key],
                )
                .await?;
            let cursor_position = state
                .as_ref()
                .map(|row| parse_cursor_position(&row.get::<_, Value>("cursor")))
                .unwrap_or_default();
            families.push(FamilyStatus {
                address_family: generator.family.to_owned(),
                enabled: generator.enabled,
                authorized_cidrs: generator.pools.iter().map(ToString::to_string).collect(),
                excluded_cidrs: generator.excluded.iter().map(ToString::to_string).collect(),
                task_prefix: generator.task_prefix,
                pending_low_watermark: generator.low_watermark,
                pending_high_watermark: generator.high_watermark,
                pending_tasks: counts.get("pending"),
                running_tasks: counts.get("running"),
                ready_scanners,
                cursor_position: status_count(generator.family, cursor_position),
                total_subnets: status_count(generator.family, generator.total_subnets),
                last_generated_at: state.as_ref().and_then(|row| row.get("last_generated_at")),
                last_error: state.as_ref().and_then(|row| row.get("last_error")),
            });
        }
        Ok(AutomaticTargetStatus {
            enabled: self.enabled(),
            strategy: self.policy.strategy.clone(),
            default_scan_profile: scan_profile,
            common_ports: self.policy.common_ports.clone(),
            repeat_after_seconds: self.policy.repeat_after_seconds,
            families,
        })
    }

    async fn record_error(&self, pool: &Pool, message: &str) {
        let Ok(client) = pool.get().await else { return };
        let message: String = message.chars().take(1000).collect();
        for generator in self.generators.iter().filter(|value| value.enabled) {
            let _ = client
                .execute(
                    "INSERT INTO automatic_target_state (strategy, policy_hash, last_error) \
                     VALUES ($1, $2, $3) ON CONFLICT (strategy) DO UPDATE SET \
                     last_error = EXCLUDED.last_error, updated_at = NOW();",
                    &[&generator.state_key, &generator.policy_hash, &message],
                )
                .await;
        }
    }
}

pub async fn run_generator(config: RuntimeConfig<AutomaticTargetConfig>, pool: Pool) {
    let mut previous_scanner_available = None;
    let mut changes = config.subscribe();
    loop {
        let settings = config.get().await.value;
        let service = match AutomaticTargetService::new(settings) {
            Ok(service) => service,
            Err(error) => {
                let error = error.to_string();
                error!(
                    target: "server::automatic_target",
                    event = "AutomaticTargetConfigurationError",
                    operation = "build_automatic_target_service",
                    error_kind = "configuration",
                    error_code = "automatic_target_configuration_invalid",
                    error_message = %error,
                    retryable = true,
                    outcome = "generator_retry_scheduled",
                    retry_after_ms = 5_000_u64,
                );
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
                    changed = changes.changed() => if changed.is_err() { return; }
                }
                continue;
            }
        };
        if !service.enabled() {
            previous_scanner_available = None;
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
                changed = changes.changed() => if changed.is_err() { return; }
            }
            continue;
        }
        match service.refill(&pool).await {
            Ok(report) => {
                if previous_scanner_available == Some(false) && report.scanner_available {
                    info!(
                        target: "server::automatic_target",
                        event = "AutomaticTargetScannerAvailable",
                        "检测到兼容且在线的扫描器，恢复自动任务生成"
                    );
                } else if previous_scanner_available != Some(false) && !report.scanner_available {
                    info!(
                        target: "server::automatic_target",
                        event = "AutomaticTargetScannerUnavailable",
                        "没有兼容且在线的扫描器，暂停自动任务生成"
                    );
                }
                previous_scanner_available = Some(report.scanner_available);
                if report.generated > 0 {
                    info!(
                        target: "server::automatic_target",
                        event = "AutomaticTargetQueueRefilled",
                        generated = report.generated,
                        pending_before = report.pending_before,
                        pending_after = report.pending_after,
                        skipped_recent = report.skipped_recent,
                        skipped_excluded = report.skipped_excluded,
                        "自动目标队列已补充"
                    );
                }
            }
            Err(error_value) => {
                let error_value = error_value.to_string();
                service.record_error(&pool, &error_value).await;
                error!(
                    target: "server::automatic_target",
                    event = "AutomaticTargetRefillError",
                    operation = "refill_automatic_target_queue",
                    error_kind = "database",
                    error_code = "automatic_target_refill_failed",
                    error_message = %error_value,
                    retryable = true,
                    outcome = "generator_retry_scheduled",
                    retry_after_ms = service.interval_seconds().saturating_mul(1_000),
                );
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(service.interval_seconds())) => {}
            changed = changes.changed() => if changed.is_err() { return; }
        }
    }
}

#[get("/api/automatic-target/status")]
pub async fn automatic_target_status(
    pool: web::Data<Pool>,
    config: web::Data<RuntimeConfig<AutomaticTargetConfig>>,
    user: crate::admin::UserBaseI,
) -> impl Responder {
    if user.role != 1 {
        return HttpResponse::Forbidden().finish();
    }
    let service = match AutomaticTargetService::new(config.get().await.value) {
        Ok(service) => service,
        Err(error_value) => {
            error!(
                event = "AutomaticTargetStatusConfigurationError",
                operation = "build_automatic_target_status_service",
                error_kind = "configuration",
                error_code = "automatic_target_status_configuration_invalid",
                error_message = %error_value,
                retryable = false,
                outcome = "request_failed",
                user_id = user.id,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    match service.status(pool.get_ref()).await {
        Ok(status) => HttpResponse::Ok().json(json!({"success": true, "data": status})),
        Err(error_value) => {
            error!(
                event = "AutomaticTargetStatusError",
                operation = "load_automatic_target_status",
                error_kind = "database",
                error_code = "automatic_target_status_load_failed",
                error_message = %error_value,
                retryable = false,
                outcome = "request_failed",
                user_id = user.id,
            );
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn family_generator(
    family: &'static str,
    enabled: bool,
    pools: Vec<IpNet>,
    excluded: Vec<IpNet>,
    task_prefix: u8,
    low_watermark: u32,
    high_watermark: u32,
    policy: &AutomaticTargetConfig,
) -> FamilyGenerator {
    let total_subnets = pools.iter().fold(0_u128, |total, network| {
        total
            .checked_add(subnet_count(*network, task_prefix))
            .expect("validated automatic target subnet count")
    });
    let state_key = if family == "ipv4" {
        STRATEGY.to_owned()
    } else {
        format!("{STRATEGY}:{family}")
    };
    let policy_hash = policy_hash(policy, family, &pools, &excluded, task_prefix);
    FamilyGenerator {
        family,
        enabled,
        pools,
        excluded,
        task_prefix,
        low_watermark,
        high_watermark,
        total_subnets,
        state_key,
        policy_hash,
    }
}

fn target_at(generator: &FamilyGenerator, position: u128) -> GeneratedTarget {
    let mut remaining = position % generator.total_subnets;
    for pool in &generator.pools {
        let count = subnet_count(*pool, generator.task_prefix);
        if remaining < count {
            let subnet = match pool {
                IpNet::V4(pool) => {
                    let size = 1_u128 << (32 - generator.task_prefix);
                    let base = u128::from(u32::from(pool.network())) + remaining * size;
                    IpNet::V4(
                        Ipv4Net::new(Ipv4Addr::from(base as u32), generator.task_prefix)
                            .expect("validated IPv4 prefix"),
                    )
                }
                IpNet::V6(pool) => {
                    let base =
                        u128::from(pool.network()) + (remaining << (128 - generator.task_prefix));
                    IpNet::V6(
                        Ipv6Net::new(Ipv6Addr::from(base), generator.task_prefix)
                            .expect("validated IPv6 prefix"),
                    )
                }
            };
            let cidr = subnet.to_string();
            let generation_key = if generator.family == "ipv4" {
                format!("{STRATEGY}:{cidr}")
            } else {
                format!("{STRATEGY}:{}:{cidr}", generator.family)
            };
            return GeneratedTarget {
                generation_key,
                cidr,
                pool: pool.to_string(),
                position,
            };
        }
        remaining -= count;
    }
    unreachable!("position is normalized to configured subnet count")
}

fn subnet_count(network: IpNet, task_prefix: u8) -> u128 {
    1_u128 << (task_prefix - network.prefix_len())
}

fn parse_cursor_position(cursor: &Value) -> u128 {
    cursor
        .get("position")
        .and_then(|position| {
            position
                .as_str()
                .and_then(|value| value.parse().ok())
                .or_else(|| position.as_u64().map(u128::from))
        })
        .unwrap_or_default()
}

fn status_count(family: &str, value: u128) -> Value {
    if family == "ipv4" {
        json!(u64::try_from(value).expect("IPv4 subnet count fits in u64"))
    } else {
        Value::String(value.to_string())
    }
}

fn is_excluded(generator: &FamilyGenerator, cidr: &str) -> bool {
    let target: IpNet = cidr.parse().expect("generated target is a valid CIDR");
    generator.excluded.iter().any(|excluded| {
        target.contains(&excluded.network()) || excluded.contains(&target.network())
    })
}

pub(crate) fn ready_scanner_exists_query(family: &str) -> String {
    format!(
        "SELECT EXISTS(SELECT 1 FROM scanner_info WHERE is_enable = true AND deleted_at IS NULL \
        AND runtime_state <> 'stopping' AND last_seen_at >= NOW() - ({}) * INTERVAL '1 second' AND supports_{family} AND {family}_ready \
        AND ($1 = 'legacy' OR scan_capabilities->'profiles' ? $1)) AS available;",
        crate::scanner_health::seconds_sql()
    )
}

fn ready_scanner_count_query(family: &str) -> String {
    format!(
        "SELECT COUNT(*)::BIGINT AS count FROM scanner_info WHERE is_enable = true AND deleted_at IS NULL \
        AND runtime_state <> 'stopping' AND last_seen_at >= NOW() - ({}) * INTERVAL '1 second' AND supports_{family} AND {family}_ready \
        AND ($1 = 'legacy' OR scan_capabilities->'profiles' ? $1);",
        crate::scanner_health::seconds_sql()
    )
}

fn policy_hash(
    policy: &AutomaticTargetConfig,
    family: &str,
    pools: &[IpNet],
    excluded: &[IpNet],
    task_prefix: u8,
) -> String {
    let serialized = if family == "ipv4" && excluded.is_empty() {
        serde_json::to_vec(&json!({
            "strategy": policy.strategy,
            "authorized_cidrs": pools.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "ipv4_task_prefix": task_prefix,
            "common_ports": policy.common_ports,
        }))
    } else if family == "ipv4" {
        serde_json::to_vec(&json!({
            "strategy": policy.strategy,
            "authorized_cidrs": pools.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "excluded_cidrs": excluded.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "ipv4_task_prefix": task_prefix,
            "common_ports": policy.common_ports,
        }))
    } else if excluded.is_empty() {
        serde_json::to_vec(&json!({
            "strategy": policy.strategy,
            "address_family": family,
            "authorized_cidrs": pools.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "task_prefix": task_prefix,
            "common_ports": policy.common_ports,
        }))
    } else {
        serde_json::to_vec(&json!({
            "strategy": policy.strategy,
            "address_family": family,
            "authorized_cidrs": pools.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "excluded_cidrs": excluded.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "task_prefix": task_prefix,
            "common_ports": policy.common_ports,
        }))
    }
    .expect("automatic target policy is serializable");
    let digest = openssl::sha::sha256(&serialized);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn system_audit_context() -> AuditContext {
    AuditContext {
        request_id: Uuid::new_v4(),
        source_ip: None,
        user_agent: None,
        http_method: "SYSTEM".to_owned(),
        request_path: SYSTEM_REQUEST_PATH.to_owned(),
    }
}

fn generated_target_audit_event(
    system_user_id: i32,
    task_id: String,
    generator: &FamilyGenerator,
    target: &GeneratedTarget,
    common_ports: &str,
    queue_depth_before: i64,
    scan_profile: &str,
) -> AuditEvent {
    let mut event = AuditEvent::anonymous("automatic_target", "task.auto_generate", "success")
        .resource("task", task_id);
    event.actor_type = "system".to_owned();
    event.actor_id = Some(system_user_id.to_string());
    event.actor_name = Some("system".to_owned());
    event.severity = "info".to_owned();
    event.response_status = Some(200);
    event.metadata = json!({
        "strategy": STRATEGY,
        "address_family": generator.family,
        "target": target.cidr,
        "ports": common_ports,
        "policy_hash": generator.policy_hash,
        "queue_depth_before": queue_depth_before,
        "scan_profile": scan_profile,
    });
    event
}

#[cfg(test)]
mod tests {
    use super::{
        AutomaticTargetService, generated_target_audit_event, is_excluded, parse_cursor_position,
        target_at,
    };
    use crate::config::AutomaticTargetConfig;
    use serde_json::json;

    #[test]
    fn sequential_strategy_walks_ipv4_and_ipv6_subnets() {
        let service = AutomaticTargetService::new(AutomaticTargetConfig {
            enabled: true,
            authorized_cidrs: vec!["10.0.0.0/23".to_owned()],
            ipv6_enabled: true,
            ipv6_authorized_cidrs: vec!["2001:db8::/63".to_owned()],
            ipv6_task_prefix: 64,
            ..AutomaticTargetConfig::default()
        })
        .unwrap();
        assert_eq!(target_at(&service.generators[0], 0).cidr, "10.0.0.0/24");
        assert_eq!(
            target_at(&service.generators[0], 0).generation_key,
            "sequential_subnet:10.0.0.0/24"
        );
        assert_eq!(target_at(&service.generators[0], 1).cidr, "10.0.1.0/24");
        assert_eq!(target_at(&service.generators[1], 0).cidr, "2001:db8::/64");
        assert_eq!(
            target_at(&service.generators[1], 1).cidr,
            "2001:db8:0:1::/64"
        );
    }

    #[test]
    fn exclusion_intersection_skips_the_entire_generated_subnet() {
        let service = AutomaticTargetService::new(AutomaticTargetConfig {
            enabled: true,
            authorized_cidrs: vec!["10.0.0.0/23".to_owned()],
            excluded_cidrs: vec!["10.0.0.128/25".to_owned()],
            ..AutomaticTargetConfig::default()
        })
        .unwrap();

        assert!(is_excluded(
            &service.generators[0],
            &target_at(&service.generators[0], 0).cidr
        ));
        assert!(!is_excluded(
            &service.generators[0],
            &target_at(&service.generators[0], 1).cidr
        ));
    }

    #[test]
    fn zero_network_is_always_excluded() {
        let service = AutomaticTargetService::new(AutomaticTargetConfig {
            enabled: true,
            authorized_cidrs: vec!["0.0.0.0/7".to_owned()],
            excluded_cidrs: Vec::new(),
            ..AutomaticTargetConfig::default()
        })
        .unwrap();
        let generator = &service.generators[0];

        assert_eq!(target_at(generator, 17).cidr, "0.0.17.0/24");
        assert!(is_excluded(generator, &target_at(generator, 17).cidr));
        assert_eq!(target_at(generator, 65_536).cidr, "1.0.0.0/24");
        assert!(!is_excluded(generator, &target_at(generator, 65_536).cidr));
    }

    #[test]
    fn sequential_strategy_supports_the_full_ipv6_address_space() {
        let service = AutomaticTargetService::new(AutomaticTargetConfig {
            ipv6_enabled: true,
            ipv6_authorized_cidrs: vec!["::/0".to_owned()],
            ipv6_task_prefix: 120,
            ..AutomaticTargetConfig::default()
        })
        .unwrap();
        let generator = &service.generators[1];

        assert_eq!(generator.total_subnets, 1_u128 << 120);
        assert_eq!(target_at(generator, 0).cidr, "::/120");
        assert_eq!(target_at(generator, 1).cidr, "::100/120");
    }

    #[test]
    fn cursor_parser_accepts_legacy_numbers_and_decimal_strings() {
        assert_eq!(parse_cursor_position(&json!({"position": 42})), 42);
        assert_eq!(
            parse_cursor_position(&json!({"position": "1329227995784915872903807060280344576"})),
            1_u128 << 120
        );
    }

    #[test]
    fn generated_targets_have_a_dedicated_audit_category() {
        let service = AutomaticTargetService::new(AutomaticTargetConfig {
            enabled: true,
            authorized_cidrs: vec!["10.0.0.0/24".to_owned()],
            ..AutomaticTargetConfig::default()
        })
        .unwrap();
        let generator = &service.generators[0];
        let target = target_at(generator, 0);

        let event = generated_target_audit_event(
            1,
            "0198-test-task".to_owned(),
            generator,
            &target,
            "80,443",
            3,
            "service_inventory",
        );

        assert_eq!(event.category, "automatic_target");
        assert_eq!(event.action, "task.auto_generate");
        assert_eq!(event.actor_type, "system");
        assert_eq!(event.resource_type.as_deref(), Some("task"));
        assert_eq!(event.resource_id.as_deref(), Some("0198-test-task"));
        assert_eq!(event.metadata["target"], "10.0.0.0/24");
        assert_eq!(event.metadata["scan_profile"], "service_inventory");
    }
}
