pub(crate) mod history;
pub(crate) mod search;

use std::net::{Ipv4Addr, Ipv6Addr};

use actix_web::{HttpRequest, HttpResponse, Responder, get, post, web};
use deadpool_postgres::Pool;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
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
    next_target: Option<String>,
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
        let mut position = resume_position(
            &stored_policy_hash,
            &generator.policy_hash,
            &cursor,
            generator.total_subnets,
        );
        let scanner_available: bool = transaction
            .query_one(
                &ready_scanner_exists_query(generator.family),
                &[&scan_profile, &scan_plan],
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
        let now = crate::clock::get_unix_epoch_ms();
        let mut due = if self.policy.strategy == "smart_refresh" {
            history::due(
                &transaction,
                generator.family,
                scan_profile,
                &self.policy.common_ports,
                (self.policy.repeat_after_seconds as i64) * 1000,
                now,
                256,
                (&generator.pools, &generator.excluded, generator.task_prefix),
            )
            .await?
            .into_iter()
        } else {
            Vec::new().into_iter()
        };
        let mut attempts = 0_u128;
        while report.generated < to_generate as usize
            && attempts < generator.total_subnets.min(256) + 256
        {
            let mut from_cursor = false;
            let target = if let Some((generation_key, cidr)) = due.next() {
                let Ok(net) = cidr.parse::<IpNet>() else {
                    continue;
                };
                if net.prefix_len() != generator.task_prefix
                    || !generator
                        .pools
                        .iter()
                        .any(|p| p.contains(&net.network()) && p.contains(&net.broadcast()))
                {
                    continue;
                }
                GeneratedTarget {
                    generation_key,
                    cidr,
                    pool: net.to_string(),
                    position,
                }
            } else {
                if attempts >= generator.total_subnets.min(256) {
                    break;
                }
                let target = target_at(generator, position);
                position = (position + 1) % generator.total_subnets;
                from_cursor = true;
                target
            };
            attempts += 1;
            if is_excluded(generator, &target.cidr) {
                report.skipped_excluded += 1;
                if from_cursor {
                    // Jump over the whole excluded block instead of crawling one
                    // task subnet per attempt: large exclusions (e.g. 0.0.0.0/8)
                    // would otherwise stall generation for hours without a log.
                    let after = position_after_exclusions(generator, target.position, &target.cidr);
                    if after > target.position + 1 {
                        info!(
                            target: "server::automatic_target",
                            event = "AutomaticTargetExcludedBlockSkipped",
                            address_family = generator.family,
                            from = %target.cidr,
                            to = %target_at(generator, after % generator.total_subnets).cidr,
                            skipped_subnets = %(after - target.position),
                            "自动目标游标整段跳过排除网段"
                        );
                    }
                    position = after % generator.total_subnets;
                }
                continue;
            }
            let recent_exists: bool = if self.policy.strategy == "smart_refresh" {
                !history::eligible(
                    &transaction,
                    &target.generation_key,
                    scan_profile,
                    &self.policy.common_ports,
                    (self.policy.repeat_after_seconds as i64) * 1000,
                    now,
                )
                .await?
            } else {
                transaction
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM scan_task \
                     WHERE generation_key = $1 AND task_source = 'automatic' \
                       AND task_create_time >= (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT - $2::BIGINT) AS recent;",
                    &[&target.generation_key, &((self.policy.repeat_after_seconds as i64) * 1000)],
                )
                .await?
                .get("recent")
            };
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
            "strategy": self.policy.strategy,
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
                  &self.policy.strategy, &target.generation_key, &metadata, &generator.family, &scan_profile, &scan_plan],
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
        history::created(
            transaction,
            &target.generation_key,
            generator.family,
            &target.cidr,
            scan_profile,
            &self.policy.common_ports,
            crate::clock::get_unix_epoch_ms(),
        )
        .await?;
        let mut event = generated_target_audit_event(
            system_user_id,
            task_id,
            generator,
            target,
            &self.policy.common_ports,
            queue_depth_before,
            scan_profile,
        );
        event.metadata["strategy"] = json!(self.policy.strategy);
        write_audit(transaction, &system_audit_context(), &event).await
    }

    async fn status(
        &self,
        pool: &Pool,
    ) -> Result<AutomaticTargetStatus, Box<dyn std::error::Error + Send + Sync>> {
        let scan_profile = get_default_scan_profile_from_database(pool).await?;
        let scan_plan = build_scan_plan(&scan_profile)
            .map_err(|message| -> Box<dyn std::error::Error + Send + Sync> { message.into() })?;
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
                    &[&scan_profile, &scan_plan],
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
                next_target: (generator.total_subnets > 0)
                    .then(|| target_at(generator, cursor_position % generator.total_subnets).cidr),
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

    fn generator(&self, family: &str) -> Result<&FamilyGenerator, CursorError> {
        self.generators
            .iter()
            .find(|generator| generator.family == family)
            .ok_or_else(|| CursorError::Invalid(format!("未知地址族：{family}")))
    }

    /// Resolve a manual cursor position from either a decimal position or a
    /// task CIDR inside the authorized pools. Exactly one input is required.
    pub fn resolve_position(
        &self,
        family: &str,
        position: Option<u128>,
        target: Option<&str>,
    ) -> Result<u128, CursorError> {
        let generator = self.generator(family)?;
        let resolved = match (position, target) {
            (Some(position), None) => position,
            (None, Some(cidr)) => position_of_cidr(generator, cidr).ok_or_else(|| {
                CursorError::Invalid(format!(
                    "目标 {cidr} 不在授权范围内，或前缀与任务前缀 /{} 不一致",
                    generator.task_prefix
                ))
            })?,
            _ => {
                return Err(CursorError::Invalid(
                    "必须且只能提供 position 或 target 之一".into(),
                ));
            }
        };
        if generator.total_subnets == 0 {
            return Err(CursorError::Invalid(
                "当前授权范围没有可生成的子网，无法设置游标".into(),
            ));
        }
        if resolved >= generator.total_subnets {
            return Err(CursorError::Invalid(format!(
                "游标位置必须小于子网总数 {}",
                generator.total_subnets
            )));
        }
        Ok(resolved)
    }

    /// Manually move the generation cursor. The row lock serializes this with
    /// the generator's refill transaction, so the next tick resumes exactly
    /// from the requested position.
    pub async fn set_cursor(
        &self,
        pool: &Pool,
        family: &str,
        position: u128,
        audit: &AuditContext,
        user: &crate::admin::UserBaseI,
    ) -> Result<CursorUpdate, CursorError> {
        let position = self.resolve_position(family, Some(position), None)?;
        let generator = self.generator(family)?;
        let target = target_at(generator, position);
        let mut client = pool
            .get()
            .await
            .map_err(|error| CursorError::Database(error.to_string()))?;
        let transaction = client.transaction().await.map_err(cursor_db_error)?;
        transaction
            .execute(
                "INSERT INTO automatic_target_state (strategy, policy_hash) VALUES ($1, $2) \
                 ON CONFLICT (strategy) DO NOTHING;",
                &[&generator.state_key, &generator.policy_hash],
            )
            .await
            .map_err(cursor_db_error)?;
        let state = transaction
            .query_one(
                "SELECT cursor FROM automatic_target_state WHERE strategy = $1 FOR UPDATE;",
                &[&generator.state_key],
            )
            .await
            .map_err(cursor_db_error)?;
        let previous_position = parse_cursor_position(&state.get::<_, Value>("cursor"));
        transaction
            .execute(
                "UPDATE automatic_target_state SET cursor = $2, policy_hash = $3, \
                 updated_at = NOW() WHERE strategy = $1;",
                &[
                    &generator.state_key,
                    &json!({"position": position.to_string()}),
                    &generator.policy_hash,
                ],
            )
            .await
            .map_err(cursor_db_error)?;
        let mut event =
            AuditEvent::user("automatic_target", "cursor.manual_update", "success", user)
                .resource("automatic_target_cursor", generator.state_key.clone());
        event.response_status = Some(200);
        event.metadata = json!({
            "address_family": generator.family,
            "position": position.to_string(),
            "previous_position": previous_position.to_string(),
            "target": target.cidr,
            "policy_hash": generator.policy_hash,
        });
        write_audit(&transaction, audit, &event)
            .await
            .map_err(cursor_db_error)?;
        transaction.commit().await.map_err(cursor_db_error)?;
        Ok(CursorUpdate {
            address_family: generator.family.to_owned(),
            position: status_count(generator.family, position),
            previous_position: status_count(generator.family, previous_position),
            target: target.cidr,
            total_subnets: status_count(generator.family, generator.total_subnets),
        })
    }
}

#[derive(Debug)]
pub enum CursorError {
    Invalid(String),
    Database(String),
}

impl std::fmt::Display for CursorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::Database(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for CursorError {}

fn cursor_db_error(error: tokio_postgres::Error) -> CursorError {
    CursorError::Database(error.to_string())
}

#[derive(Debug, Serialize)]
pub struct CursorUpdate {
    pub address_family: String,
    pub position: Value,
    pub previous_position: Value,
    pub target: String,
    pub total_subnets: Value,
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

#[derive(Deserialize)]
pub struct CursorUpdateRequest {
    address_family: String,
    #[serde(default)]
    position: Option<Value>,
    #[serde(default)]
    target: Option<String>,
}

fn parse_position_value(value: &Value) -> Option<u128> {
    value
        .as_str()
        .and_then(|text| text.trim().parse().ok())
        .or_else(|| value.as_u64().map(u128::from))
}

#[post("/api/automatic-target/cursor")]
pub async fn automatic_target_set_cursor(
    req: HttpRequest,
    pool: web::Data<Pool>,
    config: web::Data<RuntimeConfig<AutomaticTargetConfig>>,
    user: crate::admin::UserBaseI,
    body: web::Json<CursorUpdateRequest>,
) -> impl Responder {
    if user.role != 1 {
        return HttpResponse::Forbidden().finish();
    }
    let service = match AutomaticTargetService::new(config.get().await.value) {
        Ok(service) => service,
        Err(error_value) => {
            error!(
                event = "AutomaticTargetCursorConfigurationError",
                operation = "build_automatic_target_cursor_service",
                error_kind = "configuration",
                error_code = "automatic_target_cursor_configuration_invalid",
                error_message = %error_value,
                retryable = false,
                outcome = "request_failed",
                user_id = user.id,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let position = match body.position.as_ref() {
        Some(value) => match parse_position_value(value) {
            Some(position) => Some(position),
            None => {
                return HttpResponse::BadRequest().json(json!({
                    "success": false,
                    "message": "position 必须为非负十进制整数（数字或字符串）",
                }));
            }
        },
        None => None,
    };
    let position =
        match service.resolve_position(&body.address_family, position, body.target.as_deref()) {
            Ok(position) => position,
            Err(CursorError::Invalid(message)) => {
                return HttpResponse::BadRequest()
                    .json(json!({"success": false, "message": message}));
            }
            Err(CursorError::Database(message)) => {
                error!(
                    event = "AutomaticTargetCursorUpdateError",
                    operation = "resolve_automatic_target_cursor",
                    error_kind = "database",
                    error_code = "automatic_target_cursor_update_failed",
                    error_message = %message,
                    retryable = false,
                    outcome = "request_failed",
                    user_id = user.id,
                );
                return HttpResponse::InternalServerError().finish();
            }
        };
    match service
        .set_cursor(
            pool.get_ref(),
            &body.address_family,
            position,
            &AuditContext::from_request(&req),
            &user,
        )
        .await
    {
        Ok(update) => HttpResponse::Ok().json(json!({"success": true, "data": update})),
        Err(CursorError::Invalid(message)) => {
            HttpResponse::BadRequest().json(json!({"success": false, "message": message}))
        }
        Err(CursorError::Database(message)) => {
            error!(
                event = "AutomaticTargetCursorUpdateError",
                operation = "update_automatic_target_cursor",
                error_kind = "database",
                error_code = "automatic_target_cursor_update_failed",
                error_message = %message,
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
                    // At /0 the pool is a single whole-space task, so the offset
                    // is always zero and a 128-bit shift would overflow.
                    let offset = remaining
                        .checked_shl(u32::from(128 - generator.task_prefix))
                        .unwrap_or(0);
                    let base = u128::from(pool.network()) + offset;
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

/// Cursor position of an exact task CIDR inside the authorized pools, or
/// `None` when the CIDR is outside the pools or uses a different prefix.
fn position_of_cidr(generator: &FamilyGenerator, cidr: &str) -> Option<u128> {
    let net: IpNet = cidr.parse().ok()?;
    if net.prefix_len() != generator.task_prefix {
        return None;
    }
    let mut pool_start = 0_u128;
    for pool in &generator.pools {
        let count = subnet_count(*pool, generator.task_prefix);
        if pool.contains(&net.network()) && pool.contains(&net.broadcast()) {
            let (pool_base, address, bits) = match (pool, &net) {
                (IpNet::V4(pool), IpNet::V4(net)) => (
                    u128::from(u32::from(pool.network())),
                    u128::from(u32::from(net.network())),
                    32_u32,
                ),
                (IpNet::V6(pool), IpNet::V6(net)) => (
                    u128::from(pool.network()),
                    u128::from(net.network()),
                    128_u32,
                ),
                _ => return None,
            };
            let index = match 1_u128.checked_shl(bits - u32::from(generator.task_prefix)) {
                Some(size) => (address - pool_base) / size,
                // A /0 task prefix makes the whole space one subnet; the only
                // matching CIDR is the pool itself, at index 0.
                None => 0,
            };
            return Some(pool_start + index);
        }
        pool_start += count;
    }
    None
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

/// Cursor position to resume from after a policy change. The cursor is a
/// coverage pointer into the ordered subnet space, so a policy change (e.g.
/// editing `common_ports`) must not restart the walk at zero: that would
/// re-walk already covered space and stall inside mandatory exclusion blocks.
/// The stored position is kept, normalized into the new subnet space.
fn resume_position(
    stored_policy_hash: &str,
    policy_hash: &str,
    cursor: &Value,
    total_subnets: u128,
) -> u128 {
    let position = parse_cursor_position(cursor);
    if stored_policy_hash == policy_hash || total_subnets == 0 {
        position
    } else {
        position % total_subnets
    }
}

/// First cursor position after every exclusion block overlapping the subnet
/// generated at `position`. Longer exclusions inside the task subnet still
/// skip only that one subnet (task-level safety skip). Returns at most
/// `generator.total_subnets`; the caller wraps around.
fn position_after_exclusions(generator: &FamilyGenerator, position: u128, cidr: &str) -> u128 {
    let target: IpNet = cidr.parse().expect("generated target is a valid CIDR");
    let mut next = position + 1;
    let mut pool_start = 0_u128;
    for pool in &generator.pools {
        let count = subnet_count(*pool, generator.task_prefix);
        if position < pool_start || position >= pool_start + count {
            pool_start += count;
            continue;
        }
        let (pool_base, pool_broadcast, bits) = match pool {
            IpNet::V4(net) => (
                u128::from(u32::from(net.network())),
                u128::from(u32::from(net.broadcast())),
                32_u32,
            ),
            IpNet::V6(net) => (
                u128::from(net.network()),
                u128::from(net.broadcast()),
                128_u32,
            ),
        };
        let size = 1_u128.checked_shl(bits - u32::from(generator.task_prefix));
        for excluded in &generator.excluded {
            if !(target.contains(&excluded.network()) || excluded.contains(&target.network())) {
                continue;
            }
            let excluded_broadcast = match (pool, excluded) {
                (IpNet::V4(_), IpNet::V4(net)) => u128::from(u32::from(net.broadcast())),
                (IpNet::V6(_), IpNet::V6(net)) => u128::from(net.broadcast()),
                _ => continue,
            };
            let end = excluded_broadcast.min(pool_broadcast);
            let index_after = match size {
                Some(size) => (end - pool_base) / size + 1,
                // /0 task: the single whole-space subnet is excluded, so the
                // jump leaves the pool entirely.
                None => count,
            };
            next = next.max(pool_start + index_after.min(count));
        }
        break;
    }
    next
}

pub(crate) fn ready_scanner_exists_query(family: &str) -> String {
    format!(
        "SELECT EXISTS(SELECT 1 FROM scanner_info WHERE is_enable = true AND deleted_at IS NULL AND accepting_tasks \
        AND runtime_state <> 'stopping' AND last_seen_at >= NOW() - ({}) * INTERVAL '1 second' AND supports_{family} AND {family}_ready \
        AND ($1 = 'legacy' OR scan_capabilities->'profiles' ? $1) \
        {engine_gate}) AS available;",
        crate::scanner_health::seconds_sql(),
        engine_gate =
            crate::scanner_config::required_stage_engine_gate("scanner_info", "$2::jsonb"),
    )
}

fn ready_scanner_count_query(family: &str) -> String {
    format!(
        "SELECT COUNT(*)::BIGINT AS count FROM scanner_info WHERE is_enable = true AND deleted_at IS NULL AND accepting_tasks \
        AND runtime_state <> 'stopping' AND last_seen_at >= NOW() - ({}) * INTERVAL '1 second' AND supports_{family} AND {family}_ready \
        AND ($1 = 'legacy' OR scan_capabilities->'profiles' ? $1) \
        {engine_gate};",
        crate::scanner_health::seconds_sql(),
        engine_gate =
            crate::scanner_config::required_stage_engine_gate("scanner_info", "$2::jsonb"),
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
        position_after_exclusions, position_of_cidr, resume_position, target_at,
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
    fn exclusion_jump_skips_the_whole_zero_block_in_one_step() {
        let service = AutomaticTargetService::new(AutomaticTargetConfig {
            enabled: true,
            authorized_cidrs: vec!["0.0.0.0/0".to_owned()],
            ..AutomaticTargetConfig::default()
        })
        .unwrap();
        let generator = &service.generators[0];

        let start = target_at(generator, 24_832);
        assert!(is_excluded(generator, &start.cidr));
        let after = position_after_exclusions(generator, 24_832, &start.cidr);
        assert_eq!(after, 65_536);
        assert_eq!(target_at(generator, after).cidr, "1.0.0.0/24");
        assert!(!is_excluded(generator, &target_at(generator, after).cidr));
    }

    #[test]
    fn exclusion_jump_lands_on_the_next_pool() {
        let service = AutomaticTargetService::new(AutomaticTargetConfig {
            enabled: true,
            authorized_cidrs: vec!["0.0.0.0/8".to_owned(), "1.0.0.0/23".to_owned()],
            ..AutomaticTargetConfig::default()
        })
        .unwrap();
        let generator = &service.generators[0];

        let start = target_at(generator, 0);
        let after = position_after_exclusions(generator, 0, &start.cidr);
        assert_eq!(after, 65_536);
        assert_eq!(target_at(generator, after).cidr, "1.0.0.0/24");
        assert!(!is_excluded(generator, &target_at(generator, after).cidr));
    }

    #[test]
    fn exclusion_jump_respects_task_level_skip_and_block_end() {
        let service = AutomaticTargetService::new(AutomaticTargetConfig {
            enabled: true,
            authorized_cidrs: vec!["1.0.0.0/22".to_owned()],
            excluded_cidrs: vec!["1.0.0.128/25".to_owned(), "1.0.2.0/23".to_owned()],
            ..AutomaticTargetConfig::default()
        })
        .unwrap();
        let generator = &service.generators[0];

        // A /25 inside 1.0.0.0/24 skips the whole /24 task, but only one position.
        assert!(is_excluded(generator, "1.0.0.0/24"));
        assert_eq!(position_after_exclusions(generator, 0, "1.0.0.0/24"), 1);
        // A /23 covering positions 2..=3 jumps straight to the end of the pool.
        assert!(is_excluded(generator, "1.0.2.0/24"));
        assert_eq!(position_after_exclusions(generator, 2, "1.0.2.0/24"), 4);
        assert_eq!(generator.total_subnets, 4);
    }

    #[test]
    fn exclusion_jump_handles_ipv6_blocks() {
        let service = AutomaticTargetService::new(AutomaticTargetConfig {
            ipv6_enabled: true,
            ipv6_authorized_cidrs: vec!["2001:db8::/112".to_owned()],
            ipv6_excluded_cidrs: vec!["2001:db8::/113".to_owned()],
            ipv6_task_prefix: 120,
            ..AutomaticTargetConfig::default()
        })
        .unwrap();
        let generator = &service.generators[1];
        assert_eq!(generator.total_subnets, 256);

        let start = target_at(generator, 100);
        assert!(is_excluded(generator, &start.cidr));
        let after = position_after_exclusions(generator, 100, &start.cidr);
        assert_eq!(after, 128);
        assert_eq!(target_at(generator, after).cidr, "2001:db8::8000/120");
        assert!(!is_excluded(generator, &target_at(generator, after).cidr));
    }

    #[test]
    fn cursor_position_resolves_from_cidr_within_authorized_pools() {
        let service = AutomaticTargetService::new(AutomaticTargetConfig {
            enabled: true,
            authorized_cidrs: vec!["0.0.0.0/8".to_owned(), "1.0.0.0/22".to_owned()],
            ..AutomaticTargetConfig::default()
        })
        .unwrap();
        let generator = &service.generators[0];

        assert_eq!(position_of_cidr(generator, "0.0.17.0/24"), Some(17));
        assert_eq!(position_of_cidr(generator, "1.0.2.0/24"), Some(65_538));
        // Wrong prefix, outside the pools, or not a CIDR at all.
        assert_eq!(position_of_cidr(generator, "1.0.2.0/25"), None);
        assert_eq!(position_of_cidr(generator, "2.0.0.0/24"), None);
        assert_eq!(position_of_cidr(generator, "not-a-cidr"), None);

        assert_eq!(
            service
                .resolve_position("ipv4", None, Some("1.0.2.0/24"))
                .unwrap(),
            65_538
        );
        assert_eq!(
            service.resolve_position("ipv4", Some(17), None).unwrap(),
            17
        );
        assert!(
            service
                .resolve_position("ipv4", Some(65_540), None)
                .is_err()
        );
        assert!(
            service
                .resolve_position("ipv4", Some(1), Some("1.0.0.0/24"))
                .is_err()
        );
        assert!(service.resolve_position("ipv4", None, None).is_err());
        assert!(service.resolve_position("ipv5", Some(0), None).is_err());
        // IPv6 generator exists but has no authorized space in this policy.
        assert!(service.resolve_position("ipv6", Some(0), None).is_err());
    }

    #[test]
    fn cursor_position_resolves_ipv6_targets() {
        let service = AutomaticTargetService::new(AutomaticTargetConfig {
            ipv6_enabled: true,
            ipv6_authorized_cidrs: vec!["2001:db8::/112".to_owned()],
            ipv6_task_prefix: 120,
            ..AutomaticTargetConfig::default()
        })
        .unwrap();
        let generator = &service.generators[1];

        assert_eq!(position_of_cidr(generator, "2001:db8::8000/120"), Some(128));
        assert_eq!(
            service
                .resolve_position("ipv6", None, Some("2001:db8::8000/120"))
                .unwrap(),
            128
        );
        assert!(service.resolve_position("ipv6", Some(256), None).is_err());
    }

    #[test]
    fn zero_task_prefix_resolves_and_jumps_without_overflow() {
        let service = AutomaticTargetService::new(AutomaticTargetConfig {
            ipv6_enabled: true,
            ipv6_authorized_cidrs: vec!["::/0".to_owned()],
            ipv6_excluded_cidrs: vec!["fc00::/7".to_owned()],
            ipv6_task_prefix: 0,
            ..AutomaticTargetConfig::default()
        })
        .unwrap();
        let generator = &service.generators[1];
        assert_eq!(generator.total_subnets, 1);
        assert_eq!(target_at(generator, 0).cidr, "::/0");
        assert_eq!(position_of_cidr(generator, "::/0"), Some(0));
        assert!(is_excluded(generator, "::/0"));
        // The whole-space task is excluded: the jump leaves the single-subnet pool.
        assert_eq!(position_after_exclusions(generator, 0, "::/0"), 1);

        let service = AutomaticTargetService::new(AutomaticTargetConfig {
            enabled: true,
            authorized_cidrs: vec!["0.0.0.0/0".to_owned()],
            ipv4_task_prefix: 0,
            ..AutomaticTargetConfig::default()
        })
        .unwrap();
        let generator = &service.generators[0];
        assert_eq!(generator.total_subnets, 1);
        assert_eq!(target_at(generator, 0).cidr, "0.0.0.0/0");
        assert_eq!(position_of_cidr(generator, "0.0.0.0/0"), Some(0));
        assert_eq!(position_after_exclusions(generator, 0, "0.0.0.0/0"), 1);
    }

    #[test]
    fn policy_change_preserves_the_coverage_cursor() {
        let cursor = json!({"position": "129540"});
        // Same policy: position is kept as stored.
        assert_eq!(resume_position("same", "same", &cursor, 65_536), 129_540);
        // Changed policy: keep coverage, normalized into the new subnet space.
        assert_eq!(resume_position("old", "new", &cursor, 1 << 24), 129_540);
        assert_eq!(
            resume_position("old", "new", &cursor, 65_536),
            129_540 % 65_536
        );
        // Missing cursor still starts at zero; empty space never divides by zero.
        assert_eq!(resume_position("old", "new", &json!(null), 65_536), 0);
        assert_eq!(resume_position("old", "new", &cursor, 0), 129_540);
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
