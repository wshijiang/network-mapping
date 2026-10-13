//! Search-triggered tasks share the normal scanner queue. PostgreSQL owns both
//! admission and cooldown; no process-local cache is relied on for correctness.
use std::net::IpAddr;

use deadpool_postgres::Pool;
use ipnet::IpNet;
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::admin::{UserBaseI, get_default_scan_profile_from_database};
use crate::audit::{AuditContext, AuditEvent, write};
use crate::config::AutomaticTargetConfig;
use crate::elasticsearch::ElasticsearchService;
use crate::handlers::search_dsl::{
    ElasticsearchCompilation, SearchTarget, extract_search_target, parse_and_compile_elasticsearch,
};

type Error = Box<dyn std::error::Error + Send + Sync>;
// Dedicated application advisory-lock namespace, held only for short PG work.
const ADMISSION_LOCK: i64 = 0x534541524348;

#[derive(Debug, Serialize)]
pub(crate) struct GenerationResult {
    pub status: &'static str,
    pub reason: Option<&'static str>,
    pub target: Option<String>,
    pub task_id: Option<String>,
    /// Unix epoch milliseconds, consistent with search scan_time.
    pub next_eligible_at: Option<i64>,
}

impl GenerationResult {
    pub fn status(status: &'static str) -> Self {
        Self {
            status,
            reason: None,
            target: None,
            task_id: None,
            next_eligible_at: None,
        }
    }
    fn target(status: &'static str, target: &SearchTarget) -> Self {
        Self {
            target: Some(target.key.clone()),
            ..Self::status(status)
        }
    }
}

fn allows(policy: &AutomaticTargetConfig, target: &SearchTarget) -> bool {
    if target.kind == "domain" {
        return policy.search_generation.domain_enabled
            && policy
                .search_generation
                .authorized_domains
                .iter()
                .any(|value| {
                    crate::dns::canonical_scan_domain(value).is_ok_and(|domain| {
                        target.key == domain || target.key.ends_with(&format!(".{domain}"))
                    })
                });
    }
    let Ok(ip) = target.key.parse::<IpAddr>() else {
        return false;
    };
    let (authorized, excluded) = if ip.is_ipv4() {
        (&policy.authorized_cidrs, &policy.excluded_cidrs)
    } else {
        (&policy.ipv6_authorized_cidrs, &policy.ipv6_excluded_cidrs)
    };
    let contains = |value: &str| {
        value
            .parse::<IpNet>()
            .is_ok_and(|network| network.contains(&ip))
    };
    authorized.iter().any(|v| contains(v))
        && !excluded.iter().any(|v| contains(v))
        && !(ip.is_ipv4() && super::MANDATORY_IPV4_EXCLUSIONS.iter().any(|v| contains(v)))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn generate(
    pool: &Pool,
    elasticsearch: &ElasticsearchService,
    user: &UserBaseI,
    policy: &AutomaticTargetConfig,
    revision: i64,
    query: &str,
    dns_follow_up_enabled: bool,
    audit: &AuditContext,
) -> Result<GenerationResult, Error> {
    if !policy.search_generation.enabled {
        return Ok(GenerationResult::status("disabled"));
    }
    let Some(target) = extract_search_target(query) else {
        return Ok(GenerationResult::status("unsupported"));
    };
    if !allows(policy, &target) {
        return Ok(GenerationResult::target("out_of_scope", &target));
    }
    if target.kind == "domain" && !dns_follow_up_enabled {
        return Ok(GenerationResult::target("unavailable", &target));
    }
    // Never use the user's endpoint filters to infer that a target is absent.
    let query = format!(
        "{} = {}",
        if target.kind == "ip" { "ip" } else { "domain" },
        serde_json::to_string(&target.key)?
    );
    let filter = match parse_and_compile_elasticsearch(&query).map_err(|e| e.message)? {
        ElasticsearchCompilation::Supported(filter)
        | ElasticsearchCompilation::RequiresElasticsearch(filter) => filter,
        ElasticsearchCompilation::Unsupported => {
            return Ok(GenerationResult::target("unsupported", &target));
        }
    };
    let observation = elasticsearch
        .search(
            user.role,
            user.id,
            filter,
            1,
            0,
            crate::elasticsearch::SearchSort::default(),
        )
        .await?
        .items
        .first()
        .map(|item| item.scan_time);
    let profile = get_default_scan_profile_from_database(pool).await?;
    admit(
        pool,
        user,
        policy,
        revision,
        &target,
        observation,
        &profile,
        audit,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn admit(
    pool: &Pool,
    user: &UserBaseI,
    policy: &AutomaticTargetConfig,
    revision: i64,
    target: &SearchTarget,
    observation: Option<i64>,
    profile: &str,
    audit: &AuditContext,
) -> Result<GenerationResult, Error> {
    let settings = &policy.search_generation;
    let signature = json!({"profile": profile, "ports": policy.common_ports});
    let task_profile = if target.kind == "domain" {
        "dns_records"
    } else {
        profile
    };
    let plan = crate::scan_control::creation::build_scan_plan(task_profile)?;
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout = '1500ms'; SET LOCAL statement_timeout = '2000ms';")
        .await?;
    // Serializes cross-target quota admission as well as same-target requests.
    tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&ADMISSION_LOCK])
        .await?;
    tx.execute("INSERT INTO search_target_state(owner_id,target_kind,target_key) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", &[&user.id,&target.kind,&target.key]).await?;
    let state = tx.query_one("SELECT *, (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)*1000)::BIGINT AS now_ms FROM search_target_state WHERE owner_id=$1 AND target_kind=$2 AND target_key=$3 FOR UPDATE", &[&user.id,&target.kind,&target.key]).await?;
    let now: i64 = state.get("now_ms");
    let last_generated: Option<i64> = state.get("last_search_generated_at");
    let cooldown_until = last_generated.map(|at| at + i64::from(settings.cooldown_minutes) * 60000);
    // Only the owner's tasks are reusable. DNS descendants remain part of the
    // in-flight operation even after their DNS parent succeeds.
    let matching = tx.query(
        "SELECT t.task_id, e.execution_status, GREATEST(e.task_end_time, (SELECT MAX(c.task_end_time) FROM scan_task_lineage l JOIN scan_task_execution c ON c.task_id=l.child_task_id WHERE l.parent_execution_id=e.id)) AS task_end_time, \
         EXISTS(SELECT 1 FROM scan_task_lineage l JOIN scan_task_execution c ON c.task_id=l.child_task_id WHERE l.parent_execution_id=e.id AND c.execution_status IN ('pending','running')) AS child_active, \
         EXISTS(SELECT 1 FROM scan_task_lineage l JOIN scan_task_execution c ON c.task_id=l.child_task_id WHERE l.parent_execution_id=e.id AND c.execution_status <> 'succeeded') AS child_incomplete \
         FROM scan_task t JOIN scan_task_execution e ON e.task_id=t.id \
         WHERE t.user_id=$1 AND (t.task_port=$4 OR t.task_port='1-65535') AND \
         CASE WHEN $2='ip' THEN t.task_kind='ip' AND t.scan_profile=$5 AND EXISTS(SELECT 1 FROM unnest(t.task_target) a WHERE a >>= $3::text::inet) \
         ELSE t.task_kind='dns' AND $3=ANY(t.dns_targets) AND t.generation_metadata->'dns_follow_up'->>'scan_profile'=$5 END",
        &[&user.id,&target.kind,&target.key,&policy.common_ports,&profile],
    ).await?;
    if let Some(row) = matching.iter().find(|row| {
        matches!(
            row.get::<_, &str>("execution_status"),
            "pending" | "running"
        ) || row.get::<_, bool>("child_active")
    }) {
        let mut result = GenerationResult::target("existing", target);
        result.task_id = Some(row.get("task_id"));
        tx.commit().await?;
        return Ok(result);
    }
    let historical = matching
        .iter()
        .filter(|row| {
            row.get::<_, &str>("execution_status") == "succeeded"
                && !row.get::<_, bool>("child_incomplete")
        })
        .filter_map(|row| row.get::<_, Option<i64>>("task_end_time"))
        .max();
    let cached = if state.get::<_, Option<Value>>("last_success_plan").as_ref() == Some(&signature)
    {
        state.get::<_, Option<i64>>("last_success_at")
    } else {
        None
    };
    let success = historical.into_iter().chain(cached).max();
    if let Some(at) = success {
        tx.execute("UPDATE search_target_state SET last_success_at=$4,last_success_plan=$5 WHERE owner_id=$1 AND target_kind=$2 AND target_key=$3", &[&user.id,&target.kind,&target.key,&at,&signature]).await?;
    }
    // Legacy endpoint observations bootstrap IP freshness only when there is no
    // compatible execution history. They never stand in for DNS completion.
    let fresh_at = success.or_else(|| {
        if target.kind == "ip" {
            observation
        } else {
            None
        }
    });
    if fresh_at.is_some_and(|at| now - at <= i64::from(settings.stale_after_days) * 86400000) {
        tx.commit().await?;
        return Ok(GenerationResult::target("fresh", target));
    }
    if cooldown_until.is_some_and(|until| now < until) {
        let mut result = GenerationResult::target("cooldown", target);
        result.next_eligible_at = cooldown_until;
        // Task may have been deleted; don't return a broken link.
        let previous: Option<String> = state.get("last_search_task_id");
        if let Some(id) = previous
            && tx
                .query_opt(
                    "SELECT 1 FROM scan_task WHERE task_id=$1 AND user_id=$2",
                    &[&id, &user.id],
                )
                .await?
                .is_some()
        {
            result.task_id = Some(id);
        }
        tx.commit().await?;
        return Ok(result);
    }
    let pending: i64 = tx.query_one("SELECT COUNT(*) FROM scan_task t JOIN scan_task_execution e ON e.task_id=t.id WHERE t.task_source='search' AND e.execution_status='pending'", &[]).await?.get(0);
    if pending >= i64::from(settings.max_pending_tasks) {
        tx.commit().await?;
        return Ok(GenerationResult::target("queue_full", target));
    }
    tx.execute(
        "DELETE FROM search_generation_admission WHERE generated_at < $1",
        &[&(now - 3600000)],
    )
    .await?;
    let hourly: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM search_generation_admission WHERE owner_id=$1",
            &[&user.id],
        )
        .await?
        .get(0);
    if hourly >= i64::from(settings.per_user_hourly_limit) {
        tx.commit().await?;
        return Ok(GenerationResult::target("rate_limited", target));
    }
    let task_id = Uuid::now_v7().to_string();
    let reason = if success.is_some() || observation.is_some() {
        "stale"
    } else {
        "missing"
    };
    let mut metadata = json!({"reason":reason,"config_revision":revision,"target":target.key,"stale_after_days":settings.stale_after_days});
    if target.kind == "domain" {
        metadata["dns_follow_up"] = json!({"enabled":true,"scan_profile":profile});
    }
    let family = if target.kind == "ip" && target.key.parse::<IpAddr>()?.is_ipv6() {
        "ipv6"
    } else {
        "ipv4"
    };
    let key = format!("search:{}:{}:{}", user.id, target.kind, target.key);
    let task_pk: i32 = tx.query_one(
        "INSERT INTO scan_task(user_id,task_id,task_initiator,task_target,task_port,task_level,remarks,dispatch_mode,task_source,generation_strategy,generation_key,generation_metadata,address_family,scan_profile,scan_plan,task_kind,dns_targets) \
         VALUES($1,$2,$12,CASE WHEN $3='ip' THEN ARRAY[$4::text::inet] ELSE ARRAY[]::inet[] END,$5,$6,'搜索触发自动更新','automatic','search','search_on_demand',$7,$8,$9,$10,$11,CASE WHEN $3='ip' THEN 'ip' ELSE 'dns' END,CASE WHEN $3='domain' THEN ARRAY[$4::text] ELSE ARRAY[]::text[] END) RETURNING id",
        &[&user.id,&task_id,&target.kind,&target.key,&policy.common_ports,&policy.priority,&key,&metadata,&family,&task_profile,&plan,&user.username],
    ).await?.get(0);
    tx.execute(
        "INSERT INTO scan_task_execution(execution_id,task_id) VALUES($1,$2)",
        &[&Uuid::now_v7().to_string(), &task_pk],
    )
    .await?;
    tx.execute("UPDATE search_target_state SET last_search_generated_at=$4,last_search_task_id=$5 WHERE owner_id=$1 AND target_kind=$2 AND target_key=$3", &[&user.id,&target.kind,&target.key,&now,&task_id]).await?;
    tx.execute(
        "INSERT INTO search_generation_admission(owner_id,generated_at,task_id) VALUES($1,$2,$3)",
        &[&user.id, &now, &task_id],
    )
    .await?;
    let mut event = AuditEvent::user("automatic_target", "task.search_generate", "success", user)
        .resource("task", &task_id);
    event.metadata = metadata;
    write(&tx, audit, &event).await?;
    tx.commit().await?;
    Ok(GenerationResult {
        reason: Some(reason),
        task_id: Some(task_id),
        next_eligible_at: Some(now + i64::from(settings.cooldown_minutes) * 60000),
        ..GenerationResult::target("created", target)
    })
}

/// Called inside the successful-upload transaction, including zero-result
/// executions. DNS freshness waits for any generated descendants to succeed.
pub(crate) async fn record_success(
    tx: &deadpool_postgres::Transaction<'_>,
    completed_task_id: i32,
) -> Result<(), tokio_postgres::Error> {
    tx.execute(
        "WITH candidates AS (SELECT DISTINCT ON (s.owner_id,s.target_kind,s.target_key) \
         s.owner_id,s.target_kind,s.target_key,GREATEST(e.task_end_time, (SELECT MAX(c.task_end_time) FROM scan_task_lineage l JOIN scan_task_execution c ON c.task_id=l.child_task_id WHERE l.parent_execution_id=e.id)) AS task_end_time, \
         jsonb_build_object('profile',CASE WHEN t.task_kind='dns' THEN t.generation_metadata->'dns_follow_up'->>'scan_profile' ELSE t.scan_profile END,'ports',t.task_port) AS plan \
         FROM search_target_state s JOIN scan_task t ON t.user_id=s.owner_id \
         JOIN scan_task_execution e ON e.task_id=t.id \
         WHERE (t.id=$1 OR t.id IN (SELECT parent_task_id FROM scan_task_lineage WHERE child_task_id=$1)) \
         AND e.execution_status='succeeded' AND e.task_end_time IS NOT NULL \
         AND CASE WHEN s.target_kind='ip' THEN t.task_kind='ip' AND EXISTS(SELECT 1 FROM unnest(t.task_target) a WHERE a >>= s.target_key::inet) \
         ELSE t.task_kind='dns' AND s.target_key=ANY(t.dns_targets) AND t.generation_metadata->'dns_follow_up'->>'scan_profile' IS NOT NULL END \
         AND NOT EXISTS(SELECT 1 FROM scan_task_lineage l JOIN scan_task_execution child ON child.task_id=l.child_task_id WHERE l.parent_execution_id=e.id AND child.execution_status<>'succeeded') \
         ORDER BY s.owner_id,s.target_kind,s.target_key,4 DESC) \
         UPDATE search_target_state s SET last_success_at=c.task_end_time,last_success_plan=c.plan FROM candidates c \
         WHERE s.owner_id=c.owner_id AND s.target_kind=c.target_kind AND s.target_key=c.target_key \
         AND (s.last_success_at IS NULL OR s.last_success_at<=c.task_end_time)",
        &[&completed_task_id],
    ).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_require_positive_single_target_and_normalize_domains_and_ips() {
        for query in [
            "service = https",
            "ip IN 192.0.2.0/24",
            "ip = 192.0.2.1 OR port = 80",
            "NOT ip = 192.0.2.1",
            "ip = 192.0.2.1 AND ip = 192.0.2.2",
            "domain ~ example.com",
            "ip = 192.0.2.1 AND NOT port = 80",
        ] {
            assert!(extract_search_target(query).is_none(), "{query}");
        }
        assert_eq!(
            extract_search_target("ip = 2001:0db8::1 AND port = 443")
                .unwrap()
                .key,
            "2001:db8::1"
        );
        assert_eq!(
            extract_search_target("domain = \"WWW.Example.COM.\" AND service = https")
                .unwrap()
                .key,
            "www.example.com"
        );
    }

    #[test]
    fn policy_requires_authorization_and_respects_domain_label_boundaries() {
        let mut policy = AutomaticTargetConfig {
            authorized_cidrs: vec!["192.0.2.0/24".into(), "0.0.0.0/8".into()],
            excluded_cidrs: vec!["192.0.2.128/25".into()],
            ..Default::default()
        };
        policy.search_generation.domain_enabled = true;
        policy.search_generation.authorized_domains = vec!["Example.COM.".into()];
        let target = |kind, key: &str| SearchTarget {
            kind,
            key: key.into(),
        };
        assert!(allows(&policy, &target("ip", "192.0.2.1")));
        assert!(!allows(&policy, &target("ip", "192.0.2.129")));
        assert!(!allows(&policy, &target("ip", "0.1.2.3")));
        assert!(!allows(&policy, &target("ip", "2001:db8::1")));
        assert!(allows(&policy, &target("domain", "a.example.com")));
        assert!(!allows(&policy, &target("domain", "notexample.com")));
    }

    #[test]
    fn configuration_defaults_and_bounds_are_validated() {
        let policy: AutomaticTargetConfig = serde_json::from_value(json!({})).unwrap();
        assert_eq!(policy.search_generation.stale_after_days, 7);
        assert!(!policy.search_generation.enabled);
        for (key, value) in [
            ("stale_after_days", 0),
            ("cooldown_minutes", 0),
            ("max_pending_tasks", 10001),
            ("per_user_hourly_limit", 0),
        ] {
            let policy: AutomaticTargetConfig =
                serde_json::from_value(json!({"search_generation":{key:value}})).unwrap();
            assert!(policy.validate().is_err(), "{key}");
        }
    }

    struct Fixture {
        pool: Pool,
        schema: String,
        policy: AutomaticTargetConfig,
        user: UserBaseI,
        audit: AuditContext,
    }
    impl Fixture {
        async fn new() -> Self {
            let mut config: tokio_postgres::Config = std::env::var("STORAGE_TEST_DATABASE_URL")
                .expect("disposable PG URL")
                .parse()
                .unwrap();
            let schema = format!("search_{}", Uuid::new_v4().simple());
            config.options(format!("-c search_path={schema}"));
            let pool = Pool::builder(deadpool_postgres::Manager::new(
                config,
                tokio_postgres::NoTls,
            ))
            .max_size(16)
            .build()
            .unwrap();
            let c = pool.get().await.unwrap();
            c.batch_execute(&format!("CREATE SCHEMA {schema}"))
                .await
                .unwrap();
            c.batch_execute(include_str!("../../source/database/init.sql"))
                .await
                .unwrap();
            // Verify repeatable upgrades as well as fresh installation.
            c.batch_execute(include_str!("../../source/database/init.sql"))
                .await
                .unwrap();
            c.batch_execute("INSERT INTO users(id,username,password,role) VALUES(1,'search-test','unused',2),(2,'other','unused',2)").await.unwrap();
            let mut policy = AutomaticTargetConfig::default();
            policy.search_generation.enabled = true;
            policy.search_generation.per_user_hourly_limit = 1000;
            policy.search_generation.max_pending_tasks = 1000;
            Self {
                pool,
                schema,
                policy,
                user: UserBaseI {
                    id: 1,
                    username: "search-test".into(),
                    role: 2,
                    email: None,
                    limit_login: false,
                    enable_2fa: false,
                },
                audit: AuditContext {
                    request_id: Uuid::new_v4(),
                    source_ip: None,
                    user_agent: None,
                    http_method: "POST".into(),
                    request_path: "/api/search/v2".into(),
                },
            }
        }
        async fn request(
            &self,
            kind: &'static str,
            key: &str,
            observation: Option<i64>,
        ) -> GenerationResult {
            admit(
                &self.pool,
                &self.user,
                &self.policy,
                1,
                &SearchTarget {
                    kind,
                    key: key.into(),
                },
                observation,
                "legacy",
                &self.audit,
            )
            .await
            .unwrap()
        }
        async fn sql(&self, sql: &str) {
            self.pool
                .get()
                .await
                .unwrap()
                .batch_execute(sql)
                .await
                .unwrap();
        }
        async fn finish(&self, id: &str) {
            let mut c = self.pool.get().await.unwrap();
            let tx = c.transaction().await.unwrap();
            let pk: i32 = tx
                .query_one("SELECT id FROM scan_task WHERE task_id=$1", &[&id])
                .await
                .unwrap()
                .get(0);
            tx.execute("UPDATE scan_task_execution SET execution_status='succeeded', task_end_time=(EXTRACT(EPOCH FROM NOW())*1000)::BIGINT, result_ip_count=0,result_port_count=0 WHERE task_id=$1", &[&pk]).await.unwrap();
            record_success(&tx, pk).await.unwrap();
            tx.commit().await.unwrap();
        }
        async fn cleanup(self) {
            self.pool
                .get()
                .await
                .unwrap()
                .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    #[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
    async fn concurrent_searches_cooldown_freshness_and_user_isolation() {
        let mut f = Fixture::new().await;
        let requests = (0..100).map(|_| f.request("ip", "192.0.2.1", None));
        let results = futures_util::future::join_all(requests).await;
        assert_eq!(results.iter().filter(|r| r.status == "created").count(), 1);
        assert_eq!(
            results.iter().filter(|r| r.status == "existing").count(),
            99
        );
        let id = results
            .iter()
            .find(|r| r.status == "created")
            .unwrap()
            .task_id
            .as_ref()
            .unwrap();
        f.finish(id).await;
        assert_eq!(f.request("ip", "192.0.2.1", None).await.status, "fresh");
        // Completed empty scans remain fresh even after their tasks are deleted.
        f.sql("DELETE FROM scan_task").await;
        assert_eq!(f.request("ip", "192.0.2.1", None).await.status, "fresh");
        f.sql("UPDATE search_target_state SET last_success_at=last_success_at-8*86400000::BIGINT")
            .await;
        assert_eq!(f.request("ip", "192.0.2.1", None).await.status, "cooldown");
        f.sql("UPDATE search_target_state SET last_search_generated_at=last_search_generated_at-2*86400000::BIGINT").await;
        assert_eq!(f.request("ip", "192.0.2.1", None).await.status, "created");
        f.sql("UPDATE scan_task_execution SET execution_status='failed'")
            .await;
        assert_eq!(f.request("ip", "192.0.2.1", None).await.status, "cooldown");
        f.user.id = 2;
        assert_eq!(f.request("ip", "192.0.2.1", None).await.status, "created");
        f.cleanup().await;
    }

    #[tokio::test]
    #[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
    async fn quotas_rollback_observation_and_live_expiry_configuration() {
        let mut f = Fixture::new().await;
        let now = crate::clock::get_unix_epoch_ms();
        assert_eq!(
            f.request("ip", "192.0.2.1", Some(now - 6 * 86400000))
                .await
                .status,
            "fresh"
        );
        f.policy.search_generation.stale_after_days = 5;
        let r = f.request("ip", "192.0.2.1", Some(now - 6 * 86400000)).await;
        assert_eq!(r.status, "created");
        assert_eq!(r.reason, Some("stale"));
        f.policy.search_generation.max_pending_tasks = 1;
        assert_eq!(
            f.request("ip", "192.0.2.2", None).await.status,
            "queue_full"
        );
        f.sql("UPDATE scan_task_execution SET execution_status='cancelled'")
            .await;
        f.policy.search_generation.per_user_hourly_limit = 1;
        assert_eq!(
            f.request("ip", "192.0.2.2", None).await.status,
            "rate_limited"
        );
        f.sql("DELETE FROM scan_task").await;
        assert_eq!(
            f.request("ip", "192.0.2.2", None).await.status,
            "rate_limited"
        );
        f.policy.search_generation.per_user_hourly_limit = 100;
        f.policy.priority = 9; // Force insert failure after obtaining admission lock.
        assert!(
            admit(
                &f.pool,
                &f.user,
                &f.policy,
                1,
                &SearchTarget {
                    kind: "ip",
                    key: "192.0.2.2".into()
                },
                None,
                "legacy",
                &f.audit
            )
            .await
            .is_err()
        );
        f.policy.priority = 0;
        assert_eq!(f.request("ip", "192.0.2.2", None).await.status, "created");
        f.cleanup().await;
    }

    #[tokio::test]
    #[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
    async fn dns_descendants_delay_freshness_and_task_reuse_covers_subnets() {
        let f = Fixture::new().await;
        let parent = f.request("domain", "www.example.com", None).await;
        assert_eq!(parent.status, "created");
        f.sql("UPDATE scan_task_execution SET execution_status='succeeded',task_end_time=(EXTRACT(EPOCH FROM NOW())*1000)::BIGINT-8*86400000::BIGINT").await;
        let child = f.request("ip", "192.0.2.1", None).await;
        let c = f.pool.get().await.unwrap();
        c.execute("INSERT INTO scan_task_lineage(parent_task_id,parent_execution_id,child_task_id,source_addresses) SELECT p.id,e.id,c.id,ARRAY['192.0.2.1'::inet] FROM scan_task p JOIN scan_task_execution e ON e.task_id=p.id CROSS JOIN scan_task c WHERE p.task_id=$1 AND c.task_id=$2", &[&parent.task_id,&child.task_id]).await.unwrap();
        drop(c);
        assert_eq!(
            f.request("domain", "www.example.com", None).await.status,
            "existing"
        );
        f.finish(child.task_id.as_deref().unwrap()).await;
        assert_eq!(
            f.request("domain", "www.example.com", None).await.status,
            "fresh"
        );
        f.sql("UPDATE scan_task SET task_target=ARRAY['198.51.100.0/24'::inet],task_source='manual' WHERE task_kind='ip'; UPDATE scan_task_execution SET execution_status='pending' WHERE task_id IN (SELECT id FROM scan_task WHERE task_kind='ip')").await;
        assert_eq!(
            f.request("ip", "198.51.100.42", None).await.status,
            "existing"
        );
        f.cleanup().await;
    }
    #[tokio::test]
    #[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
    async fn concurrent_distinct_targets_respect_queue_and_user_limits() {
        let mut f = Fixture::new().await;
        f.policy.search_generation.per_user_hourly_limit = 2;
        f.policy.search_generation.max_pending_tasks = 3;
        let targets = (1..=100)
            .map(|i| format!("192.0.2.{i}"))
            .collect::<Vec<_>>();
        let results = futures_util::future::join_all(
            targets.iter().map(|target| f.request("ip", target, None)),
        )
        .await;
        assert_eq!(results.iter().filter(|r| r.status == "created").count(), 2);
        assert_eq!(
            results
                .iter()
                .filter(|r| r.status == "rate_limited")
                .count(),
            98
        );
        f.policy.search_generation.per_user_hourly_limit = 100;
        let targets = (1..=100)
            .map(|i| format!("198.51.100.{i}"))
            .collect::<Vec<_>>();
        let results = futures_util::future::join_all(
            targets.iter().map(|target| f.request("ip", target, None)),
        )
        .await;
        assert_eq!(results.iter().filter(|r| r.status == "created").count(), 1);
        assert_eq!(
            results.iter().filter(|r| r.status == "queue_full").count(),
            99
        );
        f.cleanup().await;
    }
}
