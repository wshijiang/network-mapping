//! Automatic placement uses GeoIP and observed execution quality; no reachability CIDRs.
//! PostgreSQL owns short preferences, so multiple servers agree and a dead planner
//! cannot hold work indefinitely. Selected/all executions retain their semantics.
use std::{collections::HashMap, net::IpAddr, time::Duration};

use deadpool_postgres::{GenericClient, Pool};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_postgres::Row;

use crate::{
    maxmind::{IpIntel, MaxMindState},
    scanner_health,
    system_maintenance::SystemMaintenanceState,
};

type Error = Box<dyn std::error::Error + Send + Sync>;
const PLANNER_LOCK: i64 = 0x4e4d524f555445;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoutingConfig {
    pub enabled: bool,
    pub preference_seconds: u32,
    pub candidate_limit: u32,
    pub feedback_max_age_hours: u32,
}
impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            preference_seconds: 15,
            candidate_limit: 64,
            feedback_max_age_hours: 168,
        }
    }
}
impl RoutingConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(5..=60).contains(&self.preference_seconds) {
            return Err("优先领取时间必须为 5～60 秒".into());
        }
        if !(1..=256).contains(&self.candidate_limit) {
            return Err("每轮调度任务数必须为 1～256".into());
        }
        if !(1..=720).contains(&self.feedback_max_age_hours) {
            return Err("执行反馈有效期必须为 1～720 小时".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Geo {
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub accuracy_radius_km: Option<u16>,
}
impl From<IpIntel> for Geo {
    fn from(i: IpIntel) -> Self {
        Self {
            country_code: i.country_code,
            region: i.region_name,
            city: i.city_name,
            latitude: i.latitude,
            longitude: i.longitude,
            accuracy_radius_km: i.accuracy_radius,
        }
    }
}

/// Bounded samples are a soft hint, never proof that a whole network is reachable.
pub fn target_geo(targets: &[String], maxmind: &MaxMindState) -> Geo {
    if targets.is_empty() || targets.len() > 16 {
        return Geo::default();
    }
    let mut locations = Vec::new();
    for target in targets {
        let net = match target
            .parse::<IpNet>()
            .ok()
            .or_else(|| target.parse::<IpAddr>().ok().map(IpNet::from))
        {
            Some(net) => net,
            None => return Geo::default(),
        };
        if (net.addr().is_ipv4() && net.prefix_len() < 24)
            || (net.addr().is_ipv6() && net.prefix_len() < 120)
        {
            return Geo::default();
        }
        for address in [net.network(), net.broadcast()] {
            let geo = Geo::from(maxmind.lookup(address));
            if geo.country_code.is_none() {
                return Geo::default();
            }
            locations.push(geo);
        }
    }
    let Some(first) = locations.first() else {
        return Geo::default();
    };
    if locations
        .iter()
        .any(|g| g.country_code != first.country_code || g.region != first.region)
    {
        return Geo::default();
    }
    first.clone()
}

pub fn target_key(targets: &[String], family: &str, profile: &str, ports: &str) -> String {
    let mut targets: Vec<String> = targets
        .iter()
        .map(|target| {
            target
                .parse::<IpNet>()
                .ok()
                .or_else(|| target.parse::<IpAddr>().ok().map(IpNet::from))
                .map(|net| net.trunc().to_string())
                .unwrap_or_else(|| target.trim().trim_end_matches('.').to_ascii_lowercase())
        })
        .collect();
    targets.sort();
    targets.dedup();
    let mut ranges: Vec<(u16, u16)> = ports
        .split(',')
        .filter_map(|p| {
            let p = p.trim();
            if let Some((a, b)) = p.split_once('-') {
                Some((a.parse().ok()?, b.parse().ok()?))
            } else {
                let p = p.parse().ok()?;
                Some((p, p))
            }
        })
        .filter(|(a, b)| a <= b)
        .collect();
    ranges.sort_unstable();
    let mut merged: Vec<(u16, u16)> = Vec::new();
    for (a, b) in ranges {
        if let Some(last) = merged.last_mut()
            && a <= last.1.saturating_add(1)
        {
            last.1 = last.1.max(b);
        } else {
            merged.push((a, b));
        }
    }
    let bytes = serde_json::to_vec(&(family, profile, merged, targets))
        .expect("serializable target signature");
    openssl::sha::sha256(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Each group becomes its own scan_task, never duplicate full-target executions.
pub fn group_targets(targets: &[IpNet], locate: impl Fn(&IpNet) -> Geo) -> Vec<Vec<IpNet>> {
    if targets.len() > 512 {
        return vec![targets.to_vec()];
    }
    let mut groups = std::collections::BTreeMap::<String, Vec<IpNet>>::new();
    for target in targets {
        let geo = locate(target);
        let key = match (geo.country_code, geo.region) {
            (Some(country), Some(region)) => format!("{country}:{region}"),
            (Some(country), None) => country,
            _ => "unknown".into(),
        };
        groups.entry(key).or_default().push(*target);
    }
    if groups.len() > 32 {
        return vec![targets.to_vec()];
    }
    groups.into_values().collect()
}

#[derive(Clone, Debug, Default)]
struct Feedback {
    successes: i32,
    route_failures: i32,
    elapsed_ms: Option<f64>,
    connect_ms: Option<f64>,
    connect_samples: i32,
}
#[derive(Clone, Debug, Serialize)]
pub struct Candidate {
    pub scanner_id: String,
    pub name: String,
    pub geo: Geo,
    pub busy: bool,
    pub reservations: i64,
    pub score: f64,
    pub reasons: Vec<String>,
    pub history_samples: i32,
    pub target_connect_ms: Option<f64>,
    #[serde(skip)]
    feedback: Feedback,
}

fn distance(a: &Geo, b: &Geo) -> Option<f64> {
    let (lat1, lon1, lat2, lon2) = (a.latitude?, a.longitude?, b.latitude?, b.longitude?);
    if [lat1, lon1, lat2, lon2].iter().any(|n| !n.is_finite()) {
        return None;
    }
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let h = ((dlat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2))
    .clamp(0.0, 1.0);
    Some(6371.0 * 2.0 * h.sqrt().asin())
}
fn rank(candidates: &mut [Candidate], target: &Geo) {
    let fastest = candidates
        .iter()
        .filter(|c| c.feedback.successes >= 3)
        .filter_map(|c| c.feedback.elapsed_ms)
        .filter(|n| n.is_finite() && *n > 0.0)
        .reduce(f64::min);
    for c in candidates.iter_mut() {
        let mut affinity = 0.5;
        c.reasons.clear();
        if target.country_code.is_some() && c.geo.country_code.is_some() {
            affinity = if target.country_code == c.geo.country_code {
                0.7
            } else {
                0.15
            };
            if target.country_code == c.geo.country_code
                && target.region.is_some()
                && target.region == c.geo.region
            {
                affinity = 0.9;
                c.reasons.push("same_region".into());
            } else if target.country_code == c.geo.country_code {
                c.reasons.push("same_country".into());
            } else {
                c.reasons.push("other_region".into());
            }
            if let Some(km) = distance(target, &c.geo) {
                let uncertainty = f64::from(target.accuracy_radius_km.unwrap_or(0))
                    + f64::from(c.geo.accuracy_radius_km.unwrap_or(0));
                affinity = 0.5 * affinity + 0.5 / (1.0 + (km - uncertainty).max(0.0) / 1000.0);
            }
        } else {
            c.reasons.push("geo_unknown".into());
        }
        let load = if c.busy {
            0.0
        } else {
            1.0 / (1.0 + c.reservations as f64)
        };
        let mut quality = 0.5;
        if c.feedback.successes >= 3 {
            if let (Some(best), Some(elapsed)) = (fastest, c.feedback.elapsed_ms) {
                quality = (best / elapsed.max(1.0)).clamp(0.0, 1.0);
            }
            c.reasons.push("execution_history".into());
        }
        if c.feedback.connect_samples >= 3
            && let Some(ms) = c.feedback.connect_ms
        {
            quality = 0.5 * quality + 0.5 / (1.0 + ms.max(0.0) / 100.0);
            c.reasons.push("measured_target_quality".into());
        }
        let route_penalty = (f64::from(c.feedback.route_failures) * 0.25).min(0.75);
        c.score = (0.45 * affinity + 0.25 * load + 0.30 * quality - route_penalty).clamp(0.0, 1.0);
        if c.feedback.route_failures > 0 {
            c.reasons.push("recent_route_failure".into());
        }
        c.reasons.push(if c.busy { "busy" } else { "idle" }.into());
        c.history_samples = c.feedback.successes;
        c.target_connect_ms = c.feedback.connect_ms;
    }
    candidates.sort_by(|a, b| {
        a.busy
            .cmp(&b.busy)
            .then_with(|| b.score.total_cmp(&a.score))
            .then_with(|| a.scanner_id.cmp(&b.scanner_id))
    });
}

pub async fn config<C: GenericClient + Sync>(client: &C) -> Result<RoutingConfig, Error> {
    let settings = client
        .query_opt(
            "SELECT document FROM runtime_configuration WHERE namespace='scan_routing'",
            &[],
        )
        .await?
        .map(|r| serde_json::from_value::<RoutingConfig>(r.get("document")))
        .transpose()?
        .unwrap_or_default();
    settings.validate().map_err(std::io::Error::other)?;
    Ok(settings)
}

#[allow(clippy::too_many_arguments)]
pub async fn candidates<C: GenericClient + Sync>(
    client: &C,
    maxmind: &MaxMindState,
    targets: &[String],
    family: &str,
    profile: &str,
    ports: &str,
    owner: i32,
    resolvers: &Value,
    required_services: &Value,
    cfg: &RoutingConfig,
) -> Result<Vec<Candidate>, Error> {
    let require_v6 = resolvers.as_array().is_some_and(|v| {
        v.iter().any(|r| {
            r.get("ip")
                .and_then(Value::as_str)
                .is_some_and(|ip| ip.contains(':'))
        })
    });
    let sql = format!(
        "SELECT s.scanner_id, s.name, CASE WHEN $1='ipv6' THEN host(s.public_ipv6) ELSE host(s.public_ipv4) END AS public_ip, \
        EXISTS(SELECT 1 FROM scan_task_execution e WHERE e.assigned_scanner_id=s.scanner_id AND e.execution_status='running') AS busy, \
        (SELECT COUNT(*) FROM scan_task_routing r JOIN scan_task t ON t.id=r.task_id WHERE r.preferred_scanner_id=s.scanner_id \
         AND r.prefer_until>(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT AND t.task_status='pending') AS reservations \
        FROM scanner_info s WHERE s.is_enable AND s.deleted_at IS NULL AND s.accepting_tasks AND s.runtime_state <> 'stopping' \
        AND s.last_seen_at >= NOW()-({})*INTERVAL '1 second' \
        AND (($1='ipv4' AND s.supports_ipv4 AND s.ipv4_ready) OR ($1='ipv6' AND s.supports_ipv6 AND s.ipv6_ready)) \
        AND ($2='legacy' OR s.scan_capabilities->'profiles' ? $2) \
        AND COALESCE(s.scan_capabilities->'service_protocols','[]'::jsonb) @> $5::jsonb AND COALESCE((s.scan_capabilities->>'max_service_probes')::INT,0) >= jsonb_array_length($5::jsonb) \
        AND (NOT $3 OR (s.supports_ipv6 AND s.ipv6_ready)) \
        AND (NOT $4 OR COALESCE((s.scan_capabilities->>'explicit_dns_resolvers')::BOOLEAN,FALSE)) ORDER BY s.scanner_id LIMIT 256",
        scanner_health::seconds_sql()
    );
    let explicit = resolvers.as_array().is_some_and(|r| !r.is_empty());
    let rows = client
        .query(
            &sql,
            &[
                &family,
                &profile,
                &require_v6,
                &explicit,
                &required_services,
            ],
        )
        .await?;
    let key = target_key(targets, family, profile, ports);
    let history = client.query("SELECT * FROM scanner_target_feedback WHERE owner_id=$1 AND target_key=$2 AND updated_at >= NOW()-$3::BIGINT*INTERVAL '1 hour'", &[&owner, &key, &i64::from(cfg.feedback_max_age_hours)]).await?;
    let mut history: HashMap<String, Feedback> = history
        .into_iter()
        .map(|r| {
            (
                r.get("scanner_id"),
                Feedback {
                    successes: r.get("successes"),
                    route_failures: r.get("route_failures"),
                    elapsed_ms: r.get("elapsed_ms"),
                    connect_ms: r.get("connect_ms"),
                    connect_samples: r.get("connect_samples"),
                },
            )
        })
        .collect();
    let mut candidates: Vec<Candidate> = rows
        .into_iter()
        .map(|r| {
            let id: String = r.get("scanner_id");
            let geo = r
                .get::<_, Option<String>>("public_ip")
                .and_then(|ip| ip.parse().ok())
                .map(|ip| Geo::from(maxmind.lookup(ip)))
                .unwrap_or_default();
            Candidate {
                name: r
                    .get::<_, Option<String>>("name")
                    .unwrap_or_else(|| id.clone()),
                geo,
                busy: r.get("busy"),
                reservations: r.get("reservations"),
                score: 0.0,
                reasons: Vec::new(),
                history_samples: 0,
                target_connect_ms: None,
                feedback: history.remove(&id).unwrap_or_default(),
                scanner_id: id,
            }
        })
        .collect();
    rank(&mut candidates, &target_geo(targets, maxmind));
    Ok(candidates)
}

pub fn claim_guard(scanner_parameter: &str) -> String {
    format!(
        "(t.dispatch_mode <> 'automatic' OR NOT COALESCE((SELECT (document->>'enabled')::BOOLEAN FROM runtime_configuration WHERE namespace='scan_routing'),TRUE) \
       OR NOT EXISTS(SELECT 1 FROM scan_task_routing r JOIN scanner_info p ON p.scanner_id=r.preferred_scanner_id \
        WHERE r.task_id=t.id AND r.preferred_scanner_id <> {scanner_parameter} AND r.prefer_until>(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT \
        AND p.is_enable AND p.deleted_at IS NULL AND p.accepting_tasks AND p.runtime_state<>'stopping' \
        AND p.last_seen_at>=NOW()-({})*INTERVAL '1 second' \
        AND ((t.address_family='ipv4' AND p.supports_ipv4 AND p.ipv4_ready) OR (t.address_family='ipv6' AND p.supports_ipv6 AND p.ipv6_ready)) \
        AND (t.scan_profile='legacy' OR p.scan_capabilities->'profiles' ? t.scan_profile) \
        AND COALESCE(p.scan_capabilities->'service_protocols','[]'::jsonb) @> COALESCE(t.scan_plan->'required_services','[]'::jsonb) \
        AND (jsonb_array_length(t.dns_resolvers)=0 OR COALESCE((p.scan_capabilities->>'explicit_dns_resolvers')::BOOLEAN,FALSE)) \
        AND (NOT EXISTS(SELECT 1 FROM jsonb_array_elements(t.dns_resolvers) d WHERE d->>'ip' LIKE '%:%') OR (p.supports_ipv6 AND p.ipv6_ready)) \
        AND NOT EXISTS(SELECT 1 FROM scan_task_execution busy WHERE busy.assigned_scanner_id=p.scanner_id AND busy.execution_status='running')))",
        scanner_health::seconds_sql()
    )
}

pub fn assignment_decision(scanner_parameter: &str) -> String {
    format!(
        "COALESCE((SELECT decision FROM scan_task_routing WHERE task_id=scan_task_execution.task_id),'{{}}'::JSONB) || \
        jsonb_build_object('assigned_scanner_id',{scanner_parameter}::TEXT, \
        'assigned_scanner_name',(SELECT COALESCE(name,scanner_id) FROM scanner_info WHERE scanner_id={scanner_parameter}), \
        'reason',CASE WHEN requested_scanner_id IS NOT NULL THEN 'user_selected' \
          WHEN COALESCE((SELECT (document->>'enabled')::BOOLEAN FROM runtime_configuration WHERE namespace='scan_routing'),TRUE) \
           AND EXISTS(SELECT 1 FROM scan_task_routing WHERE task_id=scan_task_execution.task_id AND preferred_scanner_id={scanner_parameter} \
             AND prefer_until>(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT) THEN 'ranked_candidate' ELSE 'ordinary_claim' END)"
    )
}

pub async fn plan_queue(pool: &Pool, maxmind: &MaxMindState) -> Result<(), Error> {
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='500ms'; SET LOCAL statement_timeout='3000ms'")
        .await?;
    if !tx
        .query_one(
            "SELECT pg_try_advisory_xact_lock($1) AS acquired",
            &[&PLANNER_LOCK],
        )
        .await?
        .get::<_, bool>("acquired")
    {
        return Ok(());
    }
    let cfg = config(&tx).await?;
    tx.execute("DELETE FROM scanner_target_feedback WHERE ctid IN (SELECT ctid FROM scanner_target_feedback WHERE updated_at<NOW()-$1::BIGINT*INTERVAL '1 hour' ORDER BY updated_at LIMIT 500)", &[&i64::from(cfg.feedback_max_age_hours)]).await?;
    if !cfg.enabled {
        tx.commit().await?;
        return Ok(());
    }
    let rows = tx.query("SELECT t.id, t.user_id, CASE WHEN t.task_kind='dns' THEN t.dns_targets ELSE t.task_target::TEXT[] END AS targets, \
        t.address_family, t.scan_profile, t.task_port, t.dns_resolvers, t.scan_plan, r.preferred_scanner_id, r.prefer_until \
        FROM scan_task_execution e JOIN scan_task t ON t.id=e.task_id LEFT JOIN scan_task_routing r ON r.task_id=t.id \
        WHERE t.dispatch_mode='automatic' AND t.task_status IN ('pending','running') AND e.execution_status='pending' AND e.requested_scanner_id IS NULL \
        ORDER BY t.task_level DESC,t.task_create_time,t.id FOR UPDATE OF e SKIP LOCKED LIMIT $1", &[&i64::from(cfg.candidate_limit)]).await?;
    let now = crate::clock::get_unix_epoch_ms();
    let mut placed: HashMap<String, i64> = HashMap::new();
    for row in rows {
        let targets: Vec<String> = row.get("targets");
        let mut choices = candidates(
            &tx,
            maxmind,
            &targets,
            row.get("address_family"),
            row.get("scan_profile"),
            row.get("task_port"),
            row.get("user_id"),
            &row.get("dns_resolvers"),
            &row.get::<_, Value>("scan_plan")
                .get("required_services")
                .cloned()
                .unwrap_or_else(|| json!([])),
            &cfg,
        )
        .await?;
        for choice in &mut choices {
            if let Some(extra) = placed.get(&choice.scanner_id) {
                choice.score -= 0.25 * *extra as f64;
            }
        }
        choices.sort_by(|a, b| {
            a.busy
                .cmp(&b.busy)
                .then_with(|| b.score.total_cmp(&a.score))
                .then_with(|| a.scanner_id.cmp(&b.scanner_id))
        });
        let existing: Option<String> = row.get("preferred_scanner_id");
        let previous_until: Option<i64> = row.get("prefer_until");
        if existing.is_none() && previous_until.is_some_and(|until| until > now) {
            continue;
        }
        if existing.is_some() && previous_until.is_some_and(|until| until <= now) {
            let fallback = json!({"policy":"geo_balanced","target_geo":target_geo(&targets,maxmind),"reason":"preference_expired","planned_at":now});
            tx.execute("UPDATE scan_task_routing SET preferred_scanner_id=NULL,prefer_until=$2,decision=$3,updated_at=NOW() WHERE task_id=$1", &[&row.get::<_,i32>("id"),&(now+i64::from(cfg.preference_seconds)*1000),&fallback]).await?;
            continue;
        }
        if row
            .get::<_, Option<i64>>("prefer_until")
            .is_some_and(|until| until > now)
            && existing
                .as_ref()
                .is_some_and(|id| choices.iter().any(|c| &c.scanner_id == id && !c.busy))
        {
            continue;
        }
        let preferred = choices.iter().find(|c| !c.busy);
        let id = preferred.map(|c| c.scanner_id.clone());
        if let Some(id) = &id {
            *placed.entry(id.clone()).or_default() += 1;
        }
        let decision = json!({"policy":"geo_balanced", "target_geo":target_geo(&targets,maxmind), "preferred_scanner_id":id,
            "reason":if preferred.is_some(){"ranked_candidate"}else{"no_idle_candidate"}, "candidates":choices.iter().take(5).collect::<Vec<_>>(), "planned_at":now});
        tx.execute("INSERT INTO scan_task_routing(task_id,preferred_scanner_id,prefer_until,decision) VALUES($1,$2,$3,$4) \
            ON CONFLICT(task_id) DO UPDATE SET preferred_scanner_id=EXCLUDED.preferred_scanner_id,prefer_until=EXCLUDED.prefer_until,decision=EXCLUDED.decision,updated_at=NOW()",
            &[&row.get::<_,i32>("id"), &id, &(now+i64::from(cfg.preference_seconds)*1000), &decision]).await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn run_planner(
    pool: Pool,
    maxmind: actix_web::web::Data<MaxMindState>,
    maintenance: actix_web::web::Data<SystemMaintenanceState>,
) {
    loop {
        if !maintenance.snapshot().await.blocks_new_work() {
            match tokio::time::timeout(Duration::from_secs(5), plan_queue(&pool, &maxmind)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(event="ScanRoutingPlannerError", %error),
                Err(_) => tracing::warn!(
                    event = "ScanRoutingPlannerTimeout",
                    "preferences expire independently of planner availability"
                ),
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Performance {
    pub elapsed_ms: u64,
    #[serde(default)]
    pub connections: Vec<ConnectionSample>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_targets: Vec<ResolvedTarget>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedTarget {
    pub domain: String,
    pub ip: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionSample {
    pub ip: String,
    pub port: u16,
    pub elapsed_ms: u32,
    pub outcome: String,
}
impl Performance {
    pub fn validate(&self, targets: &[String], ports: &str) -> Result<(), &'static str> {
        if !self.resolved_targets.is_empty() {
            return Err("DNS resolutions are not valid for an IP task");
        }
        self.validate_samples(targets, ports)
    }

    pub fn validate_dns(
        &self,
        domains: &[String],
        profile: &str,
        ports: &str,
    ) -> Result<(), &'static str> {
        if !matches!(profile, "dns_ports" | "dns_full") {
            if !self.connections.is_empty() || !self.resolved_targets.is_empty() {
                return Err("DNS-only tasks cannot report TCP samples");
            }
            return self.validate_samples(&[], ports);
        }
        if self.resolved_targets.len() > 8 {
            return Err("too many DNS resolution samples");
        }
        let domains = domains
            .iter()
            .filter_map(|domain| crate::dns::canonical_scan_domain(domain).ok())
            .collect::<Vec<_>>();
        let mut targets = Vec::new();
        for resolved in &self.resolved_targets {
            let domain = crate::dns::canonical_scan_domain(&resolved.domain)
                .map_err(|_| "invalid resolution domain")?;
            let ip = resolved
                .ip
                .parse::<IpAddr>()
                .map_err(|_| "invalid resolution IP")?;
            if !domains.contains(&domain)
                || !self
                    .connections
                    .iter()
                    .any(|sample| sample.ip.parse::<IpAddr>().ok() == Some(ip))
            {
                return Err("DNS resolution is outside task scope");
            }
            targets.push(ip.to_string());
        }
        self.validate_samples(&targets, ports)
    }

    fn validate_samples(&self, targets: &[String], ports: &str) -> Result<(), &'static str> {
        if self.elapsed_ms > 7 * 24 * 60 * 60 * 1000 || self.connections.len() > 8 {
            return Err("invalid performance bounds");
        }
        let nets: Vec<IpNet> = targets
            .iter()
            .filter_map(|t| {
                t.parse::<IpNet>()
                    .ok()
                    .or_else(|| t.parse::<IpAddr>().ok().map(IpNet::from))
            })
            .collect();
        for s in &self.connections {
            let ip: IpAddr = s.ip.parse().map_err(|_| "invalid connection IP")?;
            let port_allowed = ports.split(',').any(|part| {
                let part = part.trim();
                if let Some((a, b)) = part.split_once('-') {
                    a.parse::<u16>()
                        .ok()
                        .zip(b.parse::<u16>().ok())
                        .is_some_and(|(a, b)| a <= s.port && s.port <= b)
                } else {
                    part.parse::<u16>().ok() == Some(s.port)
                }
            });
            if !nets.iter().any(|n| n.contains(&ip))
                || !port_allowed
                || s.port == 0
                || s.elapsed_ms > 10_000
                || !matches!(
                    s.outcome.as_str(),
                    "connected" | "refused" | "timeout" | "route_error" | "other_error"
                )
            {
                return Err("connection sample is outside task scope");
            }
        }
        Ok(())
    }
}

/// Called in the successful receipt/failure transaction; duplicate reports cannot
/// inflate statistics. Only explicit route failures incur a reachability penalty.
pub async fn record_outcome(
    tx: &tokio_postgres::Transaction<'_>,
    execution: i32,
    route_failure: bool,
) -> Result<(), tokio_postgres::Error> {
    let Some(row)=tx.query_opt("SELECT e.attempt_count,e.assigned_scanner_id,e.execution_status,e.performance,t.user_id,t.task_kind, \
        CASE WHEN t.task_kind='dns' THEN t.dns_targets ELSE t.task_target::TEXT[] END AS targets,t.task_port,t.address_family,t.scan_profile \
        FROM scan_task_execution e JOIN scan_task t ON t.id=e.task_id WHERE e.id=$1", &[&execution]).await? else {return Ok(());};
    if row.get::<_, &str>("execution_status") != "succeeded" && !route_failure {
        return Ok(());
    }
    let Some(scanner) = row.get::<_, Option<String>>("assigned_scanner_id") else {
        return Ok(());
    };
    let inserted=tx.execute("INSERT INTO scan_routing_outcome(execution_id,attempt_no) VALUES($1,$2) ON CONFLICT DO NOTHING", &[&execution,&row.get::<_,i32>("attempt_count")]).await?;
    if inserted == 0 {
        return Ok(());
    }
    let targets: Vec<String> = row.get("targets");
    let key = target_key(
        &targets,
        row.get("address_family"),
        row.get("scan_profile"),
        row.get("task_port"),
    );
    let performance = (!route_failure)
        .then(|| row.get::<_, Option<Value>>("performance"))
        .flatten()
        .and_then(|p| serde_json::from_value::<Performance>(p).ok());
    let elapsed = performance.as_ref().map(|p| p.elapsed_ms as f64);
    let samples: Vec<f64> = performance
        .as_ref()
        .map(|p| {
            p.connections
                .iter()
                .filter(|s| matches!(s.outcome.as_str(), "connected" | "refused"))
                .map(|s| f64::from(s.elapsed_ms))
                .collect()
        })
        .unwrap_or_default();
    let connect = (!samples.is_empty()).then(|| samples.iter().sum::<f64>() / samples.len() as f64);
    let success = i32::from(!route_failure);
    let max_age:i64=tx.query_opt("SELECT COALESCE((document->>'feedback_max_age_hours')::BIGINT,168) AS age FROM runtime_configuration WHERE namespace='scan_routing'", &[]).await?.map(|r|r.get("age")).unwrap_or(168);
    tx.execute("INSERT INTO scanner_target_feedback(scanner_id,owner_id,target_key,successes,route_failures,elapsed_ms,connect_ms,connect_samples) VALUES($1,$2,$3,$4,$5,$6,$7,$8) \
        ON CONFLICT(scanner_id,owner_id,target_key) DO UPDATE SET \
        successes=CASE WHEN scanner_target_feedback.updated_at<NOW()-$9::BIGINT*INTERVAL '1 hour' THEN EXCLUDED.successes ELSE LEAST(scanner_target_feedback.successes+EXCLUDED.successes,1000000) END, \
        route_failures=CASE WHEN scanner_target_feedback.updated_at<NOW()-$9::BIGINT*INTERVAL '1 hour' THEN EXCLUDED.route_failures WHEN EXCLUDED.successes>0 THEN GREATEST(scanner_target_feedback.route_failures-1,0) ELSE LEAST(scanner_target_feedback.route_failures+1,3) END, \
        elapsed_ms=CASE WHEN scanner_target_feedback.updated_at<NOW()-$9::BIGINT*INTERVAL '1 hour' THEN EXCLUDED.elapsed_ms WHEN EXCLUDED.elapsed_ms IS NULL THEN scanner_target_feedback.elapsed_ms WHEN scanner_target_feedback.elapsed_ms IS NULL THEN EXCLUDED.elapsed_ms ELSE 0.7*scanner_target_feedback.elapsed_ms+0.3*EXCLUDED.elapsed_ms END, \
        connect_ms=CASE WHEN scanner_target_feedback.updated_at<NOW()-$9::BIGINT*INTERVAL '1 hour' THEN EXCLUDED.connect_ms WHEN EXCLUDED.connect_ms IS NULL THEN scanner_target_feedback.connect_ms WHEN scanner_target_feedback.connect_ms IS NULL THEN EXCLUDED.connect_ms ELSE 0.7*scanner_target_feedback.connect_ms+0.3*EXCLUDED.connect_ms END, \
        connect_samples=CASE WHEN scanner_target_feedback.updated_at<NOW()-$9::BIGINT*INTERVAL '1 hour' THEN EXCLUDED.connect_samples ELSE LEAST(scanner_target_feedback.connect_samples+EXCLUDED.connect_samples,1000000) END,updated_at=NOW()",
        &[&scanner,&row.get::<_,i32>("user_id"),&key,&success,&i32::from(route_failure),&elapsed,&connect,&(samples.len() as i32),&max_age]).await?;
    Ok(())
}

pub async fn decision<C: GenericClient + Sync>(
    client: &C,
    task: i32,
) -> Result<Option<Value>, tokio_postgres::Error> {
    Ok(client.query_opt("SELECT decision || jsonb_build_object('prefer_until',prefer_until) AS decision FROM scan_task_routing WHERE task_id=$1", &[&task]).await?.map(|r:Row|r.get("decision")))
}

#[cfg(test)]
#[path = "routing_tests.rs"]
mod database_tests;

#[cfg(test)]
mod tests {
    use super::*;
    fn candidate(id: &str, geo: Geo, feedback: Feedback) -> Candidate {
        Candidate {
            scanner_id: id.into(),
            name: id.into(),
            geo,
            busy: false,
            reservations: 0,
            score: 0.0,
            reasons: Vec::new(),
            history_samples: 0,
            target_connect_ms: None,
            feedback,
        }
    }
    fn geo(country: &str, region: &str, lat: f64, lon: f64) -> Geo {
        Geo {
            country_code: Some(country.into()),
            region: Some(region.into()),
            latitude: Some(lat),
            longitude: Some(lon),
            ..Default::default()
        }
    }
    #[test]
    fn nearby_idle_node_wins_but_unknown_locations_remain_candidates() {
        let target = geo("CN", "Shanghai", 31.2, 121.5);
        let mut nodes = vec![
            candidate(
                "us",
                geo("US", "California", 37.0, -122.0),
                Feedback::default(),
            ),
            candidate("cn", target.clone(), Feedback::default()),
            candidate("unknown", Geo::default(), Feedback::default()),
        ];
        rank(&mut nodes, &target);
        assert_eq!(nodes[0].scanner_id, "cn");
        assert!(nodes.iter().any(|c| c.scanner_id == "unknown"));
        nodes[0].busy = true;
        rank(&mut nodes, &target);
        assert_ne!(nodes[0].scanner_id, "cn");
    }
    #[test]
    fn measured_quality_can_outweigh_small_geo_difference() {
        let target = geo("CN", "Shanghai", 31.2, 121.5);
        let mut nodes = vec![
            candidate(
                "sh",
                target.clone(),
                Feedback {
                    successes: 8,
                    elapsed_ms: Some(10000.0),
                    connect_ms: Some(300.0),
                    connect_samples: 8,
                    ..Default::default()
                },
            ),
            candidate(
                "hz",
                geo("CN", "Zhejiang", 30.3, 120.2),
                Feedback {
                    successes: 8,
                    elapsed_ms: Some(1000.0),
                    connect_ms: Some(10.0),
                    connect_samples: 8,
                    ..Default::default()
                },
            ),
        ];
        rank(&mut nodes, &target);
        assert_eq!(nodes[0].scanner_id, "hz");
    }
    #[test]
    fn empty_port_discovery_and_single_timeout_do_not_penalize_reachability() {
        let mut nodes = vec![
            candidate(
                "a",
                Geo::default(),
                Feedback {
                    successes: 1,
                    ..Default::default()
                },
            ),
            candidate("b", Geo::default(), Feedback::default()),
        ];
        rank(&mut nodes, &Geo::default());
        assert_eq!(nodes[0].score, nodes[1].score);
        let p = Performance {
            elapsed_ms: 100,
            resolved_targets: vec![],
            connections: vec![ConnectionSample {
                ip: "192.0.2.1".into(),
                port: 443,
                elapsed_ms: 800,
                outcome: "timeout".into(),
            }],
        };
        assert!(p.validate(&["192.0.2.0/24".into()], "80,443").is_ok());
        assert!(p.validate(&["198.51.100.0/24".into()], "443").is_err());
        assert!(p.validate(&["192.0.2.0/24".into()], "80").is_err());
    }
    #[test]
    fn signature_is_order_independent_and_scope_sensitive() {
        assert_eq!(
            target_key(&["b".into(), "a".into()], "ipv4", "port_only", "443"),
            target_key(&["a".into(), "b".into()], "ipv4", "port_only", "443")
        );
        assert_ne!(
            target_key(&["a".into()], "ipv4", "port_only", "443"),
            target_key(&["a".into()], "ipv4", "port_only", "80")
        );
        let cfg = RoutingConfig {
            preference_seconds: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn dns_quality_requires_a_bounded_resolution_for_the_original_domain() {
        let mut p:Performance=serde_json::from_value(json!({"elapsed_ms":100,"connections":[{"ip":"2001:db8::1","port":443,"elapsed_ms":5,"outcome":"connected"}],"resolved_targets":[{"domain":"EXAMPLE.COM.","ip":"2001:db8::1"}]})).unwrap();
        let domains = vec!["example.com".into()];
        for profile in ["dns_ports", "dns_full"] {
            assert!(p.validate_dns(&domains, profile, "443").is_ok());
        }
        assert!(p.validate_dns(&domains, "dns_records", "443").is_err());
        assert!(p.validate(&["2001:db8::/64".into()], "443").is_err());
        assert!(
            p.validate_dns(&["other.example.com".into()], "dns_full", "443")
                .is_err()
        );
        assert!(p.validate_dns(&domains, "dns_full", "80").is_err());
        p.resolved_targets = vec![p.resolved_targets[0].clone(); 9];
        assert!(p.validate_dns(&domains, "dns_full", "443").is_err());
        p.resolved_targets.clear();
        assert!(p.validate_dns(&domains, "dns_ports", "443").is_err());
        p.connections.clear();
        assert!(p.validate_dns(&domains, "dns_records", "53").is_ok());
    }
    #[test]
    fn equivalent_host_and_port_notation_share_feedback() {
        assert_eq!(
            target_key(&["192.0.2.1".into()], "ipv4", "port_only", "80,443"),
            target_key(&["192.0.2.1/32".into()], "ipv4", "port_only", "443,80-80")
        );
        let nets = vec![
            "192.0.2.1/32".parse().unwrap(),
            "198.51.100.1/32".parse().unwrap(),
            "203.0.113.1/32".parse().unwrap(),
        ];
        let groups = group_targets(&nets, |net| {
            if net.to_string().starts_with("192.") {
                geo("CN", "Shanghai", 31.2, 121.5)
            } else if net.to_string().starts_with("198.") {
                geo("US", "California", 37.0, -122.0)
            } else {
                Geo::default()
            }
        });
        assert_eq!(groups.len(), 3);
        assert_eq!(groups.iter().map(Vec::len).sum::<usize>(), nets.len());
    }
}
