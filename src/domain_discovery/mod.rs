//! Passive certificate discovery. Evidence stays separate from DNS observations.
mod client;
mod routes;
#[cfg(test)]
mod tests;
mod worker;

use crate::{
    admin::UserBaseI,
    audit::{AuditContext, AuditEvent},
    elasticsearch::ElasticsearchService,
};
use actix_web::http::StatusCode;
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub use routes::configure;
pub use worker::run;
pub const MAX_NAMES: usize = 5000;
pub const MAX_CERTIFICATES: usize = 50;
pub const MAX_EVIDENCE_NAMES: usize = 10_000;
type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    status: StatusCode,
    code: &'static str,
}
impl Error {
    fn bad(code: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
        }
    }
    fn unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "discovery_unavailable",
        }
    }
    fn missing() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "discovery_not_found",
        }
    }
}
impl From<tokio_postgres::Error> for Error {
    fn from(_: tokio_postgres::Error) -> Self {
        Self::unavailable()
    }
}
impl From<deadpool_postgres::PoolError> for Error {
    fn from(_: deadpool_postgres::PoolError) -> Self {
        Self::unavailable()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInput {
    pub seed: String,
    #[serde(default)]
    pub include_related: bool,
    #[serde(default)]
    pub refresh: bool,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Certificate {
    pub crtsh_id: i64,
    pub fingerprint_sha256: Option<String>,
    pub names: Vec<String>,
    pub full_san: bool,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Candidate {
    pub name: String,
    pub relation: String,
    pub certificate_ids: Vec<i64>,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Evidence {
    pub seed: String,
    pub fetched_at: DateTime<Utc>,
    pub candidates: Vec<Candidate>,
    pub certificates: Vec<Certificate>,
    pub truncated: bool,
    pub incomplete_certificates: usize,
    pub source_errors: Vec<String>,
}
impl Evidence {
    fn empty(seed: &str) -> Self {
        Self {
            seed: seed.into(),
            fetched_at: Utc::now(),
            candidates: vec![],
            certificates: vec![],
            truncated: false,
            incomplete_certificates: 0,
            source_errors: vec![],
        }
    }
    fn rebuild(&mut self, related: bool) {
        let mut names = BTreeMap::<String, BTreeSet<i64>>::new();
        for cert in &self.certificates {
            for name in &cert.names {
                let plain = name.strip_prefix("*.").unwrap_or(name);
                if within_seed(plain, &self.seed) || (related && cert.full_san) {
                    if !names.contains_key(name) && names.len() >= MAX_NAMES {
                        self.truncated = true;
                        continue;
                    }
                    let ids = names.entry(name.clone()).or_default();
                    if ids.len() < MAX_CERTIFICATES {
                        ids.insert(cert.crtsh_id);
                    }
                }
            }
        }
        self.candidates = names
            .into_iter()
            .map(|(name, ids)| Candidate {
                relation: if name.starts_with("*.") {
                    "wildcard"
                } else if name == self.seed {
                    "seed"
                } else if within_seed(&name, &self.seed) {
                    "subdomain"
                } else {
                    "certificate_related"
                }
                .into(),
                name,
                certificate_ids: ids.into_iter().collect(),
            })
            .collect();
    }
}
pub fn within_seed(name: &str, seed: &str) -> bool {
    name == seed || name.ends_with(&format!(".{seed}"))
}
fn canonical_name(name: &str) -> Option<String> {
    crate::dns_follow_up::canonical_exclusion(name).ok()
}

fn job(row: &tokio_postgres::Row) -> Value {
    json!({"id":row.get::<_,Uuid>("id"),"seed":row.get::<_,String>("seed"),"include_related":row.get::<_,bool>("include_related"),
        "status":row.get::<_,String>("status"),"attempts":row.get::<_,i32>("attempts"),"summary":row.get::<_,Value>("summary"),
        "last_error":row.get::<_,Option<String>>("last_error"),"created_at":row.get::<_,DateTime<Utc>>("created_at"),"updated_at":row.get::<_,DateTime<Utc>>("updated_at")})
}
async fn owned(pool: &Pool, owner: i32, id: Uuid) -> Result<Value> {
    pool.get()
        .await?
        .query_opt(
            "SELECT * FROM domain_discovery_job WHERE id=$1 AND owner_id=$2",
            &[&id, &owner],
        )
        .await?
        .as_ref()
        .map(job)
        .ok_or_else(Error::missing)
}
pub async fn create(
    pool: &Pool,
    es: &ElasticsearchService,
    input: CreateInput,
    user: &UserBaseI,
    context: &AuditContext,
) -> Result<Value> {
    let seed =
        crate::dns::canonical_scan_domain(&input.seed).map_err(|_| Error::bad("invalid_seed"))?;
    if !es.enabled() {
        return Err(Error::unavailable());
    }
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    tx.query_one("SELECT pg_advisory_xact_lock(831917,$1)", &[&user.id])
        .await?;
    if let Some(row)=tx.query_opt("SELECT * FROM domain_discovery_job WHERE owner_id=$1 AND seed=$2 AND include_related=$3 AND (status IN ('pending','running') OR (NOT $4 AND status IN ('succeeded','partial') AND updated_at>NOW()-INTERVAL '24 hours')) ORDER BY created_at DESC LIMIT 1", &[&user.id,&seed,&input.include_related,&input.refresh]).await? {
        return Ok(json!({"job":job(&row),"reused":true}));
    }
    // One global admission lock bounds the queue across users and instances.
    tx.query_one("SELECT pg_advisory_xact_lock(831918,0)", &[])
        .await?;
    let limited:bool=tx.query_one("SELECT (SELECT COUNT(*) FROM domain_discovery_job WHERE owner_id=$1 AND created_at>NOW()-INTERVAL '1 hour')>=20 OR (SELECT COUNT(*) FROM domain_discovery_job WHERE owner_id=$1 AND status IN ('pending','running'))>=3 OR (SELECT COUNT(*) FROM domain_discovery_job WHERE status IN ('pending','running'))>=100 OR EXISTS(SELECT 1 FROM domain_discovery_job WHERE owner_id=$1 AND seed=$2 AND include_related=$3 AND created_at>NOW()-INTERVAL '5 minutes')", &[&user.id,&seed,&input.include_related]).await?.get(0);
    if limited {
        return Err(Error {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "discovery_rate_limited",
        });
    }
    let id = Uuid::now_v7();
    let row=tx.query_one("INSERT INTO domain_discovery_job(id,owner_id,seed,include_related) VALUES($1,$2,$3,$4) RETURNING *", &[&id,&user.id,&seed,&input.include_related]).await?;
    let mut event = AuditEvent::user("task", "domain.discovery_create", "success", user)
        .resource("domain_discovery", id.to_string());
    event.metadata = json!({"seed":seed,"include_related":input.include_related});
    crate::audit::write(&tx, context, &event).await?;
    tx.commit().await?;
    Ok(json!({"job":job(&row),"reused":false}))
}
pub async fn results(
    pool: &Pool,
    es: &ElasticsearchService,
    owner: i32,
    id: Uuid,
) -> Result<Evidence> {
    let record = owned(pool, owner, id).await?;
    if !matches!(record["status"].as_str(), Some("succeeded" | "partial")) {
        return Err(Error {
            status: StatusCode::CONFLICT,
            code: "discovery_not_ready",
        });
    }
    es.discovery_read(id, owner)
        .await
        .map_err(|_| Error::unavailable())
}

pub async fn queue_dns(
    pool: &Pool,
    es: &ElasticsearchService,
    policy: &crate::dns_follow_up::DnsFollowUpConfig,
    user: &UserBaseI,
    id: Uuid,
    names: Vec<String>,
    context: &AuditContext,
) -> Result<Value> {
    if names.is_empty() || names.len() > 500 {
        return Err(Error::bad("select_1_to_500_domains"));
    }
    let evidence = results(pool, es, user.id, id).await?;
    queue_evidence(pool, policy, user, id, &evidence, names, context).await
}
async fn queue_evidence(
    pool: &Pool,
    policy: &crate::dns_follow_up::DnsFollowUpConfig,
    user: &UserBaseI,
    id: Uuid,
    evidence: &Evidence,
    names: Vec<String>,
    context: &AuditContext,
) -> Result<Value> {
    let available: BTreeSet<_> = evidence
        .candidates
        .iter()
        .filter(|c| c.relation != "wildcard")
        .map(|c| c.name.as_str())
        .collect();
    let names = names
        .iter()
        .map(|s| crate::dns::canonical_scan_domain(s).map_err(|_| Error::bad("invalid_domain")))
        .collect::<Result<BTreeSet<_>>>()?;
    if names.iter().any(|s| !available.contains(s.as_str())) {
        return Err(Error::bad("domain_not_in_discovery"));
    }
    if names.iter().any(|s| !policy.allows_domain(s)) {
        return Err(Error {
            status: StatusCode::FORBIDDEN,
            code: "domain_excluded",
        });
    }
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    tx.query_one(
        "SELECT id FROM domain_discovery_job WHERE id=$1 AND owner_id=$2 FOR UPDATE",
        &[&id, &user.id],
    )
    .await?;
    let previous = tx
        .query(
            "SELECT domain,task_id FROM domain_discovery_dns_target WHERE job_id=$1",
            &[&id],
        )
        .await?;
    let mut tasks = BTreeSet::<String>::new();
    let mut pending = vec![];
    for name in names {
        if let Some(row) = previous
            .iter()
            .find(|r| r.get::<_, String>("domain") == name)
        {
            tasks.insert(row.get("task_id"));
        } else {
            pending.push(name);
        }
    }
    if !pending.is_empty() {
        let capable:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM scanner_info WHERE is_enable AND deleted_at IS NULL AND supports_ipv4 AND ipv4_ready AND scan_capabilities->'profiles' ? 'dns_records')", &[]).await?.get(0);
        if !capable {
            return Err(Error {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "dns_scanner_unavailable",
            });
        }
        let task_id = Uuid::now_v7().to_string();
        let execution = Uuid::now_v7().to_string();
        let plan = crate::scan_control::creation::build_scan_plan("dns_records")
            .map_err(|_| Error::unavailable())?;
        let row=tx.query_one("INSERT INTO scan_task(user_id,task_id,task_initiator,task_target,dns_targets,task_kind,task_port,scan_profile,scan_plan,generation_metadata,remarks) VALUES($1,$2,$3,ARRAY[]::INET[],$4,'dns','53','dns_records',$5,$6,'crt.sh 发现域名 DNS 验证') RETURNING id", &[&user.id,&task_id,&user.username,&pending,&plan,&json!({"domain_discovery":{"job_id":id,"seed":evidence.seed}})]).await?;
        let pk: i32 = row.get(0);
        tx.execute(
            "INSERT INTO scan_task_execution(execution_id,task_id) VALUES($1,$2)",
            &[&execution, &pk],
        )
        .await?;
        for name in pending {
            tx.execute(
                "INSERT INTO domain_discovery_dns_target(job_id,domain,task_id) VALUES($1,$2,$3)",
                &[&id, &name, &task_id],
            )
            .await?;
        }
        let mut event = AuditEvent::user("task", "domain.discovery_dns", "success", user)
            .resource("task", task_id.clone());
        event.metadata = json!({"discovery_job":id});
        crate::audit::write(&tx, context, &event).await?;
        tasks.insert(task_id);
    }
    tx.commit().await?;
    Ok(json!({"task_ids":tasks}))
}
