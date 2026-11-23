//! 监控规则 CRUD：管理员管全部，开启 monitor_user_enabled 后用户管自己的规则。
use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent};
use crate::runtime_config::RuntimeSettings;
use actix_web::http::StatusCode;
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    pub status: StatusCode,
    pub message: &'static str,
}

impl Error {
    pub fn bad(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }
    pub fn forbidden(message: &'static str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message,
        }
    }
    pub fn missing() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: "监控规则或运行记录不存在",
        }
    }
    pub fn conflict() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: "配置已变化或当前状态不可操作，请刷新后重试",
        }
    }
    pub fn internal() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "目标监控服务暂时不可用",
        }
    }
}

impl From<tokio_postgres::Error> for Error {
    fn from(value: tokio_postgres::Error) -> Self {
        tracing::error!(event="TargetMonitorDatabaseError", code=?value.code(), "目标监控数据库操作失败");
        Self::internal()
    }
}
impl From<deadpool_postgres::PoolError> for Error {
    fn from(_: deadpool_postgres::PoolError) -> Self {
        Self::internal()
    }
}

fn default_target_type() -> String {
    "ip".into()
}
fn default_profile() -> String {
    "service_inventory".into()
}
fn default_interval() -> i32 {
    86400
}
fn default_enabled() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleInput {
    pub name: String,
    #[serde(default = "default_target_type")]
    pub target_type: String,
    pub targets: Vec<String>,
    #[serde(default)]
    pub ports: String,
    #[serde(default = "default_profile")]
    pub scan_profile: String,
    #[serde(default = "default_interval")]
    pub interval_seconds: i32,
    #[serde(default)]
    pub recipient_ids: Vec<i32>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub expected_revision: Option<i64>,
}

pub(crate) struct ValidatedRule {
    pub name: String,
    pub target_type: String,
    pub target_family: Option<String>,
    pub targets: Vec<String>,
    pub ports: String,
    pub scan_profile: String,
    pub interval_seconds: i32,
    pub recipient_ids: Vec<i32>,
    pub enabled: bool,
}

fn networks_overlap(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.addr()) || b.contains(&a.addr())
}

async fn validate(
    pool: &Pool,
    user: &UserBaseI,
    settings: &RuntimeSettings,
    input: &RuleInput,
) -> Result<ValidatedRule> {
    let name = input.name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(Error::bad("规则名称须为 1 至 80 个字符"));
    }
    if input.targets.is_empty() || input.targets.len() > 64 {
        return Err(Error::bad("监控目标须为 1 至 64 个"));
    }
    if !(3600..=2_592_000).contains(&input.interval_seconds) {
        return Err(Error::bad("监控周期须在 1 小时至 30 天之间"));
    }
    let is_admin = user.role == 1;
    let mut targets = Vec::new();
    let mut family: Option<String> = None;
    let mut ports = input.ports.trim().to_owned();
    let mut profile = input.scan_profile.trim().to_ascii_lowercase();
    match input.target_type.as_str() {
        "ip" => {
            if !["port_only", "service_inventory", "vulnerability_scan"].contains(&profile.as_str())
            {
                return Err(Error::bad("IP 监控仅支持端口发现、服务识别或漏洞扫描模式"));
            }
            if ports.is_empty() {
                ports = crate::scan_control::creation::DEFAULT_SCAN_PORTS.to_owned();
            }
            if !crate::scan_control::target::check_port(&ports) {
                return Err(Error::bad("端口表达式无效"));
            }
            let policy = settings.automatic_target.get().await.value;
            for raw in &input.targets {
                let network = crate::scan_control::target::parse_ip_or_cidr(raw)
                    .map_err(|_| Error::bad("监控目标须为合法 IP 或 CIDR"))?;
                let current = if network.addr().is_ipv4() {
                    "ipv4"
                } else {
                    "ipv6"
                };
                if family.as_deref().is_some_and(|f| f != current) {
                    return Err(Error::bad("一条规则不能混合 IPv4 与 IPv6 目标"));
                }
                family = Some(current.to_owned());
                if !is_admin {
                    let (authorized, excluded) = if network.addr().is_ipv4() {
                        (&policy.authorized_cidrs, &policy.excluded_cidrs)
                    } else {
                        (&policy.ipv6_authorized_cidrs, &policy.ipv6_excluded_cidrs)
                    };
                    let allowed = authorized.iter().any(|value| {
                        value
                            .parse::<IpNet>()
                            .is_ok_and(|pool| pool.contains(&network))
                    });
                    let excluded_hit = excluded.iter().any(|value| {
                        value
                            .parse::<IpNet>()
                            .is_ok_and(|pool| networks_overlap(&pool, &network))
                    });
                    let mandatory_hit = network.addr().is_ipv4()
                        && crate::target_generated::MANDATORY_IPV4_EXCLUSIONS
                            .iter()
                            .any(|value| {
                                value
                                    .parse::<IpNet>()
                                    .is_ok_and(|pool| networks_overlap(&pool, &network))
                            });
                    if !allowed || excluded_hit || mandatory_hit {
                        return Err(Error::forbidden("监控目标超出授权网段或命中排除规则"));
                    }
                }
                targets.push(network.to_string());
            }
        }
        "domain" => {
            profile = "dns_records".to_owned();
            ports = "53".to_owned();
            let policy = settings.dns_follow_up.get().await.value;
            for raw in &input.targets {
                let domain = crate::dns::canonical_scan_domain(raw)
                    .map_err(|_| Error::bad("监控域名格式无效"))?;
                if !is_admin && !policy.allows_domain(&domain) {
                    return Err(Error::forbidden("监控域名命中 DNS 排除规则"));
                }
                targets.push(domain);
            }
            targets.sort();
            targets.dedup();
        }
        _ => return Err(Error::bad("监控目标类型须为 ip 或 domain")),
    }
    let recipient_ids = if is_admin {
        let mut ids = input.recipient_ids.clone();
        ids.sort();
        ids.dedup();
        if ids.len() > 32 {
            return Err(Error::bad("收件人最多 32 个"));
        }
        if !ids.is_empty() {
            let valid: i64 = pool.get().await?.query_one(
                "SELECT COUNT(*) FROM users WHERE id=ANY($1) AND role IN (1,2) AND deleted_at IS NULL AND disabled_at IS NULL",
                &[&ids],
            ).await?.get(0);
            if valid != ids.len() as i64 {
                return Err(Error::bad("收件人包含无效或已停用用户"));
            }
        }
        ids
    } else {
        vec![user.id]
    };
    Ok(ValidatedRule {
        name: name.to_owned(),
        target_type: input.target_type.clone(),
        target_family: family,
        targets,
        ports,
        scan_profile: profile,
        interval_seconds: input.interval_seconds,
        recipient_ids,
        enabled: input.enabled,
    })
}

fn rule_json(row: &tokio_postgres::Row) -> Value {
    json!({
        "id": row.get::<_, Uuid>("id"),
        "name": row.get::<_, String>("name"),
        "created_by": row.get::<_, i32>("created_by"),
        "owner_name": row.get::<_, String>("owner_name"),
        "recipient_ids": row.get::<_, Vec<i32>>("recipient_ids"),
        "target_type": row.get::<_, String>("target_type"),
        "target_family": row.get::<_, Option<String>>("target_family"),
        "targets": row.get::<_, Vec<String>>("targets"),
        "ports": row.get::<_, String>("ports"),
        "scan_profile": row.get::<_, String>("scan_profile"),
        "interval_seconds": row.get::<_, i32>("interval_seconds"),
        "enabled": row.get::<_, bool>("enabled"),
        "last_task_id": row.get::<_, Option<String>>("last_task_id"),
        "last_run_at": row.get::<_, Option<DateTime<Utc>>>("last_run_at"),
        "next_run_at": row.get::<_, DateTime<Utc>>("next_run_at"),
        "last_change_count": row.get::<_, Option<i32>>("last_change_count").unwrap_or(0),
        "revision": row.get::<_, i64>("revision"),
        "created_at": row.get::<_, DateTime<Utc>>("created_at"),
        "updated_at": row.get::<_, DateTime<Utc>>("updated_at"),
    })
}

const RULE_SELECT: &str = "SELECT r.*, u.username AS owner_name, \
    (SELECT run.change_count FROM target_monitor_run run WHERE run.rule_id=r.id ORDER BY run.id DESC LIMIT 1) AS last_change_count \
    FROM target_monitor_rule r JOIN users u ON u.id=r.created_by";

pub async fn list(pool: &Pool, user: &UserBaseI) -> Result<Value> {
    let is_admin = user.role == 1;
    let monitor_user_enabled = is_admin
        || crate::admin::get_mail_settings_from_database(pool)
            .await
            .map_err(|_| Error::internal())?
            .notification_prefs
            .monitor_user_enabled;
    let rows = pool.get().await?.query(
        &format!("{RULE_SELECT} WHERE r.deleted_at IS NULL AND ($1 OR r.created_by=$2) ORDER BY r.created_at, r.id"),
        &[&is_admin, &user.id],
    ).await?;
    Ok(json!({
        "items": rows.iter().map(rule_json).collect::<Vec<_>>(),
        "monitor_user_enabled": monitor_user_enabled,
        "is_admin": is_admin,
    }))
}

async fn audit(
    tx: &deadpool_postgres::Transaction<'_>,
    user: &UserBaseI,
    context: &AuditContext,
    action: &str,
    id: Uuid,
) -> Result<()> {
    let mut event = AuditEvent::user("target_monitor", action, "success", user)
        .resource("target_monitor_rule", id.to_string());
    event.response_status = Some(200);
    crate::audit::write(tx, context, &event).await?;
    Ok(())
}

async fn manage_allowed(pool: &Pool, user: &UserBaseI, owner: i32) -> Result<bool> {
    if user.role == 1 {
        return Ok(true);
    }
    if owner != user.id {
        return Ok(false);
    }
    Ok(crate::admin::get_mail_settings_from_database(pool)
        .await
        .map_err(|_| Error::internal())?
        .notification_prefs
        .monitor_user_enabled)
}

pub async fn create(
    pool: &Pool,
    user: &UserBaseI,
    settings: &RuntimeSettings,
    input: RuleInput,
    context: &AuditContext,
) -> Result<Value> {
    if user.role != 1 {
        let enabled = crate::admin::get_mail_settings_from_database(pool)
            .await
            .map_err(|_| Error::internal())?
            .notification_prefs
            .monitor_user_enabled;
        if !enabled {
            return Err(Error::forbidden("管理员未开放用户自助监控"));
        }
    }
    let rule = validate(pool, user, settings, &input).await?;
    let mut conn = pool.get().await?;
    let tx = conn.transaction().await?;
    tx.query_one("SELECT pg_advisory_xact_lock(728104, 3)", &[])
        .await?;
    let total: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM target_monitor_rule WHERE deleted_at IS NULL",
            &[],
        )
        .await?
        .get(0);
    if total >= 200 {
        return Err(Error::bad("监控规则总数已达上限 200"));
    }
    if user.role != 1 {
        let mine: i64 = tx.query_one("SELECT COUNT(*) FROM target_monitor_rule WHERE deleted_at IS NULL AND created_by=$1", &[&user.id]).await?.get(0);
        if mine >= 20 {
            return Err(Error::bad("每位用户最多创建 20 条监控规则"));
        }
    }
    let id = Uuid::now_v7();
    tx.execute(
        "INSERT INTO target_monitor_rule(id,name,created_by,recipient_ids,target_type,target_family,targets,ports,scan_profile,interval_seconds,enabled,next_run_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW()+$12::BIGINT*INTERVAL '1 second')",
        &[&id,&rule.name,&user.id,&rule.recipient_ids,&rule.target_type,&rule.target_family,&rule.targets,&rule.ports,&rule.scan_profile,&rule.interval_seconds,&rule.enabled,&(rule.interval_seconds as i64)],
    ).await?;
    audit(&tx, user, context, "target_monitor.rule_create", id).await?;
    let row = tx
        .query_one(&format!("{RULE_SELECT} WHERE r.id=$1"), &[&id])
        .await?;
    tx.commit().await?;
    Ok(rule_json(&row))
}

pub async fn update(
    pool: &Pool,
    user: &UserBaseI,
    settings: &RuntimeSettings,
    id: Uuid,
    input: RuleInput,
    context: &AuditContext,
) -> Result<Value> {
    let rule = validate(pool, user, settings, &input).await?;
    let mut conn = pool.get().await?;
    let tx = conn.transaction().await?;
    let row = tx.query_opt(
        "SELECT created_by,revision FROM target_monitor_rule WHERE id=$1 AND deleted_at IS NULL FOR UPDATE",
        &[&id],
    ).await?.ok_or_else(Error::missing)?;
    if !manage_allowed(pool, user, row.get("created_by")).await? {
        return Err(Error::forbidden("无权管理该监控规则"));
    }
    if Some(row.get::<_, i64>("revision")) != input.expected_revision {
        return Err(Error::conflict());
    }
    tx.execute(
        "UPDATE target_monitor_rule SET name=$2,recipient_ids=$3,target_type=$4,target_family=$5,targets=$6,ports=$7,scan_profile=$8,interval_seconds=$9,enabled=$10,revision=revision+1,updated_at=NOW() WHERE id=$1",
        &[&id,&rule.name,&rule.recipient_ids,&rule.target_type,&rule.target_family,&rule.targets,&rule.ports,&rule.scan_profile,&rule.interval_seconds,&rule.enabled],
    ).await?;
    audit(&tx, user, context, "target_monitor.rule_update", id).await?;
    let row = tx
        .query_one(&format!("{RULE_SELECT} WHERE r.id=$1"), &[&id])
        .await?;
    tx.commit().await?;
    Ok(rule_json(&row))
}

pub async fn remove(
    pool: &Pool,
    user: &UserBaseI,
    id: Uuid,
    revision: i64,
    context: &AuditContext,
) -> Result<()> {
    let mut conn = pool.get().await?;
    let tx = conn.transaction().await?;
    let row = tx.query_opt(
        "SELECT created_by FROM target_monitor_rule WHERE id=$1 AND deleted_at IS NULL FOR UPDATE",
        &[&id],
    ).await?.ok_or_else(Error::missing)?;
    if !manage_allowed(pool, user, row.get("created_by")).await? {
        return Err(Error::forbidden("无权管理该监控规则"));
    }
    let changed = tx.execute(
        "UPDATE target_monitor_rule SET deleted_at=NOW(),enabled=FALSE,revision=revision+1 WHERE id=$1 AND revision=$2",
        &[&id, &revision],
    ).await?;
    if changed != 1 {
        return Err(Error::conflict());
    }
    audit(&tx, user, context, "target_monitor.rule_delete", id).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn run_now(
    pool: &Pool,
    user: &UserBaseI,
    id: Uuid,
    context: &AuditContext,
) -> Result<()> {
    let mut conn = pool.get().await?;
    let tx = conn.transaction().await?;
    let row = tx.query_opt(
        "SELECT created_by FROM target_monitor_rule WHERE id=$1 AND deleted_at IS NULL FOR UPDATE",
        &[&id],
    ).await?.ok_or_else(Error::missing)?;
    if !manage_allowed(pool, user, row.get("created_by")).await? {
        return Err(Error::forbidden("无权管理该监控规则"));
    }
    let running: bool = tx.query_one(
        "SELECT EXISTS(SELECT 1 FROM target_monitor_run WHERE rule_id=$1 AND status IN ('pending','running'))",
        &[&id],
    ).await?.get(0);
    if running {
        return Err(Error::conflict());
    }
    tx.execute(
        "UPDATE target_monitor_rule SET next_run_at=NOW() WHERE id=$1",
        &[&id],
    )
    .await?;
    audit(&tx, user, context, "target_monitor.rule_run_now", id).await?;
    tx.commit().await?;
    Ok(())
}

async fn accessible_rule(pool: &Pool, user: &UserBaseI, rule_id: Uuid) -> Result<()> {
    let owner: Option<i32> = pool
        .get()
        .await?
        .query_opt(
            "SELECT created_by FROM target_monitor_rule WHERE id=$1 AND deleted_at IS NULL",
            &[&rule_id],
        )
        .await?
        .map(|row| row.get(0));
    let owner = owner.ok_or_else(Error::missing)?;
    if user.role == 1 || owner == user.id {
        Ok(())
    } else {
        Err(Error::forbidden("无权查看该监控规则"))
    }
}

pub async fn runs(
    pool: &Pool,
    user: &UserBaseI,
    rule_id: Uuid,
    before: Option<Uuid>,
) -> Result<Value> {
    accessible_rule(pool, user, rule_id).await?;
    let rows = pool.get().await?.query(
        "SELECT id,rule_id,task_id,status,skip_reason,started_at,finished_at,change_count,summary FROM target_monitor_run WHERE rule_id=$1 AND ($2::UUID IS NULL OR id<$2) ORDER BY id DESC LIMIT 51",
        &[&rule_id, &before],
    ).await?;
    let items: Vec<Value> = rows
        .iter()
        .take(50)
        .map(|row| {
            json!({
                "id": row.get::<_, Uuid>("id"),
                "rule_id": row.get::<_, Uuid>("rule_id"),
                "task_id": row.get::<_, Option<String>>("task_id"),
                "status": row.get::<_, String>("status"),
                "skip_reason": row.get::<_, Option<String>>("skip_reason"),
                "started_at": row.get::<_, Option<DateTime<Utc>>>("started_at"),
                "finished_at": row.get::<_, Option<DateTime<Utc>>>("finished_at"),
                "change_count": row.get::<_, i32>("change_count"),
                "summary": row.get::<_, Option<Value>>("summary"),
            })
        })
        .collect();
    let next = if rows.len() > 50 {
        items.last().and_then(|v| v.get("id")).cloned()
    } else {
        None
    };
    Ok(json!({"items":items,"next_before":next}))
}

fn change_json(row: &tokio_postgres::Row) -> Value {
    json!({
        "id": row.get::<_, Uuid>("id"),
        "run_id": row.get::<_, Uuid>("run_id"),
        "rule_id": row.get::<_, Uuid>("rule_id"),
        "kind": row.get::<_, String>("kind"),
        "severity": row.get::<_, String>("severity"),
        "target": row.get::<_, String>("target"),
        "port": row.get::<_, Option<i32>>("port"),
        "detail": row.get::<_, Value>("detail"),
        "occurred_at": row.get::<_, DateTime<Utc>>("occurred_at"),
    })
}

pub async fn run_changes(pool: &Pool, user: &UserBaseI, run_id: Uuid) -> Result<Value> {
    let rule_id: Option<Uuid> = pool
        .get()
        .await?
        .query_opt(
            "SELECT rule_id FROM target_monitor_run WHERE id=$1",
            &[&run_id],
        )
        .await?
        .map(|row| row.get(0));
    let rule_id = rule_id.ok_or_else(Error::missing)?;
    accessible_rule(pool, user, rule_id).await?;
    let rows = pool
        .get()
        .await?
        .query(
            "SELECT * FROM target_monitor_change WHERE run_id=$1 ORDER BY id LIMIT 500",
            &[&run_id],
        )
        .await?;
    Ok(json!({"items": rows.iter().map(change_json).collect::<Vec<_>>()}))
}

pub async fn changes(
    pool: &Pool,
    user: &UserBaseI,
    rule_id: Option<Uuid>,
    before: Option<Uuid>,
) -> Result<Value> {
    if let Some(rule_id) = rule_id {
        accessible_rule(pool, user, rule_id).await?;
    }
    let is_admin = user.role == 1;
    let rows = pool.get().await?.query(
        "SELECT c.*, r.name AS rule_name FROM target_monitor_change c JOIN target_monitor_rule r ON r.id=c.rule_id \
         WHERE r.deleted_at IS NULL AND ($1 OR r.created_by=$2) AND ($3::UUID IS NULL OR c.rule_id=$3) AND ($4::UUID IS NULL OR c.id<$4) \
         ORDER BY c.id DESC LIMIT 51",
        &[&is_admin, &user.id, &rule_id, &before],
    ).await?;
    let items: Vec<Value> = rows
        .iter()
        .take(50)
        .map(|row| {
            let mut value = change_json(row);
            value["rule_name"] = json!(row.get::<_, String>("rule_name"));
            value
        })
        .collect();
    let next = if rows.len() > 50 {
        items.last().and_then(|v| v.get("id")).cloned()
    } else {
        None
    };
    Ok(json!({"items":items,"next_before":next}))
}

pub async fn recipients(pool: &Pool, user: &UserBaseI) -> Result<Value> {
    if user.role != 1 {
        return Err(Error::forbidden("仅管理员可以选择收件人"));
    }
    let rows = pool.get().await?.query(
        "SELECT id,username FROM users WHERE role IN (1,2) AND deleted_at IS NULL AND disabled_at IS NULL ORDER BY username,id",
        &[],
    ).await?;
    Ok(json!(rows.iter().map(|row| json!({"id":row.get::<_,i32>("id"),"username":row.get::<_,String>("username")})).collect::<Vec<_>>()))
}
