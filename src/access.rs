//! Effective access and shared role administration for the web and local CLI.
use actix_web::{HttpMessage, HttpRequest, http::Method};
use chrono::{DateTime, Utc};
use deadpool_postgres::{GenericClient, Pool};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write as write_audit};

pub(crate) const ADMIN: i32 = 1;
pub(crate) const USER: i32 = 2;
pub(crate) const READ_ONLY: i32 = 3;
pub(crate) const AUDITOR: i32 = 4;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Permission {
    ReadResults,
    CreateScan,
    CancelScan,
    RetryScan,
    ExportResults,
    ReadAudit,
    ExportAudit,
}

impl Permission {
    fn grantable_to(self, role: i32) -> bool {
        use Permission::*;
        match role {
            USER => matches!(
                self,
                ReadResults | CreateScan | CancelScan | RetryScan | ExportResults
            ),
            READ_ONLY => matches!(self, ReadResults | ExportResults),
            AUDITOR => matches!(self, ReadAudit | ExportAudit),
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Policy {
    pub permissions: Vec<Permission>,
    pub expires_at: Option<DateTime<Utc>>,
    pub target_cidrs: Vec<IpNet>,
    pub domains: Vec<String>,
    pub scanners: Vec<Uuid>,
    pub profiles: Vec<String>,
    pub max_priority: u8,
    pub max_targets: u32,
    pub max_ports: u16,
    pub port_ranges: Vec<String>,
    pub max_active_tasks: u32,
    pub tasks_per_day: u32,
    pub audit_categories: Vec<String>,
}

impl Policy {
    fn validate(&mut self, role: i32) -> Result<(), &'static str> {
        use Permission::*;
        if !matches!(role, USER | READ_ONLY | AUDITOR)
            || self.permissions.len() > 7
            || self.permissions.iter().any(|p| !p.grantable_to(role))
        {
            return Err("角色或权限超出可授予范围");
        }
        for (index, permission) in self.permissions.iter().enumerate() {
            if self.permissions[..index].contains(permission) {
                return Err("权限不得重复");
            }
        }
        if self.expires_at.is_some_and(|at| at <= Utc::now()) {
            return Err("权限有效期必须晚于当前时间");
        }
        if self.target_cidrs.len() > 100
            || self.domains.len() > 100
            || self.scanners.len() > 100
            || self.profiles.len() > 25
            || self.port_ranges.len() > 100
            || self.audit_categories.len() > 50
            || self.max_priority > 4
        {
            return Err("权限范围超出数量或优先级限制");
        }
        for domain in &mut self.domains {
            *domain = crate::dns::canonical_scan_domain(domain).map_err(|_| "授权域名无效")?;
        }
        if self.profiles.iter().any(|p| {
            !(crate::scan_control::creation::is_ip_scan_profile(p)
                || matches!(p.as_str(), "udp_inventory" | "dns_records"))
        }) || self.audit_categories.iter().any(|c| !valid_label(c))
        {
            return Err("扫描模式或审计类别格式无效");
        }
        if self
            .port_ranges
            .iter()
            .any(|range| parse_port_range(range).is_none())
        {
            return Err("授权端口必须为单个端口或连续端口范围");
        }
        let scan = self.permissions.contains(&CreateScan);
        if scan
            && (self.scanners.is_empty()
                || self.profiles.is_empty()
                || self.max_targets == 0
                || self.max_targets > 65536
                || self.max_ports == 0
                || self.port_ranges.is_empty()
                || !(1..=100).contains(&self.max_active_tasks)
                || !(1..=10000).contains(&self.tasks_per_day)
                || (self.target_cidrs.is_empty() && self.domains.is_empty()))
        {
            return Err("创建扫描需要指定节点、模式及目标范围");
        }
        if self.permissions.contains(&RetryScan) && !scan {
            return Err("重试扫描需要创建扫描权限");
        }
        if self.permissions.contains(&ExportResults) && !self.permissions.contains(&ReadResults) {
            return Err("导出结果需要读取结果权限");
        }
        if self.permissions.contains(&ExportAudit) && !self.permissions.contains(&ReadAudit) {
            return Err("导出审计需要读取审计权限");
        }
        if self.permissions.contains(&ReadAudit) && self.audit_categories.is_empty() {
            return Err("读取审计需要指定审计类别");
        }
        Ok(())
    }

    pub(crate) fn allows_targets(
        &self,
        ips: &[IpNet],
        domains: &[String],
        profile: &str,
        priority: u8,
        ports: &str,
    ) -> bool {
        let count = ips.iter().fold(domains.len() as u128, |count, net| {
            let address_bits = if matches!(net, IpNet::V4(_)) { 32 } else { 128 };
            count.saturating_add(
                1_u128
                    .checked_shl(u32::from(address_bits - net.prefix_len()))
                    .unwrap_or(u128::MAX),
            )
        });
        let allowed: Vec<_> = self
            .port_ranges
            .iter()
            .filter_map(|range| parse_port_range(range))
            .collect();
        let port_count = ports.split(',').try_fold(0_u32, |count, range| {
            let (start, end) = parse_port_range(range)?;
            if !allowed
                .iter()
                .any(|(min, max)| *min <= start && end <= *max)
            {
                return None;
            }
            count.checked_add(u32::from(end - start) + 1)
        });
        count <= u128::from(self.max_targets)
            && port_count.is_some_and(|count| count <= u32::from(self.max_ports))
            && profile != "udp_passive"
            && priority <= self.max_priority
            && self.profiles.iter().any(|p| p == profile)
            && ips
                .iter()
                .all(|target| self.target_cidrs.iter().any(|scope| scope.contains(target)))
            && domains.iter().all(|target| {
                self.domains.iter().any(|scope| {
                    target == scope
                        || target
                            .strip_suffix(scope)
                            .is_some_and(|prefix| prefix.ends_with('.'))
                })
            })
    }
}

fn parse_port_range(range: &str) -> Option<(u16, u16)> {
    let (start, end) = range.split_once('-').unwrap_or((range, range));
    let start: u16 = start.trim().parse().ok()?;
    let end: u16 = end.trim().parse().ok()?;
    (start > 0 && start <= end).then_some((start, end))
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Access {
    pub role: i32,
    pub version: i64,
    pub policy: Option<Policy>,
}

impl Access {
    pub(crate) fn legacy_user(&self) -> bool {
        self.role == USER && self.policy.is_none()
    }

    pub(crate) fn allows(&self, permission: Permission) -> bool {
        self.role == ADMIN
            || (self.legacy_user() && permission.grantable_to(USER))
            || (permission.grantable_to(self.role)
                && self.policy.as_ref().is_some_and(|p| {
                    p.expires_at.is_none_or(|at| at > Utc::now())
                        && p.permissions.contains(&permission)
                }))
    }

    pub(crate) fn from_request(req: &HttpRequest) -> Option<Self> {
        req.extensions().get::<Self>().cloned()
    }

    pub(crate) fn from_row(row: &tokio_postgres::Row) -> serde_json::Result<Self> {
        Ok(Self {
            role: row.get("role"),
            version: row.get("access_version"),
            policy: row
                .get::<_, Option<Value>>("access_policy")
                .map(serde_json::from_value)
                .transpose()?,
        })
    }

    pub(crate) fn allows_route(&self, method: &Method, path: &str) -> bool {
        use Permission::*;
        if self.role == ADMIN || self.legacy_user() {
            return true;
        }
        let read = matches!(*method, Method::GET | Method::HEAD);
        if read
            && matches!(
                path,
                "/api/access"
                    | "/api/userinfo/get"
                    | "/api/totp/get"
                    | "/api/totp/bind"
                    | "/api/user/security/login-ip-allowlist"
                    | "/api/version"
                    | "/api/user/login-records"
                    | "/api/system/preferences"
                    | "/logout"
            )
        {
            return true;
        }
        if ((*method == Method::POST)
            && matches!(
                path,
                "/api/totp/verify" | "/api/user/password/update" | "/api/userinfo/update"
            ))
            || (*method == Method::PUT && path == "/api/user/security/login-ip-allowlist")
        {
            return true;
        }
        if self.role == AUDITOR {
            return (read
                && (path == "/api/audit/events"
                    || resource_route(path, "/api/audit/events/", ""))
                && self.allows(ReadAudit))
                || (*method == Method::POST
                    && path == "/api/audit/export"
                    && self.allows(ExportAudit))
                || (*method == Method::POST
                    && path == "/api/access/verify"
                    && self.allows(ExportAudit));
        }
        if read && resource_route(path, "/api/task/", "/export") {
            return self.allows(ExportResults);
        }
        if *method == Method::POST {
            if matches!(
                path,
                "/api/task/create" | "/api/task/create-dns" | "/api/task/placement-preview"
            ) {
                return self.allows(CreateScan);
            }
            if resource_route(path, "/api/task/", "/cancel") {
                return self.allows(CancelScan);
            }
            if resource_route(path, "/api/task/", "/retry") {
                return self.allows(RetryScan);
            }
            return matches!(
                path,
                "/api/search/v2"
                    | "/api/analysis/statistics/query"
                    | "/api/analysis/statistics/details"
            ) && self.allows(ReadResults);
        }
        read && ((path == "/api/scanner/list"
            && (self.allows(ReadResults) || self.allows(CreateScan)))
            || (path == "/api/dns/resolvers" && self.allows(CreateScan))
            || (self.allows(ReadResults)
                && (matches!(
                    path,
                    "/api/task/all"
                        | "/api/assets/summary"
                        | "/api/assets/ports"
                        | "/api/assets/port-history"
                        | "/api/assets/tags"
                        | "/api/tags"
                        | "/api/tag-categories"
                        | "/api/search/ip"
                        | "/api/search/network"
                        | "/api/search/port"
                        | "/api/search/service"
                        | "/api/search/banner"
                        | "/api/dashboard/overview"
                        | "/api/analysis/distribution"
                        | "/api/analysis/discovery-heatmap"
                        | "/api/analysis/statistics/catalog"
                ) || resource_route(path, "/api/task/", "")
                    || resource_route(path, "/api/task/", "/dns-comparison"))))
    }
}

fn resource_route(path: &str, prefix: &str, suffix: &str) -> bool {
    path.strip_prefix(prefix)
        .and_then(|tail| tail.strip_suffix(suffix))
        .is_some_and(|id| Uuid::parse_str(id).is_ok())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Update {
    pub role: i32,
    pub expected_version: i64,
    pub policy: Policy,
    pub reason: String,
}

pub(crate) enum Target<'a> {
    Id(i32),
    Username(&'a str),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UpdateError {
    #[error("用户不存在或不属于可管理角色")]
    Missing,
    #[error("权限已变更，请重新加载")]
    Conflict,
    #[error("扫描任务数已达到当前授权配额")]
    Quota,
    #[error("当前权限已失效")]
    Forbidden,
    #[error("{0}")]
    Invalid(&'static str),
    #[error(transparent)]
    Database(#[from] tokio_postgres::Error),
    #[error(transparent)]
    Pool(#[from] deadpool_postgres::PoolError),
    #[error(transparent)]
    Data(#[from] serde_json::Error),
}

pub(crate) async fn load<C: GenericClient + Sync>(
    client: &C,
    target: Target<'_>,
) -> Result<Access, UpdateError> {
    let row = match target {
        Target::Id(id) => client.query_opt(
            "SELECT role, access_version, access_policy FROM users WHERE id=$1 AND role IN (1,2,3,4) AND deleted_at IS NULL", &[&id]
        ).await?,
        Target::Username(username) => client.query_opt(
            "SELECT role, access_version, access_policy FROM users WHERE username=$1 AND role IN (1,2,3,4) AND deleted_at IS NULL", &[&username]
        ).await?,
    }.ok_or(UpdateError::Missing)?;
    Ok(Access::from_row(&row)?)
}

pub(crate) async fn update(
    pool: &Pool,
    target: Target<'_>,
    mut update: Update,
    actor: Option<&UserBaseI>,
    context: &AuditContext,
) -> Result<Access, UpdateError> {
    update
        .policy
        .validate(update.role)
        .map_err(UpdateError::Invalid)?;
    let reason = update.reason.trim();
    if reason.is_empty() || reason.chars().count() > 500 || reason.chars().any(char::is_control) {
        return Err(UpdateError::Invalid("请填写 1–500 字的变更原因"));
    }

    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    if let Some(actor) = actor {
        tx.query_opt("SELECT id FROM users WHERE id=$1 AND role=1 AND NOT limit_login AND disabled_at IS NULL AND deleted_at IS NULL FOR SHARE", &[&actor.id])
            .await?.ok_or(UpdateError::Forbidden)?;
    }
    let row = match target {
        Target::Id(id) => tx.query_opt("SELECT id, role, access_version, access_policy FROM users WHERE id=$1 AND role IN (2,3,4) AND deleted_at IS NULL FOR UPDATE", &[&id]).await?,
        Target::Username(name) => tx.query_opt("SELECT id, role, access_version, access_policy FROM users WHERE username=$1 AND role IN (2,3,4) AND deleted_at IS NULL FOR UPDATE", &[&name]).await?,
    }.ok_or(UpdateError::Missing)?;
    let before = Access::from_row(&row)?;
    if before.version != update.expected_version {
        return Err(UpdateError::Conflict);
    }
    let id: i32 = row.get("id");
    let policy = serde_json::to_value(&update.policy)?;
    if !update.policy.scanners.is_empty() {
        let ids: Vec<String> = update
            .policy
            .scanners
            .iter()
            .map(ToString::to_string)
            .collect();
        let found = tx.query("SELECT scanner_id FROM scanner_info WHERE scanner_id=ANY($1) AND deleted_at IS NULL FOR SHARE", &[&ids]).await?;
        if found.len() != ids.len() {
            return Err(UpdateError::Invalid("授权节点不存在、已删除或重复"));
        }
    }
    let after = Access::from_row(&tx.query_one(
        "UPDATE users SET role=$2, access_policy=$3, access_version=access_version+1, update_at=NOW()
         WHERE id=$1 RETURNING role, access_version, access_policy",
        &[&id, &update.role, &policy],
    ).await?)?;
    // Legacy delegated roles and stored tokens must not regain authority after a role change.
    tx.execute("DELETE FROM api_console_grant WHERE user_id=$1", &[&id])
        .await?;
    tx.execute("UPDATE api_credential SET revoked_at=NOW() WHERE revoked_at IS NULL AND client_id IN (SELECT id FROM api_client WHERE owner_user_id=$1)", &[&id]).await?;
    if before.role != after.role {
        tx.execute("UPDATE session SET is_enable=FALSE, deleted_at=NOW(), deletion_reason='access_role_changed', deleted_by_user_id=$2 WHERE user_id=$1 AND is_enable AND deleted_at IS NULL", &[&id,&actor.map(|u| u.id)]).await?;
    }
    let mut event = actor
        .map_or_else(
            || AuditEvent::system("user_security", "cli.user.access_update", "success"),
            |u| AuditEvent::user("user_security", "user.access_update", "success", u),
        )
        .resource("user", id.to_string());
    event.changes = Some(json!({"before":before,"after":after,"reason":reason}));
    write_audit(&tx, context, &event).await?;
    tx.commit().await?;
    Ok(after)
}

pub(crate) async fn ensure_scan_authorized<C: GenericClient + Sync>(
    client: &C,
    owner: i32,
    version: Option<i64>,
) -> Result<(), UpdateError> {
    let row = client.query_opt(
        "SELECT access_policy FROM users WHERE id=$1 AND deleted_at IS NULL AND disabled_at IS NULL
         AND (role=0 AND $2::BIGINT IS NULL OR NOT limit_login AND (
           (role=1 OR role=2 AND access_policy IS NULL) AND $2 IS NULL
           OR role=2 AND access_version=$2 AND access_policy->'permissions' ? 'create_scan'
             AND (access_policy->>'expires_at' IS NULL OR (access_policy->>'expires_at')::TIMESTAMPTZ>NOW())
         )) FOR NO KEY UPDATE",
        &[&owner, &version],
    ).await?.ok_or(UpdateError::Forbidden)?;
    if let Some(value) = row.get::<_, Option<Value>>("access_policy") {
        let policy: Policy = serde_json::from_value(value)?;
        let usage = client.query_one(
            "SELECT COUNT(*) FILTER (WHERE task_status IN ('pending','running')) AS active,
                COUNT(*) FILTER (WHERE task_create_time >= (EXTRACT(EPOCH FROM NOW()-INTERVAL '24 hours')*1000)::BIGINT) AS daily
             FROM scan_task WHERE user_id=$1 AND (task_status IN ('pending','running')
                OR task_create_time >= (EXTRACT(EPOCH FROM NOW()-INTERVAL '24 hours')*1000)::BIGINT)",
            &[&owner],
        ).await?;
        if usage.get::<_, i64>("active") >= i64::from(policy.max_active_tasks)
            || usage.get::<_, i64>("daily") >= i64::from(policy.tasks_per_day)
        {
            return Err(UpdateError::Quota);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scoped(role: i32, permissions: Vec<Permission>) -> Access {
        Access {
            role,
            version: 1,
            policy: Some(Policy {
                permissions,
                ..Policy::default()
            }),
        }
    }

    #[test]
    fn roles_and_expiry_bound_effective_permissions() {
        use Permission::*;
        let reader = scoped(READ_ONLY, vec![ReadResults, CreateScan]);
        assert!(reader.allows_route(&Method::POST, "/api/search/v2"));
        assert!(!reader.allows_route(&Method::POST, "/api/task/create"));
        assert!(!reader.allows_route(&Method::GET, "/api/scanner/anything"));

        let mut auditor = scoped(AUDITOR, vec![ReadAudit]);
        assert!(auditor.allows_route(&Method::GET, "/api/audit/events"));
        assert!(!auditor.allows_route(&Method::POST, "/api/audit/export"));
        assert!(!auditor.allows_route(&Method::GET, "/api/task/all"));
        auditor.policy.as_mut().unwrap().expires_at =
            Some(Utc::now() - chrono::TimeDelta::seconds(1));
        assert!(!auditor.allows_route(&Method::GET, "/api/audit/events"));
        assert!(auditor.allows_route(&Method::POST, "/api/user/password/update"));
    }

    #[test]
    fn scan_scope_checks_cidr_containment_dns_boundary_and_limits() {
        let scope = Policy {
            target_cidrs: vec!["192.0.2.0/25".parse().unwrap()],
            domains: vec!["example.org".into()],
            profiles: vec!["port_only".into(), "dns_records".into()],
            max_priority: 2,
            max_targets: 128,
            max_ports: 3,
            port_ranges: vec!["53".into(), "80".into(), "443-444".into()],
            ..Policy::default()
        };
        let ip = |cidr: &str| [cidr.parse().unwrap()];
        assert!(scope.allows_targets(&ip("192.0.2.0/25"), &[], "port_only", 2, "80,443-444"));
        assert!(!scope.allows_targets(&ip("192.0.2.0/24"), &[], "port_only", 2, "80"));
        assert!(!scope.allows_targets(&ip("192.0.2.0/25"), &[], "port_only", 2, "80-83"));
        assert!(scope.allows_targets(&[], &["docs.example.org".into()], "dns_records", 0, "53"));
        assert!(!scope.allows_targets(&[], &["otherexample.org".into()], "dns_records", 0, "53"));
    }

    #[actix_web::test]
    #[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
    async fn access_update_revokes_scoped_dispatch_and_checks_web_actor() {
        let mut config: tokio_postgres::Config = std::env::var("STORAGE_TEST_DATABASE_URL")
            .unwrap()
            .parse()
            .unwrap();
        let schema = format!("access_test_{}", Uuid::new_v4().simple());
        config.options(format!("-c search_path={schema}"));
        let pool = Pool::builder(deadpool_postgres::Manager::new(
            config,
            tokio_postgres::NoTls,
        ))
        .max_size(2)
        .build()
        .unwrap();
        let client = pool.get().await.unwrap();
        client
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        client
            .batch_execute(include_str!("../source/database/init.sql"))
            .await
            .unwrap();
        client
            .batch_execute(include_str!("../source/database/migrate_open_api.sql"))
            .await
            .unwrap();
        let scanner = Uuid::now_v7();
        client.batch_execute("INSERT INTO users(id,username,password,role) VALUES (1,'admin','unused',1),(2,'owner','unused',2),(3,'reader','unused',3);").await.unwrap();
        client.execute("INSERT INTO scanner_info(scanner_id,name,create_user,is_enable) VALUES($1,'test',1,true)", &[&scanner.to_string()]).await.unwrap();
        let actor = |id, role| UserBaseI {
            id,
            role,
            username: "fixture".into(),
            email: None,
            limit_login: false,
            enable_2fa: false,
        };
        let context = AuditContext::cli("user access set");
        let policy = Policy {
            permissions: vec![Permission::CreateScan, Permission::RetryScan],
            target_cidrs: vec!["192.0.2.0/24".parse().unwrap()],
            profiles: vec!["port_only".into()],
            scanners: vec![scanner],
            max_targets: 10,
            max_ports: 10,
            port_ranges: vec!["80".into()],
            max_active_tasks: 1,
            tasks_per_day: 1,
            ..Policy::default()
        };
        let change = |role, expected_version, policy| Update {
            role,
            expected_version,
            policy,
            reason: "test".into(),
        };
        assert!(matches!(
            update(
                &pool,
                Target::Id(2),
                change(USER, 0, policy.clone()),
                Some(&actor(3, READ_ONLY)),
                &context
            )
            .await,
            Err(UpdateError::Forbidden)
        ));
        let grant = update(
            &pool,
            Target::Username("owner"),
            change(USER, 0, policy),
            None,
            &context,
        )
        .await
        .unwrap();
        let task_id = Uuid::now_v7().to_string();
        client.execute("INSERT INTO scan_task(user_id,task_id,task_initiator,task_target,user_access_version) VALUES(2,$1,'owner',ARRAY['192.0.2.1'::INET],$2)", &[&task_id, &grant.version]).await.unwrap();
        for (candidate, allowed) in [(scanner, true), (Uuid::now_v7(), false)] {
            let eligible: bool = client.query_one("SELECT api_scan_task_enabled(t) AND user_scan_scanner_allowed(t,$2) FROM scan_task t WHERE task_id=$1", &[&task_id, &candidate.to_string()]).await.unwrap().get(0);
            assert_eq!(eligible, allowed);
        }
        drop(client);
        use crate::handlers;
        use crate::middlewares::{csrfmiddleware::CsrfMiddleware, smiddleware::AuthMiddleware};
        use actix_web::{App, cookie::Cookie, http::StatusCode, test, web};
        let password = "fixture-password";
        let hash = crate::identity::generate_hash_password(
            password,
            crate::config::PasswordHashConfig { m: 1, t: 1, p: 1 },
        )
        .unwrap();
        let client = pool.get().await.unwrap();
        client
            .execute("UPDATE users SET password=$1 WHERE id=1", &[&hash])
            .await
            .unwrap();
        client
            .batch_execute(
                "INSERT INTO session(user_id,token,csrf_token,totp_verify_successful)
             VALUES (1,'admin-session','test-csrf',true),(3,'reader-session','reader-csrf',true)",
            )
            .await
            .unwrap();
        drop(client);

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .wrap(CsrfMiddleware)
                .wrap(AuthMiddleware)
                .service(handlers::access::current)
                .service(handlers::access::verify)
                .service(handlers::access::put_user_access),
        )
        .await;
        let web_change = |session, csrf| {
            test::TestRequest::put()
            .uri("/api/admin/users/2/access")
            .cookie(Cookie::new("session", session))
            .insert_header(("X-CSRF-Token", csrf))
            .set_json(json!({"role":READ_ONLY,"expected_version":grant.version,"policy":{},"reason":"readonly"}))
            .to_request()
        };
        let denied = test::call_service(&app, web_change("reader-session", "reader-csrf")).await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let proof_needed = test::call_service(&app, web_change("admin-session", "test-csrf")).await;
        assert_eq!(proof_needed.status(), StatusCode::FORBIDDEN);
        let body: Value = test::read_body_json(proof_needed).await;
        assert_eq!(body["error"]["code"], "step_up_required");
        let verified = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/access/verify")
                .cookie(Cookie::new("session", "admin-session"))
                .insert_header(("X-CSRF-Token", "test-csrf"))
                .set_json(json!({"password":password}))
                .to_request(),
        )
        .await;
        assert_eq!(verified.status(), StatusCode::OK);
        let changed = test::call_service(&app, web_change("admin-session", "test-csrf")).await;
        assert_eq!(changed.status(), StatusCode::OK);
        let body: Value = test::read_body_json(changed).await;
        assert_eq!(body["data"]["version"], grant.version + 1);
        assert!(matches!(
            update(
                &pool,
                Target::Id(2),
                change(USER, grant.version, Policy::default()),
                None,
                &context
            )
            .await,
            Err(UpdateError::Conflict)
        ));
        let client = pool.get().await.unwrap();
        let can_dispatch: bool = client
            .query_one(
                "SELECT api_scan_task_enabled(t) FROM scan_task t WHERE task_id=$1",
                &[&task_id],
            )
            .await
            .unwrap()
            .get(0);
        assert!(!can_dispatch);
        client
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
