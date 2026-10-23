use actix_web::{HttpRequest, HttpResponse, Responder, post, web};
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    admin::UserBaseI,
    config::SecurityConfig,
    maxmind::MaxMindState,
    scan_control::{
        dispatch::{ApplyTaskError, validate_scanner_credentials_with_client},
        routing::{self, Performance},
    },
    system_maintenance::SystemMaintenanceState,
};

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Deserialize)]
pub struct PlacementRequest {
    targets: Vec<String>,
    scan_profile: String,
    #[serde(default = "default_ports")]
    port: String,
    #[serde(default = "empty_resolvers")]
    dns_resolvers: Value,
    #[serde(default)]
    required_services: Vec<String>,
}
fn default_ports() -> String {
    "1-65535".into()
}
fn empty_resolvers() -> Value {
    json!([])
}

#[post("/api/task/placement-preview")]
pub async fn placement_preview(
    pool: web::Data<Pool>,
    maxmind: web::Data<MaxMindState>,
    input: web::Json<PlacementRequest>,
    user: UserBaseI,
) -> impl Responder {
    if !matches!(user.role, 1 | 2) {
        return HttpResponse::Forbidden().finish();
    }
    let profile = input.scan_profile.trim().to_ascii_lowercase();
    if input.targets.is_empty()
        || input.targets.len() > 100
        || input.targets.iter().any(|t| t.len() > 253)
        || crate::scan_control::creation::build_service_scan_plan(
            &profile,
            &input.required_services,
        )
        .is_err()
        || !crate::scan_control::target::check_port(&input.port)
        || !input.dns_resolvers.is_array()
        || input.dns_resolvers.as_array().is_some_and(|r| r.len() > 8)
    {
        return HttpResponse::BadRequest()
            .json(json!({"success":false,"message":"无效的目标、扫描模式或端口"}));
    }
    let resolvers = match serde_json::from_value::<Vec<crate::handlers::task::CreateDnsResolver>>(
        input.dns_resolvers.clone(),
    ) {
        Ok(resolvers) => match resolvers
            .into_iter()
            .map(crate::handlers::task::CreateDnsResolver::normalize)
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(resolvers) => json!(resolvers),
            Err(reason) => {
                return HttpResponse::BadRequest().json(json!({"success":false,"message":reason}));
            }
        },
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(json!({"success":false,"message":"无效的 DNS 解析器"}));
        }
    };
    let family = if profile == "dns_records" {
        if input
            .targets
            .iter()
            .any(|t| crate::dns::canonical_scan_domain(t).is_err())
        {
            return HttpResponse::BadRequest().finish();
        }
        crate::handlers::task::DNS_TASK_ADDRESS_FAMILY
    } else {
        if resolvers.as_array().is_some_and(|r| !r.is_empty()) {
            return HttpResponse::BadRequest().finish();
        }
        let mut family = None;
        for target in &input.targets {
            let net = target.parse::<ipnet::IpNet>().ok().or_else(|| {
                target
                    .parse::<std::net::IpAddr>()
                    .ok()
                    .map(ipnet::IpNet::from)
            });
            let Some(net) = net else {
                return HttpResponse::BadRequest().finish();
            };
            let current = if net.addr().is_ipv6() { "ipv6" } else { "ipv4" };
            if family.is_some_and(|f| f != current) {
                return HttpResponse::BadRequest().finish();
            }
            family = Some(current);
        }
        family.unwrap_or("ipv4")
    };
    let result: Result<Value, Error> = async {
        let client = pool.get().await?;
        let cfg = routing::config(&client).await?;
        let nodes = routing::candidates(&client, &maxmind, &input.targets, family, &profile, &input.port, user.id, &resolvers, &json!(input.required_services), &cfg).await?;
        let preferred = cfg.enabled.then(|| nodes.iter().find(|n| !n.busy).map(|n| n.scanner_id.clone())).flatten();
        Ok(json!({"enabled":cfg.enabled,"target_geo":routing::target_geo(&input.targets,&maxmind),"preferred_scanner_id":preferred,"candidates":nodes,"reason":if !cfg.enabled{"disabled"}else if preferred.is_some(){"ranked_candidate"}else{"no_idle_candidate"}}))
    }.await;
    match result {
        Ok(data) => HttpResponse::Ok().json(json!({"success":true,"data":data})),
        Err(error) => {
            tracing::error!(event="PlacementPreviewError", %error);
            HttpResponse::ServiceUnavailable()
                .json(json!({"success":false,"message":"分配预览暂不可用"}))
        }
    }
}

#[derive(Deserialize)]
pub struct PerformanceRequest {
    scanner_id: Uuid,
    task_id: Uuid,
    performance: Performance,
}

/// Optional metrics affect placement only after the normal final receipt succeeds.
#[post("/api/scanner/task/performance")]
pub async fn report_performance(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
    input: web::Json<PerformanceRequest>,
) -> impl Responder {
    let Some(token) = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
    else {
        return HttpResponse::Unauthorized().finish();
    };
    let result: Result<HttpResponse, Error> = async {
        let mut client = pool.get().await?;
        let tx = client.transaction().await?;
        let token_hash = crate::identity::hash_scanner_token(token, &security.scanner_token_pepper)?;
        match validate_scanner_credentials_with_client(&tx, input.scanner_id, &token_hash).await {
            Ok(()) => {},
            Err(ApplyTaskError::ScannerUnauthorized) => return Ok(HttpResponse::Unauthorized().finish()),
            Err(error) => return Err(Box::new(error) as Error),
        }
        let snapshot = maintenance.snapshot().await;
        if snapshot.blocks_all_scanner_requests() { return Ok(crate::system_maintenance::maintenance_response(&snapshot)); }
        let row = tx.query_opt(
            "SELECT e.id,e.performance,t.task_target::TEXT[] AS targets,t.task_port,t.task_kind,t.dns_targets,t.scan_profile \
             FROM scan_task_execution e JOIN scan_task t ON t.id=e.task_id WHERE t.task_id=$1 AND e.assigned_scanner_id=$2 \
             AND e.execution_status='running' AND NOT e.cancel_requested \
             AND (e.lease_expires_at>(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT OR e.maintenance_hold) FOR UPDATE OF e",
            &[&input.task_id.to_string(), &input.scanner_id.to_string()],
        ).await?;
        let Some(row) = row else {
            return Ok(HttpResponse::Conflict().json(json!({"success":false,"message":"扫描执行归属或租约已变更"})));
        };
        let validation = if row.get::<_, &str>("task_kind") == "dns" {
            input.performance.validate_dns(&row.get::<_, Vec<String>>("dns_targets"), row.get("scan_profile"), row.get("task_port"))
        } else {
            input.performance.validate(&row.get::<_, Vec<String>>("targets"), row.get("task_port"))
        };
        if let Err(reason) = validation {
            return Ok(HttpResponse::BadRequest().json(json!({"success":false,"message":reason})));
        }
        if row.get::<_, Option<Value>>("performance").is_none() {
            tx.execute("UPDATE scan_task_execution SET performance=$2 WHERE id=$1", &[&row.get::<_, i32>("id"), &json!(input.performance)]).await?;
        }
        tx.commit().await?;
        Ok(HttpResponse::Ok().json(json!({"success":true})))
    }.await;
    match result {
        Ok(response) => response,
        Err(error) => {
            tracing::error!(event="TaskPerformanceReportError", %error);
            HttpResponse::ServiceUnavailable().finish()
        }
    }
}
