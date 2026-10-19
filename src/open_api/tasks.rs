use super::{
    ApiError, Principal, Result, auth, business, console, model,
    query::{self},
    request_id,
};
use crate::elasticsearch::ElasticsearchService;
use actix_web::{HttpRequest, http::StatusCode, web};
use deadpool_postgres::{GenericClient, Pool, Transaction};
use ipnet::IpNet;
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::IpAddr};
use tokio_postgres::Row;
use uuid::Uuid;

pub(crate) struct Plan {
    pub targets: Vec<String>,
    pub domains: Vec<String>,
    pub ports: String,
    pub profile: String,
    pub family: String,
    pub target_count: u128,
    pub port_count: usize,
    pub remark: String,
    pub reference: Option<String>,
}
pub(crate) fn plan(v: &Value, p: &Principal) -> Result<Plan> {
    console::allowed_keys(
        v,
        &[
            "targets",
            "domains",
            "ports",
            "scan_profile",
            "remark",
            "client_reference",
        ],
    )?;
    for key in ["ports", "scan_profile", "remark", "client_reference"] {
        if v.get(key).is_some_and(|v| !v.is_string()) {
            return Err(ApiError::bad(format!("{key} 必须为字符串")));
        }
    }
    let targets: Vec<String> =
        serde_json::from_value(v.get("targets").cloned().unwrap_or_else(|| json!([])))
            .map_err(|_| ApiError::bad("targets 格式无效"))?;
    let domains: Vec<String> =
        serde_json::from_value(v.get("domains").cloned().unwrap_or_else(|| json!([])))
            .map_err(|_| ApiError::bad("domains 格式无效"))?;
    if targets.is_empty() == domains.is_empty() {
        return Err(ApiError::bad("必须指定 targets 或 domains，不能混用"));
    }
    if targets.len() > p.policy.max_targets || domains.len() > 100 {
        return Err(ApiError::bad("目标数量超出限制"));
    }
    let profile = v["scan_profile"].as_str().unwrap_or("port_only").to_owned();
    if !p.policy.profiles.contains(&profile) {
        return Err(ApiError::forbidden());
    }
    if profile == "dns_records" && !targets.is_empty() {
        return Err(ApiError::bad("仅 DNS 扫描只接受域名"));
    }
    let mut canonical = BTreeSet::new();
    let mut family = None;
    let mut count = 0u128;
    for target in targets {
        let network = target
            .parse::<IpNet>()
            .or_else(|_| target.parse::<IpAddr>().map(IpNet::from))
            .map_err(|_| ApiError::bad("IP/CIDR 目标无效"))?;
        if !p.policy.allows_network(&network) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "target_not_allowed",
                "扫描目标不在批准范围或与排除范围相交",
            ));
        }
        let f = if network.addr().is_ipv4() {
            "ipv4"
        } else {
            "ipv6"
        };
        if family.is_some_and(|s| s != f) {
            return Err(ApiError::bad("同一任务不能混合 IPv4 和 IPv6"));
        }
        family = Some(f);
        if canonical.insert(network.trunc().to_string()) {
            let bits = if f == "ipv4" { 32 } else { 128 };
            count = count.saturating_add(
                1u128
                    .checked_shl(bits - u32::from(network.prefix_len()))
                    .unwrap_or(u128::MAX),
            );
        }
    }
    let mut normalized_domains = BTreeSet::new();
    for d in domains {
        let domain = model::normalize_domain(&d)?;
        if p.policy.domains.is_empty() || !p.policy.allows_domain(&domain) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "target_not_allowed",
                "域名不在批准范围",
            ));
        }
        normalized_domains.insert(domain);
    }
    if count > p.policy.max_targets as u128 {
        return Err(ApiError::bad("CIDR 展开地址数超过 max_targets"));
    }
    let raw_ports = v["ports"].as_str().unwrap_or(if profile == "dns_records" {
        ""
    } else {
        "80,443"
    });
    if raw_ports.len() > 4096 {
        return Err(ApiError::bad("端口表达式过长"));
    }
    let mut ports = BTreeSet::new();
    if profile == "dns_records" {
        if !raw_ports.trim().is_empty() {
            return Err(ApiError::bad("仅 DNS 模式不能指定端口"));
        }
    } else {
        for part in raw_ports.split(',') {
            let part = part.trim();
            let (start, end) = if let Some((a, b)) = part.split_once('-') {
                (a.parse::<u16>(), b.parse::<u16>())
            } else {
                let n = part.parse::<u16>();
                (n.clone(), n)
            };
            let (start, end) = (
                start.map_err(|_| ApiError::bad("端口无效"))?,
                end.map_err(|_| ApiError::bad("端口无效"))?,
            );
            if start == 0 || start > end {
                return Err(ApiError::bad("端口必须为 1–65535，范围不能逆序"));
            }
            if (end - start) as usize + 1 > p.policy.max_ports {
                return Err(ApiError::bad("端口数量超过限制"));
            }
            ports.extend(start..=end);
            if ports.len() > p.policy.max_ports {
                return Err(ApiError::bad("端口数量超过限制"));
            }
        }
        if ports.is_empty() {
            return Err(ApiError::bad("端口不能为空"));
        }
        if !normalized_domains.is_empty() && p.policy.cidrs.is_empty() {
            return Err(ApiError::bad("域名后续扫描需要批准 IP 范围"));
        }
    }
    let remark = v["remark"].as_str().unwrap_or("").to_owned();
    let reference = v["client_reference"].as_str().map(str::to_owned);
    if remark.len() > 2000 || reference.as_ref().is_some_and(|s| s.len() > 200) {
        return Err(ApiError::bad("备注或关联编号过长"));
    }
    Ok(Plan {
        targets: canonical.into_iter().collect(),
        target_count: if normalized_domains.is_empty() {
            count
        } else {
            normalized_domains.len() as u128
        },
        domains: normalized_domains.into_iter().collect(),
        ports: ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(","),
        port_count: ports.len(),
        profile,
        family: family.unwrap_or("ipv4").into(),
        remark,
        reference,
    })
}
pub(crate) async fn authorize<C: GenericClient + Sync>(tx: &C, p: &Principal) -> Result<()> {
    if tx
        .query_one("SELECT enabled FROM system_maintenance_state", &[])
        .await?
        .get::<_, bool>(0)
    {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "system_maintenance",
            "系统维护中，暂不接受业务写入",
        ));
    }
    let row=tx.query_opt("SELECT a.revision FROM api_client a JOIN api_credential k ON k.client_id=a.id JOIN users u ON u.id=a.owner_user_id CROSS JOIN api_platform_settings s WHERE a.id=$1 AND k.id=$2 AND a.status='active' AND k.revoked_at IS NULL AND k.expires_at>NOW() AND (a.expires_at IS NULL OR a.expires_at>NOW()) AND u.deleted_at IS NULL AND u.disabled_at IS NULL AND NOT u.limit_login AND COALESCE((s.document->>'enabled')::BOOLEAN,FALSE) FOR UPDATE OF a FOR SHARE OF k",&[&p.client_pk,&p.credential_id]).await?.ok_or_else(auth::unauthorized)?;
    if row.get::<_, i64>(0) != p.revision {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "policy_changed",
            "授权策略已变化，请重试",
        ));
    }
    Ok(())
}
pub(crate) fn idempotency_key(req: &HttpRequest) -> Result<String> {
    let key = req
        .headers()
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::bad("创建操作必须提供 Idempotency-Key"))?;
    if key.is_empty() || key.len() > 128 || !key.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(ApiError::bad("Idempotency-Key 无效"));
    }
    Ok(key.into())
}
pub(crate) async fn replay<C: GenericClient + Sync>(
    tx: &C,
    p: &Principal,
    op: &str,
    key: &str,
    body: &Value,
) -> Result<Option<Value>> {
    let row=tx.query_opt("SELECT fingerprint,response FROM api_idempotency_record WHERE client_id=$1 AND operation=$2 AND key=$3",&[&p.client_pk,&op,&key]).await?;
    if let Some(row) = row {
        if row.get::<_, String>(0) != model::fingerprint(body.to_string().as_bytes()) {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "idempotency_conflict",
                "同一幂等键对应了不同请求",
            ));
        }
        return Ok(Some(row.get(1)));
    }
    Ok(None)
}
pub(crate) async fn remember<C: GenericClient + Sync>(
    tx: &C,
    p: &Principal,
    op: &str,
    key: &str,
    body: &Value,
    result: &Value,
) -> Result<()> {
    tx.execute("INSERT INTO api_idempotency_record(client_id,operation,key,fingerprint,response) VALUES($1,$2,$3,$4,$5)",&[&p.client_pk,&op,&key,&model::fingerprint(body.to_string().as_bytes()),&result]).await?;
    Ok(())
}
pub(crate) async fn create(
    req: &HttpRequest,
    pool: &Pool,
    p: &Principal,
    v: &Value,
    retry: Option<&str>,
) -> Result<Value> {
    let plan = plan(v, p)?;
    let key = idempotency_key(req)?;
    let operation = retry
        .map(|id| format!("task.retry:{id}"))
        .unwrap_or_else(|| "task.create".into());
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='8s'")
        .await?;
    authorize(&tx, p).await?;
    if let Some(result) = replay(&tx, p, &operation, &key, v).await? {
        tx.commit().await?;
        return Ok(result);
    }
    if p.environment == "sandbox" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "sandbox_write_denied",
            "sandbox 应用不能提交真实扫描",
        ));
    }
    let running:i64=tx.query_one("SELECT COUNT(*) FROM scan_task WHERE api_client_id=$1 AND task_status IN ('pending','running')",&[&p.client_pk]).await?.get(0);
    if running >= p.policy.max_running_tasks {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "task_concurrency_exceeded",
            "运行及排队任务已达上限",
        ));
    }
    auth::consume(
        &tx,
        p.client_pk,
        "tasks.minute",
        p.policy.tasks_per_minute,
        1,
        false,
    )
    .await?;
    auth::consume(
        &tx,
        p.client_pk,
        "tasks.day",
        p.policy.tasks_per_day,
        1,
        true,
    )
    .await?;
    let domain_task = !plan.domains.is_empty();
    let task_profile = if domain_task {
        "dns_records"
    } else {
        plan.profile.as_str()
    };
    let scan_plan = crate::scan_control::build_scan_plan(task_profile).map_err(ApiError::bad)?;
    if domain_task {
        let runtime = req
            .app_data::<web::Data<crate::runtime_config::RuntimeSettings>>()
            .ok_or_else(ApiError::unavailable)?;
        let global = runtime.dns_follow_up.get().await;
        if plan.domains.iter().any(|d| !global.value.allows_domain(d)) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "domain_excluded",
                "目标命中平台 DNS 域名排除规则",
            ));
        }
        if plan.profile != "dns_records" && !global.value.enabled {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "dns_follow_up_disabled",
                "平台域名后续扫描未启用",
            ));
        }
    }
    let id = Uuid::now_v7();
    let tid = id.to_string();
    let metadata = json!({"open_api":{"client_id":p.client_pk,"credential_id":p.credential_id,"policy_revision":p.revision,"policy":p.policy,"client_reference":plan.reference},"dns_follow_up":{"enabled":domain_task&&plan.profile!="dns_records","scan_profile":plan.profile}});
    let row=tx.query_one("INSERT INTO scan_task(user_id,task_id,task_initiator,task_target,dns_targets,task_kind,task_port,task_level,remarks,dispatch_mode,address_family,scan_profile,scan_plan,generation_metadata,api_client_id,api_credential_id,retry_of_task_id) VALUES($1,$2,$3,ARRAY(SELECT inet(unnest($4::TEXT[]))),$5,$6,$7,1,$8,'automatic',$9,$10,$11,$12,$13,$14,$15) RETURNING id",&[&p.owner_id,&tid,&format!("api:{}",p.client_id),&plan.targets,&plan.domains,&if domain_task{"dns"}else{"ip"},&plan.ports,&plan.remark,&plan.family,&task_profile,&scan_plan,&metadata,&p.client_pk,&p.credential_id,&retry]).await?;
    let pk: i32 = row.get(0);
    let execution = Uuid::now_v7();
    tx.execute(
        "INSERT INTO scan_task_execution(execution_id,task_id) VALUES($1,$2)",
        &[&execution.to_string(), &pk],
    )
    .await?;
    let result = json!({"task_id":id,"execution_id":execution,"status":"pending","scan_profile":plan.profile,"target_count":plan.target_count.to_string(),"port_count":plan.port_count,"client_reference":plan.reference});
    remember(&tx, p, &operation, &key, v, &result).await?;
    auth::audit(&tx,Some(p.client_pk),"application",&p.client_id.to_string(),if retry.is_some(){"task.retry"}else{"task.create"},Some(&tid),Some(request_id(req)),&json!({"scan_profile":plan.profile,"target_count":plan.target_count.to_string(),"port_count":plan.port_count})).await?;
    tx.commit().await?;
    Ok(result)
}
pub(crate) fn visible(row: &Row, p: &Principal) -> bool {
    let targets: Vec<String> = row.get("targets");
    let domains: Vec<String> = row.get("dns_targets");
    targets.iter().all(|s| {
        s.parse::<IpNet>().ok().is_some_and(|n| {
            if p.policy.cidrs.is_empty() {
                p.policy.allows_ip(n.network())
                    && p.policy
                        .excluded_cidrs
                        .iter()
                        .filter_map(|s| s.parse::<IpNet>().ok())
                        .all(|e| !n.contains(&e.network()))
            } else {
                p.policy.allows_network(&n)
            }
        })
    }) && domains.iter().all(|d| p.policy.allows_domain(d))
}
fn task(row: &Row) -> Value {
    json!({"task_id":row.get::<_,String>("task_id"),"targets":row.get::<_,Vec<String>>("targets"),"domains":row.get::<_,Vec<String>>("dns_targets"),"kind":row.get::<_,String>("task_kind"),"scan_profile":row.get::<_,String>("scan_profile"),"status":row.get::<_,String>("task_status"),"created_at":row.get::<_,i64>("task_create_time"),"started_at":row.get::<_,Option<i64>>("task_start_time"),"ended_at":row.get::<_,Option<i64>>("task_end_time"),"ports":row.get::<_,String>("task_port"),"remark":row.get::<_,Option<String>>("remarks"),"retry_of_task_id":row.get::<_,Option<String>>("retry_of_task_id"),"client_reference":row.get::<_,Option<Value>>("generation_metadata").and_then(|v|v.pointer("/open_api/client_reference").cloned())})
}
pub(crate) async fn get<C: GenericClient + Sync>(
    c: &C,
    p: &Principal,
    id: &str,
    lock: bool,
) -> Result<Row> {
    model::parse_uuid(id)?;
    let sql = format!(
        "SELECT t.*,t.task_target::TEXT[] AS targets FROM scan_task t WHERE task_id=$1 AND user_id=$2 AND ($3 OR api_client_id=$4) AND ($5::BIGINT IS NULL OR task_create_time>=$5) AND ($6::BIGINT IS NULL OR task_create_time<$6) {}",
        if lock { "FOR UPDATE" } else { "" }
    );
    let row = c
        .query_opt(
            &sql,
            &[
                &id,
                &p.owner_id,
                &(p.policy.data_mode == "owner"),
                &p.client_pk,
                &p.policy.from_at,
                &p.policy.to_at,
            ],
        )
        .await?
        .ok_or_else(ApiError::missing)?;
    if !visible(&row, p) {
        return Err(ApiError::missing());
    }
    Ok(row)
}
fn execution(r: &Row) -> Value {
    json!({"execution_id":r.get::<_,String>("execution_id"),"status":r.get::<_,String>("execution_status"),"started_at":r.get::<_,Option<i64>>("task_start_time"),"ended_at":r.get::<_,Option<i64>>("task_end_time"),"attempt_count":r.get::<_,i32>("attempt_count"),"failure_code":if r.get::<_,Option<String>>("failure_reason").is_some(){Some("scan_failed")}else{None},"projection_status":r.get::<_,String>("projection_status")})
}
pub(crate) async fn dispatch(
    req: &HttpRequest,
    pool: &Pool,
    es: &ElasticsearchService,
    p: &Principal,
    e: &super::catalog::Endpoint,
    parts: &[&str],
    v: &Value,
) -> Result<Value> {
    if matches!(e.path, "/tasks/validate" | "/tasks/estimate") {
        let plan = plan(v, p)?;
        return Ok(
            json!({"valid":true,"target_count":plan.target_count.to_string(),"port_count":plan.port_count,"estimated_port_probes":(plan.target_count*plan.port_count as u128).to_string(),"address_family":plan.family,"scan_profile":plan.profile,"dns_resolved_target_count":"unknown_until_resolution"}),
        );
    }
    if e.path == "/tasks" && e.method == "POST" {
        return create(req, pool, p, v, None).await;
    }
    let mut c = pool.get().await?;
    if e.path == "/tasks" {
        let s = business::search(req, v)?;
        s.validate(p)?;
        if s.query.is_some()
            || s.fields.is_some()
            || s.task_id.is_some()
            || s.execution_id.is_some()
            || s.severity.is_some()
            || s.template_id.is_some()
        {
            return Err(ApiError::bad("任务列表只接受分页和时间条件"));
        }
        let start = match (p.policy.from_at, s.start_at) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        let end = match (p.policy.to_at, s.end_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let label = format!(
            "tasks:{}",
            model::fingerprint(
                json!({"start":start,"end":end,"size":s.size()?})
                    .to_string()
                    .as_bytes()
            )
        );
        let after = query::db_after(pool, p, s.cursor, &label).await?;
        let rows=c.query("SELECT t.*,t.task_target::TEXT[] AS targets FROM scan_task t WHERE user_id=$1 AND ($2 OR api_client_id=$3) AND id<$4 AND ($5::BIGINT IS NULL OR task_create_time>=$5) AND ($6::BIGINT IS NULL OR task_create_time<$6) ORDER BY id DESC LIMIT $7",&[&p.owner_id,&(p.policy.data_mode=="owner"),&p.client_pk,&after,&start,&end,&(s.size()? as i64+1)]).await?;
        let size = s.size()?;
        let next = if rows.len() > size {
            Some(query::db_next(pool, p, rows[size - 1].get::<_, i32>("id") as i64, &label).await?)
        } else {
            None
        };
        return Ok(
            json!({"items":rows.iter().take(size).filter(|r|visible(r,p)).map(task).collect::<Vec<_>>(),"next_cursor":next}),
        );
    }
    let id = parts[1];
    let row = get(&c, p, id, false).await?;
    let pk: i32 = row.get("id");
    match e.path {
        "/tasks/{task_id}" => {
            let mut value = task(&row);
            if row.get::<_, String>("task_kind") == "dns" {
                let generated=c.query_opt("SELECT g.status,g.eligible_ip_count,g.created_task_count FROM dns_follow_up_generation g JOIN scan_task_execution e ON e.id=g.execution_id WHERE e.task_id=$1 ORDER BY e.id DESC LIMIT 1",&[&pk]).await?;
                value["dns_follow_up"]=generated.map(|r|json!({"status":r.get::<_,String>(0),"eligible_ip_count":r.get::<_,i32>(1),"created_task_count":r.get::<_,i32>(2)})).unwrap_or(Value::Null);
            }
            Ok(value)
        }
        "/tasks/{task_id}/executions" | "/tasks/{task_id}/executions/{execution_id}" => {
            let execution_id = if parts.len() > 3 {
                Some(model::parse_uuid(parts[3])?.to_string())
            } else {
                None
            };
            let rows=c.query("SELECT e.*,CASE WHEN e.execution_status<>'succeeded' THEN 'not_started' WHEN p.processed_at IS NOT NULL THEN 'ready' ELSE 'pending' END AS projection_status FROM scan_task_execution e LEFT JOIN scan_projection_outbox p ON p.execution_id=e.id WHERE e.task_id=$1 AND ($2::TEXT IS NULL OR e.execution_id=$2) ORDER BY e.id LIMIT 100",&[&pk,&execution_id]).await?;
            if execution_id.is_some() && rows.is_empty() {
                return Err(ApiError::missing());
            }
            Ok(json!({"items":rows.iter().map(execution).collect::<Vec<_>>()}))
        }
        "/tasks/{task_id}/results" | "/tasks/{task_id}/vulnerabilities" => {
            drop(c);
            if e.path.ends_with("/vulnerabilities") {
                return business::vulnerabilities(req, pool, es, p, e, None, parts, v).await;
            }
            let s = business::search(req, v)?;
            let filters = vec![
                json!({"term":{"task_id":id}}),
                json!({"terms":{"kind":if p.has("vulnerabilities:read"){vec!["port","service","vulnerability"]}else{vec!["port","service"]}}}),
            ];
            Ok(business::project_facts(
                p,
                query::facts(pool, es, p, &s, filters).await?,
                false,
            ))
        }
        "/tasks/{task_id}/dns-comparison" => {
            if row.get::<_, String>("task_kind") != "dns" {
                return Err(ApiError::bad("此任务不是 DNS 任务"));
            }
            let mut s = business::search(req, v)?;
            s.page_size = Some(100);
            s.task_id = Some(model::parse_uuid(id)?);
            let mut result = query::dns(pool, es, p, None, &s).await?;
            // Task comparison is filtered at the ES boundary, not after pagination.
            result["task_id"] = json!(id);
            Ok(result)
        }
        "/tasks/{task_id}/children" => {
            let rows=c.query("SELECT t.*,t.task_target::TEXT[] AS targets FROM scan_task t JOIN scan_task_lineage l ON l.child_task_id=t.id WHERE l.parent_task_id=$1 AND t.user_id=$2 AND ($3 OR t.api_client_id=$4) ORDER BY t.id LIMIT 100",&[&pk,&p.owner_id,&(p.policy.data_mode=="owner"),&p.client_pk]).await?;
            Ok(json!({"items":rows.iter().filter(|r|visible(r,p)).map(task).collect::<Vec<_>>()}))
        }
        "/tasks/{task_id}/cancel" => {
            let tx = c.transaction().await?;
            authorize(&tx, p).await?;
            let row = get(&tx, p, id, true).await?;
            if row.get::<_, Option<i32>>("api_client_id") != Some(p.client_pk) {
                return Err(ApiError::forbidden());
            }
            let now = crate::clock::get_unix_epoch_ms();
            tx.execute("UPDATE scan_task_execution SET execution_status=CASE WHEN execution_status='pending' THEN 'cancelled' ELSE execution_status END,cancel_requested=execution_status='running',task_end_time=CASE WHEN execution_status='pending' THEN $2 ELSE task_end_time END WHERE task_id=$1 AND execution_status IN ('pending','running')",&[&pk,&now]).await?;
            crate::scan_control::refresh_task_aggregate(&tx, pk).await?;
            auth::audit(
                &tx,
                Some(p.client_pk),
                "application",
                &p.client_id.to_string(),
                "task.cancel",
                Some(id),
                Some(request_id(req)),
                &json!({}),
            )
            .await?;
            tx.commit().await?;
            Ok(json!({"cancel_requested":true,"task_id":id}))
        }
        "/tasks/{task_id}/retry" => {
            if !p.has("tasks:create")
                || row.get::<_, Option<i32>>("api_client_id") != Some(p.client_pk)
            {
                return Err(ApiError::forbidden());
            }
            if !matches!(
                row.get::<_, String>("task_status").as_str(),
                "succeeded" | "failed" | "partial" | "cancelled"
            ) {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "task_not_finished",
                    "只能重试已结束任务",
                ));
            }
            let original = task(&row);
            let profile = row
                .get::<_, Option<Value>>("generation_metadata")
                .and_then(|v| v.pointer("/dns_follow_up/scan_profile").cloned())
                .unwrap_or_else(|| original["scan_profile"].clone());
            let mut input =
                json!({"ports":original["ports"],"scan_profile":profile,"remark":"API task retry"});
            if row.get::<_, String>("task_kind") == "dns" {
                input["domains"] = original["domains"].clone();
            } else {
                input["targets"] = original["targets"].clone();
            }
            drop(c);
            create(req, pool, p, &input, Some(id)).await
        }
        _ => Err(ApiError::missing()),
    }
}
/// Revalidate both the captured and current grants before creating DNS child tasks.
pub(crate) async fn follow_up_scope(
    tx: &Transaction<'_>,
    metadata: &Value,
) -> std::result::Result<Option<Principal>, tokio_postgres::Error> {
    let Some(id) = metadata
        .pointer("/open_api/client_id")
        .and_then(Value::as_i64)
    else {
        return Ok(None);
    };
    let key = metadata
        .pointer("/open_api/credential_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok());
    let row=tx.query_opt("SELECT a.client_id,a.owner_user_id,a.name,a.environment,a.revision,a.policy,k.id,k.scopes,k.expires_at FROM api_client a JOIN api_credential k ON k.client_id=a.id JOIN users u ON u.id=a.owner_user_id CROSS JOIN api_platform_settings s CROSS JOIN system_maintenance_state m WHERE a.id=$1 AND k.id=$2 AND a.status='active' AND k.revoked_at IS NULL AND k.expires_at>NOW() AND (a.expires_at IS NULL OR a.expires_at>NOW()) AND u.disabled_at IS NULL AND u.deleted_at IS NULL AND NOT u.limit_login AND NOT m.enabled AND COALESCE((s.document->>'enabled')::BOOLEAN,FALSE) FOR UPDATE OF a FOR SHARE OF k",&[&(id as i32),&key]).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let revision: i64 = row.get("revision");
    if metadata
        .pointer("/open_api/policy_revision")
        .and_then(Value::as_i64)
        != Some(revision)
    {
        return Ok(None);
    }
    let Ok(policy) = serde_json::from_value::<super::Policy>(row.get("policy")) else {
        return Ok(None);
    };
    let p = Principal {
        client_pk: id as i32,
        client_id: row.get("client_id"),
        credential_id: row.get("id"),
        owner_id: row.get("owner_user_id"),
        name: row.get("name"),
        environment: row.get("environment"),
        revision,
        policy,
        scopes: row.get("scopes"),
        expires_at: row.get("expires_at"),
    };
    if !p.has("tasks:create") || p.environment == "sandbox" {
        return Ok(None);
    }
    Ok(Some(p))
}

/// Called only after follow_up_scope has locked the application in this transaction.
/// Reserve the complete child set; a daily-limit rejection must not spend minute units.
pub(crate) async fn reserve_follow_up(
    tx: &Transaction<'_>,
    p: &Principal,
    count: i64,
) -> std::result::Result<bool, tokio_postgres::Error> {
    let running:i64=tx.query_one("SELECT COUNT(*) FROM scan_task WHERE api_client_id=$1 AND task_status IN ('pending','running')",&[&p.client_pk]).await?.get(0);
    if count <= 0 || running + count > p.policy.max_running_tasks {
        return Ok(false);
    }
    tx.batch_execute("SAVEPOINT api_follow_up_quota").await?;
    for (category, limit, bucket) in [
        ("tasks.minute", p.policy.tasks_per_minute, "minute"),
        ("tasks.day", p.policy.tasks_per_day, "day"),
    ] {
        let row=tx.query_opt("INSERT INTO api_usage_bucket(client_id,category,bucket_start,units) SELECT $1,$2,date_trunc($3,NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',$4::BIGINT WHERE $4::BIGINT<=$5::BIGINT ON CONFLICT(client_id,category,bucket_start) DO UPDATE SET units=api_usage_bucket.units+EXCLUDED.units WHERE api_usage_bucket.units+EXCLUDED.units<=$5 RETURNING units",&[&p.client_pk,&category,&bucket,&count,&limit]).await?;
        if row.is_none() {
            tx.batch_execute(
                "ROLLBACK TO SAVEPOINT api_follow_up_quota; RELEASE SAVEPOINT api_follow_up_quota",
            )
            .await?;
            return Ok(false);
        }
    }
    tx.batch_execute("RELEASE SAVEPOINT api_follow_up_quota")
        .await?;
    tx.execute("INSERT INTO api_audit(client_id,actor_type,actor_id,action,changes) VALUES($1,'system','dns-follow-up','task.follow_up.reserve',$2)",&[&p.client_pk,&json!({"task_count":count})]).await?;
    Ok(true)
}
