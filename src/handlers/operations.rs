use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write as write_audit};
use crate::config::SecurityConfig;
use crate::elasticsearch::{ElasticsearchService, ScanQueryIndex};
use crate::logs::write::{error_logs, error_logs_error};
use crate::{identity::generate_scanner_token, identity::hash_scanner_token};
use actix_web::{HttpRequest, HttpResponse, Responder, delete, get, post, put, web};
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_postgres::types::ToSql;
use uuid::Uuid;

fn is_admin(user: &UserBaseI) -> bool {
    user.role == 1
}

fn log_database_error(req: &HttpRequest, event: &str, error: &(dyn std::error::Error + 'static)) {
    error_logs_error(req, event, "database_operation", error);
}

fn push_task_owner_scope<'a>(
    conditions: &mut Vec<String>,
    params: &mut Vec<&'a (dyn ToSql + Sync)>,
    user: &'a UserBaseI,
    column: &str,
) {
    if !is_admin(user) {
        params.push(&user.id);
        conditions.push(format!("{column} = ${}", params.len()));
    }
}

async fn audit(
    transaction: &deadpool_postgres::Transaction<'_>,
    req: &HttpRequest,
    user: &UserBaseI,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    detail: Value,
) -> Result<(), tokio_postgres::Error> {
    let mut event =
        AuditEvent::user("task", action, "success", user).resource(resource_type, resource_id);
    if resource_type == "scanner" {
        event.category = "scanner".to_owned();
    }
    event.changes = Some(detail);
    event.response_status = Some(200);
    write_audit(transaction, &AuditContext::from_request(req), &event).await
}

#[post("/api/task/{task_id}/cancel")]
pub(crate) async fn cancel_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    task_id: web::Path<Uuid>,
    user: UserBaseI,
) -> impl Responder {
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            log_database_error(&req, "CancelTaskDatabaseError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error) => {
            log_database_error(&req, "CancelTaskDatabaseError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let id = task_id.into_inner().to_string();
    let mut conditions = vec!["task_id = $1".to_owned()];
    let mut params: Vec<&(dyn ToSql + Sync)> = vec![&id];
    push_task_owner_scope(&mut conditions, &mut params, &user, "user_id");
    let sql = format!(
        "SELECT id, task_status FROM scan_task WHERE {} FOR UPDATE;",
        conditions.join(" AND ")
    );
    let row = match transaction.query_opt(&sql, &params).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(json!({"success": false, "message": "task not found"}));
        }
        Err(error) => {
            log_database_error(&req, "CancelTaskDatabaseError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let task_pk: i32 = row.get("id");
    let status: String = row.get("task_status");
    match status.as_str() {
        "pending" | "running" => {}
        _ => {
            return HttpResponse::Conflict()
                .json(json!({"success": false, "message": "task is already finished"}));
        }
    }
    let now = crate::clock::get_unix_epoch_ms();
    if let Err(error) = transaction.execute(
        "UPDATE scan_task_execution SET execution_status = CASE WHEN execution_status = 'pending' THEN 'cancelled' ELSE execution_status END, \
         cancel_requested = (execution_status = 'running'), task_end_time = CASE WHEN execution_status = 'pending' THEN $1::BIGINT ELSE task_end_time END, \
         lease_expires_at = CASE WHEN execution_status = 'pending' THEN NULL ELSE lease_expires_at END \
         WHERE task_id = $2 AND execution_status IN ('pending', 'running');", &[&now, &task_pk]).await {
        log_database_error(&req, "CancelTaskDatabaseError", &error);
        return HttpResponse::InternalServerError().finish();
    }
    if let Err(error) =
        crate::scan_control::dispatch::refresh_task_aggregate(&transaction, task_pk).await
    {
        log_database_error(&req, "CancelTaskDatabaseError", &error);
        return HttpResponse::InternalServerError().finish();
    }
    let aggregate = match transaction
        .query_one(
            "SELECT task_status, cancel_requested FROM scan_task WHERE id = $1;",
            &[&task_pk],
        )
        .await
    {
        Ok(row) => row,
        Err(error) => {
            log_database_error(&req, "CancelTaskDatabaseError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let aggregate_status: String = aggregate.get("task_status");
    let cancel_requested: bool = aggregate.get("cancel_requested");
    if let Err(error) = audit(
        &transaction,
        &req,
        &user,
        "task.cancel",
        "task",
        &id,
        json!({"previous_status": status}),
    )
    .await
    {
        log_database_error(&req, "CancelTaskAuditError", &error);
        return HttpResponse::InternalServerError().finish();
    }
    if let Err(error) = transaction.commit().await {
        log_database_error(&req, "CancelTaskDatabaseError", &error);
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().json(
        json!({"success": true, "status": aggregate_status, "cancel_requested": cancel_requested}),
    )
}

#[post("/api/task/{task_id}/retry")]
pub(crate) async fn retry_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    task_id: web::Path<Uuid>,
    user: UserBaseI,
) -> impl Responder {
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            log_database_error(&req, "RetryTaskDatabaseError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error) => {
            log_database_error(&req, "RetryTaskDatabaseError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let source_id = task_id.into_inner().to_string();
    let mut conditions = vec!["task_id = $1".to_owned()];
    let mut params: Vec<&(dyn ToSql + Sync)> = vec![&source_id];
    push_task_owner_scope(&mut conditions, &mut params, &user, "user_id");
    let sql = format!(
        "SELECT id, user_id, task_target, dns_targets, dns_resolvers, task_kind, task_port, task_level, remarks, task_status, \
                dispatch_mode, address_family, scan_profile, scan_plan FROM scan_task \
         WHERE {} FOR UPDATE;",
        conditions.join(" AND ")
    );
    let source = match transaction.query_opt(&sql, &params).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(json!({"success": false, "message": "task not found"}));
        }
        Err(error) => {
            log_database_error(&req, "RetryTaskDatabaseError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let status: String = source.get("task_status");
    if !matches!(
        status.as_str(),
        "failed" | "cancelled" | "succeeded" | "partial"
    ) {
        return HttpResponse::Conflict()
            .json(json!({"success": false, "message": "only finished tasks can be retried"}));
    }
    let new_id = Uuid::now_v7().to_string();
    let owner_id: i32 = source.get("user_id");
    let targets: Vec<cidr::IpInet> = source.get("task_target");
    let dns_targets: Vec<String> = source.get("dns_targets");
    let dns_resolvers: serde_json::Value = source.get("dns_resolvers");
    let task_kind: String = source.get("task_kind");
    let port: String = source.get("task_port");
    let level: i32 = source.get("task_level");
    let remarks: Option<String> = source.get("remarks");
    let dispatch_mode: String = source.get("dispatch_mode");
    let source_pk: i32 = source.get("id");
    let address_family: String = source.get("address_family");
    let scan_profile: String = source.get("scan_profile");
    let scan_plan: serde_json::Value = source.get("scan_plan");
    let new_task_pk: i32 = match transaction.query_one(
        "INSERT INTO scan_task (user_id, task_id, task_initiator, task_target, dns_targets, dns_resolvers, task_kind, task_port, task_level, remarks, retry_of_task_id, dispatch_mode, address_family, scan_profile, scan_plan) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) RETURNING id;",
        &[&owner_id, &new_id, &user.username, &targets, &dns_targets, &dns_resolvers, &task_kind, &port, &level, &remarks, &source_id, &dispatch_mode, &address_family, &scan_profile, &scan_plan]).await {
        Ok(row) => row.get("id"),
        Err(error) => { log_database_error(&req, "RetryTaskDatabaseError", &error); return HttpResponse::InternalServerError().finish(); }
    };
    let source_executions = match transaction
        .query(
            "SELECT requested_scanner_id FROM scan_task_execution WHERE task_id = $1 \
             AND execution_status <> 'superseded' ORDER BY id;",
            &[&source_pk],
        )
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            log_database_error(&req, "RetryTaskDatabaseError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    for execution in source_executions {
        let execution_id = Uuid::now_v7().to_string();
        let requested_scanner_id: Option<String> = execution.get("requested_scanner_id");
        if let Err(error) = transaction
            .execute(
                "INSERT INTO scan_task_execution (execution_id, task_id, requested_scanner_id) VALUES ($1, $2, $3);",
                &[&execution_id, &new_task_pk, &requested_scanner_id],
            )
            .await
        {
            log_database_error(&req, "RetryTaskDatabaseError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    }
    if let Err(error) = audit(
        &transaction,
        &req,
        &user,
        "task.retry",
        "task",
        &new_id,
        json!({"source_task_id": source_id}),
    )
    .await
    {
        log_database_error(&req, "RetryTaskAuditError", &error);
        return HttpResponse::InternalServerError().finish();
    }
    if let Err(error) = transaction.commit().await {
        log_database_error(&req, "RetryTaskDatabaseError", &error);
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().json(json!({"success": true, "data": {"task_id": new_id}}))
}

#[derive(Deserialize)]
pub(crate) struct ExportQuery {
    format: Option<String>,
}

fn csv_cell(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

#[get("/api/task/{task_id}/export")]
pub(crate) async fn export_task(
    req: HttpRequest,
    elasticsearch: web::Data<ElasticsearchService>,
    task_id: web::Path<Uuid>,
    query: web::Query<ExportQuery>,
    user: UserBaseI,
) -> impl Responder {
    let id = task_id.into_inner().to_string();

    return export_task_from_elasticsearch(
        &req,
        elasticsearch.get_ref(),
        &id,
        query.format.as_deref(),
        &user,
    )
    .await;
}

async fn export_task_from_elasticsearch(
    req: &HttpRequest,
    elasticsearch: &ElasticsearchService,
    task_id: &str,
    format: Option<&str>,
    user: &UserBaseI,
) -> HttpResponse {
    let mut filters = vec![json!({"term": {"task_id": task_id}})];
    if user.role != 1 {
        filters.push(json!({"term": {"user_id": user.id}}));
    }
    let mut search_after = None;
    let mut rows = Vec::new();
    loop {
        let mut body = json!({
            "size": 1000,
            "query": {"bool": {"filter": filters}},
            "sort": [{"execution_id": "asc"}, {"ip": "asc"}, {"port": "asc"}]
        });
        if let Some(value) = search_after.take() {
            body.as_object_mut()
                .expect("query body is object")
                .insert("search_after".to_owned(), value);
        }
        let result = match elasticsearch
            .scan_query(ScanQueryIndex::ExecutionEndpoints, &body)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                error_logs(req, "ExportTaskElasticsearchError", &error);
                return HttpResponse::ServiceUnavailable()
                    .json(json!({"message": "扫描结果索引暂时不可用"}));
            }
        };
        let hits = result
            .pointer("/hits/hits")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for hit in &hits {
            if let Some(source) = hit.get("_source") {
                rows.push(json!({
                    "execution_id": source.get("execution_id"),
                    "scanner_id": source.get("scanner_id"),
                    "scanner_name": source.get("scanner_name"),
                    "ip": source.get("ip"), "asn": source.get("asn"),
                    "isp": source.get("isp"), "port": source.get("port"),
                    "as_org": source.get("as_org"), "country_code": source.get("country_code"),
                    "country_name": source.get("country_name"), "city_name": source.get("city_name"),
                    "protocol": source.get("protocol"), "service": source.get("service"),
                    "banner": source.get("banner"), "scan_time": source.get("observed_at_ms")
                }));
            }
        }
        search_after = hits.last().and_then(|hit| hit.get("sort")).cloned();
        if hits.len() < 1000 || search_after.is_none() {
            break;
        }
    }
    if format == Some("json") {
        return HttpResponse::Ok().json(json!({"task_id": task_id, "results": rows}));
    }
    let mut csv = String::from(
        "execution_id,scanner_id,scanner_name,ip,asn,as_org,isp,country_code,country_name,city_name,port,protocol,service,banner,scan_time\n",
    );
    let fields = [
        "execution_id",
        "scanner_id",
        "scanner_name",
        "ip",
        "asn",
        "as_org",
        "isp",
        "country_code",
        "country_name",
        "city_name",
        "port",
        "protocol",
        "service",
        "banner",
        "scan_time",
    ];
    for row in rows {
        let values = fields.map(|field| {
            row.get(field)
                .and_then(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .or_else(|| value.as_i64().map(|number| number.to_string()))
                })
                .unwrap_or_default()
        });
        csv.push_str(
            &values
                .iter()
                .map(|value| csv_cell(value))
                .collect::<Vec<_>>()
                .join(","),
        );
        csv.push('\n');
    }
    HttpResponse::Ok()
        .insert_header((
            "Content-Disposition",
            format!("attachment; filename=task-{task_id}.csv"),
        ))
        .content_type("text/csv; charset=utf-8")
        .body(csv)
}

#[get("/api/dashboard/overview")]
pub(crate) async fn dashboard_overview(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
) -> impl Responder {
    let connection = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            log_database_error(&req, "DashboardDatabaseError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let mut summary_conditions = Vec::new();
    let mut summary_params: Vec<&(dyn ToSql + Sync)> = Vec::new();
    push_task_owner_scope(
        &mut summary_conditions,
        &mut summary_params,
        &user,
        "user_id",
    );
    let summary_filter = if summary_conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", summary_conditions.join(" AND "))
    };
    let summary_sql = format!(
        "SELECT COUNT(*) FILTER (WHERE task_status = 'pending')::BIGINT AS pending, \
         COUNT(*) FILTER (WHERE task_status = 'running')::BIGINT AS running, \
         COUNT(*) FILTER (WHERE task_status = 'succeeded')::BIGINT AS succeeded, \
         COUNT(*) FILTER (WHERE task_status = 'failed')::BIGINT AS failed, \
         COUNT(*) FILTER (WHERE task_status = 'cancelled')::BIGINT AS cancelled, \
         COALESCE(AVG(task_end_time - task_start_time) FILTER (WHERE task_status = 'succeeded'), 0)::BIGINT AS avg_duration_ms \
         FROM scan_task{summary_filter};"
    );
    let summary = match connection.query_one(&summary_sql, &summary_params).await {
        Ok(row) => row,
        Err(error) => {
            log_database_error(&req, "DashboardDatabaseError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let online_sql = format!(
        "SELECT COUNT(*)::BIGINT AS count FROM scanner_info WHERE deleted_at IS NULL AND is_enable = true \
         AND runtime_state <> 'stopping' AND last_seen_at >= NOW() - ({}) * INTERVAL '1 second';",
        crate::scanner_health::seconds_sql()
    );
    let online: i64 = match connection.query_one(&online_sql, &[]).await {
        Ok(row) => row.get("count"),
        Err(error) => {
            log_database_error(&req, "DashboardDatabaseError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let mut trend_conditions = vec![
        "(to_timestamp(t.task_create_time / 1000.0) AT TIME ZONE $1)::date = days.day::date"
            .to_owned(),
    ];
    let timezone = crate::system_time::snapshot().document.timezone;
    let mut trend_params: Vec<&(dyn ToSql + Sync)> = vec![&timezone];
    push_task_owner_scope(&mut trend_conditions, &mut trend_params, &user, "t.user_id");
    let trend_sql = format!(
        "SELECT to_char(days.day, 'YYYY-MM-DD') AS day, COALESCE(s.name, t.assigned_scanner_id, '未分配') AS scanner, COUNT(t.id)::BIGINT AS count \
         FROM generate_series((NOW() AT TIME ZONE $1)::DATE - INTERVAL '6 days', (NOW() AT TIME ZONE $1)::DATE::TIMESTAMP, INTERVAL '1 day') days(day) \
         LEFT JOIN scan_task t ON {} \
         LEFT JOIN scanner_info s ON s.scanner_id = t.assigned_scanner_id GROUP BY days.day, scanner ORDER BY days.day, scanner;",
        trend_conditions.join(" AND ")
    );
    let trend_rows = match connection.query(&trend_sql, &trend_params).await {
        Ok(rows) => rows,
        Err(error) => {
            log_database_error(&req, "DashboardDatabaseError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let mut task_conditions = vec!["t.task_status IN ('pending', 'running')".to_owned()];
    let mut task_params: Vec<&(dyn ToSql + Sync)> = Vec::new();
    push_task_owner_scope(&mut task_conditions, &mut task_params, &user, "t.user_id");
    let task_sql = format!(
        "SELECT t.task_id, t.task_target::text[], t.task_initiator, t.task_status, t.remarks, COALESCE(s.name, t.assigned_scanner_id) AS scanner_name \
         FROM scan_task t LEFT JOIN scanner_info s ON s.scanner_id = t.assigned_scanner_id \
         WHERE {} ORDER BY t.task_level DESC, t.task_create_time LIMIT 10;",
        task_conditions.join(" AND ")
    );
    let task_rows = match connection.query(&task_sql, &task_params).await {
        Ok(rows) => rows,
        Err(error) => {
            log_database_error(&req, "DashboardDatabaseError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let trend: Vec<Value> = trend_rows.iter().map(|row| json!({"day": row.get::<_, String>("day"), "scanner": row.get::<_, String>("scanner"), "count": row.get::<_, i64>("count")})).collect();
    let tasks: Vec<Value> = task_rows.iter().map(|row| json!({
        "task_id": row.get::<_, String>("task_id"), "target": row.get::<_, Vec<String>>("task_target"),
        "initiator": row.get::<_, String>("task_initiator"), "status": row.get::<_, String>("task_status"),
        "remark": row.get::<_, Option<String>>("remarks"), "scanner": row.get::<_, Option<String>>("scanner_name")
    })).collect();
    HttpResponse::Ok().json(json!({"success": true, "data": {
        "online_scanners": online,
        "tasks": {"pending": summary.get::<_, i64>("pending"), "running": summary.get::<_, i64>("running"), "succeeded": summary.get::<_, i64>("succeeded"), "failed": summary.get::<_, i64>("failed"), "cancelled": summary.get::<_, i64>("cancelled")},
        "avg_duration_ms": summary.get::<_, i64>("avg_duration_ms"), "trend": trend, "current_tasks": tasks
    }}))
}

#[derive(Deserialize)]
pub(crate) struct ScannerUpdate {
    name: String,
    location: Option<String>,
    remark: Option<String>,
    tag: Option<String>,
}

#[put("/api/scanner/{scanner_id}")]
pub(crate) async fn update_scanner(
    req: HttpRequest,
    pool: web::Data<Pool>,
    scanner_id: web::Path<Uuid>,
    body: web::Json<ScannerUpdate>,
    user: UserBaseI,
) -> impl Responder {
    if !is_admin(&user) {
        return HttpResponse::Forbidden().finish();
    }
    let name = body.name.trim();
    if name.is_empty() || name.chars().count() > 50 {
        return HttpResponse::BadRequest()
            .json(json!({"success": false, "message": "name must contain 1-50 characters"}));
    }
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            log_database_error(&req, "UpdateScannerDatabaseError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error) => {
            log_database_error(&req, "UpdateScannerDatabaseError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let id = scanner_id.into_inner().to_string();
    let changed = transaction.execute("UPDATE scanner_info SET name = $1, location = $2, remark = $3, tag = $4, update_time = NOW() WHERE scanner_id = $5 AND deleted_at IS NULL;", &[&name, &body.location, &body.remark, &body.tag, &id]).await;
    match changed {
        Ok(1) => {}
        Ok(_) => return HttpResponse::NotFound().finish(),
        Err(error) => {
            log_database_error(&req, "UpdateScannerDatabaseError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    }
    if let Err(error) = audit(
        &transaction,
        &req,
        &user,
        "scanner.update",
        "scanner",
        &id,
        json!({"name": name}),
    )
    .await
    {
        log_database_error(&req, "UpdateScannerAuditError", &error);
        return HttpResponse::InternalServerError().finish();
    }
    if let Err(error) = transaction.commit().await {
        log_database_error(&req, "UpdateScannerCommitError", &error);
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().json(json!({"success": true}))
}

#[derive(Deserialize)]
pub(crate) struct ScannerEnabled {
    enabled: bool,
}

async fn release_scanner_tasks(
    transaction: &tokio_postgres::Transaction<'_>,
    scanner_id: &str,
    reason: &str,
) -> Result<u64, tokio_postgres::Error> {
    let rows = transaction.query(
        "UPDATE scan_task_execution SET execution_status = 'pending', assigned_scanner_id = NULL, lease_expires_at = NULL, \
         maintenance_hold = FALSE, maintenance_hold_until = NULL, task_start_time = NULL, \
         cancel_requested = false, failure_reason = $1 \
         WHERE assigned_scanner_id = $2 AND execution_status = 'running' RETURNING task_id;", &[&reason, &scanner_id]).await?;
    let task_ids: std::collections::HashSet<i32> =
        rows.iter().map(|row| row.get("task_id")).collect();
    for task_id in task_ids {
        crate::scan_control::dispatch::refresh_task_aggregate(transaction, task_id).await?;
    }
    Ok(rows.len() as u64)
}

#[post("/api/scanner/{scanner_id}/enabled")]
pub(crate) async fn set_scanner_enabled(
    req: HttpRequest,
    pool: web::Data<Pool>,
    scanner_id: web::Path<Uuid>,
    body: web::Json<ScannerEnabled>,
    user: UserBaseI,
) -> impl Responder {
    if !is_admin(&user) {
        return HttpResponse::Forbidden().finish();
    }
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            log_database_error(&req, "SetScannerEnabledError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error) => {
            log_database_error(&req, "SetScannerEnabledTransactionError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let id = scanner_id.into_inner().to_string();
    let changed = transaction.execute("UPDATE scanner_info SET is_enable = $1, runtime_state = CASE WHEN $1 THEN runtime_state ELSE 'offline' END, is_run = CASE WHEN $1 THEN is_run ELSE false END, outage_monitored_at = NULL, update_time = NOW() WHERE scanner_id = $2 AND deleted_at IS NULL;", &[&body.enabled, &id]).await;
    match changed {
        Ok(1) => {}
        Ok(_) => return HttpResponse::NotFound().finish(),
        Err(error) => {
            log_database_error(&req, "SetScannerEnabledError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    }
    if !body.enabled
        && let Err(error) = crate::scanner_outage::close_without_recovery(&transaction, &id).await
    {
        log_database_error(&req, "SetScannerEnabledOutageError", &error);
        return HttpResponse::InternalServerError().finish();
    }
    let released = if body.enabled {
        0
    } else {
        match release_scanner_tasks(&transaction, &id, "scanner disabled by administrator").await {
            Ok(count) => count,
            Err(error) => {
                log_database_error(&req, "SetScannerEnabledReleaseError", &error);
                return HttpResponse::InternalServerError().finish();
            }
        }
    };
    if let Err(error) = audit(
        &transaction,
        &req,
        &user,
        if body.enabled {
            "scanner.enable"
        } else {
            "scanner.disable"
        },
        "scanner",
        &id,
        json!({"released_tasks": released}),
    )
    .await
    {
        log_database_error(&req, "SetScannerEnabledAuditError", &error);
        return HttpResponse::InternalServerError().finish();
    }
    if let Err(error) = transaction.commit().await {
        log_database_error(&req, "SetScannerEnabledCommitError", &error);
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().json(json!({"success": true, "released_tasks": released}))
}

#[post("/api/scanner/{scanner_id}/reissue-token")]
pub(crate) async fn reissue_scanner_token(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    scanner_id: web::Path<Uuid>,
    user: UserBaseI,
) -> impl Responder {
    if !is_admin(&user) {
        return HttpResponse::Forbidden().finish();
    }
    let token = match generate_scanner_token("nm_reg") {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                &req,
                "ReissueScannerTokenGenerationError",
                "generate_scanner_token",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let token_hash = match hash_scanner_token(&token, &security.scanner_token_pepper) {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                &req,
                "ReissueScannerTokenHashError",
                "hash_scanner_token",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            log_database_error(&req, "ReissueScannerTokenError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error) => {
            log_database_error(&req, "ReissueScannerTokenTransactionError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let id = scanner_id.into_inner().to_string();
    let changed = transaction.execute(
        "UPDATE scanner_info SET registration_token_hash = $1, registration_token_expires_at = NOW() + INTERVAL '24 hours', registration_consumed_at = NULL, runtime_token_hash = NULL, is_enable = false, is_run = false, runtime_state = 'offline', outage_monitored_at = NULL, update_time = NOW() WHERE scanner_id = $2 AND deleted_at IS NULL;", &[&token_hash, &id]).await;
    match changed {
        Ok(1) => {}
        Ok(_) => return HttpResponse::NotFound().finish(),
        Err(error) => {
            log_database_error(&req, "ReissueScannerTokenError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    }
    if let Err(error) = crate::scanner_outage::close_without_recovery(&transaction, &id).await {
        log_database_error(&req, "ReissueScannerTokenOutageError", &error);
        return HttpResponse::InternalServerError().finish();
    }
    let released =
        match release_scanner_tasks(&transaction, &id, "scanner credentials revoked").await {
            Ok(value) => value,
            Err(error) => {
                log_database_error(&req, "ReissueScannerTokenReleaseError", &error);
                return HttpResponse::InternalServerError().finish();
            }
        };
    if let Err(error) = audit(
        &transaction,
        &req,
        &user,
        "scanner.token.reissue",
        "scanner",
        &id,
        json!({"released_tasks": released}),
    )
    .await
    {
        log_database_error(&req, "ReissueScannerTokenAuditError", &error);
        return HttpResponse::InternalServerError().finish();
    }
    if let Err(error) = transaction.commit().await {
        log_database_error(&req, "ReissueScannerTokenCommitError", &error);
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok()
        .json(json!({"success": true, "data": {"scanner_id": id, "registration_token": token}}))
}

#[delete("/api/scanner/{scanner_id}")]
pub(crate) async fn delete_scanner(
    req: HttpRequest,
    pool: web::Data<Pool>,
    scanner_id: web::Path<Uuid>,
    user: UserBaseI,
) -> impl Responder {
    if !is_admin(&user) {
        return HttpResponse::Forbidden().finish();
    }
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            log_database_error(&req, "DeleteScannerError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error) => {
            log_database_error(&req, "DeleteScannerTransactionError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let id = scanner_id.into_inner().to_string();
    let released =
        match release_scanner_tasks(&transaction, &id, "scanner deleted by administrator").await {
            Ok(value) => value,
            Err(error) => {
                log_database_error(&req, "DeleteScannerReleaseError", &error);
                return HttpResponse::InternalServerError().finish();
            }
        };
    let changed = transaction.execute("UPDATE scanner_info SET deleted_at = NOW(), is_enable = false, is_run = false, runtime_state = 'offline', outage_monitored_at = NULL, registration_token_hash = NULL, runtime_token_hash = NULL, update_time = NOW() WHERE scanner_id = $1 AND deleted_at IS NULL;", &[&id]).await;
    match changed {
        Ok(1) => {}
        Ok(_) => return HttpResponse::NotFound().finish(),
        Err(error) => {
            log_database_error(&req, "DeleteScannerError", &error);
            return HttpResponse::InternalServerError().finish();
        }
    }
    if let Err(error) = crate::scanner_outage::close_without_recovery(&transaction, &id).await {
        log_database_error(&req, "DeleteScannerOutageError", &error);
        return HttpResponse::InternalServerError().finish();
    }
    if let Err(error) = audit(
        &transaction,
        &req,
        &user,
        "scanner.delete",
        "scanner",
        &id,
        json!({"released_tasks": released}),
    )
    .await
    {
        log_database_error(&req, "DeleteScannerAuditError", &error);
        return HttpResponse::InternalServerError().finish();
    }
    if let Err(error) = transaction.commit().await {
        log_database_error(&req, "DeleteScannerCommitError", &error);
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().json(json!({"success": true}))
}

#[cfg(test)]
mod tests {
    use tokio_postgres::types::ToSql;

    use super::{UserBaseI, csv_cell, push_task_owner_scope};

    fn user(role: i32) -> UserBaseI {
        UserBaseI {
            id: 7,
            username: "operator".to_owned(),
            role,
            email: None,
            limit_login: false,
            enable_2fa: false,
        }
    }

    #[test]
    fn csv_cell_escapes_quotes_and_commas() {
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hello\""), "\"say \"\"hello\"\"\"");
    }

    #[test]
    fn administrator_scope_adds_no_predicate() {
        let user = user(1);
        let mut conditions = vec!["task_id = $1".to_owned()];
        let task_id = "task-a".to_owned();
        let mut params: Vec<&(dyn ToSql + Sync)> = vec![&task_id];

        push_task_owner_scope(&mut conditions, &mut params, &user, "t.user_id");

        assert_eq!(conditions, ["task_id = $1"]);
        assert_eq!(params.len(), 1);
    }

    #[test]
    fn user_scope_adds_direct_owner_predicate() {
        let user = user(2);
        let mut conditions = vec!["task_id = $1".to_owned()];
        let task_id = "task-a".to_owned();
        let mut params: Vec<&(dyn ToSql + Sync)> = vec![&task_id];

        push_task_owner_scope(&mut conditions, &mut params, &user, "t.user_id");

        assert_eq!(conditions[1], "t.user_id = $2");
        assert_eq!(params.len(), 2);
        assert!(conditions.iter().all(|condition| !condition.contains("OR")));
    }
}
