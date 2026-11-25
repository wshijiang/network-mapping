use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_postgres::types::ToSql;
use uuid::Uuid;

use crate::access::{Access, Permission};
use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write_standalone};
use crate::client_ip::display_ip;
use crate::logs::write::error_logs_error;

#[derive(Deserialize)]
pub struct AuditQuery {
    category: Option<String>,
    action: Option<String>,
    outcome: Option<String>,
    actor_id: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    keyword: Option<String>,
    request_id: Option<Uuid>,
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
    page: Option<i64>,
    page_size: Option<i64>,
}

#[derive(Serialize)]
struct AuditEventResponse {
    event_id: Uuid,
    occurred_at: DateTime<Utc>,
    category: String,
    action: String,
    outcome: String,
    severity: String,
    actor_type: String,
    actor_id: Option<String>,
    actor_name: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    request_id: Option<Uuid>,
    source_ip: Option<String>,
    user_agent: Option<String>,
    http_method: Option<String>,
    request_path: Option<String>,
    response_status: Option<i16>,
    reason_code: Option<String>,
    changes: Option<Value>,
    metadata: Value,
}

fn event_from_row(row: tokio_postgres::Row, scoped: bool) -> AuditEventResponse {
    let mut event = AuditEventResponse {
        event_id: row.get("event_id"),
        occurred_at: row.get("occurred_at"),
        category: row.get("category"),
        action: row.get("action"),
        outcome: row.get("outcome"),
        severity: row.get("severity"),
        actor_type: row.get("actor_type"),
        actor_id: row.get("actor_id"),
        actor_name: row.get("actor_name"),
        resource_type: row.get("resource_type"),
        resource_id: row.get("resource_id"),
        request_id: row.get("request_id"),
        source_ip: display_ip(row.get("source_ip")),
        user_agent: row.get("user_agent"),
        http_method: row.get("http_method"),
        request_path: row.get("request_path"),
        response_status: row.get("response_status"),
        reason_code: row.get("reason_code"),
        changes: row.get("changes"),
        metadata: row.get("metadata"),
    };
    if scoped {
        event.source_ip = None;
        event.user_agent = None;
        event.request_path = None;
        event.metadata = json!({});
        event.changes = match event.action.as_str() {
            "user.access_update" | "cli.user.access_update" => event.changes.map(|changes| json!({
                "before": {"role":changes["before"]["role"],"version":changes["before"]["version"],"permissions":changes["before"]["policy"]["permissions"]},
                "after": {"role":changes["after"]["role"],"version":changes["after"]["version"],"permissions":changes["after"]["policy"]["permissions"]},
            })),
            _ => None,
        };
    }
    event
}

fn audit_categories(
    req: &HttpRequest,
    user: &UserBaseI,
    permission: Permission,
) -> Result<Option<Vec<String>>, ()> {
    if user.role == crate::access::ADMIN {
        return Ok(None);
    }
    let access = Access::from_request(req)
        .filter(|access| access.allows(permission))
        .ok_or(())?;
    Ok(Some(access.policy.ok_or(())?.audit_categories))
}

fn audit_filter<'a>(
    query: &'a AuditQuery,
    categories: &'a Option<Vec<String>>,
) -> (String, Vec<&'a (dyn ToSql + Sync)>) {
    let mut conditions = Vec::new();
    let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
    macro_rules! push_filter {
        ($value:expr, $predicate:expr) => {
            if let Some(value) = $value.as_ref() {
                params.push(value);
                conditions.push(format!($predicate, params.len()));
            }
        };
    }
    push_filter!(categories, "category = ANY(${})");
    push_filter!(query.category, "category = ${}");
    push_filter!(query.action, "action = ${}");
    push_filter!(query.outcome, "outcome = ${}");
    push_filter!(query.actor_id, "actor_id = ${}");
    push_filter!(query.resource_type, "resource_type = ${}");
    push_filter!(query.resource_id, "resource_id = ${}");
    push_filter!(query.start, "occurred_at >= ${}");
    push_filter!(query.end, "occurred_at <= ${}");
    if let Some(value) = query.keyword.as_ref() {
        params.push(value);
        let index = params.len();
        conditions.push(format!(
            "(action ILIKE '%' || ${index} || '%' \
             OR COALESCE(actor_name, '') ILIKE '%' || ${index} || '%' \
             OR COALESCE(resource_id, '') ILIKE '%' || ${index} || '%')"
        ));
    }
    push_filter!(query.request_id, "request_id = ${}");
    let sql = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };
    (sql, params)
}

fn pagination(page: Option<i64>, page_size: Option<i64>) -> (i64, i64) {
    (
        page.unwrap_or(1).max(1),
        page_size.unwrap_or(25).clamp(1, 100),
    )
}

#[get("/api/audit/events")]
pub(crate) async fn list_audit_events(
    req: HttpRequest,
    pool: web::Data<Pool>,
    query: web::Query<AuditQuery>,
    user: UserBaseI,
) -> impl Responder {
    let Ok(categories) = audit_categories(&req, &user, Permission::ReadAudit) else {
        let mut event = AuditEvent::user("authorization", "audit.query", "denied", &user);
        event.response_status = Some(403);
        event.reason_code = Some("audit_read_required".to_owned());
        write_standalone(pool.get_ref(), &AuditContext::from_request(&req), &event).await;
        return HttpResponse::Forbidden().json(json!({"success": false, "message": "forbidden"}));
    };

    let (page, page_size) = pagination(query.page, query.page_size);
    let offset = (page - 1) * page_size;
    let client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            error_logs_error(
                &req,
                "AuditQueryPoolError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let (filter_sql, filter_params) = audit_filter(&query, &categories);
    let count_sql = format!("SELECT COUNT(*) FROM audit_event{filter_sql}");
    let total: i64 = match client.query_one(&count_sql, &filter_params).await {
        Ok(row) => row.get(0),
        Err(error_value) => {
            error_logs_error(&req, "AuditQueryError", "database_operation", &error_value);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let list_sql = format!(
        "SELECT event_id, occurred_at, category, action, outcome, severity, actor_type, actor_id, \
         actor_name, resource_type, resource_id, request_id, source_ip, user_agent, \
         http_method, request_path, response_status, reason_code, changes, metadata \
         FROM audit_event{filter_sql} ORDER BY occurred_at DESC, id DESC \
         LIMIT ${} OFFSET ${}",
        filter_params.len() + 1,
        filter_params.len() + 2,
    );
    let mut params = filter_params;
    params.push(&page_size);
    params.push(&offset);
    let rows = match client.query(&list_sql, &params).await {
        Ok(rows) => rows,
        Err(error_value) => {
            error_logs_error(&req, "AuditQueryError", "database_operation", &error_value);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let items: Vec<AuditEventResponse> = rows
        .into_iter()
        .map(|row| event_from_row(row, categories.is_some()))
        .collect();

    let mut event = AuditEvent::user("audit", "audit.query", "success", &user);
    event.response_status = Some(200);
    event.metadata = json!({"result_count": items.len()});
    if let Err(error_value) =
        crate::audit::write(&client, &AuditContext::from_request(&req), &event).await
    {
        error_logs_error(
            &req,
            "AuditQueryAuditError",
            "database_operation",
            &error_value,
        );
    }

    HttpResponse::Ok().json(json!({
        "success": true,
        "items": items,
        "pagination": {"page": page, "page_size": page_size, "total": total}
    }))
}

#[get("/api/audit/events/{event_id}")]
pub(crate) async fn get_audit_event(
    req: HttpRequest,
    pool: web::Data<Pool>,
    event_id: web::Path<Uuid>,
    user: UserBaseI,
) -> impl Responder {
    let Ok(categories) = audit_categories(&req, &user, Permission::ReadAudit) else {
        return HttpResponse::Forbidden().finish();
    };
    let client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            error_logs_error(
                &req,
                "AuditDetailPoolError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let row = match client
        .query_opt(
            "SELECT event_id, occurred_at, category, action, outcome, severity, actor_type, actor_id, \
             actor_name, resource_type, resource_id, request_id, source_ip, user_agent, \
             http_method, request_path, response_status, reason_code, changes, metadata \
             FROM audit_event WHERE event_id = $1 AND ($2::TEXT[] IS NULL OR category = ANY($2))",
            &[&event_id.into_inner(), &categories],
        )
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return HttpResponse::NotFound().finish(),
        Err(error_value) => {
            error_logs_error(&req, "AuditDetailError", "database_operation", &error_value);
            return HttpResponse::InternalServerError().finish();
        }
    };
    HttpResponse::Ok()
        .json(json!({"success": true, "data": event_from_row(row, categories.is_some())}))
}

fn csv_cell(value: &str) -> String {
    let prefix = if value.trim_start().starts_with(['=', '+', '-', '@']) {
        "'"
    } else {
        ""
    };
    format!(r#""{prefix}{}""#, value.replace('"', "\"\""))
}

const AUDIT_EXPORT_HEADER: &str = "event_id,occurred_at,category,action,outcome,severity,actor_type,actor_id,actor_name,resource_type,resource_id,request_id,source_ip,user_agent,http_method,request_path,response_status,reason_code,changes,metadata\n";

#[actix_web::route("/api/audit/export", method = "GET", method = "POST")]
pub(crate) async fn export_audit_events(
    req: HttpRequest,
    pool: web::Data<Pool>,
    query: web::Query<AuditQuery>,
    user: UserBaseI,
) -> impl Responder {
    let Ok(categories) = audit_categories(&req, &user, Permission::ExportAudit) else {
        return HttpResponse::Forbidden().finish();
    };
    if let Err(error) = crate::open_api::console::require_step_up(&req, &pool, &user).await {
        return crate::open_api::response(&req, Err(error));
    }
    let client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            error_logs_error(
                &req,
                "AuditExportPoolError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let (filter_sql, params) = audit_filter(&query, &categories);
    let sql = format!(
        "SELECT event_id, occurred_at, category, action, outcome, severity, actor_type, actor_id, \
         actor_name, resource_type, resource_id, request_id, source_ip, \
         user_agent, http_method, request_path, response_status, reason_code, changes, metadata \
         FROM audit_event{filter_sql} ORDER BY occurred_at DESC, id DESC LIMIT 10000"
    );
    let rows = match client.query(&sql, &params).await {
        Ok(rows) => rows,
        Err(error_value) => {
            error_logs_error(&req, "AuditExportError", "database_operation", &error_value);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let count = rows.len();
    let mut csv = String::from(AUDIT_EXPORT_HEADER);
    for row in rows {
        let event = event_from_row(row, categories.is_some());
        let values = [
            event.event_id.to_string(),
            event.occurred_at.to_rfc3339(),
            event.category,
            event.action,
            event.outcome,
            event.severity,
            event.actor_type,
            event.actor_id.unwrap_or_default(),
            event.actor_name.unwrap_or_default(),
            event.resource_type.unwrap_or_default(),
            event.resource_id.unwrap_or_default(),
            event.request_id.map(|v| v.to_string()).unwrap_or_default(),
            event.source_ip.unwrap_or_default(),
            event.user_agent.unwrap_or_default(),
            event.http_method.unwrap_or_default(),
            event.request_path.unwrap_or_default(),
            event
                .response_status
                .map(|v| v.to_string())
                .unwrap_or_default(),
            event.reason_code.unwrap_or_default(),
            event.changes.map(|v| v.to_string()).unwrap_or_default(),
            event.metadata.to_string(),
        ];
        csv.push_str(
            &values
                .iter()
                .map(|value| csv_cell(value))
                .collect::<Vec<_>>()
                .join(","),
        );
        csv.push('\n');
    }
    let mut event = AuditEvent::user("audit", "audit.export", "success", &user);
    event.response_status = Some(200);
    event.metadata = json!({"exported_count": count, "limit": 10000});
    if let Err(error_value) =
        crate::audit::write(&client, &AuditContext::from_request(&req), &event).await
    {
        error_logs_error(
            &req,
            "AuditExportAuditError",
            "database_operation",
            &error_value,
        );
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok()
        .insert_header(("Content-Type", "text/csv; charset=utf-8"))
        .insert_header((
            "Content-Disposition",
            "attachment; filename=network-mapping-audit.csv",
        ))
        .body(csv)
}

#[cfg(test)]
mod tests {
    use super::{AUDIT_EXPORT_HEADER, AuditQuery, audit_filter, csv_cell, pagination};
    use uuid::Uuid;

    fn query() -> AuditQuery {
        AuditQuery {
            category: None,
            action: None,
            outcome: None,
            actor_id: None,
            resource_type: None,
            resource_id: None,
            keyword: None,
            request_id: None,
            start: None,
            end: None,
            page: None,
            page_size: None,
        }
    }

    #[test]
    fn audit_filter_omits_absent_predicates() {
        let value = query();
        let (sql, params) = audit_filter(&value, &None);
        assert!(sql.is_empty());
        assert!(params.is_empty());
    }

    #[test]
    fn audit_filter_reuses_keyword_parameter_and_numbers_following_filter() {
        let mut value = query();
        value.category = Some("task".to_owned());
        value.keyword = Some("scanner".to_owned());
        value.request_id = Some(Uuid::nil());
        let (sql, params) = audit_filter(&value, &None);
        assert!(sql.contains("category = $1"));
        assert_eq!(sql.matches("$2").count(), 3);
        assert!(sql.contains("request_id = $3"));
        assert_eq!(params.len(), 3);
    }

    #[test]
    fn pagination_bounds_are_stable() {
        assert_eq!(pagination(Some(-1), Some(500)), (1, 100));
        assert_eq!(pagination(None, None), (1, 25));
    }

    #[test]
    fn csv_cells_escape_quotes() {
        assert_eq!(csv_cell("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn audit_export_contains_every_detail_field() {
        assert_eq!(
            AUDIT_EXPORT_HEADER
                .trim_end()
                .split(',')
                .collect::<Vec<_>>(),
            vec![
                "event_id",
                "occurred_at",
                "category",
                "action",
                "outcome",
                "severity",
                "actor_type",
                "actor_id",
                "actor_name",
                "resource_type",
                "resource_id",
                "request_id",
                "source_ip",
                "user_agent",
                "http_method",
                "request_path",
                "response_status",
                "reason_code",
                "changes",
                "metadata",
            ]
        );
    }
}
