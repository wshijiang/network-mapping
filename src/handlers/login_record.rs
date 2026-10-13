use std::net::IpAddr;

use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_postgres::types::ToSql;
use tracing::error;
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write as write_audit, write_standalone};
use crate::client_ip::display_ip;
use crate::clock::get_unix_epoch_ms;
use crate::logs::write::error_diagnostics;

const DEFAULT_PAGE_SIZE: u32 = 10;
const MAX_PAGE_SIZE: u32 = 50;

fn log_login_record_error(
    event: &'static str,
    operation: &'static str,
    error_value: &(dyn std::error::Error + 'static),
    actor_id: i32,
    target_user_id: i32,
    page: Option<u32>,
) {
    let diagnostics = error_diagnostics(error_value);
    error!(
        event,
        operation,
        error_kind = "database",
        error_code = %format!("{operation}_failed"),
        error_message = %diagnostics.error_message,
        error_chain = %diagnostics.error_chain,
        root_cause = %diagnostics.root_cause,
        error_truncated = diagnostics.error_truncated,
        retryable = false,
        outcome = "request_failed",
        actor_id,
        target_user_id,
        page = ?page,
    );
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRecordQuery {
    page: Option<u32>,
    page_size: Option<u32>,
    outcome: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginRecord {
    event_id: Uuid,
    occurred_at: DateTime<Utc>,
    outcome: String,
    source_ip: Option<String>,
    user_agent: Option<String>,
    reason_code: Option<String>,
    auth_method: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginRecordPagination {
    page: u32,
    page_size: u32,
    total: i64,
    total_pages: u32,
}

fn normalize_query(query: &LoginRecordQuery) -> Result<(u32, u32, Option<String>), &'static str> {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query
        .page_size
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE);
    let outcome = query.outcome.as_deref().filter(|value| !value.is_empty());
    if !matches!(outcome, None | Some("success" | "failure")) {
        return Err("登录结果筛选条件不正确");
    }
    Ok((page, page_size, outcome.map(str::to_owned)))
}

fn login_record_filter<'a>(
    actor_id: &'a String,
    target_username: &'a String,
    outcome: &'a Option<String>,
) -> (String, Vec<&'a (dyn ToSql + Sync)>) {
    let mut sql = "category = 'authentication' AND action = 'auth.login' \
        AND (actor_id = $1 OR (actor_id IS NULL AND \
             COALESCE(actor_name, metadata->>'attempted_username') = $2))"
        .to_owned();
    let mut params: Vec<&(dyn ToSql + Sync)> = vec![actor_id, target_username];
    if let Some(value) = outcome.as_ref() {
        params.push(value);
        sql.push_str(&format!(" AND outcome = ${}", params.len()));
    }
    (sql, params)
}

pub(crate) async fn record_completed_login(
    pool: &Pool,
    context: &AuditContext,
    user_id: i32,
    username: &str,
    auth_method: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    let occurred_at = get_unix_epoch_ms();
    let source_ip: Option<IpAddr> = context.source_ip;
    let updated = transaction
        .execute(
            "UPDATE users SET last_login_at = $2, last_login_ip = $3, login_error_count = 0, \
             last_error_at = NULL, update_at = NOW() WHERE id = $1 AND disabled_at IS NULL \
             AND deleted_at IS NULL;",
            &[&user_id, &occurred_at, &source_ip],
        )
        .await?;
    if updated != 1 {
        return Err("登录用户已不存在或不可用".into());
    }

    let mut event = AuditEvent::anonymous("authentication", "auth.login", "success")
        .resource("user", user_id.to_string());
    event.severity = "info".to_owned();
    event.actor_type = "user".to_owned();
    event.actor_id = Some(user_id.to_string());
    event.actor_name = Some(username.to_owned());
    event.response_status = Some(200);
    event.metadata = json!({"auth_method": auth_method});
    write_audit(&transaction, context, &event).await?;
    transaction.commit().await?;
    Ok(())
}

pub(crate) fn login_failure_event(
    user: Option<&UserBaseI>,
    attempted_username: &str,
    reason_code: &str,
    auth_method: &str,
) -> AuditEvent {
    let attempted_username = attempted_username.chars().take(200).collect::<String>();
    let mut event = match user {
        Some(value) => AuditEvent::user("authentication", "auth.login", "failure", value),
        None => AuditEvent::anonymous("authentication", "auth.login", "failure"),
    };
    event.response_status = Some(401);
    event.reason_code = Some(reason_code.to_owned());
    event.metadata = json!({
        "attempted_username": attempted_username,
        "auth_method": auth_method
    });
    event
}

async fn list_login_records(
    req: &HttpRequest,
    pool: &Pool,
    actor: &UserBaseI,
    target_id: i32,
    target_username: &str,
    query: &LoginRecordQuery,
) -> HttpResponse {
    let (page, page_size, outcome) = match normalize_query(query) {
        Ok(value) => value,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    let client = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            log_login_record_error(
                "LoginRecordPoolError",
                "acquire_login_record_connection",
                &error_value,
                actor.id,
                target_id,
                Some(page),
            );
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录记录服务暂时不可用"}));
        }
    };
    let actor_id = target_id.to_string();
    let target_username = target_username.to_owned();
    let (filter_sql, filter_params) = login_record_filter(&actor_id, &target_username, &outcome);
    let total = match client
        .query_one(
            &format!("SELECT COUNT(*) AS total FROM audit_event WHERE {filter_sql};"),
            &filter_params,
        )
        .await
    {
        Ok(row) => row.get::<_, i64>("total"),
        Err(error_value) => {
            log_login_record_error(
                "LoginRecordCountError",
                "count_login_records",
                &error_value,
                actor.id,
                target_id,
                Some(page),
            );
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录记录服务暂时不可用"}));
        }
    };
    let limit = i64::from(page_size);
    let offset = i64::from((page - 1) * page_size);
    let list_sql = format!(
        "SELECT event_id, occurred_at, outcome, source_ip, user_agent, \
         reason_code, COALESCE(metadata->>'auth_method', 'password') AS auth_method \
         FROM audit_event WHERE {filter_sql} ORDER BY occurred_at DESC, id DESC \
         LIMIT ${} OFFSET ${};",
        filter_params.len() + 1,
        filter_params.len() + 2,
    );
    let mut list_params = filter_params;
    list_params.push(&limit);
    list_params.push(&offset);
    let rows = match client.query(&list_sql, &list_params).await {
        Ok(value) => value,
        Err(error_value) => {
            log_login_record_error(
                "LoginRecordQueryError",
                "list_login_records",
                &error_value,
                actor.id,
                target_id,
                Some(page),
            );
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录记录服务暂时不可用"}));
        }
    };
    let records = rows
        .into_iter()
        .map(|row| LoginRecord {
            event_id: row.get("event_id"),
            occurred_at: row.get("occurred_at"),
            outcome: row.get("outcome"),
            source_ip: display_ip(row.get("source_ip")),
            user_agent: row.get("user_agent"),
            reason_code: row.get("reason_code"),
            auth_method: row.get("auth_method"),
        })
        .collect::<Vec<_>>();
    let total_pages = if total == 0 {
        1
    } else {
        (total as u64).div_ceil(u64::from(page_size)) as u32
    };

    let mut audit_event = AuditEvent::user("audit", "user.login_records.query", "success", actor)
        .resource("user", target_id.to_string());
    audit_event.response_status = Some(200);
    audit_event.metadata = json!({"result_count": records.len()});
    write_standalone(pool, &AuditContext::from_request(req), &audit_event).await;

    HttpResponse::Ok().json(json!({
        "success": true,
        "data": records,
        "pagination": LoginRecordPagination { page, page_size, total, total_pages }
    }))
}

#[get("/api/user/login-records")]
pub async fn self_login_records(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    query: web::Query<LoginRecordQuery>,
) -> impl Responder {
    list_login_records(&req, pool.get_ref(), &user, user.id, &user.username, &query).await
}

#[get("/api/admin/users/{user_id}/login-records")]
pub async fn admin_login_records(
    req: HttpRequest,
    path: web::Path<i32>,
    pool: web::Data<Pool>,
    user: UserBaseI,
    query: web::Query<LoginRecordQuery>,
) -> impl Responder {
    if user.role != 1 {
        return HttpResponse::Forbidden()
            .json(json!({"success": false, "message": "仅管理员可以查看用户登录记录"}));
    }
    let target_id = path.into_inner();
    let client = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            log_login_record_error(
                "AdminLoginRecordPoolError",
                "acquire_admin_login_record_connection",
                &error_value,
                user.id,
                target_id,
                None,
            );
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录记录服务暂时不可用"}));
        }
    };
    let target_username = match client
        .query_opt(
            "SELECT username FROM users WHERE id = $1 AND role IN (1, 2);",
            &[&target_id],
        )
        .await
    {
        Ok(Some(row)) => row.get::<_, String>("username"),
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(json!({"success": false, "message": "用户不存在"}));
        }
        Err(error_value) => {
            log_login_record_error(
                "AdminLoginRecordTargetError",
                "resolve_login_record_user",
                &error_value,
                user.id,
                target_id,
                None,
            );
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录记录服务暂时不可用"}));
        }
    };
    drop(client);
    list_login_records(
        &req,
        pool.get_ref(),
        &user,
        target_id,
        &target_username,
        &query,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::{LoginRecordQuery, login_record_filter, normalize_query};

    #[test]
    fn login_record_query_is_bounded_and_validated() {
        let bounded = normalize_query(&LoginRecordQuery {
            page: Some(0),
            page_size: Some(500),
            outcome: Some("success".to_owned()),
        })
        .unwrap();
        assert_eq!(bounded, (1, 50, Some("success".to_owned())));

        assert!(
            normalize_query(&LoginRecordQuery {
                page: None,
                page_size: None,
                outcome: Some("denied".to_owned()),
            })
            .is_err()
        );
    }

    #[test]
    fn login_record_filter_only_adds_outcome_when_present() {
        let actor_id = "42".to_owned();
        let username = "alice".to_owned();
        let (sql, params) = login_record_filter(&actor_id, &username, &None);
        assert!(!sql.contains("outcome"));
        assert_eq!(params.len(), 2);

        let outcome = Some("success".to_owned());
        let (sql, params) = login_record_filter(&actor_id, &username, &outcome);
        assert!(sql.contains("outcome = $3"));
        assert_eq!(params.len(), 3);
    }
}
