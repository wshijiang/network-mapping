use actix_web::{HttpRequest, HttpResponse, Responder, delete, get, patch, post, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use lettre::message::Mailbox;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_postgres::error::SqlState;
use tokio_postgres::types::ToSql;
use tracing::error;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write as write_audit};
use crate::client_ip::display_ip;
use crate::config::PasswordHashConfig;
use crate::identity::generate_hash_password;

const DEFAULT_PAGE_SIZE: u32 = 20;
const MAX_PAGE_SIZE: u32 = 100;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserListQuery {
    page: Option<u32>,
    page_size: Option<u32>,
    query: Option<String>,
    role: Option<i32>,
    status: Option<String>,
}

struct NormalizedUserListQuery {
    page: u32,
    page_size: u32,
    search: Option<String>,
    role: Option<i32>,
    status: String,
}

fn user_list_filter<'a>(
    search: &'a Option<String>,
    role: &'a Option<i32>,
    status: &str,
) -> (String, Vec<&'a (dyn ToSql + Sync)>) {
    let mut conditions = vec!["u.role IN (1, 2)".to_owned()];
    let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
    if let Some(value) = search.as_ref() {
        params.push(value);
        let index = params.len();
        conditions.push(format!(
            "(u.username ILIKE '%' || ${index} || '%' \
             OR COALESCE(u.email, '') ILIKE '%' || ${index} || '%')"
        ));
    }
    if let Some(value) = role.as_ref() {
        params.push(value);
        conditions.push(format!("u.role = ${}", params.len()));
    }
    conditions.push(
        match status {
            "deleted" => "u.deleted_at IS NOT NULL",
            "active" => "u.deleted_at IS NULL AND u.disabled_at IS NULL AND u.limit_login = FALSE",
            "disabled" => "u.deleted_at IS NULL AND u.disabled_at IS NOT NULL",
            "locked" => "u.deleted_at IS NULL AND u.disabled_at IS NULL AND u.limit_login = TRUE",
            _ => "u.deleted_at IS NULL",
        }
        .to_owned(),
    );
    (conditions.join(" AND "), params)
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    username: String,
    email: Option<String>,
    password: String,
    role: i32,
}

#[derive(Debug, Deserialize)]
pub struct UserEnabledRequest {
    enabled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ManagedUser {
    id: i32,
    username: String,
    email: Option<String>,
    role: i32,
    status: String,
    enable_2fa: bool,
    active_session_count: i64,
    create_time: i64,
    last_login_at: Option<i64>,
    last_login_ip: Option<String>,
    disabled_at: Option<DateTime<Utc>>,
    deleted_at: Option<DateTime<Utc>>,
    is_self: bool,
    login_ip_allowlist_count: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UserStats {
    total: i64,
    active: i64,
    disabled: i64,
    locked: i64,
    active_sessions: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Pagination {
    page: u32,
    page_size: u32,
    total: i64,
    total_pages: u32,
}

#[derive(Debug)]
enum ManagementError {
    BadRequest(&'static str),
    NotFound,
    Conflict(&'static str),
    Database(tokio_postgres::Error),
    Other(String),
}

impl From<tokio_postgres::Error> for ManagementError {
    fn from(value: tokio_postgres::Error) -> Self {
        Self::Database(value)
    }
}

// `HttpResponse` is returned directly by every caller, so boxing it adds an
// allocation without reducing the size of an externally-visible result.
#[allow(clippy::result_large_err)]
fn require_admin(user: &UserBaseI) -> Result<(), HttpResponse> {
    if user.role == 1 {
        Ok(())
    } else {
        Err(HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以管理用户"
        })))
    }
}

fn error_response(event: &'static str, value: ManagementError) -> HttpResponse {
    match value {
        ManagementError::BadRequest(message) => {
            HttpResponse::BadRequest().json(json!({"success": false, "message": message}))
        }
        ManagementError::NotFound => {
            HttpResponse::NotFound().json(json!({"success": false, "message": "用户不存在"}))
        }
        ManagementError::Conflict(message) => {
            HttpResponse::Conflict().json(json!({"success": false, "message": message}))
        }
        ManagementError::Database(error_value) => {
            let diagnostics = crate::logs::write::error_diagnostics(&error_value);
            error!(
                event,
                operation = "manage_user",
                error_kind = "database",
                error_code = event,
                error_message = %diagnostics.error_message,
                error_chain = %diagnostics.error_chain,
                root_cause = %diagnostics.root_cause,
                error_truncated = diagnostics.error_truncated,
                retryable = false,
                outcome = "request_failed",
            );
            HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "用户管理服务暂时不可用"}))
        }
        ManagementError::Other(message) => {
            error!(
                event,
                operation = "manage_user",
                error_kind = "application",
                error_code = event,
                error_message = message,
                retryable = false,
                outcome = "request_failed",
            );
            HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "用户管理服务暂时不可用"}))
        }
    }
}

fn normalize_list_query(query: &UserListQuery) -> Result<NormalizedUserListQuery, ManagementError> {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query
        .page_size
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE);
    let search = query
        .query
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(100).collect::<String>());
    if !matches!(query.role, None | Some(1 | 2)) {
        return Err(ManagementError::BadRequest("用户角色筛选条件不正确"));
    }
    let status = query.status.as_deref().unwrap_or("all").to_owned();
    if !matches!(
        status.as_str(),
        "all" | "active" | "disabled" | "locked" | "deleted"
    ) {
        return Err(ManagementError::BadRequest("用户状态筛选条件不正确"));
    }
    Ok(NormalizedUserListQuery {
        page,
        page_size,
        search,
        role: query.role,
        status,
    })
}

#[get("/api/admin/users")]
pub async fn list_users(
    pool: web::Data<Pool>,
    user: UserBaseI,
    query: web::Query<UserListQuery>,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    let normalized = match normalize_list_query(&query) {
        Ok(value) => value,
        Err(value) => return error_response("ListManagedUsersQueryError", value),
    };
    let NormalizedUserListQuery {
        page,
        page_size,
        search,
        role,
        status,
    } = normalized;
    let conn = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            return error_response(
                "ListManagedUsersPoolError",
                ManagementError::Other(error_value.to_string()),
            );
        }
    };
    let (filter_sql, filter_params) = user_list_filter(&search, &role, &status);
    let total_sql = format!("SELECT COUNT(*) AS total FROM users u WHERE {filter_sql};");
    let total = match conn.query_one(&total_sql, &filter_params).await {
        Ok(row) => row.get::<_, i64>("total"),
        Err(error_value) => {
            return error_response("ListManagedUsersCountError", error_value.into());
        }
    };
    let offset = i64::from((page - 1) * page_size);
    let limit = i64::from(page_size);
    let list_sql = format!(
        "SELECT u.id, u.username, u.email, u.role, u.enable_2fa, u.create_time, \
         u.last_login_at, u.last_login_ip, u.disabled_at, u.deleted_at, \
         cardinality(u.login_ip_allowlist) AS login_ip_allowlist_count, \
         CASE WHEN u.deleted_at IS NOT NULL THEN 'deleted' \
              WHEN u.disabled_at IS NOT NULL THEN 'disabled' \
              WHEN u.limit_login THEN 'locked' ELSE 'active' END AS status, \
         (SELECT COUNT(*) FROM session s WHERE s.user_id = u.id AND s.is_enable = TRUE \
          AND s.deleted_at IS NULL \
          AND s.create_time + s.ttl::BIGINT * 1000 > \
              (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT) AS active_session_count \
         FROM users u WHERE {filter_sql} ORDER BY u.id DESC LIMIT ${} OFFSET ${};",
        filter_params.len() + 1,
        filter_params.len() + 2,
    );
    let mut list_params = filter_params;
    list_params.push(&limit);
    list_params.push(&offset);
    let rows = match conn.query(&list_sql, &list_params).await {
        Ok(value) => value,
        Err(error_value) => return error_response("ListManagedUsersError", error_value.into()),
    };
    let users = rows
        .iter()
        .map(|row| ManagedUser {
            id: row.get("id"),
            username: row.get("username"),
            email: row.get("email"),
            role: row.get("role"),
            status: row.get("status"),
            enable_2fa: row.get("enable_2fa"),
            active_session_count: row.get("active_session_count"),
            create_time: row.get("create_time"),
            last_login_at: row.get("last_login_at"),
            last_login_ip: display_ip(row.get("last_login_ip")),
            disabled_at: row.get("disabled_at"),
            deleted_at: row.get("deleted_at"),
            is_self: row.get::<_, i32>("id") == user.id,
            login_ip_allowlist_count: row.get("login_ip_allowlist_count"),
        })
        .collect::<Vec<_>>();
    let stats = match conn
        .query_one(
            "SELECT COUNT(*) AS total, \
             COUNT(*) FILTER (WHERE disabled_at IS NULL AND limit_login = FALSE) AS active, \
             COUNT(*) FILTER (WHERE disabled_at IS NOT NULL) AS disabled, \
             COUNT(*) FILTER (WHERE disabled_at IS NULL AND limit_login = TRUE) AS locked, \
             (SELECT COUNT(*) FROM session s JOIN users su ON su.id = s.user_id \
              WHERE s.is_enable = TRUE AND s.deleted_at IS NULL \
              AND su.role IN (1, 2) AND su.deleted_at IS NULL \
              AND s.create_time + s.ttl::BIGINT * 1000 > \
                  (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT) AS active_sessions \
             FROM users WHERE role IN (1, 2) AND deleted_at IS NULL;",
            &[],
        )
        .await
    {
        Ok(row) => UserStats {
            total: row.get("total"),
            active: row.get("active"),
            disabled: row.get("disabled"),
            locked: row.get("locked"),
            active_sessions: row.get("active_sessions"),
        },
        Err(error_value) => return error_response("ManagedUserStatsError", error_value.into()),
    };
    let total_pages = if total == 0 {
        1
    } else {
        (total as u64).div_ceil(u64::from(page_size)) as u32
    };
    HttpResponse::Ok().json(json!({
        "success": true,
        "data": users,
        "stats": stats,
        "pagination": Pagination { page, page_size, total, total_pages }
    }))
}

fn validate_create_request(
    request: &CreateUserRequest,
) -> Result<(String, Option<String>), ManagementError> {
    let username = request.username.trim();
    let username_length = username.chars().count();
    if !(3..=64).contains(&username_length)
        || !username
            .chars()
            .all(|value| value.is_alphanumeric() || matches!(value, '_' | '-' | '.'))
    {
        return Err(ManagementError::BadRequest(
            "用户名需为 3-64 个字母、数字、下划线、连字符或点",
        ));
    }
    let password_length = request.password.chars().count();
    if !(12..=256).contains(&password_length) {
        return Err(ManagementError::BadRequest("密码长度必须为 12-256 个字符"));
    }
    if !matches!(request.role, 1 | 2) {
        return Err(ManagementError::BadRequest("用户角色不正确"));
    }
    let email = request
        .email
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if email
        .as_deref()
        .is_some_and(|value| value.len() > 320 || value.parse::<Mailbox>().is_err())
    {
        return Err(ManagementError::BadRequest("邮箱格式不正确"));
    }
    Ok((username.to_owned(), email))
}

#[post("/api/admin/users")]
pub async fn create_user(
    req: HttpRequest,
    pool: web::Data<Pool>,
    password_config: web::Data<PasswordHashConfig>,
    user: UserBaseI,
    body: web::Json<CreateUserRequest>,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    let (username, email) = match validate_create_request(&body) {
        Ok(value) => value,
        Err(value) => return error_response("CreateManagedUserValidationError", value),
    };
    let password_hash =
        match generate_hash_password(&body.password, password_config.get_ref().clone()) {
            Ok(value) => value,
            Err(error_value) => {
                return error_response(
                    "CreateManagedUserPasswordHashError",
                    ManagementError::Other(error_value.to_string()),
                );
            }
        };
    let mut conn = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            return error_response(
                "CreateManagedUserPoolError",
                ManagementError::Other(error_value.to_string()),
            );
        }
    };
    let transaction = match conn.transaction().await {
        Ok(value) => value,
        Err(error_value) => return error_response("CreateManagedUserTxError", error_value.into()),
    };
    let inserted = transaction
        .query_one(
            "INSERT INTO users (username, password, role, email, limit_login, login_error_count) \
             VALUES ($1, $2, $3, $4, FALSE, 0) RETURNING id;",
            &[&username, &password_hash, &body.role, &email],
        )
        .await;
    let user_id = match inserted {
        Ok(row) => row.get::<_, i32>("id"),
        Err(error_value) if error_value.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
            return error_response(
                "CreateManagedUserConflict",
                ManagementError::Conflict("用户名已存在，已删除用户名也不能重复使用"),
            );
        }
        Err(error_value) => return error_response("CreateManagedUserError", error_value.into()),
    };
    let mut event = AuditEvent::user("user_security", "user.create", "success", &user)
        .resource("user", user_id.to_string());
    event.response_status = Some(201);
    event.changes = Some(json!({"username": username, "email": email, "role": body.role}));
    if let Err(error_value) =
        write_audit(&transaction, &AuditContext::from_request(&req), &event).await
    {
        return error_response("CreateManagedUserAuditError", error_value.into());
    }
    if let Err(error_value) = transaction.commit().await {
        return error_response("CreateManagedUserCommitError", error_value.into());
    }
    HttpResponse::Created().json(json!({
        "success": true,
        "message": "用户已创建",
        "data": {"id": user_id}
    }))
}

#[derive(Debug)]
struct TargetUser {
    id: i32,
    username: String,
    role: i32,
    disabled: bool,
    login_locked: bool,
}

async fn lock_target_user(
    transaction: &tokio_postgres::Transaction<'_>,
    user_id: i32,
) -> Result<TargetUser, ManagementError> {
    let row = transaction
        .query_opt(
            "SELECT id, username, role, disabled_at IS NOT NULL AS disabled, \
                    limit_login AS login_locked FROM users \
             WHERE id = $1 AND role IN (1, 2) AND deleted_at IS NULL FOR UPDATE;",
            &[&user_id],
        )
        .await?
        .ok_or(ManagementError::NotFound)?;
    Ok(TargetUser {
        id: row.get("id"),
        username: row.get("username"),
        role: row.get("role"),
        disabled: row.get("disabled"),
        login_locked: row.get("login_locked"),
    })
}

async fn protect_last_admin(
    transaction: &tokio_postgres::Transaction<'_>,
    target: &TargetUser,
) -> Result<(), ManagementError> {
    if target.role != 1 || target.disabled || target.login_locked {
        return Ok(());
    }
    transaction
        .query(
            "SELECT id FROM users WHERE role = 1 AND deleted_at IS NULL FOR UPDATE;",
            &[],
        )
        .await?;
    let active_admins = transaction
        .query_one(
            "SELECT COUNT(*) AS count FROM users WHERE role = 1 AND deleted_at IS NULL \
             AND disabled_at IS NULL AND limit_login = FALSE;",
            &[],
        )
        .await?
        .get::<_, i64>("count");
    if active_admins <= 1 {
        Err(ManagementError::Conflict(
            "不能禁用或删除最后一个有效管理员",
        ))
    } else {
        Ok(())
    }
}

async fn invalidate_target_sessions(
    transaction: &tokio_postgres::Transaction<'_>,
    user_id: i32,
    reason: &str,
    deleted_by_user_id: i32,
) -> Result<u64, ManagementError> {
    Ok(transaction
        .execute(
            "UPDATE session SET is_enable = FALSE, deleted_at = NOW(), \
             deletion_reason = $2, deleted_by_user_id = $3 \
             WHERE user_id = $1 AND is_enable = TRUE AND deleted_at IS NULL;",
            &[&user_id, &reason, &deleted_by_user_id],
        )
        .await?)
}

#[patch("/api/admin/users/{user_id}/status")]
pub async fn set_user_enabled(
    req: HttpRequest,
    path: web::Path<i32>,
    body: web::Json<UserEnabledRequest>,
    pool: web::Data<Pool>,
    user: UserBaseI,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    let target_id = path.into_inner();
    if target_id == user.id {
        return error_response(
            "SetManagedUserStatusSelf",
            ManagementError::Conflict("不能禁用当前登录账号"),
        );
    }
    let mut conn = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            return error_response(
                "SetManagedUserStatusPoolError",
                ManagementError::Other(error_value.to_string()),
            );
        }
    };
    let transaction = match conn.transaction().await {
        Ok(value) => value,
        Err(error_value) => {
            return error_response("SetManagedUserStatusTxError", error_value.into());
        }
    };
    let target = match lock_target_user(&transaction, target_id).await {
        Ok(value) => value,
        Err(value) => return error_response("SetManagedUserStatusTargetError", value),
    };
    if !body.enabled
        && let Err(value) = protect_last_admin(&transaction, &target).await
    {
        return error_response("SetManagedUserStatusLastAdmin", value);
    }
    let changed = if body.enabled {
        transaction
            .execute(
                "UPDATE users SET disabled_at = NULL, update_at = NOW() WHERE id = $1;",
                &[&target.id],
            )
            .await
    } else {
        transaction.execute(
            "UPDATE users SET disabled_at = COALESCE(disabled_at, NOW()), update_at = NOW() WHERE id = $1;",
            &[&target.id],
        ).await
    };
    if let Err(error_value) = changed {
        return error_response("SetManagedUserStatusError", error_value.into());
    }
    let invalidated_session_count = if body.enabled {
        0
    } else {
        match invalidate_target_sessions(&transaction, target.id, "user_disabled", user.id).await {
            Ok(value) => value,
            Err(value) => return error_response("SetManagedUserStatusSessionError", value),
        }
    };
    let action = if body.enabled {
        "user.enable"
    } else {
        "user.disable"
    };
    let mut event = AuditEvent::user("user_security", action, "success", &user)
        .resource("user", target.id.to_string());
    event.response_status = Some(200);
    event.changes = Some(json!({
        "username": target.username,
        "enabled": body.enabled,
        "invalidated_session_count": invalidated_session_count
    }));
    if let Err(error_value) =
        write_audit(&transaction, &AuditContext::from_request(&req), &event).await
    {
        return error_response("SetManagedUserStatusAuditError", error_value.into());
    }
    if let Err(error_value) = transaction.commit().await {
        return error_response("SetManagedUserStatusCommitError", error_value.into());
    }
    HttpResponse::Ok().json(json!({
        "success": true,
        "message": if body.enabled { "用户已启用" } else { "用户已禁用" },
        "data": {"invalidatedSessionCount": invalidated_session_count}
    }))
}

#[post("/api/admin/users/{user_id}/kick")]
pub async fn kick_user(
    req: HttpRequest,
    path: web::Path<i32>,
    pool: web::Data<Pool>,
    user: UserBaseI,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    let target_id = path.into_inner();
    if target_id == user.id {
        return error_response(
            "KickManagedUserSelf",
            ManagementError::Conflict("不能踢出当前登录账号"),
        );
    }
    let mut conn = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            return error_response(
                "KickManagedUserPoolError",
                ManagementError::Other(error_value.to_string()),
            );
        }
    };
    let transaction = match conn.transaction().await {
        Ok(value) => value,
        Err(error_value) => return error_response("KickManagedUserTxError", error_value.into()),
    };
    let target = match lock_target_user(&transaction, target_id).await {
        Ok(value) => value,
        Err(value) => return error_response("KickManagedUserTargetError", value),
    };
    let count =
        match invalidate_target_sessions(&transaction, target.id, "admin_kick", user.id).await {
            Ok(value) => value,
            Err(value) => return error_response("KickManagedUserSessionError", value),
        };
    let mut event = AuditEvent::user("user_security", "user.kick", "success", &user)
        .resource("user", target.id.to_string());
    event.response_status = Some(200);
    event.metadata = json!({"username": target.username, "invalidated_session_count": count});
    if let Err(error_value) =
        write_audit(&transaction, &AuditContext::from_request(&req), &event).await
    {
        return error_response("KickManagedUserAuditError", error_value.into());
    }
    if let Err(error_value) = transaction.commit().await {
        return error_response("KickManagedUserCommitError", error_value.into());
    }
    HttpResponse::Ok().json(json!({
        "success": true,
        "message": if count > 0 { "用户会话已失效" } else { "用户当前没有有效会话" },
        "data": {"invalidatedSessionCount": count}
    }))
}

#[delete("/api/admin/users/{user_id}")]
pub async fn delete_user(
    req: HttpRequest,
    path: web::Path<i32>,
    pool: web::Data<Pool>,
    user: UserBaseI,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    let target_id = path.into_inner();
    if target_id == user.id {
        return error_response(
            "DeleteManagedUserSelf",
            ManagementError::Conflict("不能删除当前登录账号"),
        );
    }
    let mut conn = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            return error_response(
                "DeleteManagedUserPoolError",
                ManagementError::Other(error_value.to_string()),
            );
        }
    };
    let transaction = match conn.transaction().await {
        Ok(value) => value,
        Err(error_value) => return error_response("DeleteManagedUserTxError", error_value.into()),
    };
    let target = match lock_target_user(&transaction, target_id).await {
        Ok(value) => value,
        Err(value) => return error_response("DeleteManagedUserTargetError", value),
    };
    if let Err(value) = protect_last_admin(&transaction, &target).await {
        return error_response("DeleteManagedUserLastAdmin", value);
    }
    if let Err(error_value) = transaction
        .execute(
            "UPDATE users SET deleted_at = NOW(), disabled_at = COALESCE(disabled_at, NOW()), \
         update_at = NOW() WHERE id = $1;",
            &[&target.id],
        )
        .await
    {
        return error_response("DeleteManagedUserError", error_value.into());
    }
    let count =
        match invalidate_target_sessions(&transaction, target.id, "user_deleted", user.id).await {
            Ok(value) => value,
            Err(value) => return error_response("DeleteManagedUserSessionError", value),
        };
    let mut event = AuditEvent::user("user_security", "user.delete", "success", &user)
        .resource("user", target.id.to_string());
    event.response_status = Some(200);
    event.changes = Some(json!({
        "username": target.username,
        "soft_deleted": true,
        "invalidated_session_count": count
    }));
    if let Err(error_value) =
        write_audit(&transaction, &AuditContext::from_request(&req), &event).await
    {
        return error_response("DeleteManagedUserAuditError", error_value.into());
    }
    if let Err(error_value) = transaction.commit().await {
        return error_response("DeleteManagedUserCommitError", error_value.into());
    }
    HttpResponse::Ok().json(json!({"success": true, "message": "用户已删除"}))
}

#[cfg(test)]
mod tests {
    use super::{
        CreateUserRequest, ManagementError, UserListQuery, normalize_list_query, user_list_filter,
        validate_create_request,
    };

    #[test]
    fn create_user_input_is_bounded() {
        let valid = CreateUserRequest {
            username: "alice.test".to_owned(),
            email: Some("alice@example.com".to_owned()),
            password: "correct horse battery staple".to_owned(),
            role: 2,
        };
        assert!(validate_create_request(&valid).is_ok());

        let short_password = CreateUserRequest {
            password: "short".to_owned(),
            ..valid
        };
        assert!(matches!(
            validate_create_request(&short_password),
            Err(ManagementError::BadRequest(_))
        ));
    }

    #[test]
    fn list_query_rejects_unknown_status_and_role() {
        let invalid_status = UserListQuery {
            page: None,
            page_size: None,
            query: None,
            role: None,
            status: Some("unknown".to_owned()),
        };
        assert!(normalize_list_query(&invalid_status).is_err());
        let invalid_role = UserListQuery {
            page: None,
            page_size: None,
            query: None,
            role: Some(0),
            status: None,
        };
        assert!(normalize_list_query(&invalid_role).is_err());
    }

    #[test]
    fn user_list_filter_only_binds_present_search_and_role() {
        let search = Some("alice".to_owned());
        let role = Some(2);
        let (sql, params) = user_list_filter(&search, &role, "active");
        assert_eq!(sql.matches("$1").count(), 2);
        assert!(sql.contains("u.role = $2"));
        assert!(sql.contains("u.deleted_at IS NULL"));
        assert!(sql.contains("u.disabled_at IS NULL"));
        assert!(sql.contains("u.limit_login = FALSE"));
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn user_list_filter_has_no_optional_parameters_by_default() {
        let (sql, params) = user_list_filter(&None, &None, "all");
        assert_eq!(sql, "u.role IN (1, 2) AND u.deleted_at IS NULL");
        assert!(params.is_empty());
    }
}
