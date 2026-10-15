use actix_web::cookie::time::OffsetDateTime;
use actix_web::{HttpRequest, HttpResponse, Responder, cookie, cookie::Cookie, get, post, web};
use deadpool_postgres::Pool;
use serde_json::json;
use std::ops::Deref;
use std::time::Instant;
use tracing::{error, warn};

use crate::admin::{
    AddScanner, GetUserInfoH, ScannerRegisterData, ScannerRegistrationUnauthorized, Unbind2FAH,
    UserBaseI, UserBaseInfo, UserSession, VerifyTotp, bind_twofa, check_twofa_bind,
    confirm_twofa_binding, get_scanner, get_scanners, get_user_info, scanner_register, totp_struct,
    totp_token_verify, totp_verify_status_change, unbind_2fa, update_user_info, web_add_scanner,
};
use crate::audit::{AuditContext, AuditEvent, write as write_audit, write_standalone};
use crate::client_ip::request_ip;
use crate::config::{PasswordHashConfig, SecurityConfig, ServerConfig};
use crate::handlers::ReceiveLoginInfo;
use crate::handlers::login_record::{login_failure_event, record_completed_login};
use crate::login::{LoginInvalidCredentials, LoginIpNotAllowlisted, user_login};
use crate::login_allowlist::{load_login_allowlist, login_ip_is_allowed};
use crate::logs::write::{error_logs, error_logs_error, info_logs};
use crate::mail_template::send_login_notification;
use crate::middlewares::render_500;
use crate::request_log::set_reason;
use crate::system_maintenance::{SystemMaintenanceState, maintenance_response};
use crate::web_support::TemplatesInit;
use crate::{
    identity::generate_hash_password, identity::log_out, identity::verify_password,
    web_support::get_conn_ip,
};
use uuid::Uuid;

fn expired_auth_cookies(
    req: &HttpRequest,
    session: &str,
    csrf_token: &str,
) -> (Cookie<'static>, Cookie<'static>) {
    let session_cookie = Cookie::build("session", session.to_owned())
        .path("/")
        .http_only(true)
        .secure(crate::tls::request_uses_https(req))
        .same_site(cookie::SameSite::Strict)
        .expires(OffsetDateTime::UNIX_EPOCH)
        .finish();
    let csrf_cookie = Cookie::build("csrf_token", csrf_token.to_owned())
        .path("/")
        .secure(crate::tls::request_uses_https(req))
        .same_site(cookie::SameSite::Strict)
        .expires(OffsetDateTime::UNIX_EPOCH)
        .finish();
    (session_cookie, csrf_cookie)
}

fn request_source_ip(req: &HttpRequest) -> String {
    get_conn_ip(req)
}

fn queue_login_notification(
    pool: deadpool_postgres::Pool,
    encryption_key: String,
    user_id: i32,
    username: String,
    source_ip: String,
) {
    tokio::spawn(async move {
        if let Err(error_value) =
            send_login_notification(&pool, &encryption_key, user_id, &username, &source_ip).await
        {
            warn!(
                event = "SendLoginNotificationError",
                operation = "send_login_notification",
                reason = %error_value,
                error_code = "login_notification_delivery_failed",
                outcome = "login_completed_without_notification",
                user_id,
                username,
            );
        }
    });
}
#[derive(serde::Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}
/// 登录接口
#[post("/api/login")]
async fn user_login_h(
    req: HttpRequest,
    pool: web::Data<deadpool_postgres::Pool>,
    server_config: web::Data<ServerConfig>,
    receiveinfo: web::Json<ReceiveLoginInfo>,
) -> impl Responder {
    let total_start = Instant::now(); // 总的开始时间
    let start = Instant::now(); // 登录函数开始时间
    let p = pool.get_ref();
    let source_ip = request_ip(&req);
    let login_result =
        match user_login(&receiveinfo.username, &receiveinfo.password, source_ip, p).await {
            Ok(value) => value,
            Err(e) => {
                let ip_denied = e.downcast_ref::<LoginIpNotAllowlisted>();
                let invalid_credentials = e.downcast_ref::<LoginInvalidCredentials>().is_some();
                let reason = if ip_denied.is_some() {
                    "ip_not_allowlisted"
                } else if invalid_credentials {
                    "invalid_credentials"
                } else {
                    "login_internal_error"
                };
                set_reason(&req, reason);
                let mut audit_event =
                    login_failure_event(None, &receiveinfo.username, reason, "password");
                if !invalid_credentials && ip_denied.is_none() {
                    audit_event.response_status = Some(500);
                }
                if let Some(denied) = ip_denied {
                    audit_event.resource_type = Some("user".to_owned());
                    audit_event.resource_id = Some(denied.user_id.to_string());
                    audit_event.response_status = Some(403);
                }
                write_standalone(p, &AuditContext::from_request(&req), &audit_event).await;
                if invalid_credentials || ip_denied.is_some() {
                    warn!(
                        event = "UserLoginRejected",
                        operation = "authenticate_user",
                        reason_code = reason,
                        outcome = "login_denied",
                        username = %receiveinfo.username,
                    );
                } else {
                    error_logs_error(&req, "UserLoginError", "authenticate_user", e.as_ref());
                }
                let body = if ip_denied.is_some() {
                    json!({
                        "success": false,
                        "code": "login_ip_not_allowlisted",
                        "message": "当前 IP 不在该账号的登录白名单中"
                    })
                } else {
                    json!({
                        "success": false,
                        "message": "登录失败"
                    })
                };
                let total_es = total_start.elapsed();
                let login_function = start.elapsed();
                tracing::debug!(
                    event = "LoginCompleted",
                    total_ms = total_es.as_millis() as u64,
                    authentication_ms = login_function.as_millis() as u64,
                    reason_code = reason
                );
                return if ip_denied.is_some() {
                    HttpResponse::Forbidden().json(body)
                } else if !invalid_credentials {
                    HttpResponse::InternalServerError().json(body)
                } else {
                    HttpResponse::Unauthorized().json(body)
                };
            }
        };
    let t_session = login_result.session;
    let csrf_token = login_result.csrf_token;
    let enable_twofa = login_result.enable_2fa;
    let session_ttl_seconds = login_result.session_ttl_seconds;
    let login_context = AuditContext::from_request(&req);

    if enable_twofa {
        let mut audit_event =
            AuditEvent::anonymous("authentication", "auth.password_verify", "success");
        audit_event.severity = "info".to_owned();
        audit_event.actor_type = "user".to_owned();
        audit_event.actor_id = Some(login_result.user_id.to_string());
        audit_event.actor_name = Some(receiveinfo.username.clone());
        audit_event.response_status = Some(401);
        audit_event.metadata = json!({"totp_required": true});
        write_standalone(p, &login_context, &audit_event).await;
    } else if let Err(error_value) = record_completed_login(
        p,
        &login_context,
        login_result.user_id,
        &receiveinfo.username,
        "password",
    )
    .await
    {
        let diagnostics = crate::logs::write::error_diagnostics(error_value.as_ref());
        error!(
            event = "RecordCompletedLoginError",
            operation = "record_completed_login",
            error_kind = "database",
            error_code = "completed_login_record_failed",
            error_message = %diagnostics.error_message,
            error_chain = %diagnostics.error_chain,
            root_cause = %diagnostics.root_cause,
            error_truncated = diagnostics.error_truncated,
            retryable = false,
            outcome = "login_session_rollback_started",
            user_id = login_result.user_id,
        );
        if let Err(logout_error) =
            log_out(&t_session, p, "login_rollback", Some(login_result.user_id)).await
        {
            let diagnostics = crate::logs::write::error_diagnostics(logout_error.as_ref());
            error!(
                event = "RollbackLoginSessionError",
                operation = "rollback_login_session",
                error_kind = "database",
                error_code = "login_session_rollback_failed",
                error_message = %diagnostics.error_message,
                error_chain = %diagnostics.error_chain,
                root_cause = %diagnostics.root_cause,
                error_truncated = diagnostics.error_truncated,
                retryable = false,
                outcome = "login_session_may_remain_active",
                user_id = login_result.user_id,
            );
        }
        return HttpResponse::InternalServerError()
            .json(json!({"success": false, "message": "登录状态保存失败，请重试"}));
    }

    let cookies = Cookie::build("session", &t_session)
        .path("/")
        .http_only(true)
        .secure(crate::tls::request_uses_https(&req))
        .max_age(cookie::time::Duration::seconds(i64::from(
            session_ttl_seconds,
        )))
        .same_site(cookie::SameSite::Strict)
        .finish();
    let cookie_csrf_token = Cookie::build("csrf_token", &csrf_token)
        .path("/")
        .secure(crate::tls::request_uses_https(&req))
        .max_age(cookie::time::Duration::seconds(i64::from(
            session_ttl_seconds,
        )))
        .same_site(cookie::SameSite::Strict)
        .finish();

    let total_es = total_start.elapsed();
    let login_function = start.elapsed();

    tracing::debug!(
        event = "LoginCompleted",
        total_ms = total_es.as_millis() as u64,
        authentication_ms = login_function.as_millis() as u64
    );
    if !enable_twofa {
        queue_login_notification(
            p.clone(),
            server_config.encrypt_key.clone(),
            login_result.user_id,
            receiveinfo.username.clone(),
            request_source_ip(&req),
        );
    }

    match enable_twofa {
        true => {
            // 使用 401 Unauthorized 表示还需要继续验证 TOTP Token
            HttpResponse::Unauthorized()
                .cookie(cookies)
                .cookie(cookie_csrf_token)
                .json(json!({
                    "success": true,
                    "code": "totp_required",
                    "message": "请验证 2FA 验证码"
                }))
        }
        false => HttpResponse::Ok()
            .cookie(cookies)
            .cookie(cookie_csrf_token)
            .json(json!({
                "success": true,
                "message": "登录成功"
            })),
    }
}

/// 注销会话接口
#[get("/logout")]
async fn user_logout(
    req: HttpRequest,
    pool: web::Data<deadpool_postgres::Pool>,
    page_template: web::Data<TemplatesInit>,
    session: UserSession,
    user: UserBaseI,
) -> impl Responder {
    let tmp_csrf_t = match &req.headers().get("X-CSRF-Token") {
        Some(s) => s.to_str().unwrap_or(""),
        None => "",
    };

    let p = pool.get_ref();
    let c_s = session.session;

    match log_out(&c_s, p, "logout", Some(user.id)).await {
        Ok(_) => {
            let mut audit_event =
                AuditEvent::user("authentication", "auth.logout", "success", &user);
            audit_event.response_status = Some(200);
            write_standalone(p, &AuditContext::from_request(&req), &audit_event).await;
            let cookies = Cookie::build("session", &c_s)
                .path("/")
                .http_only(true)
                .secure(crate::tls::request_uses_https(&req))
                .expires(OffsetDateTime::UNIX_EPOCH)
                .finish();
            let cookie_csrf_token = Cookie::build("csrf_token", tmp_csrf_t)
                .path("/")
                .secure(crate::tls::request_uses_https(&req))
                .expires(OffsetDateTime::UNIX_EPOCH)
                .finish();
            HttpResponse::Ok()
                .cookie(cookies)
                .cookie(cookie_csrf_token)
                .finish()
        }
        Err(e) => {
            error_logs_error(&req, "注销会话错误", "delete_session", e.as_ref());
            let page = page_template.get_ref();
            render_500(&req, page, "注销会话错误")
        }
    }
}

/// totp 配置
///
#[get("/api/totp/get")]
async fn totp_config_h(
    req: HttpRequest,
    user_base_i: UserBaseI,
    pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
    let pool_r = pool.get_ref();

    match check_twofa_bind(&user_base_i.username, pool_r).await {
        Ok(true) => HttpResponse::Ok().json(json!({
            "success": true,
            "message": "已绑定"
        })),
        Ok(false) => HttpResponse::Ok().json(json!({
            "success": false,
            "message": "未绑定"
        })),
        Err(e) => {
            error_logs_error(&req, "CheckTwofa", "read_two_factor_status", e.as_ref());
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// 绑定 2FA 验证器
///
/// 直接返回 optauth url
#[get("/api/totp/bind")]
async fn bind_twofa_h(
    req: HttpRequest,
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
    session: UserSession,
    s_config: web::Data<ServerConfig>,
) -> impl Responder {
    let pool_r = pool.get_ref();

    match bind_twofa(
        user_base_i.username,
        &session.session,
        pool_r,
        &s_config.encrypt_key,
    )
    .await
    {
        Ok(binding) => {
            tracing::info!(
                event = "TotpBindStarted",
                operation = "create_totp_binding",
                outcome = "pending_confirmation",
                actor_user_id = user_base_i.id,
                binding_attempt_id = %binding.attempt_id,
                expires_at_ms = binding.expires_at_ms,
            );
            HttpResponse::Ok().json(json!({"success": true, "data": binding.url}))
        }
        Err(e) => {
            set_reason(&req, "totp_bind_initialization_failed");
            error_logs_error(
                &req,
                "CreateOptauthUrlError",
                "create_totp_binding",
                e.as_ref(),
            );
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// 验证 TOTP Token 接口
#[post("/api/totp/verify")]
async fn verify_totp_h(
    info: web::Json<VerifyTotp>,
    pool: web::Data<deadpool_postgres::Pool>,
    req: HttpRequest,
    session: UserSession,
    user_base_i: UserBaseI,
    s_config: web::Data<ServerConfig>,
) -> impl Responder {
    let database_conn = pool.get_ref();
    let username = user_base_i.username.clone();

    if !user_base_i.enable_2fa {
        return match confirm_twofa_binding(
            &username,
            &session.session,
            &info.token,
            database_conn,
            &s_config.encrypt_key,
        )
        .await
        {
            Ok(result) if result.rejection.is_none() => {
                tracing::info!(
                    event = "TotpBindConfirmed",
                    operation = "confirm_totp_binding",
                    outcome = "success",
                    actor_user_id = user_base_i.id,
                    binding_attempt_id = ?result.attempt_id,
                );
                let mut audit_event =
                    AuditEvent::user("user_security", "user.totp_bind", "success", &user_base_i)
                        .resource("user", user_base_i.id.to_string());
                audit_event.response_status = Some(200);
                write_standalone(
                    database_conn,
                    &AuditContext::from_request(&req),
                    &audit_event,
                )
                .await;
                let csrf_token = req
                    .headers()
                    .get("X-CSRF-Token")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("");
                let (session_cookie, csrf_cookie) =
                    expired_auth_cookies(&req, &session.session, csrf_token);
                HttpResponse::Ok()
                    .cookie(session_cookie)
                    .cookie(csrf_cookie)
                    .json(json!({"success": true, "message": "2FA 绑定成功，请重新登录"}))
            }
            Ok(result) => {
                let reason = result
                    .rejection
                    .map(|value| value.reason_code())
                    .unwrap_or("totp_bind_unknown_rejection");
                set_reason(&req, reason);
                warn!(
                    event = "TotpBindRejected",
                    operation = "confirm_totp_binding",
                    reason_code = reason,
                    outcome = "binding_denied",
                    actor_user_id = user_base_i.id,
                    binding_attempt_id = ?result.attempt_id,
                    expires_in_ms = ?result.expires_in_ms,
                    server_totp_step = chrono::Utc::now().timestamp() / 30,
                );
                let mut audit_event =
                    AuditEvent::user("user_security", "user.totp_bind", "failure", &user_base_i);
                audit_event.response_status = Some(401);
                audit_event.reason_code = Some(reason.to_owned());
                audit_event.metadata = json!({"binding_attempt_id": result.attempt_id, "expires_in_ms": result.expires_in_ms});
                write_standalone(
                    database_conn,
                    &AuditContext::from_request(&req),
                    &audit_event,
                )
                .await;
                HttpResponse::Unauthorized()
                    .json(json!({"success": false, "message": "验证码无效或绑定已过期"}))
            }
            Err(e) => {
                set_reason(&req, "totp_bind_confirmation_failed");
                error_logs_error(
                    &req,
                    "ConfirmTotpBindingError",
                    "confirm_totp_binding",
                    e.as_ref(),
                );
                HttpResponse::InternalServerError().finish()
            }
        };
    }

    let source_ip = request_ip(&req);
    match load_login_allowlist(database_conn, user_base_i.id).await {
        Ok(allowlist) if !login_ip_is_allowed(&allowlist, source_ip) => {
            set_reason(&req, "login_ip_not_allowlisted");
            let mut event = login_failure_event(
                Some(&user_base_i),
                &user_base_i.username,
                "ip_not_allowlisted",
                "password_totp",
            );
            event.response_status = Some(403);
            write_standalone(database_conn, &AuditContext::from_request(&req), &event).await;
            if let Err(error_value) = log_out(
                &session.session,
                database_conn,
                "login_ip_denied",
                Some(user_base_i.id),
            )
            .await
            {
                error_logs_error(
                    &req,
                    "LoginIpDeniedSessionCleanupError",
                    "cleanup_login_ip_denied_session",
                    error_value.as_ref(),
                );
            }
            let csrf_token = req
                .headers()
                .get("X-CSRF-Token")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("");
            let (session_cookie, csrf_cookie) =
                expired_auth_cookies(&req, &session.session, csrf_token);
            return HttpResponse::Forbidden()
                .cookie(session_cookie)
                .cookie(csrf_cookie)
                .json(json!({
                    "success": false,
                    "code": "login_ip_not_allowlisted",
                    "message": "当前 IP 不在该账号的登录白名单中"
                }));
        }
        Ok(_) => {}
        Err(error_value) => {
            set_reason(&req, "login_ip_allowlist_load_failed");
            error_logs_error(
                &req,
                "LoadLoginIpAllowlistForTotpError",
                "load_login_ip_allowlist_for_totp",
                error_value.as_ref(),
            );
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "登录白名单校验失败，请重试"}));
        }
    }

    let totp = match totp_struct(username, &s_config.encrypt_key, database_conn).await {
        Ok(Some(tmp)) => tmp,
        Ok(None) => {
            set_reason(&req, "totp_login_secret_missing");
            info_logs(&req, "TOTPSecretNotFound", "查找用户的 totp secret 错误");
            return HttpResponse::NotFound().finish();
        }
        Err(e) => {
            set_reason(&req, "totp_login_secret_load_failed");
            error_logs_error(&req, "生成 TOTP 结构体错误", "load_totp_secret", e.as_ref());
            return HttpResponse::InternalServerError().finish();
        }
    };

    match totp_token_verify(totp, &info.token).await {
        Ok(true) => match totp_verify_status_change(&session.session, database_conn).await {
            Ok(_) => {
                let mut audit_event = AuditEvent::user(
                    "authentication",
                    "auth.totp_verify",
                    "success",
                    &user_base_i,
                );
                audit_event.response_status = Some(200);
                write_standalone(
                    database_conn,
                    &AuditContext::from_request(&req),
                    &audit_event,
                )
                .await;
                if let Err(error_value) = record_completed_login(
                    database_conn,
                    &AuditContext::from_request(&req),
                    user_base_i.id,
                    &user_base_i.username,
                    "password_totp",
                )
                .await
                {
                    error_logs(
                        &req,
                        "RecordCompletedTotpLoginError",
                        &error_value.to_string(),
                    );
                    if let Err(logout_error) = log_out(
                        &session.session,
                        database_conn,
                        "login_rollback",
                        Some(user_base_i.id),
                    )
                    .await
                    {
                        error_logs(
                            &req,
                            "RollbackTotpLoginSessionError",
                            &logout_error.to_string(),
                        );
                    }
                    return HttpResponse::InternalServerError().json(json!({
                        "success": false,
                        "message": "登录状态保存失败，请重新登录"
                    }));
                }
                queue_login_notification(
                    database_conn.clone(),
                    s_config.encrypt_key.clone(),
                    user_base_i.id,
                    user_base_i.username.clone(),
                    request_source_ip(&req),
                );
                HttpResponse::Ok().finish()
            }
            Err(error_value) => {
                set_reason(&req, "totp_login_session_update_failed");
                error_logs_error(
                    &req,
                    "TotpSessionUpdateError",
                    "update_totp_session",
                    error_value.as_ref(),
                );
                HttpResponse::InternalServerError().finish()
            }
        },
        Ok(false) => {
            set_reason(&req, "totp_login_code_mismatch");
            let mut audit_event = AuditEvent::user(
                "authentication",
                "auth.totp_verify",
                "failure",
                &user_base_i,
            );
            audit_event.response_status = Some(401);
            audit_event.reason_code = Some("totp_login_code_mismatch".to_owned());
            write_standalone(
                database_conn,
                &AuditContext::from_request(&req),
                &audit_event,
            )
            .await;
            let login_event = login_failure_event(
                Some(&user_base_i),
                &user_base_i.username,
                "totp_login_code_mismatch",
                "password_totp",
            );
            write_standalone(
                database_conn,
                &AuditContext::from_request(&req),
                &login_event,
            )
            .await;
            warn!(
                event = "TotpLoginRejected",
                operation = "verify_totp_token",
                reason_code = "totp_login_code_mismatch",
                outcome = "login_denied",
                actor_user_id = user_base_i.id,
                server_totp_step = chrono::Utc::now().timestamp() / 30,
            );
            HttpResponse::Unauthorized().finish()
        }
        Err(e) => {
            set_reason(&req, "totp_login_verification_failed");
            error_logs_error(
                &req,
                "TOTPTokenVerifyError",
                "verify_totp_token",
                e.as_ref(),
            );
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// 解绑 2FA ，该操作只能由管理员设置
///
#[post("/api/totp/unbind")]
async fn unbind_2fa_h(
    req: HttpRequest,
    unbind_info: web::Json<Unbind2FAH>,
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
    session: UserSession,
) -> impl Responder {
    let pool_c = pool.get_ref();

    if user_base_i.role != 1 {
        return HttpResponse::Forbidden().finish();
    };
    match unbind_2fa(&unbind_info.username, pool_c, user_base_i.id).await {
        Ok(true) => {
            let mut audit_event =
                AuditEvent::user("user_security", "user.totp_unbind", "success", &user_base_i)
                    .resource("user", unbind_info.username.clone());
            audit_event.response_status = Some(200);
            write_standalone(pool_c, &AuditContext::from_request(&req), &audit_event).await;
            info_logs(&req, "Unbind2FASuccessful", "解绑 2FA 成功");
            if unbind_info.username == user_base_i.username {
                let csrf_token = req
                    .headers()
                    .get("X-CSRF-Token")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("");
                let (session_cookie, csrf_cookie) =
                    expired_auth_cookies(&req, &session.session, csrf_token);
                HttpResponse::Ok()
                    .cookie(session_cookie)
                    .cookie(csrf_cookie)
                    .json(json!({"success": true, "message": "2FA 已解绑，请重新登录"}))
            } else {
                HttpResponse::Ok().json(json!({"success": true, "message": "2FA 已解绑"}))
            }
        }
        Ok(false) => HttpResponse::NotFound().finish(),
        Err(e) => {
            error_logs_error(&req, "Unbind2FAfaild", "unbind_totp", e.as_ref());
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// 获取用户信息
///
#[get("/api/userinfo/get")]
async fn get_user_info_h(
    req: HttpRequest,
    info: web::Query<GetUserInfoH>,
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
) -> impl Responder {
    let pool_ref = pool.get_ref();
    let u_role = user_base_i.role;
    let username = user_base_i.username;

    let t_username = if info.list.unwrap_or(false) {
        // 当 list 存在且为 true 时不会指定用户名
        None
    } else if u_role == 1 {
        // 管理员可以查询所有用户，如果没有指定则查询自己的信息
        Some(info.username.as_deref().unwrap_or(username.as_str()))
    } else if u_role == 2 {
        // 普通用户只能查询自己的信息
        Some(username.as_str())
    } else {
        error_logs(
            &req,
            "GetUserInfoError",
            format!("role: {}, 错误的权限", u_role).as_str(),
        );
        return HttpResponse::InternalServerError().finish();
    };

    match get_user_info(u_role, t_username, info.count.map(|c| c as i64), pool_ref).await {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => {
            error_logs_error(
                &req,
                "GetUserInfoError",
                "load_user_information",
                e.as_ref(),
            );
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// 更新用户信息
///
#[post("/api/userinfo/update")]
async fn update_user_info_h(
    req: HttpRequest,
    new_user_i: web::Json<UserBaseInfo>,
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
) -> impl Responder {
    let pool_ref = pool.get_ref();

    match update_user_info(
        &user_base_i.username,
        user_base_i.role,
        &new_user_i,
        pool_ref,
    )
    .await
    {
        Ok(()) => HttpResponse::Ok(),
        Err(e) => {
            error_logs_error(
                &req,
                "UpdateUserInfoError",
                "update_user_information",
                e.as_ref(),
            );
            HttpResponse::InternalServerError()
        }
    }
}

/// 修改当前登录用户的密码。
///
/// 修改成功后会废止该用户的所有既有 Session，以阻止旧登录态继续访问。
#[post("/api/user/password/update")]
async fn change_password_h(
    req: HttpRequest,
    password_change: web::Json<ChangePasswordRequest>,
    pool: web::Data<Pool>,
    pwd_hash_config: web::Data<PasswordHashConfig>,
    user_base_i: UserBaseI,
) -> impl Responder {
    let current_password = password_change.current_password.as_str();
    let new_password = password_change.new_password.as_str();

    if !matches!(user_base_i.role, 1 | 2) {
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "当前账户不允许修改密码"
        }));
    }
    if current_password.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "请输入当前密码"
        }));
    }
    let new_password_length = new_password.chars().count();
    if !(12..=128).contains(&new_password_length) {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "新密码长度必须在 12 到 128 个字符之间"
        }));
    }
    if current_password == new_password {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "新密码不能与当前密码相同"
        }));
    }

    let mut client = match pool.get_ref().get().await {
        Ok(client) => client,
        Err(error_value) => {
            error_logs(
                &req,
                "ChangePasswordDatabaseError",
                &error_value.to_string(),
            );
            return HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "密码修改服务暂时不可用"
            }));
        }
    };
    let transaction = match client.transaction().await {
        Ok(transaction) => transaction,
        Err(error_value) => {
            error_logs(
                &req,
                "ChangePasswordTransactionError",
                &error_value.to_string(),
            );
            return HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "密码修改服务暂时不可用"
            }));
        }
    };
    let row = match transaction
        .query_opt(
            "SELECT password FROM users WHERE id = $1 AND role IN (1, 2) FOR UPDATE;",
            &[&user_base_i.id],
        )
        .await
    {
        Ok(row) => row,
        Err(error_value) => {
            error_logs_error(
                &req,
                "ChangePasswordQueryError",
                "load_password_for_update",
                &error_value,
            );
            return HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "密码修改服务暂时不可用"
            }));
        }
    };
    let Some(row) = row else {
        return HttpResponse::NotFound().json(json!({
            "success": false,
            "message": "未找到当前用户"
        }));
    };
    let password_hash: String = row.get("password");
    if !verify_password(current_password, &password_hash) {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "当前密码不正确"
        }));
    }

    let new_password_hash =
        match generate_hash_password(new_password, pwd_hash_config.get_ref().clone()) {
            Ok(password_hash) => password_hash,
            Err(error_value) => {
                error!(
                    event = "ChangePasswordHashError",
                    operation = "hash_new_password",
                    error_kind = "cryptography",
                    error_code = "password_hash_generation_failed",
                    error_message = %error_value,
                    retryable = false,
                    outcome = "password_unchanged",
                    user_id = user_base_i.id,
                );
                return HttpResponse::InternalServerError().json(json!({
                    "success": false,
                    "message": "密码修改服务暂时不可用"
                }));
            }
        };
    if let Err(error_value) = transaction
        .execute(
            "UPDATE users SET password = $1, limit_login = false, limit_at = NULL, \
             limit_time = NULL, login_error_count = 0, last_error_at = NULL WHERE id = $2;",
            &[&new_password_hash, &user_base_i.id],
        )
        .await
    {
        error_logs_error(
            &req,
            "ChangePasswordUpdateError",
            "update_password",
            &error_value,
        );
        return HttpResponse::InternalServerError().json(json!({
            "success": false,
            "message": "密码修改服务暂时不可用"
        }));
    }
    if let Err(error_value) = transaction
        .execute(
            "UPDATE session SET is_enable = FALSE, deleted_at = NOW(), \
             deletion_reason = 'password_changed', deleted_by_user_id = $1 \
             WHERE user_id = $1 AND is_enable = TRUE AND deleted_at IS NULL;",
            &[&user_base_i.id],
        )
        .await
    {
        error_logs_error(
            &req,
            "ChangePasswordSessionError",
            "invalidate_sessions",
            &error_value,
        );
        return HttpResponse::InternalServerError().json(json!({
            "success": false,
            "message": "密码修改服务暂时不可用"
        }));
    }
    let mut audit_event = AuditEvent::user(
        "user_security",
        "user.password_change",
        "success",
        &user_base_i,
    )
    .resource("user", user_base_i.id.to_string());
    audit_event.response_status = Some(200);
    audit_event.changes = Some(json!({"sessions_invalidated": true}));
    if let Err(error_value) = write_audit(
        &transaction,
        &AuditContext::from_request(&req),
        &audit_event,
    )
    .await
    {
        error_logs_error(
            &req,
            "ChangePasswordAuditError",
            "write_audit_event",
            &error_value,
        );
        return HttpResponse::InternalServerError().json(json!({
            "success": false,
            "message": "密码修改服务暂时不可用"
        }));
    }
    if let Err(error_value) = transaction.commit().await {
        error_logs_error(
            &req,
            "ChangePasswordCommitError",
            "commit_transaction",
            &error_value,
        );
        return HttpResponse::InternalServerError().json(json!({
            "success": false,
            "message": "密码修改服务暂时不可用"
        }));
    }

    info_logs(
        &req,
        "ChangePasswordSuccessful",
        "用户密码已修改，既有会话已失效",
    );
    HttpResponse::Ok().json(json!({
        "success": true,
        "message": "密码已修改，请重新登录"
    }))
}
/// 添加扫描器
///
/// 主要是 web 端添加用的
#[post("/api/scanner/add")]
async fn web_add_scanner_h(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    user_base_i: UserBaseI,
    add_data: web::Json<AddScanner>,
) -> impl Responder {
    let pool_ref = pool.get_ref();
    let s_id = match web_add_scanner(
        pool_ref,
        &user_base_i,
        &AuditContext::from_request(&req),
        add_data.deref(),
        &security.scanner_token_pepper,
    )
    .await
    {
        Ok(ok) => ok,
        Err(e) => {
            error_logs_error(&req, "AddScannerError", "insert_scanner", e.as_ref());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let res_data = json!({
        "success": true,
        "data": s_id
    });
    HttpResponse::Ok().json(res_data)
}

#[get("/api/scanner/list")]
async fn get_scanners_h(
    req: HttpRequest,
    pool: web::Data<Pool>,
    maintenance: web::Data<SystemMaintenanceState>,
    _user_base_i: UserBaseI,
) -> impl Responder {
    match get_scanners(pool.get_ref()).await {
        Ok(scanners) => {
            let maintenance = maintenance.snapshot().await;
            HttpResponse::Ok().json(json!({
                "success": true,
                "data": scanners,
                "maintenance": maintenance.enabled.then_some(maintenance),
            }))
        }
        Err(error) => {
            error_logs_error(&req, "GetScannersError", "list_scanners", error.as_ref());
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/api/scanner/{scanner_id}")]
async fn get_scanner_h(
    req: HttpRequest,
    pool: web::Data<Pool>,
    _user_base_i: UserBaseI,
    scanner_id: web::Path<Uuid>,
) -> impl Responder {
    match get_scanner(pool.get_ref(), scanner_id.into_inner()).await {
        Ok(Some(scanner)) => HttpResponse::Ok().json(json!({
            "success": true,
            "data": scanner,
        })),
        Ok(None) => HttpResponse::NotFound().json(json!({
            "success": false,
            "message": "scanner not found",
        })),
        Err(error) => {
            error_logs_error(&req, "GetScannerError", "load_scanner", error.as_ref());
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// 扫描器注册
///
#[post("/api/scanner/register")]
async fn scanner_register_h(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
    register_data: web::Json<ScannerRegisterData>,
) -> impl Responder {
    let registration_token = req
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let Some(registration_token) = registration_token else {
        set_reason(&req, "registration_token_missing");
        return HttpResponse::Unauthorized().body("missing scanner registration token");
    };

    let maintenance_snapshot = maintenance.snapshot().await;
    if maintenance_snapshot.blocks_new_work() {
        let token_hash = match crate::identity::hash_scanner_token(
            registration_token,
            &security.scanner_token_pepper,
        ) {
            Ok(value) => value,
            Err(error_value) => {
                set_reason(&req, "registration_token_hash_failed");
                error_logs_error(
                    &req,
                    "ScannerRegistrationTokenHashError",
                    "hash_scanner_token",
                    &error_value,
                );
                return HttpResponse::InternalServerError().finish();
            }
        };
        let client = match pool.get().await {
            Ok(client) => client,
            Err(error_value) => {
                set_reason(&req, "scanner_registration_pool_failed");
                error_logs_error(
                    &req,
                    "ScannerRegistrationPoolError",
                    "acquire_registration_connection",
                    &error_value,
                );
                return HttpResponse::InternalServerError().finish();
            }
        };
        let authorized = client
            .query_opt(
                "SELECT id FROM scanner_info WHERE scanner_id = $1 \
                 AND registration_token_hash = $2 AND registration_consumed_at IS NULL \
                 AND registration_token_expires_at > NOW() AND deleted_at IS NULL LIMIT 1;",
                &[&register_data.scanner_id, &token_hash],
            )
            .await;
        match authorized {
            Ok(Some(_)) => return maintenance_response(&maintenance_snapshot),
            Ok(None) => {
                set_reason(&req, "invalid_registration_token");
                return HttpResponse::Unauthorized().finish();
            }
            Err(error_value) => {
                set_reason(&req, "scanner_registration_lookup_failed");
                error_logs_error(
                    &req,
                    "ScannerRegistrationLookupError",
                    "validate_registration_token",
                    &error_value,
                );
                return HttpResponse::InternalServerError().finish();
            }
        }
    }

    match scanner_register(
        &pool,
        &register_data,
        registration_token,
        &security.scanner_token_pepper,
        &AuditContext::from_request(&req),
    )
    .await
    {
        Ok(runtime_secret) => HttpResponse::Ok().json(runtime_secret),
        Err(e) => {
            let mut audit_event = AuditEvent::anonymous("scanner", "scanner.register", "failure");
            audit_event.actor_type = "scanner".to_owned();
            audit_event.actor_id = Some(register_data.scanner_id.clone());
            audit_event.resource_type = Some("scanner".to_owned());
            audit_event.resource_id = Some(register_data.scanner_id.clone());
            let unauthorized = e
                .downcast_ref::<ScannerRegistrationUnauthorized>()
                .is_some();
            let reason = if unauthorized {
                "invalid_registration_token"
            } else {
                "registration_error"
            };
            set_reason(&req, reason);
            audit_event.response_status = Some(if unauthorized { 401 } else { 500 });
            audit_event.reason_code = Some(reason.to_owned());
            write_standalone(
                pool.get_ref(),
                &AuditContext::from_request(&req),
                &audit_event,
            )
            .await;
            if unauthorized {
                warn!(event = "ScannerRegistrationRejected", operation = "register_scanner", reason_code = reason, scanner_id = %register_data.scanner_id);
                return HttpResponse::Unauthorized().finish();
            }
            error_logs_error(&req, "ScannerRegister", "register_scanner", e.as_ref());
            HttpResponse::InternalServerError().finish()
        }
    }
}

// 扫描器状态
//
// 通过定时接收扫描器发送的请求来判断扫描器是否在线，以及当前状态
// #[post("/api/scanner/health")]
// async fn scanner_health_h(
//     req: HttpRequest,
//     pool: web::Data<Pool>
// ) -> {

// }
