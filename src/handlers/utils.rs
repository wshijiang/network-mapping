use actix_web::{HttpRequest, HttpResponse, Responder, get, post, web};
use lettre::{Message, message::Mailbox, message::header::ContentType};
use serde_json::json;
use tracing::error;

use crate::admin::{
    MailRetryPolicy, UserBaseI, UserSession, get_config_from_database,
    get_mail_sender_key_from_database, get_mail_settings_from_database,
    get_scan_settings_from_database, get_session_settings_from_database, smtp_send_error_message,
    try_send_email, write_mail_settings_to_database, write_scan_settings_to_database,
    write_session_settings_to_database,
};
use crate::audit::{AuditContext, AuditEvent, write_standalone};
use crate::config::{
    DatabaseConfig, EmailConfig, GetConfig, MailSettingsRequest, MailTestRequest,
    ScanSettingsRequest, ServerConfig, SessionSettingsRequest, session_ttl_seconds_from_minutes,
};
use crate::monitor::MonitorHandle;
use crate::runtime_config::{
    ANALYTICS_SNAPSHOT_NAMESPACE, AUTOMATIC_TARGET_NAMESPACE, DNS_FOLLOW_UP_NAMESPACE,
    DNS_RESOLVERS_NAMESPACE, GENERAL_NAMESPACE, MONITOR_NAMESPACE, PersistError,
    REPORT_MAIL_NAMESPACE, REQUESTS_NAMESPACE, RuntimeConfigResponse, RuntimeSettings,
    SCAN_ROUTING_NAMESPACE, SCANNER_HEALTH_NAMESPACE, UpdateRuntimeConfigRequest,
    parse_analytics_snapshot, parse_automatic_target, parse_dns_follow_up, parse_dns_resolvers,
    parse_general, parse_monitor, parse_report_mail, parse_requests, parse_scan_routing,
    parse_scanner_health, persist,
};
use crate::statistics::{
    NAMESPACE as STATISTICS_CACHE_NAMESPACE, parse_config as parse_statistics_cache,
};
use crate::trusted_proxy::{
    MAX_CLIENT_IP_HEADER_LENGTH, MAX_TRUSTED_PROXY_CIDRS, TrustedProxySettings, TrustedProxyState,
    validate_settings, write_settings_to_database,
};
use crate::web_support::TEXT_HTML_UTF_8;
use crate::{
    FrontEndErrorInfo, front_end_error_page,
    logs::write::{info_logs, request_id},
    web_support::TemplatesInit,
};

#[cfg(feature = "rir")]
use crate::rir::get_rir_data;

//基准测试
use crate::{system_resources::Systems, system_resources::benchmark};

///获取系统信息基准测试
#[get("/benchmark")]
async fn benchmark_route(
    sys: web::Data<Systems>,
    pool: web::Data<&deadpool_postgres::Pool>,
    db_config: web::Data<DatabaseConfig>,
) -> impl Responder {
    benchmark(sys, pool, db_config.db_name.clone()).await;
    "Benchmark finished, check server logs."
}

pub async fn not_found(
    req: HttpRequest,
    page_template: web::Data<TemplatesInit>,
) -> impl Responder {
    if req.path() == "/api" || req.path().starts_with("/api/") {
        return HttpResponse::NotFound().json(serde_json::json!({
            "success": false,
            "message": "not found",
            "request_id": request_id(&req).to_string(),
        }));
    }

    let error_info = FrontEndErrorInfo {
        status_code: 404,
        error_title: "NotFound",
        error_message: "没有找到对应的资源",
        request_id: request_id(&req).to_string(),
    };
    HttpResponse::NotFound()
        .content_type(TEXT_HTML_UTF_8)
        .body(front_end_error_page(&error_info, &page_template))
}

/// 获取服务端版本号
#[get("/api/version")]
async fn get_server_version() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "success": true,
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// 获取管理员可见的启动配置检查快照。
#[get("/api/config/check")]
pub async fn get_config_check(
    report: web::Data<crate::config_check::ConfigCheck>,
    user: UserBaseI,
) -> impl Responder {
    if user.role != 1 {
        return HttpResponse::Forbidden()
            .json(json!({"success": false, "message": "仅管理员可以查看配置检查结果"}));
    }
    HttpResponse::Ok().json(json!({"success": true, "data": report.get_ref()}))
}

/// 获取当前 Web 监听配置（只读）
#[get("/api/config/server")]
pub async fn get_server_config_h(
    server_config: web::Data<ServerConfig>,
    user_base_i: UserBaseI,
) -> impl Responder {
    if user_base_i.role != 1 {
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以读取 Web 监听配置"
        }));
    }

    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {
            "host": server_config.host.as_str(),
            "port": server_config.port
        }
    }))
}

#[get("/api/config/runtime/{namespace}")]
async fn get_runtime_config_h(
    namespace: web::Path<String>,
    settings: web::Data<RuntimeSettings>,
    pool: web::Data<deadpool_postgres::Pool>,
    user: UserBaseI,
) -> impl Responder {
    if user.role != 1 {
        return HttpResponse::Forbidden()
            .json(json!({"success": false, "message": "仅管理员可以读取运行时配置"}));
    }
    match namespace.as_str() {
        STATISTICS_CACHE_NAMESPACE => {
            let client = match pool.get().await { Ok(c)=>c, Err(_)=>return HttpResponse::ServiceUnavailable().finish() };
            match client.query_one("SELECT document,revision FROM runtime_configuration WHERE namespace=$1", &[&STATISTICS_CACHE_NAMESPACE]).await {
                Ok(row)=>HttpResponse::Ok().json(json!({"success":true,"data":{"namespace":STATISTICS_CACHE_NAMESPACE,"revision":row.get::<_,i64>("revision"),"document":row.get::<_,serde_json::Value>("document")}})),
                Err(_)=>HttpResponse::ServiceUnavailable().finish()
            }
        }
        GENERAL_NAMESPACE => {
            match crate::system_time::refresh(pool.get_ref()).await {
                Ok(value) => HttpResponse::Ok().json(json!({"success": true, "data": {"namespace": "general", "revision": value.revision, "document": value.document}})),
                Err(_) => HttpResponse::ServiceUnavailable().json(json!({"success": false, "message": "常规设置读取失败"})),
            }
        }
        REQUESTS_NAMESPACE => {
            let value = settings.requests.get().await;
            HttpResponse::Ok().json(json!({"success": true, "data": RuntimeConfigResponse { namespace: REQUESTS_NAMESPACE, revision: value.revision, document: value.value }}))
        }
        SCANNER_HEALTH_NAMESPACE => {
            let value = settings.scanner_health.get().await;
            HttpResponse::Ok().json(json!({"success": true, "data": RuntimeConfigResponse { namespace: SCANNER_HEALTH_NAMESPACE, revision: value.revision, document: value.value }}))
        }
        MONITOR_NAMESPACE => {
            let value = settings.monitor.get().await;
            HttpResponse::Ok().json(json!({"success": true, "data": RuntimeConfigResponse { namespace: MONITOR_NAMESPACE, revision: value.revision, document: value.value }}))
        }
        SCAN_ROUTING_NAMESPACE => {
            let value = settings.scan_routing.get().await;
            HttpResponse::Ok().json(json!({"success": true, "data": RuntimeConfigResponse { namespace: SCAN_ROUTING_NAMESPACE, revision: value.revision, document: value.value }}))
        }
        AUTOMATIC_TARGET_NAMESPACE => {
            let value = settings.automatic_target.get().await;
            HttpResponse::Ok().json(json!({"success": true, "data": RuntimeConfigResponse { namespace: AUTOMATIC_TARGET_NAMESPACE, revision: value.revision, document: value.value }}))
        }
        DNS_FOLLOW_UP_NAMESPACE => {
            let value = settings.dns_follow_up.get().await;
            HttpResponse::Ok().json(json!({"success": true, "data": RuntimeConfigResponse { namespace: DNS_FOLLOW_UP_NAMESPACE, revision: value.revision, document: value.value }}))
        }
        DNS_RESOLVERS_NAMESPACE => {
            let value = settings.dns_resolvers.get().await;
            HttpResponse::Ok().json(json!({"success": true, "data": RuntimeConfigResponse { namespace: DNS_RESOLVERS_NAMESPACE, revision: value.revision, document: value.value }}))
        }
        REPORT_MAIL_NAMESPACE => {
            if crate::reports::mail_config::refresh(pool.get_ref(), &settings.report_mail).await.is_err() {
                return HttpResponse::ServiceUnavailable().json(json!({"success": false, "message": "报告邮件配置读取失败"}));
            }
            let value = settings.report_mail.get().await;
            HttpResponse::Ok().json(json!({"success": true, "data": RuntimeConfigResponse { namespace: REPORT_MAIL_NAMESPACE, revision: value.revision, document: value.value }}))
        }
        ANALYTICS_SNAPSHOT_NAMESPACE => {
            let value = settings.analytics_snapshot.get().await;
            let progress = match pool.get().await {
                Ok(client) => crate::analytics_snapshot::snapshot_progress(&client)
                    .await
                    .map_err(|error| error.to_string()),
                Err(error) => Err(error.to_string()),
            };
            HttpResponse::Ok().json(json!({"success": true,
                "data": RuntimeConfigResponse { namespace: ANALYTICS_SNAPSHOT_NAMESPACE, revision: value.revision, document: value.value },
                "progress": progress.as_ref().ok(),
                "progress_error": progress.as_ref().err()
            }))
        }
        _ => {
            HttpResponse::NotFound().json(json!({"success": false, "message": "未知运行时配置域"}))
        }
    }
}

#[get("/api/config/runtime/{namespace}/history")]
pub(crate) async fn runtime_config_history(
    namespace: web::Path<String>,
    pool: web::Data<deadpool_postgres::Pool>,
    user: UserBaseI,
) -> impl Responder {
    if user.role != 1 {
        return HttpResponse::Forbidden()
            .json(json!({"success": false, "message": "仅管理员可以读取配置历史"}));
    }
    if !matches!(
        namespace.as_str(),
        MONITOR_NAMESPACE | SCANNER_HEALTH_NAMESPACE | STATISTICS_CACHE_NAMESPACE
    ) {
        return HttpResponse::NotFound()
            .json(json!({"success": false, "message": "此配置域不支持历史查看"}));
    }
    let client = match pool.get().await {
        Ok(client) => client,
        Err(_) => {
            return HttpResponse::ServiceUnavailable()
                .json(json!({"success": false, "message": "配置历史暂不可用"}));
        }
    };
    match client.query("SELECT revision, document, changed_at, change_reason FROM runtime_configuration_revision WHERE namespace = $1 ORDER BY revision DESC LIMIT 30;", &[&namespace.as_str()]).await {
        Ok(rows) => {
            let items: Vec<_> = rows.iter().map(|row| json!({
                "revision": row.get::<_, i64>("revision"), "document": row.get::<_, serde_json::Value>("document"),
                "changed_at": row.get::<_, chrono::DateTime<chrono::Utc>>("changed_at"),
                "change_reason": row.get::<_, String>("change_reason")
            })).collect();
            HttpResponse::Ok().json(json!({"success": true, "data": items}))
        },
        Err(_) => HttpResponse::ServiceUnavailable().json(json!({"success": false, "message": "配置历史读取失败"})),
    }
}

#[allow(clippy::too_many_arguments)]
#[post("/api/config/runtime/{namespace}")]
async fn save_runtime_config_h(
    req: HttpRequest,
    namespace: web::Path<String>,
    body: web::Json<UpdateRuntimeConfigRequest>,
    pool: web::Data<deadpool_postgres::Pool>,
    settings: web::Data<RuntimeSettings>,
    monitor: web::Data<MonitorHandle>,
    statistics: web::Data<crate::statistics::StatisticsService>,
    user: UserBaseI,
) -> impl Responder {
    if user.role != 1 {
        return HttpResponse::Forbidden()
            .json(json!({"success": false, "message": "仅管理员可以修改运行时配置"}));
    }
    if body.expected_revision < 1
        || body.change_reason.len() > 500
        || body.change_reason.chars().any(char::is_control)
    {
        return HttpResponse::BadRequest()
            .json(json!({"success": false, "message": "配置版本或变更原因无效"}));
    }

    macro_rules! publish {
        ($namespace:expr, $parse:ident, $target:ident, $after:expr) => {{
            let value = match $parse(body.document.clone()) {
                Ok(value) => value,
                Err(message) => return HttpResponse::BadRequest().json(json!({"success": false, "message": message})),
            };
            let revision = match persist(pool.get_ref(), $namespace, body.expected_revision, &value, &body.change_reason, user.id).await {
                Ok(revision) => revision,
                Err(PersistError::Conflict) => return HttpResponse::Conflict().json(json!({"success": false, "message": "配置已被其他管理员更新，请重新加载后再保存"})),
                Err(error) => {
                    error!(
                        event = "SaveRuntimeConfigError",
                        operation = "persist_runtime_configuration",
                        error_kind = "database",
                        error_code = "runtime_configuration_persist_failed",
                        error_message = %error,
                        retryable = false,
                        outcome = "request_failed",
                        namespace = $namespace,
                        expected_revision = body.expected_revision,
                    );
                    return HttpResponse::InternalServerError().json(json!({"success": false, "message": "保存运行时配置失败"}));
                }
            };
            settings.$target.replace(value.clone(), revision).await;
            $after(&value);
            let mut event = AuditEvent::user("configuration", "runtime_config_update", "success", &user)
                .resource("setting", $namespace);
            event.response_status = Some(200);
            event.metadata = json!({"namespace": $namespace, "revision": revision, "change_reason": body.change_reason});
            write_standalone(pool.get_ref(), &AuditContext::from_request(&req), &event).await;
            return HttpResponse::Ok().json(json!({"success": true, "data": RuntimeConfigResponse { namespace: $namespace, revision, document: value }}));
        }};
    }

    match namespace.as_str() {
        STATISTICS_CACHE_NAMESPACE => publish!(
            STATISTICS_CACHE_NAMESPACE,
            parse_statistics_cache,
            statistics_cache,
            |value: &crate::statistics::CacheConfig| statistics
                .apply(value.clone(), body.expected_revision + 1)
        ),
        GENERAL_NAMESPACE => publish!(
            GENERAL_NAMESPACE,
            parse_general,
            general,
            |value: &crate::system_time::GeneralSettings| {
                // The runtime snapshot already contains the published revision.
                crate::system_time::apply(value.clone(), body.expected_revision + 1);
            }
        ),
        SCANNER_HEALTH_NAMESPACE => publish!(
            SCANNER_HEALTH_NAMESPACE,
            parse_scanner_health,
            scanner_health,
            |_| {}
        ),
        REQUESTS_NAMESPACE => publish!(REQUESTS_NAMESPACE, parse_requests, requests, |_| {}),
        MONITOR_NAMESPACE => publish!(
            MONITOR_NAMESPACE,
            parse_monitor,
            monitor,
            |value: &crate::config::MonitorConfig| monitor
                .replace_config(value.clone(), body.expected_revision + 1)
        ),
        SCAN_ROUTING_NAMESPACE => publish!(
            SCAN_ROUTING_NAMESPACE,
            parse_scan_routing,
            scan_routing,
            |_| {}
        ),
        AUTOMATIC_TARGET_NAMESPACE => publish!(
            AUTOMATIC_TARGET_NAMESPACE,
            parse_automatic_target,
            automatic_target,
            |_| {}
        ),
        DNS_FOLLOW_UP_NAMESPACE => publish!(
            DNS_FOLLOW_UP_NAMESPACE,
            parse_dns_follow_up,
            dns_follow_up,
            |_| {}
        ),
        DNS_RESOLVERS_NAMESPACE => publish!(
            DNS_RESOLVERS_NAMESPACE,
            parse_dns_resolvers,
            dns_resolvers,
            |_| {}
        ),
        REPORT_MAIL_NAMESPACE => publish!(
            REPORT_MAIL_NAMESPACE,
            parse_report_mail,
            report_mail,
            |_| {}
        ),
        ANALYTICS_SNAPSHOT_NAMESPACE => publish!(
            ANALYTICS_SNAPSHOT_NAMESPACE,
            parse_analytics_snapshot,
            analytics_snapshot,
            |_| {}
        ),
        _ => {
            HttpResponse::NotFound().json(json!({"success": false, "message": "未知运行时配置域"}))
        }
    }
}

/// 用于启动加载 RIR 数据
#[cfg(feature = "rir")]
#[get("/api/updaterir")]
async fn update_rir(pool: web::Data<deadpool_postgres::Pool>) -> impl Responder {
    let c = pool.get_ref();
    get_rir_data(c, "/home/wsj/project/RIR-DATA").await;
    HttpResponse::Ok().body("成功")
}

/// 获取配置
///
#[get("/api/config/get")]
async fn get_config_h(
    _req: HttpRequest,
    conf_q: web::Query<GetConfig>,
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
) -> impl Responder {
    if user_base_i.role != 1 {
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以读取系统配置"
        }));
    }
    let pool_ref = pool.get_ref();

    let mut con =
        match get_config_from_database(pool_ref, &conf_q.item_type, conf_q.key.as_deref()).await {
            Ok(o) => o,
            Err(e) => {
                error!(
                    event = "GetConfigError",
                    operation = "load_legacy_configuration",
                    error_kind = "database",
                    error_code = "legacy_configuration_load_failed",
                    error_message = %e,
                    retryable = false,
                    outcome = "request_failed",
                    config_item_type = %conf_q.item_type,
                    config_key_present = conf_q.key.is_some(),
                );
                return HttpResponse::InternalServerError().finish();
            }
        };
    for config in &mut con {
        if config.item_type == "smtp" && config.key == "sender_key" {
            config.value.clear();
        }
    }
    HttpResponse::Ok().json(con)
}

fn validate_mail_settings(
    test_recipient: &str,
    smtp_host: &str,
    smtp_port: u16,
    sender: &str,
    sender_key: &str,
) -> Result<(), &'static str> {
    if test_recipient.trim().parse::<Mailbox>().is_err() {
        return Err("测试收件人邮箱格式不正确");
    }
    let smtp_host = smtp_host.trim();
    if smtp_host.is_empty()
        || smtp_host.len() > 255
        || smtp_host.chars().any(|character| character.is_control())
    {
        return Err("邮件服务器地址不正确");
    }
    if smtp_port == 0 {
        return Err("邮件服务器端口必须在 1 到 65535 之间");
    }
    if sender.trim().parse::<Mailbox>().is_err() {
        return Err("发件人邮箱格式不正确");
    }
    if sender_key.len() > 4096 {
        return Err("发件邮箱密钥过长");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use actix_web::{App, HttpMessage, http::StatusCode, test as actix_test, web};
    use serde_json::{Value, json};

    use super::{get_server_config_h, validate_mail_settings};
    use crate::{admin::UserBaseI, config::ServerConfig};

    fn test_server_config() -> ServerConfig {
        ServerConfig {
            host: "127.0.0.1".to_owned(),
            port: 9443,
            encrypt_key: "test".to_owned(),
            max_body_size: 1024,
        }
    }

    fn test_user(role: i32) -> UserBaseI {
        UserBaseI {
            id: 1,
            username: "tester".to_owned(),
            role,
            email: None,
            limit_login: false,
            enable_2fa: false,
        }
    }

    #[actix_web::test]
    async fn server_config_returns_only_read_only_listen_fields_for_admin() {
        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(test_server_config()))
                .service(get_server_config_h),
        )
        .await;
        let request = actix_test::TestRequest::get()
            .uri("/api/config/server")
            .to_request();
        request.extensions_mut().insert(test_user(1));

        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = actix_test::read_body_json(response).await;
        assert_eq!(
            body,
            json!({
                "success": true,
                "data": { "host": "127.0.0.1", "port": 9443 }
            })
        );
    }

    #[actix_web::test]
    async fn server_config_rejects_non_admin_users() {
        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(test_server_config()))
                .service(get_server_config_h),
        )
        .await;
        let request = actix_test::TestRequest::get()
            .uri("/api/config/server")
            .to_request();
        request.extensions_mut().insert(test_user(0));

        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn valid_mail_settings_are_accepted() {
        assert!(
            validate_mail_settings(
                "security@example.com",
                "smtp.example.com",
                465,
                "scanner@example.com",
                "app-password",
            )
            .is_ok()
        );
    }

    #[test]
    fn invalid_mail_settings_are_rejected() {
        assert!(
            validate_mail_settings(
                "not-an-email",
                "smtp.example.com",
                465,
                "scanner@example.com",
                "app-password",
            )
            .is_err()
        );
        assert!(
            validate_mail_settings(
                "security@example.com",
                "smtp.example.com",
                0,
                "scanner@example.com",
                "app-password",
            )
            .is_err()
        );
    }
}

#[get("/api/config/mail")]
async fn get_mail_settings_h(
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
) -> impl Responder {
    if user_base_i.role != 1 {
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以读取邮件配置"
        }));
    }
    match get_mail_settings_from_database(pool.get_ref()).await {
        Ok(settings) => HttpResponse::Ok().json(json!({
            "success": true,
            "data": settings
        })),
        Err(error_value) => {
            error!(
                event = "GetMailSettingsError",
                operation = "load_mail_settings",
                error_kind = "database",
                error_code = "mail_settings_load_failed",
                error_message = %error_value,
                retryable = false,
                outcome = "request_failed",
                namespace = "mail",
            );
            HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "邮件配置暂时无法读取"
            }))
        }
    }
}

#[get("/api/config/security/session")]
async fn get_session_settings_h(
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
) -> impl Responder {
    if user_base_i.role != 1 {
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以读取会话策略"
        }));
    }
    match get_session_settings_from_database(pool.get_ref()).await {
        Ok(settings) => HttpResponse::Ok().json(json!({
            "success": true,
            "data": settings
        })),
        Err(error_value) => {
            error!(
                event = "GetSessionSettingsError",
                operation = "load_session_settings",
                error_kind = "database",
                error_code = "session_settings_load_failed",
                error_message = %error_value,
                retryable = false,
                outcome = "request_failed",
                namespace = "session",
            );
            HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "会话策略暂时无法读取"
            }))
        }
    }
}

#[post("/api/config/security/session")]
async fn save_session_settings_h(
    req: HttpRequest,
    settings: web::Json<SessionSettingsRequest>,
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
    user_session: UserSession,
) -> impl Responder {
    if user_base_i.role != 1 {
        let mut audit_event = AuditEvent::user(
            "configuration",
            "configuration.session_policy_update",
            "failure",
            &user_base_i,
        );
        audit_event.response_status = Some(403);
        audit_event.reason_code = Some("insufficient_role".to_owned());
        write_standalone(
            pool.get_ref(),
            &AuditContext::from_request(&req),
            &audit_event,
        )
        .await;
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以修改会话策略"
        }));
    }
    if let Err(message) = session_ttl_seconds_from_minutes(settings.session_ttl_minutes) {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": message
        }));
    }

    match write_session_settings_to_database(pool.get_ref(), &settings, &user_session.session).await
    {
        Ok(saved_settings) => {
            let mut audit_event = AuditEvent::user(
                "configuration",
                "configuration.session_policy_update",
                "success",
                &user_base_i,
            )
            .resource("setting", "security.session_ttl_seconds");
            audit_event.response_status = Some(200);
            audit_event.changes = Some(json!({
                "session_ttl_minutes": saved_settings.session_ttl_minutes,
                "invalidate_other_sessions": settings.invalidate_other_sessions,
                "invalidated_session_count": saved_settings.invalidated_session_count
            }));
            write_standalone(
                pool.get_ref(),
                &AuditContext::from_request(&req),
                &audit_event,
            )
            .await;
            HttpResponse::Ok().json(json!({
                "success": true,
                "message": "会话策略已保存",
                "data": saved_settings
            }))
        }
        Err(error_value) => {
            error!(
                event = "SaveSessionSettingsError",
                operation = "save_session_settings",
                error_kind = "database",
                error_code = "session_settings_save_failed",
                error_message = %error_value,
                retryable = false,
                outcome = "settings_unchanged",
                namespace = "session",
            );
            HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "会话策略保存失败"
            }))
        }
    }
}

#[get("/api/config/security/trusted-proxies")]
async fn get_trusted_proxy_settings_h(
    trusted_proxies: web::Data<TrustedProxyState>,
    user_base_i: UserBaseI,
) -> impl Responder {
    if user_base_i.role != 1 {
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以读取可信代理配置"
        }));
    }
    HttpResponse::Ok().json(json!({
        "success": true,
        "data": trusted_proxies.settings().await,
        "limits": {
            "maximumCidrs": MAX_TRUSTED_PROXY_CIDRS,
            "maximumHeaderNameLength": MAX_CLIENT_IP_HEADER_LENGTH,
            "supportsCustomHeader": true
        }
    }))
}

#[post("/api/config/security/trusted-proxies")]
async fn save_trusted_proxy_settings_h(
    req: HttpRequest,
    settings: web::Json<TrustedProxySettings>,
    pool: web::Data<deadpool_postgres::Pool>,
    trusted_proxies: web::Data<TrustedProxyState>,
    user_base_i: UserBaseI,
) -> impl Responder {
    if user_base_i.role != 1 {
        let mut audit_event = AuditEvent::user(
            "configuration",
            "configuration.trusted_proxies_update",
            "failure",
            &user_base_i,
        );
        audit_event.response_status = Some(403);
        audit_event.reason_code = Some("insufficient_role".to_owned());
        write_standalone(
            pool.get_ref(),
            &AuditContext::from_request(&req),
            &audit_event,
        )
        .await;
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以修改可信代理配置"
        }));
    }

    let validated = match validate_settings(settings.into_inner()) {
        Ok(settings) => settings,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({
                "success": false,
                "message": message
            }));
        }
    };
    let saved_settings = validated.settings.clone();
    if let Err(error_value) = write_settings_to_database(pool.get_ref(), &saved_settings).await {
        error!(
            event = "SaveTrustedProxySettingsError",
            operation = "save_trusted_proxy_settings",
            error_kind = "database",
            error_code = "trusted_proxy_settings_save_failed",
            error_message = %error_value,
            retryable = false,
            outcome = "settings_unchanged",
            namespace = "trusted_proxy",
        );
        return HttpResponse::InternalServerError().json(json!({
            "success": false,
            "message": "可信代理配置保存失败"
        }));
    }
    trusted_proxies.replace(validated).await;

    let mut audit_event = AuditEvent::user(
        "configuration",
        "configuration.trusted_proxies_update",
        "success",
        &user_base_i,
    )
    .resource("setting", "network.trusted_proxies");
    audit_event.response_status = Some(200);
    audit_event.changes = Some(json!({
        "trusted_proxy_cidrs": &saved_settings.trusted_proxy_cidrs,
        "client_ip_header": &saved_settings.client_ip_header
    }));
    write_standalone(
        pool.get_ref(),
        &AuditContext::from_request(&req),
        &audit_event,
    )
    .await;

    HttpResponse::Ok().json(json!({
        "success": true,
        "message": "可信代理配置已保存并立即生效",
        "data": saved_settings,
        "limits": {
            "maximumCidrs": MAX_TRUSTED_PROXY_CIDRS,
            "maximumHeaderNameLength": MAX_CLIENT_IP_HEADER_LENGTH,
            "supportsCustomHeader": true
        }
    }))
}

#[get("/api/config/scan")]
async fn get_scan_settings_h(
    pool: web::Data<deadpool_postgres::Pool>,
    _user_base_i: UserBaseI,
) -> impl Responder {
    match get_scan_settings_from_database(pool.get_ref()).await {
        Ok(settings) => HttpResponse::Ok().json(json!({
            "success": true,
            "data": settings
        })),
        Err(error_value) => {
            error!(
                event = "GetScanSettingsError",
                operation = "load_scan_settings",
                error_kind = "database",
                error_code = "scan_settings_load_failed",
                error_message = %error_value,
                retryable = false,
                outcome = "request_failed",
                namespace = "scan",
            );
            HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "扫描设置暂时无法读取"
            }))
        }
    }
}

#[post("/api/config/scan")]
async fn save_scan_settings_h(
    req: HttpRequest,
    settings: web::Json<ScanSettingsRequest>,
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
) -> impl Responder {
    if user_base_i.role != 1 {
        let mut audit_event = AuditEvent::user(
            "configuration",
            "configuration.scan_settings_update",
            "failure",
            &user_base_i,
        );
        audit_event.response_status = Some(403);
        audit_event.reason_code = Some("insufficient_role".to_owned());
        write_standalone(
            pool.get_ref(),
            &AuditContext::from_request(&req),
            &audit_event,
        )
        .await;
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以修改扫描设置"
        }));
    }
    let requested_profile = settings.default_scan_profile.trim().to_lowercase();
    if !crate::scan_control::creation::is_ip_scan_profile(&requested_profile) {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "不支持的默认扫描模式"
        }));
    }

    match write_scan_settings_to_database(pool.get_ref(), &settings).await {
        Ok(saved_settings) => {
            let mut audit_event = AuditEvent::user(
                "configuration",
                "configuration.scan_settings_update",
                "success",
                &user_base_i,
            )
            .resource("setting", "scan.default_profile");
            audit_event.response_status = Some(200);
            audit_event.changes = Some(json!({
                "default_scan_profile": saved_settings.default_scan_profile
            }));
            write_standalone(
                pool.get_ref(),
                &AuditContext::from_request(&req),
                &audit_event,
            )
            .await;
            HttpResponse::Ok().json(json!({
                "success": true,
                "message": "扫描设置已保存",
                "data": saved_settings
            }))
        }
        Err(error_value) => {
            error!(
                event = "SaveScanSettingsError",
                operation = "save_scan_settings",
                error_kind = "database",
                error_code = "scan_settings_save_failed",
                error_message = %error_value,
                retryable = false,
                outcome = "settings_unchanged",
                namespace = "scan",
            );
            HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "扫描设置保存失败"
            }))
        }
    }
}

#[post("/api/config/mail")]
async fn save_mail_settings_h(
    req: HttpRequest,
    settings: web::Json<MailSettingsRequest>,
    pool: web::Data<deadpool_postgres::Pool>,
    server_config: web::Data<ServerConfig>,
    user_base_i: UserBaseI,
) -> impl Responder {
    if user_base_i.role != 1 {
        let mut audit_event = AuditEvent::user(
            "configuration",
            "configuration.mail_update",
            "failure",
            &user_base_i,
        );
        audit_event.response_status = Some(403);
        audit_event.reason_code = Some("insufficient_role".to_owned());
        write_standalone(
            pool.get_ref(),
            &AuditContext::from_request(&req),
            &audit_event,
        )
        .await;
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以修改邮件配置"
        }));
    }
    if let Err(message) = validate_mail_settings(
        &settings.recipient,
        &settings.smtp_host,
        settings.smtp_port,
        &settings.sender,
        &settings.sender_key,
    ) {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": message
        }));
    }
    if settings.sender_key.is_empty() {
        match get_mail_sender_key_from_database(pool.get_ref(), &server_config.encrypt_key).await {
            Ok(Some(_)) => (),
            Ok(None) => {
                return HttpResponse::BadRequest().json(json!({
                    "success": false,
                    "message": "首次保存时必须填写发件邮箱密钥"
                }));
            }
            Err(error_value) => {
                error!(
                    event = "ReadMailSecretError",
                    operation = "read_existing_mail_secret",
                    error_kind = "secret_storage",
                    error_code = "mail_secret_read_failed",
                    error_message = %error_value,
                    retryable = false,
                    outcome = "settings_unchanged",
                    namespace = "mail",
                );
                return HttpResponse::InternalServerError().json(json!({
                    "success": false,
                    "message": "已保存的邮箱密钥无法读取"
                }));
            }
        }
    }

    if let Err(error_value) =
        write_mail_settings_to_database(pool.get_ref(), &settings, &server_config.encrypt_key).await
    {
        error!(
            event = "SaveMailSettingsError",
            operation = "save_mail_settings",
            error_kind = "database",
            error_code = "mail_settings_save_failed",
            error_message = %error_value,
            retryable = false,
            outcome = "settings_unchanged",
            namespace = "mail",
        );
        return HttpResponse::InternalServerError().json(json!({
            "success": false,
            "message": "邮件配置保存失败"
        }));
    }

    let saved_settings = match get_mail_settings_from_database(pool.get_ref()).await {
        Ok(saved_settings) => saved_settings,
        Err(error_value) => {
            error!(
                event = "ReloadMailSettingsError",
                operation = "reload_mail_settings",
                error_kind = "database",
                error_code = "mail_settings_reload_failed",
                error_message = %error_value,
                retryable = false,
                outcome = "settings_saved_runtime_state_stale",
                namespace = "mail",
            );
            return HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "邮件配置已写入，但重新读取失败"
            }));
        }
    };
    let mut audit_event = AuditEvent::user(
        "configuration",
        "configuration.mail_update",
        "success",
        &user_base_i,
    )
    .resource("setting", "smtp");
    audit_event.response_status = Some(200);
    audit_event.changes = Some(json!({
        "test_recipient": &saved_settings.recipient,
        "smtp_host": &saved_settings.smtp_host,
        "smtp_port": saved_settings.smtp_port,
        "sender": &saved_settings.sender,
        "sender_key_changed": !settings.sender_key.is_empty(),
        "notification_preferences": &saved_settings.notification_prefs
    }));
    write_standalone(
        pool.get_ref(),
        &AuditContext::from_request(&req),
        &audit_event,
    )
    .await;

    HttpResponse::Ok().json(json!({
        "success": true,
        "message": "邮件配置已保存",
        "data": saved_settings
    }))
}

/// 测试 SMTP 邮件服务器
#[post("/api/mail/smtp/test")]
async fn test_mail_server_h(
    req: HttpRequest,
    test_data: web::Json<MailTestRequest>,
    server_config: web::Data<ServerConfig>,
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
) -> impl Responder {
    let pool_ref = pool.get_ref();
    let u_role = user_base_i.role;

    if u_role != 1 {
        info_logs(
            &req,
            "UserPermissionDenied",
            "用户权限不足，操作请求已被拒绝。",
        );
        return HttpResponse::Forbidden().finish();
    }

    if let Err(message) = validate_mail_settings(
        &test_data.recipient,
        &test_data.smtp_host,
        test_data.smtp_port,
        &test_data.sender,
        &test_data.sender_key,
    ) {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": message
        }));
    }
    let sender_key = if test_data.sender_key.is_empty() {
        match get_mail_sender_key_from_database(pool_ref, &server_config.encrypt_key).await {
            Ok(Some(sender_key)) => sender_key,
            Ok(None) => {
                return HttpResponse::BadRequest().json(json!({
                    "success": false,
                    "message": "请填写发件邮箱密钥，或先保存邮件配置"
                }));
            }
            Err(error_value) => {
                error!(
                    event = "ReadMailSecretError",
                    operation = "read_mail_secret_for_test",
                    error_kind = "secret_storage",
                    error_code = "mail_secret_read_failed",
                    error_message = %error_value,
                    retryable = false,
                    outcome = "test_not_sent",
                    namespace = "mail",
                );
                return HttpResponse::InternalServerError().json(json!({
                    "success": false,
                    "message": "已保存的邮箱密钥无法读取"
                }));
            }
        }
    } else {
        test_data.sender_key.clone()
    };

    let mail_context = String::from(
        "这是一封测试邮件，用于测试您设置的邮件服务器是否正常工作。如果您没有发送测试邮件请忽略此封邮件。",
    );
    let mail_title = String::from("Test");
    let mail_account_name = Some(String::from("Network Mapping"));

    let mail_config = EmailConfig {
        host: test_data.smtp_host.trim().to_owned(),
        account_username: test_data.sender.trim().to_owned(),
        account_password: sender_key,
    };

    let mail_message = match Message::builder()
        .from(Mailbox::new(
            mail_account_name,
            match mail_config.account_username.parse() {
                Ok(address) => address,
                Err(_) => {
                    return HttpResponse::BadRequest().json(json!({
                        "success": false,
                        "message": "发件人邮箱格式不正确"
                    }));
                }
            },
        ))
        .to(match test_data.recipient.trim().parse::<Mailbox>() {
            Ok(mailbox) => mailbox,
            Err(_) => {
                return HttpResponse::BadRequest().json(json!({
                    "success": false,
                    "message": "测试收件人邮箱格式不正确"
                }));
            }
        })
        .subject(mail_title)
        .message_id(None)
        .header(ContentType::TEXT_PLAIN)
        .body(mail_context)
    {
        Ok(message) => message,
        Err(error_value) => {
            error!(
                event = "BuildTestMailError",
                operation = "build_test_email",
                error_kind = "validation",
                error_code = "test_email_build_failed",
                error_message = %error_value,
                retryable = false,
                outcome = "test_not_sent",
            );
            return HttpResponse::BadRequest().json(json!({
                "success": false,
                "message": "测试邮件内容构造失败"
            }));
        }
    };
    match try_send_email(
        &mail_config,
        test_data.smtp_port,
        mail_message,
        MailRetryPolicy::Interactive,
    )
    .await
    {
        Ok(()) => {
            let mut audit_event = AuditEvent::user(
                "configuration",
                "configuration.mail_test",
                "success",
                &user_base_i,
            )
            .resource("setting", "smtp");
            audit_event.response_status = Some(200);
            audit_event.metadata = json!({"recipient": test_data.recipient.trim()});
            write_standalone(pool_ref, &AuditContext::from_request(&req), &audit_event).await;
            HttpResponse::Ok().json(json!({
                "success": true,
                "message": "测试邮件已发送"
            }))
        }
        Err(error_value) => {
            error!(
                event = "TestMailSendError",
                operation = "send_test_email",
                error_kind = "email_delivery",
                error_code = "test_email_delivery_failed",
                error_message = %error_value,
                attempts = error_value.attempts(),
                retryable = error_value.is_retryable(),
                outcome = "test_not_delivered",
            );
            HttpResponse::BadGateway().json(json!({
                "success": false,
                "message": smtp_send_error_message(&error_value),
                "detail": error_value.to_string()
            }))
        }
    }
}

#[get("/api/system/preferences")]
pub async fn get_system_preferences(
    pool: web::Data<deadpool_postgres::Pool>,
    _user: UserBaseI,
) -> impl Responder {
    match crate::system_time::refresh(pool.get_ref()).await {
        Ok(value) => HttpResponse::Ok().json(json!({"success": true, "data": {"revision": value.revision, "document": value.document}})),
        Err(_) => HttpResponse::ServiceUnavailable().json(json!({"success": false, "message": "系统时间设置暂不可用"})),
    }
}
#[get("/api/system/timezones")]
pub async fn get_system_timezones(_user: UserBaseI) -> impl Responder {
    HttpResponse::Ok()
        .json(json!({"success": true, "data": crate::system_time::timezone_options()}))
}
