use actix_web::{HttpRequest, HttpResponse, Responder, get, post, put, web};
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::json;
use tracing::error;

use crate::admin::{UserBaseI, smtp_send_error_message};
use crate::audit::{AuditContext, AuditEvent, write_standalone};
use crate::config::ServerConfig;
use crate::mail_template::{
    MailTemplateSource, ScannerNotificationState, audit_source_metadata, get_template_detail,
    list_template_versions, list_templates, preview_template, publish_template,
    restore_template_version, save_template_draft, send_template_test, validate_template,
    validation_error_message,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateTestRequest {
    recipient: String,
    source: MailTemplateSource,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateSampleOptions {
    #[serde(default)]
    notification_state: ScannerNotificationState,
}

// Callers immediately return the response, so preserving the unboxed type
// avoids an allocation on authorization failures.
#[allow(clippy::result_large_err)]
fn require_admin(user: &UserBaseI) -> Result<(), HttpResponse> {
    if user.role == 1 {
        Ok(())
    } else {
        Err(HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以管理邮件模板"
        })))
    }
}

fn internal_error(event: &'static str, error_value: &dyn std::error::Error) -> HttpResponse {
    error!(
        event,
        operation = "manage_mail_template",
        error_kind = "application",
        error_code = event,
        error_message = %error_value,
        retryable = false,
        outcome = "request_failed",
    );
    HttpResponse::InternalServerError().json(json!({
        "success": false,
        "message": "邮件模板服务暂时不可用"
    }))
}

#[get("/api/mail/templates")]
pub async fn list_mail_templates(pool: web::Data<Pool>, user: UserBaseI) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    match list_templates(pool.get_ref()).await {
        Ok(templates) => HttpResponse::Ok().json(json!({"success": true, "data": templates})),
        Err(error_value) => internal_error("ListMailTemplatesError", error_value.as_ref()),
    }
}

#[get("/api/mail/templates/{template_key}")]
pub async fn get_mail_template(
    path: web::Path<String>,
    pool: web::Data<Pool>,
    user: UserBaseI,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    match get_template_detail(pool.get_ref(), &path.into_inner()).await {
        Ok(template) => HttpResponse::Ok().json(json!({"success": true, "data": template})),
        Err(error_value) if error_value.to_string() == "未知邮件模板" => {
            HttpResponse::NotFound().json(json!({"success": false, "message": "邮件模板不存在"}))
        }
        Err(error_value) => internal_error("GetMailTemplateError", error_value.as_ref()),
    }
}

#[post("/api/mail/templates/{template_key}/validate")]
pub async fn validate_mail_template(
    path: web::Path<String>,
    source: web::Json<MailTemplateSource>,
    user: UserBaseI,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    match validate_template(&path.into_inner(), &source) {
        Ok(rendered) => HttpResponse::Ok().json(json!({
            "success": true,
            "message": "模板校验通过",
            "data": rendered
        })),
        Err(error_value) => HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": validation_error_message(error_value.as_ref())
        })),
    }
}

#[post("/api/mail/templates/{template_key}/preview")]
pub async fn preview_mail_template(
    path: web::Path<String>,
    source: web::Json<MailTemplateSource>,
    options: web::Query<TemplateSampleOptions>,
    user: UserBaseI,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    match preview_template(&path.into_inner(), &source, options.notification_state) {
        Ok(rendered) => HttpResponse::Ok().json(json!({"success": true, "data": rendered})),
        Err(error_value) => HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": validation_error_message(error_value.as_ref())
        })),
    }
}

#[put("/api/mail/templates/{template_key}/draft")]
pub async fn save_mail_template_draft(
    req: HttpRequest,
    path: web::Path<String>,
    source: web::Json<MailTemplateSource>,
    pool: web::Data<Pool>,
    user: UserBaseI,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    let template_key = path.into_inner();
    match save_template_draft(pool.get_ref(), &template_key, &source, user.id).await {
        Ok(template) => {
            let mut event = AuditEvent::user(
                "configuration",
                "configuration.mail_template_draft_save",
                "success",
                &user,
            )
            .resource("mail_template", &template_key);
            event.response_status = Some(200);
            event.metadata = audit_source_metadata(&source);
            write_standalone(pool.get_ref(), &AuditContext::from_request(&req), &event).await;
            HttpResponse::Ok().json(json!({
                "success": true,
                "message": "模板草稿已保存",
                "data": template
            }))
        }
        Err(error_value) => HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": validation_error_message(error_value.as_ref())
        })),
    }
}

#[post("/api/mail/templates/{template_key}/publish")]
pub async fn publish_mail_template(
    req: HttpRequest,
    path: web::Path<String>,
    pool: web::Data<Pool>,
    user: UserBaseI,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    let template_key = path.into_inner();
    match publish_template(pool.get_ref(), &template_key).await {
        Ok(template) => {
            let mut event = AuditEvent::user(
                "configuration",
                "configuration.mail_template_publish",
                "success",
                &user,
            )
            .resource("mail_template", &template_key);
            event.response_status = Some(200);
            event.metadata = json!({"active_version": template.active_version});
            write_standalone(pool.get_ref(), &AuditContext::from_request(&req), &event).await;
            HttpResponse::Ok().json(json!({
                "success": true,
                "message": "邮件模板已发布",
                "data": template
            }))
        }
        Err(error_value) => HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": validation_error_message(error_value.as_ref())
        })),
    }
}

#[get("/api/mail/templates/{template_key}/versions")]
pub async fn get_mail_template_versions(
    path: web::Path<String>,
    pool: web::Data<Pool>,
    user: UserBaseI,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    match list_template_versions(pool.get_ref(), &path.into_inner()).await {
        Ok(versions) => HttpResponse::Ok().json(json!({"success": true, "data": versions})),
        Err(error_value) if error_value.to_string() == "未知邮件模板" => {
            HttpResponse::NotFound().json(json!({"success": false, "message": "邮件模板不存在"}))
        }
        Err(error_value) => internal_error("GetMailTemplateVersionsError", error_value.as_ref()),
    }
}

#[post("/api/mail/templates/{template_key}/versions/{version}/restore")]
pub async fn restore_mail_template_version(
    req: HttpRequest,
    path: web::Path<(String, i32)>,
    pool: web::Data<Pool>,
    user: UserBaseI,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    let (template_key, version) = path.into_inner();
    match restore_template_version(pool.get_ref(), &template_key, version, user.id).await {
        Ok(template) => {
            let mut event = AuditEvent::user(
                "configuration",
                "configuration.mail_template_restore",
                "success",
                &user,
            )
            .resource("mail_template", &template_key);
            event.response_status = Some(200);
            event.metadata = json!({"restored_version": version});
            write_standalone(pool.get_ref(), &AuditContext::from_request(&req), &event).await;
            HttpResponse::Ok().json(json!({
                "success": true,
                "message": "历史版本已恢复为草稿",
                "data": template
            }))
        }
        Err(error_value) => HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": validation_error_message(error_value.as_ref())
        })),
    }
}

#[post("/api/mail/templates/{template_key}/test")]
pub async fn test_mail_template(
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<TemplateTestRequest>,
    options: web::Query<TemplateSampleOptions>,
    pool: web::Data<Pool>,
    server_config: web::Data<ServerConfig>,
    user: UserBaseI,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    let template_key = path.into_inner();
    if body
        .recipient
        .trim()
        .parse::<lettre::message::Mailbox>()
        .is_err()
    {
        return HttpResponse::BadRequest()
            .json(json!({"success": false, "message": "测试收件人邮箱格式不正确"}));
    }
    match send_template_test(
        pool.get_ref(),
        &server_config.encrypt_key,
        &template_key,
        body.recipient.trim(),
        &body.source,
        options.notification_state,
    )
    .await
    {
        Ok(()) => {
            let mut event = AuditEvent::user(
                "configuration",
                "configuration.mail_template_test",
                "success",
                &user,
            )
            .resource("mail_template", &template_key);
            event.response_status = Some(200);
            event.metadata = json!({"recipient": body.recipient.trim()});
            write_standalone(pool.get_ref(), &AuditContext::from_request(&req), &event).await;
            HttpResponse::Ok().json(json!({"success": true, "message": "模板测试邮件已发送"}))
        }
        Err(error_value) => {
            error!(
                event = "TestMailTemplateError",
                operation = "send_mail_template_test",
                error_kind = "email_delivery",
                error_code = "mail_template_test_failed",
                error_message = %error_value,
                retryable = false,
                outcome = "request_failed",
                user_id = user.id,
                template_key,
            );
            HttpResponse::BadGateway().json(json!({
                "success": false,
                "message": smtp_send_error_message(error_value.as_ref()),
                "detail": error_value.to_string()
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ScannerNotificationState, TemplateSampleOptions};

    #[test]
    fn sample_options_default_to_offline_and_reject_unknown_states() {
        let defaults: TemplateSampleOptions = serde_json::from_str("{}").unwrap();
        assert!(matches!(
            defaults.notification_state,
            ScannerNotificationState::Offline
        ));
        let recovered: TemplateSampleOptions =
            serde_json::from_str(r#"{"notificationState":"recovered"}"#).unwrap();
        assert!(matches!(
            recovered.notification_state,
            ScannerNotificationState::Recovered
        ));
        assert!(
            serde_json::from_str::<TemplateSampleOptions>(r#"{"notificationState":"invalid"}"#)
                .is_err()
        );
    }
}
