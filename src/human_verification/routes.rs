use super::settings::{AdminSettings, ManagedVerification, SettingsError, SettingsInput};
use crate::{admin::UserBaseI, audit::AuditContext};
use actix_web::{HttpRequest, HttpResponse, http::header, web};

pub const SETTINGS_PATH: &str = "/api/config/human-verification";

fn respond(result: Result<AdminSettings, SettingsError>) -> HttpResponse {
    match result {
        Ok(data) => HttpResponse::Ok()
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .json(serde_json::json!({"success":true,"data":data})),
        Err(error) => HttpResponse::build(error.status())
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .json(serde_json::json!({"success":false,"message":error.message()})),
    }
}

async fn read(user: UserBaseI, settings: web::Data<ManagedVerification>) -> HttpResponse {
    if user.role != 1 {
        return HttpResponse::Forbidden().finish();
    }
    respond(settings.read().await)
}

async fn save(
    req: HttpRequest,
    user: UserBaseI,
    settings: web::Data<ManagedVerification>,
    input: web::Json<SettingsInput>,
) -> HttpResponse {
    if user.role != 1 {
        return HttpResponse::Forbidden().finish();
    }
    respond(
        settings
            .save(input.into_inner(), &user, &AuditContext::from_request(&req))
            .await,
    )
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource(SETTINGS_PATH)
            .app_data(web::JsonConfig::default().limit(super::LOGIN_BODY_LIMIT))
            .route(web::get().to(read))
            .route(web::put().to(save)),
    );
}
