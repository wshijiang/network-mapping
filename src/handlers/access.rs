use actix_web::{HttpRequest, HttpResponse, get, post, put, web};
use deadpool_postgres::Pool;
use serde_json::{Value, json};

use crate::access::{self, Access, Permission, Target, Update, UpdateError};
use crate::admin::UserBaseI;
use crate::audit::AuditContext;
use crate::open_api::{console, response};

pub(crate) fn update_error(error: UpdateError) -> HttpResponse {
    let message = json!({"success":false,"message":error.to_string()});
    match error {
        UpdateError::Missing => HttpResponse::NotFound().json(message),
        UpdateError::Conflict => HttpResponse::Conflict().json(message),
        UpdateError::Quota => HttpResponse::TooManyRequests().json(message),
        UpdateError::Forbidden => HttpResponse::Forbidden().json(message),
        UpdateError::Invalid(_) => HttpResponse::BadRequest().json(message),
        _ => {
            tracing::error!(%error, "user access management failed");
            HttpResponse::InternalServerError()
                .json(json!({"success":false,"message":"权限管理暂不可用"}))
        }
    }
}

#[get("/api/access")]
pub(crate) async fn current(req: HttpRequest) -> HttpResponse {
    let Some(access) = Access::from_request(&req) else {
        return HttpResponse::Unauthorized().finish();
    };
    use Permission::*;
    HttpResponse::Ok()
        .insert_header(("Cache-Control", "private, no-store"))
        .json(json!({"success":true,"data":{
            "role":access.role,
            "read_results":access.allows(ReadResults),
            "create_scan":access.allows(CreateScan),
            "cancel_scan":access.allows(CancelScan),
            "retry_scan":access.allows(RetryScan),
            "export_results":access.allows(ExportResults),
            "read_audit":access.allows(ReadAudit),
            "export_audit":access.allows(ExportAudit),
            "legacy_user":access.legacy_user(),
            "profiles":access.policy.as_ref().map(|p| &p.profiles),
            "max_priority":access.policy.as_ref().map(|p| p.max_priority),
        }}))
}

#[post("/api/access/verify")]
pub(crate) async fn verify(
    req: HttpRequest,
    pool: web::Data<Pool>,
    body: web::Json<Value>,
    user: UserBaseI,
) -> HttpResponse {
    if user.role != access::ADMIN
        && !Access::from_request(&req).is_some_and(|a| a.allows(Permission::ExportAudit))
    {
        return HttpResponse::Forbidden().finish();
    }
    response(&req, console::step_up(&req, &pool, &user, &body).await)
}

#[get("/api/admin/users/{user_id}/access")]
pub(crate) async fn get_user_access(
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<i32>,
) -> HttpResponse {
    if user.role != access::ADMIN {
        return HttpResponse::Forbidden().finish();
    }
    let client = match pool.get().await {
        Ok(client) => client,
        Err(error) => return update_error(error.into()),
    };
    match access::load(&client, Target::Id(*id)).await {
        Ok(access) => HttpResponse::Ok().json(json!({"success":true,"data":access})),
        Err(error) => update_error(error),
    }
}

#[put("/api/admin/users/{user_id}/access")]
pub(crate) async fn put_user_access(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<i32>,
    body: web::Json<Update>,
) -> HttpResponse {
    if user.role != access::ADMIN {
        return HttpResponse::Forbidden().finish();
    }
    if let Err(error) = console::require_step_up(&req, &pool, &user).await {
        return response(&req, Err(error));
    }
    match access::update(
        &pool,
        Target::Id(*id),
        body.into_inner(),
        Some(&user),
        &AuditContext::from_request(&req),
    )
    .await
    {
        Ok(access) => HttpResponse::Ok().json(json!({"success":true,"data":access})),
        Err(error) => update_error(error),
    }
}
