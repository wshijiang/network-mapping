use super::*;
use crate::config::ServerConfig;
use actix_web::{HttpRequest, HttpResponse, delete, get, post, put, web};

fn respond<T: Serialize>(result: Result<T>) -> HttpResponse {
    match result {
        Ok(data) => HttpResponse::Ok().json(json!({"success":true,"data":data})),
        Err(error) => {
            HttpResponse::build(error.status).json(json!({"success":false,"message":error.message}))
        }
    }
}
#[allow(clippy::result_large_err)]
fn admin(user: &UserBaseI) -> std::result::Result<(), HttpResponse> {
    if user.role == 1 {
        Ok(())
    } else {
        Err(HttpResponse::Forbidden()
            .json(json!({"success":false,"message":"仅管理员可以管理通知渠道"})))
    }
}

#[get("/channels")]
async fn channels(pool: web::Data<Pool>, user: UserBaseI) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    respond(list(&pool).await)
}
#[post("/channels")]
async fn create(
    req: HttpRequest,
    pool: web::Data<Pool>,
    config: web::Data<ServerConfig>,
    user: UserBaseI,
    input: web::Json<ChannelInput>,
) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    respond(
        save(
            &pool,
            &config.encrypt_key,
            None,
            input.into_inner(),
            &user,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}
#[put("/channels/{id}")]
async fn update(
    req: HttpRequest,
    pool: web::Data<Pool>,
    config: web::Data<ServerConfig>,
    user: UserBaseI,
    id: web::Path<Uuid>,
    input: web::Json<ChannelInput>,
) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    respond(
        save(
            &pool,
            &config.encrypt_key,
            Some(id.into_inner()),
            input.into_inner(),
            &user,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}
#[derive(Deserialize)]
struct Revision {
    expected_revision: i64,
}

#[post("/channels/{id}/feishu-binding")]
async fn issue_feishu_binding(
    req: HttpRequest,
    pool: web::Data<Pool>,
    config: web::Data<ServerConfig>,
    user: UserBaseI,
    id: web::Path<Uuid>,
    revision: web::Json<Revision>,
) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    let response = respond(
        super::feishu_binding::issue(
            &pool,
            &config.encrypt_key,
            id.into_inner(),
            revision.expected_revision,
            &user,
            &AuditContext::from_request(&req),
        )
        .await,
    );
    let mut response = response;
    response.headers_mut().insert(
        actix_web::http::header::CACHE_CONTROL,
        actix_web::http::header::HeaderValue::from_static("no-store"),
    );
    response
}

#[get("/channels/{id}/feishu-binding")]
async fn feishu_binding_status(
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    let mut response = respond(super::feishu_binding::status(&pool, id.into_inner()).await);
    response.headers_mut().insert(
        actix_web::http::header::CACHE_CONTROL,
        actix_web::http::header::HeaderValue::from_static("no-store"),
    );
    response
}

#[delete("/channels/{id}/feishu-binding")]
async fn cancel_feishu_binding(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    respond(
        super::feishu_binding::cancel(
            &pool,
            id.into_inner(),
            &user,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}

#[delete("/channels/{id}/feishu-binding/recipient")]
async fn remove_feishu_binding_recipient(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
    revision: web::Json<Revision>,
) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    respond(
        super::feishu_binding::unbind(
            &pool,
            id.into_inner(),
            revision.expected_revision,
            &user,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}
#[delete("/channels/{id}")]
async fn destroy(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
    revision: web::Json<Revision>,
) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    respond(
        remove(
            &pool,
            id.into_inner(),
            revision.expected_revision,
            &user,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}
#[post("/channels/{id}/test")]
async fn test(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    match test_send(
        &pool,
        id.into_inner(),
        &user,
        &AuditContext::from_request(&req),
    )
    .await
    {
        Ok(id) => HttpResponse::Accepted().json(json!({"success":true,"data":{"delivery_id":id}})),
        Err(error) => respond::<()>(Err(error)),
    }
}
#[get("/deliveries")]
async fn history(
    pool: web::Data<Pool>,
    user: UserBaseI,
    query: web::Query<DeliveryQuery>,
) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    respond(deliveries(&pool, query.into_inner()).await)
}
#[post("/deliveries/{id}/retry")]
async fn retry_delivery(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    respond(
        retry(
            &pool,
            id.into_inner(),
            &user,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}
#[get("/deliveries/{id}")]
async fn delivery_detail(
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    respond(super::delivery_detail(&pool, id.into_inner()).await)
}
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/notifications")
            .app_data(
                web::JsonConfig::default()
                    .limit(16 * 1024)
                    .error_handler(|_, _| {
                        actix_web::error::InternalError::from_response(
                            "invalid_notification_payload",
                            HttpResponse::BadRequest().json(
                                json!({"success":false,"message":"通知请求格式无效或超过 16 KiB"}),
                            ),
                        )
                        .into()
                    }),
            )
            .service(channels)
            .configure(templates::configure)
            .service(create)
            .service(update)
            .service(issue_feishu_binding)
            .service(feishu_binding_status)
            .service(cancel_feishu_binding)
            .service(remove_feishu_binding_recipient)
            .service(destroy)
            .service(test)
            .service(history)
            .service(delivery_detail)
            .service(retry_delivery),
    );
}
