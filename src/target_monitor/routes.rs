//! 目标监控 HTTP 接口（/api/target-monitor）。
use super::rules::{self, Result, RuleInput};
use crate::admin::UserBaseI;
use crate::audit::AuditContext;
use crate::runtime_config::RuntimeSettings;
use actix_web::{HttpRequest, HttpResponse, delete, get, post, put, web};
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

fn respond<T: serde::Serialize>(result: Result<T>) -> HttpResponse {
    match result {
        Ok(data) => HttpResponse::Ok().json(json!({"success":true,"data":data})),
        Err(error) => {
            HttpResponse::build(error.status).json(json!({"success":false,"message":error.message}))
        }
    }
}

#[get("/rules")]
async fn list_rules(pool: web::Data<Pool>, user: UserBaseI) -> HttpResponse {
    respond(rules::list(&pool, &user).await)
}

#[post("/rules")]
async fn create_rule(
    req: HttpRequest,
    pool: web::Data<Pool>,
    settings: web::Data<RuntimeSettings>,
    user: UserBaseI,
    input: web::Json<RuleInput>,
) -> HttpResponse {
    respond(
        rules::create(
            &pool,
            &user,
            &settings,
            input.into_inner(),
            &AuditContext::from_request(&req),
        )
        .await,
    )
}

#[put("/rules/{id}")]
async fn update_rule(
    req: HttpRequest,
    pool: web::Data<Pool>,
    settings: web::Data<RuntimeSettings>,
    user: UserBaseI,
    id: web::Path<Uuid>,
    input: web::Json<RuleInput>,
) -> HttpResponse {
    respond(
        rules::update(
            &pool,
            &user,
            &settings,
            id.into_inner(),
            input.into_inner(),
            &AuditContext::from_request(&req),
        )
        .await,
    )
}

#[derive(Deserialize)]
struct Revision {
    expected_revision: i64,
}

#[delete("/rules/{id}")]
async fn delete_rule(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
    revision: web::Json<Revision>,
) -> HttpResponse {
    respond(
        rules::remove(
            &pool,
            &user,
            id.into_inner(),
            revision.into_inner().expected_revision,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}

#[post("/rules/{id}/run")]
async fn run_rule(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    match rules::run_now(
        &pool,
        &user,
        id.into_inner(),
        &AuditContext::from_request(&req),
    )
    .await
    {
        Ok(()) => HttpResponse::Accepted().json(json!({"success":true,"data":{"queued":true}})),
        Err(error) => respond::<()>(Err(error)),
    }
}

#[derive(Deserialize)]
struct RunsQuery {
    before: Option<Uuid>,
}

#[get("/rules/{id}/runs")]
async fn rule_runs(
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
    query: web::Query<RunsQuery>,
) -> HttpResponse {
    respond(rules::runs(&pool, &user, id.into_inner(), query.into_inner().before).await)
}

#[get("/runs/{id}/changes")]
async fn run_changes(pool: web::Data<Pool>, user: UserBaseI, id: web::Path<Uuid>) -> HttpResponse {
    respond(rules::run_changes(&pool, &user, id.into_inner()).await)
}

#[derive(Deserialize)]
struct ChangesQuery {
    rule_id: Option<Uuid>,
    before: Option<Uuid>,
}

#[get("/changes")]
async fn recent_changes(
    pool: web::Data<Pool>,
    user: UserBaseI,
    query: web::Query<ChangesQuery>,
) -> HttpResponse {
    let query = query.into_inner();
    respond(rules::changes(&pool, &user, query.rule_id, query.before).await)
}

#[get("/recipients")]
async fn recipients(pool: web::Data<Pool>, user: UserBaseI) -> HttpResponse {
    respond(rules::recipients(&pool, &user).await)
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/target-monitor")
            .app_data(
                web::JsonConfig::default()
                    .limit(16 * 1024)
                    .error_handler(|_, _| {
                        actix_web::error::InternalError::from_response(
                            "invalid_target_monitor_payload",
                            HttpResponse::BadRequest().json(
                                json!({"success":false,"message":"目标监控请求格式无效或超过 16 KiB"}),
                            ),
                        )
                        .into()
                    }),
            )
            .service(list_rules)
            .service(create_rule)
            .service(update_rule)
            .service(delete_rule)
            .service(run_rule)
            .service(rule_runs)
            .service(run_changes)
            .service(recent_changes)
            .service(recipients),
    );
}
