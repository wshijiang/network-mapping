use crate::admin::UserBaseI;
use crate::reports::service::{PublishError, RendererSelection, ReportRenderService};
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::json;

#[get("/api/modules/report-render")]
pub async fn status(
    pool: web::Data<Pool>,
    service: web::Data<ReportRenderService>,
    actor: UserBaseI,
) -> HttpResponse {
    if actor.role != 1 {
        return HttpResponse::Forbidden().json(json!({"success":false,"message":"需要管理员权限"}));
    }
    match ReportRenderService::desired(&pool).await {
        Ok((selection, revision)) => {
            let status = service.status().await;
            HttpResponse::Ok().json(json!({"success":true,"data":{"expectedRevision":revision,"desiredReleaseId":selection.release_id,"appliedRevision":status.applied_revision,"appliedReleaseId":status.applied_release_id,"available":status.available,"converged":status.converged(revision),"lastRefreshError":status.last_refresh_error}}))
        }
        Err(error) => {
            HttpResponse::ServiceUnavailable().json(json!({"success":false,"message":error}))
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishRequest {
    pub expected_revision: i64,
    pub release_id: String,
    pub change_reason: String,
}

#[post("/api/modules/report-render")]
pub async fn publish(
    req: HttpRequest,
    pool: web::Data<Pool>,
    service: web::Data<ReportRenderService>,
    actor: UserBaseI,
    input: web::Json<PublishRequest>,
) -> HttpResponse {
    if actor.role != 1 {
        return HttpResponse::Forbidden().json(json!({"success":false,"message":"需要管理员权限"}));
    }
    if input.expected_revision < 1
        || input.change_reason.trim().is_empty()
        || input.change_reason.len() > 1024
    {
        return HttpResponse::BadRequest()
            .json(json!({"success":false,"message":"需要有效版本与变更原因"}));
    }
    let selection = RendererSelection {
        release_id: input.release_id.clone(),
    };
    if let Err(error) = selection.validate() {
        return HttpResponse::BadRequest().json(json!({"success":false,"message":error}));
    }
    match service
        .publish(
            &pool,
            input.expected_revision,
            selection,
            &input.change_reason,
            actor.id,
        )
        .await
    {
        Ok(revision) => {
            let mut event = crate::audit::AuditEvent::user(
                "module",
                "module.report-render.publish",
                "success",
                &actor,
            );
            event.metadata = json!({"release_id":input.release_id,"revision":revision,"change_reason":input.change_reason});
            crate::audit::write_standalone(
                &pool,
                &crate::audit::AuditContext::from_request(&req),
                &event,
            )
            .await;
            HttpResponse::Ok().json(
                json!({"success":true,"data":{"revision":revision,"releaseId":input.release_id}}),
            )
        }
        Err(PublishError::Persistence(crate::runtime_config::PersistError::Conflict)) => HttpResponse::Conflict()
            .json(json!({"success":false,"message":"配置版本冲突，请刷新后重试"})),
        Err(PublishError::InvalidCandidate(error)) => HttpResponse::BadRequest()
            .json(json!({"success":false,"message":error})),
        Err(PublishError::Persistence(error)) => HttpResponse::ServiceUnavailable()
            .json(json!({"success":false,"message":error.to_string()})),
        Err(PublishError::Activation { revision, error }) => HttpResponse::ServiceUnavailable()
            .json(json!({"success":false,"message":error,"data":{"persistedRevision":revision,"desiredReleaseId":input.release_id,"pendingActivation":true}})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, HttpMessage, dev::Service, test};

    #[actix_web::test]
    async fn module_management_rejects_non_administrators_before_database_work() {
        let manager =
            deadpool_postgres::Manager::new(tokio_postgres::Config::new(), tokio_postgres::NoTls);
        let pool = Pool::builder(manager).max_size(1).build().unwrap();
        let service = ReportRenderService::builtin().await;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .app_data(web::Data::new(service))
                .wrap_fn(|req, service| {
                    req.extensions_mut().insert(UserBaseI {
                        id: 7,
                        username: "user".into(),
                        role: 2,
                        email: None,
                        limit_login: false,
                        enable_2fa: false,
                    });
                    service.call(req)
                })
                .service(status)
                .service(publish),
        )
        .await;
        let get = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/api/modules/report-render")
                .to_request(),
        )
        .await;
        assert_eq!(get.status(), actix_web::http::StatusCode::FORBIDDEN);
        let post = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/modules/report-render")
                .set_json(json!({"expectedRevision":1,"releaseId":"builtin","changeReason":"test"}))
                .to_request(),
        )
        .await;
        assert_eq!(post.status(), actix_web::http::StatusCode::FORBIDDEN);
    }
}
