//! Cached readiness of mandatory storage dependencies. Public responses carry no diagnostics.
use std::{
    future::Future,
    sync::RwLock,
    time::{Duration, Instant},
};

use actix_web::{HttpResponse, http::header, web};
use deadpool_postgres::Pool;

use crate::elasticsearch::ElasticsearchService;

const CHECK_INTERVAL: Duration = Duration::from_secs(5);
const CHECK_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_AGE: Duration = Duration::from_secs(15);

#[derive(Default)]
struct Snapshot {
    checked_at: Option<Instant>,
    postgres: bool,
    elasticsearch: bool,
}

#[derive(Default)]
pub(crate) struct HealthState(RwLock<Snapshot>);

impl HealthState {
    fn ready(&self) -> bool {
        self.0.read().is_ok_and(|snapshot| {
            snapshot.postgres
                && snapshot.elasticsearch
                && snapshot
                    .checked_at
                    .is_some_and(|checked| checked.elapsed() <= MAX_AGE)
        })
    }

    fn record(&self, postgres: Result<(), String>, elasticsearch: Result<(), String>) {
        let Ok(mut snapshot) = self.0.write() else {
            return;
        };
        for (component, previous, result) in [
            ("postgresql", snapshot.postgres, &postgres),
            ("elasticsearch", snapshot.elasticsearch, &elasticsearch),
        ] {
            if snapshot.checked_at.is_none() || previous != result.is_ok() {
                match result {
                    Ok(()) => tracing::info!(event = "ReadinessDependencyAvailable", component),
                    Err(error) => {
                        tracing::warn!(event = "ReadinessDependencyUnavailable", component, %error)
                    }
                }
            }
        }
        *snapshot = Snapshot {
            checked_at: Some(Instant::now()),
            postgres: postgres.is_ok(),
            elasticsearch: elasticsearch.is_ok(),
        };
    }
}

pub(crate) fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/healthz")
            .route(web::get().to(healthz))
            .route(web::head().to(healthz)),
    );
}

async fn healthz(state: Option<web::Data<HealthState>>) -> HttpResponse {
    let status = if state.is_some_and(|state| state.ready()) {
        actix_web::http::StatusCode::OK
    } else {
        actix_web::http::StatusCode::SERVICE_UNAVAILABLE
    };
    HttpResponse::build(status)
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .finish()
}

async fn bounded_check(check: impl Future<Output = Result<(), String>>) -> Result<(), String> {
    tokio::time::timeout(CHECK_TIMEOUT, check)
        .await
        .map_err(|_| "readiness check timed out".to_owned())?
}

pub(crate) async fn run(
    state: web::Data<HealthState>,
    pool: Pool,
    elasticsearch: ElasticsearchService,
) {
    let mut interval = tokio::time::interval(CHECK_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        refresh(&state, &pool, &elasticsearch).await;
    }
}

async fn refresh(state: &HealthState, pool: &Pool, elasticsearch: &ElasticsearchService) {
    let postgres = bounded_check(async {
        let client = pool.get().await.map_err(|error| error.to_string())?;
        client
            .simple_query("SELECT 1")
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    });
    let elasticsearch = bounded_check(elasticsearch.health_check());
    let (postgres, elasticsearch) = tokio::join!(postgres, elasticsearch);
    state.record(postgres, elasticsearch);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middlewares::{
        csrfmiddleware::CsrfMiddleware, hmiddleware::SHeaderM, ratelimit::RateLimitMiddleware,
        smiddleware::AuthMiddleware,
    };
    use actix_web::{
        App,
        http::{Method, StatusCode},
        test,
    };

    #[actix_web::test]
    async fn anonymous_get_and_head_return_only_status_through_production_middleware() {
        let state = web::Data::new(HealthState::default());
        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .wrap(CsrfMiddleware)
                .wrap(SHeaderM)
                .wrap(AuthMiddleware)
                .wrap(RateLimitMiddleware::default())
                .wrap(crate::api_response::ApiErrorMiddleware)
                .configure(crate::http::configure),
        )
        .await;
        for postgres in [false, true] {
            for elasticsearch in [false, true] {
                state.record(
                    postgres.then_some(()).ok_or("private PG error".into()),
                    elasticsearch.then_some(()).ok_or("private ES error".into()),
                );
                for method in [Method::GET, Method::HEAD] {
                    let response = test::call_service(
                        &app,
                        test::TestRequest::with_uri("/healthz")
                            .method(method)
                            .to_request(),
                    )
                    .await;
                    assert_eq!(
                        response.status(),
                        if postgres && elasticsearch {
                            StatusCode::OK
                        } else {
                            StatusCode::SERVICE_UNAVAILABLE
                        }
                    );
                    assert_eq!(
                        response.headers().get(header::CACHE_CONTROL).unwrap(),
                        "no-store"
                    );
                    assert!(test::read_body(response).await.is_empty());
                }
            }
        }
        let response = test::call_service(
            &app,
            test::TestRequest::with_uri("/api/config/check").to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn uninitialized_missing_or_stale_state_is_unavailable_and_empty() {
        let state = web::Data::new(HealthState::default());
        let app = test::init_service(App::new().app_data(state.clone()).configure(configure)).await;
        for stale in [false, true] {
            if stale {
                state.record(Ok(()), Ok(()));
                state.0.write().unwrap().checked_at =
                    Some(Instant::now() - MAX_AGE - Duration::from_secs(1));
            }
            let response =
                test::call_service(&app, test::TestRequest::with_uri("/healthz").to_request())
                    .await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(test::read_body(response).await.is_empty());
        }
        let app = test::init_service(App::new().configure(configure)).await;
        let response =
            test::call_service(&app, test::TestRequest::with_uri("/healthz").to_request()).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(test::read_body(response).await.is_empty());
    }

    #[tokio::test]
    async fn unresponsive_dependencies_have_a_bounded_deadline() {
        assert!(
            bounded_check(std::future::pending())
                .await
                .unwrap_err()
                .contains("timed out")
        );
        assert!(bounded_check(async { Ok(()) }).await.is_ok());
    }

    #[actix_web::test]
    #[ignore = "requires READINESS_TEST_DATABASE_URL pointing to a PostgreSQL instance"]
    async fn readiness_live_postgresql_and_cluster_fixture_drive_public_status() {
        use actix_web::{HttpResponse, HttpServer};
        use serde_json::json;
        use std::{
            net::TcpListener,
            sync::atomic::{AtomicBool, Ordering},
        };
        let config = std::env::var("READINESS_TEST_DATABASE_URL")
            .expect("database fixture URL required")
            .parse::<tokio_postgres::Config>()
            .expect("invalid database fixture URL");
        let pool = Pool::builder(deadpool_postgres::Manager::new(
            config,
            tokio_postgres::NoTls,
        ))
        .max_size(2)
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .build()
        .unwrap();
        let available = web::Data::new(AtomicBool::new(true));
        let server_state = available.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = HttpServer::new(move || App::new().app_data(server_state.clone())
            .route("/_cluster/health", web::get().to(|available: web::Data<AtomicBool>| async move {
                HttpResponse::Ok().json(json!({"status": if available.load(Ordering::Relaxed) {"green"} else {"red"}, "timed_out":false}))
            }))).workers(1).listen(listener).unwrap().run();
        let handle = server.handle();
        actix_web::rt::spawn(server);
        let elasticsearch = ElasticsearchService::new(crate::config::ElasticsearchConfig {
            enabled: true,
            url: format!("http://{address}"),
            ..Default::default()
        })
        .unwrap();
        let state = web::Data::new(HealthState::default());
        let app = test::init_service(App::new().app_data(state.clone()).configure(configure)).await;
        for (es_available, close_pool, expected) in [
            (true, false, StatusCode::OK),
            (false, false, StatusCode::SERVICE_UNAVAILABLE),
            (true, false, StatusCode::OK),
            (true, true, StatusCode::SERVICE_UNAVAILABLE),
        ] {
            available.store(es_available, Ordering::Relaxed);
            if close_pool {
                pool.close();
            }
            refresh(&state, &pool, &elasticsearch).await;
            let response =
                test::call_service(&app, test::TestRequest::with_uri("/healthz").to_request())
                    .await;
            assert_eq!(response.status(), expected);
            assert!(test::read_body(response).await.is_empty());
        }
        handle.stop(true).await;
    }
}
