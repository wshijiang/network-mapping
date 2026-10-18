use std::io;
use std::path::{Path, PathBuf};

use actix_files::{Files, NamedFile};
use actix_web::http::{Method, header};
use actix_web::{HttpRequest, HttpResponse, web};
use tracing::warn;
use uuid::{Variant, Version};

const SPA_ROUTES: &[&str] = &[
    "/",
    "/create_scan",
    "/task",
    "/scanner",
    "/analysis",
    "/analysis/scan",
    "/analysis/statistics",
    "/analysis/performance",
    "/admin/users",
    "/admin/tags",
    "/admin/backups",
    "/audit",
    "/requests",
    "/reports",
    "/health",
    "/open-source",
    "/testpage",
    "/setting",
    "/setting/maintenance",
    "/setting/scan",
    "/setting/runtime",
    "/setting/human-verification",
    "/setting/mail-templates",
    "/setting/notification-templates",
    "/user/info",
    "/user/security",
    "/open-platform",
    "/open-platform/apps",
    "/open-platform/approvals",
    "/open-platform/catalog",
    "/open-platform/logs",
    "/open-platform/audit",
    "/open-platform/jobs",
    "/open-platform/deliveries",
    "/open-platform/settings",
    "/open-platform/roles",
    "/open-platform/docs",
    "/developer/open-api",
];

const REQUIRED_FRONTEND_FILES: &[&str] = &["index.html", "login.html", "search.html", "asset.html"];
const FRONTEND_STATIC_DIRECTORIES: &[(&str, &str)] = &[("/assets", "assets"), ("/maps", "maps")];

#[derive(Clone, Debug)]
pub struct FrontendAssets {
    directory: PathBuf,
}

impl FrontendAssets {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        let directory = directory.into();
        for file_name in REQUIRED_FRONTEND_FILES {
            let path = directory.join(file_name);
            if !path.is_file() {
                warn!(
                    target: "server::startup",
                    path = %path.display(),
                    "缺少前端构建文件，对应页面将返回 404"
                );
            }
        }

        for (_, directory_name) in FRONTEND_STATIC_DIRECTORIES {
            let static_directory = directory.join(directory_name);
            if !static_directory.is_dir() {
                warn!(
                    target: "server::startup",
                    path = %static_directory.display(),
                    "缺少前端资源目录，静态资源请求将返回 404"
                );
            }
        }

        Self { directory }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn has_page_for_path(&self, path: &str) -> bool {
        let file_name = if is_spa_path(path) {
            "index.html"
        } else if path == "/search.html" {
            "search.html"
        } else if matches!(path, "/asset" | "/asset.html") {
            "asset.html"
        } else {
            return true;
        };

        self.directory.join(file_name).is_file()
    }
}

pub fn configure_assets(cfg: &mut web::ServiceConfig, directory: impl AsRef<Path>) {
    for (route, directory_name) in FRONTEND_STATIC_DIRECTORIES {
        configure_static_directory(cfg, route, directory.as_ref().join(directory_name));
    }
}

fn configure_static_directory(
    cfg: &mut web::ServiceConfig,
    route: &'static str,
    directory: PathBuf,
) {
    if directory.is_dir() {
        cfg.service(
            Files::new(route, directory)
                .use_etag(true)
                .use_last_modified(true)
                .prefer_utf8(true),
        );
    } else {
        let resource_pattern = format!("{route}/{{path:.*}}");
        cfg.service(
            web::resource(resource_pattern)
                .route(web::get().to(HttpResponse::NotFound))
                .route(web::head().to(HttpResponse::NotFound)),
        );
    }
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    for route in SPA_ROUTES {
        cfg.service(
            web::resource(*route)
                .route(web::get().to(spa_entry))
                .route(web::head().to(spa_entry)),
        );
    }

    cfg.service(
        web::resource("/reports/{report_id}")
            .route(web::get().to(spa_entry))
            .route(web::head().to(spa_entry)),
    )
    .service(
        web::resource("/task/{task_id}")
            .route(web::get().to(spa_entry))
            .route(web::head().to(spa_entry)),
    )
    .service(
        web::resource("/scanner/{scanner_id}")
            .route(web::get().to(spa_entry))
            .route(web::head().to(spa_entry)),
    )
    .service(
        web::resource("/scanner/{scanner_id}/configuration")
            .route(web::get().to(spa_entry))
            .route(web::head().to(spa_entry)),
    )
    .service(
        web::resource("/login")
            .route(web::get().to(login_page))
            .route(web::head().to(login_page)),
    )
    .service(
        web::resource("/login.html")
            .route(web::get().to(login_page))
            .route(web::head().to(login_page)),
    )
    .service(
        web::resource("/search.html")
            .route(web::get().to(search_page))
            .route(web::head().to(search_page)),
    )
    .service(
        web::resource("/asset")
            .route(web::get().to(asset_page))
            .route(web::head().to(asset_page)),
    )
    .service(
        web::resource("/asset.html")
            .route(web::get().to(asset_page))
            .route(web::head().to(asset_page)),
    )
    .service(
        web::resource("/favicon.ico")
            .route(web::get().to(favicon))
            .route(web::head().to(favicon)),
    );
}

pub fn is_spa_path(path: &str) -> bool {
    if SPA_ROUTES.contains(&path) {
        return true;
    }

    // Match Vue's single-segment report route; the API validates the report ID.
    if single_path_parameter(path, "/reports/").is_some() {
        return true;
    }

    if let Some(task_id) = single_path_parameter(path, "/task/") {
        return uuid::Uuid::parse_str(task_id)
            .map(|value| {
                value.get_version() == Some(Version::SortRand)
                    && value.get_variant() == Variant::RFC4122
            })
            .unwrap_or(false);
    }

    if let Some(scanner_id) = single_path_parameter(path, "/scanner/") {
        return uuid::Uuid::parse_str(scanner_id)
            .map(|value| value.get_variant() == Variant::RFC4122)
            .unwrap_or(false);
    }

    if let Some(scanner_id) = path
        .strip_prefix("/scanner/")
        .and_then(|value| value.strip_suffix("/configuration"))
        .filter(|value| !value.is_empty() && !value.contains('/'))
    {
        return uuid::Uuid::parse_str(scanner_id)
            .map(|value| value.get_variant() == Variant::RFC4122)
            .unwrap_or(false);
    }

    false
}

pub fn is_protected_frontend_path(path: &str) -> bool {
    is_spa_path(path) || matches!(path, "/search.html" | "/asset" | "/asset.html")
}

pub fn is_frontend_resource_path(path: &str) -> bool {
    is_protected_frontend_path(path)
        || matches!(path, "/login" | "/login.html" | "/favicon.ico")
        || FRONTEND_STATIC_DIRECTORIES.iter().any(|(route, _)| {
            path.strip_prefix(route)
                .is_some_and(|path| path.starts_with('/'))
        })
}

fn single_path_parameter<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let value = path.strip_prefix(prefix)?;
    (!value.is_empty() && !value.contains('/')).then_some(value)
}

fn accepts_html(req: &HttpRequest) -> bool {
    let Some(value) = req.headers().get(header::ACCEPT) else {
        return true;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };

    value.split(',').any(|item| {
        matches!(
            item.trim().split(';').next().unwrap_or_default(),
            "text/html" | "text/*" | "*/*"
        )
    })
}

async fn spa_entry(
    req: HttpRequest,
    assets: web::Data<FrontendAssets>,
) -> actix_web::Result<HttpResponse> {
    if !is_spa_path(req.path()) {
        return Ok(HttpResponse::NotFound().finish());
    }
    html_response(&req, &assets, "index.html").await
}

async fn login_page(
    req: HttpRequest,
    assets: web::Data<FrontendAssets>,
) -> actix_web::Result<HttpResponse> {
    if req
        .app_data::<web::Data<crate::human_verification::settings::ManagedVerification>>()
        .is_some()
        && let Err(error) = crate::human_verification::for_request(&req).await
    {
        return Ok(error.response(&req));
    }
    html_response(&req, &assets, "login.html").await
}

async fn search_page(
    req: HttpRequest,
    assets: web::Data<FrontendAssets>,
) -> actix_web::Result<HttpResponse> {
    html_response(&req, &assets, "search.html").await
}

async fn asset_page(
    req: HttpRequest,
    assets: web::Data<FrontendAssets>,
) -> actix_web::Result<HttpResponse> {
    html_response(&req, &assets, "asset.html").await
}

async fn html_response(
    req: &HttpRequest,
    assets: &FrontendAssets,
    file_name: &str,
) -> actix_web::Result<HttpResponse> {
    if !accepts_html(req) {
        return Ok(HttpResponse::NotAcceptable().finish());
    }

    let Some(file) = open_frontend_file(assets.directory().join(file_name)).await? else {
        return Ok(HttpResponse::NotFound().finish());
    };
    if req.method() == Method::HEAD {
        return Ok(HttpResponse::Ok()
            .insert_header((header::CONTENT_TYPE, file.content_type().to_string()))
            .insert_header((header::CONTENT_LENGTH, file.metadata().len().to_string()))
            .insert_header((header::CACHE_CONTROL, "no-cache"))
            .finish());
    }
    let mut response = file.into_response(req);
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-cache"),
    );
    Ok(response)
}

async fn favicon(
    req: HttpRequest,
    assets: web::Data<FrontendAssets>,
) -> actix_web::Result<HttpResponse> {
    let Some(file) = open_frontend_file(assets.directory().join("favicon.ico")).await? else {
        return Ok(HttpResponse::NotFound().finish());
    };
    if req.method() == Method::HEAD {
        return Ok(HttpResponse::Ok()
            .insert_header((header::CONTENT_TYPE, file.content_type().to_string()))
            .insert_header((header::CONTENT_LENGTH, file.metadata().len().to_string()))
            .finish());
    }
    Ok(file.into_response(&req))
}

async fn open_frontend_file(path: PathBuf) -> actix_web::Result<Option<NamedFile>> {
    match NamedFile::open_async(path).await {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FrontendAssets, accepts_html, configure, configure_assets, is_frontend_resource_path,
        is_spa_path,
    };
    use actix_web::{App, HttpResponse, http::StatusCode, test as actix_test, web};
    use std::fs;

    fn frontend_fixture() -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "network-mapping-frontend-test-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(directory.join("assets")).expect("create frontend fixture");
        fs::create_dir_all(directory.join("maps")).expect("create map fixture");
        fs::write(directory.join("index.html"), "<main>spa entry</main>")
            .expect("write SPA fixture");
        fs::write(directory.join("login.html"), "<main>login entry</main>")
            .expect("write login fixture");
        fs::write(directory.join("search.html"), "<main>search entry</main>")
            .expect("write search fixture");
        fs::write(directory.join("asset.html"), "<main>asset entry</main>")
            .expect("write asset fixture");
        fs::write(directory.join("assets/app.js"), "export default true")
            .expect("write asset fixture");
        fs::write(
            directory.join("maps/world.geojson"),
            r#"{"type":"FeatureCollection","features":[]}"#,
        )
        .expect("write map fixture");
        directory
    }

    #[test]
    fn only_declared_paths_are_spa_routes() {
        assert!(is_spa_path("/"));
        assert!(is_spa_path("/audit"));
        assert!(is_spa_path("/requests"));
        assert!(is_spa_path("/reports"));
        assert!(is_spa_path("/reports/019c0000-0000-4000-8000-000000000001"));
        assert!(is_spa_path("/reports/not-a-uuid"));
        assert!(is_spa_path("/health"));
        assert!(is_spa_path("/admin/backups"));
        assert!(is_spa_path("/admin/tags"));
        assert!(is_spa_path("/analysis/scan"));
        assert!(is_spa_path("/analysis/statistics"));
        assert!(is_spa_path("/analysis/performance"));
        assert!(is_spa_path("/setting/maintenance"));
        assert!(is_spa_path("/setting/runtime"));
        assert!(!is_spa_path("/asset"));
        assert!(is_spa_path("/task/019c0000-0000-7000-8000-000000000001"));
        assert!(is_spa_path("/scanner/019c0000-0000-4000-8000-000000000001"));
        assert!(is_spa_path(
            "/scanner/019c0000-0000-4000-8000-000000000001/configuration"
        ));

        assert!(!is_spa_path("/unknown"));
        assert!(!is_spa_path("/api/audit/events"));
        assert!(!is_spa_path("/api/reports"));
        assert!(!is_spa_path("/reports/"));
        assert!(!is_spa_path("/reports/id/extra"));
        assert!(!is_spa_path("/task/not-a-uuid"));
        assert!(!is_spa_path("/task/019c0000-0000-4000-8000-000000000001"));
        assert!(!is_spa_path("/scanner/id/extra"));
        assert!(!is_spa_path("/scanner/not-a-uuid/configuration"));
        assert!(!is_spa_path(
            "/scanner/00000000-0000-0000-0000-000000000000"
        ));
    }

    #[test]
    fn frontend_resources_are_narrowly_scoped() {
        assert!(is_frontend_resource_path("/login"));
        assert!(is_frontend_resource_path("/search.html"));
        assert!(is_frontend_resource_path("/asset"));
        assert!(is_frontend_resource_path("/asset.html"));
        assert!(is_frontend_resource_path("/assets/app.js"));
        assert!(is_frontend_resource_path("/maps/world.geojson"));
        assert!(!is_frontend_resource_path("/maps-private/world.geojson"));
        assert!(!is_frontend_resource_path("/api/unknown"));
        assert!(!is_frontend_resource_path("/missing.js"));
    }

    #[test]
    fn spa_document_requires_an_html_compatible_accept_header() {
        let html = actix_test::TestRequest::default()
            .insert_header(("Accept", "text/html,application/xhtml+xml"))
            .to_http_request();
        let json = actix_test::TestRequest::default()
            .insert_header(("Accept", "application/json"))
            .to_http_request();

        assert!(accepts_html(&html));
        assert!(!accepts_html(&json));
    }

    #[actix_web::test]
    async fn explicit_routes_serve_spa_without_global_fallback() {
        let directory = frontend_fixture();
        let assets = FrontendAssets::new(&directory);
        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(assets))
                .configure(configure)
                .configure(|cfg| configure_assets(cfg, &directory))
                .default_service(web::to(|| async { HttpResponse::NotFound().finish() })),
        )
        .await;

        let spa_request = actix_test::TestRequest::get()
            .uri("/audit")
            .insert_header(("Accept", "text/html"))
            .to_request();
        let spa_response = actix_test::call_service(&app, spa_request).await;
        assert_eq!(spa_response.status(), StatusCode::OK);
        assert_eq!(
            actix_test::read_body(spa_response).await,
            web::Bytes::from_static(b"<main>spa entry</main>")
        );

        let asset_request = actix_test::TestRequest::get()
            .uri("/asset.html?ip=192.0.2.1")
            .insert_header(("Accept", "text/html"))
            .to_request();
        let asset_response = actix_test::call_service(&app, asset_request).await;
        assert_eq!(asset_response.status(), StatusCode::OK);
        assert_eq!(
            actix_test::read_body(asset_response).await,
            web::Bytes::from_static(b"<main>asset entry</main>")
        );

        let head_request = actix_test::TestRequest::default()
            .method(actix_web::http::Method::HEAD)
            .uri("/audit")
            .insert_header(("Accept", "text/html"))
            .to_request();
        let head_response = actix_test::call_service(&app, head_request).await;
        assert_eq!(head_response.status(), StatusCode::OK);
        assert!(actix_test::read_body(head_response).await.is_empty());

        let invalid_task = actix_test::TestRequest::get()
            .uri("/task/not-a-uuid")
            .insert_header(("Accept", "text/html"))
            .to_request();
        assert_eq!(
            actix_test::call_service(&app, invalid_task).await.status(),
            StatusCode::NOT_FOUND
        );

        let unknown = actix_test::TestRequest::get()
            .uri("/not-a-frontend-route")
            .insert_header(("Accept", "text/html"))
            .to_request();
        assert_eq!(
            actix_test::call_service(&app, unknown).await.status(),
            StatusCode::NOT_FOUND
        );

        let api_unknown = actix_test::TestRequest::get()
            .uri("/api/not-found")
            .to_request();
        assert_eq!(
            actix_test::call_service(&app, api_unknown).await.status(),
            StatusCode::NOT_FOUND
        );

        let wrong_method = actix_test::TestRequest::post().uri("/audit").to_request();
        assert_eq!(
            actix_test::call_service(&app, wrong_method).await.status(),
            StatusCode::METHOD_NOT_ALLOWED
        );

        let missing_asset = actix_test::TestRequest::get()
            .uri("/assets/missing.js")
            .to_request();
        assert_eq!(
            actix_test::call_service(&app, missing_asset).await.status(),
            StatusCode::NOT_FOUND
        );

        let map_request = actix_test::TestRequest::get()
            .uri("/maps/world.geojson")
            .to_request();
        let map_response = actix_test::call_service(&app, map_request).await;
        assert_eq!(map_response.status(), StatusCode::OK);
        assert_eq!(
            actix_test::read_body(map_response).await,
            web::Bytes::from_static(br#"{"type":"FeatureCollection","features":[]}"#)
        );

        fs::remove_dir_all(directory).expect("remove frontend fixture");
    }

    #[actix_web::test]
    async fn reports_and_other_history_routes_serve_spa_on_direct_requests() {
        let directory = frontend_fixture();
        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(FrontendAssets::new(&directory)))
                .configure(configure),
        )
        .await;

        for path in [
            "/reports?period_type=weekly",
            "/reports/019c0000-0000-4000-8000-000000000001",
            "/reports/not-a-uuid",
            "/analysis/statistics",
            "/setting/runtime",
        ] {
            for method in [actix_web::http::Method::GET, actix_web::http::Method::HEAD] {
                let request = actix_test::TestRequest::default()
                    .method(method.clone())
                    .uri(path)
                    .insert_header(("Accept", "text/html"))
                    .to_request();
                let response = actix_test::call_service(&app, request).await;
                assert_eq!(response.status(), StatusCode::OK, "{method} {path}");
                assert_eq!(response.headers().get("Cache-Control").unwrap(), "no-cache");
                assert!(
                    response
                        .headers()
                        .get("Content-Type")
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .starts_with("text/html")
                );
                let body = actix_test::read_body(response).await;
                if method == actix_web::http::Method::HEAD {
                    assert!(body.is_empty(), "HEAD {path}");
                } else {
                    assert_eq!(
                        body,
                        web::Bytes::from_static(b"<main>spa entry</main>"),
                        "GET {path}"
                    );
                }
            }
        }

        for path in ["/api/reports/missing", "/reports/id/extra"] {
            let request = actix_test::TestRequest::get().uri(path).to_request();
            assert_eq!(
                actix_test::call_service(&app, request).await.status(),
                StatusCode::NOT_FOUND,
                "{path}"
            );
        }
        fs::remove_dir_all(directory).expect("remove frontend fixture");
    }

    #[actix_web::test]
    async fn reports_and_other_history_routes_redirect_anonymous_users_to_login() {
        let directory = frontend_fixture();
        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(FrontendAssets::new(&directory)))
                .wrap(crate::middlewares::smiddleware::AuthMiddleware)
                .configure(configure),
        )
        .await;

        for path in [
            "/reports",
            "/reports/019c0000-0000-4000-8000-000000000001",
            "/analysis/statistics",
            "/setting/runtime",
        ] {
            for method in [actix_web::http::Method::GET, actix_web::http::Method::HEAD] {
                let request = actix_test::TestRequest::default()
                    .method(method.clone())
                    .uri(path)
                    .insert_header(("Accept", "text/html"))
                    .to_request();
                let response = actix_test::call_service(&app, request).await;
                assert_eq!(response.status(), StatusCode::FOUND, "{method} {path}");
                assert_eq!(response.headers().get("Location").unwrap(), "/login");
            }
        }
        fs::remove_dir_all(directory).expect("remove frontend fixture");
    }

    #[actix_web::test]
    async fn html_entry_rejects_json_only_clients() {
        let directory = frontend_fixture();
        let assets = FrontendAssets::new(&directory);
        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(assets))
                .configure(configure),
        )
        .await;
        let request = actix_test::TestRequest::get()
            .uri("/audit")
            .insert_header(("Accept", "application/json"))
            .to_request();

        assert_eq!(
            actix_test::call_service(&app, request).await.status(),
            StatusCode::NOT_ACCEPTABLE
        );
        fs::remove_dir_all(directory).expect("remove frontend fixture");
    }

    #[actix_web::test]
    async fn missing_frontend_files_do_not_prevent_404_service() {
        let directory = std::env::temp_dir().join(format!(
            "network-mapping-missing-frontend-test-{}",
            uuid::Uuid::new_v4()
        ));
        let assets = FrontendAssets::new(&directory);
        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(assets))
                .configure(configure)
                .configure(|cfg| configure_assets(cfg, &directory)),
        )
        .await;

        let page_request = actix_test::TestRequest::get()
            .uri("/audit")
            .insert_header(("Accept", "text/html"))
            .to_request();
        assert_eq!(
            actix_test::call_service(&app, page_request).await.status(),
            StatusCode::NOT_FOUND
        );

        let asset_request = actix_test::TestRequest::get()
            .uri("/assets/app.js")
            .to_request();
        assert_eq!(
            actix_test::call_service(&app, asset_request).await.status(),
            StatusCode::NOT_FOUND
        );

        let map_request = actix_test::TestRequest::get()
            .uri("/maps/world.geojson")
            .to_request();
        assert_eq!(
            actix_test::call_service(&app, map_request).await.status(),
            StatusCode::NOT_FOUND
        );
    }
}
