use actix_web::{App, test, web};
use clap::Parser;

use crate::config::{self, Clis};
use crate::db;
use crate::handlers::ReceiveLoginInfo;
use crate::logs;
use crate::logs::LogRollingMode;
use crate::middlewares::smiddleware::AuthMiddleware;

#[actix_web::test]
#[ignore = "requires a configured PostgreSQL database and seeded admin account"]
async fn login_test() {
    let args = Clis::parse_from(["networkm"]);

    let config = config::Config::from_file(&args.config);

    //日志系统配置
    let log = config.log;
    let log_file_directory = log.directory;
    let log_file_name = log.file_name;
    let log_file_rolling = match log.file_rolling {
        0 => LogRollingMode::Daily,
        1 => LogRollingMode::Hourly,
        2 => LogRollingMode::Minutely,
        _ => LogRollingMode::Never,
    };
    let log_debug_mode = args.debug_model;

    // let _guard = init_tracing(&log_file_directory, &log_file_name, &log_file_rolling, &log_debug_mode);
    let _guard = logs::init::init(
        &log_file_directory,
        &log_file_name,
        &log_file_rolling,
        &log_debug_mode,
        false,
    );
    println!("日志系统已启动");
    let db_config = config.database;

    // let database = format!("postgresql://{}:{}@{}/{}", db_config.username, db_config.password, db_config.host, db_config.db_name);
    let db_pool = db::create_postgresql_pool(&db_config)
        .await
        .expect("创建连接池错误");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(
                crate::human_verification::HumanVerificationService::new(config.human_verification)
                    .unwrap(),
            ))
            .app_data(web::Data::new(db_pool.clone()))
            .wrap(AuthMiddleware)
            .configure(config::init_routes),
    )
    .await;

    let r = test::TestRequest::post()
        .uri("/api/login")
        .set_json(ReceiveLoginInfo {
            username: "admin".to_string(),
            password: "1".to_string(),
            human_verification: None,
        })
        .to_request();

    let ret = test::call_service(&app, r).await;

    assert!(ret.status().is_success());
}
