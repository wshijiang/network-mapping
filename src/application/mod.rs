//! Application composition: infrastructure, domain services, background ownership and HTTP.
pub mod background;
use actix_web::{App, HttpMessage, HttpServer, dev::Service, http::header, web};
use core::panic;
use std::io;
use tokio::time::{Duration, Instant, MissedTickBehavior, interval_at};
use tracing::{Instrument, error, info};

use crate::admin::{check_default_admin_user, check_system_user, reset_admin_password};
use crate::api_response::ApiErrorMiddleware;
use crate::audit::RequestId;
use crate::backup::BackupManager;
use crate::cli_progress::CliProgressReporter;
use crate::cli_user;
use crate::client_ip::request_ip;
use crate::config::{Clis, SelfChecking};
use crate::elasticsearch::{ElasticsearchService, run_worker as run_elasticsearch_worker};
use crate::frontend::{self, FrontendAssets};
use crate::logs::write::error_diagnostics;
use crate::logs::{self, LogRollingMode};
use crate::maxmind::MaxMindState;
use crate::middlewares::{
    client_ip::ClientIpMiddleware, csrfmiddleware::CsrfMiddleware, hmiddleware::SHeaderM,
    ratelimit::RateLimitMiddleware, smiddleware::AuthMiddleware,
};
use crate::monitor::{self, HealthEvent};
use crate::open_source::OpenSourceCatalog;
use crate::request_log;
use crate::runtime_config::{RuntimeSettings, RuntimeSettingsBootstrap};
use crate::scanner_latency::{self, ScannerLatencyHistory};
use crate::scanner_outage;
use crate::system_maintenance::{
    SystemMaintenanceState, run_reconciler as run_system_maintenance_reconciler,
};
use crate::system_resource_cache::SystemResourceCache;
use crate::target_generated::run_generator;
use crate::tls::build_acceptor;
use crate::trusted_proxy::TrustedProxyState;
use crate::{
    config, db, system_resources::Systems, system_resources::insert_system_status,
    web_support::TemplatesInit,
};

pub async fn run(args: Clis) -> io::Result<()> {
    let mut background = background::BackgroundServices::default();

    if args.command.is_some()
        && (args.reset_admin_password.is_some()
            || args.refresh_ip_intel
            || args.migrate_scan_data_to_elasticsearch
            || args.rebuild_analytics_snapshots)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "用户管理子命令不能与旧维护参数同时使用",
        ));
    }

    let (config, config_check) = match args.config_source {
        config::ConfigSource::File => config::Config::from_file_with_check(&args.config)?,
        config::ConfigSource::Env => config::Config::from_env_with_check()?,
    };

    let log_file_rolling = match config.log.file_rolling {
        0 => LogRollingMode::Daily,
        1 => LogRollingMode::Hourly,
        2 => LogRollingMode::Minutely,
        _ => LogRollingMode::Never,
    };
    let log_debug_mode = args.debug_model;
    let _guard = logs::init::init(
        &config.log.directory,
        &config.log.file_name,
        &log_file_rolling,
        &log_debug_mode,
        args.terminal_verbose,
    );
    info!(target: "server::startup", config_source = ?args.config_source, "启动配置已加载");
    info!(
        target: "server::startup",
        terminal_mode = if args.terminal_verbose { "详细" } else { "精简" },
        "日志系统已启动"
    );
    config_check.emit_startup();
    config.check();
    let request_log_config = config.requests.clone();
    let monitor_config = config.monitor.clone();
    let elasticsearch_config = config.elasticsearch.clone();
    let analytics_snapshot_config = config.analytics_snapshot.clone();
    let automatic_target_config = config.automatic_target.clone();
    let dns_follow_up_config = config.dns_follow_up.clone();
    let frontend_directory = config.frontend.directory.clone();
    let scanner_diagnostics_config = config.scanner_diagnostics.clone();
    let maxmind_directory = config.maxmind.directory.clone();
    let ser_con = config.server.clone();
    let server = config.server;
    let server_host = server.host;
    let server_port = server.port;
    let server_max_body = server.max_body_size;

    //日志系统配置
    let log = config.log;
    let log_file_directory = log.directory;
    let log_file_name = log.file_name;

    //模板系统配置
    let template = config.templates;
    let template_info = TemplatesInit {
        templates_directory: template.templates_directory,
        templates_name: template.templates_name,
    };

    let db_config = config.database;
    let database_c = db_config.clone();
    let database_c2 = db_config.clone();

    let db_pool = db::create_postgresql_pool(&db_config)
        .await
        .unwrap_or_else(|error_value| {
            let diagnostics = error_diagnostics(error_value.as_ref());
            error!(
                target: "server::startup",
                event = "DatabaseStartupFailed",
                operation = "create_database_pool",
                error_kind = "database",
                error_code = "database_pool_initialization_failed",
                error_message = %diagnostics.error_message,
                error_chain = %diagnostics.error_chain,
                root_cause = %diagnostics.root_cause,
                error_truncated = diagnostics.error_truncated,
                retryable = false,
                outcome = "process_stopping",
                startup_stage = "connection_pool",
                "数据库初始化失败，服务即将终止"
            );
            panic!("数据库初始化失败：{}", diagnostics.error_chain);
        });
    let pool = db_pool.clone();
    let request_log_pool = db_pool.clone();
    let scanner_latency_pool = db_pool.clone();
    if let Some(username) = args.reset_admin_password.as_deref() {
        match reset_admin_password(username, &db_pool, config.pwd_hash.clone()).await {
            Ok(password) => {
                println!(
                    "\n┌─ 管理员密码已重置 ───────────────────────\n│ 用户名：{username}\n│ 新密码：{password}\n│ 请妥善保存；该密码不会写入日志。\n└──────────────────────────────────────────\n"
                );
                return Ok(());
            }
            Err(error) => {
                eprintln!("重置管理员密码失败：{}", error);
                return Err(io::Error::other("重置管理员密码失败"));
            }
        }
    }

    let _storage_lease = crate::scan_migration::acquire_storage_lease(
        &db_config,
        args.migrate_scan_data_to_elasticsearch,
    )
    .await
    .map_err(io::Error::other)?;

    match db::init_database_table(&db_pool, &db_config.init_database_file).await {
        Ok(_) => info!(target: "server::startup", "数据库结构初始化完成"),
        Err(error_value) => {
            let diagnostics = error_diagnostics(error_value.as_ref());
            error!(
                target: "server::startup",
                event = "DatabaseStartupFailed",
                operation = "initialize_database_schema",
                error_kind = "database",
                error_code = "database_schema_initialization_failed",
                error_message = %diagnostics.error_message,
                error_chain = %diagnostics.error_chain,
                root_cause = %diagnostics.root_cause,
                error_truncated = diagnostics.error_truncated,
                retryable = false,
                outcome = "process_stopping",
                startup_stage = "schema_initialization",
                "数据库结构初始化失败，服务即将终止"
            );
            panic!("初始化数据库错误：{}", diagnostics.error_chain);
        }
    };
    if let Some(command) = args.command.as_ref() {
        cli_user::execute(command, &db_pool, config.pwd_hash.clone())
            .await
            .map_err(|error| io::Error::other(format!("用户管理命令失败：{error}")))?;
        return Ok(());
    }
    let elasticsearch_service = ElasticsearchService::new(elasticsearch_config)
        .map_err(|error| io::Error::other(format!("创建 Elasticsearch 客户端失败：{error}")))?;
    if args.migrate_scan_data_to_elasticsearch {
        if args.refresh_ip_intel {
            crate::scan_migration::prepare(&db_pool, &crate::cli_progress::NoopProgressReporter)
                .await
                .map_err(io::Error::other)?;
            let maxmind = MaxMindState::from_directory(&maxmind_directory);
            let progress = CliProgressReporter::new("迁移前刷新 PG IP 情报");
            maxmind
                .refresh_ip_intel_with_progress(&db_pool, &progress)
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
        let progress = CliProgressReporter::new("扫描数据迁移");
        let report = match elasticsearch_service
            .migrate_scan_data_with_progress(&db_pool, &progress)
            .await
        {
            Ok(report) => report,
            Err(error) => {
                progress.fail(&error);
                return Err(io::Error::other(format!(
                    "迁移扫描数据到 Elasticsearch 失败：{error}"
                )));
            }
        };
        progress.finish(format!(
            "{} 个批次，{} 条观察",
            report.batches, report.observations
        ));
        println!(
            "扫描数据迁移完成：批次 {} 个，观察 {} 条",
            report.batches, report.observations
        );
        return Ok(());
    }
    elasticsearch_service
        .validate_scan_cutover(&db_pool)
        .await
        .map_err(|error| io::Error::other(format!("扫描存储切换检查失败：{error}")))?;
    if args.rebuild_analytics_snapshots {
        let processed = crate::analytics_snapshot::rebuild_all(&db_pool, &elasticsearch_service)
            .await
            .map_err(|error| io::Error::other(format!("重建分析快照失败：{error}")))?;
        println!("分析快照重建完成：已处理 {processed} 个扫描执行");
        return Ok(());
    }
    let human_verification = web::Data::new(
        crate::human_verification::settings::ManagedVerification::initialize(
            db_pool.clone(),
            &ser_con.encrypt_key,
            config.human_verification.clone(),
        )
        .await
        .map_err(|_| io::Error::other("无法加载登录保护配置"))?,
    );
    let runtime_settings = RuntimeSettings::load(
        &db_pool,
        RuntimeSettingsBootstrap {
            requests: request_log_config,
            monitor: monitor_config,
            automatic_target: automatic_target_config,
            dns_follow_up: dns_follow_up_config,
            dns_resolvers: Default::default(),
            analytics_snapshot: analytics_snapshot_config,
            report_mail: config.report_mail.clone(),
        },
    )
    .await
    .map_err(|error| io::Error::other(format!("加载运行时配置失败：{error}")))?;
    let report_renderer = web::Data::new(
        crate::reports::service::ReportRenderService::from_database(
            &db_pool,
            config.report_renderer.clone(),
        )
        .await
        .map_err(io::Error::other)?,
    );
    let renderer_refresh = report_renderer.clone();
    let renderer_pool = db_pool.clone();
    background.spawn("renderer-configuration", async move {
        loop {
            if let Err(error) = renderer_refresh.refresh(&renderer_pool).await {
                tracing::warn!(event="ReportRendererRefreshFailed",%error);
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
    let general_pool = db_pool.clone();
    let general_config = runtime_settings.general.clone();
    background.spawn("general-configuration", async move {
        loop {
            match crate::system_time::refresh(&general_pool).await {
                Ok(value) => general_config.replace(value.document, value.revision).await,
                Err(error) => tracing::warn!(event = "GeneralSettingsRefreshFailed", %error),
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
    let trusted_proxy_state = web::Data::new(
        TrustedProxyState::from_database(&db_pool)
            .await
            .map_err(|error| io::Error::other(format!("加载可信代理配置失败：{error}")))?,
    );
    let system_maintenance_state = web::Data::new(
        SystemMaintenanceState::from_database(&db_pool)
            .await
            .map_err(|error| io::Error::other(format!("加载系统维护状态失败：{error}")))?,
    );
    background.spawn(
        "maintenance",
        run_system_maintenance_reconciler(system_maintenance_state.clone(), db_pool.clone()),
    );
    background.spawn(
        "scanner-outage",
        scanner_outage::run_worker(
            db_pool.clone(),
            ser_con.encrypt_key.clone(),
            system_maintenance_state.clone(),
            runtime_settings.scanner_health.clone(),
        ),
    );
    if let Ok(client) = db_pool.get().await
        && let Err(error_value) = client
            .execute(
                "UPDATE backup_job SET status = 'failed', finished_at = NOW(), \
                 stderr = CASE WHEN stderr = '' THEN '服务重启，任务执行状态已中断' ELSE stderr END \
                 WHERE status IN ('queued', 'running')",
                &[],
            )
            .await
    {
        let diagnostics = error_diagnostics(&error_value);
        error!(
            event = "BackupJobRecoveryError",
            operation = "recover_interrupted_backup_jobs",
            error_kind = "database",
            error_code = "backup_job_recovery_failed",
            error_message = %diagnostics.error_message,
            error_chain = %diagnostics.error_chain,
            root_cause = %diagnostics.root_cause,
            error_truncated = diagnostics.error_truncated,
            retryable = false,
            outcome = "interrupted_jobs_state_unknown",
        );
    }

    let maxmind_state = MaxMindState::from_directory(&maxmind_directory);

    let elasticsearch_data = web::Data::new(elasticsearch_service.clone());
    let health_state = web::Data::new(crate::readiness::HealthState::default());
    background.spawn(
        "readiness",
        crate::readiness::run(
            health_state.clone(),
            db_pool.clone(),
            elasticsearch_service.clone(),
        ),
    );
    if elasticsearch_service.enabled() {
        background.spawn(
            "asset-projection",
            run_elasticsearch_worker(elasticsearch_service.clone(), db_pool.clone()),
        );
    }
    background.spawn(
        "analytics-snapshot",
        crate::analytics_snapshot::run_worker(
            runtime_settings.analytics_snapshot.clone(),
            db_pool.clone(),
            elasticsearch_service.clone(),
        ),
    );

    background.spawn_draining(
        "notification-worker",
        crate::notification::run(
            db_pool.clone(),
            ser_con.encrypt_key.clone(),
            system_maintenance_state.clone(),
            background.subscribe(),
        ),
    );
    background.spawn_draining(
        "report-worker",
        crate::reports::run_worker(
            db_pool.clone(),
            ser_con.encrypt_key.clone(),
            runtime_settings.analytics_snapshot.clone(),
            system_maintenance_state.clone(),
            report_renderer.get_ref().clone(),
            background.subscribe(),
        ),
    );

    info!(target: "server::startup", "正在检查系统账户");

    check_system_user(&db_pool).await;

    background.spawn(
        "automatic-target",
        run_generator(runtime_settings.automatic_target.clone(), db_pool.clone()),
    );

    // 定义密码加密相关配置文件
    let pwd_h = config.pwd_hash;

    check_default_admin_user(&db_pool, pwd_h.clone()).await;

    let mail_c = config.email_config;

    let monitor_handle = monitor::MonitorHandle::new_managed(
        runtime_settings.monitor.get().await,
        db_pool.clone(),
        ser_con.encrypt_key.clone(),
        &mut background,
    );
    elasticsearch_service.set_monitor(Some(monitor_handle.clone()));
    let health_settings = runtime_settings.clone();
    let health_pool = db_pool.clone();
    let health_monitor = monitor_handle.clone();
    background.spawn("health-configuration", async move {
        loop {
            match health_settings.refresh_health(&health_pool).await {
                Ok(()) => {
                    let current = health_settings.monitor.get().await;
                    health_monitor.replace_config(current.value, current.revision);
                }
                Err(error) => tracing::warn!(event = "HealthPolicyRefreshFailed", %error),
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });

    let tls = if config.tls.enabled {
        Some(build_acceptor(&config.tls)?)
    } else {
        None
    };
    let tls_config = web::Data::new(config.tls);
    let frontend_assets = FrontendAssets::new(frontend_directory);
    let frontend_directory = frontend_assets.directory().to_path_buf();
    let frontend_assets = web::Data::new(frontend_assets);

    let sys = Systems::new();
    let sys_2 = sys.clone();
    let system_resource_cache = SystemResourceCache::new();
    let system_resource_cache_data = web::Data::new(system_resource_cache.clone());
    let maxmind_state = web::Data::new(maxmind_state);
    background.spawn(
        "scan-routing",
        crate::scan_control::routing::run_planner(
            db_pool.clone(),
            maxmind_state.clone(),
            system_maintenance_state.clone(),
        ),
    );
    let runtime_settings = web::Data::new(runtime_settings);
    let automatic_target_service = web::Data::new(runtime_settings.automatic_target.clone());
    let dns_follow_up = web::Data::new(runtime_settings.dns_follow_up.clone());
    let security = web::Data::new(config.security);
    let analytics_snapshot = web::Data::new(runtime_settings.analytics_snapshot.clone());
    let statistics_service = web::Data::new(crate::statistics::StatisticsService::new());
    let statistics_settings = runtime_settings.statistics_cache.get().await;
    statistics_service.apply(statistics_settings.value, statistics_settings.revision);
    let statistics_refresh = statistics_service.clone();
    let statistics_pool = db_pool.clone();
    background.spawn("statistics-configuration", async move {
        loop {
            if let Err(error) = statistics_refresh.refresh(&statistics_pool).await {
                tracing::warn!(event="StatisticsConfigRefreshFailed", %error);
            }
            if let Err(error) = statistics_refresh.publish_status(&statistics_pool).await {
                tracing::warn!(event="StatisticsStatusPublishFailed", %error);
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
    background.spawn(
        "domain-discovery",
        crate::domain_discovery::run(
            db_pool.clone(),
            elasticsearch_service.clone(),
            system_maintenance_state.clone(),
        ),
    );
    let rate_limiter = RateLimitMiddleware::default();
    background.spawn(
        "open-api",
        crate::open_api::run_worker(
            db_pool.clone(),
            elasticsearch_service.clone(),
            ser_con.encrypt_key.as_bytes().to_vec(),
        ),
    );
    let open_source_catalog = web::Data::new(
        OpenSourceCatalog::from_embedded()
            .map_err(|error| io::Error::other(format!("开源项目清单格式错误: {error}")))?,
    );
    let backup_manager = web::Data::new(BackupManager::new(config.backup.clone()));

    info!(target: "server::startup",
        address = %format!("{}:{}", server_host, server_port),
        log_directory = %log_file_directory,
        log_file = %log_file_name,
        log_rolling_mode = log.file_rolling,
        debug = log_debug_mode,
        template_directory = %template_info.templates_directory,
        template_name = %template_info.templates_name,
        frontend_directory = %frontend_directory.display(),
        maxmind_directory = %maxmind_directory.display(),
        automatic_target_enabled = automatic_target_service.get().await.value.enabled,
        status_interval_seconds = log.status_duration,
        "服务配置就绪"
    );

    // 暂时取消等待
    // 计算下一个 2 分钟整点
    // let now = Utc::now();
    // let next_minute = ((now.minute() / 2) + 1) * 2; // 下一个偶数分钟
    // let start_time = Utc::now()
    //     .with_minute(next_minute % 60).unwrap()
    //     .with_second(0).unwrap()
    //     .with_nanosecond(0).unwrap();

    // let delay = (start_time.timestamp_millis() - now.timestamp_millis()) as u64;

    // 从整点开始，每隔一段时间 tick 一次，该时间由配置文件指定
    background.spawn(
        "session-retention",
        crate::login::run_session_expiration(db_pool.clone()),
    );
    background.spawn("system-resource-sampling", async move {
        let mut ticker = interval_at(
            Instant::now() + Duration::from_millis(0),
            Duration::from_secs(log.status_duration),
        );
        // 依赖偶发变慢时跳过已错过的周期，避免恢复后立即突发执行多次采集。
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            match insert_system_status(
                &db_pool,
                database_c.db_name.clone(),
                sys.clone(),
                &elasticsearch_service,
                &system_resource_cache,
            )
            .await
            {
                Ok(_) => (),
                Err(e) => {
                    let diagnostics = error_diagnostics(e.as_ref());
                    error!(
                        event = "SystemStatusInsertError",
                        operation = "insert_system_status",
                        error_kind = "database",
                        error_code = "system_status_insert_failed",
                        error_message = %diagnostics.error_message,
                        error_chain = %diagnostics.error_chain,
                        root_cause = %diagnostics.root_cause,
                        error_truncated = diagnostics.error_truncated,
                        retryable = true,
                        outcome = "sample_dropped",
                        retry_after_ms = log.status_duration.saturating_mul(1_000),
                    )
                }
            };
            // TODO: 监控逻辑
        }
    });

    // 请求日志采集：有界 channel + 后台 writer（永不退出）+ 定期清理。
    let (request_log_tx, request_log_rx) =
        tokio::sync::mpsc::channel(request_log::CHANNEL_CAPACITY);
    background.spawn(
        "request-log-writer",
        request_log::run_writer(request_log_pool.clone(), request_log_rx),
    );
    background.spawn(
        "request-log-retention",
        request_log::run_retention(request_log_pool.clone(), runtime_settings.requests.clone()),
    );

    let (scanner_latency_history, scanner_latency_rx) = ScannerLatencyHistory::channel();
    background.spawn(
        "scanner-latency-writer",
        scanner_latency::run_writer(scanner_latency_pool.clone(), scanner_latency_rx),
    );
    background.spawn(
        "scanner-latency-retention",
        scanner_latency::run_retention(scanner_latency_pool, scanner_latency::RETENTION_DAYS),
    );

    let scanner_diagnostics =
        crate::scanner_diagnostics::Diagnostics::new(scanner_diagnostics_config).await?;
    background.spawn(
        "scanner-diagnostics",
        crate::scanner_diagnostics::run_worker(
            pool.clone(),
            scanner_diagnostics.clone(),
            system_maintenance_state.clone(),
        ),
    );
    let scanner_diagnostics_data = web::Data::new(scanner_diagnostics);

    let renderer_shutdown = report_renderer.clone();
    let http_server = HttpServer::new(move || {
        let request_log_tx = request_log_tx.clone();
        let runtime_settings = runtime_settings.clone();
        let monitor_handle = monitor_handle.clone();

        App::new()
            .app_data(human_verification.clone())
            .app_data(health_state.clone())
            .app_data(tls_config.clone())
            .app_data(web::Data::new(config_check.clone()))
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(template_info.clone()))
            .app_data(web::Data::new(sys_2.clone()))
            .app_data(system_resource_cache_data.clone())
            .app_data(web::Data::new(database_c2.clone()))
            .app_data(web::Data::new(pwd_h.clone()))
            .app_data(web::Data::new(mail_c.clone()))
            .app_data(web::Data::new(ser_con.clone()))
            .app_data(web::Data::new(monitor_handle.clone()))
            .app_data(maxmind_state.clone())
            .app_data(automatic_target_service.clone())
            .app_data(dns_follow_up.clone())
            .app_data(open_source_catalog.clone())
            .app_data(backup_manager.clone())
            .app_data(elasticsearch_data.clone())
            .app_data(trusted_proxy_state.clone())
            .app_data(system_maintenance_state.clone())
            .app_data(security.clone())
            .app_data(analytics_snapshot.clone())
            .app_data(statistics_service.clone())
            .app_data(runtime_settings.clone())
            .app_data(report_renderer.clone())
            .app_data(web::Data::new(scanner_latency_history.clone()))
            .app_data(frontend_assets.clone())
            .app_data(scanner_diagnostics_data.clone())
            .app_data(web::JsonConfig::default().limit(server_max_body))
            .wrap(CsrfMiddleware)
            .wrap(SHeaderM)
            .wrap(AuthMiddleware)
            .wrap(rate_limiter.clone())
            .wrap(ApiErrorMiddleware)
            .wrap_fn(move |req, service| {
                let request_id = req
                    .headers()
                    .get("X-Request-ID")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| uuid::Uuid::parse_str(value).ok())
                    .unwrap_or_else(uuid::Uuid::new_v4);
                req.extensions_mut().insert(RequestId(request_id));
                let response_request_id = header::HeaderValue::from_str(&request_id.to_string())
                    .expect("UUID is a valid header value");

                // 请求日志采集：service.call 前抓取元数据，响应后抓取状态码与耗时。
                // 跳过静态资源与高频心跳，避免污染与放大数据量。
                let path = crate::reports::redact_mail_image_path(req.path()).to_owned();
                let is_scanner_heartbeat = path == "/api/scanner/heartbeat";
                let latency_probe = (is_scanner_heartbeat
                    && req
                        .headers()
                        .get("NM-Latency-Version")
                        .and_then(|value| value.to_str().ok())
                        == Some("1"))
                .then(|| {
                    req.headers()
                        .get("NM-Latency-Probe")
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| uuid::Uuid::parse_str(value).ok())
                })
                .flatten();
                let is_health_probe = path == "/healthz";
                let capture = !is_health_probe
                    && !crate::frontend::is_frontend_resource_path(&path)
                    && !is_scanner_heartbeat;
                let actor = std::sync::Arc::new(std::sync::Mutex::new(None));
                req.extensions_mut()
                    .insert(request_log::RequestActor(actor.clone()));
                let reason = std::sync::Arc::new(std::sync::Mutex::new(None));
                req.extensions_mut()
                    .insert(request_log::RequestReason(reason.clone()));
                let method = req.method().to_string();
                let client_ip = request_ip(req.request());
                let user_agent = req
                    .headers()
                    .get(header::USER_AGENT)
                    .and_then(|value| value.to_str().ok())
                    .map(|value| value.chars().take(512).collect::<String>());
                let started = std::time::Instant::now();

                // 用 request_id 建立 tracing span，使请求处理链路上的所有日志自动携带该 id，
                // 无需在每个日志宏里手动重复写 request_id。
                let span = tracing::info_span!("http_request", request_id = %request_id);
                let future = service.call(req).instrument(span);
                let request_log_tx = request_log_tx.clone();
                let runtime_settings = runtime_settings.clone();
                let monitor_handle = monitor_handle.clone();
                async move {
                    let mut response = future.await?;
                    response.headers_mut().insert(
                        header::HeaderName::from_static("x-request-id"),
                        response_request_id,
                    );
                    if response.status().is_success()
                        && let Some(probe_id) = latency_probe
                    {
                        let processing_us = started.elapsed().as_micros();
                        let sent_at_ms = crate::clock::get_unix_epoch_ms();
                        response.headers_mut().insert(
                            header::HeaderName::from_static("nm-latency-version"),
                            header::HeaderValue::from_static("1"),
                        );
                        response.headers_mut().insert(
                            header::HeaderName::from_static("nm-latency-probe"),
                            header::HeaderValue::from_str(&probe_id.to_string())
                                .expect("UUID is a valid header value"),
                        );
                        response.headers_mut().insert(
                            header::HeaderName::from_static("nm-server-processing-us"),
                            header::HeaderValue::from_str(&processing_us.to_string())
                                .expect("integer is a valid header value"),
                        );
                        response.headers_mut().insert(
                            header::HeaderName::from_static("nm-server-sent-at-ms"),
                            header::HeaderValue::from_str(&sent_at_ms.to_string())
                                .expect("integer is a valid header value"),
                        );
                    }
                    // 健康告警与请求日志独立：关闭访问日志不得关闭 5xx/慢请求监控。
                    {
                        let status = response.status().as_u16();
                        let (error_level, error_type) = request_log::classify_status(status);
                        let reason_code = reason
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .clone();
                        let elapsed = started.elapsed();
                        let duration_ms = i32::try_from(elapsed.as_millis()).ok();
                        let duration_us = i64::try_from(elapsed.as_micros()).ok();
                        let route_pattern = response.request().match_pattern();
                        let actor = actor
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .take();
                        let (actor_id, actor_name) = match actor {
                            Some((id, name)) => (Some(id), Some(name)),
                            None => (None, None),
                        };

                        if status >= 500
                            || (status >= 400
                                && (path.starts_with("/api/totp/")
                                    || path == "/api/login"
                                    || path == "/api/scanner/register"))
                        {
                            tracing::warn!(
                                event = "request_completed",
                                request_id = %request_id,
                                method,
                                path,
                                status,
                                duration_us = ?duration_us,
                                reason_code = ?reason_code,
                                actor_user_id = ?actor_id,
                            );
                        }

                        // 健康探针不重复生成请求告警；依赖变化由 readiness 后台任务记录。
                        if !is_health_probe {
                            let monitor = &monitor_handle;
                            let monitor_route = route_pattern.as_deref().unwrap_or("(unmatched)");
                            let slow_rule = duration_ms.and_then(|value| {
                                monitor.classify_request(&method, monitor_route, i64::from(value))
                            });
                            let is_expected_maintenance =
                                response.headers().contains_key("nm-maintenance-version");
                            let is_server_error = monitor.server_error_enabled()
                                && status >= 500
                                && !is_expected_maintenance;
                            if slow_rule.is_some() || is_server_error {
                                let client_ip_str = client_ip.map(|ip| ip.to_string());
                                let actor_name_str = actor_name.clone();
                                if let Some(applied) = slow_rule {
                                    let measured_ms =
                                        duration_ms.map(i64::from).unwrap_or_default();
                                    let severity = applied
                                        .rule
                                        .severity(measured_ms as f64)
                                        .unwrap_or("warning");
                                    let mut event = HealthEvent::slow_request(
                                        &method,
                                        monitor_route,
                                        status,
                                        measured_ms,
                                        request_id,
                                        client_ip_str.clone(),
                                        actor_name_str.clone(),
                                    )
                                    .with_rule(applied);
                                    event.severity = severity;
                                    monitor.emit(event);
                                }
                                if is_server_error {
                                    monitor.emit(HealthEvent::server_error(
                                        &method,
                                        monitor_route,
                                        status,
                                        duration_ms.map(i64::from),
                                        request_id,
                                        client_ip_str,
                                        actor_name_str,
                                    ));
                                }
                            }
                        }

                        if capture && runtime_settings.requests.get().await.value.enabled {
                            let entry = request_log::RequestLogEntry {
                                request_id,
                                occurred_at: chrono::Utc::now(),
                                http_method: method,
                                request_path: path,
                                route_pattern,
                                status_code: status as i16,
                                duration_ms,
                                duration_us,
                                client_ip,
                                user_agent,
                                actor_id,
                                actor_name,
                                error_level: error_level.to_owned(),
                                error_type: error_type.map(str::to_owned),
                                reason_code,
                            };
                            if request_log_tx.try_send(entry).is_err() {
                                let dropped = request_log::record_enqueue_drop();
                                if dropped.is_power_of_two() {
                                    tracing::warn!(
                                        event = "RequestLogEnqueueDropped",
                                        operation = "enqueue_request_log",
                                        reason_code = "request_log_queue_unavailable",
                                        dropped_total = dropped,
                                        request_id = %request_id,
                                    );
                                }
                            }
                        }
                    }
                    Ok(response)
                }
            })
            // 最外层先按可信代理规则解析一次来源 IP，供请求日志、限流、认证与审计复用。
            .wrap(ClientIpMiddleware::new(trusted_proxy_state.clone()))
            .configure(crate::http::configure)
            .configure(frontend::configure)
            .configure(|cfg| frontend::configure_assets(cfg, &frontend_directory))
            .default_service(web::to(crate::handlers::utils::not_found))
    });
    let scheme = if tls.is_some() { "https" } else { "http" };
    let http_server = match tls {
        Some(tls) => http_server.bind_openssl((server_host.as_str(), server_port), tls)?,
        None => {
            // Bind the same parsed IP that passed validation; never resolve a hostname here.
            let address = server_host
                .parse::<std::net::IpAddr>()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            http_server.bind(std::net::SocketAddr::new(address, server_port))?
        }
    };
    info!(target: "server::startup", host = %server_host, port = server_port,
        scheme, "HTTP 监听已绑定");
    let server_result = http_server.run().await;
    background
        .shutdown(std::time::Duration::from_secs(150))
        .await;
    if let Err(error) = renderer_shutdown
        .registry()
        .shutdown(std::time::Duration::from_secs(30))
        .await
    {
        tracing::warn!(event="ReportRendererShutdownFailed",%error);
    }
    server_result
}
