//! HTTP route composition by business domain.
use crate::handlers;
use actix_web::web;

pub fn configure(cfg: &mut web::ServiceConfig) {
    crate::readiness::configure(cfg);
    crate::open_api::configure(cfg);
    reports(cfg);
    identity(cfg);
    analytics(cfg);
    operations(cfg);
    configuration(cfg);
    assets(cfg);
    scanning(cfg);
    cfg.service(handlers::modules::status)
        .service(handlers::modules::publish);
    #[cfg(feature = "rir")]
    cfg.service(handlers::utils::update_rir);
}

fn reports(cfg: &mut web::ServiceConfig) {
    cfg.service(handlers::report_mail_assets::sample);
    cfg.service(handlers::report_mail_assets::trend);
    cfg.service(handlers::report_mail_assets::revoke);
    cfg.service(handlers::reports::generate);
    cfg.service(handlers::reports::list);
    cfg.service(handlers::reports::detail);
    cfg.service(handlers::reports::revise);
    cfg.service(handlers::reports::retry);
    cfg.service(handlers::reports::deliveries);
    cfg.service(handlers::reports::send);
    cfg.service(handlers::reports::schedules);
    cfg.service(handlers::reports::save_schedule);
    cfg.service(handlers::mail_template::list_mail_templates);
    cfg.service(handlers::mail_template::get_mail_template);
    cfg.service(handlers::mail_template::validate_mail_template);
    cfg.service(handlers::mail_template::preview_mail_template);
    cfg.service(handlers::mail_template::save_mail_template_draft);
    cfg.service(handlers::mail_template::publish_mail_template);
    cfg.service(handlers::mail_template::get_mail_template_versions);
    cfg.service(handlers::mail_template::restore_mail_template_version);
    cfg.service(handlers::mail_template::test_mail_template);
}

fn identity(cfg: &mut web::ServiceConfig) {
    cfg.configure(crate::human_verification::configure);
    cfg.service(
        web::resource("/api/login")
            .app_data(web::JsonConfig::default().limit(crate::human_verification::LOGIN_BODY_LIMIT))
            .route(web::post().to(handlers::user::user_login_h)),
    );
    cfg.service(handlers::admin_user::list_users);
    cfg.service(handlers::admin_user::create_user);
    cfg.service(handlers::admin_user::set_user_enabled);
    cfg.service(handlers::admin_user::kick_user);
    cfg.service(handlers::admin_user::delete_user);
    cfg.service(handlers::login_record::self_login_records);
    cfg.service(handlers::login_record::admin_login_records);
    cfg.service(handlers::login_allowlist::get_login_ip_allowlist);
    cfg.service(handlers::login_allowlist::update_login_ip_allowlist);
    cfg.service(handlers::login_allowlist::get_managed_login_ip_allowlist);
    cfg.service(handlers::login_allowlist::update_managed_login_ip_allowlist);
    cfg.service(handlers::user::user_logout);
    cfg.service(handlers::user::verify_totp_h);
    cfg.service(handlers::user::bind_twofa_h);
    cfg.service(handlers::user::get_user_info_h);
    cfg.service(handlers::user::update_user_info_h);
    cfg.service(handlers::user::change_password_h);
    cfg.service(handlers::user::totp_config_h);
    cfg.service(handlers::user::unbind_2fa_h);
}

fn analytics(cfg: &mut web::ServiceConfig) {
    cfg.service(handlers::data_saa::get_system_data_handler);
    cfg.service(handlers::data_saa::get_analysis_distribution);
    cfg.service(handlers::data_saa::get_analysis_discovery_heatmap);
    cfg.service(handlers::statistics::cache_status);
    cfg.service(handlers::statistics::clear_cache);
    cfg.service(handlers::statistics::catalog);
    cfg.service(handlers::statistics::query);
    cfg.service(handlers::statistics_details::details);
}

fn operations(cfg: &mut web::ServiceConfig) {
    cfg.configure(handlers::scanner_diagnostics::configure);
    cfg.service(handlers::system_resources::get_system_resource_history);
    cfg.service(handlers::system_resources::get_database_size_history);
    cfg.service(handlers::scanner_latency::get_scanner_latency_history);
    cfg.service(handlers::system_maintenance::get_maintenance_status);
    cfg.service(handlers::system_maintenance::get_maintenance_history);
    cfg.service(handlers::system_maintenance::enter_maintenance);
    cfg.service(handlers::system_maintenance::update_maintenance);
    cfg.service(handlers::system_maintenance::exit_maintenance);
    cfg.service(handlers::system_maintenance::scanner_system_maintenance_probe);
    cfg.service(handlers::open_source::get_open_source_projects);
    cfg.service(handlers::audit::list_audit_events);
    cfg.service(handlers::audit::export_audit_events);
    cfg.service(handlers::audit::get_audit_event);
    cfg.service(handlers::requests::list_requests);
    cfg.service(handlers::requests::request_summary);
    cfg.service(handlers::requests::request_performance);
    cfg.service(handlers::health::list_health_alerts);
    cfg.service(handlers::backup::backup_summary);
    cfg.service(handlers::backup::list_backup_jobs);
    cfg.service(handlers::backup::get_backup_job);
    cfg.service(handlers::backup::create_backup_job);
    cfg.service(handlers::backup::create_backup_check);
    cfg.service(handlers::health::monitor_operations);
}

fn configuration(cfg: &mut web::ServiceConfig) {
    cfg.service(handlers::utils::benchmark_route);
    cfg.service(handlers::utils::get_config_h);
    cfg.service(handlers::utils::get_config_check);
    cfg.service(handlers::utils::get_server_config_h);
    cfg.service(handlers::utils::get_system_preferences);
    cfg.service(handlers::utils::get_system_timezones);
    cfg.service(handlers::utils::runtime_config_history);
    cfg.service(handlers::utils::get_runtime_config_h);
    cfg.service(handlers::utils::save_runtime_config_h);
    cfg.service(handlers::utils::get_mail_settings_h);
    cfg.service(handlers::utils::save_mail_settings_h);
    cfg.service(handlers::utils::get_session_settings_h);
    cfg.service(handlers::utils::save_session_settings_h);
    cfg.service(handlers::utils::get_trusted_proxy_settings_h);
    cfg.service(handlers::utils::save_trusted_proxy_settings_h);
    cfg.service(handlers::utils::get_scan_settings_h);
    cfg.service(handlers::utils::save_scan_settings_h);
    cfg.service(handlers::utils::test_mail_server_h);
    cfg.service(handlers::utils::get_server_version);
}

fn assets(cfg: &mut web::ServiceConfig) {
    cfg.service(handlers::search::search_ip);
    cfg.service(handlers::search::search_network);
    cfg.service(handlers::search::search_port);
    cfg.service(handlers::search::search_service);
    cfg.service(handlers::search::search_banner);
    cfg.service(handlers::search::elasticsearch_status);
    cfg.service(handlers::search::search_v2);
    cfg.service(handlers::assets::get_asset_summary);
    cfg.service(handlers::assets::get_asset_ports);
    cfg.service(handlers::assets::get_asset_port_history);
    cfg.service(handlers::tags::list_tag_categories);
    cfg.service(handlers::tags::create_tag_category);
    cfg.service(handlers::tags::update_tag_category);
    cfg.service(handlers::tags::delete_tag_category);
    cfg.service(handlers::tags::list_tags);
    cfg.service(handlers::tags::create_tag);
    cfg.service(handlers::tags::update_tag);
    cfg.service(handlers::tags::delete_tag);
    cfg.service(handlers::tags::get_asset_tags);
    cfg.service(handlers::tags::assign_tag);
    cfg.service(handlers::tags::remove_tag);
}

fn scanning(cfg: &mut web::ServiceConfig) {
    cfg.service(handlers::scan_routing::placement_preview);
    cfg.service(handlers::scan_routing::report_performance);
    cfg.service(crate::target_generated::automatic_target_status);
    cfg.service(handlers::task::create_task);
    cfg.service(handlers::task::create_dns_task);
    cfg.service(handlers::task::get_dns_resolver_presets);
    cfg.service(handlers::task::current_task_handler);
    cfg.service(handlers::task::apply_task_handler);
    cfg.service(handlers::task::scanner_public_ip_handler);
    cfg.service(handlers::task::scanner_heartbeat_handler);
    cfg.service(handlers::task::scanner_task_failure_handler);
    cfg.service(handlers::task::scanner_task_cancelled_handler);
    cfg.service(handlers::task::upload_scanner_result_handler);
    cfg.service(handlers::task::get_all_task_handler);
    cfg.service(handlers::task::get_task);
    cfg.service(handlers::task::get_dns_comparison);
    cfg.service(handlers::operations::cancel_task);
    cfg.service(handlers::operations::retry_task);
    cfg.service(handlers::operations::export_task);
    cfg.service(handlers::operations::dashboard_overview);
    cfg.service(handlers::user::web_add_scanner_h);
    cfg.service(handlers::user::get_scanners_h);
    cfg.service(crate::scanner_config::get_runtime_scanner_configuration);
    cfg.service(handlers::user::get_scanner_h);
    cfg.service(crate::scanner_config::get_scanner_configuration);
    cfg.service(crate::scanner_config::update_scanner_configuration);
    cfg.service(handlers::operations::update_scanner);
    cfg.service(handlers::operations::set_scanner_enabled);
    cfg.service(handlers::operations::reissue_scanner_token);
    cfg.service(handlers::operations::delete_scanner);
    cfg.service(handlers::user::scanner_register_h);
}
