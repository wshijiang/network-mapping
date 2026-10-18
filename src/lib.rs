#![recursion_limit = "256"]

pub mod admin;
pub mod analytics_snapshot;
pub mod api_response;
pub mod audit;
pub mod backup;
pub mod cli_progress;
pub mod cli_user;
pub mod client_ip;
pub mod config;
pub mod config_check;
mod config_env;
pub mod db;
pub mod dns;
pub mod dns_follow_up;
pub mod dns_resolvers;
pub mod elasticsearch;
pub mod frontend;
pub mod handlers;
pub mod login;
pub mod login_allowlist;
pub mod logs;
pub mod mail_template;
pub mod maxmind;
pub use nm_module_runtime as module_runtime;
pub mod monitor;
pub mod notification;
pub mod target_generated;
pub mod tls;
pub mod trusted_proxy;

#[cfg(feature = "rir")]
pub mod rir; // 该模块用于从五大 RIR 获取 ASN 和组织等信息

// 自己的中间件
pub mod middlewares;
pub mod open_api;
pub mod open_source;
mod os_detection;
pub mod reports;
pub mod request_log;
pub mod runtime_config;
pub mod scan_migration;
pub mod scanner_config;
pub mod scanner_diagnostics;
pub mod scanner_health;
pub mod scanner_latency;
pub mod scanner_outage;
mod search_content;
pub mod search_projection;
pub mod statistics;
pub mod system_maintenance;
pub mod system_resource_cache;
pub mod system_time;

#[cfg(test)]
pub mod test; // 测试模块

// Domain modules own the implementation; root exports preserve the public API.
pub mod clock;
pub mod identity;
pub mod result_ingest;
pub mod scan_control;
pub mod system_resources;
pub mod web_support;

pub use clock::get_unix_epoch_ms;
pub use identity::{
    Permission, UserLoginInfo, decrypt_data, encrypt_data, generate_hash_password,
    generate_scanner_token, get_password_and_id_from_database, hash_scanner_token, log_out,
    verify_password,
};
pub use result_ingest::*;
pub use scan_control::*;
pub use system_resources::{
    DbResource, DbTableSizeInfo, SystemCPU, SystemDetails, SystemDisk, SystemNetInfo,
    SystemNetwork, SystemRAM, SystemResource, SystemStatusJson, Systems, benchmark,
    get_system_status_info, insert_system_status,
};
pub use web_support::{
    _ProxySetting, APPLICATION_JAVASCRIPT_UTF_8, APPLICATION_JSON, APPLICATION_OCTET_STREAM,
    IMAGE_PNG, ReadFile, TEXT_CSS_UTF_8, TEXT_HTML_UTF_8, TemplatesInit, get_conn_ip,
    get_user_agent, path_secure_join,
};
pub(crate) use web_support::{FrontEndErrorInfo, front_end_error_page};

pub mod http;
pub mod human_verification;
pub(crate) mod readiness;

pub mod application;

mod web_detection;
