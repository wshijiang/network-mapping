pub mod admin_user;
pub mod assets;
pub mod audit;
pub mod backup;
pub mod data_saa; //数据统计与分析
pub mod health;
pub mod login_allowlist;
pub mod login_record;
pub mod mail_template;
pub mod open_source;
pub mod operations;
pub mod report_mail_assets;
pub mod reports;
pub mod requests;
pub mod scanner_diagnostics;
pub mod scanner_latency;
pub mod search;
pub(crate) mod search_dsl;
pub mod statistics;
pub mod statistics_details;
pub mod system_maintenance;
pub mod system_resources;
pub mod tags;
pub mod task;
pub mod user;
pub mod utils;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct ReceiveLoginInfo {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct ResponseLoginStatus {
    pub success: bool,
    pub message: String,
}

#[derive(Deserialize)]
pub struct ScanTargetGet {
    pub scanner_id: String,
    pub test: String,
}

#[derive(Deserialize)]
pub struct ScanTargetDone {
    pub ip: String,
    pub scanner_id: String,
    pub info_count: u32,
    pub survival_ip_count: u32,
}
pub mod modules;
