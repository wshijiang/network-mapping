//! Syslog 转发：把系统运行日志、审计事件、IP 访问日志与扫描器诊断事件
//! 以 RFC 5424 格式发送到管理员配置的一台或多台远程 syslog 服务器。
//!
//! - 配置存于 `runtime_configuration`（namespace `syslog`），Web 与 CLI 对等管理。
//! - 仅适配现代产品：RFC 5424 + RFC 6587 octet-counting（TCP/TLS）。
//! - 分钟级指标支撑 Web 统计图与 CLI 终端图（malevich），以及失败率/P95/P99 通知策略。

pub mod alerts;
pub mod backfill;
pub mod cli;
pub mod config;
pub mod format;
pub mod forwarder;
pub mod hooks;
pub mod metrics;
pub mod proxy;
pub mod status;
pub mod transport;

pub use config::{NAMESPACE, SyslogConfig};
pub use forwarder::{CaptureHandle, ForwardItem, SyslogLayer, capture};
pub use status::StatusRegistry;
