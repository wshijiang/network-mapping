pub mod init;
pub mod write;

use std::net::IpAddr;
use std::path::Path;
use tracing_appender::{rolling as import_log_rolling, rolling::RollingFileAppender};
use tracing_subscriber::fmt::time::FormatTime;

pub enum LogRollingMode {
    Daily,
    Hourly,
    Minutely,
    Never,
}

impl LogRollingMode {
    pub fn build(&self, dir: impl AsRef<Path>, name: impl AsRef<Path>) -> RollingFileAppender {
        match self {
            LogRollingMode::Daily => import_log_rolling::daily(dir, name),
            LogRollingMode::Hourly => import_log_rolling::hourly(dir, name),
            LogRollingMode::Minutely => import_log_rolling::minutely(dir, name),
            LogRollingMode::Never => import_log_rolling::never(dir, name),
        }
    }
}

// pub enum LogEventType {
//     ReceivedRequests,
//     BadRequests,
//     AttackRequests,
//     TestRequests,
// }

pub struct LogTime;
///# 用于tracing日志系统的时间格式
///  
/// 使用毫秒级unix时间戳
impl FormatTime for LogTime {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        // use crate::clock::get_unix_epoch_ms;
        // let unix_epoch = get_unix_epoch();

        write!(w, "{}", crate::clock::get_unix_epoch_ms())
    }
}

pub struct ConsoleTime;

/// 面向终端阅读的本地时间，保留毫秒精度。
impl FormatTime for ConsoleTime {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        write!(w, "{}", crate::system_time::format_now())
    }
}

/// 该结构体用于存储登录日志
///
/// event_at 已被废弃了，不需要该参数，数据库会自动设置一个默认值
pub struct LoginLog {
    // pub event: String,             // 该字段存储了事件名称
    // pub event_at: u32,             // 该字段存储了产生事件的事件
    pub event_ip: IpAddr,         // 该字段存储了产生事件的ip地址
    pub event_useage_userid: i32, // 该字段存储了事件所使用的用户id，-1为用户id不存在,可以表示最大的用户ID为32767
    pub is_successful: bool,      // 该字段存储了一个 bool 值，表示（登录）是否成功
}

// 该枚举用于表示
// pub enum EventType {
//     LoginSuccessful(LoginLog),
//     Login,

// }
