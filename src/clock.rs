//! clock domain implementation, migrated from the library root.

use std::time::{SystemTime, UNIX_EPOCH};
use tracing::error;

pub fn get_unix_epoch_ms() -> i64 {
    //todo 添加一个获取普通utc时间的函数，考虑用结构体还是权举
    // 当获取时间戳失败时会返回默认值-1
    // SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis() as i64,
        Err(e) => {
            error!(
                event = "UnixEpochGenerateError",
                operation = "read_system_time",
                error_kind = "system_clock",
                error_code = "system_clock_before_unix_epoch",
                error_message = %e,
                retryable = false,
                outcome = "sentinel_timestamp_returned",
                fallback_timestamp_ms = -1_i64,
            );
            -1_i64
        }
    }
}
