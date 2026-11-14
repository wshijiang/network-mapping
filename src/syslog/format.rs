//! RFC 5424 syslog 消息编码（仅现代格式；TCP/TLS 使用 RFC 6587 octet-counting 帧）。

use std::sync::OnceLock;

use chrono::{DateTime, Utc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Info,
    Debug,
}

impl Severity {
    pub fn code(self) -> u8 {
        match self {
            Self::Error => 3,
            Self::Warning => 4,
            Self::Info => 6,
            Self::Debug => 7,
        }
    }

    pub fn from_tracing(level: &tracing::Level) -> Self {
        match *level {
            tracing::Level::ERROR => Self::Error,
            tracing::Level::WARN => Self::Warning,
            tracing::Level::INFO => Self::Info,
            _ => Self::Debug,
        }
    }
}

/// 一条待编码的转发消息（与具体目标无关；facility/app-name 在编码时注入）。
#[derive(Clone, Debug)]
pub struct Message {
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub msgid: &'static str,
    pub sd: Vec<(String, String)>,
    pub text: String,
}

/// UDP 报文上限（避免 IP 分片）；TCP/TLS 放宽到 8KB。
pub const UDP_MAX_BYTES: usize = 1024;
pub const TCP_MAX_BYTES: usize = 8192;

pub fn hostname() -> &'static str {
    static HOSTNAME: OnceLock<String> = OnceLock::new();
    HOSTNAME.get_or_init(|| {
        let raw = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_default()
            .trim()
            .to_owned();
        let sanitized: String = raw
            .chars()
            .filter(|c| c.is_ascii_graphic())
            .take(255)
            .collect();
        if sanitized.is_empty() {
            "localhost".to_owned()
        } else {
            sanitized
        }
    })
}

/// 编码为 RFC 5424 字节流；总长度不超过 `max_bytes`（按 UTF-8 边界截断 MSG）。
pub fn render(message: &Message, facility_code: u8, app_name: &str, max_bytes: usize) -> Vec<u8> {
    let priority = facility_code
        .saturating_mul(8)
        .saturating_add(message.severity.code());
    let structured = if message.sd.is_empty() {
        "-".to_owned()
    } else {
        let params: Vec<String> = message
            .sd
            .iter()
            .map(|(key, value)| format!("{}=\"{}\"", sanitize_key(key), escape_sd_value(value)))
            .collect();
        format!("[nm {}]", params.join(" "))
    };
    let header = format!(
        "<{priority}>1 {} {} {} {} {} {structured} ",
        message.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
        hostname(),
        app_name,
        std::process::id(),
        if message.msgid.is_empty() {
            "-"
        } else {
            message.msgid
        },
    );
    let mut output = header.into_bytes();
    let remaining = max_bytes.saturating_sub(output.len());
    let text = &message.text;
    if text.len() <= remaining {
        output.extend_from_slice(text.as_bytes());
    } else {
        let mut end = remaining;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        output.extend_from_slice(&text.as_bytes()[..end]);
    }
    output
}

/// RFC 6587 octet-counting 帧：`<len> <payload>`。
pub fn frame_octet_counting(payload: &[u8]) -> Vec<u8> {
    let mut framed = format!("{} ", payload.len()).into_bytes();
    framed.extend_from_slice(payload);
    framed
}

fn sanitize_key(key: &str) -> String {
    let sanitized: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .take(32)
        .collect();
    if sanitized.is_empty() {
        "field".to_owned()
    } else {
        sanitized
    }
}

fn escape_sd_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars().take(256) {
        match c {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            ']' => escaped.push_str("\\]"),
            c if c.is_control() => escaped.push(' '),
            c => escaped.push(c),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> Message {
        Message {
            timestamp: "2026-11-14T10:00:00.123Z".parse().unwrap(),
            severity: Severity::Info,
            msgid: "AppLog",
            sd: vec![("event".into(), "TestEvent".into())],
            text: "hello".into(),
        }
    }

    #[test]
    fn renders_rfc5424_header_with_priority() {
        let output = render(&message(), 16, "network-mapping", TCP_MAX_BYTES);
        let text = String::from_utf8(output).unwrap();
        assert!(text.starts_with("<134>1 2026-11-14T10:00:00.123Z "));
        assert!(text.contains(" network-mapping "));
        assert!(text.contains(" AppLog [nm event=\"TestEvent\"] hello"));
    }

    #[test]
    fn escapes_structured_data_values() {
        let mut item = message();
        item.sd = vec![("k".into(), "a\"b\\c]d".into())];
        let output = String::from_utf8(render(&item, 16, "app", TCP_MAX_BYTES)).unwrap();
        assert!(output.contains("[nm k=\"a\\\"b\\\\c\\]d\"]"));
    }

    #[test]
    fn truncates_on_utf8_boundary_within_limit() {
        let mut item = message();
        item.text = "中文日志".repeat(500);
        let output = render(&item, 16, "app", UDP_MAX_BYTES);
        assert!(output.len() <= UDP_MAX_BYTES);
        assert!(String::from_utf8(output).is_ok());
    }

    #[test]
    fn nil_structured_data_uses_dash() {
        let mut item = message();
        item.sd.clear();
        let output = String::from_utf8(render(&item, 16, "app", TCP_MAX_BYTES)).unwrap();
        assert!(output.contains(" AppLog - hello"));
    }

    #[test]
    fn octet_counting_frame_prefixes_length() {
        let framed = frame_octet_counting(b"abc");
        assert_eq!(framed, b"3 abc");
    }

    #[test]
    fn severity_mapping_matches_rfc5424() {
        assert_eq!(Severity::from_tracing(&tracing::Level::ERROR).code(), 3);
        assert_eq!(Severity::from_tracing(&tracing::Level::WARN).code(), 4);
        assert_eq!(Severity::from_tracing(&tracing::Level::INFO).code(), 6);
        assert_eq!(Severity::from_tracing(&tracing::Level::DEBUG).code(), 7);
    }
}
