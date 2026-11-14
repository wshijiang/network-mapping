//! Bounded, version tolerant normalization. Log contents are untrusted input.
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::io::BufRead;

pub const MAX_LINE_BYTES: usize = 64 * 1024;

pub fn digest(bytes: &[u8]) -> String {
    openssl::sha::sha256(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn text(value: &Value) -> String {
    let Some(value) = value.as_str() else {
        return String::new();
    };
    if value == "None" {
        return String::new();
    }
    if let Some(inner) = value
        .strip_prefix("Some(")
        .and_then(|s| s.strip_suffix(')'))
    {
        return serde_json::from_str::<String>(inner).unwrap_or_else(|_| inner.to_owned());
    }
    value.chars().take(2048).collect()
}

pub fn redact(input: &str) -> String {
    use std::sync::OnceLock;
    static CREDENTIAL: OnceLock<regex::Regex> = OnceLock::new();
    static URL: OnceLock<regex::Regex> = OnceLock::new();
    let credential = CREDENTIAL.get_or_init(|| regex::Regex::new(
        r#"(?i)(?:\b(?:password|passwd|token|secret|authorization|api_key)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)|\bbearer\s+[a-z0-9._-]+|nm_(?:run|reg)_[a-z0-9_-]+)"#
    ).expect("constant credential regex"));
    let url = URL.get_or_init(|| {
        regex::Regex::new(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s]+").expect("constant URL regex")
    });
    let redacted = credential.replace_all(input, "[REDACTED]");
    url.replace_all(&redacted, "[REDACTED]")
        .chars()
        .take(2048)
        .collect()
}

#[derive(Debug, Clone)]
pub struct ParsedEvent {
    pub event_id: String,
    pub occurred_at: DateTime<Utc>,
    pub level: String,
    pub error_code: String,
    pub category: String,
    pub operation: String,
    pub fingerprint: String,
    pub document: Value,
}

pub fn recovery(value: &Value) -> Option<(String, DateTime<Utc>)> {
    if value["level"].as_str()? != "INFO"
        || value.pointer("/fields/event")?.as_str()? != "ScannerOperationRecovered"
    {
        return None;
    }
    Some((
        text(&value["fields"]["operation"]),
        value["timestamp"].as_str()?.parse().ok()?,
    ))
}

pub fn parse(value: &Value, fallback_id: &str) -> Option<ParsedEvent> {
    let level = value["level"].as_str()?;
    if !matches!(level, "ERROR" | "WARN") {
        return None;
    }
    let fields = value.get("fields")?.as_object()?;
    let event = text(&value["fields"]["event"]);
    let mut code = text(&value["fields"]["error_code"]);
    if code == "server_maintenance" || event.contains("Maintenance") {
        return None;
    }
    if code.len() > 128
        || !code
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        code.clear();
    }
    let structured = !code.is_empty();
    let message = fields
        .get("error_message")
        .or_else(|| fields.get("reason"))
        .or_else(|| fields.get("error"))
        .or_else(|| fields.get("message"))
        .map(text)
        .unwrap_or_default();
    if code.is_empty() {
        let lower = message.to_lowercase();
        code = if event == "SCAN-ERROR" {
            "legacy_scan_failed"
        } else if lower.contains("permission denied") {
            "legacy_permission_denied"
        } else if lower.contains("no space left") {
            "legacy_disk_full"
        } else if event == "CONFIG-LOAD" {
            "legacy_config_load_failed"
        } else if lower.contains("panic") {
            "legacy_panic"
        } else if level == "WARN" {
            "unclassified_warning"
        } else {
            "unknown_error"
        }
        .to_owned();
    }
    let category = if code.contains("lease") {
        "lease"
    } else if code.contains("optional") {
        "partial_result"
    } else if code.contains("token") || code.contains("auth") {
        "authentication"
    } else if code.starts_with("server_") || code.starts_with("invalid_server") {
        "communication"
    } else if code.contains("config") || code == "scanner_engine_validation_failed" {
        "configuration"
    } else if code.contains("storage") || code.contains("cache") || code.contains("disk") {
        "storage"
    } else if code.contains("restart") || code.contains("panic") || code.contains("fatal") {
        "process"
    } else if ["masscan", "zgrab2", "nuclei", "dns", "scan_"]
        .iter()
        .any(|prefix| code.starts_with(prefix))
    {
        "scan_engine"
    } else {
        "unknown"
    }
    .to_owned();
    let engine = text(&value["fields"]["engine"]);
    let stage = text(&value["fields"]["stage"]);
    let operation = text(&value["fields"]["operation"]);
    let fingerprint = digest(format!("{code}\0{engine}\0{stage}\0{operation}").as_bytes());
    let occurred_at = value["timestamp"].as_str().and_then(|s| s.parse().ok())?;
    let event_id = value["fields"]["event_id"]
        .as_str()
        .filter(|id| uuid::Uuid::parse_str(id).is_ok())
        .unwrap_or(fallback_id)
        .to_owned();
    let task_id = fields
        .get("task_id")
        .map(text)
        .filter(|s| uuid::Uuid::parse_str(s).is_ok())
        .or_else(|| {
            value
                .pointer("/span/task_id")
                .map(text)
                .filter(|s| uuid::Uuid::parse_str(s).is_ok())
        });
    let mut details = serde_json::Map::new();
    for key in [
        "exit_code",
        "process_id",
        "elapsed_ms",
        "process_elapsed_ms",
        "result_count",
        "invalid_line_count",
        "stderr_bytes",
        "stderr_truncated",
        "http_status",
        "retryable",
        "attempt",
        "task_retryable",
    ] {
        if let Some(v) = fields.get(key) {
            // Only typed scalar diagnostics are stored; debug strings are bounded.
            let scalar = if v.is_string() {
                serde_json::from_str::<Value>(&text(v)).ok()
            } else {
                Some(v.clone())
            };
            if let Some(scalar) = scalar.filter(|v| v.is_number() || v.is_boolean() || v.is_null())
            {
                details.insert(key.to_owned(), scalar);
            }
        }
    }
    Some(ParsedEvent {
        event_id,
        occurred_at,
        level: level.to_owned(),
        error_code: code.clone(),
        category: category.clone(),
        operation: operation.clone(),
        fingerprint,
        document: json!({"event":redact(&event), "error_code":code, "category":category,
            "operation":redact(&operation), "engine":redact(&engine), "stage":redact(&stage),
            "message":redact(&message), "task_id":task_id, "boot_id":value["fields"]["boot_id"].as_str().and_then(|s| uuid::Uuid::parse_str(s).ok()).map(|id|id.to_string()),
            "classification_source":if structured {"structured"} else {"legacy_rule"},
            "confidence":if structured {"high"} else {"low"}, "details":details}),
    })
}

/// Returns a complete bounded line, or skips an oversized line without allocating it.
pub fn next_line<R: BufRead>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> std::io::Result<Option<(u64, bool)>> {
    buffer.clear();
    let mut consumed = 0_u64;
    let mut oversized = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok((consumed != 0).then_some((consumed, oversized)));
        }
        let end = available.iter().position(|b| *b == b'\n').map(|n| n + 1);
        let size = end.unwrap_or(available.len());
        consumed += size as u64;
        if buffer.len() + size <= MAX_LINE_BYTES && !oversized {
            buffer.extend_from_slice(&available[..size]);
        } else {
            oversized = true;
            buffer.clear();
        }
        reader.consume(size);
        if end.is_some() {
            return Ok(Some((consumed, oversized)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_and_structured_logs_preserve_task_semantics() {
        let event = parse(&json!({"timestamp":"2026-10-01T08:00:00Z","level":"WARN","fields":{
            "error_code":"optional_service_detection_failed","engine":"Some(\"zgrab2\")","message":"failed https://private.example?token=abc"}}),"legacy-id").unwrap();
        assert_eq!(event.category, "partial_result");
        assert_eq!(event.document["engine"], "zgrab2");
        assert!(!event.document.to_string().contains("private.example"));
        assert!(parse(&json!({"timestamp":"2026-10-01T08:00:00Z","level":"WARN","fields":{"error_code":"server_maintenance"}}),"id").is_none());
        let legacy = parse(&json!({"timestamp":"2026-10-01T08:00:00Z","level":"ERROR","fields":{"event":"SCAN-ERROR"}}),"offset").unwrap();
        assert_eq!(legacy.error_code, "legacy_scan_failed");
        assert_eq!(legacy.event_id, "offset");
    }

    #[test]
    fn oversized_line_does_not_hide_next_error() {
        let mut input = vec![b'x'; MAX_LINE_BYTES * 4];
        input.extend_from_slice(b"\n{}\n");
        let mut reader = std::io::BufReader::new(input.as_slice());
        let mut buffer = Vec::new();
        assert!(next_line(&mut reader, &mut buffer).unwrap().unwrap().1);
        assert!(buffer.is_empty());
        assert!(!next_line(&mut reader, &mut buffer).unwrap().unwrap().1);
        assert_eq!(buffer, b"{}\n");
    }
}
