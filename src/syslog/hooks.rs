//! 四类转发源的入队钩子：审计事件、IP 访问日志、扫描器诊断事件。
//! 系统运行日志由 `forwarder::SyslogLayer` 直接捕获。
//!
//! 消息构造器（`*_item`）同时供历史回填复用，保证实时与回填格式一致。

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::audit::{AuditContext, AuditEvent};
use crate::request_log::RequestLogEntry;
use crate::scanner_diagnostics::parser::ParsedEvent;
use crate::syslog::format::Severity;
use crate::syslog::forwarder::{ForwardItem, capture};
use crate::syslog::metrics::Source;

fn truncate(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

pub fn audit_item(
    event: &AuditEvent,
    context: &AuditContext,
    timestamp: DateTime<Utc>,
) -> ForwardItem {
    let severity = match event.severity.as_str() {
        "critical" | "error" => Severity::Error,
        "warning" => Severity::Warning,
        _ => Severity::Info,
    };
    let mut sd = vec![
        ("category".to_owned(), truncate(&event.category, 64)),
        ("action".to_owned(), truncate(&event.action, 128)),
        ("outcome".to_owned(), truncate(&event.outcome, 32)),
        ("actor_type".to_owned(), truncate(&event.actor_type, 32)),
        ("request_id".to_owned(), context.request_id.to_string()),
    ];
    if let Some(actor) = &event.actor_name {
        sd.push(("actor".to_owned(), truncate(actor, 128)));
    }
    if let Some(resource_type) = &event.resource_type {
        sd.push(("resource_type".to_owned(), truncate(resource_type, 64)));
    }
    if let Some(resource_id) = &event.resource_id {
        sd.push(("resource_id".to_owned(), truncate(resource_id, 128)));
    }
    if let Some(ip) = context.source_ip {
        sd.push(("source_ip".to_owned(), ip.to_string()));
    }
    ForwardItem {
        source: Source::Audit,
        severity,
        msgid: "AuditEvent",
        timestamp,
        text: truncate(
            &format!(
                "{} {} outcome={}",
                event.category, event.action, event.outcome
            ),
            2048,
        ),
        sd,
    }
}

pub fn forward_audit(event: &AuditEvent, context: &AuditContext) {
    let handle = capture();
    if !handle.is_active() {
        return;
    }
    handle.enqueue_source(audit_item(event, context, Utc::now()));
}

/// 防自激放大：syslog 自身的管理/状态/统计接口（前端轮询）不转发。
fn is_syslog_management_path(path: &str) -> bool {
    path.starts_with("/api/syslog") || path == "/api/config/runtime/syslog"
}

pub fn access_item(entry: &RequestLogEntry) -> Option<ForwardItem> {
    if is_syslog_management_path(&entry.request_path) {
        return None;
    }
    let status = entry.status_code;
    let severity = if status >= 500 {
        Severity::Error
    } else if status >= 400 {
        Severity::Warning
    } else {
        Severity::Info
    };
    let mut sd = vec![
        ("request_id".to_owned(), entry.request_id.to_string()),
        ("method".to_owned(), truncate(&entry.http_method, 16)),
        ("path".to_owned(), truncate(&entry.request_path, 512)),
        ("status".to_owned(), status.to_string()),
    ];
    if let Some(duration_ms) = entry.duration_ms {
        sd.push(("duration_ms".to_owned(), duration_ms.to_string()));
    }
    if let Some(ip) = entry.client_ip {
        sd.push(("client_ip".to_owned(), ip.to_string()));
    }
    if let Some(actor) = &entry.actor_name {
        sd.push(("actor".to_owned(), truncate(actor, 128)));
    }
    if let Some(error_type) = &entry.error_type {
        sd.push(("error_type".to_owned(), truncate(error_type, 64)));
    }
    if let Some(reason) = &entry.reason_code {
        sd.push(("reason_code".to_owned(), truncate(reason, 128)));
    }
    Some(ForwardItem {
        source: Source::Access,
        severity,
        msgid: "HttpRequest",
        timestamp: entry.occurred_at,
        text: truncate(
            &format!("{} {} {}", entry.http_method, entry.request_path, status),
            2048,
        ),
        sd,
    })
}

pub fn forward_access(entry: &RequestLogEntry) {
    let handle = capture();
    if !handle.is_active() {
        return;
    }
    if let Some(item) = access_item(entry) {
        handle.enqueue_source(item);
    }
}

pub fn scanner_item(scanner_id: Uuid, event: &ParsedEvent) -> ForwardItem {
    let severity = if event.level == "ERROR" {
        Severity::Error
    } else {
        Severity::Warning
    };
    let message = event
        .document
        .pointer("/fields/error_message")
        .or_else(|| event.document.pointer("/fields/message"))
        .or_else(|| event.document.pointer("/fields/reason"))
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let sd = vec![
        ("scanner_id".to_owned(), scanner_id.to_string()),
        ("event_id".to_owned(), truncate(&event.event_id, 128)),
        ("error_code".to_owned(), truncate(&event.error_code, 128)),
        ("category".to_owned(), truncate(&event.category, 64)),
        ("operation".to_owned(), truncate(&event.operation, 128)),
    ];
    ForwardItem {
        source: Source::Scanner,
        severity,
        msgid: "ScannerDiagnostic",
        timestamp: event.occurred_at,
        text: truncate(&format!("{} {}", event.error_code, message), 2048),
        sd,
    }
}

pub fn forward_scanner_event(scanner_id: Uuid, event: &ParsedEvent) {
    let handle = capture();
    if !handle.is_active() {
        return;
    }
    handle.enqueue_source(scanner_item(scanner_id, event));
}
