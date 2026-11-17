//! Structured, append-only security audit event support.

use std::net::IpAddr;

use actix_web::{HttpMessage, HttpRequest};
use deadpool_postgres::{GenericClient, Pool};
use serde_json::{Value, json};
use tokio_postgres::types::ToSql;
use tracing::error;
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::client_ip::request_ip;
use crate::logs::write::error_diagnostics;

#[derive(Clone, Copy, Debug)]
pub struct RequestId(pub Uuid);

#[derive(Clone, Debug)]
pub struct AuditContext {
    pub request_id: Uuid,
    pub source_ip: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub http_method: String,
    pub request_path: String,
}

impl AuditContext {
    pub fn from_request(req: &HttpRequest) -> Self {
        let request_id = req
            .extensions()
            .get::<RequestId>()
            .map(|value| value.0)
            .or_else(|| {
                req.headers()
                    .get("X-Request-ID")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| Uuid::parse_str(value).ok())
            })
            .unwrap_or_else(Uuid::new_v4);

        let source_ip = request_ip(req);
        let user_agent = req
            .headers()
            .get("User-Agent")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.chars().take(512).collect());

        Self {
            request_id,
            source_ip,
            user_agent,
            http_method: req.method().to_string(),
            request_path: req.path().to_owned(),
        }
    }

    /// Build an audit context for a local administrative CLI invocation.
    pub fn cli(command: impl Into<String>) -> Self {
        Self {
            request_id: Uuid::new_v4(),
            source_ip: None,
            user_agent: None,
            http_method: "CLI".to_owned(),
            request_path: command.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub category: String,
    pub action: String,
    pub outcome: String,
    pub severity: String,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub actor_name: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub response_status: Option<u16>,
    pub reason_code: Option<String>,
    pub changes: Option<Value>,
    pub metadata: Value,
}

impl AuditEvent {
    pub fn user(category: &str, action: &str, outcome: &str, user: &UserBaseI) -> Self {
        Self {
            category: category.to_owned(),
            action: action.to_owned(),
            outcome: outcome.to_owned(),
            severity: if outcome == "success" {
                "info"
            } else {
                "warning"
            }
            .to_owned(),
            actor_type: "user".to_owned(),
            actor_id: Some(user.id.to_string()),
            actor_name: Some(user.username.clone()),
            resource_type: None,
            resource_id: None,
            response_status: None,
            reason_code: None,
            changes: None,
            metadata: json!({}),
        }
    }

    pub fn anonymous(category: &str, action: &str, outcome: &str) -> Self {
        Self {
            category: category.to_owned(),
            action: action.to_owned(),
            outcome: outcome.to_owned(),
            severity: "warning".to_owned(),
            actor_type: "anonymous".to_owned(),
            actor_id: None,
            actor_name: None,
            resource_type: None,
            resource_id: None,
            response_status: None,
            reason_code: None,
            changes: None,
            metadata: json!({}),
        }
    }

    pub fn system(category: &str, action: &str, outcome: &str) -> Self {
        Self {
            category: category.to_owned(),
            action: action.to_owned(),
            outcome: outcome.to_owned(),
            severity: if outcome == "success" {
                "info"
            } else {
                "warning"
            }
            .to_owned(),
            actor_type: "system".to_owned(),
            actor_id: None,
            actor_name: Some("cli".to_owned()),
            resource_type: None,
            resource_id: None,
            response_status: None,
            reason_code: None,
            changes: None,
            metadata: json!({}),
        }
    }

    pub fn resource(mut self, resource_type: &str, resource_id: impl Into<String>) -> Self {
        self.resource_type = Some(resource_type.to_owned());
        self.resource_id = Some(resource_id.into());
        self
    }
}

pub async fn write<C>(
    client: &C,
    context: &AuditContext,
    event: &AuditEvent,
) -> Result<(), tokio_postgres::Error>
where
    C: GenericClient + Sync,
{
    let response_status = event.response_status.map(|value| value as i16);
    let params: &[&(dyn ToSql + Sync)] = &[
        &Uuid::new_v4(),
        &event.category,
        &event.action,
        &event.outcome,
        &event.severity,
        &event.actor_type,
        &event.actor_id,
        &event.actor_name,
        &event.resource_type,
        &event.resource_id,
        &context.request_id,
        &context.source_ip,
        &context.user_agent,
        &context.http_method,
        &context.request_path,
        &response_status,
        &event.reason_code,
        &event.changes,
        &event.metadata,
    ];
    client
        .execute(
            "INSERT INTO audit_event (event_id, category, action, outcome, severity, actor_type, \
             actor_id, actor_name, resource_type, resource_id, request_id, source_ip, user_agent, \
             http_method, request_path, response_status, reason_code, changes, metadata) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
             $16::SMALLINT, $17, $18, $19);",
            params,
        )
        .await?;
    // 尽力而为的 syslog 转发：即使外层事务随后回滚，转发副本仍保留
    // （日志转发不参与数据库事务）。
    crate::syslog::hooks::forward_audit(event, context);
    Ok(())
}

pub async fn write_standalone(pool: &Pool, context: &AuditContext, event: &AuditEvent) -> bool {
    let client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            log_audit_write_error(
                "AuditPoolError",
                "acquire_audit_connection",
                context,
                event,
                &error_value,
            );
            return false;
        }
    };
    if let Err(error_value) = write(&client, context, event).await {
        log_audit_write_error(
            "AuditWriteError",
            "insert_audit_event",
            context,
            event,
            &error_value,
        );
        return false;
    }
    true
}

fn log_audit_write_error(
    log_event: &'static str,
    operation: &'static str,
    context: &AuditContext,
    audit_event: &AuditEvent,
    error_value: &(dyn std::error::Error + 'static),
) {
    let diagnostics = error_diagnostics(error_value);
    let database = diagnostics.database.as_ref();
    error!(
        event = log_event,
        operation,
        error_kind = "database",
        error_code = %format!("{operation}_failed"),
        error_message = %diagnostics.error_message,
        error_chain = %diagnostics.error_chain,
        root_cause = %diagnostics.root_cause,
        error_truncated = diagnostics.error_truncated,
        retryable = false,
        outcome = "audit_event_dropped",
        request_id = %context.request_id,
        category = %audit_event.category,
        action = %audit_event.action,
        audit_outcome = %audit_event.outcome,
        resource_type = ?audit_event.resource_type,
        resource_id = ?audit_event.resource_id,
        sqlstate = ?database.map(|value| value.sqlstate.as_str()),
        db_constraint = ?database.and_then(|value| value.constraint.as_deref()),
    );
}

#[cfg(test)]
mod tests {
    use super::AuditContext;
    use crate::client_ip::{ResolvedClientIp, parse_ip};
    use actix_web::{HttpMessage, test as actix_test};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_ip_and_socket_address() {
        assert_eq!(
            parse_ip("192.0.2.1"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(
            parse_ip("192.0.2.1:443"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(
            parse_ip("[2001:db8::1]:443"),
            Some(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()))
        );
        assert_eq!(
            parse_ip("::ffff:64.81.116.137"),
            Some(IpAddr::V4(Ipv4Addr::new(64, 81, 116, 137)))
        );
        assert_eq!(parse_ip("unknown"), None);
    }

    #[test]
    fn audit_context_uses_centrally_resolved_client_ip() {
        let request = actix_test::TestRequest::default()
            .peer_addr("[::1]:443".parse().unwrap())
            .insert_header(("x-forwarded-for", "203.0.113.29"))
            .to_http_request();
        request
            .extensions_mut()
            .insert(ResolvedClientIp(Some("203.0.113.29".parse().unwrap())));

        assert_eq!(
            AuditContext::from_request(&request).source_ip,
            Some("203.0.113.29".parse().unwrap())
        );
    }

    #[test]
    fn database_schema_allows_backup_audit_events_and_migrates_existing_constraints() {
        let initialization_sql = include_str!("../../source/database/init.sql");

        assert!(initialization_sql.contains(
            "'data_access', 'audit', 'backup', 'data_import', 'federation', 'data_export'\n\t))"
        ));
        assert!(
            initialization_sql.contains(
                "'data_access', 'audit', 'backup', 'data_import', 'federation', 'data_export'\n        ))"
            )
        );
        assert!(
            initialization_sql.contains("OR POSITION('backup' IN pg_get_constraintdef(oid)) = 0")
        );
        assert!(
            initialization_sql
                .contains("OR POSITION('data_import' IN pg_get_constraintdef(oid)) = 0")
        );
        assert!(
            initialization_sql
                .contains("OR POSITION('federation' IN pg_get_constraintdef(oid)) = 0")
        );
        assert!(
            initialization_sql
                .contains("OR POSITION('data_export' IN pg_get_constraintdef(oid)) = 0")
        );
    }
}
