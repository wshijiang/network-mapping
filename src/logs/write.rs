use actix_web::{HttpMessage, HttpRequest};
use std::borrow::Cow;
use std::error::Error as StdError;
use tracing::{error, info, warn};
use uuid::Uuid;

// use crate::logs::LogEventType;
use crate::admin::UserBaseI;
use crate::audit::RequestId;
use crate::request_log::set_reason_if_absent;
use crate::{logs::LoginLog, web_support::get_conn_ip, web_support::get_user_agent};

const MAX_ERROR_DIAGNOSTIC_CHARS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseErrorDiagnostics {
    pub sqlstate: String,
    pub severity: String,
    pub message: String,
    pub detail: Option<String>,
    pub hint: Option<String>,
    pub schema: Option<String>,
    pub table: Option<String>,
    pub column: Option<String>,
    pub constraint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorDiagnostics {
    pub error_message: String,
    pub error_chain: String,
    pub root_cause: String,
    pub error_truncated: bool,
    pub database: Option<DatabaseErrorDiagnostics>,
}

pub fn request_id(req: &HttpRequest) -> Uuid {
    req.extensions()
        .get::<RequestId>()
        .map(|value| value.0)
        .unwrap_or_else(Uuid::nil)
}

pub fn database_error_diagnostics(error: &tokio_postgres::Error) -> String {
    let Some(database_error) = error.as_db_error() else {
        return format!("{error:?}");
    };
    format!(
        "sqlstate={} severity={} message={} detail={} hint={} schema={} table={} column={} constraint={}",
        database_error.code().code(),
        database_error.severity(),
        database_error.message(),
        database_error.detail().unwrap_or("-"),
        database_error.hint().unwrap_or("-"),
        database_error.schema().unwrap_or("-"),
        database_error.table().unwrap_or("-"),
        database_error.column().unwrap_or("-"),
        database_error.constraint().unwrap_or("-"),
    )
}

fn truncate_diagnostic(value: String) -> (String, bool) {
    if value.chars().count() <= MAX_ERROR_DIAGNOSTIC_CHARS {
        return (value, false);
    }
    let mut truncated = value
        .chars()
        .take(MAX_ERROR_DIAGNOSTIC_CHARS.saturating_sub(1))
        .collect::<String>();
    truncated.push('…');
    (truncated, true)
}

pub fn error_diagnostics(error: &(dyn StdError + 'static)) -> ErrorDiagnostics {
    let error_message = error.to_string();
    let mut chain = Vec::new();
    let mut database = None;
    let mut current = Some(error);
    while let Some(item) = current {
        if let Some(error) = item.downcast_ref::<tokio_postgres::Error>() {
            if let Some(db) = error.as_db_error() {
                database = Some(DatabaseErrorDiagnostics {
                    sqlstate: db.code().code().to_owned(),
                    severity: db.severity().to_owned(),
                    message: db.message().to_owned(),
                    detail: db.detail().map(str::to_owned),
                    hint: db.hint().map(str::to_owned),
                    schema: db.schema().map(str::to_owned),
                    table: db.table().map(str::to_owned),
                    column: db.column().map(str::to_owned),
                    constraint: db.constraint().map(str::to_owned),
                });
            }
            chain.push(database_error_diagnostics(error));
        } else {
            chain.push(item.to_string());
        }
        current = item.source();
    }
    chain.dedup();
    let root_cause = chain
        .last()
        .cloned()
        .unwrap_or_else(|| error_message.clone());
    let (error_chain, chain_truncated) = truncate_diagnostic(chain.join("; caused_by="));
    let (root_cause, root_truncated) = truncate_diagnostic(root_cause);
    let (error_message, message_truncated) = truncate_diagnostic(error_message);
    ErrorDiagnostics {
        error_message,
        error_chain,
        root_cause,
        error_truncated: chain_truncated || root_truncated || message_truncated,
        database,
    }
}

pub fn error_chain_diagnostics(error: &(dyn StdError + 'static)) -> String {
    error_diagnostics(error).error_chain
}

//TODO:需要获取代理状态下用户的原始ip
pub fn info_logs(req: &HttpRequest, event: &str, message: &str) {
    let req_method = req.method();
    let req_path = crate::reports::redact_mail_image_path(req.path());
    info!(
        event = event,  //"requests_received"
        client_ip = get_conn_ip(req),
        method = %req_method,
        user_agent = get_user_agent(req),
        path = req_path,
        message,
    );
}

pub fn warn_logs(req: &HttpRequest, event: &str, message: &str) {
    let req_method = req.method();
    let req_path = crate::reports::redact_mail_image_path(req.path());
    let actor = req.extensions().get::<UserBaseI>().cloned();
    warn!(
        event = event,
        client_ip = get_conn_ip(req),
        method = %req_method,
        user_agent = get_user_agent(req),
        path = req_path,
        actor_user_id = ?actor.as_ref().map(|value| value.id),
        actor_role = ?actor.as_ref().map(|value| value.role),
        reason = message,
        outcome = "request_continues",
    );
}

pub fn error_logs(req: &HttpRequest, event: &str, message: &str) {
    set_reason_if_absent(req, event);
    let req_method = req.method();
    let req_path = crate::reports::redact_mail_image_path(req.path());
    let actor = req.extensions().get::<UserBaseI>().cloned();
    let resource = request_resource_context(req);
    error!(
        event = event,
        operation = "handle_http_request",
        error_kind = "application",
        error_code = event,
        error_message = message,
        retryable = false,
        outcome = "request_failed",
        client_ip = get_conn_ip(req),
        method = %req_method,
        user_agent = get_user_agent(req),
        path = req_path,
        route_pattern = ?req.match_pattern(),
        actor_user_id = ?actor.as_ref().map(|value| value.id),
        actor_role = ?actor.as_ref().map(|value| value.role),
        resource_param = ?resource.as_ref().map(|value| value.0),
        resource_id = ?resource.as_ref().map(|value| value.1.as_str()),
    );
}

pub fn error_logs_error(
    req: &HttpRequest,
    event: &str,
    operation: &str,
    error_value: &(dyn StdError + 'static),
) {
    let diagnostics = error_diagnostics(error_value);
    let operation = effective_operation(event, operation);
    let error_code = format!("{operation}_failed");
    set_reason_if_absent(req, error_code.clone());
    let actor = req.extensions().get::<UserBaseI>().cloned();
    let resource = request_resource_context(req);
    if let Some(database) = diagnostics.database.as_ref() {
        error!(
            event,
            operation = %operation,
            error_kind = "database",
            error_code = %error_code,
            error_message = %diagnostics.error_message,
            error_chain = %diagnostics.error_chain,
            root_cause = %diagnostics.root_cause,
            error_truncated = diagnostics.error_truncated,
            retryable = false,
            outcome = "request_failed",
            sqlstate = database.sqlstate,
            db_severity = database.severity,
            db_message = database.message,
            db_detail = database.detail.as_deref(),
            db_hint = database.hint.as_deref(),
            db_schema = database.schema.as_deref(),
            db_table = database.table.as_deref(),
            db_column = database.column.as_deref(),
            db_constraint = database.constraint.as_deref(),
            client_ip = get_conn_ip(req),
            method = %req.method(),
            user_agent = get_user_agent(req),
            path = crate::reports::redact_mail_image_path(req.path()),
            route_pattern = ?req.match_pattern(),
            actor_user_id = ?actor.as_ref().map(|value| value.id),
            actor_role = ?actor.as_ref().map(|value| value.role),
            resource_param = ?resource.as_ref().map(|value| value.0),
            resource_id = ?resource.as_ref().map(|value| value.1.as_str()),
        );
    } else {
        error!(
            event,
            operation = %operation,
            error_kind = if operation.contains("database") { "database" } else { "application" },
            error_code = %error_code,
            error_message = %diagnostics.error_message,
            error_chain = %diagnostics.error_chain,
            root_cause = %diagnostics.root_cause,
            error_truncated = diagnostics.error_truncated,
            retryable = false,
            outcome = "request_failed",
            client_ip = get_conn_ip(req),
            method = %req.method(),
            user_agent = get_user_agent(req),
            path = crate::reports::redact_mail_image_path(req.path()),
            route_pattern = ?req.match_pattern(),
            actor_user_id = ?actor.as_ref().map(|value| value.id),
            actor_role = ?actor.as_ref().map(|value| value.role),
            resource_param = ?resource.as_ref().map(|value| value.0),
            resource_id = ?resource.as_ref().map(|value| value.1.as_str()),
        );
    }
}

fn effective_operation<'a>(event: &'a str, operation: &'a str) -> Cow<'a, str> {
    if !matches!(operation, "database_operation" | "tag_database_operation") {
        return Cow::Borrowed(operation);
    }
    let stem = event
        .strip_suffix("Error")
        .or_else(|| event.strip_suffix("Failed"))
        .unwrap_or(event);
    let mut normalized = String::with_capacity(stem.len() + 9);
    for (index, character) in stem.chars().enumerate() {
        if character.is_ascii_uppercase() && index > 0 {
            normalized.push('_');
        }
        normalized.extend(character.to_lowercase());
    }
    normalized.push_str("_database");
    Cow::Owned(normalized)
}

fn request_resource_context(req: &HttpRequest) -> Option<(&'static str, String)> {
    [
        "task_id",
        "execution_id",
        "user_id",
        "tag_id",
        "job_id",
        "scanner_id",
        "id",
    ]
    .into_iter()
    .find_map(|name| {
        req.match_info()
            .get(name)
            .map(|value| (name, value.to_owned()))
    })
}

/// 该函数可以把登录日志数据写入数据库，返回一个 bool ,
///
/// 在该函数中无需其调用者处理错误，该函数 **会自动处理错误，然后返回 bool 值**
pub async fn login_logs_to_db(pool: &deadpool_postgres::Pool, log: LoginLog) -> bool {
    let mut client = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            log_login_database_error("LoginLogPoolError", "acquire_connection", &e, &log);
            return false;
        }
    };
    let transaction = match client.transaction().await {
        Ok(t) => t,
        Err(e) => {
            log_login_database_error("LoginLogTransactionError", "begin_transaction", &e, &log);
            return false;
        }
    };

    // MARK 过一段时间把数据库规划好之后再来处理这
    let row = match transaction.execute(
        "INSERT INTO login_logs( event_ip, event_usage_id, is_successful ) VALUES ( $1, $2, $3 );",
        &[&log.event_ip, &log.event_useage_userid, &log.is_successful]
    ).await {
        Ok(r) => r,
        Err(e) => {
            log_login_database_error("LoginLogInsertError", "insert_login_log", &e, &log);
            return false
        }
    };

    if row > 0 {
        match transaction.commit().await {
            Ok(()) => (),
            Err(e) => {
                log_login_database_error("LoginLogCommitError", "commit_login_log", &e, &log);
                return false;
            }
        };
        true
    } else {
        error!(
            event = "LoginLogInsertError",
            operation = "insert_login_log",
            error_kind = "database",
            error_code = "login_log_no_rows_inserted",
            error_message = "database reported zero inserted login-log rows",
            retryable = false,
            outcome = "login_log_dropped",
            user_id = log.event_useage_userid,
            login_successful = log.is_successful,
        );
        false
    }
}

fn log_login_database_error(
    event: &'static str,
    operation: &'static str,
    error_value: &(dyn StdError + 'static),
    log: &LoginLog,
) {
    let diagnostics = error_diagnostics(error_value);
    error!(
        event,
        operation,
        error_kind = "database",
        error_code = %format!("{operation}_failed"),
        error_message = %diagnostics.error_message,
        error_chain = %diagnostics.error_chain,
        root_cause = %diagnostics.root_cause,
        error_truncated = diagnostics.error_truncated,
        retryable = false,
        outcome = "login_log_dropped",
        user_id = log.event_useage_userid,
        login_successful = log.is_successful,
    );
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_ERROR_DIAGNOSTIC_CHARS, effective_operation, error_chain_diagnostics, error_diagnostics,
    };
    use std::error::Error;
    use std::fmt;

    #[derive(Debug)]
    struct WrappedError(std::io::Error);

    impl fmt::Display for WrappedError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("outer operation failed")
        }
    }

    impl Error for WrappedError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn error_chain_diagnostics_includes_all_causes() {
        let error = WrappedError(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "database connection refused",
        ));

        let diagnostics = error_chain_diagnostics(&error);

        assert!(diagnostics.contains("outer operation failed"));
        assert!(diagnostics.contains("database connection refused"));
        assert!(diagnostics.contains("caused_by="));
    }

    #[test]
    fn structured_error_diagnostics_include_root_cause() {
        let error = WrappedError(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "database connection refused",
        ));
        let diagnostics = error_diagnostics(&error);
        assert_eq!(diagnostics.error_message, "outer operation failed");
        assert_eq!(diagnostics.root_cause, "database connection refused");
        assert!(!diagnostics.error_truncated);
        assert!(diagnostics.database.is_none());
    }

    #[test]
    fn structured_error_diagnostics_are_bounded() {
        let message = "x".repeat(MAX_ERROR_DIAGNOSTIC_CHARS + 100);
        let error = std::io::Error::other(message);
        let diagnostics = error_diagnostics(&error);
        assert!(diagnostics.error_truncated);
        assert_eq!(
            diagnostics.error_message.chars().count(),
            MAX_ERROR_DIAGNOSTIC_CHARS
        );
        assert_eq!(
            diagnostics.error_chain.chars().count(),
            MAX_ERROR_DIAGNOSTIC_CHARS
        );
        assert_eq!(
            diagnostics.root_cause.chars().count(),
            MAX_ERROR_DIAGNOSTIC_CHARS
        );
    }

    #[test]
    fn generic_database_operation_uses_event_specific_name() {
        assert_eq!(
            effective_operation("AuditQueryError", "database_operation"),
            "audit_query_database"
        );
        assert_eq!(
            effective_operation("CreateTaskError", "insert_scan_task"),
            "insert_scan_task"
        );
    }
}
