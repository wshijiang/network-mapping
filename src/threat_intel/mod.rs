//! Source-trusted IOC ingestion and mandatory, version-bound AI review.
//! Published facts are matched at read time after asset authorization. Scanner
//! observations and upload checksums never contain these mutable annotations.
mod client;
mod credentials;
mod model;
mod parse;
mod routes;
mod storage;
#[cfg(test)]
mod tests;
mod worker;

pub use routes::configure;
pub(crate) use storage::{Annotation, annotate, endpoint_keys};
pub use worker::run;

use actix_web::{HttpResponse, http::StatusCode};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    admin::UserBaseI,
    audit::{AuditContext, AuditEvent},
};
use model::*;

#[derive(Debug)]
struct Error {
    status: StatusCode,
    code: &'static str,
}
type Result<T> = std::result::Result<T, Error>;
impl Error {
    fn bad(code: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
        }
    }
    fn conflict() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "intel_revision_conflict",
        }
    }
    fn missing() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "intel_not_found",
        }
    }
    fn unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "intel_storage_unavailable",
        }
    }
}
impl From<tokio_postgres::Error> for Error {
    fn from(_: tokio_postgres::Error) -> Self {
        Self::unavailable()
    }
}
impl From<deadpool_postgres::PoolError> for Error {
    fn from(_: deadpool_postgres::PoolError) -> Self {
        Self::unavailable()
    }
}
fn admin(user: &UserBaseI) -> Result<()> {
    if user.role == 1 {
        Ok(())
    } else {
        Err(Error {
            status: StatusCode::FORBIDDEN,
            code: "intel_admin_required",
        })
    }
}
fn response<T: Serialize>(result: Result<T>) -> HttpResponse {
    match result {
        Ok(data) => HttpResponse::Ok().json(json!({"success":true,"data":data})),
        Err(e) => HttpResponse::build(e.status)
            .json(json!({"success":false,"code":e.code,"message":e.code})),
    }
}
async fn audit<C: deadpool_postgres::GenericClient + Sync>(
    c: &C,
    user: &UserBaseI,
    context: &AuditContext,
    action: &str,
    id: &str,
    metadata: Value,
) -> Result<()> {
    let mut event = AuditEvent::user("data_access", action, "success", user)
        .resource("threat_intelligence", id);
    event.metadata = metadata;
    crate::audit::write(c, context, &event).await?;
    Ok(())
}
fn digest(bytes: &[u8]) -> String {
    openssl::sha::sha256(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
