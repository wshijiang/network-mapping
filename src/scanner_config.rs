use actix_web::{HttpRequest, HttpResponse, Responder, get, put, web};
use deadpool_postgres::{GenericClient, Pool};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write as write_audit};
use crate::config::SecurityConfig;
use crate::logs::write::error_logs_error;
use crate::{ApplyTaskError, validate_scanner_credentials};

pub const SCHEMA_VERSION: i32 = 1;

pub fn default_batch_endpoints() -> usize {
    512
}
pub fn default_idle_timeout() -> u64 {
    120
}
pub fn default_service_runtime() -> u64 {
    1800
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScannerRuntimeConfig {
    pub masscan: MasscanRuntimeConfig,
    pub service_detection: ServiceDetectionRuntimeConfig,
    pub dns: DnsRuntimeConfig,
    pub nuclei: NucleiRuntimeConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MasscanRuntimeConfig {
    pub rate: i32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServiceDetectionRuntimeConfig {
    #[serde(default = "default_batch_endpoints")]
    pub batch_endpoints: usize,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_seconds: u64,
    #[serde(default = "default_service_runtime")]
    pub max_runtime_seconds: u64,
    pub enabled: bool,
    pub strategy: String,
    pub max_probes_per_endpoint: usize,
    pub confidence_threshold: u8,
    pub senders: u32,
    pub server_rate_limit: u32,
    pub connect_timeout_seconds: u64,
    pub target_timeout_seconds: u64,
    pub max_result_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DnsRuntimeConfig {
    pub enabled: bool,
    pub record_types: Vec<String>,
    pub query_timeout_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NucleiRuntimeConfig {
    pub enabled: bool,
    pub port_fallback: bool,
    pub severities: Vec<String>,
    pub rate_limit: u32,
    pub bulk_size: usize,
    pub concurrency: usize,
    pub timeout_seconds: u64,
    pub retries: u8,
    pub max_runtime_seconds: u64,
    pub max_findings: usize,
    pub max_result_bytes: usize,
}

impl Default for ScannerRuntimeConfig {
    fn default() -> Self {
        Self {
            masscan: MasscanRuntimeConfig { rate: 100_000 },
            service_detection: ServiceDetectionRuntimeConfig {
                batch_endpoints: default_batch_endpoints(),
                idle_timeout_seconds: default_idle_timeout(),
                max_runtime_seconds: default_service_runtime(),
                enabled: true,
                strategy: "adaptive".into(),
                max_probes_per_endpoint: 8,
                confidence_threshold: 80,
                senders: 200,
                server_rate_limit: 20,
                connect_timeout_seconds: 5,
                target_timeout_seconds: 15,
                max_result_bytes: 65_536,
            },
            dns: DnsRuntimeConfig {
                enabled: true,
                record_types: crate::dns::DNS_RECORD_TYPES
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                query_timeout_seconds: 5,
            },
            nuclei: NucleiRuntimeConfig {
                enabled: false,
                port_fallback: true,
                severities: vec!["medium".into(), "high".into(), "critical".into()],
                rate_limit: 20,
                bulk_size: 5,
                concurrency: 5,
                timeout_seconds: 10,
                retries: 1,
                max_runtime_seconds: 1_800,
                max_findings: 10_000,
                max_result_bytes: 262_144,
            },
        }
    }
}

impl ScannerRuntimeConfig {
    pub fn validate(&self) -> Result<(), String> {
        check_range(
            "service_detection.batch_endpoints",
            self.service_detection.batch_endpoints,
            1,
            4096,
        )?;
        check_range(
            "service_detection.idle_timeout_seconds",
            self.service_detection.idle_timeout_seconds,
            1,
            3600,
        )?;
        check_range(
            "service_detection.max_runtime_seconds",
            self.service_detection.max_runtime_seconds,
            1,
            86400,
        )?;
        check_range("masscan.rate", self.masscan.rate, 1, i32::MAX)?;
        if !matches!(
            self.service_detection.strategy.as_str(),
            "standard" | "adaptive" | "exhaustive"
        ) {
            return Err(
                "service_detection.strategy must be standard, adaptive or exhaustive".into(),
            );
        }
        check_range(
            "service_detection.max_probes_per_endpoint",
            self.service_detection.max_probes_per_endpoint,
            1,
            32,
        )?;
        check_range(
            "service_detection.confidence_threshold",
            self.service_detection.confidence_threshold,
            1,
            100,
        )?;
        check_range(
            "service_detection.senders",
            self.service_detection.senders,
            1,
            10_000,
        )?;
        check_range(
            "service_detection.server_rate_limit",
            self.service_detection.server_rate_limit,
            1,
            10_000,
        )?;
        check_range(
            "service_detection.connect_timeout_seconds",
            self.service_detection.connect_timeout_seconds,
            1,
            60,
        )?;
        check_range(
            "service_detection.target_timeout_seconds",
            self.service_detection.target_timeout_seconds,
            self.service_detection.connect_timeout_seconds,
            300,
        )?;
        check_range(
            "service_detection.max_result_bytes",
            self.service_detection.max_result_bytes,
            1_024,
            1_048_576,
        )?;
        check_range(
            "dns.query_timeout_seconds",
            self.dns.query_timeout_seconds,
            1,
            60,
        )?;
        if self.dns.record_types.is_empty()
            || self.dns.record_types.len() > crate::dns::DNS_RECORD_TYPES.len()
            || self
                .dns
                .record_types
                .iter()
                .any(|value| crate::dns::canonical_record_type(value).is_err())
        {
            return Err("dns.record_types contains an unsupported record type".into());
        }
        if self.nuclei.severities.is_empty()
            || self.nuclei.severities.len() > 5
            || self.nuclei.severities.iter().any(|value| {
                !matches!(
                    value.as_str(),
                    "info" | "low" | "medium" | "high" | "critical"
                )
            })
        {
            return Err("nuclei.severities contains an unsupported value".into());
        }
        check_range("nuclei.rate_limit", self.nuclei.rate_limit, 1, 10_000)?;
        check_range("nuclei.bulk_size", self.nuclei.bulk_size, 1, 1_000)?;
        check_range("nuclei.concurrency", self.nuclei.concurrency, 1, 1_000)?;
        check_range(
            "nuclei.timeout_seconds",
            self.nuclei.timeout_seconds,
            1,
            300,
        )?;
        check_range("nuclei.retries", self.nuclei.retries, 0, 10)?;
        check_range(
            "nuclei.max_runtime_seconds",
            self.nuclei.max_runtime_seconds,
            10,
            86_400,
        )?;
        check_range("nuclei.max_findings", self.nuclei.max_findings, 1, 100_000)?;
        check_range(
            "nuclei.max_result_bytes",
            self.nuclei.max_result_bytes,
            4_096,
            1_048_576,
        )?;
        Ok(())
    }
}

fn check_range<T>(field: &str, value: T, minimum: T, maximum: T) -> Result<(), String>
where
    T: PartialOrd + std::fmt::Display,
{
    if value < minimum || value > maximum {
        Err(format!("{field} must be between {minimum} and {maximum}"))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ScannerConfigurationEnvelope {
    pub revision: i64,
    pub schema_version: i32,
    pub document: ScannerRuntimeConfig,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScannerConfigurationNotice {
    pub revision: i64,
    pub schema_version: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateScannerConfiguration {
    expected_revision: i64,
    document: ScannerRuntimeConfig,
    #[serde(default)]
    change_reason: String,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeConfigurationQuery {
    scannerid: Uuid,
}

pub async fn ensure_configuration<C>(
    client: &C,
    scanner_id: &str,
) -> Result<(), tokio_postgres::Error>
where
    C: GenericClient + Sync,
{
    let document = serde_json::to_value(ScannerRuntimeConfig::default())
        .expect("default scanner configuration must serialize");
    client
        .execute(
            "INSERT INTO scanner_runtime_configuration (scanner_id, document) \
         SELECT scanner_id, $2 FROM scanner_info WHERE scanner_id = $1 AND deleted_at IS NULL \
         ON CONFLICT (scanner_id) DO NOTHING;",
            &[&scanner_id, &document],
        )
        .await?;
    client.execute(
        "INSERT INTO scanner_runtime_configuration_revision (scanner_id, revision, schema_version, document, change_reason) \
         SELECT scanner_id, revision, schema_version, document, 'initial defaults' FROM scanner_runtime_configuration \
         WHERE scanner_id = $1 ON CONFLICT (scanner_id, revision) DO NOTHING;",
        &[&scanner_id],
    ).await?;
    Ok(())
}

pub async fn load_configuration<C>(
    client: &C,
    scanner_id: &str,
) -> Result<Option<ScannerConfigurationEnvelope>, Box<dyn std::error::Error + Send + Sync>>
where
    C: GenericClient + Sync,
{
    ensure_configuration(client, scanner_id).await?;
    let row = client.query_opt(
        "SELECT revision, schema_version, document FROM scanner_runtime_configuration WHERE scanner_id = $1;",
        &[&scanner_id],
    ).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let document: Value = row.get("document");
    let document: ScannerRuntimeConfig = serde_json::from_value(document)?;
    document.validate()?;
    Ok(Some(ScannerConfigurationEnvelope {
        revision: row.get("revision"),
        schema_version: row.get("schema_version"),
        document,
    }))
}

#[get("/api/scanner/{scanner_id}/configuration")]
pub async fn get_scanner_configuration(
    req: HttpRequest,
    pool: web::Data<Pool>,
    scanner_id: web::Path<Uuid>,
    user: UserBaseI,
) -> impl Responder {
    if user.role != 1 {
        return HttpResponse::Forbidden()
            .json(json!({"success": false, "message": "仅管理员可以查看扫描器配置"}));
    }
    let scanner_id = scanner_id.into_inner().to_string();
    let client = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerConfigurationPoolError",
                "acquire_connection",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    match load_configuration(&client, &scanner_id).await {
        Ok(Some(configuration)) => {
            let status = client.query_one(
                "SELECT name, applied_config_revision, config_status, config_error, config_reported_at, local_config_check FROM scanner_info WHERE scanner_id = $1;",
                &[&scanner_id],
            ).await;
            match status {
                Ok(row) => HttpResponse::Ok().json(json!({"success": true, "data": {
                    "scanner_id": scanner_id,
                    "scanner_name": row.get::<_, Option<String>>("name"),
                    "revision": configuration.revision,
                    "schema_version": configuration.schema_version,
                    "document": configuration.document,
                    "applied_revision": row.get::<_, Option<i64>>("applied_config_revision"),
                    "status": row.get::<_, Option<String>>("config_status"),
                    "error": row.get::<_, Option<String>>("config_error"),
                    "reported_at": row.get::<_, Option<chrono::DateTime<chrono::Utc>>>("config_reported_at"),
                    "local_config_check": row.get::<_, Option<Value>>("local_config_check"),
                }})),
                Err(error) => {
                    error_logs_error(&req, "ScannerConfigurationStatusError", "load_status", &error);
                    HttpResponse::InternalServerError().finish()
                }
            }
        }
        Ok(None) => {
            HttpResponse::NotFound().json(json!({"success": false, "message": "scanner not found"}))
        }
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerConfigurationLoadError",
                "load_configuration",
                error.as_ref(),
            );
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[put("/api/scanner/{scanner_id}/configuration")]
pub async fn update_scanner_configuration(
    req: HttpRequest,
    pool: web::Data<Pool>,
    scanner_id: web::Path<Uuid>,
    body: web::Json<UpdateScannerConfiguration>,
    user: UserBaseI,
) -> impl Responder {
    if user.role != 1 {
        return HttpResponse::Forbidden().finish();
    }
    if let Err(message) = body.document.validate() {
        return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
    }
    if body.change_reason.chars().count() > 500 {
        return HttpResponse::BadRequest().json(
            json!({"success": false, "message": "changeReason must contain at most 500 characters"}),
        );
    }
    let scanner_id = scanner_id.into_inner().to_string();
    let document = match serde_json::to_value(&body.document) {
        Ok(value) => value,
        Err(_) => return HttpResponse::BadRequest().finish(),
    };
    let mut client = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerConfigurationPoolError",
                "acquire_connection",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match client.transaction().await {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerConfigurationTransactionError",
                "begin_transaction",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    if let Err(error) = ensure_configuration(&transaction, &scanner_id).await {
        error_logs_error(
            &req,
            "ScannerConfigurationEnsureError",
            "ensure_configuration",
            &error,
        );
        return HttpResponse::InternalServerError().finish();
    }
    let updated = transaction.query_opt(
        "UPDATE scanner_runtime_configuration SET document = $1, revision = revision + 1, schema_version = $2, \
         updated_at = NOW(), updated_by_user_id = $3 WHERE scanner_id = $4 AND revision = $5 \
         RETURNING revision;",
        &[&document, &SCHEMA_VERSION, &user.id, &scanner_id, &body.expected_revision],
    ).await;
    let revision = match updated {
        Ok(Some(row)) => row.get::<_, i64>("revision"),
        Ok(None) => {
            return HttpResponse::Conflict()
                .json(json!({"success": false, "message": "configuration revision conflict"}));
        }
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerConfigurationUpdateError",
                "update_configuration",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    if let Err(error) = transaction.execute(
        "INSERT INTO scanner_runtime_configuration_revision (scanner_id, revision, schema_version, document, changed_by_user_id, change_reason) VALUES ($1, $2, $3, $4, $5, $6);",
        &[&scanner_id, &revision, &SCHEMA_VERSION, &document, &user.id, &body.change_reason.trim()],
    ).await {
        error_logs_error(&req, "ScannerConfigurationHistoryError", "write_history", &error);
        return HttpResponse::InternalServerError().finish();
    }
    let mut event = AuditEvent::user("scanner", "scanner.configuration.update", "success", &user)
        .resource("scanner", &scanner_id);
    event.changes = Some(json!({"revision": revision, "change_reason": body.change_reason.trim()}));
    event.response_status = Some(200);
    if let Err(error) = write_audit(&transaction, &AuditContext::from_request(&req), &event).await {
        error_logs_error(
            &req,
            "ScannerConfigurationAuditError",
            "write_configuration_audit",
            &error,
        );
        return HttpResponse::InternalServerError().finish();
    }
    if let Err(error) = transaction.commit().await {
        error_logs_error(
            &req,
            "ScannerConfigurationCommitError",
            "commit_configuration_update",
            &error,
        );
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().json(json!({"success": true, "data": {
        "scanner_id": scanner_id,
        "revision": revision,
        "schema_version": SCHEMA_VERSION,
        "document": body.document,
    }}))
}

#[get("/api/scanner/runtime-config")]
pub async fn get_runtime_scanner_configuration(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    query: web::Query<RuntimeConfigurationQuery>,
) -> impl Responder {
    let Some(token) = req
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };
    match validate_scanner_credentials(
        pool.get_ref(),
        query.scannerid,
        token,
        &security.scanner_token_pepper,
    )
    .await
    {
        Ok(()) => {}
        Err(ApplyTaskError::ScannerUnauthorized) => {
            return HttpResponse::Unauthorized().body("unauthorized");
        }
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerRuntimeCredentialError",
                "validate_scanner_credentials",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    }
    let client = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerRuntimePoolError",
                "acquire_scanner_configuration_connection",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    match load_configuration(&client, &query.scannerid.to_string()).await {
        Ok(Some(configuration)) => {
            HttpResponse::Ok().json(json!({"success": true, "data": configuration}))
        }
        Ok(None) => HttpResponse::NotFound().finish(),
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerRuntimeConfigurationError",
                "load_configuration",
                error.as_ref(),
            );
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn old_configuration_documents_use_service_runtime_defaults() {
        let mut value = serde_json::to_value(super::ScannerRuntimeConfig::default()).unwrap();
        let service = value["service_detection"].as_object_mut().unwrap();
        service.remove("batch_endpoints");
        service.remove("idle_timeout_seconds");
        service.remove("max_runtime_seconds");
        let config: super::ScannerRuntimeConfig = serde_json::from_value(value).unwrap();
        config.validate().unwrap();
        assert_eq!(config.service_detection.batch_endpoints, 512);
        assert_eq!(config.service_detection.idle_timeout_seconds, 120);
        assert_eq!(config.service_detection.max_runtime_seconds, 1800);
    }

    use super::*;

    #[test]
    fn defaults_are_valid() {
        ScannerRuntimeConfig::default().validate().unwrap();
    }

    #[test]
    fn rejects_excessive_probe_budget() {
        let mut config = ScannerRuntimeConfig::default();
        config.service_detection.max_probes_per_endpoint = 33;
        assert!(config.validate().is_err());
    }
}
