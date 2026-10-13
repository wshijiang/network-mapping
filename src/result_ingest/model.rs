//! result_ingest / model domain implementation, migrated from the library root.

use ipnet::AddrParseError;
use serde::Deserialize;
use serde_json::Value;
use std::fmt;
use uuid::Uuid;

use crate::dns;

#[derive(Clone, Deserialize)]
pub struct ScannerResultUpload {
    #[serde(default = "default_result_protocol_version")]
    pub protocol_version: u16,
    pub scanner_id: Uuid,
    pub task_id: Uuid,
    pub upload_id: Option<Uuid>,
    pub batch_index: Option<u32>,
    pub is_final: Option<bool>,
    #[serde(default)]
    pub observations: Vec<ScannerObservation>,
    #[serde(default)]
    pub results: Vec<ScannerResultItem>,
}

fn default_result_protocol_version() -> u16 {
    1
}

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScannerObservation {
    Port {
        ip: String,
        port: u16,
        protocol: String,
        state: String,
        source: String,
        #[serde(default)]
        observed_at: Option<i64>,
    },
    Service {
        ip: String,
        port: u16,
        protocol: String,
        service: Option<String>,
        banner: Option<String>,
        source: String,
        data: Option<Value>,
        #[serde(default)]
        observed_at: Option<i64>,
    },
    Dns {
        #[serde(flatten)]
        observation: dns::DnsObservation,
    },
    Vulnerability {
        ip: String,
        port: u16,
        protocol: String,
        template_id: String,
        name: String,
        severity: String,
        matcher_name: Option<String>,
        matched_at: String,
        description: Option<String>,
        remediation: Option<String>,
        #[serde(default)]
        tags: Vec<String>,
        #[serde(default)]
        references: Vec<String>,
        classification: Option<Value>,
        #[serde(default)]
        extracted_results: Vec<String>,
        source: String,
        #[serde(default)]
        observed_at: Option<i64>,
    },
}

#[derive(Clone, Deserialize)]
pub struct ScannerResultItem {
    pub ip: String,
    pub port: u16,
    pub protocol: Option<String>,
    pub service: Option<String>,
    pub banner: Option<String>,
    pub other: Option<Value>,
}

#[derive(Clone, Debug)]
pub(crate) struct NormalizedObservation {
    pub(crate) kind: &'static str,
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub(crate) protocol: Option<String>,
    pub(crate) service: Option<String>,
    pub(crate) banner: Option<String>,
    pub(crate) source: String,
    pub(crate) data: Option<Value>,
    pub(crate) observed_at: Option<i64>,
}

#[derive(Debug)]
pub enum SaveScannerResultsError {
    Database(Box<dyn std::error::Error + Send + Sync>),
    Storage(String),
    BatchBusy {
        retry_after_seconds: u64,
    },
    InvalidIp {
        ip: String,
        source: AddrParseError,
    },
    ScannerUnauthorized,
    TaskNotFound,
    TaskNotOwned,
    UnsupportedProtocolVersion {
        received: u16,
    },
    InvalidBatchEnvelope {
        protocol_version: u16,
        reason: &'static str,
    },
    UploadIdentityConflict {
        execution_id: i32,
        received_upload_id: String,
        conflicting_upload_id: String,
        conflicting_upload_count: i64,
    },
    BatchPayloadConflict {
        execution_id: i32,
        upload_id: String,
        batch_index: i32,
        content_kind: &'static str,
        expected_checksum: Option<String>,
        received_checksum: String,
    },
    NonContiguousFinalBatch {
        execution_id: i32,
        upload_id: String,
        batch_index: i32,
        content_kind: &'static str,
    },
    CompletedExecutionNewBatch {
        execution_id: i32,
        upload_id: String,
        batch_index: i32,
    },
    ObservationLimitExceeded {
        actual: usize,
        limit: usize,
    },
    InvalidUpload(String),
}

impl fmt::Display for SaveScannerResultsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(e) => write!(f, "{}", e),
            Self::Storage(message) => write!(f, "扫描事实存储失败：{message}"),
            Self::BatchBusy {
                retry_after_seconds,
            } => write!(f, "DNS 批次正在写入，请在 {retry_after_seconds} 秒后重试"),
            Self::InvalidIp { ip, source } => write!(f, "无效 IP/CIDR: {} ({})", ip, source),
            Self::ScannerUnauthorized => write!(f, "扫描器认证失败"),
            Self::TaskNotFound => write!(f, "任务不存在"),
            Self::TaskNotOwned => write!(f, "任务不属于当前扫描器或租约已失效"),
            Self::UnsupportedProtocolVersion { received } => {
                write!(
                    f,
                    "无效扫描结果上传: unsupported protocol_version {received}"
                )
            }
            Self::InvalidBatchEnvelope { reason, .. } => {
                write!(f, "无效扫描结果上传: {reason}")
            }
            Self::UploadIdentityConflict { .. } => write!(
                f,
                "无效扫描结果上传: an execution cannot contain batches from multiple upload_id values"
            ),
            Self::BatchPayloadConflict { content_kind, .. } => write!(
                f,
                "无效扫描结果上传: batch identity was already used with different {content_kind} content"
            ),
            Self::NonContiguousFinalBatch { content_kind, .. } => write!(
                f,
                "无效扫描结果上传: final {content_kind} batch requires one contiguous sequence starting at batch_index 0"
            ),
            Self::CompletedExecutionNewBatch { .. } => write!(
                f,
                "无效扫描结果上传: completed execution cannot accept a new batch"
            ),
            Self::ObservationLimitExceeded { actual, limit } => write!(
                f,
                "无效扫描结果上传: observation count {actual} exceeds limit {limit}"
            ),
            Self::InvalidUpload(message) => write!(f, "无效扫描结果上传: {message}"),
        }
    }
}

impl SaveScannerResultsError {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Database(_) => "database",
            Self::Storage(_) => "storage",
            Self::BatchBusy { .. } => "concurrency",
            Self::ScannerUnauthorized => "authentication",
            Self::TaskNotFound | Self::TaskNotOwned => "task_state",
            Self::InvalidIp { .. }
            | Self::UnsupportedProtocolVersion { .. }
            | Self::InvalidBatchEnvelope { .. }
            | Self::UploadIdentityConflict { .. }
            | Self::BatchPayloadConflict { .. }
            | Self::NonContiguousFinalBatch { .. }
            | Self::CompletedExecutionNewBatch { .. }
            | Self::ObservationLimitExceeded { .. }
            | Self::InvalidUpload(_) => "validation",
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Database(_) => "scan_result_database_operation_failed",
            Self::Storage(_) => "scan_result_storage_operation_failed",
            Self::BatchBusy { .. } => "scan_result_batch_busy",
            Self::InvalidIp { .. } => "invalid_observation_ip",
            Self::ScannerUnauthorized => "scanner_unauthorized",
            Self::TaskNotFound => "scan_task_not_found",
            Self::TaskNotOwned => "scan_task_not_owned",
            Self::UnsupportedProtocolVersion { .. } => "unsupported_protocol_version",
            Self::InvalidBatchEnvelope { .. } => "invalid_batch_envelope",
            Self::UploadIdentityConflict { .. } => "execution_upload_id_conflict",
            Self::BatchPayloadConflict { .. } => "batch_payload_conflict",
            Self::NonContiguousFinalBatch { .. } => "non_contiguous_final_batch",
            Self::CompletedExecutionNewBatch { .. } => "completed_execution_new_batch",
            Self::ObservationLimitExceeded { .. } => "observation_limit_exceeded",
            Self::InvalidUpload(_) => "invalid_scan_result_upload",
        }
    }

    pub fn operation(&self) -> &'static str {
        match self {
            Self::Database(_) => "persist_scan_result_database_state",
            Self::Storage(_) => "persist_scan_result_elasticsearch_data",
            Self::BatchBusy { .. } => "claim_scan_result_batch",
            Self::InvalidIp { .. } => "normalize_scan_observation",
            Self::ScannerUnauthorized => "authenticate_scanner",
            Self::TaskNotFound | Self::TaskNotOwned => "validate_scan_task_lease",
            Self::UnsupportedProtocolVersion { .. } | Self::InvalidBatchEnvelope { .. } => {
                "validate_scan_result_envelope"
            }
            Self::UploadIdentityConflict { .. } => "validate_execution_upload_identity",
            Self::BatchPayloadConflict { .. } => "validate_scan_result_batch_identity",
            Self::NonContiguousFinalBatch { .. } => "validate_scan_result_batch_sequence",
            Self::CompletedExecutionNewBatch { .. } => "validate_execution_state",
            Self::ObservationLimitExceeded { .. } | Self::InvalidUpload(_) => {
                "validate_scan_result_payload"
            }
        }
    }

    pub fn retryable(&self) -> bool {
        matches!(self, Self::Storage(_) | Self::BatchBusy { .. })
            || matches!(self, Self::Database(error) if error.downcast_ref::<deadpool_postgres::PoolError>()
                .is_some_and(|error| matches!(error, deadpool_postgres::PoolError::Timeout(_))))
    }

    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidIp { .. }
            | Self::UnsupportedProtocolVersion { .. }
            | Self::InvalidBatchEnvelope { .. }
            | Self::UploadIdentityConflict { .. }
            | Self::BatchPayloadConflict { .. }
            | Self::NonContiguousFinalBatch { .. }
            | Self::CompletedExecutionNewBatch { .. }
            | Self::ObservationLimitExceeded { .. }
            | Self::InvalidUpload(_) => 400,
            Self::ScannerUnauthorized => 401,
            Self::TaskNotFound => 404,
            Self::TaskNotOwned => 409,
            Self::Database(_) if self.retryable() => 503,
            Self::Database(_) => 500,
            Self::Storage(_) | Self::BatchBusy { .. } => 503,
        }
    }

    pub fn execution_id(&self) -> Option<i32> {
        match self {
            Self::UploadIdentityConflict { execution_id, .. }
            | Self::BatchPayloadConflict { execution_id, .. }
            | Self::NonContiguousFinalBatch { execution_id, .. }
            | Self::CompletedExecutionNewBatch { execution_id, .. } => Some(*execution_id),
            _ => None,
        }
    }

    pub fn conflicting_upload(&self) -> Option<(&str, i64)> {
        match self {
            Self::UploadIdentityConflict {
                conflicting_upload_id,
                conflicting_upload_count,
                ..
            } => Some((conflicting_upload_id, *conflicting_upload_count)),
            _ => None,
        }
    }

    pub fn batch_conflict_checksums(&self) -> Option<(Option<&str>, &str)> {
        match self {
            Self::BatchPayloadConflict {
                expected_checksum,
                received_checksum,
                ..
            } => Some((expected_checksum.as_deref(), received_checksum)),
            _ => None,
        }
    }
}

impl std::error::Error for SaveScannerResultsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(e) => Some(e.as_ref()),
            Self::Storage(_) | Self::BatchBusy { .. } => None,
            Self::InvalidIp { source, .. } => Some(source),
            Self::ScannerUnauthorized
            | Self::TaskNotFound
            | Self::TaskNotOwned
            | Self::UnsupportedProtocolVersion { .. }
            | Self::InvalidBatchEnvelope { .. }
            | Self::UploadIdentityConflict { .. }
            | Self::BatchPayloadConflict { .. }
            | Self::NonContiguousFinalBatch { .. }
            | Self::CompletedExecutionNewBatch { .. }
            | Self::ObservationLimitExceeded { .. }
            | Self::InvalidUpload(_) => None,
        }
    }
}

#[cfg(test)]
mod save_scanner_results_error_tests {
    use super::SaveScannerResultsError;

    #[test]
    fn pool_timeout_is_retryable_but_other_database_errors_are_not() {
        let error = SaveScannerResultsError::Database(Box::new(
            deadpool_postgres::PoolError::Timeout(deadpool::managed::TimeoutType::Wait),
        ));
        assert!(error.retryable());
        assert_eq!(error.http_status(), 503);
        let other =
            SaveScannerResultsError::Database(Box::new(std::io::Error::other("database failure")));
        assert!(!other.retryable());
        assert_eq!(other.http_status(), 500);
    }

    #[test]
    fn upload_identity_conflict_has_stable_diagnostics() {
        let error = SaveScannerResultsError::UploadIdentityConflict {
            execution_id: 17,
            received_upload_id: "received".into(),
            conflicting_upload_id: "existing".into(),
            conflicting_upload_count: 2,
        };
        assert_eq!(error.kind(), "validation");
        assert_eq!(error.code(), "execution_upload_id_conflict");
        assert_eq!(error.operation(), "validate_execution_upload_identity");
        assert_eq!(error.http_status(), 400);
        assert!(!error.retryable());
        assert_eq!(error.execution_id(), Some(17));
        assert_eq!(error.conflicting_upload(), Some(("existing", 2)));
        assert!(error.to_string().contains("multiple upload_id values"));
    }

    #[test]
    fn busy_and_storage_errors_are_retryable() {
        let busy = SaveScannerResultsError::BatchBusy {
            retry_after_seconds: 3,
        };
        let storage = SaveScannerResultsError::Storage("temporarily unavailable".into());
        assert!(busy.retryable());
        assert!(storage.retryable());
        assert_eq!(busy.http_status(), 503);
        assert_eq!(storage.http_status(), 503);
    }
}
