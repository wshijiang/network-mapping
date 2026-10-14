//! Scanner upload validation and transactional result ingestion.
pub(crate) mod dns;
pub mod model;
pub(crate) mod storage;
pub(crate) mod telemetry;
pub(crate) mod upload_stream;
pub(crate) mod validation;
pub use model::{
    SaveScannerResultsError, ScannerObservation, ScannerResultItem, ScannerResultUpload,
};
pub use storage::save_scanner_results;
