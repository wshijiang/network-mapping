//! Persistent administrator weekly/monthly report snapshots and mail delivery.
pub(crate) mod assets;
pub(crate) mod chart;
pub mod mail_config;
pub(crate) mod mail_context;
pub mod period;
pub mod render_module;
pub mod service;
pub(crate) mod statistics;
pub(crate) mod storage;
mod worker;
pub use assets::redact_path as redact_mail_image_path;
pub use worker::run_worker;

#[cfg(test)]
mod tests;
