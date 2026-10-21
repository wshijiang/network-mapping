//! Provider management shares the existing IOC revision fence and bounded egress.
use super::*;
use std::collections::BTreeMap;

mod debug;
mod model;
mod routes;
mod storage;
#[cfg(test)]
mod tests;
mod transport;

pub(super) use model::Resolved;
use model::*;
pub(super) use routes::configure;
pub(super) use storage::runtime_transport;
pub(super) use transport::execute;

fn invalid() -> Error {
    Error::bad("llm_invalid_configuration")
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| invalid())
}
fn encrypt<T: Serialize>(value: &T, key: &str) -> Result<Vec<u8>> {
    let raw = serde_json::to_string(value).map_err(|_| invalid())?;
    crate::notification::encrypt(&raw, key).map_err(|_| Error::bad("llm_secret_unavailable"))
}
fn decrypt<T: serde::de::DeserializeOwned>(
    cipher: Option<Vec<u8>>,
    fallback: Value,
    key: &str,
) -> Result<T> {
    match cipher {
        Some(bytes) => {
            let raw = crate::notification::decrypt(&bytes, key)
                .map_err(|_| Error::bad("llm_secret_unavailable"))?;
            serde_json::from_str(&raw).map_err(|_| Error::bad("llm_secret_unavailable"))
        }
        None => decode(fallback),
    }
}
