//! Reuse the existing AES-256-GCM envelope and server encryption key.
use super::*;

pub(super) fn encrypt_update(value: &str, clear: bool, key: &str) -> Result<Option<Vec<u8>>> {
    if value.len() > 8192
        || (!value.is_empty() && (clear || value.trim().is_empty()))
        || value.chars().any(char::is_control)
    {
        return Err(Error::bad("intel_invalid_credential"));
    }
    if value.is_empty() {
        return Ok(None);
    }
    crate::notification::encrypt(value, key)
        .map(Some)
        .map_err(|_| crypto_error())
}
pub(super) fn resolve(ciphertext: Option<&[u8]>, env: &str, key: &str) -> Result<Option<String>> {
    match ciphertext {
        // Authentication failure must not silently select a different credential.
        Some(bytes) => crate::notification::decrypt(bytes, key)
            .map(Some)
            .map_err(|_| crypto_error()),
        None => client::secret(env),
    }
}
pub(super) fn status(ciphertext_present: bool, env: &str) -> (&'static str, bool) {
    if ciphertext_present {
        ("database", true)
    } else if matches!(client::secret(env), Ok(Some(_))) {
        ("environment", true)
    } else {
        ("none", false)
    }
}
fn crypto_error() -> Error {
    Error {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "intel_credential_crypto_failed",
        diagnostic: json!({}),
    }
}
