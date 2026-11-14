//! Shared AES-256-GCM helpers for credentials kept outside public JSON.

pub(crate) const UNAVAILABLE: &str = "proxy_configuration_unavailable";

pub(crate) fn encrypt(value: &str, encoded_key: &str) -> Result<Vec<u8>, &'static str> {
    let key = key(encoded_key)?;
    let (nonce, tag, bytes) =
        crate::identity::encrypt_data(value.as_bytes(), &key).map_err(|_| UNAVAILABLE)?;
    Ok([nonce, tag, bytes].concat())
}

pub(crate) fn decrypt(bytes: &[u8], encoded_key: &str) -> Result<String, &'static str> {
    if bytes.len() < 28 {
        return Err(UNAVAILABLE);
    }
    let key = key(encoded_key)?;
    let value = crate::identity::decrypt_data(bytes, &key).map_err(|_| UNAVAILABLE)?;
    String::from_utf8(value).map_err(|_| UNAVAILABLE)
}

fn key(encoded_key: &str) -> Result<Vec<u8>, &'static str> {
    let key = openssl::base64::decode_block(encoded_key).map_err(|_| UNAVAILABLE)?;
    if key.len() != 32 {
        return Err(UNAVAILABLE);
    }
    Ok(key)
}
