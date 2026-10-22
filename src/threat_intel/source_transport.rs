use super::*;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Header {
    pub name: String,
    pub value: String,
    pub configured: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct RequestConfig {
    pub proxy_mode: String,
    pub proxy_url: String,
    pub proxy_configured: bool,
    pub headers: Vec<Header>,
}
impl Default for RequestConfig {
    fn default() -> Self {
        Self {
            proxy_mode: "system".into(),
            proxy_url: String::new(),
            proxy_configured: false,
            headers: Vec::new(),
        }
    }
}
impl RequestConfig {
    pub fn redact(&self) -> Self {
        let mut out = self.clone();
        out.proxy_configured = !out.proxy_url.is_empty();
        out.proxy_url.clear();
        for header in &mut out.headers {
            header.configured = !header.value.is_empty();
            header.value.clear();
        }
        out
    }
    pub fn preserve(&mut self, old: &Self) {
        if self.proxy_url.is_empty() && self.proxy_configured {
            self.proxy_url = old.proxy_url.clone();
        }
        for header in &mut self.headers {
            if header.value.is_empty() && header.configured {
                if let Some(previous) = old
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case(&header.name))
                {
                    header.value = previous.value.clone();
                } else {
                    header.configured = false;
                }
            }
        }
    }
    pub fn validate(&mut self) -> Result<()> {
        if !matches!(self.proxy_mode.as_str(), "system" | "direct" | "custom") {
            return Err(Error::bad("intel_invalid_proxy"));
        }
        if self.proxy_mode == "custom" {
            crate::outbound_proxy::validate_url(&self.proxy_url)
                .map_err(|_| Error::bad("intel_invalid_proxy"))?;
            reqwest::Proxy::all(&self.proxy_url).map_err(|_| Error::bad("intel_invalid_proxy"))?;
        } else {
            self.proxy_url.clear();
        }
        self.header_map()?;
        Ok(())
    }
    pub fn header_map(&self) -> Result<HeaderMap> {
        let invalid = || Error::bad("intel_invalid_headers");
        if self.headers.len() > 64
            || self
                .headers
                .iter()
                .map(|h| h.name.len() + h.value.len())
                .sum::<usize>()
                > 32768
        {
            return Err(invalid());
        }
        let mut headers = HeaderMap::new();
        for header in &self.headers {
            let name = HeaderName::from_bytes(header.name.as_bytes()).map_err(|_| invalid())?;
            if matches!(
                name.as_str(),
                "host"
                    | "content-length"
                    | "connection"
                    | "transfer-encoding"
                    | "proxy-authorization"
                    | "proxy-connection"
                    | "upgrade"
                    | "te"
                    | "trailer"
                    | "accept-encoding"
            ) || headers.contains_key(&name)
                || header.value.len() > 8192
                || header.value.is_empty()
            {
                return Err(invalid());
            }
            let mut value = HeaderValue::from_str(&header.value).map_err(|_| invalid())?;
            value.set_sensitive(true);
            headers.insert(name, value);
        }
        Ok(headers)
    }
    pub fn request_headers(&self, auth: Option<(&str, &str)>) -> Result<HeaderMap> {
        let mut headers = self.header_map()?;
        if let Some((name, secret)) = auth {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| Error::bad("intel_invalid_credential"))?;
            let mut value = HeaderValue::from_str(secret)
                .map_err(|_| Error::bad("intel_invalid_credential"))?;
            value.set_sensitive(true);
            headers.insert(name, value);
        }
        Ok(headers)
    }
    pub fn builder(&self, host: &str) -> Result<reqwest::ClientBuilder> {
        let builder = client::http_builder(host);
        match self.proxy_mode.as_str() {
            "system" => Ok(builder),
            "direct" => Ok(builder.no_proxy()),
            "custom" => Ok(builder.no_proxy().proxy(
                reqwest::Proxy::all(&self.proxy_url)
                    .map_err(|_| Error::bad("intel_invalid_proxy"))?,
            )),
            _ => Err(Error::bad("intel_invalid_proxy")),
        }
    }
    pub fn encrypt(&self, key: &str) -> Result<Vec<u8>> {
        let value = serde_json::to_string(self).map_err(|_| Error::unavailable())?;
        crate::notification::encrypt(&value, key)
            .map_err(|_| Error::bad("intel_credential_crypto_failed"))
    }
    pub fn decrypt(ciphertext: Option<&[u8]>, key: &str) -> Result<Self> {
        let Some(bytes) = ciphertext else {
            return Ok(Self::default());
        };
        let value = crate::notification::decrypt(bytes, key)
            .map_err(|_| Error::bad("intel_credential_crypto_failed"))?;
        serde_json::from_str(&value).map_err(|_| Error::bad("intel_credential_crypto_failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_request_secrets_are_encrypted_redacted_preserved_and_removable() {
        let key = crate::threat_intel::tests::encryption_key();
        let mut config: RequestConfig = serde_json::from_value(json!({
            "proxy_mode":"custom", "proxy_url":"socks5h://user:fixture-password@127.0.0.1:1080",
            "headers":[{"name":"Cookie","value":"session=fixture-token"},{"name":"User-Agent","value":"Fixture/1.0"}]
        })).unwrap();
        config.validate().unwrap();
        let ciphertext = config.encrypt(&key).unwrap();
        assert!(
            !ciphertext
                .windows(b"fixture-token".len())
                .any(|w| w == b"fixture-token")
        );
        let saved = RequestConfig::decrypt(Some(&ciphertext), &key).unwrap();
        let mut edit = saved.redact();
        let public = json!(edit).to_string();
        assert!(!public.contains("fixture-token") && !public.contains("fixture-password"));
        assert!(edit.proxy_configured && edit.headers[0].configured);
        edit.preserve(&saved);
        edit.validate().unwrap();
        assert_eq!(
            edit.header_map().unwrap()["cookie"],
            "session=fixture-token"
        );
        edit.headers.remove(0);
        edit.proxy_mode = "direct".into();
        edit.validate().unwrap();
        assert!(edit.proxy_url.is_empty());
        assert!(!edit.header_map().unwrap().contains_key("cookie"));
        assert!(RequestConfig::decrypt(Some(&ciphertext), "invalid-key").is_err());
    }

    #[test]
    fn explicit_source_credentials_replace_custom_auth_without_duplicate_headers() {
        let config: RequestConfig = serde_json::from_value(
            json!({"headers":[{"name":"Authorization","value":"custom-key"}]}),
        )
        .unwrap();
        let headers = config
            .request_headers(Some(("Authorization", "dedicated-key")))
            .unwrap();
        assert_eq!(headers.get_all("authorization").iter().count(), 1);
        assert_eq!(headers["authorization"], "dedicated-key");
    }

    #[test]
    fn source_request_settings_reject_invalid_proxy_and_header_injection() {
        for proxy in [
            "",
            "ftp://proxy.example:21",
            "http://proxy.example/path",
            "http://proxy.example:0",
        ] {
            let mut config: RequestConfig =
                serde_json::from_value(json!({"proxy_mode":"custom","proxy_url":proxy})).unwrap();
            assert!(config.validate().is_err(), "{proxy}");
        }
        for headers in [
            json!([{"name":"Host","value":"other.example"}]),
            json!([{"name":"X-Token","value":"key\r\nInjected: value"}]),
            json!([{"name":"Cookie","value":"a"},{"name":"cookie","value":"b"}]),
            json!([{"name":"X-Token","value":"","configured":true}]),
        ] {
            let mut config: RequestConfig =
                serde_json::from_value(json!({"headers":headers})).unwrap();
            assert!(config.validate().is_err());
        }
    }
}
