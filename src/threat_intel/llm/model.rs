use super::*;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Header {
    pub name: String,
    pub value: String,
    pub configured: bool,
    pub remove: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Transport {
    pub proxy_mode: String,
    pub proxy_url: String,
    pub proxy_configured: bool,
    pub headers_mode: String,
    pub headers: Vec<Header>,
    pub session_mode: String,
    pub session_header: String,
    pub session_value: String,
    pub session_configured: bool,
    pub stream: Option<bool>,
}
impl Default for Transport {
    fn default() -> Self {
        Self {
            proxy_mode: "inherit".into(),
            proxy_url: String::new(),
            proxy_configured: false,
            headers_mode: "merge".into(),
            headers: vec![],
            session_mode: "inherit".into(),
            session_header: "x-opencode-session".into(),
            session_value: String::new(),
            session_configured: false,
            stream: None,
        }
    }
}
impl Transport {
    pub fn global() -> Self {
        Self {
            proxy_mode: "system".into(),
            headers_mode: "replace".into(),
            session_mode: "disabled".into(),
            stream: Some(false),
            ..Self::default()
        }
    }
    pub fn redact(&self) -> Self {
        let mut out = self.clone();
        out.proxy_configured = !out.proxy_url.is_empty();
        out.proxy_url.clear();
        out.session_configured = !out.session_value.is_empty();
        out.session_value.clear();
        for h in &mut out.headers {
            h.configured = !h.value.is_empty();
            h.value.clear();
        }
        out
    }
    pub fn preserve(&mut self, old: &Self) {
        if self.proxy_url.is_empty() && self.proxy_configured {
            self.proxy_url = old.proxy_url.clone();
        }
        if self.session_value.is_empty() && self.session_configured {
            self.session_value = old.session_value.clone();
        }
        for h in &mut self.headers {
            if h.value.is_empty()
                && h.configured
                && let Some(previous) = old
                    .headers
                    .iter()
                    .find(|v| v.name.eq_ignore_ascii_case(&h.name))
            {
                h.value = previous.value.clone();
            }
        }
    }
    pub fn validate(&self, global: bool) -> Result<()> {
        if !matches!(
            self.proxy_mode.as_str(),
            "inherit" | "system" | "direct" | "custom"
        ) || (global && self.proxy_mode == "inherit")
            || !matches!(self.headers_mode.as_str(), "merge" | "replace" | "disabled")
            || !matches!(
                self.session_mode.as_str(),
                "inherit" | "disabled" | "auto" | "fixed"
            )
            || (global && (self.session_mode == "inherit" || self.stream.is_none()))
            || self.headers.len() > 64
        {
            return Err(invalid());
        }
        if self.proxy_mode == "custom" {
            crate::outbound_proxy::validate_url(&self.proxy_url).map_err(|_| invalid())?;
        }
        let mut names = std::collections::HashSet::new();
        for h in &self.headers {
            let name = header_name(&h.name)?;
            if !names.insert(name.clone())
                || h.value.len() > 8192
                || (!h.remove && h.value.is_empty())
            {
                return Err(invalid());
            }
            HeaderValue::from_str(&h.value).map_err(|_| invalid())?;
        }
        if matches!(self.session_mode.as_str(), "auto" | "fixed") {
            header_name(&self.session_header)?;
            if self.session_mode == "fixed"
                && (self.session_value.is_empty() || self.session_value.len() > 1024)
            {
                return Err(invalid());
            }
            HeaderValue::from_str(&self.session_value).map_err(|_| invalid())?;
        }
        Ok(())
    }
}
fn header_name(value: &str) -> Result<HeaderName> {
    let name = HeaderName::from_bytes(value.as_bytes()).map_err(|_| invalid())?;
    if matches!(
        name.as_str(),
        "host"
            | "content-length"
            | "connection"
            | "transfer-encoding"
            | "cookie"
            | "set-cookie"
            | "content-type"
            | "accept-encoding"
    ) {
        return Err(invalid());
    }
    Ok(name)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Model {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub available: bool,
}
impl Default for Model {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            protocol: String::new(),
            available: true,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Provider {
    pub id: Option<Uuid>,
    pub name: String,
    pub preset: String,
    pub endpoint: String,
    pub models_url: String,
    pub protocol: String,
    pub default_model: String,
    pub models: Vec<Model>,
    pub key_env: String,
    pub credential: String,
    pub clear_credential: bool,
    pub credential_configured: bool,
    pub database_credential_configured: bool,
    pub timeout_seconds: u64,
    pub max_output_tokens: u32,
    pub reasoning_effort: String,
    pub transport: Transport,
}
impl Default for Provider {
    fn default() -> Self {
        Self {
            id: None,
            name: String::new(),
            preset: String::new(),
            endpoint: "https://api.openai.com/v1".into(),
            models_url: String::new(),
            protocol: "chat".into(),
            default_model: String::new(),
            models: vec![],
            key_env: String::new(),
            credential: String::new(),
            clear_credential: false,
            credential_configured: false,
            database_credential_configured: false,
            timeout_seconds: 180,
            max_output_tokens: 65536,
            reasoning_effort: "default".into(),
            transport: Transport::default(),
        }
    }
}
impl Provider {
    pub fn settings(&self, model: &str, enabled: bool) -> Result<Settings> {
        let protocol = self
            .models
            .iter()
            .find(|m| m.id == model)
            .map(|m| m.protocol.as_str())
            .filter(|p| !p.is_empty())
            .unwrap_or(&self.protocol);
        let s = decode::<Settings>(
            json!({"ai_enabled":enabled,"ai_endpoint":self.endpoint,"ai_model":model,"ai_key_env":self.key_env,"ai_timeout_seconds":self.timeout_seconds,"ai_protocol":protocol,"ai_max_output_tokens":self.max_output_tokens,"ai_reasoning_effort":self.reasoning_effort}),
        )?;
        s.validate()?;
        Ok(s)
    }
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty()
            || self.name.len() > 100
            || self.models.len() > 500
            || self.preset.len() > 50
        {
            return Err(invalid());
        }
        self.settings("", false)?;
        if !self.models_url.is_empty() {
            validate_endpoint(&self.models_url)?;
        }
        let mut ids = std::collections::HashSet::new();
        for m in &self.models {
            if m.id.is_empty()
                || m.id.len() > 100
                || m.id.chars().any(char::is_control)
                || m.name.len() > 200
                || !ids.insert(&m.id)
                || !matches!(
                    m.protocol.as_str(),
                    "" | "chat" | "responses" | "anthropic" | "google" | "unsupported"
                )
            {
                return Err(invalid());
            }
            if m.available && matches!(m.protocol.as_str(), "" | "chat" | "responses") {
                self.settings(&m.id, false)?;
            }
        }
        if !self.default_model.is_empty()
            && !self.models.iter().any(|m| {
                m.id == self.default_model
                    && m.available
                    && matches!(m.protocol.as_str(), "" | "chat" | "responses")
            })
        {
            return Err(invalid());
        }
        self.transport.validate(false)
    }
    pub fn redact(&self) -> Self {
        let mut out = self.clone();
        out.transport = out.transport.redact();
        out.credential.clear();
        out.clear_credential = false;
        out
    }
}
pub(super) fn validate_endpoint(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).map_err(|_| invalid())?;
    validate_url(value, &[url.host_str().unwrap_or("").into()])
}

#[derive(Clone, Default)]
pub(in crate::threat_intel) struct Resolved {
    pub provider_id: Option<Uuid>,
    pub proxy_mode: String,
    pub proxy_url: String,
    pub headers: HeaderMap,
    pub session_mode: String,
    pub session_header: String,
    pub session_value: String,
    pub stream: bool,
}
pub(super) fn resolve(global: &Transport, local: &Transport) -> Result<Resolved> {
    let proxy = if local.proxy_mode == "inherit" {
        global
    } else {
        local
    };
    let session = if local.session_mode == "inherit" {
        global
    } else {
        local
    };
    let mut headers = HeaderMap::new();
    if local.headers_mode == "merge" && global.headers_mode != "disabled" {
        add_headers(&mut headers, &global.headers)?;
    }
    if local.headers_mode != "disabled" {
        add_headers(&mut headers, &local.headers)?;
    }
    if matches!(session.session_mode.as_str(), "auto" | "fixed")
        && headers.contains_key(header_name(&session.session_header)?)
    {
        return Err(Error::bad("llm_session_header_conflict"));
    }
    Ok(Resolved {
        provider_id: None,
        proxy_mode: proxy.proxy_mode.clone(),
        proxy_url: proxy.proxy_url.clone(),
        headers,
        session_mode: session.session_mode.clone(),
        session_header: session.session_header.clone(),
        session_value: session.session_value.clone(),
        stream: local.stream.or(global.stream).unwrap_or(false),
    })
}
fn add_headers(out: &mut HeaderMap, headers: &[Header]) -> Result<()> {
    for h in headers {
        let name = header_name(&h.name)?;
        if h.remove {
            out.remove(name);
        } else {
            out.insert(
                name,
                HeaderValue::from_str(&h.value).map_err(|_| invalid())?,
            );
        }
    }
    Ok(())
}
impl Resolved {
    pub fn request_headers(&self, key: &str, session: &str) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        if !key.is_empty() {
            headers.insert(
                "authorization",
                HeaderValue::from_str(&format!("Bearer {key}")).map_err(|_| invalid())?,
            );
        }
        headers.extend(self.headers.clone());
        if !session.is_empty() && matches!(self.session_mode.as_str(), "auto" | "fixed") {
            let value = if self.session_mode == "fixed" {
                &self.session_value
            } else {
                session
            };
            headers.insert(
                header_name(&self.session_header)?,
                HeaderValue::from_str(value).map_err(|_| invalid())?,
            );
        }
        Ok(headers)
    }
    pub fn preview(&self) -> Value {
        json!({"provider_id":self.provider_id,"proxy_mode":self.proxy_mode,"headers":self.headers.keys().map(|n|n.as_str()).collect::<Vec<_>>(),"session_mode":self.session_mode,"session_header":self.session_header,"stream":self.stream})
    }
}

pub(super) fn presets() -> Vec<Provider> {
    [
        (
            "deepseek",
            "DeepSeek",
            "https://api.deepseek.com/v1",
            "https://api.deepseek.com/models",
        ),
        (
            "opencode-go",
            "OpenCode Go",
            "https://opencode.ai/inference/go/openai/v1",
            "https://opencode.ai/inference/go/v1/models",
        ),
        (
            "commandcode-goat",
            "CommandCode GOAT",
            "https://api.commandcode.ai/provider/v1",
            "https://api.commandcode.ai/provider/v1/models",
        ),
    ]
    .into_iter()
    .map(|(preset, name, endpoint, models_url)| Provider {
        preset: preset.into(),
        name: name.into(),
        endpoint: endpoint.into(),
        models_url: models_url.into(),
        ..Provider::default()
    })
    .collect()
}

pub(super) fn normalize_models(value: Value, provider: &Provider) -> Result<Vec<Model>> {
    let list = value
        .get("data")
        .or_else(|| value.get("models"))
        .or_else(|| value.as_array().map(|_| &value))
        .and_then(Value::as_array)
        .ok_or_else(|| Error::bad("llm_invalid_model_list"))?;
    if list.len() > 500 {
        return Err(Error::bad("llm_invalid_model_list"));
    }
    let mut models = BTreeMap::new();
    for item in list {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .or_else(|| item.as_str())
            .unwrap_or("");
        if id.is_empty() || id.len() > 100 {
            return Err(Error::bad("llm_invalid_model_list"));
        }
        let routes = item.get("supported_endpoints").and_then(Value::as_array);
        let protocol = if let Some(routes) = routes {
            if routes
                .iter()
                .any(|v| v.as_str().is_some_and(|s| s.ends_with("chat/completions")))
            {
                "chat"
            } else if routes
                .iter()
                .any(|v| v.as_str().is_some_and(|s| s.ends_with("responses")))
            {
                "responses"
            } else {
                "unsupported"
            }
        } else if provider.preset == "opencode-go" {
            "unsupported"
        } else {
            &provider.protocol
        };
        // A manual protocol selection is authoritative for an existing model.
        let protocol = provider
            .models
            .iter()
            .find(|m| m.id == id)
            .map(|m| m.protocol.as_str())
            .filter(|p| !p.is_empty())
            .unwrap_or(protocol);
        models.insert(
            id.to_owned(),
            Model {
                id: id.into(),
                name: item
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or(id)
                    .chars()
                    .take(200)
                    .collect(),
                protocol: protocol.into(),
                available: true,
            },
        );
    }
    // Discovery updates availability, but never silently removes saved metadata.
    for previous in &provider.models {
        models.entry(previous.id.clone()).or_insert_with(|| Model {
            available: false,
            ..previous.clone()
        });
    }
    Ok(models.into_values().collect())
}
