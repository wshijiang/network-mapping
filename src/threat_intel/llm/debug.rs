//! Per-request debug overrides. These never write provider or IOC settings.
use super::*;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Parameters {
    pub reasoning_effort: Option<String>,
    pub max_output_tokens: Option<u32>,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub timeout_seconds: Option<u64>,
    pub stream: Option<bool>,
    pub token_limit_field: Option<String>,
}

impl Parameters {
    pub fn validate(&self) -> Result<()> {
        if self.reasoning_effort.as_deref().is_some_and(|v| {
            !matches!(
                v,
                "default" | "none" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max"
            )
        }) || self
            .max_output_tokens
            .is_some_and(|v| !(1..=MAX_AI_OUTPUT_TOKENS).contains(&v))
            || self
                .temperature
                .is_some_and(|v| !v.is_finite() || !(0.0..=2.0).contains(&v))
            || self
                .top_p
                .is_some_and(|v| !v.is_finite() || !(0.0..=1.0).contains(&v))
            || self
                .timeout_seconds
                .is_some_and(|v| !(1..=1800).contains(&v))
            || self
                .token_limit_field
                .as_deref()
                .is_some_and(|v| !matches!(v, "max_tokens" | "max_completion_tokens"))
        {
            return Err(Error::bad("llm_invalid_debug_parameters"));
        }
        Ok(())
    }

    pub fn apply(&self, settings: &mut Settings, transport: &mut Resolved) -> Result<()> {
        self.validate()?;
        if settings.ai_protocol != "chat" && self.token_limit_field.is_some() {
            return Err(Error::bad("llm_invalid_debug_parameters"));
        }
        if let Some(value) = self.max_output_tokens {
            settings.ai_max_output_tokens = value;
        }
        if let Some(value) = self.timeout_seconds {
            settings.ai_timeout_seconds = value;
        }
        if let Some(value) = self.stream {
            transport.stream = value;
        }
        Ok(())
    }

    pub fn payload(&self, settings: &Settings, messages: Value) -> Value {
        let mut payload = if settings.ai_protocol == "responses" {
            json!({"model":settings.ai_model,"input":messages,"max_output_tokens":settings.ai_max_output_tokens,"store":false})
        } else {
            let mut payload = json!({"model":settings.ai_model,"messages":messages});
            payload[self.token_limit_field.as_deref().unwrap_or("max_tokens")] =
                json!(settings.ai_max_output_tokens);
            payload
        };
        let effort = self
            .reasoning_effort
            .as_deref()
            .unwrap_or(&settings.ai_reasoning_effort);
        if effort != "default" {
            if settings.ai_protocol == "responses" {
                payload["reasoning"] = json!({"effort":effort});
            } else {
                payload["reasoning_effort"] = json!(effort);
            }
        }
        if let Some(value) = self.temperature {
            payload["temperature"] = json!(value);
        }
        if let Some(value) = self.top_p {
            payload["top_p"] = json!(value);
        }
        payload
    }

    pub fn effective(&self, settings: &Settings, transport: &Resolved) -> Value {
        json!({"reasoning_effort":self.reasoning_effort.as_deref().unwrap_or(&settings.ai_reasoning_effort),
            "max_output_tokens":settings.ai_max_output_tokens,"timeout_seconds":settings.ai_timeout_seconds,
            "temperature":self.temperature,"top_p":self.top_p,"stream":transport.stream,
            "token_limit_field":if settings.ai_protocol=="responses" {"max_output_tokens"} else {self.token_limit_field.as_deref().unwrap_or("max_tokens")}})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(protocol: &str) -> Settings {
        decode(
            json!({"ai_enabled":false,"ai_endpoint":"https://api.example/v1","ai_model":"fixture",
            "ai_key_env":"","ai_protocol":protocol,"ai_max_output_tokens":4096,
            "ai_reasoning_effort":"medium","ai_timeout_seconds":180}),
        )
        .unwrap()
    }

    #[test]
    fn debug_overrides_map_each_protocol_and_leave_original_configuration_untouched() {
        for protocol in ["chat", "responses"] {
            let original = settings(protocol);
            let mut local = original.clone();
            let mut transport = resolve(&Transport::global(), &Transport::default()).unwrap();
            let parameters: Parameters =
                decode(json!({"reasoning_effort":"high","max_output_tokens":128,
                "timeout_seconds":30,"temperature":0,"top_p":0.8,"stream":true}))
                .unwrap();
            parameters.apply(&mut local, &mut transport).unwrap();
            let payload = parameters.payload(&local, json!([{"role":"user","content":"hello"}]));
            assert_eq!(
                payload[if protocol == "responses" {
                    "max_output_tokens"
                } else {
                    "max_tokens"
                }],
                128
            );
            assert_eq!(payload["temperature"].as_f64(), Some(0.0));
            assert_eq!(payload["top_p"], 0.8);
            if protocol == "responses" {
                assert_eq!(payload["reasoning"]["effort"], "high");
            } else {
                assert_eq!(payload["reasoning_effort"], "high");
            }
            assert_eq!(local.ai_timeout_seconds, 30);
            assert!(transport.stream);
            assert_eq!(original.ai_max_output_tokens, 4096);
            assert_eq!(original.ai_timeout_seconds, 180);
            assert_eq!(original.ai_reasoning_effort, "medium");
            assert_eq!(parameters.effective(&local, &transport)["stream"], true);
        }
    }

    #[test]
    fn inheritance_and_explicit_interface_defaults_are_distinct_and_sampling_is_optional() {
        let local = settings("chat");
        let inherited = Parameters::default().payload(&local, json!([]));
        assert_eq!(inherited["reasoning_effort"], "medium");
        assert!(inherited.get("temperature").is_none());
        assert!(inherited.get("top_p").is_none());
        let parameters: Parameters = decode(
            json!({"reasoning_effort":"default","token_limit_field":"max_completion_tokens"}),
        )
        .unwrap();
        let payload = parameters.payload(&local, json!([]));
        assert!(payload.get("reasoning_effort").is_none());
        assert!(payload.get("max_tokens").is_none());
        assert_eq!(payload["max_completion_tokens"], 4096);
    }

    #[test]
    fn malformed_and_out_of_range_parameters_fail_before_any_provider_request() {
        for invalid in [
            json!({"temperature":-0.1}),
            json!({"temperature":2.1}),
            json!({"top_p":1.1}),
            json!({"max_output_tokens":0}),
            json!({"max_output_tokens":393217}),
            json!({"timeout_seconds":0}),
            json!({"timeout_seconds":1801}),
            json!({"reasoning_effort":"invented"}),
            json!({"token_limit_field":"invented"}),
        ] {
            let parameters: Parameters = decode(invalid).unwrap();
            assert_eq!(
                parameters.validate().unwrap_err().code,
                "llm_invalid_debug_parameters"
            );
        }
        for malformed in [
            json!({"temperature":"0.5"}),
            json!({"stream":"true"}),
            json!({"max_output_tokens":1.5}),
            json!({"unknown":true}),
        ] {
            assert!(decode::<Parameters>(malformed).is_err());
        }
        for effort in [
            "default", "none", "minimal", "low", "medium", "high", "xhigh", "max",
        ] {
            decode::<Parameters>(json!({"reasoning_effort":effort}))
                .unwrap()
                .validate()
                .unwrap();
        }
        let parameters: Parameters =
            decode(json!({"token_limit_field":"max_completion_tokens"})).unwrap();
        let mut local = settings("responses");
        let mut transport = resolve(&Transport::global(), &Transport::default()).unwrap();
        assert!(parameters.apply(&mut local, &mut transport).is_err());
    }
}
