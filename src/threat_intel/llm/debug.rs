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
                if effort != "none" {
                    payload["reasoning"]["summary"] = json!("auto");
                }
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

// Only expose provider-returned text to the administrator's transient debug UI.
// Never decode encrypted reasoning or add this data to subsequent messages.
pub(super) fn reasoning_delta<'a>(event: &'a Value, protocol: &str) -> Option<&'a str> {
    if protocol == "responses" {
        match event.get("type").and_then(Value::as_str) {
            Some("response.reasoning_summary_text.delta" | "response.reasoning_text.delta") => {
                event
                    .get("delta")
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty())
            }
            _ => None,
        }
    } else {
        [
            "/choices/0/delta/reasoning_content",
            "/choices/0/delta/reasoning",
        ]
        .into_iter()
        .find_map(|path| {
            event
                .pointer(path)
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
        })
    }
}

pub(super) fn reasoning_text(response: &Value, protocol: &str) -> String {
    if protocol != "responses" {
        return [
            "/choices/0/message/reasoning_content",
            "/choices/0/message/reasoning",
        ]
        .into_iter()
        .find_map(|path| {
            response
                .pointer(path)
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
        })
        .unwrap_or_default()
        .to_owned();
    }
    response
        .get("output")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| item["type"] == "reasoning")
        .flat_map(|item| {
            // Prefer summaries when the provider returns both forms.
            let summary = item.get("summary").and_then(Value::as_array);
            let parts = summary
                .filter(|parts| !parts.is_empty())
                .or_else(|| item.get("content").and_then(Value::as_array));
            parts
                .into_iter()
                .flatten()
                .filter(|part| {
                    matches!(
                        part["type"].as_str(),
                        Some("summary_text" | "reasoning_text")
                    )
                })
                .filter_map(|part| part.get("text").and_then(Value::as_str))
        })
        .collect::<Vec<_>>()
        .join("\n\n")
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
                assert_eq!(payload["reasoning"]["summary"], "auto");
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

    #[test]
    fn debug_reasoning_only_extracts_provider_text_and_keeps_protocols_separate() {
        for field in ["reasoning_content", "reasoning"] {
            let mut chat = json!({"choices":[{"delta":{},"message":{}}]});
            chat["choices"][0]["delta"][field] = json!("思考增量");
            chat["choices"][0]["message"][field] = json!("完整思考");
            assert_eq!(reasoning_delta(&chat, "chat"), Some("思考增量"));
            assert_eq!(reasoning_text(&chat, "chat"), "完整思考");
            assert!(reasoning_text(&chat, "responses").is_empty());
        }
        for kind in [
            "response.reasoning_summary_text.delta",
            "response.reasoning_text.delta",
        ] {
            let event = json!({"type":kind,"delta":"思考增量"});
            assert_eq!(reasoning_delta(&event, "responses"), Some("思考增量"));
        }
        assert_eq!(
            reasoning_delta(
                &json!({"type":"response.output_text.delta","delta":"answer"}),
                "responses"
            ),
            None
        );
        let response = json!({"output":[
            {"type":"reasoning","summary":[{"type":"summary_text","text":"摘要一"},{"type":"summary_text","text":"摘要二"}],"encrypted_content":"must-not-decode"},
            {"type":"reasoning","content":[{"type":"reasoning_text","text":"兼容思考"}]},
            {"type":"message","content":[{"type":"output_text","text":"answer"}]}
        ]});
        assert_eq!(
            reasoning_text(&response, "responses"),
            "摘要一\n\n摘要二\n\n兼容思考"
        );
        assert!(
            reasoning_text(
                &json!({"output":[{"type":"reasoning","encrypted_content":"opaque"}]}),
                "responses"
            )
            .is_empty()
        );
        let local = settings("responses");
        let parameters: Parameters = decode(json!({"reasoning_effort":"none"})).unwrap();
        assert!(
            parameters.payload(&local, json!([]))["reasoning"]
                .get("summary")
                .is_none()
        );
    }
}
