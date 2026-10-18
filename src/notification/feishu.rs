//! Feishu custom-bot protocol. Never include request URLs or response bodies in errors.
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use serde_json::{Value, json};
use std::time::Duration;

pub fn validate_url(value: &str) -> Result<reqwest::Url, &'static str> {
    let url = reqwest::Url::parse(value).map_err(|_| "飞书 Webhook 地址无效")?;
    let hook = url.path().strip_prefix("/open-apis/bot/v2/hook/");
    if url.scheme() != "https"
        || url.host_str() != Some("open.feishu.cn")
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || hook.is_none_or(|id| uuid::Uuid::parse_str(id).is_err() || id.len() != 36)
    {
        return Err("仅支持 https://open.feishu.cn/open-apis/bot/v2/hook/<机器人 UUID>");
    }
    Ok(url)
}

pub fn signature(timestamp: i64, secret: &str) -> Result<String, openssl::error::ErrorStack> {
    let key = PKey::hmac(format!("{timestamp}\n{secret}").as_bytes())?;
    let signer = Signer::new(MessageDigest::sha256(), &key)?;
    Ok(openssl::base64::encode_block(&signer.sign_to_vec()?))
}

pub use super::Outcome;

pub fn classify(http: u16, value: Option<&Value>) -> Outcome {
    let code = value
        .and_then(|v| v.get("code").or_else(|| v.get("StatusCode")))
        .and_then(Value::as_i64);
    let sent = (200..300).contains(&http) && code == Some(0);
    let retryable = http == 429
        || http >= 500
        || matches!(code, Some(11232 | 11233 | 99991400))
        || ((200..300).contains(&http) && code.is_none());
    Outcome {
        sent,
        retryable,
        http: Some(i32::from(http)),
        code,
        retry_after: 0,
        reason: if sent {
            "sent"
        } else if retryable {
            "provider_temporarily_unavailable"
        } else if matches!(code, Some(19002 | 9499)) {
            "invalid_payload"
        } else {
            "provider_rejected"
        },
    }
}

pub async fn send(
    client: &reqwest::Client,
    url: &str,
    secret: Option<&str>,
    text: &str,
) -> Outcome {
    send_payload(
        client,
        url,
        secret,
        json!({"msg_type":"text","content":{"text":text}}),
    )
    .await
}

pub(super) async fn send_payload(
    client: &reqwest::Client,
    url: &str,
    secret: Option<&str>,
    payload: Value,
) -> Outcome {
    let Ok(url) = validate_url(url) else {
        return Outcome::failure("invalid_destination", false);
    };
    let bytes = match encode_payload(payload, secret, chrono::Utc::now().timestamp()) {
        Ok(bytes) => bytes,
        Err(outcome) => return outcome,
    };
    transmit(client, url, bytes).await
}

fn encode_payload(
    mut payload: Value,
    secret: Option<&str>,
    timestamp: i64,
) -> Result<Vec<u8>, Outcome> {
    // Custom bots do not support post node styles (unlike the application bot API).
    // Also normalize persisted template-test snapshots created by older servers.
    if payload["msg_type"] == "post"
        && let Some(locales) = payload
            .get_mut("content")
            .and_then(|content| content.get_mut("post"))
            .and_then(Value::as_object_mut)
    {
        for locale in locales.values_mut() {
            if let Some(lines) = locale.get_mut("content").and_then(Value::as_array_mut) {
                for line in lines {
                    if let Some(nodes) = line.as_array_mut() {
                        for node in nodes {
                            if let Some(node) = node.as_object_mut() {
                                node.remove("style");
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some(secret) = secret {
        let Ok(sign) = signature(timestamp, secret) else {
            return Err(Outcome::failure("signing_failed", false));
        };
        payload["timestamp"] = json!(timestamp.to_string());
        payload["sign"] = json!(sign);
    }
    let Ok(bytes) = serde_json::to_vec(&payload) else {
        return Err(Outcome::failure("invalid_payload", false));
    };
    if bytes.len() > 20 * 1024 {
        return Err(Outcome::failure("payload_too_large", false));
    }
    Ok(bytes)
}

async fn transmit(client: &reqwest::Client, url: reqwest::Url, bytes: Vec<u8>) -> Outcome {
    let Ok(mut response) = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(bytes)
        .send()
        .await
    else {
        return Outcome::failure("network_or_tls_error", true);
    };
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get("Retry-After")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0)
        .clamp(0, 86400);
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if body.len() + chunk.len() <= 16 * 1024 => {
                body.extend_from_slice(&chunk)
            }
            Ok(Some(_)) => return Outcome::failure("response_too_large", false),
            Ok(None) => break,
            Err(_) => return Outcome::failure("response_read_failed", true),
        }
    }
    let value = serde_json::from_slice::<Value>(&body).ok();
    let mut outcome = classify(status, value.as_ref());
    outcome.retry_after = retry_after;
    outcome
}

pub fn client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn destinations_are_fixed_to_the_feishu_bot_endpoint() {
        let good =
            "https://open.feishu.cn/open-apis/bot/v2/hook/00000000-0000-4000-8000-000000000001";
        assert!(validate_url(good).is_ok());
        for bad in [
            good.replace("https:", "http:"),
            good.replace("open.feishu.cn", "localhost"),
            good.replace("open.feishu.cn", "open.feishu.cn.evil.example"),
            format!("{good}?x=1"),
            format!("{good}#x"),
            good.replace("open.feishu.cn", "user@open.feishu.cn"),
            good.replace("open.feishu.cn", "open.feishu.cn:444"),
            format!("{good}/other"),
        ] {
            assert!(validate_url(&bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn business_failure_is_not_http_success() {
        assert!(classify(200, Some(&json!({"code":0}))).sent);
        assert!(classify(200, Some(&json!({"StatusCode":0}))).sent);
        assert!(!classify(200, Some(&json!({"code":19021}))).retryable);
        assert!(classify(200, Some(&json!({"code":11232}))).retryable);
        assert!(classify(429, None).retryable);
        assert!(classify(503, None).retryable);
        assert!(!classify(403, Some(&json!({"code":0}))).sent);
        assert!(!classify(200, None).sent);
        for code in [19002, 9499] {
            let outcome = classify(200, Some(&json!({"code":code})));
            assert!(!outcome.sent);
            assert!(!outcome.retryable);
            assert_eq!(outcome.reason, "invalid_payload");
            assert_eq!(outcome.code, Some(code));
        }
    }

    #[test]
    fn old_post_snapshots_drop_styles_before_encoding_and_signing() {
        let mut payload = json!({"msg_type":"post","content":{"post":{}}});
        for locale in ["zh_cn", "en_us"] {
            payload["content"]["post"][locale] = json!({
                "title":"测试通知",
                "content":[[
                    {"tag":"text","text":"正文","style":["bold","underline"]},
                    {"tag":"a","text":"查看","href":"https://example.com?a=1&b=2","style":[]}
                ]]
            });
        }
        for secret in [None, Some("demo")] {
            let bytes = encode_payload(payload.clone(), secret, 1599360473).unwrap();
            let actual: Value = serde_json::from_slice(&bytes).unwrap();
            for locale in ["zh_cn", "en_us"] {
                assert_eq!(
                    actual["content"]["post"][locale],
                    json!({
                        "title":"测试通知",
                        "content":[[
                            {"tag":"text","text":"正文"},
                            {"tag":"a","text":"查看","href":"https://example.com?a=1&b=2"}
                        ]]
                    })
                );
            }
            if secret.is_some() {
                assert_eq!(actual["timestamp"], "1599360473");
                assert_eq!(
                    actual["sign"],
                    "l1N0gAcBjdwBvGm1xMjOF0XSyaLRpR7tuO5dHfhAYc8="
                );
            } else {
                assert!(actual.get("timestamp").is_none());
                assert!(actual.get("sign").is_none());
            }
        }
        let text = json!({"msg_type":"text","content":{"text":"style 正文 <b>原样</b>"}});
        let actual: Value =
            serde_json::from_slice(&encode_payload(text.clone(), None, 0).unwrap()).unwrap();
        assert_eq!(actual, text);
        assert_eq!(
            encode_payload(
                json!({"msg_type":"text","content":{"text":"x".repeat(20*1024)}}),
                Some("demo"),
                0
            )
            .unwrap_err()
            .reason,
            "payload_too_large"
        );
    }

    #[test]
    fn interactive_card_encoding_preserves_card_and_adds_signature() {
        let rendered = super::super::template_render::render(
            "feishu",
            &super::super::template_render::event_default_source("health.alert"),
            &super::super::template_render::sample_context("health.alert"),
        )
        .unwrap();
        for secret in [None, Some("demo")] {
            let encoded: Value = serde_json::from_slice(
                &encode_payload(rendered.payload.clone(), secret, 1599360473).unwrap(),
            )
            .unwrap();
            assert_eq!(encoded["msg_type"], "interactive");
            assert_eq!(encoded["card"], rendered.payload["card"]);
            assert!(encoded.get("content").is_none());
            if secret.is_some() {
                assert_eq!(encoded["timestamp"], "1599360473");
                assert_eq!(
                    encoded["sign"],
                    "l1N0gAcBjdwBvGm1xMjOF0XSyaLRpR7tuO5dHfhAYc8="
                );
            }
        }
    }
    #[test]
    fn signature_uses_timestamp_and_secret_as_key_and_empty_message() {
        // Independent Python hmac test vector, not the platform's webhook signature format.
        assert_eq!(
            signature(1599360473, "demo").unwrap(),
            "l1N0gAcBjdwBvGm1xMjOF0XSyaLRpR7tuO5dHfhAYc8="
        );
    }

    #[actix_web::test]
    async fn http_adapter_reads_business_codes_bounds_bodies_and_honors_retry_after() {
        use actix_web::{App, HttpResponse, HttpServer, web};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = HttpServer::new(|| {
            App::new()
                .route(
                    "/card",
                    web::post().to(|payload: web::Json<Value>| async move {
                        let card = &payload["card"];
                        let valid = payload["msg_type"] == "interactive"
                            && payload.get("content").is_none()
                            && card["schema"] == "2.0"
                            && card["header"]["title"]["tag"] == "plain_text"
                            && card["header"]["title"]["content"].is_string()
                            && card["body"]["elements"].as_array().is_some_and(|elements| {
                                !elements.is_empty()
                                    && elements.iter().all(|element| {
                                        element["tag"] == "hr"
                                            || (element["tag"] == "markdown"
                                                && element["content"]
                                                    .as_str()
                                                    .is_some_and(|text| !text.is_empty()))
                                    })
                            });
                        HttpResponse::Ok().json(json!({"code":if valid {0} else {19002}}))
                    }),
                )
                .route(
                    "/post",
                    web::post().to(|payload: web::Json<Value>| async move {
                        let post = &payload["content"]["post"]["zh_cn"];
                        let valid = payload["msg_type"] == "post"
                            && post["title"].is_string()
                            && post["content"].as_array().is_some_and(|lines| {
                                !lines.is_empty()
                                    && lines.iter().all(|line| {
                                        line.as_array().is_some_and(|nodes| {
                                            !nodes.is_empty()
                                                && nodes.iter().all(|node| {
                                                    node.get("style").is_none()
                                                        && node["text"].is_string()
                                                        && (node["tag"] == "text"
                                                            || (node["tag"] == "a"
                                                                && node["href"].is_string()))
                                                })
                                        })
                                    })
                            });
                        HttpResponse::Ok().json(json!({"code":if valid {0} else {19002}}))
                    }),
                )
                .route(
                    "/rejected",
                    web::post().to(|| async {
                        HttpResponse::Ok()
                            .json(json!({"code":19021,"msg":"sensitive provider content"}))
                    }),
                )
                .route(
                    "/limited",
                    web::post().to(|| async {
                        HttpResponse::TooManyRequests()
                            .insert_header(("Retry-After", "120"))
                            .json(json!({"code":11232}))
                    }),
                )
                .route(
                    "/large",
                    web::post().to(|| async { HttpResponse::Ok().body(vec![b'x'; 17 * 1024]) }),
                )
        })
        .listen(listener)
        .unwrap()
        .run();
        let handle = server.handle();
        actix_web::rt::spawn(server);
        // Test transport only: loopback fixture does not change the production HTTPS allowlist.
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let old_snapshot = json!({"msg_type":"post","content":{"post":{"zh_cn":{
            "title":"测试通知","content":[[{"tag":"text","text":"正文","style":["bold"]}]]
        }}}});
        let post_url = reqwest::Url::parse(&format!("http://{address}/post")).unwrap();
        let invalid = transmit(
            &client,
            post_url.clone(),
            serde_json::to_vec(&old_snapshot).unwrap(),
        )
        .await;
        assert_eq!(invalid.code, Some(19002));
        assert_eq!(invalid.reason, "invalid_payload");
        let retried = transmit(
            &client,
            post_url.clone(),
            encode_payload(old_snapshot, Some("demo"), 1599360473).unwrap(),
        )
        .await;
        assert!(retried.sent);
        let card_url = reqwest::Url::parse(&format!("http://{address}/card")).unwrap();
        // Exercise the same renderer used by template tests and normal event deliveries.
        for event in super::super::EVENT_TYPES {
            for severity in ["warning", "critical"] {
                let mut context = super::super::template_render::sample_context(event);
                context.insert("severity", severity);
                let rendered = super::super::template_render::render(
                    "feishu",
                    &super::super::template_render::event_default_source(event),
                    &context,
                )
                .unwrap();
                let outcome = transmit(
                    &client,
                    card_url.clone(),
                    encode_payload(rendered.payload, None, 0).unwrap(),
                )
                .await;
                assert!(outcome.sent, "{event}/{severity}: {outcome:?}");
            }
        }
        let rejected = transmit(
            &client,
            format!("http://{address}/rejected").parse().unwrap(),
            b"{}".to_vec(),
        )
        .await;
        assert_eq!(rejected.code, Some(19021));
        assert!(!rejected.sent);
        assert!(!rejected.retryable);
        assert!(!format!("{rejected:?}").contains("sensitive"));
        let limited = transmit(
            &client,
            format!("http://{address}/limited").parse().unwrap(),
            b"{}".to_vec(),
        )
        .await;
        assert!(limited.retryable);
        assert_eq!(limited.retry_after, 120);
        let large = transmit(
            &client,
            format!("http://{address}/large").parse().unwrap(),
            b"{}".to_vec(),
        )
        .await;
        assert_eq!(large.reason, "response_too_large");
        handle.stop(true).await;
    }
}
