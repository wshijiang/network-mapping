//! Telegram Bot API adapter. Credentials and provider response text never leave this module.
use super::Outcome;
use serde_json::{Value, json};

pub fn validate_token(token: &str) -> bool {
    let Some((id, secret)) = token.split_once(':') else {
        return false;
    };
    !id.is_empty()
        && id.len() <= 20
        && id.bytes().all(|b| b.is_ascii_digit())
        && (20..=128).contains(&secret.len())
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub fn validate_chat_id(chat: &str) -> bool {
    if let Some(name) = chat.strip_prefix('@') {
        (5..=32).contains(&name.len())
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    } else {
        chat.parse::<i64>().is_ok_and(|id| id != 0)
    }
}

fn classify(status: u16, value: Option<&Value>) -> Outcome {
    let sent = (200..300).contains(&status)
        && value.is_some_and(|v| v["ok"] == true && v["result"]["message_id"].is_i64());
    let code = value.and_then(|v| v["error_code"].as_i64());
    let retryable = status == 429
        || status >= 500
        || code == Some(429)
        || ((200..300).contains(&status) && value.is_none());
    Outcome {
        sent,
        retryable,
        http: Some(i32::from(status)),
        code,
        retry_after: value
            .and_then(|v| v["parameters"]["retry_after"].as_i64())
            .unwrap_or(0)
            .clamp(0, 86400),
        reason: if sent {
            "sent"
        } else if retryable {
            "provider_temporarily_unavailable"
        } else {
            "provider_rejected"
        },
    }
}

pub async fn send(client: &reqwest::Client, token: &str, chat_id: &str, text: &str) -> Outcome {
    if !validate_token(token) || !validate_chat_id(chat_id) {
        return Outcome::failure("invalid_destination", false);
    }
    // Leave room for supplementary-plane characters under Telegram's 4096 UTF-16 unit limit.
    if text.encode_utf16().count() > 4096 {
        return Outcome::failure("payload_too_large", false);
    }
    transmit(
        client,
        &format!("https://api.telegram.org/bot{token}/sendMessage"),
        json!({
            "chat_id": chat_id, "text": text, "link_preview_options": {"is_disabled": true}
        }),
    )
    .await
}

async fn transmit(client: &reqwest::Client, url: &str, payload: Value) -> Outcome {
    let Ok(mut response) = client.post(url).json(&payload).send().await else {
        return Outcome::failure("network_or_tls_error", true);
    };
    let status = response.status().as_u16();
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
    classify(status, serde_json::from_slice::<Value>(&body).ok().as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_cannot_change_the_bot_api_destination() {
        assert!(validate_token("123456:abcdefghijklmnopqrstuvwxyz_ABC-123"));
        for bad in [
            "123:short",
            "123:abcdefghijklmnopqrstuvwxyz/other",
            "x:abcdefghijklmnopqrstuvwxyz",
            "123:abcdefghijklmnopqrstuvwxyz?x=1",
        ] {
            assert!(!validate_token(bad));
        }
        assert!(validate_chat_id("-1001234567890"));
        assert!(validate_chat_id("@operations_channel"));
        for bad in ["0", "https://other.example", "@a", "@bad/channel"] {
            assert!(!validate_chat_id(bad));
        }
    }
    #[test]
    fn telegram_requires_business_success_and_uses_retry_after() {
        assert!(classify(200, Some(&json!({"ok":true,"result":{"message_id":1}}))).sent);
        assert!(
            !classify(
                200,
                Some(&json!({"ok":false,"error_code":403,"description":"secret"}))
            )
            .sent
        );
        assert!(!classify(200, Some(&json!({"ok":true}))).sent);
        let limited = classify(
            429,
            Some(&json!({"ok":false,"error_code":429,"parameters":{"retry_after":120}})),
        );
        assert!(limited.retryable);
        assert_eq!(limited.retry_after, 120);
        assert!(!classify(403, None).retryable);
        assert!(classify(503, None).retryable);
    }

    #[actix_web::test]
    async fn http_transport_checks_business_result_retry_delay_and_response_size() {
        use actix_web::{App, HttpResponse, HttpServer, web};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = HttpServer::new(|| App::new()
            .route("/success",web::post().to(|payload:web::Json<Value>| async move {
                assert_eq!(payload["chat_id"],"-100123");
                assert_eq!(payload["text"],"test message");
                HttpResponse::Ok().json(json!({"ok":true,"result":{"message_id":42}}))
            }))
            .route("/limited",web::post().to(|| async { HttpResponse::TooManyRequests().json(json!({"ok":false,"error_code":429,"parameters":{"retry_after":90},"description":"private provider text"})) }))
            .route("/large",web::post().to(|| async { HttpResponse::Ok().body(vec![b'x';17*1024]) })))
            .listen(listener).unwrap().run();
        let handle = server.handle();
        actix_web::rt::spawn(server);
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let payload = json!({"chat_id":"-100123","text":"test message"});
        assert!(
            transmit(
                &client,
                &format!("http://{address}/success"),
                payload.clone()
            )
            .await
            .sent
        );
        let limited = transmit(
            &client,
            &format!("http://{address}/limited"),
            payload.clone(),
        )
        .await;
        assert!(limited.retryable);
        assert_eq!(limited.retry_after, 90);
        assert!(!format!("{limited:?}").contains("private provider text"));
        assert_eq!(
            transmit(&client, &format!("http://{address}/large"), payload)
                .await
                .reason,
            "response_too_large"
        );
        handle.stop(true).await;
    }
}
