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
    send_payload(
        client,
        token,
        chat_id,
        json!({"text":text,"link_preview_options":{"is_disabled":true}}),
    )
    .await
}

pub(super) async fn send_payload(
    client: &reqwest::Client,
    token: &str,
    chat_id: &str,
    mut payload: Value,
) -> Outcome {
    if !validate_token(token) || !validate_chat_id(chat_id) {
        return Outcome::failure("invalid_destination", false);
    }
    if serde_json::to_vec(&payload).map_or(true, |bytes| bytes.len() > 20 * 1024) {
        return Outcome::failure("payload_too_large", false);
    }
    payload["chat_id"] = json!(chat_id);
    let method = if payload.get("rich_message").is_some() {
        "sendRichMessage"
    } else {
        "sendMessage"
    };
    transmit(
        client,
        &format!("https://api.telegram.org/bot{token}/{method}"),
        payload,
    )
    .await
}

pub(super) async fn send_report_image(
    client: &reqwest::Client,
    token: &str,
    chat_id: &str,
    payload: Value,
    image: Vec<u8>,
) -> Outcome {
    if !validate_token(token) || !validate_chat_id(chat_id) {
        return Outcome::failure("invalid_destination", false);
    }
    send_report_image_to(
        client,
        &format!("https://api.telegram.org/bot{token}/sendRichMessage"),
        chat_id,
        payload,
        image,
    )
    .await
}

async fn send_report_image_to(
    client: &reqwest::Client,
    url: &str,
    chat_id: &str,
    mut payload: Value,
    image: Vec<u8>,
) -> Outcome {
    let Some(html) = payload["rich_message"]["html"].as_str() else {
        return Outcome::failure("invalid_payload", false);
    };
    let position = html
        .find("<b>与上一周期比较</b>")
        .or_else(|| html.rfind("<br/>事件 ID："))
        .unwrap_or(html.len());
    let html = format!(
        "{}<img src=\"tg://photo?id=trend\"/>{}",
        &html[..position],
        &html[position..]
    );
    payload["rich_message"]["html"] = json!(html);
    payload["rich_message"]["media"] =
        json!([{"id":"trend","media":{"type":"photo","media":"attach://trend"}}]);
    let Ok(rich) = serde_json::to_string(&payload["rich_message"]) else {
        return Outcome::failure("invalid_payload", false);
    };
    if rich.len() > 20 * 1024 {
        return Outcome::failure("payload_too_large", false);
    }
    let Ok(part) = reqwest::multipart::Part::bytes(image)
        .file_name("trend.png")
        .mime_str("image/png")
    else {
        return Outcome::failure("invalid_payload", false);
    };
    let form = reqwest::multipart::Form::new()
        .text("chat_id", chat_id.to_owned())
        .text("rich_message", rich)
        .part("trend", part);
    let response = client.post(url).multipart(form).send().await;
    read_response(response).await
}

async fn transmit(client: &reqwest::Client, url: &str, payload: Value) -> Outcome {
    read_response(client.post(url).json(&payload).send().await).await
}

async fn read_response(response: Result<reqwest::Response, reqwest::Error>) -> Outcome {
    let Ok(mut response) = response else {
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
    #[actix_web::test]
    async fn rich_report_upload_references_attached_image() {
        use actix_web::{App, HttpResponse, HttpServer, web};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = HttpServer::new(|| {
            App::new().route(
                "/rich",
                web::post().to(|body: web::Bytes| async move {
                    let body = String::from_utf8_lossy(&body);
                    assert!(body.contains("name=\"chat_id\"") && body.contains("-100123"));
                    assert!(
                        body.contains("tg://photo?id=trend") && body.contains("attach://trend")
                    );
                    assert!(
                        body.find("tg://photo?id=trend").unwrap()
                            < body.find("与上一周期比较").unwrap()
                    );
                    assert!(body.contains("name=\"trend\"") && body.contains("trend.png"));
                    HttpResponse::Ok().json(json!({"ok":true,"result":{"message_id":42}}))
                }),
            )
        })
        .listen(listener)
        .unwrap()
        .run();
        let handle = server.handle();
        actix_web::rt::spawn(server);
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let payload =
            json!({"rich_message":{"html":"<b>报告</b><br/><b>与上一周期比较</b><br/>事件 ID：1"}});
        assert!(
            send_report_image_to(
                &client,
                &format!("http://{address}/rich"),
                "-100123",
                payload,
                b"png".to_vec()
            )
            .await
            .sent
        );
        handle.stop(true).await;
    }
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
