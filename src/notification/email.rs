//! SMTP notification transport: one attempt, with retry owned by the durable queue.
use super::{ChannelSettings, Outcome};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    transport::smtp::authentication::Credentials,
};
use std::time::Duration;

pub async fn render(
    pool: &deadpool_postgres::Pool,
    context: &serde_json::Value,
) -> Result<Option<crate::mail_template::RenderedMailTemplate>, Outcome> {
    let mut context = context.clone();
    if let Some(outage) = context["outage_id"].as_i64() {
        let c = pool
            .get()
            .await
            .map_err(|_| Outcome::failure("notification_source_unavailable", true))?;
        let row=c.query_opt("SELECT o.scanner_id,o.last_seen_at,o.detected_at,o.recovered_at,s.name,s.location FROM scanner_outage o JOIN scanner_info s ON s.scanner_id=o.scanner_id WHERE o.id=$1", &[&outage]).await.map_err(|_| Outcome::failure("notification_source_unavailable",true))?.ok_or_else(|| Outcome::failure("notification_source_unavailable",false))?;
        let scanner: String = row.get("scanner_id");
        let offline = context["event_type"] == "scanner.offline";
        let at: chrono::DateTime<chrono::Utc> = if offline {
            row.get("detected_at")
        } else {
            row.get::<_, Option<chrono::DateTime<chrono::Utc>>>("recovered_at")
                .unwrap_or_else(chrono::Utc::now)
        };
        context = serde_json::json!({"mail_template":crate::mail_template::SCANNER_OUTAGE_TEMPLATE_KEY,"mail_context":{
            "system_name":"Network Mapping","event_label":if offline {"掉线"} else {"恢复"},
            "scanner_id":scanner,"scanner_name":row.get::<_,Option<String>>("name").filter(|s| !s.is_empty()).unwrap_or_else(||scanner.clone()),
            "location":row.get::<_,Option<String>>("location").unwrap_or_default(),"last_seen_at":row.get::<_,chrono::DateTime<chrono::Utc>>("last_seen_at").format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            "event_at":at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),"detail_path":format!("/scanner/{scanner}")
        }});
    }
    if let Some(report) = context["report_id"].as_str() {
        let id = report
            .parse::<uuid::Uuid>()
            .map_err(|_| Outcome::failure("invalid_payload", false))?;
        let c = pool
            .get()
            .await
            .map_err(|_| Outcome::failure("notification_source_unavailable", true))?;
        let row = c
            .query_opt(
                "SELECT rendered_mail FROM report_run WHERE id=$1 AND status='ready'",
                &[&id],
            )
            .await
            .map_err(|_| Outcome::failure("notification_source_unavailable", true))?;
        return row
            .and_then(|row| row.get::<_, Option<serde_json::Value>>(0))
            .and_then(|v| serde_json::from_value(v).ok())
            .map(Some)
            .ok_or_else(|| Outcome::failure("report_unavailable", false));
    }
    let Some(template) = context["mail_template"].as_str() else {
        return Ok(None);
    };
    let source = crate::mail_template::get_published_source(pool, template)
        .await
        .map_err(|_| Outcome::failure("notification_source_unavailable", true))?
        .ok_or_else(|| Outcome::failure("mail_template_disabled", false))?;
    let context = tera::Context::from_serialize(&context["mail_context"])
        .map_err(|_| Outcome::failure("invalid_payload", false))?;
    crate::mail_template::render_template(template, &source, &context)
        .map(Some)
        .map_err(|_| Outcome::failure("invalid_payload", false))
}

fn build_message(
    settings: &ChannelSettings,
    _password: &str,
    recipients: &[String],
    title: &str,
    text: &str,
    rendered: Option<&crate::mail_template::RenderedMailTemplate>,
) -> Result<Message, Outcome> {
    let Some(first) = recipients.first() else {
        return Err(Outcome::failure("no_recipients", false));
    };
    let Ok(sender) = settings.smtp_sender.parse() else {
        return Err(Outcome::failure("invalid_destination", false));
    };
    let Ok(recipient) = first.parse() else {
        return Err(Outcome::failure("invalid_destination", false));
    };
    // One envelope with Bcc recipients avoids exposing other recipients and partial per-recipient retries.
    let mut builder = Message::builder()
        .from(sender)
        .to(recipient)
        .subject(rendered.map(|r| r.subject.as_str()).unwrap_or(title));
    for recipient in recipients.iter().skip(1) {
        let Ok(recipient) = recipient.parse() else {
            return Err(Outcome::failure("invalid_destination", false));
        };
        builder = builder.bcc(recipient);
    }
    let message = match rendered {
        Some(rendered) => builder.multipart(lettre::message::MultiPart::alternative_plain_html(
            rendered.text_body.clone(),
            rendered.html_body.clone(),
        )),
        None => builder.body(text.to_owned()),
    };
    let Ok(message) = message else {
        return Err(Outcome::failure("invalid_payload", false));
    };
    Ok(message)
}

pub async fn send(
    settings: &ChannelSettings,
    password: &str,
    recipients: &[String],
    title: &str,
    text: &str,
    rendered: Option<&crate::mail_template::RenderedMailTemplate>,
) -> Outcome {
    let message = match build_message(settings, password, recipients, title, text, rendered) {
        Ok(message) => message,
        Err(outcome) => return outcome,
    };
    let Ok(transport) = AsyncSmtpTransport::<Tokio1Executor>::relay(&settings.smtp_host) else {
        return Outcome::failure("invalid_destination", false);
    };
    let transport = transport
        .port(settings.smtp_port)
        .credentials(Credentials::new(
            settings.smtp_sender.clone(),
            password.to_owned(),
        ))
        .timeout(Some(Duration::from_secs(10)))
        .build();
    match transport.send(message).await {
        Ok(_) => Outcome {
            sent: true,
            retryable: false,
            reason: "sent",
            http: None,
            code: None,
            retry_after: 0,
        },
        Err(error) => Outcome::failure(
            "smtp_delivery_failed",
            !(error.is_permanent() || error.is_client() || error.is_tls()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mail_envelope_preserves_all_recipients_without_exposing_bcc_or_credentials() {
        let settings = ChannelSettings {
            smtp_sender: "sender@example.com".into(),
            ..Default::default()
        };
        let rendered = crate::mail_template::RenderedMailTemplate {
            subject: "subject".into(),
            text_body: "plain content".into(),
            html_body: "<p>html content</p>".into(),
        };
        let message = build_message(
            &settings,
            "smtp-secret",
            &["first@example.com".into(), "second@example.com".into()],
            "fallback",
            "fallback",
            Some(&rendered),
        )
        .unwrap();
        assert_eq!(message.envelope().to().len(), 2);
        let wire = String::from_utf8(message.formatted()).unwrap();
        assert!(wire.contains("plain content"));
        assert!(wire.contains("html content"));
        assert!(!wire.contains("Bcc:"));
        assert!(!wire.contains("second@example.com"));
        assert!(!wire.contains("smtp-secret"));
        assert_eq!(
            build_message(&settings, "secret", &[], "subject", "body", None)
                .unwrap_err()
                .reason,
            "no_recipients"
        );
    }
}
