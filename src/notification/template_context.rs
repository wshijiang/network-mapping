//! Shared event data for mail and bot templates. Only catalogued fields cross into templates.
use super::Outcome;
use crate::mail_template as mail;
use deadpool_postgres::Pool;
use serde_json::{Value, json};

pub fn key(event: &str) -> Option<&'static str> {
    match event {
        "user.login" => Some(mail::LOGIN_SUCCESS_TEMPLATE_KEY),
        "health.alert" => Some(mail::HEALTH_ALERT_TEMPLATE_KEY),
        "scanner.offline" | "scanner.recovered" => Some(mail::SCANNER_OUTAGE_TEMPLATE_KEY),
        "report.weekly" => Some(mail::REPORT_WEEKLY_TEMPLATE_KEY),
        "report.monthly" => Some(mail::REPORT_MONTHLY_TEMPLATE_KEY),
        _ => None,
    }
}

pub fn variables(event: &str) -> Vec<mail::MailTemplateVariable> {
    key(event).map(mail::template_variables).unwrap_or_default()
}

pub fn project(event: &str, value: &Value) -> Value {
    Value::Object(
        variables(event)
            .into_iter()
            .filter_map(|v| {
                value
                    .get(v.key)
                    .map(|value| (v.key.to_owned(), value.clone()))
            })
            .collect(),
    )
}

pub async fn resolve(pool: &Pool, event: &str, stored: &Value) -> Result<Value, Outcome> {
    let unavailable = || Outcome::failure("notification_source_unavailable", true);
    if let Some(outage) = stored["outage_id"].as_i64() {
        let c = pool.get().await.map_err(|_| unavailable())?;
        let row = c.query_opt("SELECT o.scanner_id,o.last_seen_at,o.detected_at,o.recovered_at,s.name,s.location FROM scanner_outage o JOIN scanner_info s ON s.scanner_id=o.scanner_id WHERE o.id=$1", &[&outage]).await.map_err(|_| unavailable())?.ok_or_else(|| Outcome::failure("notification_source_unavailable", false))?;
        let scanner: String = row.get("scanner_id");
        let offline = event == "scanner.offline";
        let at: chrono::DateTime<chrono::Utc> = if offline {
            row.get("detected_at")
        } else {
            row.get::<_, Option<chrono::DateTime<chrono::Utc>>>("recovered_at")
                .ok_or_else(|| Outcome::failure("notification_source_unavailable", false))?
        };
        return Ok(
            json!({"system_name":"Network Mapping","event_label":if offline {"掉线"} else {"恢复"},
            "scanner_id":scanner,"scanner_name":row.get::<_,Option<String>>("name").filter(|s| !s.is_empty()).unwrap_or_else(||scanner.clone()),
            "location":row.get::<_,Option<String>>("location").unwrap_or_default(),
            "last_seen_at":row.get::<_,chrono::DateTime<chrono::Utc>>("last_seen_at").format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            "event_at":at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),"detail_path":format!("/scanner/{scanner}")}),
        );
    }
    if stored["mail_context"].is_object() {
        return Ok(project(event, &stored["mail_context"]));
    }
    if let Some(report) = stored["report_id"].as_str() {
        let id = report
            .parse::<uuid::Uuid>()
            .map_err(|_| Outcome::failure("invalid_payload", false))?;
        let c = pool.get().await.map_err(|_| unavailable())?;
        let row = c.query_opt("SELECT notification_context,payload,quality,revision,generated_at,cutoff_at FROM report_run WHERE id=$1 AND status='ready'", &[&id]).await.map_err(|_| unavailable())?.ok_or_else(|| Outcome::failure("report_unavailable", false))?;
        if let Some(context) = row.get::<_, Option<Value>>("notification_context") {
            return Ok(project(event, &context));
        }
        // Reports archived before this feature can be projected from their immutable statistics.
        let config = crate::reports::mail_config::load(&c)
            .await
            .map_err(|_| unavailable())?;
        let meta = crate::reports::mail_context::MailMetadata {
            revision: row.get("revision"),
            generated_at: row
                .get::<_, Option<chrono::DateTime<chrono::Utc>>>("generated_at")
                .ok_or_else(|| Outcome::failure("report_unavailable", false))?,
            cutoff_at: row.get("cutoff_at"),
        };
        return crate::reports::mail_context::build(
            &row.get::<_, Option<Value>>("payload")
                .unwrap_or(Value::Null),
            &row.get::<_, Value>("quality"),
            id,
            &meta,
            &config,
            "",
        )
        .map(|v| project(event, &v))
        .map_err(|_| Outcome::failure("report_unavailable", false));
    }
    Ok(json!({}))
}
