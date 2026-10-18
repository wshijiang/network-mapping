//! Durable, administrator-managed notification channels with shared event subscriptions.
mod email;
mod outcome;
pub use outcome::Outcome;
pub mod feishu;
mod routes;
pub mod telegram;
mod template_context;
mod template_render;
mod templates;
#[cfg(test)]
mod tests;
mod worker;

use actix_web::http::StatusCode;
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use crate::{
    admin::UserBaseI,
    audit::{AuditContext, AuditEvent},
};
pub use routes::configure;
pub use worker::run;

pub const EVENT_TYPES: [&str; 6] = [
    "health.alert",
    "scanner.offline",
    "scanner.recovered",
    "user.login",
    "report.weekly",
    "report.monthly",
];
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    pub status: StatusCode,
    pub message: &'static str,
}
impl Error {
    pub fn bad(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }
    pub fn missing() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: "通知渠道或投递记录不存在",
        }
    }
    pub fn conflict() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: "配置已变化或当前状态不可操作，请刷新后重试",
        }
    }
    pub fn internal() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "通知服务暂时不可用",
        }
    }
}
impl From<tokio_postgres::Error> for Error {
    fn from(value: tokio_postgres::Error) -> Self {
        tracing::error!(event="NotificationDatabaseError", code=?value.code(), "通知数据库操作失败");
        Self::internal()
    }
}
impl From<deadpool_postgres::PoolError> for Error {
    fn from(_: deadpool_postgres::PoolError) -> Self {
        Self::internal()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelInput {
    #[serde(default = "default_provider")]
    pub provider: String,
    pub name: String,
    pub enabled: bool,
    pub event_types: Vec<String>,
    pub minimum_severity: String,
    #[serde(default)]
    pub webhook_url: String,
    #[serde(default)]
    pub signing_secret: String,
    #[serde(default)]
    pub clear_signing_secret: bool,
    #[serde(default)]
    pub bot_token: String,
    #[serde(default)]
    pub smtp_password: String,
    #[serde(default)]
    pub settings: ChannelSettings,
    pub expected_revision: Option<i64>,
}

fn default_provider() -> String {
    "feishu".into()
}
fn default_smtp_port() -> u16 {
    465
}

#[derive(Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelSettings {
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    #[serde(default)]
    pub smtp_sender: String,
    /// Empty means the currently active administrators, never the legacy SMTP test recipient.
    #[serde(default)]
    pub recipients: Vec<String>,
    #[serde(default)]
    pub chat_id: String,
}

impl ChannelInput {
    fn validate(&self, creating: bool) -> Result<()> {
        if self.name.trim().is_empty() || self.name.trim().chars().count() > 80 {
            return Err(Error::bad("渠道名称须为 1 至 80 个字符"));
        }
        if self.event_types.is_empty()
            || self.event_types.len() > EVENT_TYPES.len()
            || self
                .event_types
                .iter()
                .any(|v| !EVENT_TYPES.contains(&v.as_str()))
            || self
                .event_types
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != self.event_types.len()
        {
            return Err(Error::bad("请选择有效且不重复的通知事件"));
        }
        if !["warning", "critical"].contains(&self.minimum_severity.as_str()) {
            return Err(Error::bad("通知级别须为 warning 或 critical"));
        }
        match self.provider.as_str() {
            "feishu" => {
                if creating || !self.webhook_url.is_empty() {
                    feishu::validate_url(&self.webhook_url).map_err(Error::bad)?;
                }
                if self.signing_secret.len() > 512
                    || (self.clear_signing_secret && !self.signing_secret.is_empty())
                {
                    return Err(Error::bad("签名密钥设置无效"));
                }
            }
            "telegram" => {
                if !telegram::validate_chat_id(&self.settings.chat_id)
                    || ((creating || !self.bot_token.is_empty())
                        && !telegram::validate_token(&self.bot_token))
                {
                    return Err(Error::bad("Telegram Bot Token 或 Chat ID 无效"));
                }
            }
            "email" => {
                let s = &self.settings;
                if s.smtp_host.is_empty()
                    || s.smtp_host.len() > 253
                    || s.smtp_host
                        .chars()
                        .any(|c| c.is_whitespace() || "/\\:@?#".contains(c))
                    || s.smtp_port == 0
                    || s.smtp_sender.parse::<lettre::message::Mailbox>().is_err()
                    || s.recipients.len() > 32
                    || s.recipients
                        .iter()
                        .any(|r| r.parse::<lettre::message::Mailbox>().is_err())
                    || self.smtp_password.len() > 1024
                    || (creating && self.smtp_password.is_empty())
                {
                    return Err(Error::bad(
                        "请填写有效的 SMTP 服务器、端口、发件人、密钥和收件人",
                    ));
                }
            }
            _ => return Err(Error::bad("不支持的通知渠道类型")),
        }
        if !creating && self.expected_revision.is_none_or(|v| v < 1) {
            return Err(Error::bad("缺少配置版本"));
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub struct Channel {
    pub id: Uuid,
    pub provider: String,
    pub name: String,
    pub enabled: bool,
    pub event_types: Vec<String>,
    pub minimum_severity: String,
    pub webhook_configured: bool,
    pub signing_secret_configured: bool,
    pub credential_configured: bool,
    pub settings: ChannelSettings,
    pub revision: i64,
    pub updated_at: DateTime<Utc>,
}
fn channel(row: &Row) -> Channel {
    Channel {
        id: row.get("id"),
        provider: row.get("provider"),
        name: row.get("name"),
        enabled: row.get("enabled"),
        event_types: row.get("event_types"),
        minimum_severity: row.get("minimum_severity"),
        webhook_configured: row.get::<_, String>("provider") == "feishu",
        signing_secret_configured: row.get::<_, String>("provider") == "feishu"
            && row.get("secret_configured"),
        credential_configured: row.get("secret_configured"),
        settings: serde_json::from_value(row.get("settings")).unwrap_or_default(),
        revision: row.get("revision"),
        updated_at: row.get("updated_at"),
    }
}
const CHANNEL_COLUMNS: &str = "id, provider, settings, name, enabled, event_types, minimum_severity, secret_ciphertext IS NOT NULL AS secret_configured, revision, updated_at";

pub fn encrypt(value: &str, encoded_key: &str) -> Result<Vec<u8>> {
    let key = openssl::base64::decode_block(encoded_key).map_err(|_| Error::internal())?;
    if key.len() != 32 {
        return Err(Error::internal());
    }
    let (nonce, tag, bytes) =
        crate::identity::encrypt_data(value.as_bytes(), &key).map_err(|_| Error::internal())?;
    Ok([nonce, tag, bytes].concat())
}
fn decrypt(bytes: &[u8], encoded_key: &str) -> Result<String> {
    if bytes.len() < 28 {
        return Err(Error::internal());
    }
    let key = openssl::base64::decode_block(encoded_key).map_err(|_| Error::internal())?;
    if key.len() != 32 {
        return Err(Error::internal());
    }
    let value = crate::identity::decrypt_data(bytes, &key).map_err(|_| Error::internal())?;
    String::from_utf8(value).map_err(|_| Error::internal())
}

pub async fn list(pool: &Pool) -> Result<Vec<Channel>> {
    Ok(pool.get().await?.query(&format!("SELECT {CHANNEL_COLUMNS} FROM notification_channel WHERE deleted_at IS NULL ORDER BY created_at,id"), &[])
        .await?.iter().map(channel).collect())
}

async fn audit(
    tx: &deadpool_postgres::Transaction<'_>,
    user: &UserBaseI,
    context: &AuditContext,
    action: &str,
    id: Uuid,
) -> Result<()> {
    let mut event = AuditEvent::user("configuration", action, "success", user)
        .resource("notification", id.to_string());
    event.response_status = Some(200);
    crate::audit::write(tx, context, &event).await?;
    Ok(())
}

pub async fn save(
    pool: &Pool,
    key: &str,
    id: Option<Uuid>,
    input: ChannelInput,
    user: &UserBaseI,
    context: &AuditContext,
) -> Result<Channel> {
    input.validate(id.is_none())?;
    let mut conn = pool.get().await?;
    let tx = conn.transaction().await?;
    // Serialize channel count checks, including concurrent creations.
    tx.query_one("SELECT pg_advisory_xact_lock(728104, 1)", &[])
        .await?;
    let target = id.unwrap_or_else(Uuid::now_v7);
    let settings = serde_json::to_value(&input.settings).map_err(|_| Error::internal())?;
    let credential = match input.provider.as_str() {
        "email" => &input.smtp_password,
        "telegram" => &input.bot_token,
        _ => &input.signing_secret,
    };
    let secret = if credential.is_empty() {
        None
    } else {
        Some(encrypt(credential, key)?)
    };
    if let Some(id) = id {
        let row = tx.query_opt("SELECT revision,provider,settings,secret_ciphertext IS NOT NULL AS secret_configured FROM notification_channel WHERE id=$1 AND deleted_at IS NULL FOR UPDATE", &[&id]).await?.ok_or_else(Error::missing)?;
        if Some(row.get::<_, i64>("revision")) != input.expected_revision {
            return Err(Error::conflict());
        }
        if row.get::<_, String>("provider") != input.provider {
            return Err(Error::bad("渠道类型不可修改，请创建新渠道"));
        }
        if input.provider != "feishu"
            && secret.is_none()
            && !row.get::<_, bool>("secret_configured")
        {
            return Err(Error::bad("首次配置渠道须填写凭据"));
        }
        let url = if input.provider != "feishu" || input.webhook_url.is_empty() {
            None
        } else {
            Some(encrypt(&input.webhook_url, key)?)
        };
        let clear = input.provider == "feishu" && input.clear_signing_secret;
        // Imported settings may omit optional keys that the Web DTO fills with defaults.
        // Compare their meaning so renames/subscription edits retain offline receipts.
        let previous_settings: ChannelSettings =
            serde_json::from_value(row.get("settings")).map_err(|_| Error::internal())?;
        let destination_changed = url.is_some()
            || (input.provider != "feishu" && previous_settings != input.settings)
            || (input.provider == "telegram" && secret.is_some());
        tx.execute("UPDATE notification_channel SET name=$2,enabled=$3,event_types=$4,minimum_severity=$5,webhook_ciphertext=COALESCE($6,webhook_ciphertext),secret_ciphertext=CASE WHEN $8 THEN NULL ELSE COALESCE($7,secret_ciphertext) END,settings=$9,revision=revision+1,destination_revision=destination_revision+CASE WHEN $10 THEN 1 ELSE 0 END,updated_at=NOW() WHERE id=$1", &[&id,&input.name.trim(),&input.enabled,&input.event_types,&input.minimum_severity,&url,&secret,&clear,&settings,&destination_changed]).await?;
        // An edit cancels queued work. In-flight requests may already have left the process.
        tx.execute("UPDATE notification_delivery SET status='cancelled',last_error='channel_changed',finished_at=NOW(),claim_token=NULL,lease_until=NULL WHERE channel_id=$1 AND status IN ('pending','sending')", &[&id]).await?;
    } else {
        let count: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM notification_channel WHERE deleted_at IS NULL",
                &[],
            )
            .await?
            .get(0);
        if count >= 32 {
            return Err(Error::bad("最多配置 32 个通知渠道"));
        }
        let url = if input.provider == "feishu" {
            encrypt(&input.webhook_url, key)?
        } else {
            Vec::new()
        };
        tx.execute("INSERT INTO notification_channel(id,provider,name,enabled,event_types,minimum_severity,webhook_ciphertext,secret_ciphertext,settings) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", &[&target,&input.provider,&input.name.trim(),&input.enabled,&input.event_types,&input.minimum_severity,&url,&secret,&settings]).await?;
    }
    if input.provider == "email" {
        // Deferred legacy work is handed off atomically with the first usable Web email setup.
        tx.batch_execute("SELECT notification_transfer_legacy_mail()")
            .await?;
        sync_email_transport(&tx).await?;
    }
    audit(&tx, user, context, "notification.channel_save", target).await?;
    let row = tx
        .query_one(
            &format!("SELECT {CHANNEL_COLUMNS} FROM notification_channel WHERE id=$1"),
            &[&target],
        )
        .await?;
    tx.commit().await?;
    Ok(channel(&row))
}

pub async fn remove(
    pool: &Pool,
    id: Uuid,
    revision: i64,
    user: &UserBaseI,
    context: &AuditContext,
) -> Result<()> {
    let mut conn = pool.get().await?;
    let tx = conn.transaction().await?;
    tx.query_one("SELECT pg_advisory_xact_lock(728104, 1)", &[])
        .await?;
    let changed = tx.execute("UPDATE notification_channel SET enabled=FALSE,deleted_at=NOW(),revision=revision+1,webhook_ciphertext=''::BYTEA,secret_ciphertext=NULL WHERE id=$1 AND revision=$2 AND deleted_at IS NULL", &[&id,&revision]).await?;
    if changed != 1 {
        return Err(Error::conflict());
    }
    if tx
        .query_one(
            "SELECT provider FROM notification_channel WHERE id=$1",
            &[&id],
        )
        .await?
        .get::<_, String>(0)
        == "email"
    {
        sync_email_transport(&tx).await?;
    }
    tx.execute("UPDATE notification_delivery SET status='cancelled',last_error='channel_deleted',finished_at=NOW(),claim_token=NULL,lease_until=NULL WHERE channel_id=$1 AND status IN ('pending','sending')", &[&id]).await?;
    audit(&tx, user, context, "notification.channel_delete", id).await?;
    tx.commit().await?;
    Ok(())
}

// Keep explicitly requested report emails and template tests using the first email transport.
// Notification subscriptions themselves are read exclusively from notification_channel.
async fn sync_email_transport(tx: &deadpool_postgres::Transaction<'_>) -> Result<()> {
    let Some(row) = tx.query_opt("SELECT settings,secret_ciphertext FROM notification_channel WHERE provider='email' AND deleted_at IS NULL ORDER BY created_at,id LIMIT 1", &[]).await? else {
        tx.execute("DELETE FROM setting WHERE item_type='smtp' AND key IN ('host','port','sender','sender_key')", &[]).await?;
        return Ok(());
    };
    let settings: ChannelSettings =
        serde_json::from_value(row.get("settings")).map_err(|_| Error::internal())?;
    let encrypted: Option<Vec<u8>> = row.get("secret_ciphertext");
    for (name, value) in [
        ("host", settings.smtp_host),
        ("port", settings.smtp_port.to_string()),
        ("sender", settings.smtp_sender),
        (
            "sender_key",
            encrypted
                .map(|bytes| openssl::base64::encode_block(&bytes))
                .unwrap_or_default(),
        ),
    ] {
        tx.execute("INSERT INTO setting(item_type,key,value) VALUES('smtp',$1,$2) ON CONFLICT(item_type,key) DO UPDATE SET value=EXCLUDED.value,update_at=NOW()", &[&name,&value]).await?;
    }
    Ok(())
}

pub(crate) async fn enqueue(
    tx: &Transaction<'_>,
    event_type: &str,
    severity: &str,
    dedup: &str,
    title: &str,
    body: &str,
    outage: Option<i64>,
) -> std::result::Result<(), tokio_postgres::Error> {
    enqueue_with_context(
        tx,
        event_type,
        severity,
        dedup,
        title,
        body,
        outage,
        json!({}),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn enqueue_with_context(
    tx: &Transaction<'_>,
    event_type: &str,
    severity: &str,
    dedup: &str,
    title: &str,
    body: &str,
    outage: Option<i64>,
    context: Value,
) -> std::result::Result<(), tokio_postgres::Error> {
    let id = Uuid::now_v7();
    let inserted = tx.execute("INSERT INTO notification_event(id,dedup_key,event_type,severity,title,body,outage_id,context) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(dedup_key) DO NOTHING", &[&id,&dedup,&event_type,&severity,&title,&body,&outage,&context]).await?;
    if inserted == 0 {
        return Ok(());
    }
    // Lock matching channels against concurrent edits/deletion until fanout commits.
    let rows = tx.query("SELECT id,destination_revision,legacy_email FROM notification_channel WHERE enabled AND deleted_at IS NULL AND $1=ANY(event_types) AND ($2='critical' OR minimum_severity='warning') FOR SHARE", &[&event_type,&severity]).await?;
    for row in rows {
        let channel: Uuid = row.get("id");
        let destination: i64 = row.get("destination_revision");
        if event_type == "scanner.recovered" {
            // Prepared legacy email recoveries were transferred separately per recipient.
            // Other channels still use their own offline receipts to prepare recovery.
            let legacy = row.get::<_, bool>("legacy_email");
            let sent: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM notification_delivery d JOIN notification_event e ON e.id=d.event_id WHERE e.outage_id=$1 AND e.event_type='scanner.offline' AND d.channel_id=$2 AND d.destination_revision=$3 AND d.status='sent') AND NOT EXISTS(SELECT 1 FROM scanner_outage WHERE id=$1 AND recovery_delivery_prepared AND $4) AND NOT EXISTS(SELECT 1 FROM notification_delivery d JOIN notification_event e ON e.id=d.event_id WHERE d.channel_id=$2 AND d.destination_revision=$3 AND e.outage_id=$1 AND e.event_type='scanner.recovered' AND e.context ? 'legacy_recipient')", &[&outage,&channel,&destination,&legacy]).await?.get(0);
            if !sent {
                continue;
            }
        }
        tx.execute("INSERT INTO notification_delivery(id,event_id,channel_id,destination_revision) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING", &[&Uuid::now_v7(),&id,&channel,&destination]).await?;
    }
    Ok(())
}

pub(crate) async fn enqueue_report(
    tx: &Transaction<'_>,
    report: Uuid,
) -> std::result::Result<(), tokio_postgres::Error> {
    let Some(row) = tx.query_opt("SELECT period_type,period_start,period_end,recipient_ids FROM report_run WHERE id=$1 AND status='ready'", &[&report]).await? else { return Ok(()) };
    let kind: String = row.get("period_type");
    let label = if kind == "weekly" { "周报" } else { "月报" };
    enqueue_with_context(
        tx,
        &format!("report.{kind}"),
        "warning",
        &format!("report:{report}"),
        &format!("{label}已生成"),
        &format!(
            "报告周期：{} 至 {}\n报告 ID：{report}\n请登录平台报告中心查看。",
            row.get::<_, DateTime<Utc>>("period_start"),
            row.get::<_, DateTime<Utc>>("period_end")
        ),
        None,
        json!({"report_id":report,"recipient_ids":row.get::<_,Vec<i32>>("recipient_ids")}),
    )
    .await
}

pub async fn test_send(
    pool: &Pool,
    id: Uuid,
    user: &UserBaseI,
    context: &AuditContext,
) -> Result<Uuid> {
    let mut conn = pool.get().await?;
    let tx = conn.transaction().await?;
    let channel = tx.query_opt("UPDATE notification_channel SET last_test_at=NOW() WHERE id=$1 AND deleted_at IS NULL AND enabled AND (last_test_at IS NULL OR last_test_at<NOW()-INTERVAL '30 seconds') RETURNING destination_revision", &[&id]).await?.ok_or_else(Error::conflict)?;
    let event = Uuid::now_v7();
    let delivery = Uuid::now_v7();
    tx.execute("INSERT INTO notification_event(id,dedup_key,event_type,severity,title,body) VALUES($1,$2,'notification.test','warning','通知渠道测试','管理员从 Web 控制台发起测试。')", &[&event,&format!("test:{event}")]).await?;
    tx.execute("INSERT INTO notification_delivery(id,event_id,channel_id,destination_revision) VALUES($1,$2,$3,$4)", &[&delivery,&event,&id,&channel.get::<_,i64>("destination_revision")]).await?;
    audit(&tx, user, context, "notification.test", id).await?;
    tx.commit().await?;
    Ok(delivery)
}

#[derive(Deserialize)]
pub struct DeliveryQuery {
    pub channel_id: Option<Uuid>,
    pub status: Option<String>,
    pub before: Option<Uuid>,
}
pub async fn deliveries(pool: &Pool, query: DeliveryQuery) -> Result<Value> {
    if query.status.as_ref().is_some_and(|v| {
        !["pending", "sending", "sent", "failed", "cancelled"].contains(&v.as_str())
    }) {
        return Err(Error::bad("投递状态无效"));
    }
    let conn = pool.get().await?;
    let rows = conn.query("SELECT d.id,d.channel_id,c.name,d.status,d.attempts,d.last_error,d.response_status,d.provider_code,d.created_at,d.finished_at,d.available_at,e.event_type,e.severity,e.title FROM notification_delivery d JOIN notification_channel c ON c.id=d.channel_id JOIN notification_event e ON e.id=d.event_id WHERE ($1::UUID IS NULL OR d.channel_id=$1) AND ($2::TEXT IS NULL OR d.status=$2) AND ($3::UUID IS NULL OR d.id<$3) ORDER BY d.id DESC LIMIT 51", &[&query.channel_id,&query.status,&query.before]).await?;
    let items: Vec<Value> = rows.iter().take(50).map(|row| json!({
        "id":row.get::<_,Uuid>("id"),"channel_id":row.get::<_,Uuid>("channel_id"),"channel_name":row.get::<_,String>("name"),
        "status":row.get::<_,String>("status"),"attempts":row.get::<_,i32>("attempts"),"last_error":row.get::<_,Option<String>>("last_error"),
        "response_status":row.get::<_,Option<i32>>("response_status"),"provider_code":row.get::<_,Option<i64>>("provider_code"),
        "created_at":row.get::<_,DateTime<Utc>>("created_at"),"finished_at":row.get::<_,Option<DateTime<Utc>>>("finished_at"),
        "available_at":row.get::<_,DateTime<Utc>>("available_at"),"event_type":row.get::<_,String>("event_type"),
        "severity":row.get::<_,String>("severity"),"title":row.get::<_,String>("title")
    })).collect();
    let next = if rows.len() > 50 {
        items.last().and_then(|v| v.get("id")).cloned()
    } else {
        None
    };
    Ok(json!({"items":items,"next_before":next}))
}

pub async fn retry(pool: &Pool, id: Uuid, user: &UserBaseI, context: &AuditContext) -> Result<()> {
    let mut conn = pool.get().await?;
    let tx = conn.transaction().await?;
    let changed = tx.execute("UPDATE notification_delivery d SET status='pending',attempts=0,available_at=NOW(),finished_at=NULL,last_error=NULL FROM notification_channel c,notification_event e WHERE d.id=$1 AND d.channel_id=c.id AND d.event_id=e.id AND d.status='failed' AND c.enabled AND c.deleted_at IS NULL AND c.destination_revision=d.destination_revision AND (e.event_type='notification.test' OR (e.event_type=ANY(c.event_types) AND (e.severity='critical' OR c.minimum_severity='warning'))) AND (e.event_type<>'scanner.offline' OR EXISTS(SELECT 1 FROM scanner_outage o JOIN scanner_info s ON s.scanner_id=o.scanner_id WHERE o.id=e.outage_id AND o.recovered_at IS NULL AND s.deleted_at IS NULL AND s.is_enable))", &[&id]).await?;
    if changed != 1 {
        return Err(Error::conflict());
    }
    audit(&tx, user, context, "notification.retry", id).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn delivery_detail(pool: &Pool, id: Uuid) -> Result<Value> {
    let conn = pool.get().await?;
    let row = conn.query_opt("SELECT d.id,d.channel_id,d.status,d.last_error,d.attempts,d.finished_at,e.title FROM notification_delivery d JOIN notification_event e ON e.id=d.event_id WHERE d.id=$1", &[&id]).await?.ok_or_else(Error::missing)?;
    Ok(
        json!({"id":row.get::<_,Uuid>("id"),"channel_id":row.get::<_,Uuid>("channel_id"),"status":row.get::<_,String>("status"),"last_error":row.get::<_,Option<String>>("last_error"),"attempts":row.get::<_,i32>("attempts"),"finished_at":row.get::<_,Option<DateTime<Utc>>>("finished_at"),"title":row.get::<_,String>("title")}),
    )
}
