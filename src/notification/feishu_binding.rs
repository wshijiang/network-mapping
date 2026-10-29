//! Feishu application-bot binding primitives.
//!
//! Binding codes are bearer credentials: never include them in logs, errors,
//! debug output, or persistent storage.
use deadpool_postgres::Pool;
use openssl::{hash::MessageDigest, pkey::PKey, rand::rand_bytes, sign::Signer};
use serde_json::Value;
use uuid::Uuid;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A uniformly distributed 30-bit Crockford Base32 code.
pub(super) fn generate_code() -> Result<String, openssl::error::ErrorStack> {
    let mut random = [0_u8; 4];
    rand_bytes(&mut random)?;
    let mut value = u32::from_be_bytes(random) & 0x3fff_ffff;
    let mut output = [0_u8; 6];
    for symbol in output.iter_mut().rev() {
        *symbol = ALPHABET[(value & 31) as usize];
        value >>= 5;
    }
    // ALPHABET is constant ASCII.
    Ok(output.iter().map(|byte| char::from(*byte)).collect())
}

/// Derive a private lookup value scoped to an application.
pub(super) fn code_digest(
    encryption_key: &str,
    app_id: &str,
    code: &str,
) -> super::Result<Vec<u8>> {
    let key =
        openssl::base64::decode_block(encryption_key).map_err(|_| super::Error::internal())?;
    if key.len() != 32 {
        return Err(super::Error::internal());
    }
    let key = PKey::hmac(&key).map_err(|_| super::Error::internal())?;
    let mut signer =
        Signer::new(MessageDigest::sha256(), &key).map_err(|_| super::Error::internal())?;
    signer
        .update(b"network-mapping/feishu-binding/v1\0")
        .map_err(|_| super::Error::internal())?;
    signer
        .update(&(app_id.len() as u64).to_be_bytes())
        .map_err(|_| super::Error::internal())?;
    signer
        .update(app_id.as_bytes())
        .map_err(|_| super::Error::internal())?;
    signer
        .update(code.as_bytes())
        .map_err(|_| super::Error::internal())?;
    signer.sign_to_vec().map_err(|_| super::Error::internal())
}

/// Extract only exact, single-line commands from Feishu plain-text payloads.
pub(super) fn parse_command(content: &str) -> Option<String> {
    if content.len() > 1024 {
        return None;
    }
    let value: Value = serde_json::from_str(content).ok()?;
    let text = value.get("text")?.as_str()?.trim();
    let (command, code) = text.split_once(' ')?;
    if command != "/bind" || code.len() != 6 || !code.is_ascii() {
        return None;
    }
    let code = code.to_ascii_uppercase();
    code.bytes()
        .all(|byte| ALPHABET.contains(&byte))
        .then_some(code)
}

#[derive(serde::Serialize)]
pub(super) struct IssuedBinding {
    pub code: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

pub(super) async fn status(pool: &Pool, channel_id: Uuid) -> super::Result<Value> {
    let client = pool.get().await?;
    let channel = client.query_opt("SELECT settings FROM notification_channel WHERE id=$1 AND provider='feishu' AND deleted_at IS NULL", &[&channel_id]).await?.ok_or_else(super::Error::missing)?;
    let settings: super::ChannelSettings =
        serde_json::from_value(channel.get("settings")).map_err(|_| super::Error::internal())?;
    if !settings.feishu_application() {
        return Err(super::Error::bad("仅飞书应用机器人支持绑定"));
    }
    let request = client.query_opt("SELECT CASE WHEN status='pending' AND expires_at<=NOW() THEN 'expired' ELSE status END AS status,expires_at FROM feishu_binding_request WHERE channel_id=$1 ORDER BY created_at DESC LIMIT 1", &[&channel_id]).await?;
    let connection = client
        .query_opt(
            "SELECT CASE WHEN state='conflict' THEN state WHEN lease_until>NOW() THEN state ELSE 'disconnected' END AS state FROM feishu_binding_connection WHERE app_id=$1",
            &[&settings.feishu_app_id],
        )
        .await?;
    let bound = settings.feishu_target() == super::FeishuTargetType::User
        && !settings.feishu_open_id.is_empty();
    let binding_status = request
        .as_ref()
        .map(|r| r.get::<_, String>("status"))
        .map(|s| {
            if s == "bound" && !bound {
                "unbound".into()
            } else {
                s
            }
        })
        .unwrap_or_else(|| {
            if bound {
                "bound".into()
            } else {
                "unbound".into()
            }
        });
    Ok(serde_json::json!({
        "binding_status": binding_status,
        "expires_at": request.as_ref().map(|r| r.get::<_,chrono::DateTime<chrono::Utc>>("expires_at")),
        "connection_status": connection.as_ref().map(|r| r.get::<_,String>("state")).unwrap_or_else(|| "disconnected".into()),
    }))
}

pub(super) async fn cancel(
    pool: &Pool,
    channel_id: Uuid,
    user: &crate::admin::UserBaseI,
    context: &crate::audit::AuditContext,
) -> super::Result<()> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let row = tx.query_opt("SELECT settings FROM notification_channel WHERE id=$1 AND provider='feishu' AND deleted_at IS NULL", &[&channel_id]).await?.ok_or_else(super::Error::missing)?;
    let settings: super::ChannelSettings =
        serde_json::from_value(row.get("settings")).map_err(|_| super::Error::internal())?;
    if !settings.feishu_application() {
        return Err(super::Error::bad("仅飞书应用机器人支持绑定"));
    }
    tx.query_one(
        "SELECT pg_advisory_xact_lock(728105, hashtext($1))",
        &[&settings.feishu_app_id],
    )
    .await?;
    tx.execute("UPDATE feishu_binding_request SET status='cancelled',completed_at=NOW() WHERE channel_id=$1 AND status='pending'", &[&channel_id]).await?;
    super::audit(
        &tx,
        user,
        context,
        "notification.feishu_binding_cancel",
        channel_id,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Remove an existing personal recipient and stop delivery until rebound.
pub(super) async fn unbind(
    pool: &Pool,
    channel_id: Uuid,
    expected_revision: i64,
    user: &crate::admin::UserBaseI,
    context: &crate::audit::AuditContext,
) -> super::Result<()> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let row = tx.query_opt("SELECT revision,settings FROM notification_channel WHERE id=$1 AND provider='feishu' AND deleted_at IS NULL FOR UPDATE", &[&channel_id]).await?.ok_or_else(super::Error::missing)?;
    if row.get::<_, i64>("revision") != expected_revision {
        return Err(super::Error::conflict());
    }
    let mut settings: super::ChannelSettings =
        serde_json::from_value(row.get("settings")).map_err(|_| super::Error::internal())?;
    if !settings.feishu_application()
        || settings.feishu_target() != super::FeishuTargetType::User
        || settings.feishu_open_id.is_empty()
    {
        return Err(super::Error::bad("该渠道没有绑定个人接收者"));
    }
    settings.feishu_open_id.clear();
    let settings = serde_json::to_value(settings).map_err(|_| super::Error::internal())?;
    tx.execute("UPDATE notification_channel SET settings=$2,enabled=false,revision=revision+1,destination_revision=destination_revision+1,updated_at=NOW() WHERE id=$1", &[&channel_id,&settings]).await?;
    tx.execute("UPDATE notification_delivery SET status='cancelled',last_error='channel_changed',finished_at=NOW(),claim_token=NULL,lease_until=NULL WHERE channel_id=$1 AND status IN ('pending','sending')", &[&channel_id]).await?;
    tx.execute("UPDATE feishu_binding_request SET status='cancelled',completed_at=NOW() WHERE channel_id=$1 AND status='pending'", &[&channel_id]).await?;
    super::audit(
        &tx,
        user,
        context,
        "notification.feishu_binding_remove",
        channel_id,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Issue a one-time code. The channel revision binds the request to the
/// configuration seen by the administrator at issuance time.
pub(super) async fn issue(
    pool: &Pool,
    key: &str,
    channel_id: Uuid,
    expected_revision: i64,
    user: &crate::admin::UserBaseI,
    context: &crate::audit::AuditContext,
) -> super::Result<IssuedBinding> {
    let mut connection = pool.get().await?;
    let tx = connection.transaction().await?;
    let row = tx.query_opt("SELECT settings FROM notification_channel WHERE id=$1 AND provider='feishu' AND deleted_at IS NULL", &[&channel_id]).await?.ok_or_else(super::Error::missing)?;
    let settings: super::ChannelSettings =
        serde_json::from_value(row.get("settings")).map_err(|_| super::Error::internal())?;
    if !settings.feishu_application() || settings.feishu_app_id.is_empty() {
        return Err(super::Error::bad("仅飞书应用机器人支持绑定"));
    }
    let app_id = settings.feishu_app_id;
    tx.query_one(
        "SELECT pg_advisory_xact_lock(728105, hashtext($1))",
        &[&app_id],
    )
    .await?;
    let row = tx.query_opt("SELECT revision,settings,feishu_app_secret_ciphertext IS NOT NULL AS configured FROM notification_channel WHERE id=$1 AND provider='feishu' AND deleted_at IS NULL FOR UPDATE", &[&channel_id]).await?.ok_or_else(super::Error::missing)?;
    let current: super::ChannelSettings =
        serde_json::from_value(row.get("settings")).map_err(|_| super::Error::internal())?;
    if row.get::<_, i64>("revision") != expected_revision || current.feishu_app_id != app_id {
        return Err(super::Error::conflict());
    }
    if !current.feishu_application() || !row.get::<_, bool>("configured") {
        return Err(super::Error::bad("请先配置飞书应用凭据"));
    }
    let recent: i64 = tx.query_one("SELECT COUNT(*) FROM feishu_binding_request WHERE channel_id=$1 AND created_at > NOW()-INTERVAL '5 minutes'", &[&channel_id]).await?.get(0);
    if recent >= 10 {
        return Err(super::Error::bad("绑定码生成过于频繁，请稍后重试"));
    }
    tx.execute("UPDATE feishu_binding_request SET status='expired',completed_at=NOW() WHERE app_id=$1 AND status='pending' AND expires_at<=NOW()", &[&app_id]).await?;
    tx.execute("UPDATE feishu_binding_request SET status='cancelled',completed_at=NOW() WHERE channel_id=$1 AND status='pending'", &[&channel_id]).await?;
    let mut selected = None;
    for _ in 0..8 {
        let code = generate_code().map_err(|_| super::Error::internal())?;
        let digest = code_digest(key, &app_id, &code)?;
        let exists: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM feishu_binding_request WHERE app_id=$1 AND code_digest=$2 AND status='pending')", &[&app_id,&digest]).await?.get(0);
        if !exists {
            selected = Some((code, digest));
            break;
        }
    }
    let (code, digest) = selected.ok_or_else(super::Error::internal)?;
    let id = Uuid::now_v7();
    let expires_at = tx.query_one("INSERT INTO feishu_binding_request(id,channel_id,app_id,code_digest,channel_revision,created_by,status,expires_at) VALUES($1,$2,$3,$4,$5,$6,'pending',NOW()+INTERVAL '10 minutes') RETURNING expires_at", &[&id,&channel_id,&app_id,&digest,&expected_revision,&user.id]).await?.get(0);
    super::audit(
        &tx,
        user,
        context,
        "notification.feishu_binding_issue",
        channel_id,
    )
    .await?;
    tx.commit().await?;
    Ok(IssuedBinding { code, expires_at })
}

/// Persist event consumption and destination changes before acknowledging the
/// event. A valid lease fences an instance that lost connection ownership.
pub(super) async fn consume(
    pool: &Pool,
    key: &str,
    app_id: &str,
    lease: (Uuid, i64),
    event_id: &str,
    open_id: &str,
    code: &str,
) -> super::Result<()> {
    let (owner, generation) = lease;
    if event_id.is_empty()
        || event_id.len() > 256
        || !open_id.starts_with("ou_")
        || open_id.len() <= 3
        || open_id.len() > 128
        || open_id.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Ok(());
    }
    let digest = code_digest(key, app_id, code)?;
    let sender_digest = code_digest(key, app_id, &format!("sender:{open_id}"))?;
    let mut connection = pool.get().await?;
    let tx = connection.transaction().await?;
    tx.query_one(
        "SELECT pg_advisory_xact_lock(728105, hashtext($1))",
        &[&app_id],
    )
    .await?;
    let lease = tx.query_opt("SELECT app_id FROM feishu_binding_connection WHERE app_id=$1 AND owner=$2 AND generation=$3 AND lease_until>clock_timestamp() FOR UPDATE", &[&app_id,&owner,&generation]).await?;
    if lease.is_none() {
        return Err(super::Error::conflict());
    }
    let inserted = tx.execute("INSERT INTO feishu_binding_event(app_id,event_id) VALUES($1,$2) ON CONFLICT DO NOTHING", &[&app_id,&event_id]).await?;
    if inserted == 0 {
        tx.commit().await?;
        return Ok(());
    }
    for (subject, maximum) in [
        (b"app".as_slice(), 30_i32),
        (sender_digest.as_slice(), 5_i32),
    ] {
        let attempts: i32 = tx.query_one("INSERT INTO feishu_binding_rate(app_id,subject,window_start,attempts) VALUES($1,$2,NOW(),1) ON CONFLICT(app_id,subject) DO UPDATE SET attempts=CASE WHEN feishu_binding_rate.window_start<NOW()-INTERVAL '1 minute' THEN 1 ELSE feishu_binding_rate.attempts+1 END, window_start=CASE WHEN feishu_binding_rate.window_start<NOW()-INTERVAL '1 minute' THEN NOW() ELSE feishu_binding_rate.window_start END RETURNING attempts", &[&app_id,&subject]).await?.get(0);
        if attempts > maximum {
            tx.commit().await?;
            return Ok(());
        }
    }
    let Some(request) = tx.query_opt("SELECT id,channel_id,channel_revision FROM feishu_binding_request WHERE app_id=$1 AND code_digest=$2 AND status='pending' AND expires_at>NOW()", &[&app_id,&digest]).await? else {
        tx.commit().await?;
        return Ok(());
    };
    let request_id: Uuid = request.get("id");
    let channel_id: Uuid = request.get("channel_id");
    let revision: i64 = request.get("channel_revision");
    let Some(channel) = tx.query_opt("SELECT revision,settings FROM notification_channel WHERE id=$1 AND provider='feishu' AND deleted_at IS NULL FOR UPDATE", &[&channel_id]).await? else {
        tx.execute("UPDATE feishu_binding_request SET status='cancelled',completed_at=NOW() WHERE id=$1", &[&request_id]).await?;
        tx.commit().await?;
        return Ok(());
    };
    // Channel edits lock the channel before cancelling its pending request.
    // Take locks in the same order, then recheck the request under its lock.
    if tx.query_opt("SELECT id FROM feishu_binding_request WHERE id=$1 AND status='pending' AND expires_at>NOW() FOR UPDATE", &[&request_id]).await?.is_none() {
        tx.commit().await?;
        return Ok(());
    }
    let mut settings: super::ChannelSettings =
        serde_json::from_value(channel.get("settings")).map_err(|_| super::Error::internal())?;
    if channel.get::<_, i64>("revision") != revision
        || !settings.feishu_application()
        || settings.feishu_app_id != app_id
    {
        tx.execute(
            "UPDATE feishu_binding_request SET status='cancelled',completed_at=NOW() WHERE id=$1",
            &[&request_id],
        )
        .await?;
        tx.commit().await?;
        return Ok(());
    }
    settings.feishu_target_type = Some(super::FeishuTargetType::User);
    settings.feishu_open_id = open_id.to_owned();
    settings.feishu_chat_id.clear();
    let settings = serde_json::to_value(settings).map_err(|_| super::Error::internal())?;
    tx.execute("UPDATE notification_channel SET settings=$2,revision=revision+1,destination_revision=destination_revision+1,updated_at=NOW() WHERE id=$1", &[&channel_id,&settings]).await?;
    tx.execute("UPDATE notification_delivery SET status='cancelled',last_error='channel_changed',finished_at=NOW(),claim_token=NULL,lease_until=NULL WHERE channel_id=$1 AND status IN ('pending','sending')", &[&channel_id]).await?;
    tx.execute(
        "UPDATE feishu_binding_request SET status='bound',completed_at=NOW() WHERE id=$1",
        &[&request_id],
    )
    .await?;
    let reply_id = Uuid::now_v7();
    tx.execute(
        "INSERT INTO feishu_binding_reply(id,app_id,channel_id,target_open_id) VALUES($1,$2,$3,$4)",
        &[&reply_id, &app_id, &channel_id, &open_id],
    )
    .await?;
    let event = crate::audit::AuditEvent::system(
        "configuration",
        "notification.feishu_binding_complete",
        "success",
    )
    .resource("notification", channel_id.to_string());
    crate::audit::write(
        &tx,
        &crate::audit::AuditContext::cli("feishu-binding"),
        &event,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_are_six_unambiguous_base32_symbols() {
        for _ in 0..256 {
            let code = generate_code().unwrap();
            assert_eq!(code.len(), 6);
            assert!(code.bytes().all(|byte| ALPHABET.contains(&byte)));
        }
    }

    #[test]
    fn accepts_only_single_private_binding_commands() {
        assert_eq!(
            parse_command(r#"{"text":"/bind abc123"}"#).as_deref(),
            Some("ABC123")
        );
        for invalid in [
            r#"{"text":"/bind ABC12I"}"#,
            r#"{"text":"/bind ABC123 extra"}"#,
            r#"{"text":"/bind ABC123\nhello"}"#,
            r#"{"text":"prefix /bind ABC123"}"#,
            r#"{"text":"/bind ABC12"}"#,
            r#"{"text":"/bind  ABC123"}"#,
        ] {
            assert!(parse_command(invalid).is_none());
        }
    }

    #[test]
    fn digest_is_secret_and_application_scoped() {
        let key = openssl::base64::encode_block(&[7; 32]);
        let digest = code_digest(&key, "cli_a", "ABC123").unwrap();
        assert_ne!(digest, code_digest(&key, "cli_b", "ABC123").unwrap());
        assert_ne!(digest, code_digest(&key, "cli_a", "ABC124").unwrap());
        assert_ne!(digest, b"ABC123");
    }
}
