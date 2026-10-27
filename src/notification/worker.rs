use super::*;
use crate::system_maintenance::SystemMaintenanceState;
use std::time::Duration;
use tokio::sync::watch;

pub async fn run(
    pool: Pool,
    key: String,
    maintenance: actix_web::web::Data<SystemMaintenanceState>,
    mut stopping: watch::Receiver<bool>,
) {
    let client = match feishu::client() {
        Ok(client) => client,
        Err(_) => {
            tracing::error!(
                event = "NotificationClientUnavailable",
                "通知 HTTP 客户端初始化失败"
            );
            return;
        }
    };
    let mut cleanup_at = std::time::Instant::now();
    loop {
        if *stopping.borrow() {
            return;
        }
        if !maintenance.snapshot().await.enabled {
            if reconcile_recoveries(&pool).await.is_err() {
                tracing::warn!(event = "NotificationRecoveryFailed", "通知恢复状态对账失败");
            }
            for _ in 0..32 {
                if *stopping.borrow() {
                    return;
                }
                if maintenance.snapshot().await.enabled {
                    break;
                }
                match deliver_one(&pool, &key, &client).await {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(_) => {
                        tracing::warn!(
                            event = "NotificationDeliveryWorkerFailed",
                            "通知投递处理失败，将在下一轮恢复"
                        );
                        break;
                    }
                }
            }
        }
        if std::time::Instant::now() >= cleanup_at {
            if let Ok(conn) = pool.get().await {
                // Keep active incidents and their successful offline receipts for later recovery.
                let _ = conn.execute("DELETE FROM notification_event e WHERE occurred_at<NOW()-INTERVAL '30 days' AND NOT EXISTS(SELECT 1 FROM notification_delivery d WHERE d.event_id=e.id AND d.status IN ('pending','sending')) AND (outage_id IS NULL OR EXISTS(SELECT 1 FROM scanner_outage o WHERE o.id=e.outage_id AND o.recovered_at<NOW()-INTERVAL '30 days'))", &[]).await;
                let _ = conn.execute("DELETE FROM notification_health_gate WHERE admitted_at<NOW()-INTERVAL '7 days'", &[]).await;
            }
            cleanup_at = std::time::Instant::now() + Duration::from_secs(3600);
        }
        tokio::select! {
            _=tokio::time::sleep(Duration::from_secs(1)) => {},
            _=stopping.changed()=>{},
        }
    }
}

pub(crate) async fn reconcile_recoveries(pool: &Pool) -> Result<()> {
    let mut conn = pool.get().await?;
    let tx = conn.transaction().await?;
    // Only non-key flags change here; permit FK references during a Web channel handoff.
    let rows = tx.query("SELECT o.id,o.scanner_id,o.recovered_at FROM scanner_outage o WHERE (o.notification_recovery OR o.recovery_requested) AND NOT o.notification_recovery_prepared AND o.recovered_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM notification_delivery d JOIN notification_event e ON e.id=d.event_id WHERE e.outage_id=o.id AND e.event_type='scanner.offline' AND d.status IN ('pending','sending')) ORDER BY o.id LIMIT 100 FOR NO KEY UPDATE OF o SKIP LOCKED", &[]).await?;
    for row in rows {
        let id: i64 = row.get("id");
        let scanner: String = row.get("scanner_id");
        let at: DateTime<Utc> = row.get("recovered_at");
        if at >= Utc::now() - chrono::Duration::hours(24) {
            enqueue(
                &tx,
                "scanner.recovered",
                "warning",
                &format!("outage:{id}:recovered"),
                "Scanner 恢复连接",
                &format!("扫描器：{scanner}\n恢复时间：{at}\n掉线事件：{id}"),
                Some(id),
            )
            .await?;
        }
        // Keep the preparation marker after retention removes the event/receipts.
        tx.execute(
            "UPDATE scanner_outage SET notification_recovery_prepared=TRUE WHERE id=$1",
            &[&id],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub(super) struct Claimed {
    pub(super) id: Uuid,
    pub(super) token: Uuid,
    pub(super) attempts: i32,
    url: Vec<u8>,
    secret: Option<Vec<u8>>,
    feishu_app_secret: Option<Vec<u8>>,
    provider: String,
    proxy_mode: ProxyMode,
    proxy_ciphertext: Option<Vec<u8>>,
    settings: ChannelSettings,
    title: String,
    event_type: String,
    context: Value,
    text: String,
    bot_context: tera::Context,
}

pub(super) enum ClaimOutcome {
    Empty,
    Processed,
    Ready(Box<Claimed>),
}

pub(super) async fn claim(pool: &Pool) -> Result<ClaimOutcome> {
    let mut conn = pool.get().await?;
    let tx = conn.transaction().await?;
    // Channel first: shares lock order with edits and enforces one send/second across replicas.
    let row = tx.query_opt("SELECT c.* FROM notification_channel c WHERE c.enabled AND c.deleted_at IS NULL AND c.next_send_at<=NOW() AND EXISTS(SELECT 1 FROM notification_delivery d WHERE d.channel_id=c.id AND ((d.status='pending' AND d.available_at<=NOW()) OR (d.status='sending' AND d.lease_until<NOW()))) ORDER BY c.next_send_at,c.id LIMIT 1 FOR UPDATE OF c SKIP LOCKED", &[]).await?;
    let Some(channel) = row else {
        return Ok(ClaimOutcome::Empty);
    };
    let cid: Uuid = channel.get("id");
    let row = tx.query_opt("SELECT d.*,e.event_type,e.severity,e.title,e.body,e.outage_id,e.occurred_at,e.context FROM notification_delivery d JOIN notification_event e ON e.id=d.event_id WHERE d.channel_id=$1 AND ((d.status='pending' AND d.available_at<=NOW()) OR (d.status='sending' AND d.lease_until<NOW())) ORDER BY d.available_at,d.id LIMIT 1 FOR UPDATE OF d SKIP LOCKED", &[&cid]).await?;
    let Some(row) = row else {
        return Ok(ClaimOutcome::Empty);
    };
    let id: Uuid = row.get("id");
    let kind: String = row.get("event_type");
    let severity: String = row.get("severity");
    let attempts: i32 = row.get("attempts");
    let manual_report =
        kind.starts_with("report.") && row.get::<_, Value>("context")["manual_report"] == true;
    let subscribed = manual_report
        || channel.get::<_, Vec<String>>("event_types").contains(&kind)
            && (severity == "critical"
                || channel.get::<_, String>("minimum_severity") == "warning");
    let mut permitted = row.get::<_, i64>("destination_revision")
        == channel.get::<_, i64>("destination_revision")
        && (kind == "notification.test" || subscribed);
    if let Some(outage) = row.get::<_, Option<i64>>("outage_id") {
        permitted &= tx.query_opt("SELECT o.recovered_at,s.is_enable,s.deleted_at,o.notification_recovery,o.recovery_requested FROM scanner_outage o JOIN scanner_info s ON s.scanner_id=o.scanner_id WHERE o.id=$1", &[&outage]).await?.is_some_and(|o| {
            o.get::<_,bool>("is_enable") && o.get::<_,Option<DateTime<Utc>>>("deleted_at").is_none()
                && if kind=="scanner.offline" { o.get::<_,Option<DateTime<Utc>>>("recovered_at").is_none() } else { o.get::<_,bool>("notification_recovery") || o.get::<_,bool>("recovery_requested") }
        });
    }
    let expired =
        row.get::<_, DateTime<Utc>>("occurred_at") < Utc::now() - chrono::Duration::hours(24);
    if !permitted || expired || attempts >= 5 {
        let status = if attempts >= 5 { "failed" } else { "cancelled" };
        let reason = if !permitted {
            "channel_or_incident_changed"
        } else if expired {
            "event_expired"
        } else {
            "attempts_exhausted"
        };
        tx.execute("UPDATE notification_delivery SET status=$2,last_error=$3,finished_at=NOW(),claim_token=NULL,lease_until=NULL WHERE id=$1", &[&id,&status,&reason]).await?;
        tx.commit().await?;
        // Cleanup is progress: continue the bounded batch without using a send slot.
        return Ok(ClaimOutcome::Processed);
    }
    let token = Uuid::new_v4();
    tx.execute("UPDATE notification_delivery SET status='sending',attempts=attempts+1,claim_token=$2,lease_until=NOW()+INTERVAL '60 seconds' WHERE id=$1", &[&id,&token]).await?;
    tx.execute(
        "UPDATE notification_channel SET next_send_at=NOW()+INTERVAL '1 second' WHERE id=$1",
        &[&cid],
    )
    .await?;
    let title: String = row.get("title");
    let body: String = row.get("body");
    let event: Uuid = row.get("event_id");
    let short_title: String = title.chars().take(120).collect();
    let short_body: String = body.chars().take(1400).collect();
    let text = format!(
        "[Network Mapping] {short_title}\n级别：{severity}\n{short_body}\n事件 ID：{event}"
    );
    let mut context: Value = row.get("context");
    if let Some(outage) = row.get::<_, Option<i64>>("outage_id") {
        context["outage_id"] = json!(outage);
        context["event_type"] = json!(kind);
    }
    let result = Claimed {
        id,
        token,
        attempts: attempts + 1,
        url: channel.get("webhook_ciphertext"),
        secret: channel.get("secret_ciphertext"),
        feishu_app_secret: channel.get("feishu_app_secret_ciphertext"),
        provider: channel.get("provider"),
        proxy_mode: channel
            .get::<_, String>("proxy_mode")
            .parse()
            .map_err(|_| Error::internal())?,
        proxy_ciphertext: channel.get("proxy_ciphertext"),
        settings: serde_json::from_value(channel.get("settings")).map_err(|_| Error::internal())?,
        title,
        event_type: kind.clone(),
        context,
        bot_context: templates::context(
            &kind,
            &short_title,
            &short_body,
            &severity,
            &event.to_string(),
            &row.get::<_, DateTime<Utc>>("occurred_at").to_rfc3339(),
        ),
        text,
    };
    tx.commit().await?;
    Ok(ClaimOutcome::Ready(Box::new(result)))
}

pub(crate) async fn deliver_one(pool: &Pool, key: &str, client: &reqwest::Client) -> Result<bool> {
    let claimed = match claim(pool).await? {
        ClaimOutcome::Empty => return Ok(false),
        ClaimOutcome::Processed => return Ok(true),
        ClaimOutcome::Ready(claimed) => claimed,
    };
    let secret = claimed
        .secret
        .as_ref()
        .map(|bytes| decrypt(bytes, key))
        .transpose();
    let outcome = match secret {
        Ok(secret) => tokio::time::timeout(Duration::from_secs(20), async {
            let proxy =
                match decrypted_proxy(claimed.proxy_mode, claimed.proxy_ciphertext.as_deref(), key)
                {
                    Ok(proxy) => proxy,
                    Err(_) => return Ok(Outcome::failure("secret_unavailable", false)),
                };
            let delivery_client =
                if claimed.proxy_mode == ProxyMode::System || claimed.provider == "email" {
                    client.clone()
                } else {
                    match proxy.http_client() {
                        Ok(client) => client,
                        Err(e) => return Ok(Outcome::failure(e.code, e.retryable)),
                    }
                };
            let outcome = match claimed.provider.as_str() {
                "feishu" | "telegram" => {
                    match templates::delivery_payload(
                        pool,
                        &claimed.provider,
                        &claimed.event_type,
                        &claimed.context,
                        &claimed.bot_context,
                    )
                    .await
                    {
                        Err(outcome) => outcome,
                        Ok(mut payload) => {
                            let wants_image = claimed.context["report_id"].is_string()
                                && ((claimed.provider == "telegram"
                                    && payload.get("rich_message").is_some())
                                    || (claimed.provider == "feishu"
                                        && claimed.feishu_app_secret.is_some()));
                            let image = if wants_image {
                                match report_image(pool, &claimed.context).await {
                                    Ok(image) => Some(image),
                                    Err(outcome) => return Ok(outcome),
                                }
                            } else {
                                None
                            };
                            if claimed.provider == "feishu" {
                                if let Some(image) = image {
                                    let app_secret = match claimed
                                        .feishu_app_secret
                                        .as_deref()
                                        .map(|v| decrypt(v, key))
                                        .transpose()
                                    {
                                        Ok(Some(secret)) => secret,
                                        _ => {
                                            return Ok(Outcome::failure(
                                                "secret_unavailable",
                                                false,
                                            ));
                                        }
                                    };
                                    let image_key = match feishu::upload_report_image(
                                        &delivery_client,
                                        &claimed.settings.feishu_app_id,
                                        &app_secret,
                                        image,
                                    )
                                    .await
                                    {
                                        Ok(image_key) => image_key,
                                        Err(outcome) => return Ok(outcome),
                                    };
                                    payload = match feishu::attach_report_image(payload, &image_key)
                                    {
                                        Ok(payload) => payload,
                                        Err(outcome) => return Ok(outcome),
                                    };
                                }
                                match decrypt(&claimed.url, key) {
                                    Ok(url) => {
                                        feishu::send_payload(
                                            &delivery_client,
                                            &url,
                                            secret.as_deref(),
                                            payload,
                                        )
                                        .await
                                    }
                                    Err(_) => Outcome::failure("secret_unavailable", false),
                                }
                            } else {
                                if let Some(image) = image {
                                    return Ok(telegram::send_report_image(
                                        &delivery_client,
                                        secret.as_deref().unwrap_or_default(),
                                        &claimed.settings.chat_id,
                                        payload,
                                        image,
                                    )
                                    .await);
                                }
                                telegram::send_payload(
                                    &delivery_client,
                                    secret.as_deref().unwrap_or_default(),
                                    &claimed.settings.chat_id,
                                    payload,
                                )
                                .await
                            }
                        }
                    }
                }

                "email" => {
                    let recipients = email_recipients(pool, &claimed).await?;
                    match email::render(pool, &claimed.context).await {
                        Ok(rendered) => {
                            email::send(
                                &proxy,
                                &claimed.settings,
                                secret.as_deref().unwrap_or_default(),
                                &recipients,
                                &claimed.title,
                                &claimed.text,
                                rendered.as_ref(),
                            )
                            .await
                        }
                        Err(outcome) => outcome,
                    }
                }
                _ => Outcome::failure("invalid_destination", false),
            };
            Ok::<_, Error>(outcome)
        })
        .await
        .unwrap_or_else(|_| Ok(Outcome::failure("delivery_timeout", true)))?,
        Err(_) => Outcome::failure("secret_unavailable", false),
    };
    complete(pool, claimed.id, claimed.token, claimed.attempts, outcome).await?;
    Ok(true)
}

pub(super) async fn report_image(
    pool: &Pool,
    context: &Value,
) -> std::result::Result<Vec<u8>, Outcome> {
    let id = context["report_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| Outcome::failure("invalid_payload", false))?;
    let conn = pool
        .get()
        .await
        .map_err(|_| Outcome::failure("notification_source_unavailable", true))?;
    let row = conn
        .query_opt(
            "SELECT payload FROM report_run WHERE id=$1 AND status='ready'",
            &[&id],
        )
        .await
        .map_err(|_| Outcome::failure("notification_source_unavailable", true))?
        .ok_or_else(|| Outcome::failure("report_unavailable", false))?;
    let payload: Option<Value> = row.get("payload");
    drop(conn);
    let trend = serde_json::from_value(payload.unwrap_or(Value::Null)["trend"].clone())
        .map_err(|_| Outcome::failure("report_image_invalid", false))?;
    crate::reports::chart::render_async_checked(trend)
        .await
        .map_err(|error| Outcome::failure("report_image_invalid", error.is_retryable()))
}

pub(super) async fn email_recipients(pool: &Pool, claimed: &Claimed) -> Result<Vec<String>> {
    if let Some(recipient) = claimed.context["legacy_recipient"].as_str() {
        // A transferred per-recipient job must never expand to the current administrator list.
        // Revalidate the original recipient just as the legacy queue did before sending.
        let report = claimed.event_type.starts_with("report.");
        let user = claimed.context["legacy_recipient_user_id"]
            .as_i64()
            .and_then(|id| i32::try_from(id).ok());
        let active: bool = pool.get().await?.query_one("SELECT EXISTS(SELECT 1 FROM users WHERE role=1 AND disabled_at IS NULL AND deleted_at IS NULL AND lower(trim(email))=lower(trim($1)) AND (NOT $2 OR (id=$3 AND NOT limit_login)))", &[&recipient,&report,&user]).await?.get(0);
        return Ok(if active {
            vec![recipient.to_owned()]
        } else {
            Vec::new()
        });
    }
    let mut recipients = if claimed.settings.recipients.is_empty() {
        default_recipients(pool, &claimed.event_type, &claimed.context).await?
    } else {
        claimed.settings.recipients.clone()
    };
    if claimed.event_type == "scanner.recovered" {
        // Legacy SMTP had one receipt per address. Preserve that boundary when only some
        // recipients received the offline mail; newly added admins must not get its recovery.
        let receipts = pool.get().await?.query("SELECT e.context->>'legacy_recipient' AS recipient FROM notification_delivery recovery JOIN notification_delivery offline ON offline.channel_id=recovery.channel_id AND offline.destination_revision=recovery.destination_revision AND offline.status='sent' JOIN notification_event e ON e.id=offline.event_id WHERE recovery.id=$1 AND e.outage_id=$2 AND e.event_type='scanner.offline'", &[&claimed.id,&claimed.context["outage_id"].as_i64()]).await?;
        let legacy: Option<Vec<String>> = receipts.iter().map(|r| r.get("recipient")).collect();
        if let Some(legacy) = legacy {
            recipients.retain(|recipient| {
                legacy
                    .iter()
                    .any(|sent| sent.trim().eq_ignore_ascii_case(recipient.trim()))
            });
        }
    }
    Ok(recipients)
}

async fn default_recipients(pool: &Pool, event_type: &str, context: &Value) -> Result<Vec<String>> {
    if event_type == "user.login" {
        let Some(id) = context["user_id"]
            .as_i64()
            .and_then(|id| i32::try_from(id).ok())
        else {
            return Ok(Vec::new());
        };
        return crate::mail_template::get_user_notification_recipient(pool, id)
            .await
            .map(|recipient| recipient.into_iter().collect())
            .map_err(|_| Error::internal());
    }
    if event_type.starts_with("report.") {
        let selected: Vec<i32> = context["recipient_ids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_i64().and_then(|v| i32::try_from(v).ok()))
            .collect();
        return crate::reports::storage::recipients(&pool.get().await?, &selected)
            .await
            .map(|recipients| recipients.into_iter().map(|(_, email)| email).collect())
            .map_err(|_| Error::internal());
    }
    crate::mail_template::get_admin_recipients(pool)
        .await
        .map_err(|_| Error::internal())
}

pub(crate) async fn complete(
    pool: &Pool,
    id: Uuid,
    token: Uuid,
    attempts: i32,
    outcome: Outcome,
) -> Result<()> {
    let retry = !outcome.sent && outcome.retryable && attempts < 5;
    let status = if outcome.sent {
        "sent"
    } else if retry {
        "pending"
    } else {
        "failed"
    };
    let delay = (30_i64 * (1_i64 << attempts.clamp(0, 4))).max(outcome.retry_after);
    let updated = pool.get().await?.execute("UPDATE notification_delivery SET status=$3,last_error=CASE WHEN $3='sent' THEN NULL ELSE $4 END,response_status=$5,provider_code=$6,available_at=NOW()+$7::BIGINT*INTERVAL '1 second',finished_at=CASE WHEN $3='pending' THEN NULL ELSE NOW() END,claim_token=NULL,lease_until=NULL WHERE id=$1 AND claim_token=$2 AND status='sending' AND lease_until>clock_timestamp()", &[&id,&token,&status,&outcome.reason,&outcome.http,&outcome.code,&delay]).await?;
    tracing::info!(event="NotificationDeliveryFinished",delivery_id=%id,status,attempts,reason=outcome.reason,applied=updated==1,"通知投递尝试完成");
    Ok(())
}
