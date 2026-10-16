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
    let rows = tx.query("SELECT o.id,o.scanner_id,o.recovered_at FROM scanner_outage o WHERE o.notification_recovery AND NOT o.notification_recovery_prepared AND o.recovered_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM notification_delivery d JOIN notification_event e ON e.id=d.event_id WHERE e.outage_id=o.id AND e.event_type='scanner.offline' AND d.status IN ('pending','sending')) ORDER BY o.id LIMIT 100 FOR UPDATE OF o SKIP LOCKED", &[]).await?;
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
    text: String,
}

pub(super) enum ClaimOutcome {
    Empty,
    Processed,
    Ready(Claimed),
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
    let row = tx.query_opt("SELECT d.*,e.event_type,e.severity,e.title,e.body,e.outage_id,e.occurred_at FROM notification_delivery d JOIN notification_event e ON e.id=d.event_id WHERE d.channel_id=$1 AND ((d.status='pending' AND d.available_at<=NOW()) OR (d.status='sending' AND d.lease_until<NOW())) ORDER BY d.available_at,d.id LIMIT 1 FOR UPDATE OF d SKIP LOCKED", &[&cid]).await?;
    let Some(row) = row else {
        return Ok(ClaimOutcome::Empty);
    };
    let id: Uuid = row.get("id");
    let kind: String = row.get("event_type");
    let severity: String = row.get("severity");
    let attempts: i32 = row.get("attempts");
    let subscribed = channel.get::<_, Vec<String>>("event_types").contains(&kind)
        && (severity == "critical" || channel.get::<_, String>("minimum_severity") == "warning");
    let mut permitted = row.get::<_, i64>("destination_revision")
        == channel.get::<_, i64>("destination_revision")
        && (kind == "notification.test" || subscribed);
    if let Some(outage) = row.get::<_, Option<i64>>("outage_id") {
        permitted &= tx.query_opt("SELECT o.recovered_at,s.is_enable,s.deleted_at,o.notification_recovery FROM scanner_outage o JOIN scanner_info s ON s.scanner_id=o.scanner_id WHERE o.id=$1", &[&outage]).await?.is_some_and(|o| {
            o.get::<_,bool>("is_enable") && o.get::<_,Option<DateTime<Utc>>>("deleted_at").is_none()
                && if kind=="scanner.offline" { o.get::<_,Option<DateTime<Utc>>>("recovered_at").is_none() } else { o.get::<_,bool>("notification_recovery") }
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
    let text = format!("[Network Mapping] {title}\n级别：{severity}\n{body}\n事件 ID：{event}");
    let result = Claimed {
        id,
        token,
        attempts: attempts + 1,
        url: channel.get("webhook_ciphertext"),
        secret: channel.get("secret_ciphertext"),
        text,
    };
    tx.commit().await?;
    Ok(ClaimOutcome::Ready(result))
}

pub(crate) async fn deliver_one(pool: &Pool, key: &str, client: &reqwest::Client) -> Result<bool> {
    let claimed = match claim(pool).await? {
        ClaimOutcome::Empty => return Ok(false),
        ClaimOutcome::Processed => return Ok(true),
        ClaimOutcome::Ready(claimed) => claimed,
    };
    let secrets = decrypt(&claimed.url, key).and_then(|url| {
        let secret = claimed
            .secret
            .as_ref()
            .map(|bytes| decrypt(bytes, key))
            .transpose()?;
        Ok((url, secret))
    });
    let outcome = match secrets {
        Ok((url, secret)) => tokio::time::timeout(
            Duration::from_secs(20),
            feishu::send(client, &url, secret.as_deref(), &claimed.text),
        )
        .await
        .unwrap_or_else(|_| feishu::Outcome::failure("delivery_timeout", true)),
        Err(_) => feishu::Outcome::failure("secret_unavailable", false),
    };
    complete(pool, claimed.id, claimed.token, claimed.attempts, outcome).await?;
    Ok(true)
}

pub(crate) async fn complete(
    pool: &Pool,
    id: Uuid,
    token: Uuid,
    attempts: i32,
    outcome: feishu::Outcome,
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
