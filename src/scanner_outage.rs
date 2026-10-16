//! Persistent scanner disconnect detection and mail delivery.

use crate::runtime_config::RuntimeConfig;
use crate::scanner_health::ScannerHealthConfig;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use deadpool_postgres::Pool;
use tokio::time::Duration;
use tokio_postgres::Transaction;
use tracing::{error, warn};

use crate::admin::get_mail_settings_from_database;
use crate::mail_template::{ScannerOutageMail, get_admin_recipients, send_scanner_outage_email};
use crate::system_maintenance::SystemMaintenanceState;

/// Called inside the scanner-state transaction, after a valid heartbeat updates scanner_info.
/// The scanner_info row lock serializes this transition with the outage detector.
pub async fn record_recovery(
    transaction: &Transaction<'_>,
    scanner_id: &str,
) -> Result<(), tokio_postgres::Error> {
    let row = transaction
        .query_opt(
            "UPDATE scanner_outage SET recovered_at = NOW(), notification_recovery = TRUE, recovery_requested = \
             COALESCE((SELECT value::boolean FROM setting WHERE item_type = 'notification' \
             AND key = 'scanner_recovery_enabled'), TRUE) \
             WHERE scanner_id = $1 AND recovered_at IS NULL RETURNING id;",
            &[&scanner_id],
        )
        .await?;
    if let Some(row) = row {
        let outage_id: i64 = row.get("id");
        transaction
            .execute(
                "UPDATE scanner_outage_delivery SET status = 'cancelled', claimed_until = NULL \
                 WHERE outage_id = $1 AND kind = 'offline' AND status = 'pending';",
                &[&outage_id],
            )
            .await?;
        transaction.execute("UPDATE notification_delivery d SET status='cancelled',last_error='scanner_recovered',finished_at=NOW(),claim_token=NULL,lease_until=NULL FROM notification_event e WHERE d.event_id=e.id AND e.outage_id=$1 AND e.event_type='scanner.offline' AND d.status='pending'", &[&outage_id]).await?;
    }
    Ok(())
}

/// Administrative deactivation ends an incident without announcing a recovery.
pub async fn close_without_recovery(
    transaction: &Transaction<'_>,
    scanner_id: &str,
) -> Result<(), tokio_postgres::Error> {
    let row = transaction
        .query_opt(
            "UPDATE scanner_outage SET recovered_at = NOW(), recovery_requested = FALSE, notification_recovery = FALSE \
         WHERE scanner_id = $1 AND recovered_at IS NULL RETURNING id;",
            &[&scanner_id],
        )
        .await?;
    if let Some(row) = row {
        let outage_id: i64 = row.get("id");
        transaction
            .execute(
                "UPDATE scanner_outage_delivery SET status = 'cancelled', claimed_until = NULL \
             WHERE outage_id = $1 AND status = 'pending';",
                &[&outage_id],
            )
            .await?;
        transaction.execute("UPDATE notification_delivery d SET status='cancelled',last_error='scanner_deactivated',finished_at=NOW(),claim_token=NULL,lease_until=NULL FROM notification_event e WHERE d.event_id=e.id AND e.outage_id=$1 AND d.status IN ('pending','sending')", &[&outage_id]).await?;
    }
    Ok(())
}

pub async fn run_worker(
    pool: Pool,
    encryption_key: String,
    maintenance: actix_web::web::Data<SystemMaintenanceState>,
    policy: RuntimeConfig<ScannerHealthConfig>,
) {
    let mut revisions = policy.subscribe();
    loop {
        let current = policy.get().await.value;
        if let Err(error_value) = run_once(&pool, &encryption_key, &maintenance, &current).await {
            error!(event = "ScannerOutageWorkerError", error = %error_value, "扫描器掉线通知处理失败");
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(current.check_interval_seconds)) => {},
            changed = revisions.changed() => { if changed.is_err() { return; } }
        }
    }
}

pub(crate) async fn run_once(
    pool: &Pool,
    encryption_key: &str,
    maintenance: &SystemMaintenanceState,
    policy: &ScannerHealthConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let snapshot = maintenance.snapshot().await;
    if snapshot.enabled
        || Utc::now()
            < snapshot.updated_at + ChronoDuration::seconds(policy.maintenance_grace_seconds)
    {
        return Ok(());
    }

    let settings = get_mail_settings_from_database(pool)
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let notify = settings.notification_prefs.scanner_offline_enabled;
    let can_send = notify
        && !settings.smtp_host.trim().is_empty()
        && !settings.sender.trim().is_empty()
        && settings.sender_key_configured;
    let recipients = if notify {
        get_admin_recipients(pool)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?
    } else {
        Vec::new()
    };
    detect_outages(pool, &recipients, policy.alert_after_seconds).await?;
    enqueue_recoveries(pool).await?;

    if !settings.notification_prefs.scanner_recovery_enabled {
        pool.get()
            .await?
            .execute(
                "UPDATE scanner_outage_delivery SET status = 'cancelled', claimed_until = NULL \
                 WHERE status = 'pending' AND kind = 'recovered';",
                &[],
            )
            .await?;
    }

    if !notify {
        pool.get()
            .await?
            .execute(
                "UPDATE scanner_outage_delivery SET status = 'cancelled', claimed_until = NULL \
             WHERE status = 'pending';",
                &[],
            )
            .await?;
        return Ok(());
    }
    if !can_send {
        return Ok(());
    }
    for _ in 0..20 {
        if !send_next(pool, encryption_key).await? {
            break;
        }
    }
    Ok(())
}

pub(crate) async fn detect_outages(
    pool: &Pool,
    recipients: &[String],
    alert_after_seconds: i64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut connection = pool.get().await?;
    let transaction = connection.transaction().await?;
    let rows = transaction
        .query(
            "SELECT s.scanner_id, s.last_seen_at FROM scanner_info s \
         WHERE s.deleted_at IS NULL AND s.is_enable = TRUE \
         AND s.outage_monitored_at < NOW() - $1::BIGINT * INTERVAL '1 second' \
         AND s.last_seen_at < NOW() - $1::BIGINT * INTERVAL '1 second' \
         AND NOT EXISTS (SELECT 1 FROM scanner_outage o \
             WHERE o.scanner_id = s.scanner_id AND o.recovered_at IS NULL) \
         ORDER BY s.outage_monitored_at LIMIT 100 FOR UPDATE OF s SKIP LOCKED;",
            &[&alert_after_seconds],
        )
        .await?;
    for row in rows {
        let scanner_id: String = row.get("scanner_id");
        let last_seen_at: DateTime<Utc> = row.get("last_seen_at");
        let created = transaction
            .query_opt(
                "INSERT INTO scanner_outage(scanner_id, last_seen_at) VALUES ($1, $2) \
             ON CONFLICT (scanner_id) WHERE recovered_at IS NULL DO NOTHING RETURNING id;",
                &[&scanner_id, &last_seen_at],
            )
            .await?;
        if let Some(created) = created {
            let outage_id: i64 = created.get("id");
            crate::notification::enqueue(
                &transaction,
                "scanner.offline",
                "warning",
                &format!("outage:{outage_id}:offline"),
                "Scanner 掉线",
                &format!("扫描器：{scanner_id}\n最后心跳：{last_seen_at}\n掉线事件：{outage_id}"),
                Some(outage_id),
            )
            .await?;
            for recipient in recipients {
                transaction
                    .execute(
                        "INSERT INTO scanner_outage_delivery(outage_id, kind, recipient) \
                     VALUES ($1, 'offline', $2) ON CONFLICT DO NOTHING;",
                        &[&outage_id, recipient],
                    )
                    .await?;
            }
        }
    }
    transaction.commit().await?;
    Ok(())
}

async fn enqueue_recoveries(pool: &Pool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut connection = pool.get().await?;
    let transaction = connection.transaction().await?;
    let rows = transaction
        .query(
            "SELECT o.id FROM scanner_outage o \
         WHERE o.recovered_at IS NOT NULL AND o.recovery_requested \
         AND NOT o.recovery_delivery_prepared \
         AND NOT EXISTS (SELECT 1 FROM scanner_outage_delivery d \
             WHERE d.outage_id = o.id AND d.kind = 'offline' \
             AND d.status IN ('pending', 'sending')) \
         ORDER BY o.id LIMIT 100 FOR UPDATE OF o SKIP LOCKED;",
            &[],
        )
        .await?;
    for row in rows {
        let outage_id: i64 = row.get("id");
        transaction
            .execute(
                "INSERT INTO scanner_outage_delivery(outage_id, kind, recipient) \
             SELECT $1, 'recovered', recipient FROM scanner_outage_delivery \
             WHERE outage_id = $1 AND kind = 'offline' AND status = 'sent' \
             ON CONFLICT DO NOTHING;",
                &[&outage_id],
            )
            .await?;
        transaction
            .execute(
                "UPDATE scanner_outage SET recovery_delivery_prepared = TRUE WHERE id = $1;",
                &[&outage_id],
            )
            .await?;
    }
    transaction.commit().await?;
    Ok(())
}

async fn send_next(
    pool: &Pool,
    encryption_key: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let connection = pool.get().await?;
    let row = connection
        .query_opt(
            "WITH chosen AS (SELECT id FROM scanner_outage_delivery \
           WHERE (status = 'pending' AND available_at <= NOW()) \
              OR (status = 'sending' AND claimed_until < NOW()) \
           ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1) \
         UPDATE scanner_outage_delivery d SET status = 'sending', \
           claimed_until = NOW() + INTERVAL '2 minutes', attempts = attempts + 1 \
         FROM chosen WHERE d.id = chosen.id \
         RETURNING d.id, d.outage_id, d.kind, d.recipient, d.attempts;",
            &[],
        )
        .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let id: i64 = row.get("id");
    let outage_id: i64 = row.get("outage_id");
    let kind: String = row.get("kind");
    let recipient: String = row.get("recipient");
    let attempts: i32 = row.get("attempts");

    let detail = connection
        .query_opt(
            "SELECT o.scanner_id, o.last_seen_at, o.detected_at, o.recovered_at, \
         s.name, s.location FROM scanner_outage o \
         JOIN scanner_info s ON s.scanner_id = o.scanner_id WHERE o.id = $1;",
            &[&outage_id],
        )
        .await?;
    let Some(detail) = detail else {
        return Ok(true);
    };
    let recovered_at: Option<DateTime<Utc>> = detail.get("recovered_at");
    if kind == "offline" && recovered_at.is_some() {
        connection
            .execute(
                "UPDATE scanner_outage_delivery SET status = 'cancelled', claimed_until = NULL \
             WHERE id = $1 AND status = 'sending';",
                &[&id],
            )
            .await?;
        return Ok(true);
    }
    let recipient_active: bool = connection
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM users WHERE role = 1 \
             AND disabled_at IS NULL AND deleted_at IS NULL \
             AND lower(trim(email)) = lower($1)) AS active;",
            &[&recipient],
        )
        .await?
        .get("active");
    if !recipient_active {
        connection
            .execute(
                "UPDATE scanner_outage_delivery SET status = 'cancelled', claimed_until = NULL \
                 WHERE id = $1 AND status = 'sending';",
                &[&id],
            )
            .await?;
        return Ok(true);
    }
    let scanner_id: String = detail.get("scanner_id");
    let name: Option<String> = detail.get("name");
    let location: Option<String> = detail.get("location");
    let last_seen_at: DateTime<Utc> = detail.get("last_seen_at");
    let event_at: DateTime<Utc> = if kind == "offline" {
        detail.get("detected_at")
    } else {
        recovered_at.unwrap_or_else(Utc::now)
    };
    drop(connection);
    let mail = ScannerOutageMail {
        kind: &kind,
        scanner_id: &scanner_id,
        scanner_name: name.as_deref().unwrap_or("未命名扫描器"),
        location: location.as_deref().unwrap_or("-"),
        last_seen_at,
        event_at,
    };
    let result = send_scanner_outage_email(pool, encryption_key, &recipient, &mail)
        .await
        .map_err(|error| error.to_string());
    let connection = pool.get().await?;
    match result {
        Ok(true) => {
            connection
                .execute(
                    "UPDATE scanner_outage_delivery SET status = 'sent', sent_at = NOW(), \
                 claimed_until = NULL, last_error = NULL WHERE id = $1;",
                    &[&id],
                )
                .await?;
        }
        Ok(false) => {
            connection
                .execute(
                    "UPDATE scanner_outage_delivery SET status = 'cancelled', claimed_until = NULL \
                 WHERE id = $1;",
                    &[&id],
                )
                .await?;
        }
        Err(error_value) => {
            warn!(event = "ScannerOutageMailFailed", outage_id, kind, recipient = %recipient, error = %error_value);
            let status = if attempts >= 5 { "failed" } else { "pending" };
            let backoff_seconds = 60_i64 * i64::from(attempts.min(5));
            connection
                .execute(
                    "UPDATE scanner_outage_delivery SET status = $2, claimed_until = NULL, \
                 available_at = NOW() + $3::BIGINT * INTERVAL '1 second', \
                 last_error = LEFT($4, 500) WHERE id = $1;",
                    &[&id, &status, &backoff_seconds, &error_value.to_string()],
                )
                .await?;
        }
    }
    Ok(true)
}
