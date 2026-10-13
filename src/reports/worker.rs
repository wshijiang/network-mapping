use chrono::{DateTime, Duration as ChronoDuration, Utc};
use deadpool_postgres::Pool;
use serde_json::Value;
use tokio::time::{Duration, Instant};
use tokio_postgres::IsolationLevel;
use tracing::warn;
use uuid::Uuid;

use super::{
    period::{Period, PeriodType},
    statistics, storage,
};
use crate::{
    admin::get_mail_settings_from_database, config::AnalyticsSnapshotConfig, mail_template,
    runtime_config::RuntimeConfig, system_maintenance::SystemMaintenanceState,
};

pub async fn run_worker(
    pool: Pool,
    encryption_key: String,
    analytics: RuntimeConfig<AnalyticsSnapshotConfig>,
    maintenance: actix_web::web::Data<SystemMaintenanceState>,
    renderer: super::service::ReportRenderService,
    mut stopping: tokio::sync::watch::Receiver<bool>,
) {
    let mut next_schedule = Instant::now();
    loop {
        if *stopping.borrow() {
            return;
        }
        if !maintenance.snapshot().await.enabled {
            if Instant::now() >= next_schedule {
                if analytics.get().await.value.mode.runs_worker()
                    && let Err(error) = schedule(&pool).await
                {
                    warn!(event = "ReportScheduleFailed", %error);
                }
                next_schedule = Instant::now() + Duration::from_secs(60);
            }
            if let Err(error) = process_one_with_renderer(&pool, &analytics, &renderer).await {
                warn!(event = "ReportGenerationFailed", %error);
            }
            if *stopping.borrow() {
                return;
            }
            if let Err(error) = send_one(&pool, &encryption_key).await {
                warn!(event = "ReportDeliveryFailed", %error);
            }
        }
        tokio::select! {
            _=tokio::time::sleep(Duration::from_secs(5))=>{},
            changed=stopping.changed()=>if changed.is_err() || *stopping.borrow() { return; },
        }
    }
}

pub(crate) async fn schedule(pool: &Pool) -> Result<(), String> {
    let settings = get_mail_settings_from_database(pool)
        .await
        .map_err(|e| e.to_string())?;
    let client = pool.get().await.map_err(|e| e.to_string())?;
    let rows = client
        .query("SELECT * FROM report_schedule WHERE enabled;", &[])
        .await
        .map_err(|e| e.to_string())?;
    drop(client);
    let calendar = crate::system_time::refresh(pool).await?;
    let timezone = calendar.document.timezone;
    let tz = timezone
        .parse::<chrono_tz::Tz>()
        .map_err(|e| e.to_string())?;
    let now = Utc::now();
    for row in rows {
        let kind = PeriodType::parse(&row.get::<_, String>("period_type"))?;
        let notify = match kind {
            PeriodType::Weekly => settings.notification_prefs.report_weekly,
            PeriodType::Monthly => settings.notification_prefs.report_monthly,
        };
        if !notify {
            continue;
        }
        let start: DateTime<Utc> = row
            .get::<_, Option<DateTime<Utc>>>("last_period_end")
            .or(row.get("enabled_at"))
            .unwrap_or(now);
        let hour = row.get::<_, i16>("send_hour") as u32;
        let minute = row.get::<_, i16>("send_minute") as u32;
        // Bounded catch-up: at most eight periods per plan and tick, never send pre-activation history.
        let mut period = if start < now - ChronoDuration::days(366) {
            Period::containing_in(
                kind,
                now.with_timezone(&tz).date_naive(),
                &timezone,
                calendar.revision,
            )?
            .previous()?
        } else {
            Period::containing_in(
                kind,
                start.with_timezone(&tz).date_naive(),
                &timezone,
                calendar.revision,
            )?
        };
        for _ in 0..8 {
            if period.due_at(hour, minute)? > now {
                break;
            }
            storage::create(pool, &period, None, "automatic", None).await?;
            period = Period::containing_in(
                kind,
                period.date(period.end)?,
                &timezone,
                calendar.revision,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) async fn process_one(
    pool: &Pool,
    analytics: &RuntimeConfig<AnalyticsSnapshotConfig>,
) -> Result<bool, String> {
    let renderer = super::service::ReportRenderService::builtin().await;
    process_one_with_renderer(pool, analytics, &renderer).await
}

async fn process_one_with_renderer(
    pool: &Pool,
    analytics: &RuntimeConfig<AnalyticsSnapshotConfig>,
    renderer: &super::service::ReportRenderService,
) -> Result<bool, String> {
    let client = pool.get().await.map_err(|e| e.to_string())?;
    client.execute("UPDATE report_job SET status = 'retry_wait', available_at = NOW(), claim_token = NULL, lease_until = NULL \
        WHERE status = 'running' AND lease_until < NOW();", &[]).await.map_err(|e| e.to_string())?;
    let token = Uuid::new_v4();
    let row = client.query_opt("WITH picked AS (SELECT report_id FROM report_job WHERE status IN ('pending','retry_wait') AND available_at <= NOW() \
        ORDER BY available_at, report_id LIMIT 1 FOR UPDATE SKIP LOCKED) \
        UPDATE report_job j SET status = 'running', claim_token = $1, lease_until = NOW() + INTERVAL '5 minutes', attempts = attempts + 1 \
        FROM picked WHERE j.report_id = picked.report_id RETURNING j.report_id, j.attempts;", &[&token]).await.map_err(|e| e.to_string())?;
    let Some(row) = row else {
        return Ok(false);
    };
    let id: Uuid = row.get("report_id");
    let attempts: i32 = row.get("attempts");
    client.execute("UPDATE report_run SET status = 'generating' WHERE id = $1 AND status <> 'ready' AND EXISTS (SELECT 1 FROM report_job WHERE report_id = $1 AND claim_token = $2);", &[&id, &token]).await.map_err(|e| e.to_string())?;
    drop(client);
    let mode_ready = analytics.get().await.value.mode.runs_worker();
    let result = match tokio::time::timeout(
        Duration::from_secs(50),
        generate(pool, id, token, mode_ready, renderer),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err("报告生成超时，请检查数据库负载".into()),
    };
    if let Err(error) = result {
        let mut client = pool.get().await.map_err(|e| e.to_string())?;
        let tx = client.transaction().await.map_err(|e| e.to_string())?;
        let failed = attempts >= 5;
        let changed = tx.execute("UPDATE report_job SET status = $3, available_at = NOW() + $4::BIGINT * INTERVAL '1 second', \
            last_error = $5, claim_token = NULL, lease_until = NULL WHERE report_id = $1 AND claim_token = $2;",
            &[&id, &token, &if failed { "failed" } else { "retry_wait" }, &(60_i64 * i64::from(attempts.min(5))), &error]).await.map_err(|e| e.to_string())?;
        if changed > 0 {
            tx.execute("UPDATE report_run SET status = $2, last_error = $3 WHERE id = $1 AND status <> 'ready';", &[&id, &if failed { "failed" } else { "queued" }, &error]).await.map_err(|e| e.to_string())?;
        }
        tx.commit().await.map_err(|e| e.to_string())?;
    }
    Ok(true)
}

struct CapturedReport {
    payload: Value,
    quality: Value,
    checksum: String,
    key: &'static str,
    source: Option<crate::mail_template::MailTemplateSource>,
    version: i32,
    mail_settings: super::mail_config::ReportMailConfig,
    metadata: super::mail_context::MailMetadata,
    send_email: bool,
    recipients: Vec<i32>,
}

async fn capture(
    pool: &Pool,
    id: Uuid,
    token: Uuid,
    mode_ready: bool,
) -> Result<Option<CapturedReport>, String> {
    let mut client = pool.get().await.map_err(|e| e.to_string())?;
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .start()
        .await
        .map_err(|e| e.to_string())?;
    tx.batch_execute("SET LOCAL statement_timeout = '30s';")
        .await
        .map_err(|e| e.to_string())?;
    let claim = tx.query_opt("SELECT report_id, wait_deadline FROM report_job WHERE report_id = $1 AND claim_token = $2 AND status = 'running' AND lease_until > NOW() FOR UPDATE;", &[&id, &token]).await.map_err(|e| e.to_string())?;
    let Some(claim) = claim else {
        return Ok(None);
    };
    let row = tx
        .query_one("SELECT * FROM report_run WHERE id = $1 FOR UPDATE;", &[&id])
        .await
        .map_err(|e| e.to_string())?;
    let mut quality = statistics::quality(&tx, id).await?;
    let current = &quality["current"];
    if current["expected"] != current["ready"]
        || (!mode_ready && current["expected"].as_i64().unwrap_or(0) > 0)
    {
        let deadline: DateTime<Utc> = claim.get("wait_deadline");
        let permanent = current["deleted"].as_i64().unwrap_or(0) > 0 || Utc::now() > deadline;
        let error = if current["deleted"].as_i64().unwrap_or(0) > 0 {
            "固定输入中的扫描执行已被删除，请生成修订版"
        } else if !mode_ready {
            "统计快照未启用，请将分析快照模式设置为 shadow 或 snapshot"
        } else if permanent {
            "统计快照等待已超过 24 小时，请检查回填任务后重试"
        } else {
            "等待扫描统计完整：请检查分析快照进度"
        };
        tx.execute(
            "UPDATE report_run SET status = $2, quality = $3, last_error = $4 WHERE id = $1;",
            &[
                &id,
                &if permanent { "failed" } else { "waiting_data" },
                &quality,
                &error,
            ],
        )
        .await
        .map_err(|e| e.to_string())?;
        tx.execute("UPDATE report_job SET status = $3, available_at = NOW() + INTERVAL '1 minute', attempts = 0, claim_token = NULL, lease_until = NULL, last_error = $4 \
            WHERE report_id = $1 AND claim_token = $2;", &[&id, &token, &if permanent { "failed" } else { "retry_wait" }, &error]).await.map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        return Ok(None);
    }
    let period = Period {
        timezone: row.get("timezone"),
        settings_revision: row.get("settings_revision"),
        kind: PeriodType::parse(&row.get::<_, String>("period_type"))?,
        start: row.get("period_start"),
        end: row.get("period_end"),
    };
    let snapshot: Value = row.get("task_snapshot");
    let payload = statistics::build(&tx, id, &period, &snapshot, &quality).await?;
    let checksum = openssl::hash::hash(
        openssl::hash::MessageDigest::sha256(),
        &serde_json::to_vec(&payload).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?
    .iter()
    .map(|b| format!("{b:02x}"))
    .collect::<String>();
    let key = if period.kind == PeriodType::Weekly {
        mail_template::REPORT_WEEKLY_TEMPLATE_KEY
    } else {
        mail_template::REPORT_MONTHLY_TEMPLATE_KEY
    };
    let mail_settings = match super::mail_config::load(&tx).await {
        Ok(settings) => settings,
        Err(error) => {
            quality["mail_error"] = serde_json::json!(error);
            Default::default()
        }
    };
    let generated_at: DateTime<Utc> = tx
        .query_one("SELECT NOW() AS at", &[])
        .await
        .map_err(|e| e.to_string())?
        .get("at");
    let metadata = super::mail_context::MailMetadata {
        revision: row.get("revision"),
        generated_at,
        cutoff_at: row.get("cutoff_at"),
    };
    let template = mail_template::load_report_template(&tx, key).await;
    let (source, version) = match template {
        Ok(Some((source, version))) => (Some(source), version),
        Ok(None) => {
            quality["mail_error"] = serde_json::json!("报告邮件模板已停用");
            (None, 0)
        }
        Err(error) => {
            quality["mail_error"] = serde_json::json!(error);
            (None, 0)
        }
    };
    let send_email = row.get("send_email");
    let recipients = row.get("recipient_ids");
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(Some(CapturedReport {
        payload,
        quality,
        checksum,
        key,
        source,
        version,
        mail_settings,
        metadata,
        send_email,
        recipients,
    }))
}

async fn generate(
    pool: &Pool,
    id: Uuid,
    token: Uuid,
    mode_ready: bool,
    renderer: &super::service::ReportRenderService,
) -> Result<(), String> {
    use super::render_module::{ReportRenderInput, ReportRenderOutput};
    let Some(mut input) = capture(pool, id, token, mode_ready).await? else {
        return Ok(());
    };
    // CPU and IPC run after the snapshot transaction and connection are released.
    let image = if input.mail_settings.remote_images_enabled {
        match serde_json::from_value::<Vec<super::chart::TrendDay>>(input.payload["trend"].clone())
        {
            Ok(trend) => super::chart::render_async(trend).await,
            Err(error) => Err(error.to_string()),
        }
    } else {
        Ok(Vec::new())
    };
    let asset = match image {
        Ok(bytes) if !bytes.is_empty() => Some(super::assets::PreparedAsset::prepare(
            bytes,
            &input.mail_settings,
            input.metadata.generated_at,
        )?),
        Ok(_) => None,
        Err(error) => {
            input.quality["mail_error"] = serde_json::json!(error);
            None
        }
    };
    let image_url = asset.as_ref().map(|asset| asset.url.as_str()).unwrap_or("");
    let lease = renderer
        .registry()
        .acquire(super::render_module::MODULE_ID)
        .await;
    let mut rendered = None;
    if input.quality.get("mail_error").is_none() {
        let context = super::mail_context::build(
            &input.payload,
            &input.quality,
            id,
            &input.metadata,
            &input.mail_settings,
            image_url,
        )?;
        if let Some(source) = input.source.take() {
            let document = serde_json::to_value(ReportRenderInput {
                template_key: input.key.into(),
                template_version: input.version,
                source,
                context,
            })
            .map_err(|e| e.to_string())?;
            let input_checksum =
                super::assets::digest(&serde_json::to_vec(&document).map_err(|e| e.to_string())?)?;
            let result = match &lease {
                Ok(lease) => lease
                    .invoke("render", document)
                    .await
                    .map_err(|e| e.to_string()),
                Err(error) => Err(error.to_string()),
            };
            match result.and_then(|value| {
                serde_json::from_value::<ReportRenderOutput>(value).map_err(|e| e.to_string())
            }) {
                Ok(output) if output.template_version == input.version => {
                    let mut mail = output.rendered;
                    if let Err(error) = nm_report_renderer::validate_rendered_mail(&mut mail) {
                        input.quality["mail_error"] = serde_json::json!(error.to_string());
                    } else {
                        if let Ok(lease) = &lease {
                            input.quality["renderer"] = serde_json::json!({"release_id":lease.release_id(),"generation":lease.generation(),"input_checksum":input_checksum});
                        }
                        rendered = Some(mail);
                    }
                }
                Ok(_) => {
                    input.quality["mail_error"] = serde_json::json!("渲染器返回了不匹配的模板版本")
                }
                Err(error) => input.quality["mail_error"] = serde_json::json!(error),
            }
        }
    }
    let keep_asset = rendered.as_ref().is_some_and(|mail| {
        !image_url.is_empty()
            && (mail.html_body.contains(image_url) || mail.text_body.contains(image_url))
    });
    let rendered = rendered
        .map(serde_json::to_value)
        .transpose()
        .map_err(|e| e.to_string())?;
    let mut client = pool.get().await.map_err(|e| e.to_string())?;
    let tx = client.transaction().await.map_err(|e| e.to_string())?;
    tx.batch_execute("SET LOCAL statement_timeout='30s'")
        .await
        .map_err(|e| e.to_string())?;
    let valid=tx.query_opt("SELECT report_id FROM report_job WHERE report_id=$1 AND claim_token=$2 AND status='running' AND lease_until>clock_timestamp() FOR UPDATE", &[&id,&token]).await.map_err(|e|e.to_string())?;
    if valid.is_none() {
        return Ok(());
    }
    let row = tx
        .query_one(
            "SELECT revision,status FROM report_run WHERE id=$1 FOR UPDATE",
            &[&id],
        )
        .await
        .map_err(|e| e.to_string())?;
    if row.get::<_, i32>("revision") != input.metadata.revision {
        return Err("报告版本在渲染期间发生变化".into());
    }
    if row.get::<_, String>("status") == "ready" {
        return Ok(());
    }
    let latest = statistics::quality(&tx, id).await?;
    if latest["current"]["deleted"] != input.quality["current"]["deleted"]
        || latest["current"]["ready"] != input.quality["current"]["ready"]
    {
        return Err("报告固定输入在渲染期间发生变化，请重试".into());
    }
    tx.execute("DELETE FROM report_mail_asset WHERE report_id=$1", &[&id])
        .await
        .map_err(|e| e.to_string())?;
    if keep_asset && let Some(asset) = &asset {
        asset.commit(&tx, id).await?;
    }
    tx.execute("UPDATE report_run SET status='ready',payload=$2,quality=$3,generated_at=$8,last_error=NULL,content_checksum=$4,template_key=$5,template_version=$6,rendered_mail=$7 WHERE id=$1", &[&id,&input.payload,&input.quality,&input.checksum,&input.key,&input.version,&rendered,&input.metadata.generated_at]).await.map_err(|e|e.to_string())?;
    if input.send_email {
        storage::enqueue_delivery(&tx, id, &input.recipients, true, false).await?;
    }
    let changed=tx.execute("UPDATE report_job SET status='succeeded',claim_token=NULL,lease_until=NULL,last_error=NULL WHERE report_id=$1 AND claim_token=$2 AND lease_until>clock_timestamp()", &[&id,&token]).await.map_err(|e|e.to_string())?;
    if changed != 1 {
        return Err("报告提交租约已失效".into());
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    drop(lease);
    Ok(())
}

pub(crate) async fn send_one(pool: &Pool, encryption_key: &str) -> Result<bool, String> {
    let client = pool.get().await.map_err(|e| e.to_string())?;
    let token = Uuid::new_v4();
    let row = client.query_opt("WITH picked AS (SELECT id FROM report_delivery WHERE (status = 'pending' AND available_at <= NOW()) \
        OR (status = 'sending' AND lease_until < NOW()) ORDER BY available_at, id LIMIT 1 FOR UPDATE SKIP LOCKED) \
        UPDATE report_delivery d SET status = 'sending', claim_token = $1, lease_until = NOW() + INTERVAL '5 minutes', attempts = attempts + 1 \
        FROM picked WHERE d.id = picked.id RETURNING d.*;", &[&token]).await.map_err(|e| e.to_string())?;
    let Some(row) = row else {
        return Ok(false);
    };
    let id: Uuid = row.get("id");
    let report: Uuid = row.get("report_id");
    let user: i32 = row.get("recipient_user_id");
    let email: String = row.get("recipient");
    let attempts: i32 = row.get("attempts");
    let automatic: bool = row.get("automatic");
    let report = client.query_one("SELECT r.rendered_mail, r.period_type, r.period_end, s.enabled, s.enabled_at, s.recipient_ids, \
        NOT EXISTS (SELECT 1 FROM report_mail_asset a WHERE a.report_id = r.id AND (a.revoked_at IS NOT NULL OR a.expires_at <= NOW())) AS image_available, COALESCE((SELECT enabled FROM mail_template WHERE template_key = r.template_key), TRUE) AS template_enabled \
        FROM report_run r JOIN report_schedule s ON s.period_type = r.period_type WHERE r.id = $1;", &[&report]).await.map_err(|e| e.to_string())?;
    let active: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND role = 1 AND disabled_at IS NULL \
        AND deleted_at IS NULL AND NOT limit_login AND trim(email) = $2) AS active;",
            &[&user, &email],
        )
        .await
        .map_err(|e| e.to_string())?
        .get("active");
    let rendered: Option<Value> = report.get("rendered_mail");
    drop(client);
    let settings = get_mail_settings_from_database(pool)
        .await
        .map_err(|e| e.to_string())?;
    let kind: String = report.get("period_type");
    let selected: Vec<i32> = report.get("recipient_ids");
    let preference = if kind == "weekly" {
        settings.notification_prefs.report_weekly
    } else {
        settings.notification_prefs.report_monthly
    };
    let activation_valid = report
        .get::<_, Option<DateTime<Utc>>>("enabled_at")
        .is_some_and(|at| report.get::<_, DateTime<Utc>>("period_end") >= at);
    let permitted = active
        && report.get::<_, bool>("image_available")
        && report.get::<_, bool>("template_enabled")
        && rendered.is_some()
        && (!automatic
            || (report.get::<_, bool>("enabled")
                && activation_valid
                && preference
                && (selected.is_empty() || selected.contains(&user))));
    if !permitted {
        let client = pool.get().await.map_err(|e| e.to_string())?;
        client.execute("UPDATE report_delivery SET status = 'cancelled', last_error = '收件人、计划或模板已停用', claim_token = NULL, lease_until = NULL WHERE id = $1 AND claim_token = $2;", &[&id, &token]).await.map_err(|e| e.to_string())?;
        return Ok(true);
    }
    let result = match tokio::time::timeout(
        Duration::from_secs(90),
        mail_template::send_archived_report(
            pool,
            encryption_key,
            &email,
            rendered.unwrap_or(Value::Null),
            id,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err("SMTP 投递超时".into()),
    };
    let client = pool.get().await.map_err(|e| e.to_string())?;
    match result {
        Ok(()) => {
            client.execute("UPDATE report_delivery SET status = 'sent', sent_at = NOW(), last_error = NULL, claim_token = NULL, lease_until = NULL WHERE id = $1 AND claim_token = $2;", &[&id, &token]).await.map_err(|e| e.to_string())?;
        }
        Err(error) => {
            client.execute("UPDATE report_delivery SET status = $3, available_at = NOW() + $4::BIGINT * INTERVAL '1 second', \
            last_error = $5, claim_token = NULL, lease_until = NULL WHERE id = $1 AND claim_token = $2;", &[&id, &token, &if attempts >= 5 { "failed" } else { "pending" }, &(60_i64 * i64::from(attempts.min(5))), &error]).await.map_err(|e| e.to_string())?;
        }
    }
    Ok(true)
}
