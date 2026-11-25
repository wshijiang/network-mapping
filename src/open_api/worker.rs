use super::{
    ApiError, Principal, Result, analytics, auth, model,
    query::{self, Search},
    resources, tasks,
};
use crate::elasticsearch::ElasticsearchService;
use chrono::Utc;
use deadpool_postgres::Pool;
use serde_json::{Value, json};
use uuid::Uuid;

pub(crate) fn content_type(format: &str) -> &'static str {
    match format {
        "csv" => "text/csv; charset=utf-8",
        "jsonl" => "application/x-ndjson; charset=utf-8",
        _ => "application/json; charset=utf-8",
    }
}
pub(crate) fn csv_cell(value: &Value) -> String {
    let raw = if let Some(s) = value.as_str() {
        s.to_owned()
    } else if value.is_null() {
        String::new()
    } else {
        value.to_string()
    };
    let prefix = if raw.trim_start().starts_with(['=', '+', '-', '@'])
        || raw.starts_with(['\t', '\r', '\n'])
    {
        "'"
    } else {
        ""
    };
    format!("\"{prefix}{}\"", raw.replace('"', "\"\""))
}
pub(crate) fn render_artifact(value: &Value, format: &str) -> Result<(Vec<u8>, String)> {
    let rows = value.get("items").and_then(Value::as_array);
    let data = match format {
        "jsonl" => {
            let owned = vec![value.clone()];
            rows.unwrap_or(&owned)
                .iter()
                .map(|v| format!("{v}\n"))
                .collect::<String>()
                .into_bytes()
        }
        "csv" => {
            let mut output = String::from("\u{feff}");
            if let Some(rows) = rows {
                let columns = rows
                    .iter()
                    .flat_map(|v| v.as_object().into_iter().flat_map(|o| o.keys()))
                    .collect::<std::collections::BTreeSet<_>>();
                output.push_str(
                    &columns
                        .iter()
                        .map(|k| csv_cell(&json!(k)))
                        .collect::<Vec<_>>()
                        .join(","),
                );
                output.push('\n');
                for row in rows {
                    output.push_str(
                        &columns
                            .iter()
                            .map(|key| csv_cell(&row[*key]))
                            .collect::<Vec<_>>()
                            .join(","),
                    );
                    output.push('\n');
                }
            } else {
                output.push_str("\"section\",\"data\"\n");
                if let Some(object) = value.as_object() {
                    for (key, v) in object {
                        output.push_str(&format!("{},{}\n", csv_cell(&json!(key)), csv_cell(v)));
                    }
                }
            }
            output.into_bytes()
        }
        _ => serde_json::to_vec(value).map_err(|_| ApiError::unavailable())?,
    };
    if data.len() > 8 * 1024 * 1024 {
        return Err(ApiError::bad("生成文件超过 8 MiB，请缩小范围"));
    }
    Ok((data, content_type(format).into()))
}
pub(crate) async fn run(pool: Pool, es: ElasticsearchService, encryption_key: Vec<u8>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut cycles = 0u64;
    loop {
        tick.tick().await;
        cycles += 1;
        let outcome = async {
            reconcile_events(&pool).await?;
            process_job(&pool, &es).await?;
            process_delivery(&pool, &encryption_key).await?;
            if cycles.is_multiple_of(1800) {
                retention(&pool).await?;
            }
            Ok::<_, ApiError>(())
        }
        .await;
        if let Err(e) = outcome {
            tracing::warn!(event = "OpenApiWorkerFailed", code = e.code);
        }
    }
}
pub(super) async fn process_job(pool: &Pool, es: &ElasticsearchService) -> Result<()> {
    if pool
        .get()
        .await?
        .query_one("SELECT enabled FROM system_maintenance_state", &[])
        .await?
        .get::<_, bool>(0)
    {
        return Ok(());
    }
    let claim = Uuid::new_v4();
    let row = {
        let c = pool.get().await?;
        c.query_opt("WITH candidate AS (SELECT id FROM api_job WHERE (status='queued' OR (status='running' AND lease_expires_at<NOW())) AND expires_at>NOW() ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE api_job j SET status='running',claim_token=$1,lease_expires_at=NOW()+INTERVAL '60 seconds' FROM candidate c WHERE j.id=c.id RETURNING j.*",&[&claim]).await?
    };
    let Some(row) = row else {
        return Ok(());
    };
    let id: Uuid = row.get("id");
    let client: i32 = row.get("client_id");
    let key: Uuid = row.get("credential_id");
    let revision: i64 = row.get("policy_revision");
    let kind: String = row.get("kind");
    let spec: Value = row.get("spec");
    let result=tokio::time::timeout(std::time::Duration::from_secs(45),async {
        let (p,_,_)=auth::load(pool,key).await?;
        if p.revision!=revision||!p.has(if kind=="export"{"exports:create"}else{"reports:create"})||!p.has(if kind=="export"{"assets:read"}else{"analytics:read"}){return Err(ApiError::forbidden());}
        let mut s:Search=serde_json::from_value(json!({"query":spec.get("query"),"fields":spec.get("fields"),"start_at":spec.get("start_at"),"end_at":spec.get("end_at")})).map_err(|_|ApiError::bad("任务参数无效"))?;
        s.page_size=Some(100);
        let captured_at=Utc::now();
        let value=if kind=="report" {
            let _slot=crate::statistics::ClusterSlot::acquire(pool).await.map_err(|_|ApiError::unavailable())?;
            let task_ids=query::task_ids(pool,&p).await?;
            let inputs=query::execution_ids(pool,&p).await?;
            let discovery=analytics::scan_statistics_from_inputs(pool,es,&p,&s,"discovery","day",Some(&inputs)).await?;
            let ports=analytics::scan_statistics_from_inputs(pool,es,&p,&s,"port","port",Some(&inputs)).await?;
            let services=analytics::scan_statistics_from_inputs(pool,es,&p,&s,"service","service",Some(&inputs)).await?;
            let remaining=query::execution_ids(pool,&p).await?;
            if inputs.iter().any(|id|!remaining.contains(id)){return Err(ApiError::new(actix_web::http::StatusCode::CONFLICT,"report_input_changed","报告输入执行已变化，请重新生成"));}
            json!({"report_id":id,"client_id":p.client_id,"captured_at":captured_at,"period":{"start_at":s.start_at,"end_at":s.end_at,"timezone":crate::system_time::timezone().name()},"policy_revision":p.revision,"input_task_ids":task_ids,"input_execution_ids":inputs,"discovery":discovery,"ports":ports,"services":services,"quality":{"based_on_retained_history":true,"scope":"authorized_successful_executions","closed_ports_inferred":false,"vulnerability_remediation_inferred":false},"schema_version":1})
        }else {
            let mut items=Vec::new();let mut bytes=0usize;
            loop {
                let page=query::endpoints(pool,es,&p,&s,vec![]).await?;
                for value in page["items"].as_array().into_iter().flatten(){bytes=bytes.saturating_add(value.to_string().len());if items.len()>=p.policy.max_export_rows||bytes>8*1024*1024{return Err(ApiError::bad("导出超过行数或文件预算，请缩小范围"));}items.push(value.clone());}
                s.cursor=page["next_cursor"].as_str().and_then(|s|Uuid::parse_str(s).ok());if s.cursor.is_none(){break;}
                let (current,_,_)=auth::load(pool,key).await?;if current.revision!=revision{return Err(ApiError::forbidden());}
            }
            json!({"items":items,"meta":{"captured_at":captured_at,"policy_revision":revision,"consistency":"live_projection","row_count":items.len(),"query":spec.get("query")}})
        };
        let format=spec["format"].as_str().unwrap_or("json");let (artifact,content_type)=render_artifact(&value,format)?;
        let checksum=model::fingerprint(&artifact);Ok::<_,ApiError>((value,artifact,content_type,format.to_owned(),checksum))
    }).await.unwrap_or_else(|_|Err(ApiError::unavailable()));
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    let (status, error) = match result {
        Ok((value, artifact, content_type, format, checksum)) => {
            let (p, _, _) = match auth::load(pool, key).await {
                Ok(p) => p,
                Err(_) => {
                    tx.execute("UPDATE api_job SET status='failed',last_error='authorization_changed',finished_at=NOW(),claim_token=NULL WHERE id=$1 AND claim_token=$2",&[&id,&claim]).await?;
                    tx.commit().await?;
                    return Ok(());
                }
            };
            if p.revision != revision {
                tx.execute("UPDATE api_job SET status='failed',last_error='authorization_changed',finished_at=NOW(),claim_token=NULL WHERE id=$1 AND claim_token=$2",&[&id,&claim]).await?;
                tx.commit().await?;
                return Ok(());
            }
            tasks::authorize(&tx, &p).await?;
            let changed=tx.execute("UPDATE api_job SET status='succeeded',result=$3,artifact=$4,content_type=$5,filename=$6,artifact_checksum=$7,finished_at=NOW(),claim_token=NULL,lease_expires_at=NULL WHERE id=$1 AND claim_token=$2 AND status='running' AND lease_expires_at>NOW()",&[&id,&claim,&value,&artifact,&content_type,&format!("{kind}-{id}.{format}"),&checksum]).await?;
            if changed == 0 {
                tx.commit().await?;
                return Ok(());
            }
            ("succeeded", None)
        }
        Err(error) => {
            let changed=tx.execute("UPDATE api_job SET status='failed',last_error=$3,finished_at=NOW(),claim_token=NULL,lease_expires_at=NULL WHERE id=$1 AND claim_token=$2 AND status='running'",&[&id,&claim,&error.code]).await?;
            if changed == 0 {
                tx.commit().await?;
                return Ok(());
            }
            ("failed", Some(error.code))
        }
    };
    let event_type = format!("{kind}.{status}");
    resources::event(
        &tx,
        client,
        &event_type,
        &id.to_string(),
        &json!({"id":id,"status":status,"reason_code":error,"policy_revision":revision}),
        &format!("job:{id}:{status}"),
    )
    .await?;
    auth::audit(
        &tx,
        Some(client),
        "system",
        "open-api-worker",
        &event_type,
        Some(&id.to_string()),
        None,
        &json!({"status":status,"reason_code":error}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
pub(super) async fn reconcile_events(pool: &Pool) -> Result<()> {
    let mut connection = pool.get().await?;
    let c = connection.transaction().await?;
    // Keys and policies are checked again at dispatch. Notify already running
    // executions through the existing cancellation protocol as soon as possible.
    c.execute(
        "WITH denied AS (
             SELECT e.id FROM scan_task_execution e JOIN scan_task t ON e.task_id=t.id
             WHERE e.execution_status='running' AND NOT e.cancel_requested AND NOT api_scan_task_enabled(t)
             ORDER BY e.id LIMIT 256 FOR UPDATE OF e SKIP LOCKED
         )
         UPDATE scan_task_execution e SET cancel_requested=TRUE FROM denied WHERE e.id=denied.id",
        &[],
    ).await?;
    let cancelled = c.query(
        "WITH denied AS (
             SELECT e.id FROM scan_task_execution e JOIN scan_task t ON e.task_id=t.id
             WHERE e.execution_status='pending' AND NOT api_scan_task_enabled(t)
             ORDER BY e.id LIMIT 256 FOR UPDATE OF e SKIP LOCKED
         )
         UPDATE scan_task_execution e SET execution_status='cancelled',task_end_time=$1,cancel_requested=FALSE
         FROM denied WHERE e.id=denied.id RETURNING e.task_id",
        &[&crate::clock::get_unix_epoch_ms()],
    ).await?;
    let task_ids: std::collections::BTreeSet<i32> =
        cancelled.iter().map(|row| row.get(0)).collect();
    for task_id in task_ids {
        crate::scan_control::refresh_task_aggregate(&c, task_id).await?;
    }
    c.execute("INSERT INTO api_event_outbox(event_id,client_id,event_type,resource_id,payload,dedup_key) SELECT gen_random_uuid(),t.api_client_id,'task.'||t.task_status,t.task_id,jsonb_build_object('task_id',t.task_id,'status',t.task_status),'task:'||t.task_id||':'||t.task_status FROM scan_task t WHERE t.api_client_id IS NOT NULL AND t.task_status IN ('succeeded','failed','partial','cancelled') AND t.task_end_time>=(EXTRACT(EPOCH FROM (NOW()-INTERVAL '30 days'))*1000)::BIGINT AND NOT EXISTS(SELECT 1 FROM api_event_outbox o WHERE o.dedup_key='task:'||t.task_id||':'||t.task_status) ORDER BY t.id LIMIT 100 ON CONFLICT(dedup_key) DO NOTHING",&[]).await?;
    c.execute("INSERT INTO api_event_outbox(event_id,client_id,event_type,resource_id,payload,dedup_key) SELECT gen_random_uuid(),t.api_client_id,'asset.ready',e.execution_id,jsonb_build_object('task_id',t.task_id,'execution_id',e.execution_id),'projection:'||e.execution_id FROM scan_projection_outbox p JOIN scan_task_execution e ON e.id=p.execution_id JOIN scan_task t ON t.id=e.task_id WHERE p.processed_at>NOW()-INTERVAL '30 days' AND t.api_client_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM api_event_outbox o WHERE o.dedup_key='projection:'||e.execution_id) ORDER BY p.execution_id LIMIT 100 ON CONFLICT(dedup_key) DO NOTHING",&[]).await?;
    c.execute("INSERT INTO api_webhook_delivery(id,webhook_id,event_id) SELECT gen_random_uuid(),w.id,o.id FROM api_event_outbox o JOIN api_webhook w ON w.client_id=o.client_id AND w.enabled AND w.deleted_at IS NULL AND o.event_type=ANY(w.event_types) WHERE o.created_at>=w.created_at AND o.created_at>NOW()-INTERVAL '7 days' AND NOT EXISTS(SELECT 1 FROM api_webhook_delivery d WHERE d.webhook_id=w.id AND d.event_id=o.id) ORDER BY o.id LIMIT 100 ON CONFLICT(webhook_id,event_id) DO NOTHING",&[]).await?;
    c.commit().await?;
    Ok(())
}
pub(crate) async fn resource_allowed(
    pool: &Pool,
    p: &Principal,
    kind: &str,
    resource: &str,
    payload: &Value,
) -> Result<bool> {
    if !resources::event_allowed(p, kind) {
        return Ok(false);
    }
    if kind.starts_with("task.") || kind == "asset.ready" {
        let id = payload["task_id"].as_str().unwrap_or(resource);
        let c = pool.get().await?;
        return Ok(tasks::get(&c, p, id, false).await.is_ok());
    }
    if kind.starts_with("export.") || kind.starts_with("report.") {
        return Ok(payload["policy_revision"].as_i64() == Some(p.revision));
    }
    Ok(true)
}
pub(super) async fn process_delivery(pool: &Pool, encryption_key: &[u8]) -> Result<()> {
    let claim = Uuid::new_v4();
    let row = {
        let c = pool.get().await?;
        c.query_opt("WITH candidate AS (SELECT id FROM api_webhook_delivery WHERE (status='pending' OR (status='running' AND lease_expires_at<NOW())) AND next_attempt_at<=NOW() ORDER BY next_attempt_at FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE api_webhook_delivery d SET status='running',claim_token=$1,lease_expires_at=NOW()+INTERVAL '30 seconds',attempt_count=attempt_count+1 FROM candidate c WHERE d.id=c.id RETURNING d.*",&[&claim]).await?
    };
    let Some(row) = row else {
        return Ok(());
    };
    let id: Uuid = row.get("id");
    let webhook: Uuid = row.get("webhook_id");
    let event: i64 = row.get("event_id");
    let attempts: i32 = row.get("attempt_count");
    let result=tokio::time::timeout(std::time::Duration::from_secs(20),async {
        let (w,o)={let c=pool.get().await?;let w=c.query_opt("SELECT * FROM api_webhook WHERE id=$1 AND enabled AND deleted_at IS NULL",&[&webhook]).await?.ok_or_else(ApiError::forbidden)?;let o=c.query_one("SELECT * FROM api_event_outbox WHERE id=$1",&[&event]).await?;(w,o)};
        let (p,_,_)=auth::load(pool,w.get("credential_id")).await?;
        let kind:String=o.get("event_type");let resource:String=o.get("resource_id");let payload:Value=o.get("payload");
        if !p.has("webhooks:manage")||!w.get::<_,Vec<String>>("event_types").contains(&kind)&&kind!="webhook.test"||!resource_allowed(pool,&p,&kind,&resource,&payload).await? {return Err(ApiError::forbidden());}
        let url=resources::validate_webhook_url(&w.get::<_,String>("url"),&resources::allowed_webhook_hosts(pool).await?)?;
        let host=url.host_str().ok_or_else(ApiError::forbidden)?.to_owned();
        let addresses=tokio::net::lookup_host((host.as_str(),443)).await.map_err(|_|ApiError::unavailable())?.collect::<Vec<_>>();
        if addresses.is_empty()||addresses.iter().any(|a|!resources::public_ip(a.ip())){return Err(ApiError::forbidden());}
        let encrypted:Vec<u8>=w.get("signing_secret");if encrypted.len()<28{return Err(ApiError::unavailable());}
        let secret=crate::identity::decrypt_data(&encrypted,encryption_key).map_err(|_|ApiError::unavailable())?;
        let eid:Uuid=o.get("event_id");let value=json!({"id":eid,"type":kind,"version":1,"resource_id":resource,"payload":payload,"occurred_at":o.get::<_,chrono::DateTime<Utc>>("created_at")});let bytes=value.to_string();let timestamp=Utc::now().timestamp().to_string();
        let key=openssl::pkey::PKey::hmac(&secret).map_err(|_|ApiError::unavailable())?;let mut signer=openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(),&key).map_err(|_|ApiError::unavailable())?;
        signer.update(format!("{timestamp}.{bytes}").as_bytes()).map_err(|_|ApiError::unavailable())?;let signature=signer.sign_to_vec().map_err(|_|ApiError::unavailable())?.iter().map(|b|format!("{b:02x}")).collect::<String>();
        let client=reqwest::Client::builder().https_only(true).redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(10)).resolve_to_addrs(&host,&addresses).build().map_err(|_|ApiError::unavailable())?;
        let response=client.post(url).header("Content-Type","application/json").header("NM-Event-ID",eid.to_string()).header("NM-Event-Timestamp",timestamp).header("NM-Event-Signature",format!("v1={signature}")).body(bytes).send().await.map_err(|_|ApiError::unavailable())?;
        Ok::<_,ApiError>(response.status().as_u16())
    }).await.unwrap_or_else(|_|Err(ApiError::unavailable()));
    let (status, http, error) = match result {
        Ok(http) if (200..300).contains(&http) => ("succeeded", Some(http as i32), None),
        Ok(http) => (
            if attempts >= 5 { "failed" } else { "pending" },
            Some(http as i32),
            Some("receiver_rejected"),
        ),
        Err(e) => (
            if matches!(
                e.code,
                "scope_denied" | "invalid_credential" | "invalid_parameter"
            ) {
                "cancelled"
            } else if attempts >= 5 {
                "failed"
            } else {
                "pending"
            },
            None,
            Some(e.code),
        ),
    };
    let delay = (30i64 * 2i64.pow(attempts.min(7) as u32)).min(3600) as f64;
    pool.get().await?.execute("UPDATE api_webhook_delivery SET status=$3,response_status=$4,last_error=$5,next_attempt_at=NOW()+$6*INTERVAL '1 second',claim_token=NULL,lease_expires_at=NULL,finished_at=CASE WHEN $3='pending' THEN NULL ELSE NOW() END WHERE id=$1 AND claim_token=$2 AND status='running'",&[&id,&claim,&status,&http,&error,&delay]).await?;
    Ok(())
}
async fn retention(pool: &Pool) -> Result<()> {
    let c = pool.get().await?;
    c.batch_execute("DELETE FROM api_console_verification WHERE expires_at<NOW(); DELETE FROM api_console_verification_attempt WHERE bucket_start<NOW()-INTERVAL '1 day'; DELETE FROM api_cursor WHERE expires_at<NOW(); DELETE FROM api_idempotency_record WHERE created_at<NOW()-INTERVAL '24 hours'; UPDATE api_job SET status='failed',last_error='job_expired',claim_token=NULL,lease_expires_at=NULL,finished_at=NOW() WHERE expires_at<NOW() AND status IN ('queued','running'); UPDATE api_job SET artifact=NULL,result=NULL WHERE expires_at<NOW() AND (artifact IS NOT NULL OR result IS NOT NULL); DELETE FROM api_call_log WHERE created_at<NOW()-((SELECT COALESCE((document->>'retention_days')::INT,30) FROM api_platform_settings)*INTERVAL '1 day'); DELETE FROM api_audit WHERE created_at<NOW()-((SELECT COALESCE((document->>'audit_retention_days')::INT,180) FROM api_platform_settings)*INTERVAL '1 day'); DELETE FROM api_usage_bucket WHERE bucket_start<NOW()-INTERVAL '366 days'; DELETE FROM api_webhook_delivery WHERE created_at<NOW()-INTERVAL '30 days'; DELETE FROM api_event_outbox WHERE created_at<NOW()-INTERVAL '30 days' AND NOT EXISTS(SELECT 1 FROM api_webhook_delivery d WHERE d.event_id=api_event_outbox.id)").await?;
    Ok(())
}
