//! result_ingest / dns domain implementation, migrated from the library root.

use super::storage::dns_sidecar_upload_id;
use super::telemetry::WriteStage;
use crate::target_generated;

use deadpool_postgres::GenericClient;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::Duration;
use tokio_postgres::Row;
use tracing::{info, warn};
use uuid::Uuid;

use crate::elasticsearch::{DnsWriteMode, ElasticsearchService, ScanBatchContext};

use super::model::*;
use super::storage::{scanner_result_database_error, validate_execution_upload_ids};
use crate::clock::get_unix_epoch_ms;
use crate::identity::hash_scanner_token;
use crate::scan_control::creation::build_scan_plan;
use crate::scan_control::dispatch::refresh_task_aggregate;
use crate::{dns, dns_follow_up};

const DNS_BATCH_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

const DNS_BATCH_WRITE_LEASE_SECONDS: i64 = 45;

async fn record_dns_batch_write_error(
    pool: &deadpool_postgres::Pool,
    execution_id: i32,
    upload_id: &str,
    batch_index: i32,
    write_token: Uuid,
    message: &str,
) {
    let message = message.chars().take(2_000).collect::<String>();
    let Ok(Ok(client)) = tokio::time::timeout(Duration::from_secs(1), pool.get()).await else {
        warn!(
            event = "DnsBatchWriteErrorNotRecorded",
            execution_id, upload_id, batch_index, "无法获取 PostgreSQL 连接记录 DNS 批次写入错误"
        );
        return;
    };
    if let Err(error) = client
        .execute(
            "UPDATE scan_result_batch SET last_write_error = $5 \
             WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3 \
               AND storage_backend = 'pending' AND write_token = $4;",
            &[
                &execution_id,
                &upload_id,
                &batch_index,
                &write_token,
                &message,
            ],
        )
        .await
    {
        warn!(
            event = "DnsBatchWriteErrorNotRecorded",
            execution_id,
            upload_id,
            batch_index,
            %error,
            "记录 DNS 批次写入错误失败"
        );
    }
}

pub(crate) fn dns_batch_payload_checksum(
    execution_id: &str,
    upload_id: &str,
    batch_index: i32,
    is_final: bool,
    observations: &[&dns::DnsObservation],
) -> Result<String, SaveScannerResultsError> {
    let content = serde_json::to_vec(&serde_json::json!({
        "execution_id": execution_id,
        "upload_id": upload_id,
        "batch_index": batch_index,
        "is_final": is_final,
        "observations": observations,
    }))
    .map_err(scanner_result_database_error)?;
    Ok(openssl::sha::sha256(&content)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub(crate) async fn save_dns_scanner_results(
    pool: &deadpool_postgres::Pool,
    elasticsearch: &ElasticsearchService,
    dns_follow_up: &dns_follow_up::DnsFollowUpConfig,
    upload: &ScannerResultUpload,
    token: &str,
    token_pepper: &str,
    parent_upload_id: Option<Uuid>,
) -> Result<usize, SaveScannerResultsError> {
    if !elasticsearch.enabled() {
        return Err(SaveScannerResultsError::Storage(
            "DNS observations require elasticsearch.enabled=true".into(),
        ));
    }
    let observations = upload
        .observations
        .iter()
        .map(|item| match item {
            ScannerObservation::Dns { observation } => observation.clone().normalize(),
            _ => Err("a DNS upload batch may contain only DNS observations".to_owned()),
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(SaveScannerResultsError::InvalidUpload)?;
    let observation_count = i32::try_from(observations.len()).map_err(|_| {
        SaveScannerResultsError::ObservationLimitExceeded {
            actual: observations.len(),
            limit: i32::MAX as usize,
        }
    })?;
    let upload_id = upload
        .upload_id
        .expect("protocol v2 upload ID was validated")
        .to_string();
    let batch_index = i32::try_from(upload.batch_index.expect("protocol v2 batch was validated"))
        .map_err(|_| {
        SaveScannerResultsError::InvalidUpload("batch_index is too large".into())
    })?;
    let is_final = upload
        .is_final
        .expect("protocol v2 final flag was validated");
    let mut client = crate::db::acquire_write_connection(pool, "reserve_dns_batch")
        .await
        .map_err(scanner_result_database_error)?;
    let transaction = client
        .transaction()
        .await
        .map_err(scanner_result_database_error)?;
    transaction
        .batch_execute("SET LOCAL lock_timeout = '1500ms'; SET LOCAL statement_timeout = '5s';")
        .await
        .map_err(scanner_result_database_error)?;
    let token_hash =
        hash_scanner_token(token, token_pepper).map_err(scanner_result_database_error)?;
    let scanner_id = upload.scanner_id.to_string();
    let stage = WriteStage::new("authenticate_dns_execution");
    let scanner = transaction
        .query_opt(
            "SELECT id FROM scanner_info WHERE scanner_id = $1 AND runtime_token_hash = $2 AND is_enable = true;",
            &[&scanner_id, &token_hash],
        )
        .await
        .map_err(scanner_result_database_error)?;
    if scanner.is_none() {
        return Err(SaveScannerResultsError::ScannerUnauthorized);
    }
    let task = transaction
        .query_opt(
            "SELECT t.id AS task_id, t.user_id, t.task_port, t.task_level, t.remarks, t.generation_metadata, \
             e.id AS execution_id, e.execution_id AS public_execution_id, e.execution_status, t.task_source, \
             COALESCE(s.name, e.assigned_scanner_id) AS scanner_name \
             FROM scan_task t JOIN scan_task_execution e ON e.task_id = t.id \
             LEFT JOIN scanner_info s ON s.scanner_id = e.assigned_scanner_id \
             WHERE t.task_id = $1 AND e.assigned_scanner_id = $2 \
             AND e.execution_status IN ('running', 'succeeded') LIMIT 1 FOR UPDATE OF e;",
            &[&upload.task_id.to_string(), &scanner_id],
        )
        .await
        .map_err(scanner_result_database_error)?;
    let Some(task) = task else {
        return Err(SaveScannerResultsError::TaskNotFound);
    };
    stage.finish(true);
    let already_succeeded = task.get::<_, String>("execution_status") == "succeeded";

    let task_db_id: i32 = task.get("task_id");
    let execution_db_id: i32 = task.get("execution_id");
    let mut allowed_upload_ids = vec![upload_id.clone()];
    if let Some(parent) = parent_upload_id {
        debug_assert_eq!(upload.upload_id, Some(dns_sidecar_upload_id(parent)));
        debug_assert!(!is_final);
        allowed_upload_ids.push(parent.to_string());
    }
    let stage = WriteStage::new("dns_upload_identity");
    validate_execution_upload_ids(&transaction, execution_db_id, &allowed_upload_ids).await?;
    stage.finish(true);
    let context = ScanBatchContext {
        task_id: upload.task_id.to_string(),
        execution_id: task.get("public_execution_id"),
        user_id: task.get("user_id"),
        task_source: task.get("task_source"),
        scanner_id: scanner_id.clone(),
        scanner_name: task.get("scanner_name"),
        upload_id: upload_id.clone(),
        batch_index,
        is_final,
    };
    let follow_up_enabled = task
        .get::<_, Option<Value>>("generation_metadata")
        .as_ref()
        .and_then(|metadata| metadata.pointer("/dns_follow_up/enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let payload_checksum = dns_batch_payload_checksum(
        &context.execution_id,
        &upload_id,
        batch_index,
        is_final,
        &observations.iter().collect::<Vec<_>>(),
    )?;
    if is_final {
        let stage = WriteStage::new("validate_dns_final_sequence");
        let sequence = transaction
            .query_one(
                "SELECT COUNT(*) FILTER (WHERE batch_index < $3 AND storage_backend <> 'pending')::BIGINT AS prior_count, \
                 MIN(batch_index) FILTER (WHERE batch_index < $3) AS first_prior, \
                 MAX(batch_index) FILTER (WHERE batch_index < $3) AS last_prior, \
                 COUNT(*) FILTER (WHERE batch_index > $3)::BIGINT AS later_count, \
                 COUNT(*) FILTER (WHERE is_final)::BIGINT AS final_count, \
                 BOOL_OR(is_final) FILTER (WHERE batch_index = $3) AS current_is_final \
                 FROM scan_result_batch WHERE execution_id = $1 AND upload_id = $2;",
                &[&execution_db_id, &upload_id, &batch_index],
            )
            .await
            .map_err(scanner_result_database_error)?;
        let prior_count: i64 = sequence.get("prior_count");
        let first_prior: Option<i32> = sequence.get("first_prior");
        let last_prior: Option<i32> = sequence.get("last_prior");
        let complete_prior_sequence = if batch_index == 0 {
            prior_count == 0 && first_prior.is_none() && last_prior.is_none()
        } else {
            prior_count == i64::from(batch_index)
                && first_prior == Some(0)
                && last_prior == Some(batch_index - 1)
        };
        let final_count: i64 = sequence.get("final_count");
        let current_is_final: Option<bool> = sequence.get("current_is_final");
        let existing_final_valid = match current_is_final {
            Some(true) => final_count == 1,
            Some(false) => false,
            None => final_count == 0,
        };
        if !complete_prior_sequence
            || sequence.get::<_, i64>("later_count") != 0
            || !existing_final_valid
        {
            return Err(SaveScannerResultsError::NonContiguousFinalBatch {
                execution_id: execution_db_id,
                upload_id: upload_id.clone(),
                batch_index,
                content_kind: "DNS",
            });
        }
        stage.finish(true);
    }
    let stage = WriteStage::new("reserve_dns_receipt");
    let write_token = Uuid::new_v4();
    let (write_attempts, write_mode) = if let Some(existing) = transaction
        .query_opt(
            "SELECT is_final, observation_count, payload_checksum, storage_backend FROM scan_result_batch \
             WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3;",
            &[&execution_db_id, &upload_id, &batch_index],
        )
        .await
        .map_err(scanner_result_database_error)?
    {
        let existing_checksum: Option<String> = existing.get("payload_checksum");
        let matches = existing.get::<_, bool>("is_final") == is_final
            && existing.get::<_, i32>("observation_count") == observation_count
            && existing_checksum.as_deref() == Some(payload_checksum.as_str());
        if !matches {
            return Err(SaveScannerResultsError::BatchPayloadConflict {
                execution_id: execution_db_id,
                upload_id: upload_id.clone(),
                batch_index,
                content_kind: "DNS",
                expected_checksum: existing_checksum,
                received_checksum: payload_checksum.clone(),
            });
        }
        if existing.get::<_, String>("storage_backend") != "pending" {
            transaction
                .commit()
                .await
                .map_err(scanner_result_database_error)?;
            stage.finish(true);
            return Ok(0);
        }
        let claimed = transaction
            .query_opt(
                "UPDATE scan_result_batch SET write_token = $4, \
                 write_lease_expires_at = clock_timestamp() + ($5::BIGINT * INTERVAL '1 second'), \
                 write_started_at = clock_timestamp(), write_attempts = write_attempts + 1, \
                 last_write_error = NULL \
                 WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3 \
                   AND storage_backend = 'pending' \
                   AND (write_token IS NULL OR write_lease_expires_at IS NULL \
                        OR write_lease_expires_at <= clock_timestamp()) \
                 RETURNING write_attempts;",
                &[
                    &execution_db_id,
                    &upload_id,
                    &batch_index,
                    &write_token,
                    &DNS_BATCH_WRITE_LEASE_SECONDS,
                ],
            )
            .await
            .map_err(scanner_result_database_error)?;
        let Some(claimed) = claimed else {
            let retry_after: i64 = transaction
                .query_one(
                    "SELECT GREATEST(1, CEIL(EXTRACT(EPOCH FROM \
                     (write_lease_expires_at - clock_timestamp())))::BIGINT) \
                     FROM scan_result_batch \
                     WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3;",
                    &[&execution_db_id, &upload_id, &batch_index],
                )
                .await
                .map_err(scanner_result_database_error)?
                .get(0);
            return Err(SaveScannerResultsError::BatchBusy {
                retry_after_seconds: u64::try_from(retry_after).unwrap_or(1),
            });
        };
        (
            claimed.get::<_, i32>("write_attempts"),
            DnsWriteMode::Reconcile,
        )
    } else {
        if already_succeeded {
            return Err(SaveScannerResultsError::CompletedExecutionNewBatch {
                execution_id: execution_db_id,
                upload_id: upload_id.clone(),
                batch_index,
            });
        }
        let write_attempts = transaction
            .query_one(
                "INSERT INTO scan_result_batch (execution_id, upload_id, batch_index, is_final, observation_count, \
                 protocol_version, payload_checksum, storage_backend, storage_references, write_token, \
                 write_lease_expires_at, write_attempts, write_started_at) \
                 VALUES ($1, $2, $3, $4, $5, 2, $6, 'pending', '[]'::JSONB, $7, \
                         clock_timestamp() + ($8::BIGINT * INTERVAL '1 second'), 1, clock_timestamp()) \
                 RETURNING write_attempts;",
                &[
                    &execution_db_id,
                    &upload_id,
                    &batch_index,
                    &is_final,
                    &observation_count,
                    &payload_checksum,
                    &write_token,
                    &DNS_BATCH_WRITE_LEASE_SECONDS,
                ],
            )
            .await
            .map_err(scanner_result_database_error)?
            .get::<_, i32>("write_attempts");
        (write_attempts, DnsWriteMode::Fresh)
    };
    // `pending` 是持久化的上传占位符。先提交占位符再访问 ES，可以释放任务行锁和
    // PostgreSQL 连接；进程中断后，同一批次会从 pending 状态幂等重试。
    transaction
        .commit()
        .await
        .map_err(scanner_result_database_error)?;
    drop(client);
    stage.finish(true);
    info!(
        event = "DnsBatchWriteClaimed",
        execution_id = execution_db_id,
        upload_id,
        batch_index,
        write_attempts,
        mode = ?write_mode,
        "DNS 批次写入租约已领取"
    );
    let stage = WriteStage::new("write_dns_elasticsearch");
    let dns_references = match tokio::time::timeout(
        DNS_BATCH_WRITE_TIMEOUT,
        elasticsearch.persist_dns_observations(&context, "default", &observations, write_mode),
    )
    .await
    {
        Ok(Ok(references)) => references,
        Ok(Err(message)) => {
            record_dns_batch_write_error(
                pool,
                execution_db_id,
                &upload_id,
                batch_index,
                write_token,
                &message,
            )
            .await;
            return Err(SaveScannerResultsError::Storage(message));
        }
        Err(_) => {
            let message = "DNS Elasticsearch 持久化超过固定 30 秒时间预算".to_owned();
            record_dns_batch_write_error(
                pool,
                execution_db_id,
                &upload_id,
                batch_index,
                write_token,
                &message,
            )
            .await;
            return Err(SaveScannerResultsError::Storage(message));
        }
    };
    stage.finish(true);
    let mut client = crate::db::acquire_write_connection(pool, "confirm_dns_batch")
        .await
        .map_err(scanner_result_database_error)?;
    let stage = WriteStage::new("confirm_dns_receipt");
    let transaction = client
        .transaction()
        .await
        .map_err(scanner_result_database_error)?;
    transaction
        .batch_execute("SET LOCAL lock_timeout = '1500ms'; SET LOCAL statement_timeout = '10s';")
        .await
        .map_err(scanner_result_database_error)?;
    let current_execution = transaction
        .query_one("SELECT execution_status, assigned_scanner_id FROM scan_task_execution WHERE id = $1 FOR UPDATE", &[&execution_db_id])
        .await.map_err(scanner_result_database_error)?;
    if !matches!(
        current_execution
            .get::<_, String>("execution_status")
            .as_str(),
        "running" | "succeeded"
    ) || current_execution
        .get::<_, Option<String>>("assigned_scanner_id")
        .as_deref()
        != Some(scanner_id.as_str())
    {
        return Err(SaveScannerResultsError::TaskNotOwned);
    }
    let receipt_updated = transaction
        .execute(
            "UPDATE scan_result_batch SET storage_backend = 'elasticsearch', storage_references = $4, \
             write_token = NULL, write_lease_expires_at = NULL, last_write_error = NULL \
             WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3 \
             AND storage_backend = 'pending' AND write_token = $5;",
            &[
                &execution_db_id,
                &upload_id,
                &batch_index,
                &serde_json::json!(dns_references),
                &write_token,
            ],
        )
        .await
        .map_err(scanner_result_database_error)?;
    if receipt_updated == 0 {
        let receipt = transaction
            .query_one(
                "SELECT storage_backend, GREATEST(1, COALESCE(CEIL(EXTRACT(EPOCH FROM \
                 (write_lease_expires_at - clock_timestamp())))::BIGINT, 1)) AS retry_after \
                 FROM scan_result_batch \
                 WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3;",
                &[&execution_db_id, &upload_id, &batch_index],
            )
            .await
            .map_err(scanner_result_database_error)?;
        if receipt.get::<_, String>("storage_backend") != "pending" {
            stage.finish(true);
            transaction
                .commit()
                .await
                .map_err(scanner_result_database_error)?;
            return Ok(0);
        }
        let retry_after: i64 = receipt.get("retry_after");
        return Err(SaveScannerResultsError::BatchBusy {
            retry_after_seconds: u64::try_from(retry_after).unwrap_or(1),
        });
    }
    stage.finish(true);
    if follow_up_enabled {
        let resolved_ips = resolved_dns_answer_ips(&observations);
        if !resolved_ips.is_empty() {
            let values = resolved_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            transaction
                .execute(
                    "INSERT INTO dns_resolved_address (execution_id, task_id, ip_address) \
                     SELECT $1, $2, value::INET FROM UNNEST($3::TEXT[]) AS value \
                     ON CONFLICT (execution_id, ip_address) DO NOTHING;",
                    &[&execution_db_id, &task_db_id, &values],
                )
                .await
                .map_err(scanner_result_database_error)?;
        }
    }
    if is_final {
        transaction
            .execute(
                "UPDATE scan_task_execution SET execution_status = 'succeeded', task_end_time = $1, \
                 lease_expires_at = NULL, failure_reason = NULL, cancel_requested = false, \
                 maintenance_hold = FALSE, maintenance_hold_until = NULL, \
                 result_ip_count = 0, result_port_count = 0, result_observation_count = (SELECT COALESCE(SUM(observation_count), 0) FROM scan_result_batch WHERE execution_id = $2) WHERE id = $2;",
                &[&get_unix_epoch_ms(), &execution_db_id],
            )
            .await
            .map_err(scanner_result_database_error)?;
        let stage = WriteStage::new("refresh_dns_task_aggregate");
        refresh_task_aggregate(&transaction, task_db_id)
            .await
            .map_err(scanner_result_database_error)?;
        stage.finish(true);
        if follow_up_enabled {
            let stage = WriteStage::new("create_dns_follow_up_tasks");
            create_dns_follow_up_tasks(
                &transaction,
                &task,
                dns_follow_up,
                task_db_id,
                execution_db_id,
            )
            .await
            .map_err(scanner_result_database_error)?;
            stage.finish(true);
        }
        let stage = WriteStage::new("update_dns_target_freshness");
        target_generated::search::record_success(&transaction, task_db_id)
            .await
            .map_err(scanner_result_database_error)?;
        stage.finish(true);
    }
    let stage = WriteStage::new("commit_dns_receipt");
    transaction
        .commit()
        .await
        .map_err(scanner_result_database_error)?;
    stage.finish(true);
    Ok(usize::try_from(observation_count).expect("non-negative observation count"))
}

fn resolved_dns_answer_ips(observations: &[dns::DnsObservation]) -> Vec<IpAddr> {
    observations
        .iter()
        .flat_map(|observation| observation.answers.iter())
        .filter(|answer| matches!(answer.record_type.as_str(), "A" | "AAAA"))
        .filter_map(|answer| answer.value.parse::<IpAddr>().ok())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

async fn create_dns_follow_up_tasks(
    transaction: &deadpool_postgres::Transaction<'_>,
    parent: &Row,
    policy: &dns_follow_up::DnsFollowUpConfig,
    parent_task_id: i32,
    parent_execution_id: i32,
) -> Result<(), tokio_postgres::Error> {
    let metadata: Value = parent.get("generation_metadata");
    let Some(follow_up) = metadata.get("dns_follow_up") else {
        return Ok(());
    };
    if follow_up.get("enabled").and_then(Value::as_bool) != Some(true) {
        return Ok(());
    }
    let scan_profile = follow_up
        .get("scan_profile")
        .and_then(Value::as_str)
        .unwrap_or("port_only");
    let stored_addresses = transaction
        .query(
            "SELECT host(ip_address) AS ip FROM dns_resolved_address WHERE execution_id = $1 ORDER BY ip_address;",
            &[&parent_execution_id],
        )
        .await?;
    let mut targets = BTreeMap::<&str, Vec<String>>::new();
    for row in stored_addresses {
        let ip: String = row.get("ip");
        let Ok(parsed) = ip.parse::<IpAddr>() else {
            continue;
        };
        if policy.enabled && policy.allows(parsed) {
            targets
                .entry(if parsed.is_ipv4() { "ipv4" } else { "ipv6" })
                .or_default()
                .push(parsed.to_string());
        }
    }
    let eligible_ip_count = targets.values().map(Vec::len).sum::<usize>();
    if !policy.enabled {
        transaction
            .execute(
                "INSERT INTO dns_follow_up_generation (execution_id, status, eligible_ip_count, created_task_count) \
                 VALUES ($1, 'blocked_policy', 0, 0) ON CONFLICT (execution_id) DO NOTHING;",
                &[&parent_execution_id],
            )
            .await?;
        return Ok(());
    }
    if eligible_ip_count == 0 {
        transaction
            .execute(
                "INSERT INTO dns_follow_up_generation (execution_id, status, eligible_ip_count, created_task_count) \
                 VALUES ($1, 'no_eligible_ip', 0, 0) ON CONFLICT (execution_id) DO NOTHING;",
                &[&parent_execution_id],
            )
            .await?;
        return Ok(());
    }
    let claimed = transaction
        .execute(
            "INSERT INTO dns_follow_up_generation (execution_id, status, eligible_ip_count, created_task_count) \
             VALUES ($1, 'succeeded', $2, 0) ON CONFLICT (execution_id) DO NOTHING;",
            &[&parent_execution_id, &(eligible_ip_count as i32)],
        )
        .await?;
    if claimed == 0 {
        return Ok(());
    }

    let user_id: i32 = parent.get("user_id");
    let port: String = parent.get("task_port");
    let level: i32 = parent.get("task_level");
    let parent_public_execution_id: String = parent.get("public_execution_id");
    let scan_plan =
        build_scan_plan(scan_profile).expect("stored DNS follow-up profile was validated");
    let mut created_task_count = 0_i32;
    for (family, family_targets) in targets {
        for (chunk_index, chunk) in family_targets
            .chunks(usize::from(policy.max_targets_per_task))
            .enumerate()
        {
            let task_id = Uuid::now_v7().to_string();
            let metadata = serde_json::json!({
                "dns_follow_up": {
                    "parent_task_id": parent_task_id,
                    "parent_execution_id": parent_public_execution_id,
                    "source": "dns_a_aaaa_answer",
                }
            });
            let task_pk: i32 = transaction
                .query_one(
                    "INSERT INTO scan_task (user_id, task_id, task_initiator, task_target, task_port, task_level, remarks, \
                     dispatch_mode, task_source, generation_strategy, generation_key, generation_metadata, address_family, scan_profile, scan_plan) \
                     VALUES ($1, $2, 'system', ARRAY(SELECT value::INET FROM UNNEST($3::TEXT[]) AS value), $4, $5, \
                     'DNS 解析自动生成端口扫描任务', 'automatic', 'dns_follow_up', 'dns_resolution', $6, $7, $8, $9, $10) \
                     RETURNING id;",
                    &[
                        &user_id,
                        &task_id,
                        &chunk,
                        &port,
                        &level,
                        &format!("dns:{parent_public_execution_id}:{family}:{chunk_index}"),
                        &metadata,
                        &family,
                        &scan_profile,
                        &scan_plan,
                    ],
                )
                .await?
                .get("id");
            transaction
                .execute(
                    "INSERT INTO scan_task_execution (execution_id, task_id, requested_scanner_id) VALUES ($1, $2, NULL);",
                    &[&Uuid::now_v7().to_string(), &task_pk],
                )
                .await?;
            transaction
                .execute(
                    "INSERT INTO scan_task_lineage (parent_task_id, parent_execution_id, child_task_id, source_addresses) \
                     VALUES ($1, $2, $3, ARRAY(SELECT value::INET FROM UNNEST($4::TEXT[]) AS value));",
                    &[&parent_task_id, &parent_execution_id, &task_pk, &chunk],
                )
                .await?;
            created_task_count += 1;
        }
    }
    transaction
        .execute(
            "UPDATE dns_follow_up_generation SET created_task_count = $2 WHERE execution_id = $1;",
            &[&parent_execution_id, &created_task_count],
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod dns_follow_up_tests {
    use super::resolved_dns_answer_ips;
    use crate::dns::{DnsAnswer, DnsObservation, DnsQuestion};

    fn observation(answers: Vec<(&str, &str)>) -> DnsObservation {
        DnsObservation {
            observed_at: 1,
            question: DnsQuestion {
                name: "example.test".into(),
                record_type: "A".into(),
                class: "IN".into(),
            },
            response_code: "NOERROR".into(),
            authoritative: false,
            truncated: false,
            dnssec_authenticated: false,
            answers: answers
                .into_iter()
                .map(|(record_type, value)| DnsAnswer {
                    record_type: record_type.into(),
                    value: value.into(),
                    ttl: 60,
                    priority: None,
                    weight: None,
                    port: None,
                })
                .collect(),
            authority: Vec::new(),
            additional: Vec::new(),
            resolver_ip: None,
            resolver_id: None,
            resolver_label: None,
            resolver_port: None,
            resolver_transport: None,
            latency_ms: None,
        }
    }

    #[test]
    fn resolved_dns_addresses_include_only_unique_a_and_aaaa_answers() {
        let resolved = resolved_dns_answer_ips(&[
            observation(vec![
                ("A", "192.0.2.10"),
                ("AAAA", "2001:db8::10"),
                ("CNAME", "alias.example.test"),
            ]),
            observation(vec![("A", "192.0.2.10"), ("A", "not-an-ip")]),
        ]);
        assert_eq!(
            resolved
                .into_iter()
                .map(|address| address.to_string())
                .collect::<Vec<_>>(),
            vec!["192.0.2.10", "2001:db8::10"]
        );
    }
}
