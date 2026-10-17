//! result_ingest / storage domain implementation, migrated from the library root.

use super::dns::dns_batch_payload_checksum;
use super::telemetry::WriteStage;
use super::upload_stream;
use crate::{search_content, target_generated};
use tracing::{Instrument, info_span};

use deadpool_postgres::GenericClient;
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

use crate::elasticsearch::{ElasticsearchService, ScanBatchContext, scan_batch_payload_checksum};
use crate::maxmind::MaxMindState;

use super::dns::save_dns_scanner_results;
use super::model::*;
use super::validation::*;
use crate::clock::get_unix_epoch_ms;
use crate::identity::hash_scanner_token;
use crate::scan_control::dispatch::refresh_task_aggregate;
use crate::scan_control::target::scan_observation_addresses;
use crate::{db, dns_follow_up};

pub(crate) fn scanner_result_database_error<E>(value: E) -> SaveScannerResultsError
where
    E: std::error::Error + Send + Sync + 'static,
{
    SaveScannerResultsError::Database(Box::new(value))
}

pub(crate) fn dns_sidecar_upload_id(upload_id: Uuid) -> Uuid {
    let digest = openssl::sha::sha256(format!("dns-observations:{upload_id}").as_bytes());
    Uuid::from_slice(&digest[..16]).expect("SHA-256 prefix has UUID length")
}

pub(crate) async fn validate_execution_upload_ids(
    transaction: &tokio_postgres::Transaction<'_>,
    execution_id: i32,
    upload_ids: &[String],
) -> Result<(), SaveScannerResultsError> {
    upload_stream::repair_deleted_receipts(transaction, execution_id).await?;
    let conflict = transaction
        .query_one(
            "SELECT COUNT(DISTINCT upload_id)::BIGINT AS conflicting_count, \
                    MIN(upload_id) AS conflicting_upload_id \
             FROM scan_upload_stream \
             WHERE execution_id = $1 AND NOT (upload_id = ANY($2::TEXT[]));",
            &[&execution_id, &upload_ids],
        )
        .await
        .map_err(scanner_result_database_error)?;
    let conflicting_upload_count: i64 = conflict.get("conflicting_count");
    if let Some(conflicting_upload_id) = conflict.get("conflicting_upload_id") {
        return Err(SaveScannerResultsError::UploadIdentityConflict {
            execution_id,
            received_upload_id: upload_ids.first().cloned().unwrap_or_default(),
            conflicting_upload_id,
            conflicting_upload_count,
        });
    }
    Ok(())
}

pub async fn save_scanner_results(
    pool: &deadpool_postgres::Pool,
    maxmind: &MaxMindState,
    elasticsearch: &ElasticsearchService,
    dns_follow_up: &dns_follow_up::DnsFollowUpConfig,
    upload: &ScannerResultUpload,
    token: &str,
    token_pepper: &str,
) -> Result<usize, SaveScannerResultsError> {
    let span = info_span!("ScanResultUpload",
        request_id = tracing::field::Empty,
        scanner_id = %upload.scanner_id, task_id = %upload.task_id,
        upload_id = ?upload.upload_id, batch_index = ?upload.batch_index,
        is_final = ?upload.is_final, protocol_version = upload.protocol_version,
        observation_count = upload.observations.len(),
    );
    if let Ok(request_id) = super::telemetry::UPLOAD_REQUEST_ID.try_with(|id| *id) {
        span.record("request_id", tracing::field::display(request_id));
    }
    async {
        let stage = WriteStage::new("upload");
        let result = save_scanner_results_inner(
            pool,
            maxmind,
            elasticsearch,
            dns_follow_up,
            upload,
            token,
            token_pepper,
        )
        .await;
        stage.finish(result.is_ok());
        result
    }
    .instrument(span)
    .await
}

async fn save_scanner_results_inner(
    pool: &deadpool_postgres::Pool,
    maxmind: &MaxMindState,
    elasticsearch: &ElasticsearchService,
    dns_follow_up: &dns_follow_up::DnsFollowUpConfig,
    upload: &ScannerResultUpload,
    token: &str,
    token_pepper: &str,
) -> Result<usize, SaveScannerResultsError> {
    let is_typed = matches!(upload.protocol_version, 2 | 3);
    if upload.protocol_version != 1 && !is_typed {
        return Err(SaveScannerResultsError::UnsupportedProtocolVersion {
            received: upload.protocol_version,
        });
    }
    if is_typed
        && (upload.upload_id.is_none()
            || upload.batch_index.is_none()
            || upload.is_final.is_none()
            || !upload.results.is_empty())
    {
        return Err(SaveScannerResultsError::InvalidBatchEnvelope {
            protocol_version: upload.protocol_version,
            reason: "typed result protocols require upload_id, batch_index and is_final, accept only observations, and limit each batch to 500 observations",
        });
    }
    if is_typed && upload.observations.len() > 500 {
        return Err(SaveScannerResultsError::ObservationLimitExceeded {
            actual: upload.observations.len(),
            limit: 500,
        });
    }
    if !is_typed && !upload.observations.is_empty() {
        return Err(SaveScannerResultsError::InvalidBatchEnvelope {
            protocol_version: upload.protocol_version,
            reason: "typed observations require protocol_version 2 or 3",
        });
    }
    if upload.protocol_version == 2
        && upload
            .observations
            .iter()
            .any(|item| matches!(item, ScannerObservation::Vulnerability { .. }))
    {
        return Err(SaveScannerResultsError::InvalidBatchEnvelope {
            protocol_version: upload.protocol_version,
            reason: "vulnerability observations require protocol_version 3",
        });
    }

    let mut regular_upload = upload.clone();
    regular_upload
        .observations
        .retain(|item| !matches!(item, ScannerObservation::Dns { .. }));
    let mut dns_upload = upload.clone();
    dns_upload
        .observations
        .retain(|item| matches!(item, ScannerObservation::Dns { .. }));
    // Route DNS-only tasks by their persisted profile, not by this batch's
    // contents: a dns_full upload can start or end with a DNS-only batch.
    if is_typed && regular_upload.observations.is_empty() {
        let client = db::acquire_write_connection(pool, "classify_scan_profile")
            .await
            .map_err(scanner_result_database_error)?;
        let dns_only = client
            .query_opt(
                "SELECT scan_profile FROM scan_task WHERE task_id = $1;",
                &[&upload.task_id.to_string()],
            )
            .await
            .map_err(scanner_result_database_error)?
            .is_some_and(|row| row.get::<_, String>("scan_profile") == "dns_records");
        drop(client);
        if dns_only {
            return save_dns_scanner_results(
                pool,
                elasticsearch,
                dns_follow_up,
                upload,
                token,
                token_pepper,
                None,
                Some(maxmind),
            )
            .await;
        }
    }
    let normalized_observations = normalize_upload_observations(&regular_upload)?;
    // Normalize before reserving a primary receipt, so invalid DNS cannot leave
    // a permanently pending batch behind.
    for item in &mut dns_upload.observations {
        if let ScannerObservation::Dns { observation } = item {
            *observation = observation
                .clone()
                .normalize()
                .map_err(SaveScannerResultsError::InvalidUpload)?;
        }
    }
    if !dns_upload.observations.is_empty() && !elasticsearch.enabled() {
        return Err(SaveScannerResultsError::Storage(
            "DNS observations require elasticsearch.enabled=true".into(),
        ));
    }

    let mut client = db::acquire_write_connection(pool, "reserve_scan_batch")
        .await
        .map_err(scanner_result_database_error)?;
    let transaction = client
        .transaction()
        .await
        .map_err(scanner_result_database_error)?;
    transaction
        .batch_execute("SET LOCAL lock_timeout = '1500ms'; SET LOCAL statement_timeout = '10s';")
        .await
        .map_err(scanner_result_database_error)?;
    let token_hash =
        hash_scanner_token(token, token_pepper).map_err(scanner_result_database_error)?;
    let scanner_id = upload.scanner_id.to_string();

    let stage = WriteStage::new("authenticate_execution");
    let scanner = transaction.query_opt(
        "SELECT id FROM scanner_info WHERE scanner_id = $1 AND runtime_token_hash = $2 AND is_enable = true;",
        &[&scanner_id, &token_hash]
    ).await.map_err(scanner_result_database_error)?;

    if scanner.is_none() {
        return Err(SaveScannerResultsError::ScannerUnauthorized);
    }

    let task_row = transaction
        .query_opt(
            "SELECT t.id AS task_id, t.user_id, e.id AS execution_id, e.execution_id AS public_execution_id, \
             e.execution_status, e.task_start_time, t.task_source, COALESCE(s.name, e.assigned_scanner_id) AS scanner_name \
             FROM scan_task t JOIN scan_task_execution e ON e.task_id = t.id \
             LEFT JOIN scanner_info s ON s.scanner_id = e.assigned_scanner_id \
             WHERE t.task_id = $1 AND e.assigned_scanner_id = $2 \
             AND e.execution_status IN ('running', 'succeeded') LIMIT 1 FOR UPDATE OF e;",
            &[&upload.task_id.to_string(), &scanner_id],
        )
        .await
        .map_err(scanner_result_database_error)?;

    stage.finish(true);
    let already_succeeded = task_row
        .as_ref()
        .is_some_and(|row| row.get::<_, String>("execution_status") == "succeeded");

    let (
        task_db_id,
        user_id,
        execution_db_id,
        public_execution_id,
        task_start_time,
        task_source,
        scanner_name,
    ): (i32, i32, i32, String, Option<i64>, String, Option<String>) = match task_row {
        Some(row) => (
            row.get("task_id"),
            row.get("user_id"),
            row.get("execution_id"),
            row.get("public_execution_id"),
            row.get("task_start_time"),
            row.get("task_source"),
            row.get("scanner_name"),
        ),
        None => return Err(SaveScannerResultsError::TaskNotFound),
    };

    let (upload_id, batch_index, is_final) = if is_typed {
        (
            upload.upload_id.expect("validated above").to_string(),
            i32::try_from(upload.batch_index.expect("validated above")).map_err(|_| {
                SaveScannerResultsError::InvalidUpload("batch_index is too large".into())
            })?,
            upload.is_final.expect("validated above"),
        )
    } else {
        (public_execution_id.clone(), 0, true)
    };
    let batch_context = ScanBatchContext {
        task_id: upload.task_id.to_string(),
        execution_id: public_execution_id.clone(),
        user_id,
        task_source: task_source.clone(),
        scanner_id: scanner_id.clone(),
        scanner_name: scanner_name.clone(),
        upload_id: upload_id.clone(),
        batch_index,
        is_final,
    };
    let sidecar_upload_id = if is_typed {
        upload.upload_id.map(dns_sidecar_upload_id)
    } else {
        None
    };
    let sidecar_identity = sidecar_upload_id.map(|id| id.to_string());
    let mut allowed_upload_ids = vec![upload_id.clone()];
    allowed_upload_ids.extend(sidecar_identity.iter().cloned());
    let stage = WriteStage::new("upload_identity");
    validate_execution_upload_ids(&transaction, execution_db_id, &allowed_upload_ids).await?;
    stage.finish(true);
    // Older servers may have committed the DNS child before creating the primary
    // receipt. Validate that child first so a changed retry cannot reserve (and
    // poison) the primary identity or silently drop already persisted DNS data.
    if let Some(sidecar) = &sidecar_identity
        && let Some(existing) = transaction
            .query_opt(
                "SELECT is_final, observation_count, payload_checksum FROM scan_result_batch \
             WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3;",
                &[&execution_db_id, sidecar, &batch_index],
            )
            .await
            .map_err(scanner_result_database_error)?
    {
        let observations = dns_upload
            .observations
            .iter()
            .filter_map(|item| match item {
                ScannerObservation::Dns { observation } => Some(observation),
                _ => None,
            })
            .collect::<Vec<_>>();
        let expected = dns_batch_payload_checksum(
            &public_execution_id,
            sidecar,
            batch_index,
            false,
            &observations,
        )?;
        let existing_checksum: Option<String> = existing.get("payload_checksum");
        if observations.is_empty()
            || existing.get::<_, bool>("is_final")
            || existing.get::<_, i32>("observation_count") as usize != observations.len()
            || existing_checksum.as_deref() != Some(expected.as_str())
        {
            return Err(SaveScannerResultsError::BatchPayloadConflict {
                execution_id: execution_db_id,
                upload_id: upload_id.clone(),
                batch_index,
                content_kind: "DNS",
                expected_checksum: existing_checksum,
                received_checksum: expected,
            });
        }
    }
    if is_final {
        let stage = WriteStage::new("validate_final_sequence");
        upload_stream::validate_final(
            &transaction,
            execution_db_id,
            &upload_id,
            batch_index,
            "scan result",
            false,
        )
        .await?;
        stage.finish(true);
    }
    let observation_count = i32::try_from(normalized_observations.len()).map_err(|_| {
        SaveScannerResultsError::ObservationLimitExceeded {
            actual: normalized_observations.len(),
            limit: i32::MAX as usize,
        }
    })?;
    let protocol_version = i16::try_from(upload.protocol_version).expect("validated above");
    let stage = WriteStage::new("enrich_observations");
    let mut observation_rows = Vec::with_capacity(normalized_observations.len());
    let mut ip_intel_cache = HashMap::new();
    let fallback_observed_at = task_start_time.unwrap_or_else(get_unix_epoch_ms);
    for observation in &normalized_observations {
        let (ip_address, ip_network, parsed_ip) = scan_observation_addresses(&observation.ip)
            .map_err(|source_error| SaveScannerResultsError::InvalidIp {
                ip: observation.ip.clone(),
                source: source_error,
            })?;
        let observation_key = serde_json::to_string(&serde_json::json!([
            observation.kind,
            ip_network,
            observation.port,
            observation.protocol,
            observation.service,
            observation.source,
            observation
                .data
                .as_ref()
                .and_then(|value| value.get("template_id")),
            observation
                .data
                .as_ref()
                .and_then(|value| value.get("matcher_name")),
            observation
                .data
                .as_ref()
                .and_then(|value| value.get("matched_at"))
        ]))
        .map_err(scanner_result_database_error)?;
        let endpoint_id = openssl::sha::sha256(
            format!(
                "{}\0{}\0{}",
                public_execution_id, ip_network, observation.port
            )
            .as_bytes(),
        )
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
        let intel = ip_intel_cache
            .entry(parsed_ip)
            .or_insert_with(|| maxmind.lookup(parsed_ip))
            .clone();
        let search_content = search_content::extract_search_content(observation.data.as_ref());
        let observed_at = observation.observed_at.unwrap_or(fallback_observed_at);
        if observed_at <= 0 || observed_at > get_unix_epoch_ms().saturating_add(86_400_000) {
            return Err(SaveScannerResultsError::InvalidUpload(
                "observed_at must be a Unix epoch millisecond value no more than 24 hours in the future".into(),
            ));
        }
        observation_rows.push(serde_json::json!({
            "observation_key": observation_key,
            "endpoint_id": endpoint_id,
            "kind": observation.kind,
            // `ip` fields reject CIDR strings. Preserve the network separately
            // as `ip_range`, including /32 and /128 single-host networks.
            "ip_address": ip_address,
            "ip_network": ip_network,
            "port": i32::from(observation.port),
            "protocol": observation.protocol,
            "service": observation.service,
            "banner": observation.banner,
            "title": search_content.title,
            "http_body": search_content.http_body,
            "http_body_truncated": search_content.http_body_truncated,
            "tls_mode": search_content.tls_mode,
            "tls_version": search_content.tls_version,
            "tls_cipher_suite": search_content.tls_cipher_suite,
            "tls_subject": search_content.tls_subject,
            "tls_issuer": search_content.tls_issuer,
            "tls_names": search_content.tls_names,
            "tls_serial_number": search_content.tls_serial_number,
            "tls_not_before": search_content.tls_not_before,
            "tls_not_after": search_content.tls_not_after,
            "tls_fingerprint_sha256": search_content.tls_fingerprint_sha256,
            "tls_self_signed": search_content.tls_self_signed,
            "search_content_extracted": true,
            "source": observation.source,
            "data": observation.data,
            "observed_at": observed_at,
            "asn": intel.asn,
            "isp": intel.isp,
            "as_org": intel.as_org,
            "country_code": intel.country_code,
            "country_name": intel.country_name,
            "region_name": intel.region_name,
            "city_name": intel.city_name,
            "latitude": intel.latitude,
            "longitude": intel.longitude,
        }));
    }
    stage.finish(true);
    if !observation_rows.is_empty() {
        let stage = WriteStage::new("load_asset_tags");
        let addresses = observation_rows
            .iter()
            .filter_map(|row| {
                row.get("ip_network")
                    .or_else(|| row.get("ip_address"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let tag_rows = transaction
            .query(
                "SELECT host(assignment.ip_address) AS ip, JSONB_AGG(JSONB_BUILD_OBJECT( \
                    'id', tag.id, 'name', tag.name, 'kind', tag.kind, 'description', tag.description, \
                    'category_id', category.id, 'category_name', category.name) \
                    ORDER BY category.sort_order, LOWER(category.name), tag.id) AS tags \
                 FROM asset_ip_tag assignment JOIN asset_tag tag ON tag.id = assignment.tag_id \
                 JOIN asset_tag_category category ON category.id = tag.category_id \
                 WHERE tag.is_active AND category.is_active AND assignment.ip_address IN \
                    (SELECT address::INET FROM UNNEST($1::TEXT[]) address) \
                 GROUP BY assignment.ip_address;",
                &[&addresses],
            )
            .await
            .map_err(scanner_result_database_error)?;
        let tags_by_ip = tag_rows
            .into_iter()
            .map(|row| (row.get::<_, String>("ip"), row.get::<_, Value>("tags")))
            .collect::<HashMap<_, _>>();
        for row in &mut observation_rows {
            let tags = row
                .get("ip_address")
                .and_then(Value::as_str)
                .and_then(|ip| tags_by_ip.get(ip))
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new()));
            row.as_object_mut()
                .expect("observation row is object")
                .insert("tags".to_owned(), tags);
        }
        stage.finish(true);
    }
    let storage_backend = "elasticsearch";
    let (transaction, es_execution_summary) = {
        let stage = WriteStage::new("reserve_scan_receipt");
        let es_checksum = scan_batch_payload_checksum(&batch_context, &observation_rows)
            .map_err(SaveScannerResultsError::Storage)?;
        let expected_checksum = if dns_upload.observations.is_empty() {
            es_checksum.clone()
        } else {
            let content = serde_json::to_vec(&serde_json::json!({
                "endpoint_checksum": es_checksum,
                "dns_observations": dns_upload.observations.iter().filter_map(|item| match item {
                    ScannerObservation::Dns { observation } => Some(observation),
                    _ => None,
                }).collect::<Vec<_>>(),
            }))
            .map_err(scanner_result_database_error)?;
            openssl::sha::sha256(&content)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        };
        if let Some(existing) = transaction
            .query_opt(
                "SELECT is_final, observation_count, payload_checksum, storage_backend FROM scan_result_batch \
                 WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3;",
                &[&execution_db_id, &upload_id, &batch_index],
            )
            .await
            .map_err(scanner_result_database_error)?
        {
            let existing_checksum: Option<String> = existing.get("payload_checksum");
            if existing.get::<_, bool>("is_final") != is_final
                || existing.get::<_, i32>("observation_count") != observation_count
                || existing_checksum
                    .as_deref()
                    .is_none_or(|checksum| checksum != expected_checksum)
            {
                return Err(SaveScannerResultsError::BatchPayloadConflict {
                    execution_id: execution_db_id,
                    upload_id: upload_id.clone(),
                    batch_index,
                    content_kind: "scan result",
                    expected_checksum: existing_checksum,
                    received_checksum: expected_checksum.clone(),
                });
            }
            if existing.get::<_, String>("storage_backend") != "pending" {
                transaction
                    .commit()
                    .await
                    .map_err(scanner_result_database_error)?;
                drop(client);
                stage.finish(true);
                return Ok(0);
            }
        } else {
            upload_stream::ensure_open(&transaction, execution_db_id, &upload_id, batch_index, "scan result").await?;
            if already_succeeded {
                return Err(SaveScannerResultsError::CompletedExecutionNewBatch {
                    execution_id: execution_db_id,
                    upload_id: upload_id.clone(),
                    batch_index,
                });
            }
            transaction
                .execute(
                    "INSERT INTO scan_result_batch (execution_id, upload_id, batch_index, is_final, observation_count, \
                     protocol_version, payload_checksum, storage_backend, storage_references) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', '[]'::JSONB);",
                    &[
                        &execution_db_id,
                        &upload_id,
                        &batch_index,
                        &is_final,
                        &observation_count,
                        &protocol_version,
                        &expected_checksum,
                    ],
                )
                .await
                .map_err(scanner_result_database_error)?;
        }
        let summary_indices = if is_final {
            let stage = WriteStage::new("load_execution_index_manifest");
            let receipts = transaction
                .query(
                    "SELECT storage_references, observation_count FROM scan_result_batch \
                 WHERE execution_id = $1 AND upload_id = $2 AND storage_backend <> 'pending';",
                    &[&execution_db_id, &upload_id],
                )
                .await
                .map_err(scanner_result_database_error)?;
            let mut indices = elasticsearch
                .scan_batch_indices(&observation_rows)
                .map_err(SaveScannerResultsError::Storage)?
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>();
            let mut legacy_manifest = false;
            for receipt in receipts {
                let references: Value = receipt.get("storage_references");
                let references = references.as_array().ok_or_else(|| {
                    SaveScannerResultsError::Storage("invalid scan index manifest".into())
                })?;
                legacy_manifest |=
                    receipt.get::<_, i32>("observation_count") > 0 && references.is_empty();
                for index in references {
                    indices.insert(
                        index
                            .as_str()
                            .ok_or_else(|| {
                                SaveScannerResultsError::Storage(
                                    "invalid scan index reference".into(),
                                )
                            })?
                            .to_owned(),
                    );
                }
            }
            stage.finish(true);
            if legacy_manifest {
                None
            } else {
                Some(indices.into_iter().collect::<Vec<_>>())
            }
        } else {
            Some(Vec::new())
        };
        // 关键边界：任务行锁和连接在任何 Elasticsearch await 之前释放。
        transaction
            .commit()
            .await
            .map_err(scanner_result_database_error)?;
        drop(client);
        stage.finish(true);
        if !dns_upload.observations.is_empty() {
            dns_upload.upload_id = sidecar_upload_id;
            dns_upload.is_final = Some(false);
            save_dns_scanner_results(
                pool,
                elasticsearch,
                dns_follow_up,
                &dns_upload,
                token,
                token_pepper,
                upload.upload_id,
                Some(maxmind),
            )
            .await?;
        }
        let result = elasticsearch
            .persist_scan_batch_scoped(
                &batch_context,
                &observation_rows,
                summary_indices.as_deref(),
            )
            .await
            .map_err(SaveScannerResultsError::Storage)?;
        debug_assert_eq!(result.payload_checksum, es_checksum);
        let storage_references =
            Value::Array(result.indices.into_iter().map(Value::String).collect());
        client = db::acquire_write_connection(pool, "confirm_scan_batch")
            .await
            .map_err(scanner_result_database_error)?;
        let stage = WriteStage::new("confirm_scan_receipt");
        let transaction = client
            .transaction()
            .await
            .map_err(scanner_result_database_error)?;
        transaction
            .batch_execute(
                "SET LOCAL lock_timeout = '1500ms'; SET LOCAL statement_timeout = '15s';",
            )
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
        let receipt = transaction
            .query_opt(
                "UPDATE scan_result_batch SET storage_backend = $4, storage_references = $5 \
                 WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3 \
                 AND storage_backend = 'pending' RETURNING id;",
                &[
                    &execution_db_id,
                    &upload_id,
                    &batch_index,
                    &storage_backend,
                    &storage_references,
                ],
            )
            .await
            .map_err(scanner_result_database_error)?;
        let Some(_) = receipt else {
            stage.finish(true);
            transaction
                .commit()
                .await
                .map_err(scanner_result_database_error)?;
            return Ok(0);
        };
        stage.finish(true);
        (transaction, result.execution_summary)
    };
    transaction.execute("UPDATE scan_task_execution SET asset_signature=COALESCE(asset_signature,repeat('0',256)::BIT(256)) # $2::TEXT::BIT(256) WHERE id=$1",
        &[&execution_db_id,&target_generated::history::fingerprint(&observation_rows)]).await.map_err(scanner_result_database_error)?;
    let saved = normalized_observations.len() + dns_upload.observations.len();

    if !is_typed || upload.is_final == Some(true) {
        upload_stream::validate_final(
            &transaction,
            execution_db_id,
            &upload_id,
            batch_index,
            "scan result",
            true,
        )
        .await?;
        let execution_summary = {
            es_execution_summary.ok_or_else(|| {
                SaveScannerResultsError::Storage(
                    "final batch did not produce execution counters".into(),
                )
            })?
        };
        let dns_summary = if let Some(sidecar) = &sidecar_identity {
            upload_stream::load(&transaction, execution_db_id, sidecar).await?
        } else {
            None
        };
        let dns_count = if let Some(summary) = dns_summary {
            if summary.get::<_, bool>("dirty")
                || summary.get::<_, i64>("pending_count") != 0
                || summary.get::<_, i64>("final_count") != 0
                || summary
                    .get::<_, Option<i32>>("last_batch")
                    .is_some_and(|last| last > batch_index)
            {
                return Err(SaveScannerResultsError::InvalidUpload(
                    "final batch requires completed DNS children with matching primary batches"
                        .into(),
                ));
            }
            summary.get::<_, i64>("confirmed_observations")
        } else {
            0
        };
        let total_observation_count = execution_summary.observation_count + dns_count;
        transaction
            .execute(
                "UPDATE scan_task_execution SET execution_status = 'succeeded', task_end_time = $1, \
                 lease_expires_at = NULL, failure_reason = NULL, cancel_requested = false, \
                 maintenance_hold = FALSE, maintenance_hold_until = NULL, \
                 result_ip_count = $3, result_port_count = $4, result_observation_count = $5 WHERE id = $2;",
                &[
                    &get_unix_epoch_ms(),
                    &execution_db_id,
                    &execution_summary.ip_count,
                    &execution_summary.port_count,
                    &total_observation_count,
                ],
            )
            .await
            .map_err(scanner_result_database_error)?;
        // New servers enqueue analytics in the same transaction as successful completion.
        // The analytics worker still reconciles older completed executions during upgrades.
        transaction
            .execute(
                "INSERT INTO analytics_outbox (execution_id, status, available_at, locked_at, completed_at, last_error) \
                 VALUES ($1, 'pending', NOW(), NULL, NULL, NULL) \
                 ON CONFLICT (execution_id) DO UPDATE SET status = 'pending', available_at = NOW(), \
                    locked_at = NULL, completed_at = NULL, last_error = NULL, updated_at = NOW();",
                &[&execution_db_id],
            )
            .await
            .map_err(scanner_result_database_error)?;

        {
            transaction
                .execute(
                    "INSERT INTO scan_projection_outbox (execution_id, attempts, available_at, processed_at, last_error) \
                     VALUES ($1, 0, NOW(), NULL, NULL) ON CONFLICT (execution_id) DO NOTHING;",
                    &[&execution_db_id],
                )
                .await
                .map_err(scanner_result_database_error)?;
        }
        transaction.execute(
            "INSERT INTO os_detection_outbox(execution_id,ruleset_revision) VALUES($1,$2) ON CONFLICT DO NOTHING",
            &[&execution_db_id, &crate::os_detection::RULESET_REVISION],
        ).await.map_err(scanner_result_database_error)?;
        let stage = WriteStage::new("refresh_task_aggregate");
        refresh_task_aggregate(&transaction, task_db_id)
            .await
            .map_err(scanner_result_database_error)?;
        stage.finish(true);
        let stage = WriteStage::new("update_target_freshness");
        crate::scan_control::routing::record_outcome(&transaction, execution_db_id, false)
            .await
            .map_err(scanner_result_database_error)?;
        target_generated::history::record_result(&transaction, task_db_id)
            .await
            .map_err(scanner_result_database_error)?;
        target_generated::search::record_success(&transaction, task_db_id)
            .await
            .map_err(scanner_result_database_error)?;
        stage.finish(true);
    }
    let stage = WriteStage::new("commit_scan_receipt");
    transaction
        .commit()
        .await
        .map_err(scanner_result_database_error)?;
    drop(client);
    stage.finish(true);
    if is_final {
        elasticsearch.notify_projection_worker();
    }
    Ok(saved)
}
