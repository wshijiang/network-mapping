//! Resumable current-endpoint publication. No PG connection crosses ES I/O.
use super::*;
use std::future::Future;

const OWNERSHIP_LOST: &str = "scan projection lease lost";

struct ProjectionJob {
    database_id: i32,
    token: Uuid,
    attempts: i32,
    cursor: Option<Value>,
    phase: String,
    context: ScanBatchContext,
    api_client_id: Option<i32>,
}

pub(super) struct ProjectionPage {
    pub(super) cursor: Option<Value>,
    pub(super) endpoints: i64,
    pub(super) done: bool,
}

impl ElasticsearchService {
    pub(crate) fn notify_projection_worker(&self) {
        self.inner.projection_notify.notify_one();
    }

    async fn claim_projection(&self, pool: &Pool) -> Result<Option<ProjectionJob>, String> {
        let token = Uuid::new_v4();
        let lease_seconds = self.inner.config.projection_lease_seconds as i64;
        let mut connection = crate::db::acquire_write_connection(pool, "scan_projection_control")
            .await
            .map_err(|e| e.to_string())?;
        let transaction = connection.transaction().await.map_err(|e| e.to_string())?;
        transaction
            .batch_execute("SET LOCAL lock_timeout = '1500ms'; SET LOCAL statement_timeout = '5s';")
            .await
            .map_err(|e| e.to_string())?;
        let row = transaction
            .query_opt(
                "WITH candidate AS (SELECT o.execution_id FROM scan_projection_outbox o \
             JOIN scan_task_execution e ON e.id = o.execution_id \
             WHERE o.processed_at IS NULL AND e.execution_status = 'succeeded' \
               AND o.available_at <= clock_timestamp() \
               AND (o.lease_expires_at IS NULL OR o.lease_expires_at <= clock_timestamp()) \
             ORDER BY o.available_at, o.execution_id FOR UPDATE OF o SKIP LOCKED LIMIT 1) \
             UPDATE scan_projection_outbox o SET claim_token = $1, \
               lease_expires_at = clock_timestamp() + ($2::BIGINT * INTERVAL '1 second'), \
               attempts = attempts + 1, updated_at = clock_timestamp() \
             FROM candidate WHERE o.execution_id = candidate.execution_id \
             RETURNING o.execution_id, o.attempts, o.cursor, o.phase;",
                &[&token, &lease_seconds],
            )
            .await
            .map_err(|e| e.to_string())?;
        let job = if let Some(row) = row {
            let database_id = row.get("execution_id");
            Some(ProjectionJob {
                database_id,
                token,
                attempts: row.get("attempts"),
                cursor: row.get("cursor"),
                phase: row.get("phase"),
                context: load_scan_batch_context(&transaction, database_id).await?,
                api_client_id: transaction.query_one("SELECT t.api_client_id FROM scan_task t JOIN scan_task_execution e ON e.task_id=t.id WHERE e.id=$1", &[&database_id]).await.map_err(|e|e.to_string())?.get(0),
            })
        } else {
            None
        };
        transaction.commit().await.map_err(|e| e.to_string())?;
        Ok(job)
    }

    async fn renew_projection(&self, pool: &Pool, job: &ProjectionJob) -> Result<(), String> {
        projection_update(
            pool,
            "UPDATE scan_projection_outbox SET lease_expires_at = clock_timestamp() + \
               ($3::BIGINT * INTERVAL '1 second'), updated_at = clock_timestamp() \
             WHERE execution_id = $1 AND claim_token = $2 AND processed_at IS NULL \
               AND lease_expires_at > clock_timestamp();",
            &[
                &job.database_id,
                &job.token,
                &(self.inner.config.projection_lease_seconds as i64),
            ],
        )
        .await
    }

    // This wrapper only surrounds ES futures, never a future holding a PG client.
    async fn with_projection_lease<T>(
        &self,
        pool: &Pool,
        job: &ProjectionJob,
        work: impl Future<Output = Result<T, String>>,
    ) -> Result<T, String> {
        self.renew_projection(pool, job).await?;
        let mut heartbeat = interval(Duration::from_secs(
            self.inner.config.projection_heartbeat_seconds,
        ));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        heartbeat.tick().await;
        tokio::pin!(work);
        loop {
            tokio::select! {
                result = &mut work => return result,
                _ = heartbeat.tick() => self.renew_projection(pool, job).await?,
            }
        }
    }

    async fn checkpoint_projection(
        &self,
        pool: &Pool,
        job: &ProjectionJob,
        page: &ProjectionPage,
    ) -> Result<(), String> {
        let phase = if page.done { "refreshing" } else { "promoting" };
        projection_update(
            pool,
            "UPDATE scan_projection_outbox SET cursor = $3, phase = $4, \
               processed_endpoints = processed_endpoints + $5, attempts = 0, last_error = NULL, \
               updated_at = clock_timestamp() \
             WHERE execution_id = $1 AND claim_token = $2 AND processed_at IS NULL \
               AND lease_expires_at > clock_timestamp();",
            &[
                &job.database_id,
                &job.token,
                &page.cursor,
                &phase,
                &page.endpoints,
            ],
        )
        .await
    }

    async fn release_projection(
        &self,
        pool: &Pool,
        job: &ProjectionJob,
        complete: bool,
    ) -> Result<(), String> {
        projection_update(pool,
            "UPDATE scan_projection_outbox SET processed_at = CASE WHEN $3 THEN clock_timestamp() ELSE NULL END, \
               claim_token = NULL, lease_expires_at = NULL, available_at = clock_timestamp(), \
               last_error = NULL, attempts = 0, updated_at = clock_timestamp() \
             WHERE execution_id = $1 AND claim_token = $2 AND processed_at IS NULL \
               AND lease_expires_at > clock_timestamp();",
            &[&job.database_id, &job.token, &complete],
        ).await
    }

    async fn retry_projection(
        &self,
        pool: &Pool,
        job: &ProjectionJob,
        message: &str,
    ) -> Result<(), String> {
        let delay = i64::from(2_i32.saturating_pow(job.attempts.clamp(1, 8) as u32));
        let message = message.chars().take(2000).collect::<String>();
        projection_update(
            pool,
            "UPDATE scan_projection_outbox SET claim_token = NULL, lease_expires_at = NULL, \
               available_at = clock_timestamp() + ($3::BIGINT * INTERVAL '1 second'), \
               last_error = $4, updated_at = clock_timestamp() \
             WHERE execution_id = $1 AND claim_token = $2 AND processed_at IS NULL \
               AND lease_expires_at > clock_timestamp();",
            &[&job.database_id, &job.token, &delay, &message],
        )
        .await
    }

    pub(super) async fn process_scan_projection_outbox(&self, pool: &Pool) -> Result<bool, String> {
        let Some(mut job) = self.claim_projection(pool).await? else {
            return Ok(false);
        };
        let started = Instant::now();
        info!(event = "ScanProjectionClaimed", execution_id = %job.context.execution_id,
            phase = %job.phase, attempt = job.attempts);
        let result = async {
            for _ in 0..self.inner.config.projection_pages_per_tick {
                if job.phase == "refreshing" {
                    self.with_projection_lease(pool, &job, self.refresh_current_projection()).await?;
                    self.release_projection(pool, &job, true).await?;
                    info!(event = "ScanProjectionCompleted", execution_id = %job.context.execution_id,
                        slice_duration_ms = started.elapsed().as_millis() as u64);
                    return Ok(());
                }
                let page = self.with_projection_lease(pool, &job,
                    self.promote_execution_page(&job.context, job.cursor.as_ref(), job.api_client_id)).await?;
                self.checkpoint_projection(pool, &job, &page).await?;
                info!(event = "ScanProjectionPageCompleted", execution_id = %job.context.execution_id,
                    endpoints = page.endpoints, final_page = page.done,
                    slice_duration_ms = started.elapsed().as_millis() as u64);
                job.cursor = page.cursor;
                job.attempts = 1; // successful pages reset consecutive failure backoff
                if page.done { job.phase = "refreshing".into(); }
            }
            self.release_projection(pool, &job, false).await?;
            // Yield to other executions and the tag queue before the next slice.
            Ok::<(), String>(())
        }.await;
        if let Err(error) = result {
            if error != OWNERSHIP_LOST
                && let Err(mark_error) = self.retry_projection(pool, &job, &error).await
            {
                warn!(event = "ScanProjectionRetryScheduleError", execution_id = %job.context.execution_id,
                    error_message = %mark_error, outcome = "lease_recovery_pending");
            }
            warn!(event = "ScanProjectionOutboxError", execution_id = %job.context.execution_id,
                phase = %job.phase, error_message = %error, retryable = true,
                slice_duration_ms = started.elapsed().as_millis() as u64);
            return Err(error);
        }
        Ok(true)
    }

    // Also used by the offline migration, which has no online outbox lease.
    pub(super) async fn promote_execution(&self, context: &ScanBatchContext) -> Result<(), String> {
        let mut cursor = None;
        loop {
            let page = self
                .promote_execution_page(context, cursor.as_ref(), None)
                .await?;
            cursor = page.cursor;
            if page.done {
                break;
            }
        }
        self.refresh_current_projection().await
    }

    pub(super) async fn refresh_current_projection(&self) -> Result<(), String> {
        let response = self
            .send_json_request(
                ElasticsearchOperation::IndexAdmin,
                Method::POST,
                &format!("/{}/_refresh", self.inner.config.current_endpoint_index),
                |r| r,
            )
            .await?;
        validate_scan_refresh_response(&response)
    }

    pub(super) async fn promote_execution_page(
        &self,
        context: &ScanBatchContext,
        cursor: Option<&Value>,
        api_client_id: Option<i32>,
    ) -> Result<ProjectionPage, String> {
        let page_size = self.inner.config.projection_page_size;
        let mut query = json!({"size": page_size, "track_total_hits": false,
            "query": {"term": {"execution_id": context.execution_id}},
            "sort": [{"endpoint_key": "asc"}]});
        if let Some(cursor) = cursor {
            query["search_after"] = cursor.clone();
        }
        let response = self
            .send_json_request(
                ElasticsearchOperation::ProjectionSearch,
                Method::POST,
                &format!("/{}/_search", self.inner.config.execution_endpoint_index),
                |r| r.json(&query),
            )
            .await?;
        validate_scan_search_response(&response)?;
        let hits = response
            .pointer("/hits/hits")
            .and_then(Value::as_array)
            .ok_or_else(|| "执行端点投影响应缺少 hits".to_owned())?;
        let next = if let Some(hit) = hits.last() {
            let sort = hit
                .get("sort")
                .filter(|v| v.is_array())
                .ok_or_else(|| "执行端点投影缺少分页 sort".to_owned())?;
            if Some(sort) == cursor {
                return Err("执行端点投影分页没有前进".into());
            }
            Some(sort.clone())
        } else {
            cursor.cloned()
        };
        // A page contains distinct endpoint keys and scopes. Its bulks can run
        // concurrently offline; the caller still waits for the entire page before
        // checkpointing or publishing the next execution.
        let concurrency = if self
            .inner
            .maintenance_run_id
            .read()
            .expect("maintenance identity lock poisoned")
            .is_some()
        {
            self.inner.config.bulk_max_concurrency
        } else {
            1
        };
        let mut pending = futures_util::stream::FuturesUnordered::new();
        let send = |body: String, ids: Vec<String>| async move {
            self.write_projection_bulk(context, &body, &ids).await
        };
        let mut body = String::new();
        let mut ids = Vec::new();
        for hit in hits {
            let source = hit
                .get("_source")
                .ok_or_else(|| "执行端点投影缺少 _source".to_owned())?;
            let ip = source
                .get("ip")
                .and_then(Value::as_str)
                .ok_or_else(|| "端点缺少 ip".to_owned())?;
            let port = source
                .get("port")
                .and_then(Value::as_i64)
                .ok_or_else(|| "端点缺少 port".to_owned())?;
            let mut scopes = vec![("global", 0), ("user", context.user_id)];
            if let Some(id) = api_client_id {
                scopes.push(("api_client", id));
            }
            for (scope_type, scope_id) in scopes {
                let mut scoped = source.clone();
                scoped["scope_type"] = json!(scope_type);
                scoped["scope_id"] = json!(scope_id);
                let id = sha256_hex(
                    format!(
                        "{scope_type}\0{scope_id}\0{ip}\0{port}\0{}",
                        endpoint_protocol(source)
                    )
                    .as_bytes(),
                );
                let mut action = String::new();
                append_projection_update(
                    &mut action,
                    &self.inner.config.current_endpoint_index,
                    &id,
                    &scoped,
                )?;
                if action.len() > self.inner.config.projection_bulk_max_bytes {
                    return Err(
                        "单个端点投影超过 projection_bulk_max_bytes，请调整限制或检查端点大小"
                            .into(),
                    );
                }
                if !body.is_empty()
                    && (body.len() + action.len() > self.inner.config.projection_bulk_max_bytes
                        || ids.len() >= self.inner.config.bulk_batch_size)
                {
                    pending.push(send(std::mem::take(&mut body), std::mem::take(&mut ids)));
                    if pending.len() >= concurrency
                        && let Some(result) = pending.next().await
                    {
                        result?;
                    }
                }
                body.push_str(&action);
                ids.push(id);
            }
        }
        if !body.is_empty() {
            pending.push(send(body, ids));
        }
        while let Some(result) = pending.next().await {
            result?;
        }
        Ok(ProjectionPage {
            cursor: next,
            endpoints: hits.len() as i64,
            done: hits.len() < page_size,
        })
    }

    async fn write_projection_bulk(
        &self,
        context: &ScanBatchContext,
        body: &str,
        ids: &[String],
    ) -> Result<(), String> {
        let result = self
            .send_bulk_with_retry(
                &format!(
                    "/_bulk?wait_for_active_shards={}",
                    self.inner.config.write_wait_for_active_shards
                ),
                body,
                false,
            )
            .await?;
        validate_projection_bulk(&result, &self.inner.config.current_endpoint_index, ids)?;
        info!(event = "ScanProjectionBulkCompleted", execution_id = %context.execution_id,
            request_bytes = body.len(), operations = ids.len());
        Ok(())
    }
}

// Short bounded transactions prevent a lost DB connection from hanging lease maintenance.
async fn projection_update(
    pool: &Pool,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<(), String> {
    let mut connection = crate::db::acquire_write_connection(pool, "scan_projection_control")
        .await
        .map_err(|e| e.to_string())?;
    let transaction = connection.transaction().await.map_err(|e| e.to_string())?;
    transaction
        .batch_execute("SET LOCAL lock_timeout = '1500ms'; SET LOCAL statement_timeout = '5s';")
        .await
        .map_err(|e| e.to_string())?;
    let changed = transaction
        .execute(sql, params)
        .await
        .map_err(|e| e.to_string())?;
    transaction.commit().await.map_err(|e| e.to_string())?;
    if changed != 1 {
        return Err(OWNERSHIP_LOST.into());
    }
    Ok(())
}

pub(super) fn validate_projection_bulk(
    result: &Value,
    index: &str,
    ids: &[String],
) -> Result<(), String> {
    let items = result
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| "投影 Bulk 响应缺少 items".to_owned())?;
    if items.len() != ids.len() {
        return Err("投影 Bulk 响应条目数不匹配".into());
    }
    for (item, id) in items.iter().zip(ids) {
        let update = item
            .get("update")
            .ok_or_else(|| "投影 Bulk 缺少 update".to_owned())?;
        if !update
            .get("status")
            .and_then(Value::as_u64)
            .is_some_and(|s| (200..300).contains(&s))
            || update.get("_id").and_then(Value::as_str) != Some(id.as_str())
            || update.get("_index").and_then(Value::as_str) != Some(index)
        {
            return Err(format!("投影 Bulk 条目失败或身份不匹配：{update}"));
        }
    }
    if result.get("errors").and_then(Value::as_bool) != Some(false) {
        return Err("投影 Bulk 未确认完整成功".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "projection/tests.rs"]
mod integration_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projection_bulk_rejects_partial_malformed_and_mismatched_responses() {
        let ids = vec!["one".to_owned()];
        let good = json!({"errors":false,"items":[{"update":{"_index":"current","_id":"one","status":200}}]});
        assert!(validate_projection_bulk(&good, "current", &ids).is_ok());
        for bad in [
            json!({"errors":false}),
            json!({"errors":false,"items":[]}),
            json!({"errors":false,"items":[{"create":{"status":201}}]}),
            json!({"errors":false,"items":[{"update":{"_index":"current","_id":"one","status":429}}]}),
            json!({"errors":false,"items":[{"update":{"_index":"current","_id":"other","status":200}}]}),
        ] {
            assert!(validate_projection_bulk(&bad, "current", &ids).is_err());
        }
    }
}
