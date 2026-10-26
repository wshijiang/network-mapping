use super::*;
use std::sync::atomic::AtomicU64;

impl ElasticsearchService {
    fn rebuild_observation(
        &self,
        execution: &Execution,
        hit: &Value,
    ) -> Result<(ScanBatchContext, Value), String> {
        let source = hit.get("_source").ok_or("扫描事实缺少 _source")?;

        let mut observation = source.clone();
        let object = observation.as_object_mut().ok_or("扫描事实不是对象")?;
        for field in [
            "task_id",
            "execution_id",
            "user_id",
            "task_source",
            "scanner_id",
            "scanner_name",
            "upload_id",
            "batch_index",
            "payload_checksum",
            "document_checksum",
        ] {
            object.remove(field);
        }
        let mut context = execution.context.clone();
        context.upload_id = source
            .get("upload_id")
            .and_then(Value::as_str)
            .ok_or("事实缺少 upload_id")?
            .to_owned();
        context.batch_index = source
            .get("batch_index")
            .and_then(Value::as_i64)
            .and_then(|v| i32::try_from(v).ok())
            .ok_or("事实缺少有效 batch_index")?;
        context.is_final = false;
        Ok((context, observation))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn replay_rebuild_execution(
        &self,
        pool: &Pool,
        run: &Run,
        execution: &Execution,
        mut checkpoint: Checkpoint,
        progress: (&AtomicU64, u64),
        reporter: &dyn ProgressReporter,
        stop: &AtomicBool,
    ) -> Result<(), String> {
        let (completed, total) = progress;
        if checkpoint.replayed > 0 && checkpoint.replay_cursor.is_none() {
            return Err("重放断点缺少分页游标".into());
        }
        if checkpoint.replay_complete {
            return Ok(());
        }
        let page_size = self.inner.config.projection_page_size;
        loop {
            cancelled(stop)?;
            reporter.report(ProgressUpdate::count(
                "[2/6] 事实重放",
                completed.load(Ordering::Acquire),
                Some(total),
                "条",
                format!(
                    "执行 {}：{}/{}，等待扫描查询",
                    execution.id,
                    checkpoint.replayed,
                    execution.expected()
                ),
            ));
            let mut query = json!({"size":page_size,"track_total_hits":false,"query":{"term":{"execution_id":execution.context.execution_id}},
                "sort":[{"observed_at":"asc"},{"upload_id":"asc"},{"batch_index":"asc"},{"observation_key":"asc"}]});
            if let Some(cursor) = &checkpoint.replay_cursor {
                query["search_after"] = cursor.clone();
            }
            let response = self.rebuild_search(execution, &query).await?;
            let hits = response
                .pointer("/hits/hits")
                .and_then(Value::as_array)
                .ok_or("扫描事实缺少 hits")?;
            let count = hits.len() as u64;
            if hits.is_empty() {
                break;
            }
            let next = hits
                .last()
                .and_then(|h| h.get("sort"))
                .filter(|v| v.as_array().is_some_and(|a| a.len() == 4))
                .cloned()
                .ok_or("扫描事实缺少稳定排序游标")?;
            if checkpoint.replay_cursor.as_ref() == Some(&next) {
                return Err("扫描事实重建分页没有前进".into());
            }
            let mut bulk = Bulk::new(&self.inner.config.execution_endpoint_index);
            for hit in hits {
                let (context, mut observation) = self.rebuild_observation(execution, hit)?;
                if observation.get("kind").and_then(Value::as_str) == Some("vulnerability") {
                    continue;
                }
                let raw_ip = observation
                    .get("ip_address")
                    .and_then(Value::as_str)
                    .ok_or("端点事实缺少 IP")?;
                let ip = raw_ip
                    .parse::<std::net::IpAddr>()
                    .or_else(|_| raw_ip.parse::<ipnet::IpNet>().map(|n| n.addr()))
                    .map_err(|_| "端点事实 IP 无效")?
                    .to_string();
                observation["ip_address"] = json!(ip);
                let port = observation
                    .get("port")
                    .and_then(Value::as_i64)
                    .filter(|p| (0..=65535).contains(p))
                    .ok_or("端点事实端口无效")?;
                let observed = observation["observed_at"].as_i64().ok_or("事实时间无效")?;
                let document = endpoint_projection_document(&context, &observation, observed);
                let id = sha256_hex(
                    format!(
                        "{}\0{ip}\0{port}\0{}",
                        context.execution_id,
                        endpoint_protocol(&observation)
                    )
                    .as_bytes(),
                );
                let mut action = String::new();
                append_projection_update(
                    &mut action,
                    &self.inner.config.execution_endpoint_index,
                    &id,
                    &document,
                )?;
                bulk.push(self, id, action).await?;
            }
            bulk.flush(self).await?;
            checkpoint.replay_cursor = Some(next);
            checkpoint.replayed += count;
            save(pool, &checkpoint_key(run, execution.id), &checkpoint).await?;
            let confirmed = completed.fetch_add(count, Ordering::AcqRel) + count;
            reporter.report(ProgressUpdate::count(
                "[2/6] 事实重放",
                confirmed,
                Some(total),
                "条",
                format!(
                    "执行 {}：{}/{}，本页断点已保存",
                    execution.id,
                    checkpoint.replayed,
                    execution.expected()
                ),
            ));
        }
        checkpoint.replay_complete = true;
        save(pool, &checkpoint_key(run, execution.id), &checkpoint).await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn publish_rebuild_execution(
        &self,
        pool: &Pool,
        run: &Run,
        execution: &Execution,
        mut checkpoint: Checkpoint,
        progress: (u64, u64),
        reporter: &dyn ProgressReporter,
        stop: &AtomicBool,
    ) -> Result<u64, String> {
        let (base, total) = progress;
        if !checkpoint.replay_complete {
            return Err(format!("执行 {} 的事实尚未验证完成", execution.id));
        }
        if !execution.succeeded {
            return Ok(0);
        }
        if checkpoint.publish_complete {
            return Ok(checkpoint.published);
        }
        // Keep several page writes in flight while the next page's search
        // advances the cursor. Pages of one execution cover distinct endpoint
        // keys, so this preserves the existing cross-execution ordering while
        // overlapping searches with bulk requests.
        let pipeline_depth = self.inner.config.bulk_max_concurrency.clamp(1, 4);
        let mut pending = futures_util::stream::FuturesOrdered::new();
        let mut cursor = checkpoint.publish_cursor.clone();
        let mut fetched_done = false;
        let mut published = checkpoint.published;
        loop {
            if !fetched_done && !stop.load(Ordering::Acquire) {
                let page = self
                    .fetch_projection_page(&execution.context, cursor.as_ref())
                    .await?;
                cursor = page.cursor.clone();
                fetched_done = page.done;
                let done = page.done;
                let page_cursor = page.cursor.clone();
                let search_ms = page.search_ms;
                let hits = page.hits;
                pending.push_back(async move {
                    let write_started = Instant::now();
                    let endpoints = self
                        .write_projection_page(&execution.context, &hits, execution.api_client_id)
                        .await?;
                    let write_ms = write_started.elapsed().as_millis() as u64;
                    Ok::<_, String>((endpoints, done, page_cursor, search_ms, write_ms))
                });
                if pending.len() < pipeline_depth && !fetched_done {
                    continue;
                }
            }
            let Some(result) = pending.next().await else {
                break;
            };
            let (count, done, page_cursor, search_ms, write_ms) = result?;
            published += count;
            checkpoint.published = published;
            checkpoint.publish_cursor = page_cursor;
            checkpoint.publish_complete = done && pending.is_empty() && fetched_done;
            save(pool, &checkpoint_key(run, execution.id), &checkpoint).await?;
            reporter.report(ProgressUpdate::count(
                "[3/6] 端点发布",
                base + published,
                Some(total),
                "端点",
                format!("执行 {}，等待发布页确认", execution.id),
            ));
            info!(event = "TransportRebuildPagePublished",
                execution_id = %execution.context.execution_id,
                endpoints = count,
                search_ms,
                write_ms,
                "重建端点发布页完成");
            if checkpoint.publish_complete {
                return Ok(published);
            }
        }
        cancelled(stop)?;
        Ok(published)
    }
}
