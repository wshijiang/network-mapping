use super::*;
use std::sync::atomic::AtomicU64;

impl ElasticsearchService {
    fn rebuild_observation(
        &self,
        execution: &Execution,
        hit: &Value,
    ) -> Result<(ScanBatchContext, Value), String> {
        let source = hit.get("_source").ok_or("扫描事实缺少 _source")?;
        let batch = execution.batch(source)?;
        let key = source
            .get("observation_key")
            .and_then(Value::as_str)
            .ok_or("扫描事实缺少 observation_key")?;
        let observed = source
            .get("observed_at")
            .and_then(Value::as_i64)
            .ok_or("扫描事实缺少 observed_at")?;
        let index = scan_observation_index(&self.inner.config.observation_index_prefix, observed)?;
        let expected_id =
            sha256_hex(format!("{}\0{key}", execution.context.execution_id).as_bytes());
        if source.get("execution_id") != Some(&json!(execution.context.execution_id))
            || source.get("task_id") != Some(&json!(execution.context.task_id))
            || source.get("user_id") != Some(&json!(execution.context.user_id))
            || hit.get("_id").and_then(Value::as_str) != Some(&expected_id)
            || hit.get("_index").and_then(Value::as_str) != Some(&index)
            || !batch.indices.contains(&index)
            || source.get("payload_checksum").and_then(Value::as_str) != batch.checksum.as_deref()
        {
            return Err(format!(
                "执行 {} 批次 {} 的事实身份、归属、索引或回执校验和不匹配",
                execution.id, batch.batch_index
            ));
        }
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
        let checksum = sha256_hex(
            &serde_json::to_vec(&immutable_scan_observation(&observation))
                .map_err(|e| e.to_string())?,
        );
        if source.get("document_checksum").and_then(Value::as_str) != Some(&checksum) {
            return Err(format!(
                "执行 {} 批次 {} 的原始事实内容校验失败",
                execution.id, batch.batch_index
            ));
        }
        let mut context = execution.context.clone();
        context.upload_id = batch.upload_id.clone();
        context.batch_index = batch.batch_index;
        context.is_final = batch.is_final;
        Ok((context, observation))
    }

    pub(super) async fn replay_rebuild_execution(
        &self,
        pool: &Pool,
        run: &Run,
        execution: &Execution,
        progress: (&AtomicU64, u64),
        reporter: &dyn ProgressReporter,
        stop: &AtomicBool,
    ) -> Result<(), String> {
        let (completed, total) = progress;
        let mut checkpoint = checkpoint(pool, run, execution.id).await?;
        if checkpoint.replayed > execution.expected()
            || checkpoint.replay_complete && checkpoint.replayed != execution.expected()
            || checkpoint.replayed > 0 && checkpoint.replay_cursor.is_none()
        {
            return Err(format!("执行 {} 的重放断点计数不可信", execution.id));
        }
        if checkpoint.replay_complete {
            return Ok(());
        }
        let page_size = self.inner.config.projection_page_size.min(1000);
        while checkpoint.replayed < execution.expected() {
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
            if count == 0 || checkpoint.replayed + count > execution.expected() {
                return Err(format!(
                    "执行 {} 重放数量不符：预期 {}，已确认 {}，本页 {count}",
                    execution.id,
                    execution.expected(),
                    checkpoint.replayed
                ));
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

    pub(super) async fn publish_rebuild_execution(
        &self,
        pool: &Pool,
        run: &Run,
        execution: &Execution,
        progress: (u64, u64),
        reporter: &dyn ProgressReporter,
        stop: &AtomicBool,
    ) -> Result<u64, String> {
        let (base, total) = progress;
        let mut checkpoint = checkpoint(pool, run, execution.id).await?;
        if !checkpoint.replay_complete {
            return Err(format!("执行 {} 的事实尚未验证完成", execution.id));
        }
        if !execution.succeeded {
            return Ok(0);
        }
        let expected = u64::try_from(checkpoint.port_count.ok_or("发布缺少已验证端点总量")?)
            .map_err(|e| e.to_string())?;
        if checkpoint.published > expected
            || checkpoint.publish_complete && checkpoint.published != expected
        {
            return Err("发布断点计数不可信".into());
        }
        if checkpoint.publish_complete {
            return Ok(expected);
        }
        loop {
            cancelled(stop)?;
            reporter.report(ProgressUpdate::count(
                "[3/6] 端点发布",
                base + checkpoint.published,
                Some(total),
                "端点",
                format!("执行 {}，等待发布页确认", execution.id),
            ));
            let page = self
                .promote_execution_page(
                    &execution.context,
                    checkpoint.publish_cursor.as_ref(),
                    execution.api_client_id,
                )
                .await?;
            let count = u64::try_from(page.endpoints).map_err(|e| e.to_string())?;
            checkpoint.published += count;
            if checkpoint.published > expected || page.done && checkpoint.published != expected {
                return Err("发布结果与执行端点精确数量不符".into());
            }
            checkpoint.publish_cursor = page.cursor;
            checkpoint.publish_complete = page.done;
            save(pool, &checkpoint_key(run, execution.id), &checkpoint).await?;
            if page.done {
                return Ok(checkpoint.published);
            }
        }
    }
}
