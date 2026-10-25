use super::*;

pub(super) struct Bulk {
    index: String,
    body: String,
    ids: Vec<String>,
}

impl Bulk {
    pub fn new(index: &str) -> Self {
        Self {
            index: index.into(),
            body: String::new(),
            ids: Vec::new(),
        }
    }

    pub async fn push(
        &mut self,
        service: &ElasticsearchService,
        id: String,
        action: String,
    ) -> Result<(), String> {
        let config = &service.inner.config;
        if action.len() > config.projection_bulk_max_bytes {
            return Err("单条重建动作超过 projection_bulk_max_bytes，拒绝截断事实".into());
        }
        if !self.ids.is_empty()
            && (self.ids.len() >= config.bulk_batch_size
                || self.body.len() + action.len() > config.projection_bulk_max_bytes)
        {
            self.flush(service).await?;
        }
        self.body.push_str(&action);
        self.ids.push(id);
        Ok(())
    }

    pub async fn flush(&mut self, service: &ElasticsearchService) -> Result<(), String> {
        if self.ids.is_empty() {
            return Ok(());
        }
        let result = service
            .send_bulk_with_retry(
                &format!(
                    "/_bulk?wait_for_active_shards={}",
                    service.inner.config.write_wait_for_active_shards
                ),
                &self.body,
                false,
            )
            .await?;
        super::super::projection::validate_projection_bulk(&result, &self.index, &self.ids)?;
        self.body.clear();
        self.ids.clear();
        Ok(())
    }
}

impl ElasticsearchService {
    pub(super) async fn rebuild_search(
        &self,
        execution: &Execution,
        body: &Value,
    ) -> Result<Value, String> {
        let indices = execution.indices();
        if indices.is_empty() {
            return Ok(json!({"hits":{"hits":[]},"aggregations":{"batches":{"buckets":[]}}}));
        }
        let target =
            observation_search_target(&self.inner.config.observation_index_prefix, &indices)?;
        let path = format!(
            "/{target}/_search?allow_no_indices=false&ignore_unavailable=false&allow_partial_search_results=false"
        );
        ensure_scan_request_line_fits(&self.inner.config.url, &path)?;
        let response = self
            .send_json_request(
                ElasticsearchOperation::ScanQuery,
                Method::POST,
                &path,
                |r| r.json(body),
            )
            .await?;
        validate_scan_search_response(&response)?;
        Ok(response)
    }

    pub(super) async fn preflight_rebuild(
        &self,
        jobs: &[Execution],
        source: &Value,
        reporter: &dyn ProgressReporter,
        stop: &AtomicBool,
    ) -> Result<(), String> {
        let expected: u64 = jobs.iter().map(Execution::expected).sum();
        let indices = source
            .get("indices")
            .and_then(Value::as_object)
            .ok_or("源清单缺少索引")?;
        for execution in jobs {
            for batch in &execution.batches {
                if batch.observation_count > 0
                    && (batch.indices.is_empty() || batch.checksum.is_none())
                {
                    return Err(format!(
                        "执行 {} 批次 {} 缺少事实索引或校验和，请先完成迁移对账",
                        execution.id, batch.batch_index
                    ));
                }
                for index in &batch.indices {
                    if !indices.contains_key(index) {
                        return Err(format!("扫描回执索引 {index} 不存在或与事实前缀不符"));
                    }
                }
            }
        }
        let actual = if indices.is_empty() {
            0
        } else {
            let response = self
                .send_json_request(
                    ElasticsearchOperation::ScanQuery,
                    Method::POST,
                    &format!(
                        "/{}-*/_count?allow_no_indices=false&ignore_unavailable=false",
                        self.inner.config.observation_index_prefix
                    ),
                    |r| r.json(&json!({"query":{"match_all":{}}})),
                )
                .await?;
            validate_scan_search_response(&response)?;
            response
                .get("count")
                .and_then(Value::as_u64)
                .ok_or("源事实缺少精确数量")?
        };
        if actual != expected {
            return Err(format!(
                "PG/ES 数据不配套：PG 回执预期 {expected} 条 IP 扫描观察，ES 实际 {actual} 条；请恢复配套 PG/ES，未创建目标或推进断点"
            ));
        }
        let mut verified = 0;
        for execution in jobs {
            cancelled(stop)?;
            reporter.report(ProgressUpdate::count(
                "[1/6] 校验源批次",
                verified,
                Some(expected),
                "条",
                format!("执行 {}；仅查询原始事实", execution.id),
            ));
            let expected_batches = execution
                .batches
                .iter()
                .map(|b| {
                    (
                        json!([b.upload_id, b.batch_index]).to_string(),
                        b.observation_count,
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let mut seen = BTreeMap::new();
            let mut after: Option<Value> = None;
            loop {
                cancelled(stop)?;
                let mut composite = json!({"size":1000,"sources":[{"upload":{"terms":{"field":"upload_id"}}},{"batch":{"terms":{"field":"batch_index"}}}]});
                if let Some(value) = &after {
                    composite["after"] = value.clone();
                }
                let response=self.rebuild_search(execution,&json!({"size":0,"query":{"term":{"execution_id":execution.context.execution_id}},"aggs":{"batches":{"composite":composite}}})).await?;
                let buckets = response
                    .pointer("/aggregations/batches/buckets")
                    .and_then(Value::as_array)
                    .ok_or("批次校验响应缺少 buckets")?;
                for bucket in buckets {
                    let key = json!([
                        bucket.pointer("/key/upload").ok_or("批次聚合缺少 upload")?,
                        bucket.pointer("/key/batch").ok_or("批次聚合缺少 batch")?
                    ])
                    .to_string();
                    let count = bucket
                        .get("doc_count")
                        .and_then(Value::as_u64)
                        .ok_or("批次聚合缺少数量")?;
                    if expected_batches.get(&key) != Some(&count)
                        || seen.insert(key.clone(), count).is_some()
                    {
                        return Err(format!(
                            "执行 {} 批次 {key} 事实数量不匹配或重复：PG {:?}，ES {count}",
                            execution.id,
                            expected_batches.get(&key)
                        ));
                    }
                }
                let next = response.pointer("/aggregations/batches/after_key").cloned();
                if buckets.len() < 1000 || next.is_none() {
                    break;
                }
                if next == after {
                    return Err("批次校验分页未前进".into());
                }
                after = next;
            }
            for (key, count) in expected_batches {
                let actual = seen.get(&key).copied().unwrap_or(0);
                if count != actual {
                    return Err(format!(
                        "执行 {} 批次 {key} 事实缺失：PG {count}，ES {actual}",
                        execution.id
                    ));
                }
            }
            verified += execution.expected();
        }
        if &self.rebuild_source().await? != source {
            return Err("预检期间源索引发生变化，请保持扫描事实停写".into());
        }
        Ok(())
    }

    pub(super) async fn refresh_rebuild_index(&self, index: &str) -> Result<(), String> {
        let response = self
            .send_json_request(
                ElasticsearchOperation::IndexAdmin,
                Method::POST,
                &format!("/{index}/_refresh"),
                |r| r,
            )
            .await?;
        validate_scan_refresh_response(&response)
    }

    pub(super) async fn drain_rebuild_requests(
        &self,
        run: &Run,
        reporter: &dyn ProgressReporter,
        stop: &AtomicBool,
    ) -> Result<(), String> {
        let opaque = format!("network-mapping:transport-rebuild:{}", run.run_id);
        let started = Instant::now();
        loop {
            cancelled(stop)?;
            let response = self
                .send_json_request(
                    ElasticsearchOperation::IndexAdmin,
                    Method::GET,
                    "/_tasks?actions=indices:data/write/*&detailed=false",
                    |r| r,
                )
                .await?;
            if response
                .get("node_failures")
                .and_then(Value::as_array)
                .is_some_and(|v| !v.is_empty())
                || response
                    .get("task_failures")
                    .and_then(Value::as_array)
                    .is_some_and(|v| !v.is_empty())
            {
                return Err("无法确认上次重建的 ES 请求状态".into());
            }
            let pending = response
                .get("nodes")
                .and_then(Value::as_object)
                .into_iter()
                .flat_map(|n| n.values())
                .filter_map(|n| n.get("tasks").and_then(Value::as_object))
                .flat_map(|t| t.values())
                .any(|t| {
                    t.pointer("/headers/X-Opaque-Id")
                        .or_else(|| t.pointer("/headers/x-opaque-id"))
                        .and_then(Value::as_str)
                        == Some(&opaque)
                });
            if !pending {
                return Ok(());
            }
            reporter.report(ProgressUpdate::phase("等待上次重建的 ES 请求结束"));
            if started.elapsed()
                > Duration::from_secs(self.inner.config.request_timeout_seconds.max(5))
            {
                return Err("上次重建仍有未完成 ES 请求，断点已保留，请稍后重试".into());
            }
            sleep(Duration::from_millis(250)).await;
        }
    }
}
