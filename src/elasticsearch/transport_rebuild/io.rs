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
        _execution: &Execution,
        body: &Value,
    ) -> Result<Value, String> {
        let path = format!(
            "/{}-*/_search?allow_no_indices=true&ignore_unavailable=false&allow_partial_search_results=false",
            self.inner.config.observation_index_prefix
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

    /// Counts are progress estimates only, never a prerequisite for successful replay.
    ///
    /// One composite aggregation returns many execution buckets at once. The
    /// previous implementation issued one `_count` request per execution, which
    /// dominated startup on installations with many small scans.
    pub(super) async fn rebuild_progress_counts(
        &self,
        jobs: &[Execution],
        reporter: &dyn ProgressReporter,
        stop: &AtomicBool,
    ) -> Result<BTreeMap<i32, u64>, String> {
        let execution_ids = jobs
            .iter()
            .map(|job| (job.context.execution_id.clone(), job.id))
            .collect::<BTreeMap<_, _>>();
        let mut counts = BTreeMap::new();
        let path = format!(
            "/{}-*/_search?allow_no_indices=true&ignore_unavailable=false&allow_partial_search_results=false",
            self.inner.config.observation_index_prefix
        );
        let page_size = 10_000;
        let mut after = None;
        loop {
            cancelled(stop)?;
            let mut body = json!({
                "size": 0,
                "track_total_hits": false,
                "aggs": {"executions": {"composite": {
                    "size": page_size,
                    "sources": [{"execution_id": {"terms": {"field": "execution_id"}}}]
                }}}
            });
            if let Some(after) = after.take() {
                body["aggs"]["executions"]["composite"]["after"] = after;
            }
            let response = self
                .send_json_request(
                    ElasticsearchOperation::ScanQuery,
                    Method::POST,
                    &path,
                    |r| r.json(&body),
                )
                .await?;
            validate_scan_search_response(&response)?;
            let buckets = response
                .pointer("/aggregations/executions/buckets")
                .and_then(Value::as_array)
                .ok_or("ES 执行计数聚合缺少 buckets")?;
            if buckets.is_empty() {
                break;
            }
            for bucket in buckets {
                let execution_id = bucket
                    .pointer("/key/execution_id")
                    .and_then(Value::as_str)
                    .ok_or("ES 执行计数聚合缺少 execution_id")?;
                let count = bucket
                    .get("doc_count")
                    .and_then(Value::as_u64)
                    .ok_or("ES 执行计数聚合缺少 doc_count")?;
                if let Some(id) = execution_ids.get(execution_id) {
                    *counts.entry(*id).or_insert(0) += count;
                }
            }
            after = response
                .pointer("/aggregations/executions/after_key")
                .cloned();
            reporter.report(ProgressUpdate::count(
                "[1/6] 准备重建进度",
                counts.len() as u64,
                Some(jobs.len() as u64),
                "执行",
                "只统计 ES 现存事实，不核对历史回执",
            ));
            if after.is_none() {
                break;
            }
        }
        // Executions without surviving ES facts still participate in phase
        // totals and must resume with a known zero count.
        for job in jobs {
            counts.entry(job.id).or_insert(0);
        }
        Ok(counts)
    }

    pub(super) async fn refresh_rebuild_index(&self, index: &str) -> Result<(), String> {
        // A full refresh of a freshly built index can exceed the normal request
        // timeout; maintenance requests get a dedicated budget.
        let response = self
            .send_json_request(
                ElasticsearchOperation::IndexAdmin,
                Method::POST,
                &format!("/{index}/_refresh"),
                |r| r.timeout(Duration::from_secs(300)),
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
