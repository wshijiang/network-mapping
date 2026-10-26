use super::*;

pub(super) const STATE_KEY: &str = "transport_endpoints_rebuild";
pub(super) const FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Execution {
    pub id: i32,
    pub context: ScanBatchContext,
    pub succeeded: bool,
    pub api_client_id: Option<i32>,
    #[serde(skip)]
    pub source_count: Option<u64>,
}

impl Execution {
    pub fn expected(&self) -> u64 {
        self.source_count.unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Initializing,
    Replaying,
    RefreshExecution,
    Publishing,
    RefreshCurrent,
    Tags,
    RefreshTags,
    Cutover,
    Complete,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Run {
    pub format_version: u32,
    pub run_id: Uuid,
    pub target: Value,
    pub previous_runtime: Option<Value>,
    pub source: Value,
    // Absent in previous page-checkpoint runs, which used receipt counts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_counts: Option<BTreeMap<i32, u64>>,
    pub target_uuids: BTreeMap<String, String>,
    pub phase: Phase,
    pub tag_cursor: Option<Value>,
    pub tagged: u64,
    pub tag_changes: u64,
    pub tag_total: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(super) struct Checkpoint {
    pub replay_cursor: Option<Value>,
    pub replayed: u64,
    pub replay_complete: bool,
    pub publish_cursor: Option<Value>,
    pub published: u64,
    pub publish_complete: bool,
    pub ip_count: Option<i64>,
    pub port_count: Option<i64>,
}

pub(super) fn checkpoint_key(run: &Run, id: i32) -> String {
    format!("transport_rebuild:{}:{id}", run.run_id)
}

pub(super) async fn load(pool: &Pool, key: &str) -> Result<Option<Value>, String> {
    let connection = pool.get().await.map_err(|e| e.to_string())?;
    connection
        .query_opt(
            "SELECT state_value FROM scan_storage_state WHERE state_key=$1",
            &[&key],
        )
        .await
        .map(|row| row.map(|r| r.get(0)))
        .map_err(|e| e.to_string())
}

pub(super) async fn save<T: Serialize>(pool: &Pool, key: &str, value: &T) -> Result<(), String> {
    let value = serde_json::to_value(value).map_err(|e| e.to_string())?;
    pool.get().await.map_err(|e| e.to_string())?
        .execute("INSERT INTO scan_storage_state(state_key,state_value) VALUES($1,$2) ON CONFLICT(state_key) DO UPDATE SET state_value=EXCLUDED.state_value,updated_at=clock_timestamp()", &[&key,&value])
        .await.map_err(|e|e.to_string())?;
    Ok(())
}

pub(super) async fn checkpoint(pool: &Pool, run: &Run, id: i32) -> Result<Checkpoint, String> {
    load(pool, &checkpoint_key(run, id))
        .await?
        .map(serde_json::from_value)
        .transpose()
        .map(|v| v.unwrap_or_default())
        .map_err(|e| format!("执行 {id} 重建断点损坏：{e}"))
}

pub(super) async fn executions(pool: &Pool) -> Result<Vec<Execution>, String> {
    let connection = pool.get().await.map_err(|e| e.to_string())?;
    let rows = connection.query(
        "SELECT jsonb_build_object('id',e.id,'succeeded',e.execution_status='succeeded',
           'api_client_id',t.api_client_id,'context',jsonb_build_object(
             'task_id',t.task_id,'execution_id',e.execution_id,'user_id',t.user_id,
             'task_source',t.task_source,'scanner_id',COALESCE(e.assigned_scanner_id,e.requested_scanner_id,'unknown'),
             'scanner_name',s.name,'upload_id','','batch_index',0,'is_final',false))
         FROM scan_task_execution e JOIN scan_task t ON t.id=e.task_id
         LEFT JOIN scanner_info s ON s.scanner_id=COALESCE(e.assigned_scanner_id,e.requested_scanner_id)
         WHERE t.task_kind='ip'
         ORDER BY e.id", &[]).await.map_err(|e|e.to_string())?;
    rows.into_iter()
        .map(|row| serde_json::from_value(row.get(0)).map_err(|e| format!("执行元数据无效：{e}")))
        .collect()
}

/// Old checkpoints may also contain sequence numbers; these are not data audits.
pub(super) fn source_identity(source: &Value) -> Value {
    let indices = source
        .get("indices")
        .and_then(Value::as_object)
        .map(|v| {
            v.iter()
                .map(|(k, v)| (k.clone(), json!({"uuid":v["uuid"]})))
                .collect::<serde_json::Map<_, _>>()
        })
        .unwrap_or_default();
    json!({"cluster_uuid":source["cluster_uuid"],"indices":indices})
}

pub(super) fn cancelled(stop: &AtomicBool) -> Result<(), String> {
    if stop.load(Ordering::Acquire) {
        Err("重建已中断，可信断点已保留；重新运行同一命令将自动恢复".into())
    } else {
        Ok(())
    }
}

impl ElasticsearchService {
    pub(super) fn rebuild_target(&self) -> Value {
        json!({"execution_endpoint_index":self.inner.config.execution_endpoint_index,
               "current_endpoint_index":self.inner.config.current_endpoint_index})
    }

    pub(super) fn rebuild_runtime(&self) -> Value {
        json!({"observation_index_prefix":self.inner.config.observation_index_prefix,
          "execution_endpoint_index":self.inner.config.execution_endpoint_index,
          "current_endpoint_index":self.inner.config.current_endpoint_index,
          "dns_observation_data_stream":self.inner.config.dns_observation_data_stream,
          "dns_record_index":self.inner.config.dns_record_index,"endpoint_identity_version":2})
    }

    /// Inspect index identity only; do not compare source document contents or counts.
    pub(super) async fn rebuild_source(&self) -> Result<Value, String> {
        let root = self
            .send_json_request(ElasticsearchOperation::ClusterInfo, Method::GET, "/", |r| r)
            .await?;
        let version = root
            .pointer("/version/number")
            .and_then(Value::as_str)
            .ok_or("ES 缺少版本")?;
        self.inner.config.validate_server_version(version)?;
        let cluster = root
            .get("cluster_uuid")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty() && *v != "_na_")
            .ok_or("ES 缺少可信 cluster_uuid")?;
        let stats = self.send_json_request(ElasticsearchOperation::IndexAdmin, Method::GET,
            &format!("/{}-*/_stats?allow_no_indices=true&ignore_unavailable=false&filter_path=indices.*.uuid",self.inner.config.observation_index_prefix), |r|r).await?;
        let mut indices = BTreeMap::new();
        if let Some(values) = stats.get("indices").and_then(Value::as_object) {
            for (index, value) in values {
                validated_observation_indices(
                    &self.inner.config.observation_index_prefix,
                    std::slice::from_ref(index),
                )?;
                let uuid = value
                    .get("uuid")
                    .and_then(Value::as_str)
                    .ok_or("源索引缺少 UUID")?;
                indices.insert(index, json!({"uuid":uuid}));
            }
        }
        Ok(json!({"cluster_uuid":cluster,"indices":indices}))
    }

    pub(super) async fn rebuild_index(&self, name: &str) -> Result<Option<Value>, String> {
        let response = self
            .send_request(
                ElasticsearchOperation::IndexAdmin,
                Method::GET,
                &format!("/{name}?filter_path=*.settings.index.uuid,*.mappings._meta"),
                |r| r,
            )
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let value = response_json(response).await?;
        Ok(Some(
            value.get(name).cloned().ok_or("目标索引元数据缺少索引名")?,
        ))
    }

    pub(super) async fn restore_rebuild_refresh(&self) -> Result<(), String> {
        for name in [
            &self.inner.config.execution_endpoint_index,
            &self.inner.config.current_endpoint_index,
        ] {
            let result = self
                .send_json_request(
                    ElasticsearchOperation::IndexAdmin,
                    Method::PUT,
                    &format!("/{name}/_settings"),
                    |r| r.json(&json!({"index":{"refresh_interval":"1s"}})),
                )
                .await?;
            if result.get("acknowledged") != Some(&json!(true)) {
                return Err(format!(
                    "目标 {name} 恢复自动刷新未获确认；重跑将继续完成切换"
                ));
            }
        }
        Ok(())
    }

    pub(super) async fn prepare_rebuild_targets(
        &self,
        pool: &Pool,
        run: &mut Run,
    ) -> Result<(), String> {
        for name in [
            &self.inner.config.execution_endpoint_index,
            &self.inner.config.current_endpoint_index,
        ] {
            let metadata = match self.rebuild_index(name).await? {
                Some(value) => value,
                None if run.phase == Phase::Initializing
                    && !run.target_uuids.contains_key(name) =>
                {
                    let mut definition =
                        scan_endpoint_index_definition(self.inner.config.scan_number_of_replicas);
                    definition["mappings"]["_meta"]["rebuild_run_id"] = json!(run.run_id);
                    definition["settings"]["refresh_interval"] = json!("-1");
                    self.send_json_request(
                        ElasticsearchOperation::IndexAdmin,
                        Method::PUT,
                        &format!("/{name}"),
                        |r| r.json(&definition),
                    )
                    .await?;
                    self.rebuild_index(name)
                        .await?
                        .ok_or("重建目标创建后不可用")?
                }
                None => {
                    return Err(format!(
                        "重建目标 {name} 已丢失，拒绝自动创建空索引并跳过断点"
                    ));
                }
            };
            let uuid = metadata
                .pointer("/settings/index/uuid")
                .and_then(Value::as_str)
                .ok_or("重建目标缺少 UUID")?;
            if metadata.pointer("/mappings/_meta/rebuild_run_id") != Some(&json!(run.run_id))
                || metadata.pointer("/mappings/_meta/schema_version")
                    != Some(&json!(ENDPOINT_INDEX_SCHEMA_VERSION))
                || run.target_uuids.get(name).is_some_and(|v| v != uuid)
            {
                return Err(format!(
                    "重建目标 {name} 的运行身份、UUID 或 mapping 不匹配"
                ));
            }
            if !run.target_uuids.contains_key(name) {
                if run.phase != Phase::Initializing {
                    return Err("运行断点缺少目标 UUID".into());
                }
                run.target_uuids.insert(name.clone(), uuid.to_owned());
                save(pool, STATE_KEY, run).await?;
            }
        }
        self.update_runtime(|r| {
            r.connected = true;
            r.read_ready = true;
        });
        Ok(())
    }
}
