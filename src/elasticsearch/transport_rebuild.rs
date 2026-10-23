//! Offline, idempotent replay into new transport-aware projections; raw facts stay immutable.
use super::*;
impl ElasticsearchService {
    pub async fn rebuild_transport_endpoints(&self, pool: &Pool) -> Result<u64, String> {
        let connection = pool.get().await.map_err(|e| e.to_string())?;
        let previous:Option<Value>=connection.query_opt("SELECT state_value FROM scan_storage_state WHERE state_key='elasticsearch_runtime'",&[]).await.map_err(|e|e.to_string())?.map(|r|r.get(0));
        if let Some(old) = &previous {
            if old.get("endpoint_identity_version") != Some(&json!(2))
                && (old.get("execution_endpoint_index").and_then(Value::as_str)
                    == Some(&self.inner.config.execution_endpoint_index)
                    || old.get("current_endpoint_index").and_then(Value::as_str)
                        == Some(&self.inner.config.current_endpoint_index))
            {
                return Err(
                    "重建必须使用新的 execution/current 端点索引名，保留旧索引用于回滚".into(),
                );
            }
            for (key, expected) in [
                (
                    "observation_index_prefix",
                    &self.inner.config.observation_index_prefix,
                ),
                (
                    "dns_observation_data_stream",
                    &self.inner.config.dns_observation_data_stream,
                ),
                ("dns_record_index", &self.inner.config.dns_record_index),
            ] {
                if old.get(key).and_then(Value::as_str) != Some(expected) {
                    return Err("端点重建不能同时切换不可变扫描事实或 DNS 存储目标".into());
                }
            }
        }
        let pending:i64=connection.query_one("SELECT COUNT(*) FROM scan_result_batch WHERE storage_backend='pending' OR storage_backend NOT IN ('elasticsearch','dual')",&[]).await.map_err(|e|e.to_string())?.get(0);
        if pending != 0 {
            return Err("请先完成扫描上传对账和 PG→ES 迁移，再重建端点投影".into());
        }
        let target_key = json!({"execution_endpoint_index":self.inner.config.execution_endpoint_index,"current_endpoint_index":self.inner.config.current_endpoint_index});
        let saved:Option<Value>=connection.query_opt("SELECT state_value FROM scan_storage_state WHERE state_key='transport_endpoints_rebuild'",&[]).await.map_err(|e|e.to_string())?.map(|r|r.get(0));
        let resume = saved
            .as_ref()
            .filter(|v| v.get("target") == Some(&target_key))
            .and_then(|v| v.get("last_execution_id"))
            .and_then(Value::as_i64)
            .and_then(|v| i32::try_from(v).ok())
            .unwrap_or(0);
        if let Some(previous) = &previous {
            connection.execute("INSERT INTO scan_storage_state(state_key,state_value) VALUES('transport_endpoints_previous_runtime',$1) ON CONFLICT DO NOTHING",&[previous]).await.map_err(|e|e.to_string())?;
        }
        let references=connection.query("SELECT DISTINCT ref #>> '{}' FROM scan_result_batch b CROSS JOIN LATERAL jsonb_array_elements(b.storage_references) ref",&[]).await.map_err(|e|e.to_string())?;
        drop(connection);
        for row in references {
            let index: String = row.get(0);
            if !matches!(index.as_str(), "dns-observations" | "dns-records") {
                self.require_existing_index(&index).await?;
            }
        }
        self.initialize(pool).await?;
        let mut after = resume;
        let mut count = 0;
        loop {
            let connection = pool.get().await.map_err(|e| e.to_string())?;
            let row=connection.query_opt("SELECT e.id,e.execution_status,t.api_client_id FROM scan_task_execution e JOIN scan_task t ON t.id=e.task_id WHERE e.id>$1 AND EXISTS(SELECT 1 FROM scan_result_batch b WHERE b.execution_id=e.id) ORDER BY e.id LIMIT 1",&[&after]).await.map_err(|e|e.to_string())?;
            let Some(row) = row else {
                break;
            };
            after = row.get(0);
            let succeeded = row.get::<_, String>(1) == "succeeded";
            let api_client_id: Option<i32> = row.get(2);
            let context = load_scan_batch_context(&connection, after).await?;
            drop(connection);
            let mut cursor: Option<Value> = None;
            loop {
                let mut query = json!({"size":200,"track_total_hits":false,"query":{"term":{"execution_id":context.execution_id}},"sort":[{"observed_at":"asc"},{"upload_id":"asc"},{"batch_index":"asc"},{"observation_key":"asc"}]});
                if let Some(c) = &cursor {
                    query["search_after"] = c.clone();
                }
                let page = self
                    .scan_query(ScanQueryIndex::Observations, &query)
                    .await?;
                validate_scan_search_response(&page)?;
                let hits = page
                    .pointer("/hits/hits")
                    .and_then(Value::as_array)
                    .ok_or("扫描事实缺少 hits")?;
                if hits.is_empty() {
                    break;
                }
                for hit in hits {
                    let observation = hit.get("_source").ok_or("扫描事实缺少 _source")?;
                    let mut batch = context.clone();
                    batch.upload_id = observation
                        .get("upload_id")
                        .and_then(Value::as_str)
                        .ok_or("扫描事实缺少 upload_id")?
                        .into();
                    batch.batch_index = observation
                        .get("batch_index")
                        .and_then(Value::as_i64)
                        .and_then(|v| i32::try_from(v).ok())
                        .ok_or("扫描事实缺少 batch_index")?;
                    self.update_scan_endpoint_projections(
                        &batch,
                        std::slice::from_ref(observation),
                    )
                    .await?;
                }
                let next = hits
                    .last()
                    .and_then(|h| h.get("sort"))
                    .ok_or("扫描事实缺少 sort")?
                    .clone();
                if cursor.as_ref() == Some(&next) {
                    return Err("扫描事实重建分页没有前进".into());
                }
                cursor = Some(next);
                if hits.len() < 200 {
                    break;
                }
            }
            self.send_json_request(
                ElasticsearchOperation::IndexAdmin,
                Method::POST,
                &format!("/{}/_refresh", self.inner.config.execution_endpoint_index),
                |r| r,
            )
            .await?;
            if succeeded {
                // Include API client scope, preserving ownership during replay.
                let mut cursor = None;
                loop {
                    let page = self
                        .promote_execution_page(&context, cursor.as_ref(), api_client_id)
                        .await?;
                    cursor = page.cursor;
                    if page.done {
                        break;
                    }
                }
            }
            if succeeded {
                let summary = self.execution_summary(&context.execution_id, &[]).await?;
                let connection = pool.get().await.map_err(|e| e.to_string())?;
                connection.execute("UPDATE scan_task_execution SET result_ip_count=$2,result_port_count=$3 WHERE id=$1",&[&after,&summary.ip_count,&summary.port_count]).await.map_err(|e|e.to_string())?;
                for (table, revision) in [
                    ("os_detection_outbox", crate::os_detection::RULESET_REVISION),
                    (
                        "web_detection_outbox",
                        crate::web_detection::RULESET_REVISION,
                    ),
                ] {
                    connection.execute(&format!("INSERT INTO {table}(execution_id,ruleset_revision) VALUES($1,$2) ON CONFLICT(execution_id,ruleset_revision) DO UPDATE SET processed_at=NULL,cursor=NULL,claim_token=NULL,lease_expires_at=NULL,attempts=0,available_at=NOW()"),&[&after,&revision]).await.map_err(|e|e.to_string())?;
                }
            }
            let checkpoint = json!({"target":target_key,"last_execution_id":after});
            pool.get().await.map_err(|e|e.to_string())?.execute("INSERT INTO scan_storage_state(state_key,state_value) VALUES('transport_endpoints_rebuild',$1) ON CONFLICT(state_key) DO UPDATE SET state_value=EXCLUDED.state_value,updated_at=NOW()",&[&checkpoint]).await.map_err(|e|e.to_string())?;
            count += 1;
        }
        self.refresh_current_projection().await?;
        // Tags are mutable authorization inputs. Replay their current PG state
        // after all historic facts, including removed assignments, before cutover.
        let mut after: Option<Value> = None;
        loop {
            let mut composite = json!({"size":500,"sources":[{"ip":{"terms":{"field":"ip"}}}]});
            if let Some(value) = after.take() {
                composite["after"] = value;
            }
            let page = self
                .scan_query(
                    ScanQueryIndex::CurrentEndpoints,
                    &json!({"size":0,"aggs":{"ips":{"composite":composite}}}),
                )
                .await?;
            validate_scan_search_response(&page)?;
            let buckets = page
                .pointer("/aggregations/ips/buckets")
                .and_then(Value::as_array)
                .ok_or("端点重建标签分页缺少 buckets")?;
            for bucket in buckets {
                let ip = bucket
                    .pointer("/key/ip")
                    .and_then(Value::as_str)
                    .ok_or("端点重建标签缺少 IP")?;
                crate::handlers::tags::refresh_elasticsearch_tags(pool, self, ip).await?;
            }
            after = page.pointer("/aggregations/ips/after_key").cloned();
            if buckets.len() < 500 || after.is_none() {
                break;
            }
        }
        let target = json!({"observation_index_prefix":self.inner.config.observation_index_prefix,"execution_endpoint_index":self.inner.config.execution_endpoint_index,"current_endpoint_index":self.inner.config.current_endpoint_index,"dns_observation_data_stream":self.inner.config.dns_observation_data_stream,"dns_record_index":self.inner.config.dns_record_index,"endpoint_identity_version":2});
        pool.get().await.map_err(|e|e.to_string())?.execute("INSERT INTO scan_storage_state(state_key,state_value) VALUES('elasticsearch_runtime',$1) ON CONFLICT(state_key) DO UPDATE SET state_value=EXCLUDED.state_value,updated_at=NOW()",&[&target]).await.map_err(|e|e.to_string())?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elasticsearch::storage_tests::{EsFixture, isolated_pool_with_size, seed_execution};
    #[tokio::test]
    #[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
    async fn rebuild_preserves_facts_separates_transports_and_resumes_completed_execution() {
        let (pool, schema) = isolated_pool_with_size(2).await;
        seed_execution(&pool).await;
        let fixture = EsFixture::start();
        let service = fixture.service();
        let context = ScanBatchContext {
            task_id: "task".into(),
            execution_id: "execution".into(),
            user_id: 1,
            task_source: "user".into(),
            scanner_id: "scanner".into(),
            scanner_name: None,
            upload_id: "upload".into(),
            batch_index: 0,
            is_final: true,
        };
        let observations = vec![
            json!({"observation_key":"tcp","kind":"service","ip_address":"192.0.2.1","port":53,"protocol":"tcp","service":"dns","observed_at":1000}),
            json!({"observation_key":"udp","kind":"service","ip_address":"192.0.2.1","port":53,"protocol":"udp","service":"dns","observed_at":1000}),
        ];
        service
            .persist_scan_batch_prepared(&context, &observations, None)
            .await
            .unwrap();
        let raw = fixture
            .state
            .lock()
            .unwrap()
            .documents
            .iter()
            .filter(|((index, _), _)| index.contains("scan-observations"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<BTreeMap<_, _>>();
        fixture
            .state
            .lock()
            .unwrap()
            .documents
            .retain(|(index, _), _| !index.contains("endpoints"));
        pool.get().await.unwrap().batch_execute("UPDATE scan_task_execution SET execution_status='succeeded' WHERE id=1;INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count,storage_backend) VALUES(1,'upload',0,true,2,'elasticsearch');").await.unwrap();
        let previous = json!({"observation_index_prefix":service.inner.config.observation_index_prefix,"execution_endpoint_index":"legacy-execution","current_endpoint_index":"legacy-current","dns_observation_data_stream":service.inner.config.dns_observation_data_stream,"dns_record_index":service.inner.config.dns_record_index});
        pool.get().await.unwrap().execute("INSERT INTO scan_storage_state(state_key,state_value) VALUES('elasticsearch_runtime',$1)",&[&previous]).await.unwrap();
        assert_eq!(service.rebuild_transport_endpoints(&pool).await.unwrap(), 1);
        assert_eq!(service.rebuild_transport_endpoints(&pool).await.unwrap(), 0);
        assert!(
            fixture
                .state
                .lock()
                .unwrap()
                .requests
                .iter()
                .any(|r| r.contains("_update_by_query"))
        );
        let docs = fixture.state.lock().unwrap().documents.clone();
        assert_eq!(
            docs.iter()
                .filter(|((index, _), _)| index == &service.inner.config.execution_endpoint_index)
                .count(),
            2
        );
        assert_eq!(
            docs.iter()
                .filter(|((index, _), _)| index == &service.inner.config.current_endpoint_index)
                .count(),
            4
        );
        for (key, value) in raw {
            assert_eq!(docs.get(&key), Some(&value));
        }
        let connection = pool.get().await.unwrap();
        let runtime:Value=connection.query_one("SELECT state_value FROM scan_storage_state WHERE state_key='elasticsearch_runtime'",&[]).await.unwrap().get(0);
        assert_eq!(runtime["endpoint_identity_version"], 2);
        let ports: i64 = connection
            .query_one(
                "SELECT result_port_count FROM scan_task_execution WHERE id=1",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(ports, 2);
        connection
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
