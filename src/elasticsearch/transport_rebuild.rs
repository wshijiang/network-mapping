//! Offline replay with durable page checkpoints and atomic runtime cutover.
use super::*;
mod io;
mod replay;
mod runner;
mod state;
mod tags;
use io::Bulk;
use state::*;
impl ElasticsearchService {
    /// Offline CLI profile: use the supported throughput limits without changing normal service defaults.
    pub(crate) fn transport_rebuild_config(mut config: ElasticsearchConfig) -> ElasticsearchConfig {
        config.bulk_batch_size = 2000;
        config.projection_page_size = 2000;
        config.projection_bulk_max_bytes = 16 * 1024 * 1024;
        config.bulk_max_concurrency = 32;
        config.scan_migration_concurrency = 32;
        config.scan_migration_page_size = config.scan_migration_page_size.max(32);
        config
    }

    pub async fn rebuild_transport_endpoints(&self, pool: &Pool) -> Result<u64, String> {
        self.rebuild_transport_endpoints_with_progress(pool, &NoopProgressReporter)
            .await
    }
    pub async fn rebuild_transport_endpoints_with_progress(
        &self,
        pool: &Pool,
        reporter: &dyn ProgressReporter,
    ) -> Result<u64, String> {
        self.rebuild_transport_endpoints_controlled(pool, reporter, &AtomicBool::new(false))
            .await
    }
    pub(crate) async fn rebuild_transport_endpoints_controlled(
        &self,
        pool: &Pool,
        reporter: &dyn ProgressReporter,
        stop: &AtomicBool,
    ) -> Result<u64, String> {
        reporter.report(ProgressUpdate::phase(format!(
            "重建吞吐：并发 {}，分页 {}，Bulk {} 条 / {} MiB",
            self.inner
                .config
                .bulk_max_concurrency
                .min(self.inner.config.scan_migration_concurrency),
            self.inner.config.projection_page_size,
            self.inner.config.bulk_batch_size,
            self.inner.config.projection_bulk_max_bytes / (1024 * 1024)
        )));
        let result = runner::run(self, pool, reporter, stop).await;
        *self
            .inner
            .maintenance_run_id
            .write()
            .expect("maintenance identity lock poisoned") = None;
        result
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
            json!({"observation_key":"vulnerability","kind":"vulnerability","ip_address":"192.0.2.1","port":53,"protocol":"tcp","observed_at":1000,"data":{"template_id":"test-only"}}),
        ];
        let receipt = service
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
        pool.get().await.unwrap().batch_execute("UPDATE scan_task_execution SET execution_status='succeeded' WHERE id=1;INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count,storage_backend) VALUES(1,'upload',0,true,3,'elasticsearch');INSERT INTO scan_projection_outbox(execution_id,cursor,phase,attempts,last_error,claim_token,lease_expires_at) VALUES(1,'[\"192.0.2.1\",53]'::jsonb,'promoting',3,'legacy cursor',gen_random_uuid(),NOW()+INTERVAL '1 hour');").await.unwrap();
        pool.get()
            .await
            .unwrap()
            .execute(
                "UPDATE scan_result_batch SET payload_checksum=$1,storage_references=$2",
                &[&receipt.payload_checksum, &json!(receipt.indices)],
            )
            .await
            .unwrap();
        let previous = json!({"observation_index_prefix":service.inner.config.observation_index_prefix,"execution_endpoint_index":"legacy-execution","current_endpoint_index":"legacy-current","dns_observation_data_stream":service.inner.config.dns_observation_data_stream,"dns_record_index":service.inner.config.dns_record_index});
        pool.get().await.unwrap().execute("INSERT INTO scan_storage_state(state_key,state_value) VALUES('elasticsearch_runtime',$1)",&[&previous]).await.unwrap();
        fixture
            .state
            .lock()
            .unwrap()
            .refresh_responses
            .push_back(json!({"_shards":{"total":1,"successful":0,"failed":0}}));
        let error = service
            .rebuild_transport_endpoints(&pool)
            .await
            .unwrap_err();
        assert!(error.contains("successful=0"), "{error}");
        let connection = pool.get().await.unwrap();
        let unchanged: Value = connection.query_one("SELECT state_value FROM scan_storage_state WHERE state_key='elasticsearch_runtime'",&[]).await.unwrap().get(0);
        assert_eq!(unchanged, previous);
        assert!(connection.query_opt("SELECT state_value FROM scan_storage_state WHERE state_key='transport_endpoints_rebuild'",&[]).await.unwrap().is_some());
        let published: bool = connection
            .query_one(
                "SELECT processed_at IS NOT NULL FROM scan_projection_outbox WHERE execution_id=1",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert!(!published);
        drop(connection);
        // Restore shard availability and rerun without deleting facts or state.
        assert_eq!(service.rebuild_transport_endpoints(&pool).await.unwrap(), 1);
        assert_eq!(service.rebuild_transport_endpoints(&pool).await.unwrap(), 0);
        assert!(
            fixture
                .state
                .lock()
                .unwrap()
                .requests
                .iter()
                .all(|r| !r.contains("_update_by_query"))
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
        let publication=connection.query_one("SELECT cursor,processed_at IS NOT NULL AS complete,claim_token,attempts,processed_endpoints FROM scan_projection_outbox WHERE execution_id=1",&[]).await.unwrap();
        assert!(publication.get::<_, Option<Value>>("cursor").is_none());
        assert!(publication.get::<_, bool>("complete"));
        assert!(publication.get::<_, Option<Uuid>>("claim_token").is_none());
        assert_eq!(publication.get::<_, i32>("attempts"), 0);
        assert_eq!(publication.get::<_, i64>("processed_endpoints"), 2);
        let ready:i64=connection.query_one("SELECT COUNT(*) FROM os_detection_outbox o JOIN scan_projection_outbox p USING(execution_id) WHERE p.processed_at IS NOT NULL AND o.processed_at IS NULL",&[]).await.unwrap().get(0);
        assert_eq!(ready, 1);

        connection
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn vulnerability_only_projection_does_not_send_an_empty_bulk() {
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
        service
            .update_scan_endpoint_projections(&context, &[json!({"kind":"vulnerability"})])
            .await
            .unwrap();
        assert!(fixture.state.lock().unwrap().requests.is_empty());
    }
}

#[cfg(test)]
mod recovery_tests;
