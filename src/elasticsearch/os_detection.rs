//! Resumable OS enrichment. PG clients never cross Elasticsearch I/O.
use super::*;
use crate::os_detection::{RULESET_REVISION, infer};

struct OsJob {
    execution_id: i32,
    token: Uuid,
    attempts: i32,
    cursor: Option<Value>,
    context: ScanBatchContext,
    api_client_id: Option<i32>,
}

pub(super) fn service_observation_reference(
    context: &ScanBatchContext,
    observation: &Value,
    at: i64,
) -> Value {
    let Some(key) = observation.get("observation_key").and_then(Value::as_str) else {
        return Value::Null;
    };
    json!({
        "id": sha256_hex(format!("{}\0{key}", context.execution_id).as_bytes()),
        "observed_at": at
    })
}

const UPDATE_OS: &str = r#"
    boolean matches = ctx._source.service_observation_ref != null &&
        ctx._source.service_observation_ref.id == params.reference.id && ctx._source.service_observed_at_ms == params.observed_at;
    boolean legacy = (ctx._source.service_observation_ref == null || ctx._source.service_observation_ref.observed_at != ctx._source.service_observed_at_ms) &&
        ctx._source.execution_id == params.execution_id && ctx._source.user_id == params.user_id &&
        ctx._source.service_observed_at_ms == params.observed_at &&
        ctx._source.service == params.service && ctx._source.banner == params.banner;
    if ((matches || legacy) && (ctx._source.os == null ||
        ctx._source.os.ruleset_revision == null || ctx._source.os.ruleset_revision <= params.revision)) {
        ctx._source.os = params.os;
        ctx._source.service_observation_ref = params.reference;
    } else { ctx.op = 'noop'; }
"#;

impl ElasticsearchService {
    /// Backfills old successful executions in bounded slices. A new rule
    /// revision creates new jobs without changing immutable observations.
    async fn enqueue_os_backfill(&self, pool: &Pool) -> Result<(), String> {
        let mut connection = pool.get().await.map_err(|e| e.to_string())?;
        let transaction = connection.transaction().await.map_err(|e| e.to_string())?;
        transaction
            .batch_execute("SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1500ms';")
            .await
            .map_err(|e| e.to_string())?;
        transaction.execute("INSERT INTO os_detection_backfill(ruleset_revision,last_execution_id) VALUES($1,0) ON CONFLICT DO NOTHING", &[&RULESET_REVISION]).await.map_err(|e|e.to_string())?;
        let cursor: i32 = transaction.query_one("SELECT last_execution_id FROM os_detection_backfill WHERE ruleset_revision=$1 FOR UPDATE", &[&RULESET_REVISION]).await.map_err(|e|e.to_string())?.get(0);
        let rows = transaction.query("SELECT p.execution_id FROM scan_projection_outbox p JOIN scan_task_execution e ON e.id=p.execution_id WHERE p.execution_id>$1 AND e.execution_status='succeeded' ORDER BY p.execution_id LIMIT 100", &[&cursor]).await.map_err(|e|e.to_string())?;
        let ids: Vec<i32> = rows.iter().map(|r| r.get(0)).collect();
        if let Some(last) = ids.last() {
            transaction.execute("INSERT INTO os_detection_outbox(execution_id,ruleset_revision) SELECT UNNEST($1::INTEGER[]),$2 ON CONFLICT DO NOTHING", &[&ids,&RULESET_REVISION]).await.map_err(|e|e.to_string())?;
            transaction.execute("UPDATE os_detection_backfill SET last_execution_id=$2 WHERE ruleset_revision=$1", &[&RULESET_REVISION,last]).await.map_err(|e|e.to_string())?;
        }
        transaction.commit().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn claim_os_job(&self, pool: &Pool) -> Result<Option<OsJob>, String> {
        let token = Uuid::new_v4();
        let connection = pool.get().await.map_err(|e| e.to_string())?;
        let row = connection.query_opt(
            "WITH candidate AS (SELECT o.execution_id FROM os_detection_outbox o \
             JOIN scan_task_execution e ON e.id = o.execution_id \
             JOIN scan_projection_outbox p ON p.execution_id=o.execution_id \
             WHERE o.ruleset_revision = $1 AND o.processed_at IS NULL \
               AND e.execution_status = 'succeeded' AND p.processed_at IS NOT NULL AND o.available_at <= clock_timestamp() \
               AND (o.lease_expires_at IS NULL OR o.lease_expires_at <= clock_timestamp()) \
             ORDER BY o.available_at, o.execution_id FOR UPDATE OF o SKIP LOCKED LIMIT 1) \
             UPDATE os_detection_outbox o SET claim_token = $2, attempts = attempts + 1, \
               lease_expires_at = clock_timestamp() + ($3::BIGINT * INTERVAL '1 second'), updated_at = clock_timestamp() \
             FROM candidate WHERE o.execution_id = candidate.execution_id AND o.ruleset_revision = $1 \
             RETURNING o.execution_id, o.attempts, o.cursor",
            &[&RULESET_REVISION, &token, &(self.inner.config.projection_lease_seconds as i64)],
        ).await.map_err(|e| e.to_string())?;
        let Some(row) = row else {
            return Ok(None);
        };
        let execution_id: i32 = row.get("execution_id");
        let context = load_scan_batch_context(&connection, execution_id).await?;
        let api_client_id = connection.query_one(
            "SELECT t.api_client_id FROM scan_task t JOIN scan_task_execution e ON e.task_id=t.id WHERE e.id=$1",
            &[&execution_id],
        ).await.map_err(|e| e.to_string())?.get(0);
        Ok(Some(OsJob {
            execution_id,
            token,
            attempts: row.get("attempts"),
            cursor: row.get("cursor"),
            context,
            api_client_id,
        }))
    }

    async fn renew_os_job(&self, pool: &Pool, job: &OsJob) -> Result<(), String> {
        let connection = pool.get().await.map_err(|e| e.to_string())?;
        let count = connection.execute(
            "UPDATE os_detection_outbox SET lease_expires_at = clock_timestamp() + ($4::BIGINT * INTERVAL '1 second') \
             WHERE execution_id=$1 AND ruleset_revision=$2 AND claim_token=$3 \
               AND processed_at IS NULL AND lease_expires_at > clock_timestamp()",
            &[&job.execution_id, &RULESET_REVISION, &job.token, &(self.inner.config.projection_lease_seconds as i64)],
        ).await.map_err(|e| e.to_string())?;
        if count != 1 {
            return Err("OS detection lease lost".into());
        }
        Ok(())
    }

    pub(super) async fn process_os_detection_outbox(&self, pool: &Pool) -> Result<bool, String> {
        self.enqueue_os_backfill(pool).await?;
        let Some(job) = self.claim_os_job(pool).await? else {
            return Ok(false);
        };
        let work = self.enrich_os_page(&job);
        tokio::pin!(work);
        let mut heartbeat = interval(Duration::from_secs(
            self.inner.config.projection_heartbeat_seconds,
        ));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        heartbeat.tick().await;
        let outcome = loop {
            tokio::select! {
                result = &mut work => break result,
                _ = heartbeat.tick() => {
                    if let Err(error) = self.renew_os_job(pool, &job).await { break Err(error); }
                }
            }
        };
        let connection = pool.get().await.map_err(|e| e.to_string())?;
        match outcome {
            Ok((cursor, done)) => {
                let updated = connection.execute(
                    "UPDATE os_detection_outbox SET cursor=$4, processed_at=CASE WHEN $5 THEN clock_timestamp() ELSE NULL END, \
                     claim_token=NULL, lease_expires_at=NULL, attempts=0, last_error=NULL, available_at=clock_timestamp(), updated_at=clock_timestamp() \
                     WHERE execution_id=$1 AND ruleset_revision=$2 AND claim_token=$3 AND lease_expires_at > clock_timestamp()",
                    &[&job.execution_id, &RULESET_REVISION, &job.token, &cursor, &done],
                ).await.map_err(|e| e.to_string())?;
                if updated != 1 {
                    return Err("OS detection lease lost before checkpoint".into());
                }
                info!(event="OsDetectionPageCompleted", execution_id=%job.context.execution_id, complete=done, ruleset_revision=RULESET_REVISION);
            }
            Err(error) => {
                let delay = i64::from(2_i32.saturating_pow(job.attempts.clamp(1, 8) as u32));
                let message: String = error.chars().take(2000).collect();
                connection.execute(
                    "UPDATE os_detection_outbox SET claim_token=NULL, lease_expires_at=NULL, last_error=$4, \
                     available_at=clock_timestamp()+($5::BIGINT*INTERVAL '1 second'), updated_at=clock_timestamp() \
                     WHERE execution_id=$1 AND ruleset_revision=$2 AND claim_token=$3 AND lease_expires_at > clock_timestamp()",
                    &[&job.execution_id, &RULESET_REVISION, &job.token, &message, &delay],
                ).await.map_err(|e| e.to_string())?;
                return Err(error);
            }
        }
        Ok(true)
    }

    async fn enrich_os_page(&self, job: &OsJob) -> Result<(Option<Value>, bool), String> {
        let size = self.inner.config.projection_page_size.clamp(1, 64);
        let mut query = json!({"size":size,"track_total_hits":false,
            "query":{"bool":{"filter":[{"term":{"execution_id":job.context.execution_id}},{"term":{"kind":"service"}}]}},
            "sort":[{"ip_address":"asc"},{"port":"asc"},{"observed_at":"asc"},{"observation_key":"asc"}]});
        if let Some(cursor) = &job.cursor {
            query["search_after"] = cursor.clone();
        }
        let result = self
            .scan_query(ScanQueryIndex::Observations, &query)
            .await?;
        let hits = result
            .pointer("/hits/hits")
            .and_then(Value::as_array)
            .ok_or("OS evidence search missing hits")?;
        let cursor = hits
            .last()
            .map(|hit| hit.get("sort").cloned().ok_or("OS evidence missing sort"))
            .transpose()?
            .or_else(|| job.cursor.clone());
        if !hits.is_empty() && cursor == job.cursor {
            return Err("OS evidence cursor did not advance".into());
        }
        let mut body = String::new();
        let mut count = 0;
        for hit in hits {
            let source = hit.get("_source").ok_or("OS evidence missing source")?;
            let id = hit
                .get("_id")
                .and_then(Value::as_str)
                .ok_or("OS evidence missing id")?;
            let index = hit
                .get("_index")
                .and_then(Value::as_str)
                .ok_or("OS evidence missing index")?;
            let ip = source
                .get("ip_address")
                .and_then(Value::as_str)
                .ok_or("OS evidence missing IP")?;
            let port = source
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|n| u16::try_from(n).ok())
                .ok_or("OS evidence invalid port")?;
            let at = source
                .get("observed_at")
                .and_then(Value::as_i64)
                .ok_or("OS evidence missing timestamp")?;
            let service = source.get("service").and_then(Value::as_str);
            let banner = source.get("banner").and_then(Value::as_str);
            let reference = format!("{index}/{id}");
            let mut os = infer(
                service,
                banner,
                source.get("data"),
                port,
                at,
                Some(&reference),
            );
            for item in &mut os.evidence {
                item.scanner_id = Some(job.context.scanner_id.clone());
            }
            let params = json!({"reference":{"id":id,"index":index,"observed_at":at},"execution_id":job.context.execution_id,"user_id":job.context.user_id,"observed_at":at,"service":service,"banner":banner,"revision":RULESET_REVISION,"os":os});
            let mut targets = vec![(
                self.inner.config.execution_endpoint_index.as_str(),
                sha256_hex(format!("{}\0{ip}\0{port}", job.context.execution_id).as_bytes()),
            )];
            let mut scopes = vec![("global", 0), ("user", job.context.user_id)];
            if let Some(id) = job.api_client_id {
                scopes.push(("api_client", id));
            }
            for (scope, id) in scopes {
                targets.push((
                    self.inner.config.current_endpoint_index.as_str(),
                    sha256_hex(format!("{scope}\0{id}\0{ip}\0{port}").as_bytes()),
                ));
            }
            for (index, id) in targets {
                body.push_str(
                    &serde_json::to_string(
                        &json!({"update":{"_index":index,"_id":id,"retry_on_conflict":5}}),
                    )
                    .map_err(|e| e.to_string())?,
                );
                body.push('\n');
                body.push_str(
                    &serde_json::to_string(
                        &json!({"script":{"lang":"painless","source":UPDATE_OS,"params":params}}),
                    )
                    .map_err(|e| e.to_string())?,
                );
                body.push('\n');
                count += 1;
            }
        }
        if count > 0 {
            let response = self
                .send_bulk_with_retry(
                    &format!(
                        "/_bulk?wait_for_active_shards={}",
                        self.inner.config.write_wait_for_active_shards
                    ),
                    &body,
                    false,
                )
                .await?;
            let items = response
                .get("items")
                .and_then(Value::as_array)
                .ok_or("OS bulk response missing items")?;
            if items.len() != count
                || items.iter().any(|item| {
                    item.pointer("/update/status")
                        .and_then(Value::as_u64)
                        .is_none_or(|status| !(200..300).contains(&status))
                })
            {
                return Err("OS bulk update failed or incomplete".into());
            }
            // Later pages read immutable observations, not endpoint search
            // results. Leave visibility to the configured refresh interval.
        }
        Ok((cursor, hits.len() < size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn paged_os_enrichment_does_not_force_index_refreshes() {
        let fixture = super::super::storage_tests::EsFixture::start();
        let service = ElasticsearchService::new(ElasticsearchConfig {
            url: fixture.url.clone(),
            projection_page_size: 2,
            bulk_max_retries: 0,
            ..ElasticsearchConfig::default()
        })
        .unwrap();
        service.open_api_test_ready();
        let hit = |port: u16| {
            json!({
                "_index":"network-mapping-scan-observations-2026.10", "_id":format!("service-{port}"),
                "_source":{"ip_address":"192.0.2.1", "port":port, "observed_at":1000,
                    "service":"ssh", "banner":"SSH-2.0-OpenSSH_9.6 Ubuntu"},
                "sort":["192.0.2.1",port,1000,format!("service-{port}")]
            })
        };
        fixture.state.lock().unwrap().search_responses = [
            json!({"hits":{"hits":[hit(22),hit(2222)]},"_shards":{"failed":0}}),
            json!({"hits":{"hits":[hit(2223)]},"_shards":{"failed":0}}),
        ]
        .into();
        let mut job = OsJob {
            execution_id: 1,
            token: Uuid::new_v4(),
            attempts: 1,
            cursor: None,
            api_client_id: None,
            context: ScanBatchContext {
                task_id: "task".into(),
                execution_id: "execution".into(),
                user_id: 1,
                task_source: "manual".into(),
                scanner_id: "scanner".into(),
                scanner_name: None,
                upload_id: "upload".into(),
                batch_index: 0,
                is_final: true,
            },
        };
        let (cursor, done) = service.enrich_os_page(&job).await.unwrap();
        assert!(!done);
        assert_eq!(
            cursor,
            Some(json!(["192.0.2.1", 2222, 1000, "service-2222"]))
        );
        job.cursor = cursor;
        let (_, done) = service.enrich_os_page(&job).await.unwrap();
        assert!(done);
        let state = fixture.state.lock().unwrap();
        assert_eq!(state.query_bodies.len(), 2);
        assert_eq!(state.query_bodies[1].1["search_after"], job.cursor.unwrap());
        assert_eq!(
            state
                .requests
                .iter()
                .filter(|path| path.contains("/_bulk"))
                .count(),
            2
        );
        assert!(
            state
                .requests
                .iter()
                .all(|path| !path.contains("_refresh") && !path.contains("refresh="))
        );
    }

    #[tokio::test]
    #[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
    async fn os_jobs_wait_for_publication_and_recover_expired_leases() {
        let (pool, schema) = super::super::storage_tests::isolated_pool_with_size(1).await;
        super::super::storage_tests::seed_execution(&pool).await;
        let fixture = super::super::storage_tests::EsFixture::start();
        let service = fixture.service();
        {
            let c = pool.get().await.unwrap();
            c.batch_execute("UPDATE scan_task_execution SET execution_status='succeeded' WHERE id=1;
                INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count) VALUES(1,'upload',0,true,0);
                INSERT INTO scan_projection_outbox(execution_id) VALUES(1);").await.unwrap();
        }
        service.enqueue_os_backfill(&pool).await.unwrap();
        service.enqueue_os_backfill(&pool).await.unwrap();
        assert!(service.claim_os_job(&pool).await.unwrap().is_none());
        pool.get()
            .await
            .unwrap()
            .execute(
                "UPDATE scan_projection_outbox SET processed_at=NOW() WHERE execution_id=1",
                &[],
            )
            .await
            .unwrap();
        let first = service.claim_os_job(&pool).await.unwrap().unwrap();
        assert!(service.claim_os_job(&pool).await.unwrap().is_none());
        pool.get()
            .await
            .unwrap()
            .execute(
                "UPDATE os_detection_outbox SET lease_expires_at=NOW()-INTERVAL '1 second'",
                &[],
            )
            .await
            .unwrap();
        let second = service.claim_os_job(&pool).await.unwrap().unwrap();
        assert_ne!(first.token, second.token);
        assert!(service.renew_os_job(&pool, &first).await.is_err());
        service.renew_os_job(&pool, &second).await.unwrap();
        let connection = pool.get().await.unwrap();
        assert_eq!(
            connection
                .query_one("SELECT COUNT(*) FROM os_detection_outbox", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            1
        );
        assert_eq!(
            connection
                .query_one("SELECT last_execution_id FROM os_detection_backfill", &[])
                .await
                .unwrap()
                .get::<_, i32>(0),
            1
        );
        connection
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires STORAGE_TEST_DATABASE_URL and real Elasticsearch STORAGE_TEST_CONFIG_PATH"]
    async fn live_os_enrichment_preserves_raw_checksums_and_newer_service_evidence() {
        let (pool, schema) = super::super::storage_tests::isolated_pool_with_size(1).await;
        super::super::storage_tests::seed_execution(&pool).await;
        let mut config = super::super::storage_tests::live_test_elasticsearch_config();
        let prefix = format!("nm-os-test-{}", Uuid::new_v4().simple());
        config.observation_index_prefix = format!("{prefix}-observations");
        config.execution_endpoint_index = format!("{prefix}-execution");
        config.current_endpoint_index = format!("{prefix}-current");
        config.dns_observation_data_stream = format!("{prefix}-dns");
        config.dns_record_index = format!("{prefix}-rr");
        config.scan_number_of_replicas = 0;
        config.projection_page_size = 1; // Force the resumable path.
        let service = ElasticsearchService::new(config).unwrap();
        let at = Utc::now().timestamp_millis();
        let test=async {
            // Existing strict indices must receive the additive mapping too.
            let mut legacy=scan_endpoint_index_definition(0);
            legacy["mappings"]["properties"].as_object_mut().unwrap().remove("os");
            legacy["mappings"]["properties"].as_object_mut().unwrap().remove("service_observation_ref");
            legacy["mappings"]["_meta"]["schema_version"]=json!("5");
            service.ensure_named_index(&service.inner.config.execution_endpoint_index,&legacy).await?;
            service.ensure_named_index(&service.inner.config.current_endpoint_index,&legacy).await?;
            service.initialize(&pool).await?;
            {
                let c=pool.get().await.map_err(|e|e.to_string())?;
                c.batch_execute("UPDATE scan_task_execution SET execution_status='succeeded' WHERE id=1;
                    INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count) VALUES(1,'upload',0,true,0);
                    INSERT INTO api_client(id,client_id,owner_user_id,name,kind,policy,requested_policy) VALUES(77,gen_random_uuid(),1,'OS fixture','personal','{}','{}');
                    UPDATE scan_task SET api_client_id=77 WHERE id=1;
                    INSERT INTO scan_projection_outbox(execution_id) VALUES(1);").await.map_err(|e|e.to_string())?;
            }
            let mut context={let c=pool.get().await.map_err(|e|e.to_string())?;load_scan_batch_context(&c,1).await?};
            context.is_final=false;
            let observation=json!({"observation_key":"ssh-1","endpoint_id":"endpoint","kind":"service","ip_address":"192.0.2.1","ip_network":"192.0.2.1/32","port":2222,"protocol":"tcp","service":"ssh","banner":"SSH-2.0-OpenSSH_9.6 Ubuntu-3ubuntu0.11","source":"zgrab2","data":{"schema_version":2,"evidence":[]},"observed_at":at,"tags":[]});
            let before=scan_batch_payload_checksum(&context,std::slice::from_ref(&observation))?;
            service.persist_scan_batch_prepared(&context,std::slice::from_ref(&observation),None).await?;
            service.send_json_request(ElasticsearchOperation::IndexAdmin,Method::POST,&format!("/{prefix}-*/_refresh"),|r|r).await?;
            let raw_index=scan_observation_index(&service.inner.config.observation_index_prefix,at)?;
            let raw_id=sha256_hex(format!("{}\0ssh-1",context.execution_id).as_bytes());
            let raw_before=service.send_json_request(ElasticsearchOperation::ScanQuery,Method::GET,&format!("/{raw_index}/_doc/{raw_id}"),|r|r).await?;
            for _ in 0..10 { if !service.process_scan_projection_outbox(&pool).await? {break;} }
            for _ in 0..5 {
                if !service.process_os_detection_outbox(&pool).await? { break; }
            }
            // Production uses normal near-real-time refresh. Make this test's
            // search visibility deterministic without refreshing each page.
            service.send_json_request(ElasticsearchOperation::IndexAdmin,Method::POST,
                &format!("/{},{}/_refresh",service.inner.config.execution_endpoint_index,service.inner.config.current_endpoint_index),|r|r).await?;
            let job=OsJob { execution_id:1, token:Uuid::new_v4(),attempts:1,cursor:None,context:context.clone(),api_client_id:Some(77) };
            let results=service.scan_query(ScanQueryIndex::CurrentEndpoints,&json!({"size":10,"query":{"match_all":{}}})).await?;
            let hits=results.pointer("/hits/hits").and_then(Value::as_array).ok_or("missing enriched hits")?;
            assert_eq!(hits.len(),3);
            for hit in hits {assert_eq!(hit["_source"]["os"]["family"],"linux");}
            assert_eq!(before,scan_batch_payload_checksum(&context,std::slice::from_ref(&observation))?);
            let receipt=pool.get().await.map_err(|e|e.to_string())?.query_one("SELECT processed_at IS NOT NULL FROM os_detection_outbox WHERE execution_id=1",&[]).await.map_err(|e|e.to_string())?;
            assert!(receipt.get::<_,bool>(0));
            // A newer successful service result must invalidate the previous
            // OS conclusion, and replaying the older job must not restore it.
            let mut newer=observation.clone(); newer["observation_key"]=json!("ssh-2");newer["banner"]=json!("SSH-2.0-OpenSSH_for_Windows_9.5");
            let event=endpoint_projection_document(&context,&newer,at+1000);
            let current_id=sha256_hex(format!("user\0{}\0{}\0{}",1,"192.0.2.1",2222).as_bytes());
            let mut bulk=String::new(); append_projection_update(&mut bulk,&service.inner.config.current_endpoint_index,&current_id,&event)?;
            let response=service.send_bulk_with_retry("/_bulk",&bulk,false).await?;assert_eq!(response["errors"],false);
            service.enrich_os_page(&job).await?;
            let current=service.send_json_request(ElasticsearchOperation::ScanQuery,Method::GET,&format!("/{}/_doc/{current_id}",service.inner.config.current_endpoint_index),|r|r).await?;
            assert_eq!(current["_source"]["os"]["status"],"pending");
            let raw_after=service.send_json_request(ElasticsearchOperation::ScanQuery,Method::GET,&format!("/{raw_index}/_doc/{raw_id}"),|r|r).await?;
            assert_eq!(raw_before["_source"],raw_after["_source"]);
            // Retrying the same raw upload after enrichment is still identical.
            service.persist_scan_batch_prepared(&context,&[observation],None).await?;
            Ok::<(),String>(())
        }.await;
        let _ = service
            .send_json_request(
                ElasticsearchOperation::IndexAdmin,
                Method::DELETE,
                &format!("/_data_stream/{prefix}-dns"),
                |r| r,
            )
            .await;
        let raw_index =
            scan_observation_index(&service.inner.config.observation_index_prefix, at).unwrap();
        let mut cleanup_error = None;
        for index in [
            &service.inner.config.execution_endpoint_index,
            &service.inner.config.current_endpoint_index,
            &service.inner.config.dns_record_index,
            &raw_index,
        ] {
            if let Err(error) = service
                .send_json_request(
                    ElasticsearchOperation::IndexAdmin,
                    Method::DELETE,
                    &format!("/{index}"),
                    |r| r,
                )
                .await
            {
                cleanup_error = Some(error);
            }
        }
        for template in [
            format!("{prefix}-observations-template"),
            format!("{prefix}-dns-template"),
        ] {
            let _ = service
                .send_json_request(
                    ElasticsearchOperation::IndexAdmin,
                    Method::DELETE,
                    &format!("/_index_template/{template}"),
                    |r| r,
                )
                .await;
        }
        pool.get()
            .await
            .unwrap()
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
        test.unwrap();
        assert!(cleanup_error.is_none(), "{cleanup_error:?}");
    }
}
