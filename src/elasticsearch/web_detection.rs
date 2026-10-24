//! Resumable Web enrichment. PG clients never cross Elasticsearch I/O.
use super::*;
use crate::web_detection::{RULESET_REVISION, infer};

struct WebJob {
    execution_id: i32,
    token: Uuid,
    attempts: i32,
    cursor: Option<Value>,
    context: ScanBatchContext,
    api_client_id: Option<i32>,
}

// The endpoint execution tracks the latest port observation, not necessarily
// its preserved service evidence. Legacy matches use the service clock and
// contents; a valid, different service reference must never use this fallback.
const UPDATE_WEB: &str = r#"
    boolean matches = ctx._source.service_observation_ref != null &&
        ctx._source.service_observation_ref.id == params.reference.id && ctx._source.service_observed_at_ms == params.observed_at;
    boolean legacy = params.allow_legacy && (ctx._source.service_observation_ref == null || ctx._source.service_observation_ref.observed_at != ctx._source.service_observed_at_ms) &&
        ctx._source.user_id == params.user_id &&
        ctx._source.service_observed_at_ms == params.observed_at &&
        ctx._source.service == params.service && ctx._source.banner == params.banner;
    if ((matches || legacy) && (ctx._source.web == null ||
        ctx._source.web.ruleset_revision == null || ctx._source.web.ruleset_revision <= params.revision)) {
        ctx._source.web = params.web;
        ctx._source.service_observation_ref = params.reference;
    } else { ctx.op = 'noop'; }
"#;

impl ElasticsearchService {
    /// A legacy endpoint has no stable service identity. Timestamp and banner
    /// equality cannot distinguish observations from different executions, so
    /// only enable that fallback when no other service observation exists at
    /// the same user's endpoint and service time. Ignore content equality:
    /// rejecting more old matches is preferable to installing the wrong ref.
    #[allow(clippy::too_many_arguments)]
    async fn web_legacy_evidence_is_unique(
        &self,
        user_id: i32,
        ip: &str,
        port: u16,
        protocol: &str,
        at: i64,
        observation_id: &str,
    ) -> Result<bool, String> {
        let transport = if protocol == "unknown" {
            json!({"bool":{"must_not":{"terms":{"protocol":["tcp","udp"]}}}})
        } else {
            json!({"term":{"protocol":protocol}})
        };
        let query = json!({
            "size": 1, "track_total_hits": false, "_source": false,
            "query": {"bool": {
                "filter": [
                    {"term": {"user_id": user_id}},
                    {"term": {"ip_address": ip}},
                    {"term": {"port": port}},
                    transport,
                    {"term": {"kind": "service"}},
                    {"term": {"observed_at": at}}
                ],
                "must_not": [{"ids": {"values": [observation_id]}}]
            }}
        });
        let result = self
            .scan_query(ScanQueryIndex::Observations, &query)
            .await?;
        let hits = result
            .pointer("/hits/hits")
            .and_then(Value::as_array)
            .ok_or("Web legacy evidence uniqueness search missing hits")?;
        Ok(hits.is_empty())
    }

    /// Backfills old successful executions in bounded slices. A new rule
    /// revision creates new jobs without changing immutable observations.
    async fn enqueue_web_backfill(&self, pool: &Pool) -> Result<(), String> {
        let mut connection = pool.get().await.map_err(|e| e.to_string())?;
        let transaction = connection.transaction().await.map_err(|e| e.to_string())?;
        transaction
            .batch_execute("SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1500ms';")
            .await
            .map_err(|e| e.to_string())?;
        transaction.execute("INSERT INTO web_detection_backfill(ruleset_revision,last_execution_id) VALUES($1,0) ON CONFLICT DO NOTHING", &[&RULESET_REVISION]).await.map_err(|e|e.to_string())?;
        let cursor: i32 = transaction.query_one("SELECT last_execution_id FROM web_detection_backfill WHERE ruleset_revision=$1 FOR UPDATE", &[&RULESET_REVISION]).await.map_err(|e|e.to_string())?.get(0);
        let rows = transaction.query("SELECT p.execution_id FROM scan_projection_outbox p JOIN scan_task_execution e ON e.id=p.execution_id WHERE p.execution_id>$1 AND e.execution_status='succeeded' ORDER BY p.execution_id LIMIT 100", &[&cursor]).await.map_err(|e|e.to_string())?;
        let ids: Vec<i32> = rows.iter().map(|r| r.get(0)).collect();
        if let Some(last) = ids.last() {
            transaction.execute("INSERT INTO web_detection_outbox(execution_id,ruleset_revision) SELECT UNNEST($1::INTEGER[]),$2 ON CONFLICT DO NOTHING", &[&ids,&RULESET_REVISION]).await.map_err(|e|e.to_string())?;
            transaction.execute("UPDATE web_detection_backfill SET last_execution_id=$2 WHERE ruleset_revision=$1", &[&RULESET_REVISION,last]).await.map_err(|e|e.to_string())?;
        }
        transaction.commit().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn claim_web_job(&self, pool: &Pool) -> Result<Option<WebJob>, String> {
        let token = Uuid::new_v4();
        let connection = pool.get().await.map_err(|e| e.to_string())?;
        let row = connection.query_opt(
            "WITH candidate AS (SELECT o.execution_id FROM web_detection_outbox o \
             JOIN scan_task_execution e ON e.id = o.execution_id \
             JOIN scan_projection_outbox p ON p.execution_id=o.execution_id \
             WHERE o.ruleset_revision = $1 AND o.processed_at IS NULL \
               AND e.execution_status = 'succeeded' AND p.processed_at IS NOT NULL AND o.available_at <= clock_timestamp() \
               AND (o.lease_expires_at IS NULL OR o.lease_expires_at <= clock_timestamp()) \
             ORDER BY o.available_at, o.execution_id FOR UPDATE OF o SKIP LOCKED LIMIT 1) \
             UPDATE web_detection_outbox o SET claim_token = $2, attempts = attempts + 1, \
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
        Ok(Some(WebJob {
            execution_id,
            token,
            attempts: row.get("attempts"),
            cursor: row.get("cursor"),
            context,
            api_client_id,
        }))
    }

    async fn renew_web_job(&self, pool: &Pool, job: &WebJob) -> Result<(), String> {
        let connection = pool.get().await.map_err(|e| e.to_string())?;
        let count = connection.execute(
            "UPDATE web_detection_outbox SET lease_expires_at = clock_timestamp() + ($4::BIGINT * INTERVAL '1 second') \
             WHERE execution_id=$1 AND ruleset_revision=$2 AND claim_token=$3 \
               AND processed_at IS NULL AND lease_expires_at > clock_timestamp()",
            &[&job.execution_id, &RULESET_REVISION, &job.token, &(self.inner.config.projection_lease_seconds as i64)],
        ).await.map_err(|e| e.to_string())?;
        if count != 1 {
            return Err("Web detection lease lost".into());
        }
        Ok(())
    }

    pub(super) async fn process_web_detection_outbox(&self, pool: &Pool) -> Result<bool, String> {
        self.enqueue_web_backfill(pool).await?;
        let Some(job) = self.claim_web_job(pool).await? else {
            return Ok(false);
        };
        let work = self.enrich_web_page(&job);
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
                    if let Err(error) = self.renew_web_job(pool, &job).await { break Err(error); }
                }
            }
        };
        let connection = pool.get().await.map_err(|e| e.to_string())?;
        match outcome {
            Ok((cursor, done)) => {
                let updated = connection.execute(
                    "UPDATE web_detection_outbox SET cursor=$4, processed_at=CASE WHEN $5 THEN clock_timestamp() ELSE NULL END, \
                     claim_token=NULL, lease_expires_at=NULL, attempts=0, last_error=NULL, available_at=clock_timestamp(), updated_at=clock_timestamp() \
                     WHERE execution_id=$1 AND ruleset_revision=$2 AND claim_token=$3 AND lease_expires_at > clock_timestamp()",
                    &[&job.execution_id, &RULESET_REVISION, &job.token, &cursor, &done],
                ).await.map_err(|e| e.to_string())?;
                if updated != 1 {
                    return Err("Web detection lease lost before checkpoint".into());
                }
                info!(event="WebDetectionPageCompleted", execution_id=%job.context.execution_id, complete=done, ruleset_revision=RULESET_REVISION);
            }
            Err(error) => {
                let delay = i64::from(2_i32.saturating_pow(job.attempts.clamp(1, 8) as u32));
                let message: String = error.chars().take(2000).collect();
                connection.execute(
                    "UPDATE web_detection_outbox SET claim_token=NULL, lease_expires_at=NULL, last_error=$4, \
                     available_at=clock_timestamp()+($5::BIGINT*INTERVAL '1 second'), updated_at=clock_timestamp() \
                     WHERE execution_id=$1 AND ruleset_revision=$2 AND claim_token=$3 AND lease_expires_at > clock_timestamp()",
                    &[&job.execution_id, &RULESET_REVISION, &job.token, &message, &delay],
                ).await.map_err(|e| e.to_string())?;
                return Err(error);
            }
        }
        Ok(true)
    }

    async fn enrich_web_page(&self, job: &WebJob) -> Result<(Option<Value>, bool), String> {
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
            .ok_or("Web evidence search missing hits")?;
        let cursor = hits
            .last()
            .map(|hit| hit.get("sort").cloned().ok_or("Web evidence missing sort"))
            .transpose()?
            .or_else(|| job.cursor.clone());
        if !hits.is_empty() && cursor == job.cursor {
            return Err("Web evidence cursor did not advance".into());
        }
        let mut body = String::new();
        let mut count = 0;
        for hit in hits {
            let source = hit.get("_source").ok_or("Web evidence missing source")?;
            let id = hit
                .get("_id")
                .and_then(Value::as_str)
                .ok_or("Web evidence missing id")?;
            let index = hit
                .get("_index")
                .and_then(Value::as_str)
                .ok_or("Web evidence missing index")?;
            let ip = source
                .get("ip_address")
                .and_then(Value::as_str)
                .ok_or("Web evidence missing IP")?;
            let port = source
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|n| u16::try_from(n).ok())
                .ok_or("Web evidence invalid port")?;
            let at = source
                .get("observed_at")
                .and_then(Value::as_i64)
                .ok_or("Web evidence missing timestamp")?;
            let service = source.get("service").and_then(Value::as_str);
            let banner = source.get("banner").and_then(Value::as_str);
            let reference = format!("{index}/{id}");
            let web = infer(
                service,
                banner,
                source.get("data"),
                port,
                at,
                Some(&reference),
            );
            let allow_legacy = self
                .web_legacy_evidence_is_unique(
                    job.context.user_id,
                    ip,
                    port,
                    endpoint_protocol(source),
                    at,
                    id,
                )
                .await?;
            let params = json!({"reference":{"id":id,"index":index,"observed_at":at},"allow_legacy":allow_legacy,"execution_id":job.context.execution_id,"user_id":job.context.user_id,"observed_at":at,"service":service,"banner":banner,"revision":RULESET_REVISION,"web":web});
            let mut targets = vec![(
                self.inner.config.execution_endpoint_index.as_str(),
                sha256_hex(
                    format!(
                        "{}\0{ip}\0{port}\0{}",
                        job.context.execution_id,
                        endpoint_protocol(source)
                    )
                    .as_bytes(),
                ),
            )];
            let mut scopes = vec![("global", 0), ("user", job.context.user_id)];
            if let Some(id) = job.api_client_id {
                scopes.push(("api_client", id));
            }
            for (scope, id) in scopes {
                targets.push((
                    self.inner.config.current_endpoint_index.as_str(),
                    sha256_hex(
                        format!("{scope}\0{id}\0{ip}\0{port}\0{}", endpoint_protocol(source))
                            .as_bytes(),
                    ),
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
                        &json!({"script":{"lang":"painless","source":UPDATE_WEB,"params":params}}),
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
                .ok_or("Web bulk response missing items")?;
            if items.len() != count
                || items.iter().any(|item| {
                    let status = item.pointer("/update/status").and_then(Value::as_u64);
                    let deleted = status == Some(404)
                        && item.pointer("/update/error/type").and_then(Value::as_str)
                            == Some("document_missing_exception");
                    !deleted && status.is_none_or(|status| !(200..300).contains(&status))
                })
            {
                return Err("Web bulk update failed or incomplete".into());
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
    async fn paged_web_enrichment_does_not_force_index_refreshes() {
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
                    "service":"http", "data":{"schema_version":2,"evidence":[{"module":"http","result":{"response":{"headers":{"server":"nginx/1.26.2"},"body":""}}}]}},
                "sort":["192.0.2.1",port,1000,format!("service-{port}")]
            })
        };
        fixture.state.lock().unwrap().search_responses = [
            json!({"hits":{"hits":[hit(22),hit(2222)]},"_shards":{"failed":0}}),
            json!({"hits":{"hits":[]},"_shards":{"failed":0}}),
            json!({"hits":{"hits":[]},"_shards":{"failed":0}}),
            json!({"hits":{"hits":[hit(2223)]},"_shards":{"failed":0}}),
            json!({"hits":{"hits":[]},"_shards":{"failed":0}}),
        ]
        .into();
        let mut job = WebJob {
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
        let (cursor, done) = service.enrich_web_page(&job).await.unwrap();
        assert!(!done);
        assert_eq!(
            cursor,
            Some(json!(["192.0.2.1", 2222, 1000, "service-2222"]))
        );
        job.cursor = cursor;
        let (_, done) = service.enrich_web_page(&job).await.unwrap();
        assert!(done);
        let state = fixture.state.lock().unwrap();
        assert_eq!(state.query_bodies.len(), 5);
        assert_eq!(state.query_bodies[3].1["search_after"], job.cursor.unwrap());
        let uniqueness = &state.query_bodies[1].1;
        assert_eq!(uniqueness["size"], 1);
        assert_eq!(
            uniqueness["query"]["bool"]["filter"][0]["term"]["user_id"],
            1
        );
        assert_eq!(
            uniqueness["query"]["bool"]["must_not"][0]["ids"]["values"][0],
            "service-22"
        );
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
    async fn web_jobs_wait_for_publication_and_recover_expired_leases() {
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
        service.enqueue_web_backfill(&pool).await.unwrap();
        service.enqueue_web_backfill(&pool).await.unwrap();
        assert!(service.claim_web_job(&pool).await.unwrap().is_none());
        pool.get()
            .await
            .unwrap()
            .execute(
                "UPDATE scan_projection_outbox SET processed_at=NOW() WHERE execution_id=1",
                &[],
            )
            .await
            .unwrap();
        let first = service.claim_web_job(&pool).await.unwrap().unwrap();
        assert!(service.claim_web_job(&pool).await.unwrap().is_none());
        pool.get()
            .await
            .unwrap()
            .execute(
                "UPDATE web_detection_outbox SET lease_expires_at=NOW()-INTERVAL '1 second'",
                &[],
            )
            .await
            .unwrap();
        let second = service.claim_web_job(&pool).await.unwrap().unwrap();
        assert_ne!(first.token, second.token);
        assert!(service.renew_web_job(&pool, &first).await.is_err());
        service.renew_web_job(&pool, &second).await.unwrap();
        let connection = pool.get().await.unwrap();
        assert_eq!(
            connection
                .query_one("SELECT COUNT(*) FROM web_detection_outbox", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            1
        );
        assert_eq!(
            connection
                .query_one("SELECT last_execution_id FROM web_detection_backfill", &[])
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
    async fn live_web_enrichment_preserves_raw_checksums_and_newer_service_evidence() {
        let (pool, schema) = super::super::storage_tests::isolated_pool_with_size(1).await;
        super::super::storage_tests::seed_execution(&pool).await;
        let mut config = super::super::storage_tests::live_test_elasticsearch_config();
        let prefix = format!("nm-web-test-{}", Uuid::new_v4().simple());
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
            legacy["mappings"]["properties"].as_object_mut().unwrap().remove("web");
            legacy["mappings"]["properties"].as_object_mut().unwrap().remove("service_observation_ref");
            legacy["mappings"]["_meta"]["schema_version"]=json!("5");
            service.ensure_named_index(&service.inner.config.execution_endpoint_index,&legacy).await?;
            service.ensure_named_index(&service.inner.config.current_endpoint_index,&legacy).await?;
            service.initialize(&pool).await?;
            {
                let c=pool.get().await.map_err(|e|e.to_string())?;
                c.batch_execute("UPDATE scan_task_execution SET execution_status='succeeded' WHERE id=1;
                    INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count) VALUES(1,'upload',0,true,0);
                    INSERT INTO api_client(id,client_id,owner_user_id,name,kind,policy,requested_policy) VALUES(77,gen_random_uuid(),1,'Web fixture','personal','{}','{}');
                    UPDATE scan_task SET api_client_id=77 WHERE id=1;
                    INSERT INTO scan_projection_outbox(execution_id) VALUES(1);").await.map_err(|e|e.to_string())?;
            }
            let mut context={let c=pool.get().await.map_err(|e|e.to_string())?;load_scan_batch_context(&c,1).await?};
            context.is_final=false;
            let observation=json!({"observation_key":"http-1","endpoint_id":"endpoint","kind":"service","ip_address":"192.0.2.1","ip_network":"192.0.2.1/32","port":2222,"protocol":"tcp","service":"http","banner":"HTTP/1.1 200 OK","source":"zgrab2","data":{"schema_version":2,"evidence":[{"module":"http","result":{"response":{"headers":{"server":"nginx/1.26.2"},"body":"<script src=\"/jquery-3.7.1.min.js\"></script>"}}}]},"observed_at":at,"tags":[]});
            let before=scan_batch_payload_checksum(&context,std::slice::from_ref(&observation))?;
            service.persist_scan_batch_prepared(&context,std::slice::from_ref(&observation),None).await?;
            service.send_json_request(ElasticsearchOperation::IndexAdmin,Method::POST,&format!("/{prefix}-*/_refresh"),|r|r).await?;
            let raw_index=scan_observation_index(&service.inner.config.observation_index_prefix,at)?;
            let raw_id=sha256_hex(format!("{}\0http-1",context.execution_id).as_bytes());
            let raw_before=service.send_json_request(ElasticsearchOperation::ScanQuery,Method::GET,&format!("/{raw_index}/_doc/{raw_id}"),|r|r).await?;
            for _ in 0..10 { if !service.process_scan_projection_outbox(&pool).await? {break;} }
            for _ in 0..5 {
                if !service.process_web_detection_outbox(&pool).await? { break; }
            }
            // Production uses normal near-real-time refresh. Make this test's
            // search visibility deterministic without refreshing each page.
            service.send_json_request(ElasticsearchOperation::IndexAdmin,Method::POST,
                &format!("/{},{}/_refresh",service.inner.config.execution_endpoint_index,service.inner.config.current_endpoint_index),|r|r).await?;
            let job=WebJob { execution_id:1, token:Uuid::new_v4(),attempts:1,cursor:None,context:context.clone(),api_client_id:Some(77) };
            let results=service.scan_query(ScanQueryIndex::CurrentEndpoints,&json!({"size":10,"query":{"match_all":{}}})).await?;
            let hits=results.pointer("/hits/hits").and_then(Value::as_array).ok_or("missing enriched hits")?;
            assert_eq!(hits.len(),3);
            for hit in hits {assert_eq!(hit["_source"]["web"]["status"],"identified"); assert_eq!(hit["_source"]["web"]["technologies"].as_array().unwrap().len(),2);}
            assert_eq!(before,scan_batch_payload_checksum(&context,std::slice::from_ref(&observation))?);
            let receipt=pool.get().await.map_err(|e|e.to_string())?.query_one("SELECT processed_at IS NOT NULL FROM web_detection_outbox WHERE execution_id=1",&[]).await.map_err(|e|e.to_string())?;
            assert!(receipt.get::<_,bool>(0));
            // Correlate a technology ID and version in real nested mappings.
            for (expression,expected) in [("tech = \"jquery@3.7.1\"",3),("tech = \"nginx@3.7.1\"",0)] {
                let crate::handlers::search_dsl::ElasticsearchCompilation::Supported(filter)=crate::handlers::search_dsl::parse_and_compile_elasticsearch(expression).map_err(|e|e.message)? else { return Err("unsupported technology filter".into()) };
                let result=service.scan_query(ScanQueryIndex::CurrentEndpoints,&json!({"size":10,"query":filter})).await?;
                assert_eq!(result.pointer("/hits/total/value").and_then(Value::as_i64),Some(expected));
            }
            let current_id=sha256_hex(format!("user\0{}\0{}\0{}\0tcp",1,"192.0.2.1",2222).as_bytes());
            // Re-publication of the same observation must retain enrichment.
            let event=endpoint_projection_document(&context,&observation,at);
            let mut bulk=String::new(); append_projection_update(&mut bulk,&service.inner.config.current_endpoint_index,&current_id,&event)?;
            let response=service.send_bulk_with_retry("/_bulk",&bulk,false).await?; assert_eq!(response["errors"],false);
            let current=service.send_json_request(ElasticsearchOperation::ScanQuery,Method::GET,&format!("/{}/_doc/{current_id}",service.inner.config.current_endpoint_index),|r|r).await?;
            assert_eq!(current["_source"]["web"]["status"],"identified");
            // Upgrade a legacy endpoint before a different port-only execution.
            // The service clock and contents survive, but the endpoint execution
            // advances and must not prevent the older service job from matching.
            let update_path=format!("/{}/_update/{current_id}",service.inner.config.current_endpoint_index);
            service.send_json_request(ElasticsearchOperation::BulkWrite,Method::POST,&update_path,|r|r.json(&json!({"script":{"source":"ctx._source.remove('service_observation_ref'); ctx._source.remove('web');"}}))).await?;
            let port=json!({"kind":"port","ip_address":"192.0.2.1","port":2222,"protocol":"tcp","observed_at":at+500,"source":"masscan"});
            let mut port_context=context.clone();
            port_context.execution_id="newer-port-only-execution".into();
            let event=endpoint_projection_document(&port_context,&port,at+500);
            let mut bulk=String::new(); append_projection_update(&mut bulk,&service.inner.config.current_endpoint_index,&current_id,&event)?;
            service.send_bulk_with_retry("/_bulk",&bulk,false).await?;
            let current=service.send_json_request(ElasticsearchOperation::ScanQuery,Method::GET,&format!("/{}/_doc/{current_id}",service.inner.config.current_endpoint_index),|r|r).await?;
            assert_eq!(current["_source"]["execution_id"],port_context.execution_id);
            assert_eq!(current["_source"]["service_observed_at_ms"],at);
            assert!(current["_source"]["service_observation_ref"].is_null());
            assert!(current["_source"]["web"].is_null());
            // Removing the endpoint execution guard must not weaken evidence
            // or user matching, or replace a valid reference to another service.
            for (field,value) in [
                ("user_id",json!(2)),
                ("service",json!("ssh")),
                ("banner",json!("different banner")),
                ("service_observed_at_ms",json!(at-1)),
                ("service_observation_ref",json!({"id":"different-service","observed_at":at})),
            ] {
                let mut changed=serde_json::Map::new();changed.insert(field.into(),value);
                service.send_json_request(ElasticsearchOperation::BulkWrite,Method::POST,&update_path,|r|r.json(&json!({"doc":changed}))).await?;
                service.enrich_web_page(&job).await?;
                let unchanged=service.send_json_request(ElasticsearchOperation::ScanQuery,Method::GET,&format!("/{}/_doc/{current_id}",service.inner.config.current_endpoint_index),|r|r).await?;
                assert!(unchanged["_source"]["web"].is_null(),"legacy guard failed: {field}");
                let mut restored=serde_json::Map::new();restored.insert(field.into(),current["_source"][field].clone());
                service.send_json_request(ElasticsearchOperation::BulkWrite,Method::POST,&update_path,|r|r.json(&json!({"doc":restored}))).await?;
            }
            service.enrich_web_page(&job).await?;
            let current=service.send_json_request(ElasticsearchOperation::ScanQuery,Method::GET,&format!("/{}/_doc/{current_id}",service.inner.config.current_endpoint_index),|r|r).await?;
            assert_eq!(current["_source"]["web"]["status"],"identified");
            assert_eq!(current["_source"]["execution_id"],port_context.execution_id);
            assert_eq!(current["_source"]["service_observation_ref"]["id"],raw_id);
            assert_eq!(current["_source"]["service_observation_ref"]["observed_at"],at);
            let view=crate::web_detection::endpoint_view(serde_json::from_value(current["_source"]["web"].clone()).ok(),at+500,at+500).unwrap();
            assert!(view.stale);

            // The caller's millisecond timestamp, service and banner are not a
            // unique identity: another execution can have different HTTP data.
            let mut other_context=context.clone();
            other_context.execution_id="ambiguous-service-execution".into();
            other_context.upload_id="ambiguous-service-upload".into();
            let mut other=observation.clone();
            other["data"]=json!({"schema_version":2,"evidence":[{"module":"http","result":{"response":{"headers":{"server":"Apache/2.4.62"},"body":""}}}]});
            service.persist_scan_batch_prepared(&other_context,std::slice::from_ref(&other),None).await?;
            service.send_json_request(ElasticsearchOperation::IndexAdmin,Method::POST,&format!("/{raw_index}/_refresh"),|r|r).await?;
            service.send_json_request(ElasticsearchOperation::BulkWrite,Method::POST,&update_path,|r|r.json(&json!({"script":{"source":"ctx._source.remove('service_observation_ref'); ctx._source.remove('web');"}}))).await?;
            let other_job=WebJob { execution_id:1, token:Uuid::new_v4(),attempts:1,cursor:None,context:other_context.clone(),api_client_id:Some(77) };
            for replay in [&other_job,&job] {
                service.enrich_web_page(replay).await?;
                let ambiguous=service.send_json_request(ElasticsearchOperation::ScanQuery,Method::GET,&format!("/{}/_doc/{current_id}",service.inner.config.current_endpoint_index),|r|r).await?;
                assert!(ambiguous["_source"]["web"].is_null(),"ambiguous legacy response must not be selected");
                assert!(ambiguous["_source"]["service_observation_ref"].is_null());
                assert_eq!(ambiguous["_source"]["execution_id"],port_context.execution_id);
            }
            // A real observation publication supplies an exact reference, which
            // remains authoritative even when timestamps and banners collide.
            let event=endpoint_projection_document(&context,&observation,at);
            let mut bulk=String::new();append_projection_update(&mut bulk,&service.inner.config.current_endpoint_index,&current_id,&event)?;
            service.send_bulk_with_retry("/_bulk",&bulk,false).await?;
            service.enrich_web_page(&job).await?;
            service.enrich_web_page(&other_job).await?;
            let exact=service.send_json_request(ElasticsearchOperation::ScanQuery,Method::GET,&format!("/{}/_doc/{current_id}",service.inner.config.current_endpoint_index),|r|r).await?;
            assert_eq!(exact["_source"]["web"]["status"],"identified");
            assert_eq!(exact["_source"]["service_observation_ref"]["id"],raw_id);
            let technologies=exact["_source"]["web"]["technologies"].as_array().unwrap();
            assert!(technologies.iter().any(|technology|technology["id"]=="nginx"));
            assert!(!technologies.iter().any(|technology|technology["id"]=="apache"));

            // A newer successful service result must invalidate the previous
            // Web conclusion, and replaying the older job must not restore it.
            let mut newer=observation.clone(); newer["observation_key"]=json!("http-2");newer["banner"]=json!("HTTP/1.1 201 Created");
            let event=endpoint_projection_document(&context,&newer,at+1000);
            let current_id=sha256_hex(format!("user\0{}\0{}\0{}\0tcp",1,"192.0.2.1",2222).as_bytes());
            let mut bulk=String::new(); append_projection_update(&mut bulk,&service.inner.config.current_endpoint_index,&current_id,&event)?;
            let response=service.send_bulk_with_retry("/_bulk",&bulk,false).await?;assert_eq!(response["errors"],false);
            service.enrich_web_page(&job).await?;
            let current=service.send_json_request(ElasticsearchOperation::ScanQuery,Method::GET,&format!("/{}/_doc/{current_id}",service.inner.config.current_endpoint_index),|r|r).await?;
            assert_eq!(current["_source"]["web"]["status"],"pending");
            let raw_after=service.send_json_request(ElasticsearchOperation::ScanQuery,Method::GET,&format!("/{raw_index}/_doc/{raw_id}"),|r|r).await?;
            assert_eq!(raw_before["_source"],raw_after["_source"]);
            // Deletion must not recreate current assets or poison a replay queue.
            service.send_json_request(ElasticsearchOperation::IndexAdmin,Method::DELETE,&format!("/{}/_doc/{current_id}",service.inner.config.current_endpoint_index),|r|r).await?;
            service.enrich_web_page(&job).await?;
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
