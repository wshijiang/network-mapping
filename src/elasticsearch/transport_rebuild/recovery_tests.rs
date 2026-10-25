use super::*;
use crate::elasticsearch::storage_tests::{EsFixture, isolated_pool_with_size, seed_execution};

async fn setup(count: usize) -> (Pool, String, EsFixture, ElasticsearchService) {
    let (pool, schema) = isolated_pool_with_size(3).await;
    seed_execution(&pool).await;
    let fixture = EsFixture::start();
    let service = ElasticsearchService::new(ElasticsearchConfig {
        url: fixture.url.clone(),
        projection_page_size: 2,
        bulk_batch_size: 2,
        bulk_max_retries: 0,
        ..ElasticsearchConfig::default()
    })
    .unwrap();
    let context = ScanBatchContext {
        task_id: "task".into(),
        execution_id: "execution".into(),
        user_id: 1,
        task_source: "user".into(),
        scanner_id: "unknown".into(),
        scanner_name: None,
        upload_id: "upload".into(),
        batch_index: 0,
        is_final: true,
    };
    let observations=(0..count).map(|n|json!({"observation_key":format!("k{n:04}"),"kind":"service","ip_address":"192.0.2.1","port":1000+n,"protocol":"tcp","service":"http","observed_at":1000})).collect::<Vec<_>>();
    let receipt = service
        .persist_scan_batch_prepared(&context, &observations, None)
        .await
        .unwrap();
    fixture
        .state
        .lock()
        .unwrap()
        .documents
        .retain(|(index, _), _| !index.contains("endpoints"));
    pool.get().await.unwrap().execute("INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count,storage_backend,payload_checksum,storage_references) VALUES(1,'upload',0,true,$1,'elasticsearch',$2,$3)",&[&(count as i32),&receipt.payload_checksum,&json!(receipt.indices)]).await.unwrap();
    pool.get().await.unwrap().batch_execute("UPDATE scan_task_execution SET execution_status='succeeded',result_ip_count=77,result_port_count=88").await.unwrap();
    (pool, schema, fixture, service)
}
async fn cleanup(pool: &Pool, schema: &str) {
    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn mismatched_facts_fail_before_target_or_checkpoint_writes() {
    let (pool, schema, fixture, service) = setup(3).await;
    fixture.state.lock().unwrap().documents.pop_first();
    let error = service
        .rebuild_transport_endpoints(&pool)
        .await
        .unwrap_err();
    assert!(error.contains("数据不配套"), "{error}");
    assert!(load(&pool, STATE_KEY).await.unwrap().is_none());
    assert!(fixture.state.lock().unwrap().index_metadata.is_empty());
    let row = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT result_ip_count,result_port_count FROM scan_task_execution WHERE id=1",
            &[],
        )
        .await
        .unwrap();
    assert_eq!((row.get::<_, i64>(0), row.get::<_, i64>(1)), (77, 88));
    cleanup(&pool, &schema).await;
}

struct StopAfterPage<'a>(&'a AtomicBool);
impl ProgressReporter for StopAfterPage<'_> {
    fn report(&self, update: ProgressUpdate) {
        if update.phase.contains("事实重放") && update.completed == Some(2) {
            self.0.store(true, Ordering::Release);
        }
    }
}
#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn interrupted_page_resumes_with_a_new_client_and_preserves_facts() {
    let (pool, schema, fixture, service) = setup(5).await;
    let raw = fixture.state.lock().unwrap().documents.clone();
    let stop = AtomicBool::new(false);
    let error = service
        .rebuild_transport_endpoints_controlled(&pool, &StopAfterPage(&stop), &stop)
        .await
        .unwrap_err();
    assert!(error.contains("已中断"), "{error}");
    let run: Run = serde_json::from_value(load(&pool, STATE_KEY).await.unwrap().unwrap()).unwrap();
    assert_eq!(checkpoint(&pool, &run, 1).await.unwrap().replayed, 2);
    assert!(
        load(&pool, "elasticsearch_runtime")
            .await
            .unwrap()
            .is_none()
    );
    let service = ElasticsearchService::new(service.inner.config.clone()).unwrap();
    assert_eq!(service.rebuild_transport_endpoints(&pool).await.unwrap(), 1);
    assert_eq!(service.rebuild_transport_endpoints(&pool).await.unwrap(), 0);
    {
        let state = fixture.state.lock().unwrap();
        for (key, value) in raw {
            assert_eq!(state.documents.get(&key), Some(&value));
        }
        let pages = state
            .query_bodies
            .iter()
            .filter(|(_, v)| v.pointer("/sort/0/observed_at").is_some())
            .collect::<Vec<_>>();
        assert_eq!(pages.len(), 3);
        assert!(pages[1].1.get("search_after").is_some());
        assert!(
            !state
                .requests
                .iter()
                .any(|p| p.contains("_update_by_query"))
        );
    }
    cleanup(&pool, &schema).await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn changed_target_uuid_or_source_checksum_blocks_resume() {
    let (pool, schema, fixture, service) = setup(3).await;
    let stop = AtomicBool::new(false);
    service
        .rebuild_transport_endpoints_controlled(&pool, &StopAfterPage(&stop), &stop)
        .await
        .unwrap_err();
    let name = &service.inner.config.execution_endpoint_index;
    fixture
        .state
        .lock()
        .unwrap()
        .index_metadata
        .get_mut(name)
        .unwrap()["settings"]["index"]["uuid"] = json!("replaced");
    assert!(
        service
            .rebuild_transport_endpoints(&pool)
            .await
            .unwrap_err()
            .contains("UUID")
    );
    fixture
        .state
        .lock()
        .unwrap()
        .index_metadata
        .get_mut(name)
        .unwrap()["settings"]["index"]["uuid"] = json!(format!("uuid-{name}"));
    for ((index, _), value) in &mut fixture.state.lock().unwrap().documents {
        if index.contains("scan-observations") && value["observation_key"] == "k0002" {
            value["service"] = json!("tampered");
        }
    }
    assert!(
        service
            .rebuild_transport_endpoints(&pool)
            .await
            .unwrap_err()
            .contains("内容校验失败")
    );
    let run: Run = serde_json::from_value(load(&pool, STATE_KEY).await.unwrap().unwrap()).unwrap();
    assert_eq!(checkpoint(&pool, &run, 1).await.unwrap().replayed, 2);
    cleanup(&pool, &schema).await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn partial_publish_bulk_never_advances_checkpoint() {
    let (pool, schema, fixture, service) = setup(5).await;
    fixture.state.lock().unwrap().projection_fail_after = Some(1);
    service
        .rebuild_transport_endpoints(&pool)
        .await
        .unwrap_err();
    let run: Run = serde_json::from_value(load(&pool, STATE_KEY).await.unwrap().unwrap()).unwrap();
    assert_eq!(run.phase, Phase::Publishing);
    assert_eq!(checkpoint(&pool, &run, 1).await.unwrap().published, 0);
    assert!(
        load(&pool, "elasticsearch_runtime")
            .await
            .unwrap()
            .is_none()
    );
    fixture.state.lock().unwrap().projection_fail_after = None;
    assert_eq!(service.rebuild_transport_endpoints(&pool).await.unwrap(), 1);
    cleanup(&pool, &schema).await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn legacy_checkpoint_is_not_trusted() {
    let (pool, schema, fixture, service) = setup(1).await;
    save(
        &pool,
        STATE_KEY,
        &json!({"target":service.rebuild_target(),"last_execution_id":999}),
    )
    .await
    .unwrap();
    assert!(
        service
            .rebuild_transport_endpoints(&pool)
            .await
            .unwrap_err()
            .contains("旧格式")
    );
    assert!(fixture.state.lock().unwrap().index_metadata.is_empty());
    cleanup(&pool, &schema).await;
}

#[tokio::test]
#[ignore = "requires disposable PG and real ES via STORAGE_TEST_CONFIG_PATH; creates only UUID-named synthetic indices"]
async fn live_transport_rebuild_resumes_and_preserves_raw_documents() {
    let (pool, schema) = isolated_pool_with_size(3).await;
    seed_execution(&pool).await;
    let mut config = crate::elasticsearch::storage_tests::live_test_elasticsearch_config();
    let prefix = format!("nm-test-transport-{}", Uuid::new_v4().simple());
    config.observation_index_prefix = format!("{prefix}-observations");
    config.execution_endpoint_index = format!("{prefix}-execution");
    config.current_endpoint_index = format!("{prefix}-current");
    config.projection_page_size = 2;
    config.bulk_batch_size = 2;
    config.scan_number_of_replicas = 0;
    let service = ElasticsearchService::new(config.clone()).unwrap();
    let source = scan_observation_index(&config.observation_index_prefix, 1000).unwrap();
    let staging = format!("{prefix}-staging");
    let test=async {
        let template=scan_observation_template(&config.observation_index_prefix,0);
        service.send_json_request(ElasticsearchOperation::IndexAdmin,Method::PUT,&format!("/{source}"),|r|r.json(&template["template"])).await?;
        service.send_json_request(ElasticsearchOperation::IndexAdmin,Method::PUT,&format!("/{staging}"),|r|r.json(&scan_endpoint_index_definition(0))).await?;
        let mut writer_config=config.clone();writer_config.execution_endpoint_index=staging.clone();
        let writer=ElasticsearchService::new(writer_config).map_err(|e|e.to_string())?;
        let context=ScanBatchContext {task_id:"task".into(),execution_id:"execution".into(),user_id:1,task_source:"user".into(),scanner_id:"unknown".into(),scanner_name:None,upload_id:"upload".into(),batch_index:0,is_final:false};
        let observations=(0..5).map(|n|json!({"observation_key":format!("k{n:04}"),"kind":"service","ip_address":"192.0.2.1","port":1000+n/2,"protocol":if n%2==0{"tcp"}else{"udp"},"service":"http","observed_at":1000})).collect::<Vec<_>>();
        let receipt=writer.persist_scan_batch_prepared(&context,&observations,None).await?;
        service.refresh_rebuild_index(&source).await?;
        pool.get().await.map_err(|e|e.to_string())?.execute("INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count,storage_backend,payload_checksum,storage_references) VALUES(1,'upload',0,false,5,'elasticsearch',$1,$2)",&[&receipt.payload_checksum,&json!(receipt.indices)]).await.map_err(|e|e.to_string())?;
        pool.get().await.map_err(|e|e.to_string())?.batch_execute("UPDATE scan_task_execution SET execution_status='succeeded'").await.map_err(|e|e.to_string())?;
        let source_identity=service.rebuild_source().await?;
        let stop=AtomicBool::new(false);
        let error=service.rebuild_transport_endpoints_controlled(&pool,&StopAfterPage(&stop),&stop).await.unwrap_err();
        if !error.contains("已中断"){return Err(error);}
        let resumed=ElasticsearchService::new(config.clone()).map_err(|e|e.to_string())?;
        if resumed.rebuild_transport_endpoints(&pool).await?!=1 {return Err("重建未完成".into());}
        if resumed.rebuild_transport_endpoints(&pool).await?!=0 {return Err("完成后的重跑不幂等".into());}
        if source_identity!=service.rebuild_source().await? {return Err("原始事实索引被改写".into());}
        let summary=resumed.execution_summary("execution",&[]).await?;
        if summary.port_count!=5 || summary.ip_count!=1 {return Err(format!("端点计数错误：{summary:?}"));}
        let current=resumed.send_json_request(ElasticsearchOperation::ScanQuery,Method::POST,&format!("/{}/_search",config.current_endpoint_index),|r|r.json(&json!({"size":20,"query":{"match_all":{}}}))).await?;
        let hits=current.pointer("/hits/hits").and_then(Value::as_array).ok_or("缺少当前端点")?;
        if hits.len()!=10 || hits.iter().any(|h|h.pointer("/_source/tags")!=Some(&json!([]))) {return Err("当前范围或标签同步错误".into());}
        Ok::<_,String>(())
    }.await;
    // Explicit names only: never delete a wildcard or any configured business index.
    for index in [
        &source,
        &staging,
        &config.execution_endpoint_index,
        &config.current_endpoint_index,
    ] {
        let response = service
            .send_request(
                ElasticsearchOperation::IndexAdmin,
                Method::DELETE,
                &format!("/{index}"),
                |r| r,
            )
            .await
            .unwrap();
        assert!(response.status().is_success() || response.status() == StatusCode::NOT_FOUND);
    }
    cleanup(&pool, &schema).await;
    test.unwrap();
}

struct StopTags<'a>(&'a AtomicBool);
impl ProgressReporter for StopTags<'_> {
    fn report(&self, update: ProgressUpdate) {
        if update.phase.contains("标签同步") && update.completed.is_some_and(|n| n >= 2) {
            self.0.store(true, Ordering::Release);
        }
    }
}
#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn tag_pages_resume_and_changed_assignments_restart_tag_scan() {
    let (pool, schema, fixture, service) = setup(5).await;
    pool.get().await.unwrap().batch_execute("INSERT INTO asset_tag(id,name,kind,category_id) SELECT 99,'fixture','info',id FROM asset_tag_category ORDER BY id LIMIT 1; INSERT INTO asset_ip_tag(ip_address,tag_id) VALUES('192.0.2.1',99)").await.unwrap();
    let stop = AtomicBool::new(false);
    let error = service
        .rebuild_transport_endpoints_controlled(&pool, &StopTags(&stop), &stop)
        .await
        .unwrap_err();
    assert!(error.contains("已中断"), "{error}");
    let run: Run = serde_json::from_value(load(&pool, STATE_KEY).await.unwrap().unwrap()).unwrap();
    assert_eq!(run.phase, Phase::Tags);
    assert!(run.tagged > 0 && run.tagged < run.tag_total.unwrap());
    assert!(run.tag_cursor.is_some());
    assert!(
        load(&pool, "elasticsearch_runtime")
            .await
            .unwrap()
            .is_none()
    );
    pool.get()
        .await
        .unwrap()
        .batch_execute("DELETE FROM asset_ip_tag")
        .await
        .unwrap();
    assert_eq!(service.rebuild_transport_endpoints(&pool).await.unwrap(), 1);
    for ((index, _), doc) in &fixture.state.lock().unwrap().documents {
        if index == &service.inner.config.current_endpoint_index {
            assert_eq!(doc["tags"], json!([]));
            assert_eq!(doc["tag_ids"], json!([]));
        }
    }
    cleanup(&pool, &schema).await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn equal_total_with_wrong_batch_still_fails_preflight() {
    let (pool, schema, fixture, service) = setup(3).await;
    fixture
        .state
        .lock()
        .unwrap()
        .documents
        .first_entry()
        .unwrap()
        .get_mut()["upload_id"] = json!("wrong-upload");
    let error = service
        .rebuild_transport_endpoints(&pool)
        .await
        .unwrap_err();
    assert!(error.contains("事实数量不匹配"), "{error}");
    assert!(load(&pool, STATE_KEY).await.unwrap().is_none());
    assert!(fixture.state.lock().unwrap().index_metadata.is_empty());
    cleanup(&pool, &schema).await;
}
