use super::*;
use crate::elasticsearch::storage_tests::{
    EsFixture, isolated_pool_with_size, port_observation, seed_dns_upload, seed_execution,
};

async fn seed(pool: &Pool, fixture: &EsFixture, count: usize) {
    seed_execution(pool).await;
    pool.get().await.unwrap().batch_execute(
        "UPDATE scan_task_execution SET execution_status='succeeded' WHERE id=1; \
         INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count,storage_backend) \
         VALUES(1,'upload',0,true,0,'elasticsearch'); \
         INSERT INTO scan_projection_outbox(execution_id) VALUES(1);"
    ).await.unwrap();
    let mut state = fixture.state.lock().unwrap();
    for port in 1..=count {
        state.documents.insert(
            (
                "network-mapping-execution-endpoints-v2".into(),
                port.to_string(),
            ),
            json!({"execution_id":"execution","ip":"192.0.2.1","port":port,"protocol":"tcp","endpoint_key":format!("192.0.2.1|{port}|tcp"),"observed_at_ms":1000}),
        );
    }
}

fn service(fixture: &EsFixture) -> ElasticsearchService {
    ElasticsearchService::new(ElasticsearchConfig {
        url: fixture.url.clone(),
        projection_page_size: 2,
        projection_pages_per_tick: 1,
        projection_bulk_max_bytes: 16 * 1024,
        projection_lease_seconds: 3,
        projection_heartbeat_seconds: 1,
        bulk_batch_size: 100, // the byte limit must split pages independently
        bulk_max_retries: 0,
        ..ElasticsearchConfig::default()
    })
    .unwrap()
}

async fn clean(pool: &Pool, schema: &str) {
    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn api_task_projection_publishes_an_independent_application_scope() {
    let (pool, schema) = isolated_pool_with_size(2).await;
    let fixture = EsFixture::start();
    seed(&pool, &fixture, 1).await;
    let c = pool.get().await.unwrap();
    let id:i32=c.query_one("INSERT INTO api_client(client_id,owner_user_id,name,kind,policy,requested_policy) VALUES($1,1,'projection','personal','{}','{}') RETURNING id",&[&Uuid::new_v4()]).await.unwrap().get(0);
    c.execute("UPDATE scan_task SET api_client_id=$1 WHERE id=1", &[&id])
        .await
        .unwrap();
    drop(c);
    let service = service(&fixture);
    for _ in 0..5 {
        if !service.process_scan_projection_outbox(&pool).await.unwrap() {
            break;
        }
    }
    let documents = fixture
        .state
        .lock()
        .unwrap()
        .documents
        .values()
        .filter(|v| v["scope_type"] == "api_client" && v["scope_id"] == id)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(documents.len(), 1);
    assert_eq!(documents[0]["ip"], "192.0.2.1");
    assert_eq!(documents[0]["port"], 1);
    clean(&pool, &schema).await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn projection_claim_is_atomic_and_expired_owner_cannot_commit() {
    let (pool, schema) = isolated_pool_with_size(2).await;
    let fixture = EsFixture::start();
    let service = service(&fixture);
    seed(&pool, &fixture, 1).await;
    let (one, two) = tokio::join!(
        service.claim_projection(&pool),
        service.claim_projection(&pool)
    );
    let mut jobs = [one.unwrap(), two.unwrap()].into_iter().flatten();
    let old = jobs.next().unwrap();
    assert!(jobs.next().is_none());
    pool.get().await.unwrap().batch_execute("UPDATE scan_projection_outbox SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'").await.unwrap();
    let new = service.claim_projection(&pool).await.unwrap().unwrap();
    assert_ne!(old.token, new.token);
    assert_eq!(
        service.renew_projection(&pool, &old).await.unwrap_err(),
        OWNERSHIP_LOST
    );
    assert_eq!(
        service
            .release_projection(&pool, &old, true)
            .await
            .unwrap_err(),
        OWNERSHIP_LOST
    );
    assert_eq!(
        service
            .retry_projection(&pool, &old, "old failure")
            .await
            .unwrap_err(),
        OWNERSHIP_LOST
    );
    let page = ProjectionPage {
        cursor: Some(json!(["192.0.2.1", 1])),
        endpoints: 1,
        done: false,
    };
    assert_eq!(
        service
            .checkpoint_projection(&pool, &old, &page)
            .await
            .unwrap_err(),
        OWNERSHIP_LOST
    );
    service
        .release_projection(&pool, &new, false)
        .await
        .unwrap();
    clean(&pool, &schema).await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn projection_wait_releases_single_connection_and_renews_during_slow_es() {
    let (pool, schema) = isolated_pool_with_size(1).await;
    let fixture = EsFixture::start();
    let service = service(&fixture);
    seed(&pool, &fixture, 1).await;
    {
        let mut state = fixture.state.lock().unwrap();
        state.delay_path = Some("execution-endpoints-v2/_search".into());
        state.delay_ms = 3500; // exceeds the initial 3 second lease
    }
    let probe = async {
        loop {
            if fixture
                .state
                .lock()
                .unwrap()
                .requests
                .iter()
                .any(|path| path.contains("execution-endpoints-v2/_search"))
            {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
        let connection = timeout(Duration::from_millis(250), pool.get())
            .await
            .unwrap()
            .unwrap();
        let token: Option<Uuid> = connection
            .query_one("SELECT claim_token FROM scan_projection_outbox", &[])
            .await
            .unwrap()
            .get(0);
        assert!(token.is_some());
        drop(connection);
    };
    let (work, ()) = tokio::join!(service.process_scan_projection_outbox(&pool), probe);
    assert!(work.unwrap());
    // The checkpoint after the delayed response proves that renewal succeeded.
    let phase: String = pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT phase FROM scan_projection_outbox", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(phase, "refreshing");
    clean(&pool, &schema).await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn projection_resumes_pages_and_retries_refresh_without_republishing() {
    let (pool, schema) = isolated_pool_with_size(1).await;
    let fixture = EsFixture::start();
    seed(&pool, &fixture, 5).await;
    let service = service(&fixture);
    assert!(service.process_scan_projection_outbox(&pool).await.unwrap());
    let row = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT cursor,processed_endpoints FROM scan_projection_outbox",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, Value>(0), json!(["192.0.2.1|2|tcp"]));
    assert_eq!(row.get::<_, i64>(1), 2);
    // A new service has no in-memory continuation; resume entirely from PG.
    let restarted = self::service(&fixture);
    assert!(
        restarted
            .process_scan_projection_outbox(&pool)
            .await
            .unwrap()
    );
    assert!(
        restarted
            .process_scan_projection_outbox(&pool)
            .await
            .unwrap()
    );
    let before = fixture.state.lock().unwrap().projection_bulk_sizes.len();
    assert!(before > 3, "three pages must be split by the byte limit");
    fixture.state.lock().unwrap().fail_path = Some("endpoints-current-v3/_refresh".into());
    assert!(
        restarted
            .process_scan_projection_outbox(&pool)
            .await
            .is_err()
    );
    let row = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT phase,processed_at IS NULL FROM scan_projection_outbox",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "refreshing");
    assert!(row.get::<_, bool>(1));
    fixture.state.lock().unwrap().fail_path = None;
    fixture
        .state
        .lock()
        .unwrap()
        .refresh_responses
        .push_back(json!({"_shards":{"total":1,"successful":0,"failed":0}}));
    pool.get()
        .await
        .unwrap()
        .batch_execute("UPDATE scan_projection_outbox SET available_at=clock_timestamp()")
        .await
        .unwrap();
    let error = restarted
        .process_scan_projection_outbox(&pool)
        .await
        .unwrap_err();
    assert!(error.contains("successful=0"), "{error}");
    let complete: bool = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT processed_at IS NOT NULL FROM scan_projection_outbox",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!complete);
    pool.get()
        .await
        .unwrap()
        .batch_execute("UPDATE scan_projection_outbox SET available_at=clock_timestamp()")
        .await
        .unwrap();
    assert!(
        restarted
            .process_scan_projection_outbox(&pool)
            .await
            .unwrap()
    );
    assert!(
        !restarted
            .process_scan_projection_outbox(&pool)
            .await
            .unwrap()
    );
    {
        let state = fixture.state.lock().unwrap();
        assert_eq!(state.projection_bulk_sizes.len(), before);
        assert!(
            state
                .projection_bulk_sizes
                .iter()
                .all(|bytes| *bytes <= 16 * 1024)
        );
        assert_eq!(
            state
                .documents
                .keys()
                .filter(|(index, _)| index.contains("endpoints-current"))
                .count(),
            10
        );
    }
    let row = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT processed_endpoints,processed_at IS NOT NULL FROM scan_projection_outbox",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 5);
    assert!(row.get::<_, bool>(1));
    clean(&pool, &schema).await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn projection_malformed_bulk_does_not_advance_checkpoint() {
    let (pool, schema) = isolated_pool_with_size(1).await;
    let fixture = EsFixture::start();
    seed(&pool, &fixture, 2).await;
    let service = service(&fixture);
    fixture.state.lock().unwrap().malformed_projection_bulk = true;
    assert!(service.process_scan_projection_outbox(&pool).await.is_err());
    let row = pool.get().await.unwrap().query_one("SELECT cursor IS NULL,processed_endpoints,processed_at IS NULL FROM scan_projection_outbox", &[]).await.unwrap();
    assert!(row.get::<_, bool>(0));
    assert_eq!(row.get::<_, i64>(1), 0);
    assert!(row.get::<_, bool>(2));
    fixture.state.lock().unwrap().malformed_projection_bulk = false;
    pool.get()
        .await
        .unwrap()
        .batch_execute("UPDATE scan_projection_outbox SET available_at=clock_timestamp()")
        .await
        .unwrap();
    assert!(service.process_scan_projection_outbox(&pool).await.unwrap());
    clean(&pool, &schema).await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn final_upload_and_duplicate_do_not_wait_for_current_projection() {
    let (pool, schema) = isolated_pool_with_size(1).await;
    let fixture = EsFixture::start();
    let service = fixture.service();
    let mut upload = seed_dns_upload(&pool).await;
    pool.get()
        .await
        .unwrap()
        .batch_execute("UPDATE scan_task SET task_kind='ip',scan_profile='port_only' WHERE id=1")
        .await
        .unwrap();
    upload.observations = vec![port_observation()];
    upload.is_final = Some(true);
    let maxmind = crate::maxmind::MaxMindState::from_directory("/tmp/nm-es-no-maxmind");
    let follow_up = crate::dns_follow_up::DnsFollowUpConfig::default();
    service.ensure_scan_indices().await.unwrap();
    fixture.state.lock().unwrap().fail_path = Some("endpoints-current-v3".into());
    for expected in [1, 0] {
        let saved = timeout(
            Duration::from_secs(5),
            crate::result_ingest::storage::save_scanner_results(
                &pool,
                &maxmind,
                &service,
                &follow_up,
                &upload,
                "fixture-token",
                "fixture-pepper",
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(saved, expected);
    }
    assert!(
        !fixture
            .state
            .lock()
            .unwrap()
            .requests
            .iter()
            .any(|path| path.contains("endpoints-current-v3/_refresh"))
    );
    let row = pool.get().await.unwrap().query_one("SELECT e.execution_status,p.processed_at IS NULL,p.attempts FROM scan_task_execution e JOIN scan_projection_outbox p ON p.execution_id=e.id", &[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "succeeded");
    assert!(row.get::<_, bool>(1));
    assert_eq!(row.get::<_, i32>(2), 0);
    clean(&pool, &schema).await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn projection_recovers_a_partially_written_page_after_process_loss() {
    let (pool, schema) = isolated_pool_with_size(1).await;
    let fixture = EsFixture::start();
    seed(&pool, &fixture, 2).await;
    let service = ElasticsearchService::new(ElasticsearchConfig {
        url: fixture.url.clone(),
        bulk_batch_size: 1,
        bulk_max_retries: 0,
        projection_page_size: 2,
        projection_pages_per_tick: 1,
        ..Default::default()
    })
    .unwrap();
    let abandoned = service.claim_projection(&pool).await.unwrap().unwrap();
    fixture.state.lock().unwrap().projection_fail_after = Some(1);
    assert!(
        service
            .promote_execution_page(&abandoned.context, None, None)
            .await
            .is_err()
    );
    assert_eq!(
        fixture
            .state
            .lock()
            .unwrap()
            .documents
            .keys()
            .filter(|(index, _)| index.contains("endpoints-current"))
            .count(),
        1
    );
    // Simulate process loss before either checkpoint or retry scheduling.
    pool.get().await.unwrap().batch_execute("UPDATE scan_projection_outbox SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'").await.unwrap();
    fixture.state.lock().unwrap().projection_fail_after = None;
    assert!(service.process_scan_projection_outbox(&pool).await.unwrap());
    assert!(service.process_scan_projection_outbox(&pool).await.unwrap());
    assert!(service.process_scan_projection_outbox(&pool).await.unwrap());
    assert_eq!(
        fixture
            .state
            .lock()
            .unwrap()
            .documents
            .keys()
            .filter(|(index, _)| index.contains("endpoints-current"))
            .count(),
        4
    );
    assert_eq!(
        service
            .release_projection(&pool, &abandoned, true)
            .await
            .unwrap_err(),
        OWNERSHIP_LOST
    );
    clean(&pool, &schema).await;
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn projection_migration_preserves_legacy_queue_and_is_idempotent() {
    let (pool, schema) = isolated_pool_with_size(1).await;
    let fixture = EsFixture::start();
    seed(&pool, &fixture, 0).await;
    let client = pool.get().await.unwrap();
    client.batch_execute("ALTER TABLE scan_projection_outbox DROP COLUMN claim_token, DROP COLUMN lease_expires_at, DROP COLUMN cursor, DROP COLUMN phase, DROP COLUMN processed_endpoints, DROP COLUMN updated_at").await.unwrap();
    for _ in 0..2 {
        client
            .batch_execute(include_str!(
                "../../../source/database/migrate_scan_projection.sql"
            ))
            .await
            .unwrap();
    }
    let row = client.query_one("SELECT phase,cursor IS NULL,claim_token IS NULL,processed_at IS NULL FROM scan_projection_outbox WHERE execution_id=1", &[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "promoting");
    for i in 1..=3 {
        assert!(row.get::<_, bool>(i));
    }
    drop(client);
    clean(&pool, &schema).await;
}
