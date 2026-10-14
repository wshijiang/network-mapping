//! Protocol tests with a disposable PG schema and a local HTTP fixture, not an ES cluster.
use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Mutex;

#[derive(Default)]
pub(super) struct FixtureState {
    pub(super) requests: Vec<String>,
    pub(super) query_bodies: Vec<(String, Value)>,
    pub(super) documents: BTreeMap<(String, String), Value>,
    pub(super) fail_path: Option<String>,
    pub(super) max_request_line_bytes: Option<usize>,
    pub(super) count_responses: std::collections::VecDeque<Value>,
    pub(super) delay_path: Option<String>,
    pub(super) delay_ms: u64,
    pub(super) projection_bulk_sizes: Vec<usize>,
    pub(super) malformed_projection_bulk: bool,
    pub(super) projection_fail_after: Option<usize>,
    server_version: Option<String>,
    dns_generation: usize,
}

pub(super) struct EsFixture {
    pub(super) url: String,
    pub(super) state: Arc<Mutex<FixtureState>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl EsFixture {
    pub(super) fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(FixtureState::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_state = state.clone();
        let thread_stop = stop.clone();
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                let Ok((mut socket, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut data = Vec::new();
                let mut buffer = [0; 8192];
                let (header_end, length) = loop {
                    let count = socket.read(&mut buffer).unwrap();
                    assert!(count > 0);
                    data.extend_from_slice(&buffer[..count]);
                    if let Some(position) = data.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&data[..position]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_lowercase()
                                    .strip_prefix("content-length:")?
                                    .trim()
                                    .parse::<usize>()
                                    .ok()
                            })
                            .unwrap_or(0);
                        break (position + 4, length);
                    }
                };
                while data.len() < header_end + length {
                    let count = socket.read(&mut buffer).unwrap();
                    assert!(count > 0);
                    data.extend_from_slice(&buffer[..count]);
                }
                let header = String::from_utf8_lossy(&data[..header_end]);
                let first = header.lines().next().unwrap();
                let mut parts = first.split_whitespace();
                let method = parts.next().unwrap();
                let path = parts.next().unwrap();
                let body = String::from_utf8_lossy(&data[header_end..header_end + length]);
                let (fail, delay_ms) = {
                    let mut state = thread_state.lock().unwrap();
                    state.requests.push(format!("{method} {path}"));
                    (
                        state
                            .fail_path
                            .as_ref()
                            .is_some_and(|needle| path.contains(needle))
                            || state
                                .max_request_line_bytes
                                .is_some_and(|max| first.len() > max),
                        state
                            .delay_path
                            .as_ref()
                            .filter(|needle| path.contains(*needle))
                            .map_or(0, |_| state.delay_ms),
                    )
                };
                if delay_ms > 0 {
                    std::thread::sleep(Duration::from_millis(delay_ms));
                }
                let mut state = thread_state.lock().unwrap();
                let response = if fail {
                    json!({"error": "fixture failure"})
                } else {
                    fixture_response(&mut state, method, path, &body)
                };
                let response = if method == "HEAD" {
                    String::new()
                } else {
                    response.to_string()
                };
                write!(socket, "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    if fail { "503 Unavailable" } else { "200 OK" }, response.len(), response).unwrap();
            }
        });
        Self {
            url,
            state,
            stop,
            thread: Some(thread),
        }
    }

    pub(super) fn service(&self) -> ElasticsearchService {
        ElasticsearchService::new(ElasticsearchConfig {
            url: self.url.clone(),
            bulk_max_retries: 0,
            ..ElasticsearchConfig::default()
        })
        .unwrap()
    }
}

impl Drop for EsFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn fixture_response(state: &mut FixtureState, _method: &str, path: &str, body: &str) -> Value {
    if path == "/" {
        return json!({"version": {"number": state.server_version.as_deref().unwrap_or("9.5.3")}});
    }
    if path.starts_with("/_data_stream/") {
        return json!({"data_streams": [{"indices": [{"index_name": format!(".ds-dns-{}", state.dns_generation)}]}]});
    }
    if path.starts_with("/_bulk") {
        let lines: Vec<Value> = body
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let is_projection = lines
            .first()
            .and_then(|line| line.pointer("/update/_index"))
            .and_then(Value::as_str)
            .is_some_and(|index| index.contains("endpoints-current"));
        if is_projection {
            state.projection_bulk_sizes.push(body.len());
            if state.malformed_projection_bulk
                || state
                    .projection_fail_after
                    .is_some_and(|n| state.projection_bulk_sizes.len() > n)
            {
                return json!({"errors":false,"items":[]});
            }
        }
        let mut items = Vec::new();
        for pair in lines.as_chunks::<2>().0 {
            let (operation, action) = pair[0].as_object().unwrap().iter().next().unwrap();
            let requested_index = action["_index"].as_str().unwrap();
            let backing_create = operation == "create" && requested_index.starts_with(".ds-");
            let actual_index = if requested_index == "network-mapping-dns-observations" {
                format!(".ds-dns-{}", state.dns_generation)
            } else {
                requested_index.to_owned()
            };
            let key = (
                actual_index.clone(),
                action["_id"].as_str().unwrap().to_owned(),
            );
            let conflict =
                !backing_create && operation == "create" && state.documents.contains_key(&key);
            if !backing_create && !conflict {
                let document = if operation == "update" {
                    pair[1]["script"]["params"]["doc"].clone()
                } else {
                    pair[1].clone()
                };
                state.documents.insert(key, document);
            }
            let status = if backing_create {
                400
            } else if conflict {
                409
            } else {
                201
            };
            let mut result = json!({
                "status": status,
                "_index": actual_index,
                "_id": action["_id"]
            });
            if backing_create {
                result["error"] = json!({"reason":
                    "index request with op_type=create targeting backing indices is disallowed"
                });
            }
            items.push(json!({(operation): result}));
        }
        return json!({
            "errors": items.iter().any(|item| item.as_object().unwrap().values().any(|action| {
                action["status"].as_u64().is_some_and(|status| status >= 300)
            })),
            "items": items
        });
    }
    if path.contains("_mget") {
        let request: Value = serde_json::from_str(body).unwrap();
        let docs = request["docs"].as_array().unwrap().iter().map(|doc| {
            let key = (doc["_index"].as_str().unwrap().to_owned(), doc["_id"].as_str().unwrap().to_owned());
            json!({"found": true, "_source": state.documents.get(&key).unwrap(), "_id": doc["_id"], "_index": doc["_index"]})
        }).collect::<Vec<_>>();
        return json!({"docs": docs});
    }
    let matches_index = |index: &str| {
        path.trim_start_matches('/')
            .split('/')
            .next()
            .unwrap()
            .split(',')
            .any(|target| {
                target
                    .strip_suffix('*')
                    .map_or(index == target, |prefix| index.starts_with(prefix))
            })
    };
    if path.contains("_count") {
        if let Some(response) = state.count_responses.pop_front() {
            return response;
        }
        let request: Value = serde_json::from_str(body).unwrap();
        state.query_bodies.push((path.into(), request.clone()));
        let execution = request
            .pointer("/query/term/execution_id")
            .and_then(Value::as_str);
        return json!({"count": state.documents.iter().filter(|((index, _), doc)| {
            matches_index(index) && doc.get("execution_id").and_then(Value::as_str) == execution
        }).count(), "_shards": {"failed":0}});
    }
    if path.contains("_search") {
        let request: Value = serde_json::from_str(body).unwrap();
        state.query_bodies.push((path.into(), request.clone()));
        if path.contains("network-mapping-dns-observations/_search")
            && request.pointer("/query/bool/filter").is_some()
        {
            let hits = state
                .documents
                .iter()
                .filter(|((index, _), _)| index.starts_with(".ds-dns-"))
                .map(|((index, id), _)| json!({"_index": index, "_id": id}))
                .collect::<Vec<_>>();
            return json!({
                "hits": {"total": {"value": hits.len(), "relation": "eq"}, "hits": hits},
                "_shards": {"failed": 0}
            });
        }
        if request.pointer("/aggs/indices").is_some() {
            return json!({"aggregations": {"indices": {"buckets": []}}, "_shards": {"failed":0}});
        }
        if request.pointer("/sort/0/ip").is_some() {
            let execution = request
                .pointer("/query/term/execution_id")
                .and_then(Value::as_str);
            let mut hits = state
                .documents
                .iter()
                .filter(|((index, _), doc)| {
                    path.contains(index)
                        && doc.get("execution_id").and_then(Value::as_str) == execution
                })
                .map(
                    |((_, id), doc)| json!({"_id":id,"_source":doc,"sort":[doc["ip"],doc["port"]]}),
                )
                .collect::<Vec<_>>();
            let key = |hit: &Value| {
                (
                    hit["sort"][0].as_str().unwrap().to_owned(),
                    hit["sort"][1].as_i64().unwrap(),
                )
            };
            hits.sort_by_key(&key);
            if let Some(after) = request.get("search_after") {
                let after = (
                    after[0].as_str().unwrap().to_owned(),
                    after[1].as_i64().unwrap(),
                );
                hits.retain(|hit| key(hit) > after);
            }
            hits.truncate(request["size"].as_u64().unwrap() as usize);
            return json!({"hits":{"hits":hits},"_shards":{"failed":0}});
        }
        let hits: Vec<_> = state
            .documents
            .iter()
            .filter(|((index, _), doc)| {
                matches_index(index)
                    && request
                        .pointer("/query/term/execution_id")
                        .is_none_or(|id| doc.get("execution_id") == Some(id))
            })
            .map(|((_, id), doc)| json!({"_source": doc, "sort": [id]}))
            .collect();
        let ips: std::collections::BTreeSet<_> = hits
            .iter()
            .filter_map(|hit| hit["_source"]["ip"].as_str())
            .collect();
        let size = request
            .pointer("/aggs/ips/composite/size")
            .and_then(Value::as_u64)
            .unwrap_or(1000) as usize;
        let after = request
            .pointer("/aggs/ips/composite/after/ip")
            .and_then(Value::as_str);
        let buckets = ips
            .iter()
            .filter(|ip| after.is_none_or(|after| **ip > after))
            .take(size)
            .map(|ip| json!({"key": {"ip":ip}}))
            .collect::<Vec<_>>();
        let after_key = buckets.last().map(|bucket| bucket["key"].clone());
        return json!({"hits": {"total": {"value": hits.len(), "relation": "eq"}, "hits": hits}, "_shards": {"failed":0},
            "aggregations": {"ips": {"buckets": buckets, "after_key": after_key}}});
    }
    json!({"acknowledged": true, "_shards": {"failed":0}})
}

async fn isolated_pool() -> (Pool, String) {
    isolated_pool_with_size(8).await
}

pub(super) async fn isolated_pool_with_size(max_size: usize) -> (Pool, String) {
    let mut config: tokio_postgres::Config = std::env::var("STORAGE_TEST_DATABASE_URL")
        .expect("disposable PG URL")
        .parse()
        .unwrap();
    let schema = format!("storage_{}", Uuid::new_v4().simple());
    config.options(format!("-c search_path={schema}"));
    let manager = deadpool_postgres::Manager::new(config, tokio_postgres::NoTls);
    let pool = Pool::builder(manager).max_size(max_size).build().unwrap();
    let client = pool.get().await.unwrap();
    client
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    client
        .batch_execute(include_str!("../source/database/init.sql"))
        .await
        .unwrap();
    // Match startup: task claims also read the scanner admission/health fields.
    client
        .batch_execute(include_str!(
            "../source/database/migrate_scanner_diagnostics.sql"
        ))
        .await
        .unwrap();
    (pool, schema)
}

pub(super) async fn seed_execution(pool: &Pool) {
    pool.get().await.unwrap().batch_execute(
        "INSERT INTO users(id,username,password) VALUES(1,'fixture','unused');
         INSERT INTO scan_task(id,user_id,task_id,task_initiator,task_target) VALUES(1,1,'task','fixture',ARRAY['192.0.2.1'::inet]);
         INSERT INTO scan_task_execution(id,execution_id,task_id,execution_status,result_ip_count,result_port_count,result_observation_count)
         VALUES(1,'execution',1,'running',0,0,0);"
    ).await.unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn fresh_install_restart_pending_and_missing_index_gate() {
    let (pool, schema) = isolated_pool().await;
    let fixture = EsFixture::start();
    let service = fixture.service();
    service.validate_scan_cutover(&pool).await.unwrap();
    let client = pool.get().await.unwrap();
    client
        .batch_execute(include_str!("../source/database/init.sql"))
        .await
        .unwrap();
    for name in ["ips", "ports", "scan_observation", "asset_endpoint_current"] {
        assert!(
            !client
                .query_one("SELECT to_regclass($1) IS NOT NULL", &[&name])
                .await
                .unwrap()
                .get::<_, bool>(0)
        );
    }
    drop(client);
    seed_execution(&pool).await;
    pool.get().await.unwrap().batch_execute("INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count) VALUES(1,'upload',0,true,0); INSERT INTO scan_projection_outbox(execution_id) VALUES(1);").await.unwrap();
    service.validate_scan_cutover(&pool).await.unwrap(); // pending must not brick restart
    fixture.state.lock().unwrap().fail_path = Some("endpoints-current".into());
    assert!(
        service
            .validate_scan_cutover(&pool)
            .await
            .unwrap_err()
            .contains("不可用")
    );
    fixture.state.lock().unwrap().fail_path = None;
    pool.get()
        .await
        .unwrap()
        .batch_execute("DROP TRIGGER scan_upload_stream_receipt ON scan_result_batch; ALTER TABLE scan_result_batch DROP COLUMN storage_backend")
        .await
        .unwrap();
    // Upgrading a pre-backend-column schema must classify existing receipts as PG.
    pool.get()
        .await
        .unwrap()
        .batch_execute(include_str!("../source/database/init.sql"))
        .await
        .unwrap();
    assert_eq!(
        pool.get()
            .await
            .unwrap()
            .query_one("SELECT storage_backend FROM scan_result_batch", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "postgres"
    );
    assert!(
        service
            .validate_scan_cutover(&pool)
            .await
            .unwrap_err()
            .contains("未迁移")
    );
    assert!(
        !fixture
            .state
            .lock()
            .unwrap()
            .requests
            .iter()
            .any(|path| path.contains("assets-v1"))
    );
    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn pg_migration_is_explicit_repeatable_and_checks_batch_completeness() {
    let (pool, schema) = isolated_pool().await;
    seed_execution(&pool).await;
    let fixture = EsFixture::start();
    let service = fixture.service();
    crate::scan_migration::prepare(&pool, &NoopProgressReporter)
        .await
        .unwrap();
    pool.get().await.unwrap().batch_execute(
        "INSERT INTO scan_result_batch(id,execution_id,upload_id,batch_index,is_final,observation_count,storage_backend) VALUES(1,1,'upload',0,true,1,'postgres');
         INSERT INTO ips(task_id,execution_id,ip_address) VALUES(1,1,'192.0.2.1');"
    ).await.unwrap();
    assert!(service.validate_scan_cutover(&pool).await.is_err());
    assert!(
        service
            .migrate_scan_data(&pool)
            .await
            .unwrap_err()
            .contains("观察数量")
    );
    pool.get().await.unwrap().batch_execute(
        "INSERT INTO scan_observation(execution_id,batch_id,observation_key,kind,ip_address,port,protocol,source,observed_at)
         VALUES(1,1,'observation','port','192.0.2.1',443,'tcp','fixture','2026-08-01T00:00:00Z');"
    ).await.unwrap();
    let report = service.migrate_scan_data(&pool).await.unwrap();
    assert_eq!(report.batches, 1);
    assert_eq!(report.observations, 1);
    service.validate_scan_cutover(&pool).await.unwrap();
    let documents = fixture.state.lock().unwrap().documents.len();
    service.migrate_scan_data(&pool).await.unwrap();
    assert_eq!(fixture.state.lock().unwrap().documents.len(), documents);
    assert_eq!(
        pool.get()
            .await
            .unwrap()
            .query_one(
                "SELECT storage_backend FROM scan_result_batch WHERE id=1",
                &[]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "elasticsearch"
    );
    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

fn dns_test_context() -> ScanBatchContext {
    ScanBatchContext {
        task_id: "task".into(),
        execution_id: "execution".into(),
        user_id: 1,
        task_source: "manual".into(),
        scanner_id: "scanner".into(),
        scanner_name: None,
        upload_id: "upload".into(),
        batch_index: 0,
        is_final: true,
    }
}

fn dns_test_observation(name: &str) -> DnsObservation {
    DnsObservation {
        observed_at: 1_788_883_200_000,
        question: crate::dns::DnsQuestion {
            name: name.into(),
            record_type: "A".into(),
            class: "IN".into(),
        },
        response_code: "NXDOMAIN".into(),
        authoritative: false,
        truncated: false,
        dnssec_authenticated: false,
        answers: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        resolver_ip: None,
        resolver_id: None,
        resolver_label: None,
        resolver_port: None,
        resolver_transport: None,
        latency_ms: Some(1),
    }
}

#[tokio::test]
async fn dns_retry_reconciles_through_data_stream_across_rollover() {
    let fixture = EsFixture::start();
    let service = fixture.service();
    let context = dns_test_context();
    let observations = vec![dns_test_observation("example.com")];
    let first = service
        .persist_dns_observations(&context, "default", &observations, DnsWriteMode::Fresh)
        .await
        .unwrap();
    fixture.state.lock().unwrap().dns_generation = 1;
    let retried = service
        .persist_dns_observations(&context, "default", &observations, DnsWriteMode::Reconcile)
        .await
        .unwrap();
    assert_eq!(first, retried);
    assert_eq!(first[0], ".ds-dns-0");
    assert_eq!(first[1], "network-mapping-dns-records-v1");
    let state = fixture.state.lock().unwrap();
    assert_eq!(
        state
            .documents
            .keys()
            .filter(|(index, _)| index.starts_with(".ds-dns-"))
            .count(),
        1
    );
    assert_eq!(
        state
            .requests
            .iter()
            .filter(|request| request.contains("/_refresh"))
            .count(),
        1
    );
    assert_eq!(
        state
            .requests
            .iter()
            .filter(|request| request.contains("/_search"))
            .count(),
        1
    );
    assert_eq!(
        state
            .requests
            .iter()
            .filter(|request| request.contains("/_bulk"))
            .count(),
        1
    );
}

#[tokio::test]
async fn dns_retry_only_writes_missing_documents_after_rollover() {
    let fixture = EsFixture::start();
    let service = fixture.service();
    let context = dns_test_context();
    let observations = vec![
        dns_test_observation("example.com"),
        dns_test_observation("www.example.com"),
    ];
    service
        .persist_dns_observations(&context, "default", &observations, DnsWriteMode::Fresh)
        .await
        .unwrap();
    {
        let mut state = fixture.state.lock().unwrap();
        let removed = state
            .documents
            .keys()
            .find(|(index, _)| index.starts_with(".ds-dns-"))
            .cloned()
            .unwrap();
        state.documents.remove(&removed);
        state.dns_generation = 1;
    }

    let references = service
        .persist_dns_observations(&context, "default", &observations, DnsWriteMode::Reconcile)
        .await
        .unwrap();
    assert_eq!(
        references,
        vec![
            ".ds-dns-0".to_owned(),
            ".ds-dns-1".to_owned(),
            "network-mapping-dns-records-v1".to_owned()
        ]
    );
    let state = fixture.state.lock().unwrap();
    assert_eq!(
        state
            .documents
            .keys()
            .filter(|(index, _)| index.starts_with(".ds-dns-"))
            .count(),
        2
    );
}

#[tokio::test]
async fn dns_reconciliation_rejects_duplicate_id_across_backing_indices() {
    let fixture = EsFixture::start();
    let service = fixture.service();
    let context = dns_test_context();
    let observations = vec![dns_test_observation("example.com")];
    service
        .persist_dns_observations(&context, "default", &observations, DnsWriteMode::Fresh)
        .await
        .unwrap();
    {
        let mut state = fixture.state.lock().unwrap();
        let ((_, id), document) = state
            .documents
            .iter()
            .find(|((index, _), _)| index.starts_with(".ds-dns-"))
            .map(|(key, document)| (key.clone(), document.clone()))
            .unwrap();
        state.documents.insert((".ds-dns-1".into(), id), document);
    }

    let error = service
        .persist_dns_observations(&context, "default", &observations, DnsWriteMode::Reconcile)
        .await
        .unwrap_err();
    assert!(error.contains("跨 backing index 重复"));
}

pub(super) async fn seed_dns_upload(
    pool: &Pool,
) -> crate::result_ingest::model::ScannerResultUpload {
    seed_execution(pool).await;
    let scanner = "00000000-0000-0000-0000-000000000001";
    let task = "00000000-0000-0000-0000-000000000002";
    let token_hash =
        crate::identity::hash_scanner_token("fixture-token", "fixture-pepper").unwrap();
    let client = pool.get().await.unwrap();
    client.execute("INSERT INTO scanner_info(scanner_id,create_user,runtime_token_hash,is_enable) VALUES($1,1,$2,true)", &[&scanner,&token_hash]).await.unwrap();
    client
        .execute(
            "UPDATE scan_task SET task_id=$1, task_kind='dns', scan_profile='dns_records' WHERE id=1",
            &[&task],
        )
        .await
        .unwrap();
    client.execute("UPDATE scan_task_execution SET assigned_scanner_id=$1,task_start_time=1785542400000 WHERE id=1", &[&scanner]).await.unwrap();
    drop(client);
    serde_json::from_value(json!({
        "protocol_version": 2,
        "scanner_id": scanner,
        "task_id": task,
        "upload_id": "00000000-0000-0000-0000-000000000003",
        "batch_index": 0,
        "is_final": false,
        "observations": [{
            "kind": "dns",
            "observed_at": 1_788_883_200_000_i64,
            "question": {"name": "example.com", "type": "A", "class": "IN"},
            "response_code": "NXDOMAIN",
            "authoritative": false,
            "truncated": false,
            "dnssec_authenticated": false,
            "answers": [],
            "authority": [],
            "additional": [],
            "resolver_ip": null,
            "resolver_id": null,
            "resolver_label": null,
            "resolver_port": null,
            "resolver_transport": null,
            "latency_ms": 1
        }]
    }))
    .unwrap()
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn dns_batch_write_lease_blocks_overlap_and_recovers_after_expiry() {
    let (pool, schema) = isolated_pool().await;
    let fixture = EsFixture::start();
    let service = fixture.service();
    let upload = seed_dns_upload(&pool).await;
    let maxmind = crate::maxmind::MaxMindState::from_directory("/tmp/nm-es-no-maxmind");
    let follow_up = crate::dns_follow_up::DnsFollowUpConfig::default();

    fixture.state.lock().unwrap().fail_path = Some("_bulk".into());
    let failed_write = crate::result_ingest::storage::save_scanner_results(
        &pool,
        &maxmind,
        &service,
        &follow_up,
        &upload,
        "fixture-token",
        "fixture-pepper",
    )
    .await;
    assert!(
        matches!(
            &failed_write,
            Err(crate::result_ingest::model::SaveScannerResultsError::Storage(_))
        ),
        "unexpected first write result: {failed_write:?}"
    );
    assert!(matches!(
        crate::result_ingest::storage::save_scanner_results(
            &pool,
            &maxmind,
            &service,
            &follow_up,
            &upload,
            "fixture-token",
            "fixture-pepper"
        )
        .await,
        Err(crate::result_ingest::model::SaveScannerResultsError::BatchBusy { .. })
    ));

    fixture.state.lock().unwrap().fail_path = None;
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE scan_result_batch SET write_lease_expires_at = clock_timestamp() - INTERVAL '1 second'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        crate::result_ingest::storage::save_scanner_results(
            &pool,
            &maxmind,
            &service,
            &follow_up,
            &upload,
            "fixture-token",
            "fixture-pepper"
        )
        .await
        .unwrap(),
        1
    );
    let receipt = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT storage_backend, write_token IS NULL, write_attempts FROM scan_result_batch",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(receipt.get::<_, String>(0), "elasticsearch");
    assert!(receipt.get::<_, bool>(1));
    assert_eq!(receipt.get::<_, i32>(2), 2);

    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn dns_elasticsearch_wait_does_not_hold_the_postgres_connection() {
    let (pool, schema) = isolated_pool_with_size(1).await;
    let fixture = EsFixture::start();
    let service = fixture.service();
    let upload = seed_dns_upload(&pool).await;
    let maxmind = crate::maxmind::MaxMindState::from_directory("/tmp/nm-es-no-maxmind");
    let follow_up = crate::dns_follow_up::DnsFollowUpConfig::default();
    {
        let mut state = fixture.state.lock().unwrap();
        state.delay_path = Some("_bulk".into());
        state.delay_ms = 750;
    }

    let write = crate::result_ingest::storage::save_scanner_results(
        &pool,
        &maxmind,
        &service,
        &follow_up,
        &upload,
        "fixture-token",
        "fixture-pepper",
    );
    let pool_probe = async {
        loop {
            if fixture
                .state
                .lock()
                .unwrap()
                .requests
                .iter()
                .any(|request| request.contains("/_bulk"))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        matches!(
            tokio::time::timeout(Duration::from_millis(250), pool.get()).await,
            Ok(Ok(_))
        )
    };
    let (write_result, pool_was_available) = tokio::join!(write, pool_probe);
    assert!(
        pool_was_available,
        "ES I/O must not retain the PG connection"
    );
    assert_eq!(write_result.unwrap(), 1);

    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires STORAGE_TEST_CONFIG_PATH and creates isolated local ES resources"]
async fn live_elasticsearch_accepts_fresh_and_reconciled_dns_writes() {
    let config_path = std::env::var("STORAGE_TEST_CONFIG_PATH").expect("test config path");
    let mut config = crate::config::Config::from_file(config_path).elasticsearch;
    let suffix = Uuid::new_v4().simple().to_string();
    config.dns_observation_data_stream = format!("nm-test-dns-{suffix}");
    config.dns_record_index = format!("nm-test-dns-records-{suffix}");
    let stream = config.dns_observation_data_stream.clone();
    let record_index = config.dns_record_index.clone();
    let template = format!("{stream}-template");
    let service = ElasticsearchService::new(config).unwrap();
    let mut context = dns_test_context();
    context.execution_id = format!("execution-{suffix}");
    context.upload_id = format!("upload-{suffix}");
    let observations = vec![dns_test_observation("live-test.example")];

    let first = service
        .persist_dns_observations(&context, "default", &observations, DnsWriteMode::Fresh)
        .await;
    let recovered = if first.is_ok() {
        service
            .persist_dns_observations(&context, "default", &observations, DnsWriteMode::Reconcile)
            .await
    } else {
        Err("fresh write failed".to_owned())
    };

    for path in [
        format!("/_data_stream/{stream}"),
        format!("/{record_index}"),
        format!("/_index_template/{template}"),
    ] {
        let _ = service
            .send_json_request(
                ElasticsearchOperation::IndexAdmin,
                reqwest::Method::DELETE,
                &path,
                |request| request,
            )
            .await;
    }

    let first = first.unwrap();
    let recovered = recovered.unwrap();
    assert_eq!(first, recovered);
    assert_eq!(
        first
            .iter()
            .filter(|index| index.starts_with(".ds-nm-test-dns-"))
            .count(),
        1
    );
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn task_claim_keeps_selected_priority_then_uses_public_queue() {
    let (pool, schema) = isolated_pool().await;
    let scanner = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let second_scanner = Uuid::parse_str("00000000-0000-0000-0000-000000000004").unwrap();
    let selected_task = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let public_task = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
    let token_hash =
        crate::identity::hash_scanner_token("fixture-token", "fixture-pepper").unwrap();
    let second_token_hash =
        crate::identity::hash_scanner_token("second-fixture-token", "fixture-pepper").unwrap();
    let client = pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO users(id,username,password) VALUES(1,'fixture','unused')",
            &[],
        )
        .await
        .unwrap();
    client.execute("INSERT INTO scanner_info(scanner_id,create_user,runtime_token_hash,is_enable) VALUES($1,1,$2,true)", &[&scanner.to_string(),&token_hash]).await.unwrap();
    client.execute("INSERT INTO scanner_info(scanner_id,create_user,runtime_token_hash,is_enable) VALUES($1,1,$2,true)", &[&second_scanner.to_string(),&second_token_hash]).await.unwrap();
    client.execute("INSERT INTO scan_task(id,user_id,task_id,task_initiator,task_target,task_level,task_create_time) VALUES(1,1,$1,'fixture',ARRAY['192.0.2.1'::inet],1,2),(2,1,$2,'fixture',ARRAY['192.0.2.2'::inet],4,1)", &[&selected_task.to_string(), &public_task.to_string()]).await.unwrap();
    client.execute("INSERT INTO scan_task_execution(id,execution_id,task_id,requested_scanner_id) VALUES(1,'selected-execution',1,$1),(2,'public-execution',2,NULL)", &[&scanner.to_string()]).await.unwrap();
    drop(client);

    let selected = crate::scan_control::dispatch::apply_task(
        &pool,
        scanner,
        "fixture-token",
        "fixture-pepper",
    )
    .await
    .unwrap();
    assert_eq!(selected.task_id, selected_task);

    let mut client = pool.get().await.unwrap();
    let transaction = client.transaction().await.unwrap();
    transaction
        .execute(
            "UPDATE scan_task_execution SET execution_status='succeeded', lease_expires_at=NULL WHERE id=1",
            &[],
        )
        .await
        .unwrap();
    crate::scan_control::dispatch::refresh_task_aggregate(&transaction, 1)
        .await
        .unwrap();
    transaction.commit().await.unwrap();

    let public = crate::scan_control::dispatch::apply_task(
        &pool,
        scanner,
        "fixture-token",
        "fixture-pepper",
    )
    .await
    .unwrap();
    assert_eq!(public.task_id, public_task);

    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE scan_task_execution SET lease_expires_at = $1 WHERE id=2",
            &[&(crate::clock::get_unix_epoch_ms() - 1)],
        )
        .await
        .unwrap();
    let reclaimed = crate::scan_control::dispatch::apply_task(
        &pool,
        second_scanner,
        "second-fixture-token",
        "fixture-pepper",
    )
    .await
    .unwrap();
    assert_eq!(reclaimed.task_id, public_task);

    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn durable_upload_recovery_rotates_an_execution_with_a_different_upload_identity() {
    let (pool, schema) = isolated_pool().await;
    let scanner = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let task_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let cached_upload_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
    let token_hash =
        crate::identity::hash_scanner_token("fixture-token", "fixture-pepper").unwrap();
    let client = pool.get().await.unwrap();
    client
        .batch_execute("INSERT INTO users(id,username,password) VALUES(1,'fixture','unused')")
        .await
        .unwrap();
    client.execute("INSERT INTO scanner_info(scanner_id,create_user,runtime_token_hash,is_enable) VALUES($1,1,$2,true)", &[&scanner.to_string(), &token_hash]).await.unwrap();
    client.execute("INSERT INTO scan_task(id,user_id,task_id,task_initiator,task_target,task_status) VALUES(1,1,$1,'fixture',ARRAY['192.0.2.1'::inet],'running')", &[&task_id.to_string()]).await.unwrap();
    client.execute("INSERT INTO scan_task_execution(id,execution_id,task_id,requested_scanner_id,assigned_scanner_id,execution_status,attempt_count,task_start_time,lease_expires_at) VALUES(1,'old-execution',1,$1,$1,'running',1,1,1)", &[&scanner.to_string()]).await.unwrap();
    client.execute("INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count,protocol_version,storage_backend) VALUES(1,'old-upload',0,false,500,3,'elasticsearch')", &[]).await.unwrap();
    client.batch_execute("SELECT setval(pg_get_serial_sequence('scan_task_execution','id'),(SELECT MAX(id) FROM scan_task_execution),true)").await.unwrap();
    drop(client);

    let recovered = crate::scan_control::dispatch::recover_scanner_task(
        &pool,
        scanner,
        Some(task_id),
        Some(cached_upload_id),
        "fixture-token",
        "fixture-pepper",
    )
    .await
    .unwrap();
    assert_eq!(recovered.task_id, task_id);

    let client = pool.get().await.unwrap();
    let rows = client
        .query(
            "SELECT id, execution_status, requested_scanner_id, assigned_scanner_id, attempt_count FROM scan_task_execution ORDER BY id",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<_, String>("execution_status"), "superseded");
    assert_eq!(
        rows[0].get::<_, Option<String>>("requested_scanner_id"),
        None
    );
    assert_eq!(rows[1].get::<_, String>("execution_status"), "running");
    assert_eq!(
        rows[1]
            .get::<_, Option<String>>("assigned_scanner_id")
            .as_deref(),
        Some(scanner.to_string().as_str())
    );
    assert_eq!(rows[1].get::<_, i32>("attempt_count"), 1);
    assert_eq!(
        client
            .query_one("SELECT execution_id FROM scan_result_batch", &[])
            .await
            .unwrap()
            .get::<_, i32>(0),
        rows[0].get::<_, i32>("id")
    );

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn fresh_recovery_rotates_an_execution_that_already_has_batches() {
    let (pool, schema) = isolated_pool().await;
    let scanner = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let task_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let token_hash =
        crate::identity::hash_scanner_token("fixture-token", "fixture-pepper").unwrap();
    let client = pool.get().await.unwrap();
    client
        .batch_execute("INSERT INTO users(id,username,password) VALUES(1,'fixture','unused')")
        .await
        .unwrap();
    client.execute("INSERT INTO scanner_info(scanner_id,create_user,runtime_token_hash,is_enable) VALUES($1,1,$2,true)", &[&scanner.to_string(), &token_hash]).await.unwrap();
    client.execute("INSERT INTO scan_task(id,user_id,task_id,task_initiator,task_target,task_status) VALUES(1,1,$1,'fixture',ARRAY['192.0.2.1'::inet],'running')", &[&task_id.to_string()]).await.unwrap();
    client.execute("INSERT INTO scan_task_execution(id,execution_id,task_id,requested_scanner_id,assigned_scanner_id,execution_status,attempt_count,task_start_time,lease_expires_at) VALUES(1,'old-execution',1,$1,$1,'running',1,1,1)", &[&scanner.to_string()]).await.unwrap();
    client.execute("INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count,protocol_version,storage_backend) VALUES(1,'old-upload',0,false,500,3,'elasticsearch')", &[]).await.unwrap();
    client.batch_execute("SELECT setval(pg_get_serial_sequence('scan_task_execution','id'),(SELECT MAX(id) FROM scan_task_execution),true)").await.unwrap();
    drop(client);

    let recovered = crate::scan_control::dispatch::recover_scanner_task(
        &pool,
        scanner,
        None,
        None,
        "fixture-token",
        "fixture-pepper",
    )
    .await
    .unwrap();
    assert_eq!(recovered.task_id, task_id);

    let client = pool.get().await.unwrap();
    let rows = client
        .query(
            "SELECT id, execution_status, requested_scanner_id, assigned_scanner_id, attempt_count FROM scan_task_execution ORDER BY id",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<_, String>("execution_status"), "superseded");
    assert_eq!(rows[1].get::<_, String>("execution_status"), "running");
    assert_eq!(
        rows[1]
            .get::<_, Option<String>>("assigned_scanner_id")
            .as_deref(),
        Some(scanner.to_string().as_str())
    );
    assert_eq!(rows[1].get::<_, i32>("attempt_count"), 1);
    assert_eq!(
        client
            .query_one("SELECT execution_id FROM scan_result_batch", &[])
            .await
            .unwrap()
            .get::<_, i32>(0),
        rows[0].get::<_, i32>("id")
    );

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn expired_execution_claim_rotates_existing_batches_for_the_next_scanner() {
    let (pool, schema) = isolated_pool().await;
    let first_scanner = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let second_scanner = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let task_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
    let second_token_hash =
        crate::identity::hash_scanner_token("second-fixture-token", "fixture-pepper").unwrap();
    let client = pool.get().await.unwrap();
    client
        .batch_execute("INSERT INTO users(id,username,password) VALUES(1,'fixture','unused')")
        .await
        .unwrap();
    client.execute("INSERT INTO scanner_info(scanner_id,create_user,runtime_token_hash,is_enable) VALUES($1,1,'unused',true),($2,1,$3,true)", &[&first_scanner.to_string(), &second_scanner.to_string(), &second_token_hash]).await.unwrap();
    client.execute("INSERT INTO scan_task(id,user_id,task_id,task_initiator,task_target,task_status) VALUES(1,1,$1,'fixture',ARRAY['192.0.2.1'::inet],'running')", &[&task_id.to_string()]).await.unwrap();
    client.execute("INSERT INTO scan_task_execution(id,execution_id,task_id,assigned_scanner_id,execution_status,attempt_count,task_start_time,lease_expires_at) VALUES(1,'old-execution',1,$1,'running',1,1,1)", &[&first_scanner.to_string()]).await.unwrap();
    client.execute("INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count,protocol_version,storage_backend) VALUES(1,'old-upload',0,false,500,3,'elasticsearch')", &[]).await.unwrap();
    client.batch_execute("SELECT setval(pg_get_serial_sequence('scan_task_execution','id'),(SELECT MAX(id) FROM scan_task_execution),true)").await.unwrap();
    drop(client);

    let claimed = crate::scan_control::dispatch::apply_task(
        &pool,
        second_scanner,
        "second-fixture-token",
        "fixture-pepper",
    )
    .await
    .unwrap();
    assert_eq!(claimed.task_id, task_id);

    let client = pool.get().await.unwrap();
    let rows = client
        .query(
            "SELECT id, execution_status, assigned_scanner_id, attempt_count FROM scan_task_execution ORDER BY id",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<_, String>("execution_status"), "superseded");
    assert_eq!(rows[1].get::<_, String>("execution_status"), "running");
    assert_eq!(
        rows[1]
            .get::<_, Option<String>>("assigned_scanner_id")
            .as_deref(),
        Some(second_scanner.to_string().as_str())
    );
    assert_eq!(rows[1].get::<_, i32>("attempt_count"), 1);

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn concurrent_task_claims_do_not_assign_one_execution_twice() {
    let (pool, schema) = isolated_pool().await;
    let first_scanner = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let second_scanner = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let task_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
    let first_hash = crate::identity::hash_scanner_token("first-token", "fixture-pepper").unwrap();
    let second_hash =
        crate::identity::hash_scanner_token("second-token", "fixture-pepper").unwrap();
    let client = pool.get().await.unwrap();
    client
        .batch_execute("INSERT INTO users(id,username,password) VALUES(1,'fixture','unused')")
        .await
        .unwrap();
    client.execute("INSERT INTO scanner_info(scanner_id,create_user,runtime_token_hash,is_enable) VALUES($1,1,$2,true),($3,1,$4,true)", &[&first_scanner.to_string(), &first_hash, &second_scanner.to_string(), &second_hash]).await.unwrap();
    client.execute("INSERT INTO scan_task(id,user_id,task_id,task_initiator,task_target) VALUES(1,1,$1,'fixture',ARRAY['192.0.2.1'::inet])", &[&task_id.to_string()]).await.unwrap();
    client
        .batch_execute(
            "INSERT INTO scan_task_execution(id,execution_id,task_id) VALUES(1,'execution',1)",
        )
        .await
        .unwrap();
    drop(client);

    let (first, second) = tokio::join!(
        crate::scan_control::dispatch::apply_task(
            &pool,
            first_scanner,
            "first-token",
            "fixture-pepper"
        ),
        crate::scan_control::dispatch::apply_task(
            &pool,
            second_scanner,
            "second-token",
            "fixture-pepper"
        )
    );
    let successes = [&first, &second]
        .into_iter()
        .filter(|result| result.is_ok())
        .count();
    assert_eq!(successes, 1);
    assert!(matches!(
        first,
        Ok(_) | Err(crate::scan_control::dispatch::ApplyTaskError::NoTask)
    ));
    assert!(matches!(
        second,
        Ok(_) | Err(crate::scan_control::dispatch::ApplyTaskError::NoTask)
    ));

    let execution = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT execution_status, assigned_scanner_id FROM scan_task_execution WHERE id=1",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(execution.get::<_, String>(0), "running");
    assert!(matches!(
        execution.get::<_, Option<String>>(1).as_deref(),
        Some(value) if value == first_scanner.to_string() || value == second_scanner.to_string()
    ));

    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn no_task_result_commits_bounded_cancel_reaping() {
    let (pool, schema) = isolated_pool().await;
    let scanner = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let task_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let token_hash =
        crate::identity::hash_scanner_token("fixture-token", "fixture-pepper").unwrap();
    let client = pool.get().await.unwrap();
    client
        .batch_execute("INSERT INTO users(id,username,password) VALUES(1,'fixture','unused')")
        .await
        .unwrap();
    client.execute("INSERT INTO scanner_info(scanner_id,create_user,runtime_token_hash,is_enable) VALUES($1,1,$2,true)", &[&scanner.to_string(), &token_hash]).await.unwrap();
    client.execute("INSERT INTO scan_task(id,user_id,task_id,task_initiator,task_target,task_status) VALUES(1,1,$1,'fixture',ARRAY['192.0.2.1'::inet],'running')", &[&task_id.to_string()]).await.unwrap();
    client.execute("INSERT INTO scan_task_execution(id,execution_id,task_id,execution_status,assigned_scanner_id,lease_expires_at,cancel_requested) VALUES(1,'execution',1,'running','other-scanner',$1,true)", &[&(crate::clock::get_unix_epoch_ms() - 1)]).await.unwrap();
    drop(client);

    assert!(matches!(
        crate::scan_control::dispatch::apply_task(
            &pool,
            scanner,
            "fixture-token",
            "fixture-pepper"
        )
        .await,
        Err(crate::scan_control::dispatch::ApplyTaskError::NoTask)
    ));
    let status: String = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT execution_status FROM scan_task_execution WHERE id=1",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(status, "cancelled");

    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

fn plan_contains_node(value: &Value, node_type: &str, relation: Option<&str>) -> bool {
    match value {
        Value::Array(values) => values
            .iter()
            .any(|value| plan_contains_node(value, node_type, relation)),
        Value::Object(values) => {
            let matches = values.get("Node Type").and_then(Value::as_str) == Some(node_type)
                && relation.is_none_or(|relation| {
                    values.get("Relation Name").and_then(Value::as_str) == Some(relation)
                });
            matches
                || values
                    .values()
                    .any(|value| plan_contains_node(value, node_type, relation))
        }
        _ => false,
    }
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and inserts 200k synthetic tasks"]
async fn task_claim_plan_avoids_global_scans_and_disk_sort_at_scale() {
    let (pool, schema) = isolated_pool().await;
    let scanner = "00000000-0000-0000-0000-000000000001";
    let mut client = pool.get().await.unwrap();
    client
        .batch_execute(
            "INSERT INTO users(id,username,password) VALUES(1,'fixture','unused');
             INSERT INTO scanner_info(scanner_id,create_user,is_enable) VALUES
                 ('00000000-0000-0000-0000-000000000001',1,true);
             INSERT INTO scan_task(id,user_id,task_id,task_initiator,task_target,task_level,task_create_time)
             SELECT value, 1, LPAD(value::TEXT, 36, '0'), 'fixture',
                    ARRAY['192.0.2.1'::INET], value % 5, value
             FROM generate_series(1, 200000) AS value;
             INSERT INTO scan_task_execution(id,execution_id,task_id)
             SELECT value, 'execution-' || value, value
             FROM generate_series(1, 200000) AS value;
             ANALYZE scan_task;
             ANALYZE scan_task_execution;",
        )
        .await
        .unwrap();
    let transaction = client.transaction().await.unwrap();
    let selected_plan: Value = transaction
        .query_one(
            "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) \
             SELECT t.id AS task_pk, e.id AS execution_pk \
             FROM scan_task_execution e \
             JOIN scan_task t ON t.id = e.task_id \
             JOIN scanner_info s ON s.scanner_id = $1 \
             WHERE e.execution_status = 'pending' AND e.requested_scanner_id = $1 \
               AND t.task_status IN ('pending', 'running') \
             ORDER BY t.task_level DESC, t.task_create_time, t.id, e.id \
             FOR UPDATE OF e SKIP LOCKED LIMIT 1;",
            &[&scanner],
        )
        .await
        .unwrap()
        .get(0);
    let plan: Value = transaction
        .query_one(
            "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) \
             SELECT t.id AS task_pk, e.execution_pk, t.user_id, t.task_id, \
                 CASE WHEN t.task_kind = 'dns' THEN t.dns_targets ELSE t.task_target::text[] END AS task_target, \
                 t.task_port, t.address_family, t.scan_plan, t.dns_resolvers \
             FROM scan_task t \
             JOIN scanner_info s ON s.scanner_id = $2 \
             JOIN LATERAL ( \
                 SELECT candidate.id AS execution_pk \
                 FROM scan_task_execution candidate \
                 WHERE candidate.task_id = t.id AND ( \
                     (candidate.execution_status = 'pending' AND candidate.requested_scanner_id IS NULL) \
                     OR (candidate.execution_status = 'running' \
                         AND candidate.maintenance_hold = FALSE \
                         AND candidate.cancel_requested = FALSE \
                         AND (candidate.lease_expires_at IS NULL OR candidate.lease_expires_at < $1) \
                         AND (candidate.requested_scanner_id IS NULL OR candidate.requested_scanner_id = $2)) \
                 ) \
                 ORDER BY candidate.id FOR UPDATE SKIP LOCKED LIMIT 1 \
             ) e ON TRUE \
             WHERE t.task_status IN ('pending', 'running') \
               AND ((t.address_family = 'ipv4' AND s.supports_ipv4 AND s.ipv4_ready) \
                 OR (t.address_family = 'ipv6' AND s.supports_ipv6 AND s.ipv6_ready)) \
               AND (t.scan_profile = 'legacy' OR s.scan_capabilities->'profiles' ? t.scan_profile) \
               AND (jsonb_array_length(t.dns_resolvers) = 0 \
                 OR COALESCE((s.scan_capabilities->>'explicit_dns_resolvers')::BOOLEAN, FALSE)) \
             ORDER BY t.task_level DESC, t.task_create_time, t.id, e.execution_pk \
             LIMIT 1;",
            &[&crate::clock::get_unix_epoch_ms(), &scanner],
        )
        .await
        .unwrap()
        .get(0);
    transaction.rollback().await.unwrap();
    assert!(!plan_contains_node(
        &selected_plan,
        "Seq Scan",
        Some("scan_task")
    ));
    assert!(!plan_contains_node(
        &selected_plan,
        "Seq Scan",
        Some("scan_task_execution")
    ));
    assert!(!plan_contains_node(&plan, "Seq Scan", Some("scan_task")));
    assert!(!plan_contains_node(
        &plan,
        "Seq Scan",
        Some("scan_task_execution")
    ));
    assert!(!plan.to_string().contains("external merge"));
    eprintln!(
        "200k selected/general task claim execution time: {}/{} ms",
        selected_plan
            .pointer("/0/Execution Time")
            .and_then(Value::as_f64)
            .unwrap_or_default(),
        plan.pointer("/0/Execution Time")
            .and_then(Value::as_f64)
            .unwrap_or_default()
    );

    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn uploads_recover_without_pg_facts_and_reject_changed_completed_batches() {
    let (pool, schema) = isolated_pool().await;
    seed_execution(&pool).await;
    let fixture = EsFixture::start();
    let service = fixture.service();
    service.validate_scan_cutover(&pool).await.unwrap();
    let scanner = "00000000-0000-0000-0000-000000000001";
    let task = "00000000-0000-0000-0000-000000000002";
    let token_hash =
        crate::identity::hash_scanner_token("fixture-token", "fixture-pepper").unwrap();
    let client = pool.get().await.unwrap();
    client.execute("INSERT INTO scanner_info(scanner_id,create_user,runtime_token_hash,is_enable) VALUES($1,1,$2,true)", &[&scanner,&token_hash]).await.unwrap();
    client
        .execute("UPDATE scan_task SET task_id=$1 WHERE id=1", &[&task])
        .await
        .unwrap();
    client.execute("UPDATE scan_task_execution SET assigned_scanner_id=$1,task_start_time=1785542400000 WHERE id=1", &[&scanner]).await.unwrap();
    drop(client);
    let payload = json!({"protocol_version":2, "scanner_id":scanner, "task_id":task,
        "upload_id":"00000000-0000-0000-0000-000000000003", "batch_index":0,"is_final":false,
        "observations":[{"kind":"port","ip":"192.0.2.1","port":443,"protocol":"tcp","state":"open","source":"fixture","observed_at":1785542400000_i64}]});
    let upload: crate::result_ingest::model::ScannerResultUpload =
        serde_json::from_value(payload.clone()).unwrap();
    let maxmind = crate::maxmind::MaxMindState::from_directory("/tmp/nm-es-no-maxmind");
    let follow_up = crate::dns_follow_up::DnsFollowUpConfig::default();
    fixture.state.lock().unwrap().fail_path = Some("_bulk".into());
    assert!(
        crate::result_ingest::storage::save_scanner_results(
            &pool,
            &maxmind,
            &service,
            &follow_up,
            &upload,
            "fixture-token",
            "fixture-pepper"
        )
        .await
        .is_err()
    );
    let backend: String = pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT storage_backend FROM scan_result_batch", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(backend, "pending");
    fixture.state.lock().unwrap().fail_path = None;
    service.validate_scan_cutover(&pool).await.unwrap();
    assert_eq!(
        crate::result_ingest::storage::save_scanner_results(
            &pool,
            &maxmind,
            &service,
            &follow_up,
            &upload,
            "fixture-token",
            "fixture-pepper"
        )
        .await
        .unwrap(),
        1
    );
    // Force the crash boundary: ES contains facts, but PG still only has a reservation.
    pool.get()
        .await
        .unwrap()
        .batch_execute("UPDATE scan_result_batch SET storage_backend='pending'")
        .await
        .unwrap();
    crate::result_ingest::storage::save_scanner_results(
        &pool,
        &maxmind,
        &service,
        &follow_up,
        &upload,
        "fixture-token",
        "fixture-pepper",
    )
    .await
    .unwrap();
    assert_eq!(
        fixture
            .state
            .lock()
            .unwrap()
            .documents
            .keys()
            .filter(|(index, _)| index.contains("scan-observations"))
            .count(),
        1
    );
    let mut final_upload = upload.clone();
    final_upload.batch_index = Some(1);
    final_upload.is_final = Some(true);
    final_upload.observations.clear();
    crate::result_ingest::storage::save_scanner_results(
        &pool,
        &maxmind,
        &service,
        &follow_up,
        &final_upload,
        "fixture-token",
        "fixture-pepper",
    )
    .await
    .unwrap();
    let row = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT execution_status,result_observation_count FROM scan_task_execution WHERE id=1",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "succeeded");
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(
        crate::result_ingest::storage::save_scanner_results(
            &pool,
            &maxmind,
            &service,
            &follow_up,
            &upload,
            "fixture-token",
            "fixture-pepper"
        )
        .await
        .unwrap(),
        0
    );
    let mut changed = payload;
    changed["observations"][0]["port"] = json!(80);
    let changed: crate::result_ingest::model::ScannerResultUpload =
        serde_json::from_value(changed).unwrap();
    assert!(
        crate::result_ingest::storage::save_scanner_results(
            &pool,
            &maxmind,
            &service,
            &follow_up,
            &changed,
            "fixture-token",
            "fixture-pepper"
        )
        .await
        .is_err()
    );
    assert!(fixture.state.lock().unwrap().requests.iter().any(|path| {
        path.contains("scan-observations-v1-") && !path.contains('*') && path.contains("_refresh")
    }));
    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[test]
fn failed_service_probe_does_not_advance_successful_service_clock() {
    let context = dns_test_context();
    let failed = json!({"kind": "service", "ip_address": "192.0.2.1", "port": 80,
        "service": null, "banner": null, "data": {"evidence": [], "confidence": 0}});
    let projection = endpoint_projection_document(&context, &failed, 2000);
    assert_eq!(projection["observed_at_ms"], 2000);
    assert!(projection["service_observed_at_ms"].is_null());
    let mut successful = failed;
    successful["service"] = json!("http");
    assert_eq!(
        endpoint_projection_document(&context, &successful, 1000)["service_observed_at_ms"],
        1000
    );
}

#[tokio::test]
#[ignore = "requires STORAGE_TEST_CONFIG_PATH and creates an isolated ES index"]
async fn live_elasticsearch_preserves_successful_web_evidence_after_failed_probes() {
    let config_path = std::env::var("STORAGE_TEST_CONFIG_PATH").expect("test config path");
    let service =
        ElasticsearchService::new(crate::config::Config::from_file(config_path).elasticsearch)
            .unwrap();
    let index = format!("nm-test-web-projection-{}", Uuid::new_v4().simple());
    let context = dns_test_context();
    let test = async {
        service
            .send_json_request(
                ElasticsearchOperation::IndexAdmin,
                Method::PUT,
                &format!("/{index}"),
                |request| request.json(&scan_endpoint_index_definition(0)),
            )
            .await?;
        let success = json!({"kind": "service", "ip_address": "192.0.2.1", "port": 443,
            "service": "https", "title": "Camera", "http_body": "<title>Camera</title>",
            "banner": "HTTP/1.1 200 OK", "tls_subject": "CN=camera"});
        let failed = json!({"kind": "service", "ip_address": "192.0.2.1", "port": 443});
        let mut latest_success = success.clone();
        latest_success["title"] = json!("Updated camera");
        let documents = [
            endpoint_projection_document(&context, &success, 1000),
            endpoint_projection_document(&context, &failed, 2000),
            endpoint_projection_document(&context, &latest_success, 1500),
            endpoint_projection_document(&context, &success, 1200),
            endpoint_projection_document(&context, &failed, 2500),
        ];
        for (position, document) in documents.iter().enumerate() {
            let mut body = String::new();
            append_projection_update(&mut body, &index, "endpoint", document)?;
            let result = service.send_bulk_with_retry("/_bulk", &body, false).await?;
            if result["errors"] != false {
                return Err(format!("projection failed: {result}"));
            }
            let current = service
                .send_json_request(
                    ElasticsearchOperation::ScanQuery,
                    Method::GET,
                    &format!("/{index}/_doc/endpoint"),
                    |request| request,
                )
                .await?;
            let source = &current["_source"];
            let expected_title = if position < 2 {
                "Camera"
            } else {
                "Updated camera"
            };
            if source["title"] != expected_title
                || source["tls_subject"] != "CN=camera"
                || source["http_body"] != "<title>Camera</title>"
            {
                return Err(format!("web evidence lost at step {position}: {source}"));
            }
            if position == 4 {
                if source["service_observed_at_ms"] != 1500 || source["observed_at_ms"] != 2500 {
                    return Err(format!("incorrect observation clocks: {source}"));
                }
                // Promotion must carry the successful-service timestamp, even
                // though a later failed probe set the endpoint timestamp.
                let mut body = String::new();
                append_projection_update(&mut body, &index, "promoted", source)?;
                let newer = endpoint_projection_document(&context, &success, 1750);
                append_projection_update(&mut body, &index, "promoted", &newer)?;
                let result = service.send_bulk_with_retry("/_bulk", &body, false).await?;
                if result["errors"] != false {
                    return Err(format!("promotion failed: {result}"));
                }
                let promoted = service
                    .send_json_request(
                        ElasticsearchOperation::ScanQuery,
                        Method::GET,
                        &format!("/{index}/_doc/promoted"),
                        |request| request,
                    )
                    .await?;
                if promoted["_source"]["title"] != "Camera"
                    || promoted["_source"]["service_observed_at_ms"] != 1750
                {
                    return Err(format!("promotion used endpoint clock: {promoted}"));
                }
            }
        }
        Ok::<(), String>(())
    }
    .await;
    let cleanup = service
        .send_json_request(
            ElasticsearchOperation::IndexAdmin,
            Method::DELETE,
            &format!("/{index}"),
            |request| request,
        )
        .await;
    test.unwrap();
    cleanup.unwrap();
}

async fn save_upload_fixture(
    pool: &Pool,
    service: &ElasticsearchService,
    upload: &crate::result_ingest::model::ScannerResultUpload,
) -> Result<usize, crate::result_ingest::model::SaveScannerResultsError> {
    crate::result_ingest::storage::save_scanner_results(
        pool,
        &crate::maxmind::MaxMindState::from_directory("/tmp/nm-es-no-maxmind"),
        service,
        &crate::dns_follow_up::DnsFollowUpConfig::default(),
        upload,
        "fixture-token",
        "fixture-pepper",
    )
    .await
}

pub(super) fn port_observation() -> crate::result_ingest::model::ScannerObservation {
    serde_json::from_value(json!({
        "kind": "port", "ip": "192.0.2.1", "port": 443,
        "protocol": "tcp", "state": "open", "source": "masscan",
        "observed_at": 1_788_883_200_000_i64
    }))
    .unwrap()
}

async fn seed_mixed_upload(pool: &Pool) -> crate::result_ingest::model::ScannerResultUpload {
    let mut upload = seed_dns_upload(pool).await;
    pool.get()
        .await
        .unwrap()
        .batch_execute("UPDATE scan_task SET scan_profile='dns_full' WHERE id=1")
        .await
        .unwrap();
    upload.protocol_version = 3;
    upload.observations.push(port_observation());
    upload
}

#[tokio::test]
async fn execution_summary_only_counts_total_on_first_composite_page() {
    let fixture = EsFixture::start();
    let service = fixture.service();
    {
        let mut state = fixture.state.lock().unwrap();
        for number in 0..1001 {
            state.documents.insert(
                (service.inner.config.execution_endpoint_index.clone(), number.to_string()),
                json!({"execution_id":"execution", "ip":format!("192.0.{}.{}", number / 256, number % 256), "port":443}),
            );
        }
    }
    let summary = service.execution_summary("execution", &[]).await.unwrap();
    assert_eq!(
        (
            summary.ip_count,
            summary.port_count,
            summary.observation_count
        ),
        (1001, 1001, 0)
    );
    let state = fixture.state.lock().unwrap();
    let queries = state
        .query_bodies
        .iter()
        .map(|(_, query)| query)
        .collect::<Vec<_>>();
    assert_eq!(queries.len(), 2);
    assert_eq!(queries[0]["track_total_hits"], true);
    assert_eq!(queries[1]["track_total_hits"], false);
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn many_month_final_is_bounded_and_recovers_from_later_chunk_failure() {
    for empty_final in [false, true] {
        for operation in ["_refresh", "_count"] {
            let (pool, schema) = isolated_pool().await;
            let fixture = EsFixture::start();
            fixture.state.lock().unwrap().max_request_line_bytes = Some(4096);
            let service = fixture.service();
            let mut upload = seed_dns_upload(&pool).await;
            pool.get()
                .await
                .unwrap()
                .batch_execute(
                    "UPDATE scan_task SET task_kind='ip',scan_profile='port_only' WHERE id=1",
                )
                .await
                .unwrap();
            upload.protocol_version = 3;
            let indices = (0..500)
                .map(|month| {
                    format!(
                        "{}-{}.{:02}",
                        service.inner.config.observation_index_prefix,
                        1970 + month / 12,
                        month % 12 + 1
                    )
                })
                .collect::<Vec<_>>();
            upload.observations = (0..500)
                .map(|month| {
                    let date = chrono::NaiveDate::from_ymd_opt(
                        1970 + month / 12,
                        (month % 12 + 1) as u32,
                        2,
                    )
                    .unwrap();
                    serde_json::from_value(json!({"kind":"port",
                        "ip":format!("192.0.{}.{}", month / 256, month % 256), "port":443,
                        "protocol":"tcp", "state":"open", "source":"masscan",
                        "observed_at":date.and_hms_opt(0,0,0).unwrap().and_utc().timestamp_millis(),
                    }))
                    .unwrap()
                })
                .collect();
            if empty_final {
                assert_eq!(
                    save_upload_fixture(&pool, &service, &upload).await.unwrap(),
                    500
                );
                upload.observations.clear();
                upload.batch_index = Some(1);
            }
            upload.is_final = Some(true);
            let mut targets = indices.iter().map(String::as_str).collect::<Vec<_>>();
            if operation == "_refresh" {
                targets.push(&service.inner.config.execution_endpoint_index);
            }
            let paths =
                bounded_scan_index_paths(&service.inner.config.url, &targets, operation).unwrap();
            assert!(paths.len() > 1);
            {
                let mut state = fixture.state.lock().unwrap();
                state.fail_path = Some(paths[1].clone());
                // Same execution in a different month must not enter the scoped count.
                state.documents.insert(
                    (
                        format!("{}-1969.12", service.inner.config.observation_index_prefix),
                        "unrelated-month".into(),
                    ),
                    json!({"execution_id":"execution"}),
                );
                // A different execution in a selected month must also be excluded.
                state.documents.insert(
                    (indices[0].clone(), "unrelated-execution".into()),
                    json!({"execution_id":"other"}),
                );
            }
            assert!(matches!(
                save_upload_fixture(&pool, &service, &upload).await,
                Err(crate::result_ingest::model::SaveScannerResultsError::Storage(_))
            ));
            let client = pool.get().await.unwrap();
            let status: String = client
                .query_one(
                    "SELECT execution_status FROM scan_task_execution WHERE id=1",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(status, "running");
            let pending: i64 = client
                .query_one(
                    "SELECT COUNT(*) FROM scan_result_batch WHERE storage_backend='pending'",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(pending, 1);
            let outbox: i64 = client
                .query_one("SELECT COUNT(*) FROM scan_projection_outbox", &[])
                .await
                .unwrap()
                .get(0);
            assert_eq!(outbox, 0);
            fixture.state.lock().unwrap().fail_path = None;
            let before = fixture.state.lock().unwrap().requests.len();
            assert_eq!(
                save_upload_fixture(&pool, &service, &upload).await.unwrap(),
                if empty_final { 0 } else { 500 }
            );
            assert_eq!(
                save_upload_fixture(&pool, &service, &upload).await.unwrap(),
                0
            );
            let counters = client.query_one("SELECT execution_status,result_ip_count,result_port_count,result_observation_count FROM scan_task_execution WHERE id=1", &[]).await.unwrap();
            assert_eq!(counters.get::<_, String>(0), "succeeded");
            for column in 1..=3 {
                assert_eq!(counters.get::<_, i64>(column), 500);
            }
            {
                let state = fixture.state.lock().unwrap();
                let final_requests = state.requests[before..]
                    .iter()
                    .filter(|request| request.contains("/_refresh") || request.contains("/_count"))
                    .collect::<Vec<_>>();
                assert!(final_requests.len() > 2);
                assert!(
                    final_requests
                        .iter()
                        .all(|request| request.len() + " HTTP/1.1".len()
                            <= SCAN_REQUEST_LINE_BUDGET
                            && !request.contains('*')
                            && !request.contains("1969.12"))
                );
                let refresh = final_requests
                    .iter()
                    .filter(|request| request.contains("/_refresh"))
                    .collect::<Vec<_>>();
                assert_eq!(
                    refresh
                        .iter()
                        .filter(|request| request
                            .contains(&service.inner.config.execution_endpoint_index))
                        .count(),
                    1
                );
            }
            client
                .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
                .await
                .unwrap();
        }
    }
}

#[tokio::test]
async fn execution_summary_rejects_invalid_partial_and_overflowed_chunk_counts() {
    for responses in [
        vec![json!({"count":-1})],
        vec![json!({})],
        vec![json!({"count":1,"_shards":{"failed":1}})],
        vec![json!({"count":i64::MAX}), json!({"count":1})],
    ] {
        let fixture = EsFixture::start();
        fixture.state.lock().unwrap().count_responses = responses.into();
        let service = fixture.service();
        assert!(
            service
                .execution_summary("execution", &["/a/_count".into(), "/b/_count".into()])
                .await
                .is_err()
        );
    }
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn empty_final_uses_all_execution_months_and_excludes_unrelated_history() {
    let (pool, schema) = isolated_pool().await;
    let fixture = EsFixture::start();
    let service = fixture.service();
    let mut upload = seed_dns_upload(&pool).await;
    pool.get()
        .await
        .unwrap()
        .batch_execute("UPDATE scan_task SET task_kind='ip', scan_profile='port_only' WHERE id=1")
        .await
        .unwrap();
    for (batch, observed_at) in [1767225600000_i64, 1769904000000_i64]
        .into_iter()
        .enumerate()
    {
        upload.batch_index = Some(batch as u32);
        upload.observations = vec![
            serde_json::from_value(json!({
                "kind":"port", "ip":format!("192.0.2.{}", batch + 1), "port":443,
                "protocol":"tcp", "state":"open", "source":"masscan", "observed_at":observed_at,
            }))
            .unwrap(),
        ];
        assert_eq!(
            save_upload_fixture(&pool, &service, &upload).await.unwrap(),
            1
        );
    }
    fixture.state.lock().unwrap().documents.insert(
        (
            format!("{}-2025.01", service.inner.config.observation_index_prefix),
            "unrelated".into(),
        ),
        json!({"execution_id":"unrelated"}),
    );
    upload.batch_index = Some(2);
    upload.is_final = Some(true);
    upload.observations.clear();
    save_upload_fixture(&pool, &service, &upload).await.unwrap();
    assert_eq!(
        save_upload_fixture(&pool, &service, &upload).await.unwrap(),
        0
    );
    let counters = pool.get().await.unwrap().query_one("SELECT result_ip_count,result_port_count,result_observation_count FROM scan_task_execution WHERE id=1", &[]).await.unwrap();
    assert_eq!(
        (
            counters.get::<_, i64>(0),
            counters.get::<_, i64>(1),
            counters.get::<_, i64>(2)
        ),
        (2, 2, 2)
    );
    {
        let state = fixture.state.lock().unwrap();
        let refresh = state
            .requests
            .iter()
            .find(|path| path.contains("/_refresh"))
            .unwrap();
        assert!(refresh.contains("2026.01") && refresh.contains("2026.02"));
        assert!(!refresh.contains('*') && !refresh.contains("2025.01"));
        let count = state
            .requests
            .iter()
            .find(|path| path.contains("/_count"))
            .unwrap();
        assert!(count.contains("2026.01") && count.contains("2026.02"));
        assert!(!count.contains('*'));
    }
    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn upload_stream_tracks_gaps_retries_deletions_and_final_boundary() {
    use crate::result_ingest::upload_stream;
    let (pool, schema) = isolated_pool().await;
    seed_execution(&pool).await;
    let mut client = pool.get().await.unwrap();
    client.batch_execute("INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count,storage_backend)
        VALUES(1,'upload',2,false,5,'elasticsearch'),(1,'upload',0,false,3,'pending');").await.unwrap();
    let tx = client.transaction().await.unwrap();
    assert!(
        upload_stream::validate_final(&tx, 1, "upload", 3, "scan result", false)
            .await
            .is_err()
    );
    tx.commit().await.unwrap();
    client.batch_execute("UPDATE scan_result_batch SET storage_backend='elasticsearch' WHERE batch_index=0;
        INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count,storage_backend)
        VALUES(1,'upload',1,false,4,'elasticsearch');").await.unwrap();
    let tx = client.transaction().await.unwrap();
    upload_stream::validate_final(&tx, 1, "upload", 3, "scan result", false)
        .await
        .unwrap();
    tx.execute("INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count,storage_backend) VALUES(1,'upload',3,true,0,'pending')",&[]).await.unwrap();
    assert!(
        upload_stream::ensure_open(&tx, 1, "upload", 4, "scan result")
            .await
            .is_err()
    );
    assert!(
        upload_stream::validate_final(&tx, 1, "upload", 3, "scan result", true)
            .await
            .is_err()
    );
    tx.execute(
        "UPDATE scan_result_batch SET storage_backend='elasticsearch' WHERE batch_index=3",
        &[],
    )
    .await
    .unwrap();
    tx.execute(
        "UPDATE scan_result_batch SET storage_backend='elasticsearch' WHERE batch_index=3",
        &[],
    )
    .await
    .unwrap();
    upload_stream::validate_final(&tx, 1, "upload", 3, "scan result", true)
        .await
        .unwrap();
    let state = upload_stream::load(&tx, 1, "upload")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.get::<_, i64>("confirmed_count"), 4);
    assert_eq!(state.get::<_, i64>("confirmed_observations"), 12);
    tx.execute("DELETE FROM scan_result_batch WHERE batch_index=1", &[])
        .await
        .unwrap();
    upload_stream::repair_deleted_receipts(&tx, 1)
        .await
        .unwrap();
    assert!(
        upload_stream::validate_final(&tx, 1, "upload", 3, "scan result", true)
            .await
            .is_err()
    );
    tx.commit().await.unwrap();
    client
        .execute("DELETE FROM scan_task_execution WHERE id=1", &[])
        .await
        .unwrap();
    assert_eq!(
        client
            .query_one("SELECT COUNT(*) FROM scan_upload_stream", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn upload_stream_migration_backfills_legacy_receipts_once_and_is_idempotent() {
    let (pool, schema) = isolated_pool().await;
    seed_execution(&pool).await;
    let client = pool.get().await.unwrap();
    client.batch_execute("DROP TRIGGER scan_upload_stream_receipt ON scan_result_batch;
        DROP TABLE scan_upload_stream; DELETE FROM scan_storage_state WHERE state_key='upload_stream_schema_v1';
        INSERT INTO scan_result_batch(execution_id,upload_id,batch_index,is_final,observation_count,storage_backend)
        VALUES(1,'legacy',0,false,3,'elasticsearch'),(1,'legacy',1,true,4,'pending');").await.unwrap();
    for _ in 0..2 {
        client
            .batch_execute(include_str!(
                "../source/database/migrate_scan_upload_stream.sql"
            ))
            .await
            .unwrap();
    }
    let state = client
        .query_one("SELECT * FROM scan_upload_stream", &[])
        .await
        .unwrap();
    assert_eq!(state.get::<_, i64>("batch_count"), 2);
    assert_eq!(state.get::<_, i64>("confirmed_count"), 1);
    assert_eq!(state.get::<_, i64>("pending_count"), 1);
    assert_eq!(state.get::<_, i64>("confirmed_observations"), 3);
    client
        .execute(
            "UPDATE scan_result_batch SET storage_backend='elasticsearch' WHERE batch_index=1",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        client
            .query_one("SELECT confirmed_observations FROM scan_upload_stream", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        7
    );
    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn mixed_upload_completes_and_retries_without_duplicate_observations() {
    let (pool, schema) = isolated_pool().await;
    let fixture = EsFixture::start();
    let service = fixture.service();
    let mut upload = seed_mixed_upload(&pool).await;
    upload.is_final = Some(true);
    assert_eq!(
        save_upload_fixture(&pool, &service, &upload).await.unwrap(),
        2
    );
    let documents = fixture.state.lock().unwrap().documents.len();
    assert_eq!(
        save_upload_fixture(&pool, &service, &upload).await.unwrap(),
        0
    );
    assert_eq!(fixture.state.lock().unwrap().documents.len(), documents);
    let client = pool.get().await.unwrap();
    let execution = client.query_one(
        "SELECT execution_status,result_ip_count,result_port_count,result_observation_count FROM scan_task_execution WHERE id=1", &[]
    ).await.unwrap();
    assert_eq!(execution.get::<_, String>(0), "succeeded");
    assert_eq!(execution.get::<_, i64>(1), 1);
    assert_eq!(execution.get::<_, i64>(2), 1);
    assert_eq!(execution.get::<_, i64>(3), 2);
    let receipt = client.query_one(
        "SELECT COUNT(*)::BIGINT, COUNT(*) FILTER (WHERE is_final)::BIGINT, COUNT(*) FILTER (WHERE storage_backend='pending')::BIGINT FROM scan_result_batch", &[]
    ).await.unwrap();
    assert_eq!(receipt.get::<_, i64>(0), 2);
    assert_eq!(receipt.get::<_, i64>(1), 1);
    assert_eq!(receipt.get::<_, i64>(2), 0);
    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn mixed_upload_keeps_dns_only_and_endpoint_only_batches_in_one_sequence() {
    for dns_last in [false, true] {
        let (pool, schema) = isolated_pool().await;
        let fixture = EsFixture::start();
        let service = fixture.service();
        let mut upload = seed_mixed_upload(&pool).await;
        let dns = upload.observations[0].clone();
        upload.observations = if dns_last {
            vec![port_observation()]
        } else {
            vec![dns.clone()]
        };
        assert_eq!(
            save_upload_fixture(&pool, &service, &upload).await.unwrap(),
            1
        );
        let status: String = pool
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT execution_status FROM scan_task_execution WHERE id=1",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(status, "running");
        upload.batch_index = Some(2);
        upload.is_final = Some(true);
        upload.observations = if dns_last {
            vec![dns]
        } else {
            vec![port_observation()]
        };
        assert!(matches!(
            save_upload_fixture(&pool, &service, &upload).await,
            Err(
                crate::result_ingest::model::SaveScannerResultsError::NonContiguousFinalBatch { .. }
            )
        ));
        upload.batch_index = Some(1);
        assert_eq!(
            save_upload_fixture(&pool, &service, &upload).await.unwrap(),
            1
        );
        let client = pool.get().await.unwrap();
        let row = client.query_one(
            "SELECT execution_status,result_observation_count FROM scan_task_execution WHERE id=1", &[]
        ).await.unwrap();
        assert_eq!(row.get::<_, String>(0), "succeeded");
        assert_eq!(row.get::<_, i64>(1), 2);
        client
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn mixed_upload_recovers_after_dns_commit_and_rejects_changed_payload_or_identity() {
    let (pool, schema) = isolated_pool().await;
    let fixture = EsFixture::start();
    let service = fixture.service();
    let mut upload = seed_mixed_upload(&pool).await;
    upload.is_final = Some(true);
    fixture.state.lock().unwrap().fail_path = Some("network-mapping-execution-endpoints".into());
    assert!(matches!(
        save_upload_fixture(&pool, &service, &upload).await,
        Err(crate::result_ingest::model::SaveScannerResultsError::Storage(_))
    ));
    let client = pool.get().await.unwrap();
    let receipts = client.query_one(
        "SELECT COUNT(*) FILTER (WHERE storage_backend='pending')::BIGINT, COUNT(*) FILTER (WHERE storage_backend='elasticsearch')::BIGINT FROM scan_result_batch", &[]
    ).await.unwrap();
    assert_eq!(receipts.get::<_, i64>(0), 1);
    assert_eq!(receipts.get::<_, i64>(1), 1);
    assert_eq!(
        client
            .query_one(
                "SELECT execution_status FROM scan_task_execution WHERE id=1",
                &[]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "running"
    );
    let documents = fixture.state.lock().unwrap().documents.len();
    let mut changed = upload.clone();
    changed.observations.remove(0);
    assert!(matches!(
        save_upload_fixture(&pool, &service, &changed).await,
        Err(crate::result_ingest::model::SaveScannerResultsError::BatchPayloadConflict { .. })
    ));
    changed = upload.clone();
    if let crate::result_ingest::model::ScannerObservation::Dns { observation } =
        &mut changed.observations[0]
    {
        observation.question.name = "changed.example.com".into();
    }
    assert!(matches!(
        save_upload_fixture(&pool, &service, &changed).await,
        Err(crate::result_ingest::model::SaveScannerResultsError::BatchPayloadConflict { .. })
    ));
    changed = upload.clone();
    changed.upload_id = Some(Uuid::new_v4());
    assert!(matches!(
        save_upload_fixture(&pool, &service, &changed).await,
        Err(crate::result_ingest::model::SaveScannerResultsError::UploadIdentityConflict { .. })
    ));
    assert_eq!(fixture.state.lock().unwrap().documents.len(), documents);
    fixture.state.lock().unwrap().fail_path = None;
    assert_eq!(
        save_upload_fixture(&pool, &service, &upload).await.unwrap(),
        2
    );
    assert_eq!(
        save_upload_fixture(&pool, &service, &upload).await.unwrap(),
        0
    );
    assert_eq!(
        fixture
            .state
            .lock()
            .unwrap()
            .documents
            .keys()
            .filter(|(index, _)| index.starts_with(".ds-dns-"))
            .count(),
        1
    );
    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn mixed_upload_resumes_dns_sidecar_left_by_previous_server() {
    let (pool, schema) = isolated_pool().await;
    let fixture = EsFixture::start();
    let service = fixture.service();
    let mut upload = seed_mixed_upload(&pool).await;
    let mut sidecar = upload.clone();
    sidecar.upload_id = upload
        .upload_id
        .map(crate::result_ingest::storage::dns_sidecar_upload_id);
    sidecar.observations.truncate(1);
    crate::result_ingest::dns::save_dns_scanner_results(
        &pool,
        &service,
        &crate::dns_follow_up::DnsFollowUpConfig::default(),
        &sidecar,
        "fixture-token",
        "fixture-pepper",
        upload.upload_id,
    )
    .await
    .unwrap();
    let mut changed = upload.clone();
    changed.observations.remove(0);
    assert!(matches!(
        save_upload_fixture(&pool, &service, &changed).await,
        Err(crate::result_ingest::model::SaveScannerResultsError::BatchPayloadConflict { .. })
    ));
    changed = upload.clone();
    if let crate::result_ingest::model::ScannerObservation::Dns { observation } =
        &mut changed.observations[0]
    {
        observation.question.name = "changed.example.com".into();
    }
    assert!(matches!(
        save_upload_fixture(&pool, &service, &changed).await,
        Err(crate::result_ingest::model::SaveScannerResultsError::BatchPayloadConflict { .. })
    ));
    assert_eq!(
        pool.get()
            .await
            .unwrap()
            .query_one("SELECT COUNT(*)::BIGINT FROM scan_result_batch", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    upload.is_final = Some(true);
    assert_eq!(
        save_upload_fixture(&pool, &service, &upload).await.unwrap(),
        2
    );
    assert_eq!(
        fixture
            .state
            .lock()
            .unwrap()
            .documents
            .keys()
            .filter(|(index, _)| index.starts_with(".ds-dns-"))
            .count(),
        1
    );
    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn mixed_upload_dns_only_results_and_empty_final_preserve_task_completion() {
    for profile in ["dns_records", "dns_full"] {
        let (pool, schema) = isolated_pool().await;
        let fixture = EsFixture::start();
        let service = fixture.service();
        let mut upload = seed_dns_upload(&pool).await;
        let client = pool.get().await.unwrap();
        client
            .execute(
                "UPDATE scan_task SET scan_profile=$1 WHERE id=1",
                &[&profile],
            )
            .await
            .unwrap();
        assert_eq!(
            save_upload_fixture(&pool, &service, &upload).await.unwrap(),
            1
        );
        let mut unrelated = upload.clone();
        unrelated.upload_id = Some(Uuid::new_v4());
        assert!(matches!(
            save_upload_fixture(&pool, &service, &unrelated).await,
            Err(
                crate::result_ingest::model::SaveScannerResultsError::UploadIdentityConflict { .. }
            )
        ));
        upload.batch_index = Some(1);
        upload.is_final = Some(true);
        upload.observations.clear();
        assert_eq!(
            save_upload_fixture(&pool, &service, &upload).await.unwrap(),
            0
        );
        assert_eq!(
            save_upload_fixture(&pool, &service, &upload).await.unwrap(),
            0
        );
        let row = client.query_one(
            "SELECT execution_status,result_ip_count,result_port_count,result_observation_count FROM scan_task_execution WHERE id=1", &[]
        ).await.unwrap();
        assert_eq!(row.get::<_, String>(0), "succeeded", "{profile}");
        assert_eq!(row.get::<_, i64>(1), 0, "{profile}");
        assert_eq!(row.get::<_, i64>(2), 0, "{profile}");
        assert_eq!(row.get::<_, i64>(3), 1, "{profile}");
        client
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and local HTTP sockets"]
async fn mixed_upload_cannot_finish_with_an_unmatched_dns_child() {
    let (pool, schema) = isolated_pool().await;
    let fixture = EsFixture::start();
    let service = fixture.service();
    let mut upload = seed_mixed_upload(&pool).await;
    let mut child = upload.clone();
    child.upload_id = upload
        .upload_id
        .map(crate::result_ingest::storage::dns_sidecar_upload_id);
    child.batch_index = Some(1);
    child.observations.truncate(1);
    crate::result_ingest::dns::save_dns_scanner_results(
        &pool,
        &service,
        &crate::dns_follow_up::DnsFollowUpConfig::default(),
        &child,
        "fixture-token",
        "fixture-pepper",
        upload.upload_id,
    )
    .await
    .unwrap();
    upload.observations.remove(0);
    upload.is_final = Some(true);
    assert!(matches!(
        save_upload_fixture(&pool, &service, &upload).await,
        Err(crate::result_ingest::model::SaveScannerResultsError::InvalidUpload(_))
    ));
    let client = pool.get().await.unwrap();
    assert_eq!(
        client
            .query_one(
                "SELECT execution_status FROM scan_task_execution WHERE id=1",
                &[]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "running"
    );
    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL"]
async fn recovery_failure_reports_are_idempotent_and_stop_after_three_failures() {
    let (pool, schema) = isolated_pool().await;
    let scanner = Uuid::now_v7();
    let task = Uuid::now_v7();
    let hash = crate::identity::hash_scanner_token("fixture-token", "fixture-pepper").unwrap();
    let client = pool.get().await.unwrap();
    client
        .batch_execute("INSERT INTO users(id,username,password) VALUES(1,'fixture','unused')")
        .await
        .unwrap();
    client.execute("INSERT INTO scanner_info(scanner_id,create_user,runtime_token_hash,is_enable) VALUES($1,1,$2,true)",&[&scanner.to_string(),&hash]).await.unwrap();
    client.execute("INSERT INTO scan_task(id,user_id,task_id,task_initiator,task_target,task_status) VALUES(1,1,$1,'fixture',ARRAY['192.0.2.1'::inet],'running')",&[&task.to_string()]).await.unwrap();
    client.execute("INSERT INTO scan_task_execution(id,execution_id,task_id,assigned_scanner_id,execution_status,attempt_count,lease_expires_at) VALUES(1,'execution',1,$1,'running',1,1)",&[&scanner.to_string()]).await.unwrap();
    drop(client);
    for count in [1, 1, 2, 2] {
        let recovered = crate::scan_control::dispatch::recover_scanner_task_with_failure(
            &pool,
            scanner,
            None,
            None,
            Some(crate::scan_control::dispatch::RecoveryFailureReport {
                task_id: task,
                count,
            }),
            "fixture-token",
            "fixture-pepper",
        )
        .await
        .unwrap();
        assert_eq!(recovered.task_id, task);
        let row = pool.get().await.unwrap().query_one("SELECT recovery_failure_count,execution_status FROM scan_task_execution WHERE id=1",&[]).await.unwrap();
        assert_eq!(row.get::<_, i32>(0), count as i32);
        assert_eq!(row.get::<_, String>(1), "running");
    }
    let outcome = crate::scan_control::dispatch::recover_scanner_task_with_failure(
        &pool,
        scanner,
        None,
        None,
        Some(crate::scan_control::dispatch::RecoveryFailureReport {
            task_id: task,
            count: 3,
        }),
        "fixture-token",
        "fixture-pepper",
    )
    .await;
    assert!(matches!(
        outcome,
        Err(crate::scan_control::dispatch::ApplyTaskError::NoTask)
    ));
    let client = pool.get().await.unwrap();
    let row = client.query_one("SELECT recovery_failure_count,execution_status,lease_expires_at FROM scan_task_execution WHERE id=1",&[]).await.unwrap();
    assert_eq!(row.get::<_, i32>(0), 3);
    assert_eq!(row.get::<_, String>(1), "failed");
    assert!(row.get::<_, Option<i64>>(2).is_none());
    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
async fn startup_checks_version_before_index_writes_and_reports_actual_version() {
    // initialize does not acquire a PG connection; keep this protocol test independent of PG.
    let manager =
        deadpool_postgres::Manager::new(tokio_postgres::Config::new(), tokio_postgres::NoTls);
    let pool = Pool::builder(manager).max_size(1).build().unwrap();
    for (policy, version, accepted) in [
        ("9.5.x", "9.5.0", true),
        ("9.5.x", "9.5.2", true),
        ("9.5.x", "9.5.3", true),
        ("9.5.x", "9.5.123", true),
        ("9.5.3", "9.5.3", true),
        ("9.5.3", "9.5.2", true),
        ("9.5.3", "9.5.4", true),
        ("9.5.3", "9.6.0", false),
        ("9.5.3", "9.5.4-SNAPSHOT", false),
        ("9.5.x", "9.4.9", false),
        ("9.5.x", "9.6.0", false),
        ("9.5.x", "10.0.0", false),
        ("9.5.x", "9.5.3-SNAPSHOT", false),
        ("9.5.x", "invalid", false),
    ] {
        let fixture = EsFixture::start();
        fixture.state.lock().unwrap().server_version = Some(version.to_owned());
        let service = ElasticsearchService::new(ElasticsearchConfig {
            url: fixture.url.clone(),
            expected_version: policy.to_owned(),
            ..Default::default()
        })
        .unwrap();
        let result = service.initialize(&pool).await;
        let runtime = service.inner.runtime.read().unwrap();
        let state = fixture.state.lock().unwrap();
        if accepted {
            assert!(result.is_ok(), "{policy}: {version}: {result:?}");
            assert!(runtime.connected && runtime.read_ready);
            assert_eq!(runtime.server_version.as_deref(), Some(version));
            assert!(
                state
                    .requests
                    .iter()
                    .any(|request| request.starts_with("PUT "))
            );
        } else {
            let error = result.unwrap_err();
            assert!(error.contains(policy) && error.contains(version), "{error}");
            assert_eq!(state.requests, ["GET /"]);
            assert!(!runtime.connected && !runtime.read_ready);
        }
    }
}
