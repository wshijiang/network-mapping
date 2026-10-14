//! Opt-in write-path benchmark against disposable PG and an explicit local ES URL.
//! No network scanning or production configuration is used.
use super::storage_tests::isolated_pool_with_size;
use super::*;
use crate::result_ingest::{ScannerResultUpload, save_scanner_results};
use std::sync::Mutex;
use tracing::field::{Field, Visit};
use tracing_subscriber::{Layer, layer::SubscriberExt};

#[derive(Clone, Default)]
struct Timings(
    Arc<Mutex<BTreeMap<String, Vec<f64>>>>,
    Arc<Mutex<Vec<Value>>>,
);

#[derive(Default)]
struct Fields {
    strings: BTreeMap<String, String>,
    numbers: BTreeMap<String, u64>,
}
impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.strings.insert(field.name().into(), value.into());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.numbers.insert(field.name().into(), value);
    }
    fn record_debug(&mut self, _: &Field, _: &dyn std::fmt::Debug) {}
}
impl<S: tracing::Subscriber> Layer<S> for Timings {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let Some(name) = fields.strings.get("event") else {
            return;
        };
        if name == "ScanFinalRequestPlan" {
            self.1.lock().unwrap().push(json!(fields.numbers));
            return;
        }
        let mut samples = self.0.lock().unwrap();
        if name == "ScanWriteStageCompleted" {
            if let (Some(stage), Some(us)) = (
                fields.strings.get("stage"),
                fields.numbers.get("duration_us"),
            ) {
                samples
                    .entry(stage.clone())
                    .or_default()
                    .push(*us as f64 / 1000.0);
            }
        } else {
            for key in [
                "wait_ms",
                "hold_ms",
                "queue_wait_ms",
                "request_ms",
                "backoff_ms",
            ] {
                if let Some(ms) = fields.numbers.get(key) {
                    samples
                        .entry(format!("{name}.{key}"))
                        .or_default()
                        .push(*ms as f64);
                }
            }
        }
    }
}

fn percentiles(mut samples: Vec<f64>) -> Value {
    samples.sort_by(f64::total_cmp);
    let percentile = |p: usize| {
        if samples.is_empty() {
            0.0
        } else {
            samples[(samples.len() * p).div_ceil(100).saturating_sub(1)]
        }
    };
    json!({"samples":samples.len(), "p50_ms":percentile(50), "p95_ms":percentile(95),
        "p99_ms":percentile(99), "max_ms":samples.last().copied().unwrap_or_default()})
}

async fn es_stats(service: &ElasticsearchService) -> Value {
    service.send_json_request(ElasticsearchOperation::IndexAdmin, Method::GET,
        "/_nodes/stats/indices,jvm,process?filter_path=nodes.*.indices.indexing,nodes.*.indices.refresh,nodes.*.indices.merges,nodes.*.jvm.mem,nodes.*.jvm.gc,nodes.*.process.cpu", |r| r)
        .await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires disposable STORAGE_TEST_DATABASE_URL and explicit SCAN_STRESS_ES_URL; writes up to one million observations"]
async fn scan_write_large_data_stress() {
    let es_url =
        std::env::var("SCAN_STRESS_ES_URL").expect("explicit disposable Elasticsearch URL");
    let counts = std::env::var("SCAN_STRESS_COUNTS")
        .unwrap_or_else(|_| "10000,100000,1000000".into())
        .split(',')
        .map(|v| v.parse::<usize>().unwrap())
        .collect::<Vec<_>>();
    let concurrency = std::env::var("SCAN_STRESS_CONCURRENCY")
        .unwrap_or_else(|_| "4".into())
        .parse::<usize>()
        .unwrap();
    let months = std::env::var("SCAN_STRESS_MONTHS")
        .unwrap_or_else(|_| "3".into())
        .parse::<usize>()
        .unwrap();
    let prefix_padding = std::env::var("SCAN_STRESS_PREFIX_PADDING")
        .unwrap_or_else(|_| "0".into())
        .parse::<usize>()
        .unwrap();
    let empty_final = std::env::var("SCAN_STRESS_EMPTY_FINAL").is_ok_and(|v| v == "true");
    assert!((1..=500).contains(&months) && prefix_padding <= 150);
    assert!(
        (1..=16).contains(&concurrency)
            && counts.iter().all(|n| *n >= concurrency && *n <= 1_000_000)
    );
    let timings = Timings::default();
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(timings.clone()))
        .unwrap();
    let (pool, schema) = isolated_pool_with_size(concurrency + 2).await;
    let prefix = format!("nm-stress-{}", Uuid::new_v4().simple());
    let service = ElasticsearchService::new(ElasticsearchConfig {
        url: es_url,
        observation_index_prefix: format!("{prefix}-observations{}", "x".repeat(prefix_padding)),
        execution_endpoint_index: format!("{prefix}-execution"),
        current_endpoint_index: format!("{prefix}-current"),
        scan_number_of_replicas: 0,
        bulk_max_concurrency: 4,
        ..ElasticsearchConfig::default()
    })
    .unwrap();
    service.ensure_scan_indices().await.unwrap();
    let month_indices = (0..months)
        .map(|month| {
            let (year, month) = if months == 3 {
                (2026, month + 1)
            } else {
                (1970 + month / 12, month % 12 + 1)
            };
            format!(
                "{}-{year}.{month:02}",
                service.inner.config.observation_index_prefix
            )
        })
        .collect::<Vec<_>>();
    let unchunked_path = format!("/{}/_count?{SCAN_INDEX_OPTIONS}", month_indices.join(","));
    let unchunked_request_line_bytes =
        scan_request_line_length(&service.inner.config.url, &unchunked_path).unwrap();
    let unchunked_request_rejected = if unchunked_request_line_bytes > 4096 {
        let error = service
            .send_json_request(
                ElasticsearchOperation::ExecutionSummary,
                Method::POST,
                &unchunked_path,
                |r| r.json(&json!({"query":{"match_all":{}}})),
            )
            .await
            .unwrap_err();
        assert!(
            error.contains("too_long") || error.contains("An HTTP line is larger"),
            "{error}"
        );
        true
    } else {
        false
    };
    // Twelve irrelevant historical indices expose wildcard refresh fan-out.
    for month in 1..=12 {
        service
            .send_json_request(
                ElasticsearchOperation::IndexAdmin,
                Method::PUT,
                &format!(
                    "/{}-2024.{month:02}",
                    service.inner.config.observation_index_prefix
                ),
                |r| r.json(&json!({})),
            )
            .await
            .unwrap();
    }
    let scanner_id = Uuid::new_v4();
    let token = "stress-test-token";
    let pepper = "stress-test-pepper";
    let token_hash = crate::identity::hash_scanner_token(token, pepper).unwrap();
    let client = pool.get().await.unwrap();
    client
        .batch_execute(
            "INSERT INTO users(id,username,password) VALUES(1,'stress','unused');
        INSERT INTO search_target_state(owner_id,target_kind,target_key)
        SELECT 1,'ip',host('10.0.0.0'::inet+n) FROM generate_series(1,100000) n;",
        )
        .await
        .unwrap();
    client.execute("INSERT INTO scanner_info(scanner_id,create_user,runtime_token_hash,is_enable) VALUES($1,1,$2,true)", &[&scanner_id.to_string(), &token_hash]).await.unwrap();
    client
        .batch_execute("ANALYZE search_target_state")
        .await
        .unwrap();
    drop(client);
    let mut results = Vec::new();
    for total in counts {
        let mut jobs = Vec::new();
        for worker in 0..concurrency {
            let task_id = Uuid::new_v4();
            let execution_id = Uuid::new_v4();
            let client = pool.get().await.unwrap();
            let task_pk: i32 = client
                .query_one(
                    "INSERT INTO scan_task(user_id,task_id,task_initiator,task_target,scan_profile)
                VALUES(1,$1,'stress',ARRAY['198.18.0.0/15'::inet],'port_only') RETURNING id",
                    &[&task_id.to_string()],
                )
                .await
                .unwrap()
                .get(0);
            let execution_pk: i32 = client.query_one("INSERT INTO scan_task_execution(execution_id,task_id,assigned_scanner_id,execution_status,task_start_time)
                VALUES($1,$2,$3,'running',$4) RETURNING id", &[&execution_id.to_string(), &task_pk, &scanner_id.to_string(), &crate::clock::get_unix_epoch_ms()]).await.unwrap().get(0);
            let start = total * worker / concurrency;
            let end = total * (worker + 1) / concurrency;
            jobs.push((task_id, execution_pk, start, end));
        }
        timings.0.lock().unwrap().clear();
        timings.1.lock().unwrap().clear();
        let resources_before = es_stats(&service).await;
        let started = Instant::now();
        let mut tasks = Vec::new();
        for (task_id, execution_pk, start, end) in jobs {
            let pool = pool.clone();
            let service = service.clone();
            tasks.push(tokio::spawn(async move {
                let upload_id = Uuid::new_v4();
                let maxmind = crate::maxmind::MaxMindState::from_directory("/tmp/nm-stress-no-maxmind");
                let follow_up = crate::dns_follow_up::DnsFollowUpConfig::default();
                let mut normal_ms = Vec::new();
                let mut final_ms = Vec::new();
                let mut saved = 0;
                let mut errors = Vec::new();
                let mut last_upload = None;
                for (batch, offset) in (start..end).step_by(500).enumerate() {
                    let limit = (offset+500).min(end);
                    let observations = (offset..limit).map(|ordinal| {
                        let ip = ordinal / 10;
                        serde_json::from_value(json!({"kind":"port", "ip":format!("198.{}.{}.{}",18+ip/65536,(ip/256)%256,ip%256),
                            "port":443+ordinal%10, "protocol":"tcp", "state":"open", "source":"masscan",
                            "observed_at": if months == 3 {1767225600000_i64+(ordinal%3) as i64*31*86400000} else {
                                let month = ordinal % months;
                                chrono::NaiveDate::from_ymd_opt(1970 + (month / 12) as i32, (month % 12 + 1) as u32, 2)
                                    .unwrap().and_hms_opt(0,0,0).unwrap().and_utc().timestamp_millis()
                            },
                        })).unwrap()
                    }).collect();
                    let upload = ScannerResultUpload { protocol_version:3, scanner_id, task_id, upload_id:Some(upload_id),
                        batch_index:Some(batch as u32), is_final:Some(limit==end && !empty_final), observations, results:Vec::new() };
                    let tick = Instant::now();
                    let result = save_scanner_results(&pool,&maxmind,&service,&follow_up,&upload,token,pepper).await;
                    let ms = tick.elapsed().as_secs_f64()*1000.0;
                    if limit==end && !empty_final { final_ms.push(ms); } else { normal_ms.push(ms); }
                    match result { Ok(n)=>saved+=n, Err(e)=>{errors.push(e.to_string()); break;} }
                    last_upload=Some(upload);
                }
                let mut retry_ms = 0.0;
                if errors.is_empty() && empty_final {
                        let upload = last_upload.as_mut().unwrap();
                        upload.batch_index = Some(upload.batch_index.unwrap() + 1);
                        upload.is_final = Some(true);
                        upload.observations.clear();
                        let tick = Instant::now();
                        match save_scanner_results(&pool,&maxmind,&service,&follow_up,upload,token,pepper).await {
                            Ok(n) => { assert_eq!(n, 0); },
                            Err(e) => errors.push(e.to_string()),
                        }
                        final_ms.push(tick.elapsed().as_secs_f64()*1000.0);
                }
                if errors.is_empty() {
                    let tick=Instant::now();
                    let repeated=save_scanner_results(&pool,&maxmind,&service,&follow_up,last_upload.as_ref().unwrap(),token,pepper).await;
                    retry_ms=tick.elapsed().as_secs_f64()*1000.0;
                    assert_eq!(repeated.unwrap(),0);
                    let row=pool.get().await.unwrap().query_one("SELECT execution_status,result_port_count,result_observation_count,result_ip_count FROM scan_task_execution WHERE id=$1",&[&execution_pk]).await.unwrap();
                    assert_eq!(row.get::<_,String>(0),"succeeded");
                    assert_eq!(row.get::<_,i64>(1),(end-start) as i64);
                    assert_eq!(row.get::<_,i64>(2),(end-start) as i64);
                    assert_eq!(row.get::<_,i64>(3), ((end-1)/10-start/10+1) as i64);
                }
                (saved, normal_ms, final_ms, retry_ms, errors)
            }));
        }
        let mut saved = 0;
        let mut normal = Vec::new();
        let mut finals = Vec::new();
        let mut retries = Vec::new();
        let mut errors = Vec::new();
        for task in tasks {
            let (n, ordinary, final_ms, retry, failures) = task.await.unwrap();
            saved += n;
            normal.extend(ordinary);
            finals.extend(final_ms);
            retries.push(retry);
            errors.extend(failures);
        }
        let elapsed = started.elapsed().as_secs_f64();
        let stages = timings
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|(key, values)| (key.clone(), percentiles(values.clone())))
            .collect::<BTreeMap<_, _>>();
        let final_request_plans = timings.1.lock().unwrap().clone();
        if errors.is_empty() {
            assert_eq!(final_request_plans.len(), concurrency);
            for plan in &final_request_plans {
                assert!(
                    plan["max_request_line_bytes"].as_u64().unwrap()
                        <= SCAN_REQUEST_LINE_BUDGET as u64
                );
                if unchunked_request_line_bytes <= SCAN_REQUEST_LINE_BUDGET {
                    assert_eq!(plan["refresh_requests"], 1);
                    assert_eq!(plan["count_requests"], 1);
                } else {
                    assert!(plan["count_requests"].as_u64().unwrap() > 1);
                }
            }
        }
        let resources_after = es_stats(&service).await;
        let result = json!({"observations":total, "saved":saved, "concurrency":concurrency,
            "elapsed_seconds":elapsed,"observations_per_second":saved as f64/elapsed,
            "ordinary_batch":percentiles(normal),"final_batch":percentiles(finals),"duplicate_final":percentiles(retries),
            "errors":errors,"stages":stages,"final_request_plans":final_request_plans,
            "es_before":resources_before,"es_after":resources_after});
        println!("SCAN_STRESS_RESULT={result}");
        results.push(result);
    }
    if let Ok(path) = std::env::var("SCAN_STRESS_OUTPUT") {
        std::fs::write(
            path,
            serde_json::to_vec_pretty(
                &json!({"schema":schema,"index_prefix":prefix,"batch_size":500,
            "background_workers":false,"historical_indices":12,"unrelated_search_targets":100000,
            "observation_months":months,"prefix_padding":prefix_padding,"empty_final":empty_final,
            "unchunked_request_line_bytes":unchunked_request_line_bytes,
            "unchunked_request_rejected":unchunked_request_rejected,
            "results":results}),
            )
            .unwrap(),
        )
        .unwrap();
    }
    pool.get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
    // ES rejects wildcard deletes by default. Resolve only this run's names.
    let resolved = service
        .send_json_request(
            ElasticsearchOperation::IndexAdmin,
            Method::GET,
            &format!("/_resolve/index/{prefix}-*"),
            |r| r,
        )
        .await
        .unwrap();
    let indices = resolved["indices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|index| index["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(
        indices
            .iter()
            .all(|name| name.starts_with(&format!("{prefix}-")))
    );
    for chunk in indices.chunks(10) {
        service
            .send_json_request(
                ElasticsearchOperation::IndexAdmin,
                Method::DELETE,
                &format!("/{}", chunk.join(",")),
                |r| r,
            )
            .await
            .unwrap();
    }
    service
        .send_json_request(
            ElasticsearchOperation::IndexAdmin,
            Method::DELETE,
            &format!(
                "/_index_template/{}-template",
                service.inner.config.observation_index_prefix
            ),
            |r| r,
        )
        .await
        .unwrap();
    assert!(
        results
            .iter()
            .all(|r| r["errors"].as_array().unwrap().is_empty() && r["saved"] == r["observations"])
    );
}
