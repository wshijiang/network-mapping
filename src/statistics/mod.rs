//! Bounded, shared admission and result caching for interactive statistics.
use actix_web::web::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{Semaphore, watch};
use tracing::Instrument;

pub const NAMESPACE: &str = "statistics_cache";
pub const CONCURRENCY: usize = 2;
pub const QUEUE: usize = 8;
pub const QUERY_SECONDS: u64 = 15;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheConfig {
    pub enabled: bool,
    pub realtime_ttl_seconds: u64,
    pub history_ttl_seconds: u64,
    pub snapshot_ttl_seconds: u64,
    pub max_entries: usize,
    pub max_size_mib: usize,
    pub max_entry_kib: usize,
}
impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            realtime_ttl_seconds: 30,
            history_ttl_seconds: 30,
            snapshot_ttl_seconds: 60,
            max_entries: 256,
            max_size_mib: 32,
            max_entry_kib: 2048,
        }
    }
}
impl CacheConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(5..=300).contains(&self.realtime_ttl_seconds)
            || !(5..=300).contains(&self.history_ttl_seconds)
            || !(10..=900).contains(&self.snapshot_ttl_seconds)
            || !(16..=4096).contains(&self.max_entries)
            || !(8..=256).contains(&self.max_size_mib)
            || !(256..=8192).contains(&self.max_entry_kib)
            || self.max_entry_kib > self.max_size_mib * 1024
        {
            return Err("缓存配置超出允许范围，且单条容量不能超过总容量".into());
        }
        Ok(())
    }
    fn ttl(&self, mode: &str) -> Duration {
        Duration::from_secs(match mode {
            "snapshot" => self.snapshot_ttl_seconds,
            "realtime" => self.realtime_ttl_seconds,
            _ => self.history_ttl_seconds,
        })
    }
}
pub fn parse_config(value: Value) -> Result<CacheConfig, String> {
    let config: CacheConfig = serde_json::from_value(value).map_err(|e| e.to_string())?;
    config.validate()?;
    Ok(config)
}

#[derive(Clone, Debug)]
pub struct Failure(pub &'static str, pub &'static str);
impl Failure {
    pub fn busy() -> Self {
        Self("statistics_busy", "统计服务繁忙，请稍后重试")
    }
    pub fn timeout() -> Self {
        Self("statistics_timeout", "统计查询超时，请缩小时间范围")
    }
}
pub type Outcome = Result<Bytes, Failure>;

/// A session-scoped cluster slot. On any exceptional exit, detach and close the
/// connection rather than returning a session carrying advisory locks to the pool.
pub struct ClusterSlot {
    client: Option<deadpool_postgres::Client>,
    slot: i32,
}
impl ClusterSlot {
    pub fn client(&mut self) -> Result<&mut deadpool_postgres::Client, Failure> {
        self.client.as_mut().ok_or_else(Failure::busy)
    }
    pub async fn acquire(pool: &deadpool_postgres::Pool) -> Result<Self, Failure> {
        let client = tokio::time::timeout(Duration::from_secs(2), pool.get())
            .await
            .map_err(|_| {
                tracing::warn!(
                    event = "StatisticsAdmissionRejected",
                    reason = "pool_timeout"
                );
                Failure::busy()
            })?
            .map_err(|_| {
                tracing::warn!(
                    event = "StatisticsAdmissionRejected",
                    reason = "pool_unavailable"
                );
                Failure::busy()
            })?;
        let mut guard = Self {
            client: Some(client),
            slot: 0,
        };
        let client = guard.client.as_ref().ok_or_else(Failure::busy)?;
        for slot in 0..CONCURRENCY as i32 {
            let row = client
                .query_one("SELECT pg_try_advisory_lock(1313686356,$1)", &[&slot])
                .await
                .map_err(|_| {
                    tracing::warn!(
                        event = "StatisticsAdmissionRejected",
                        reason = "cluster_lock_error"
                    );
                    Failure::busy()
                })?;
            if row.get::<_, bool>(0) {
                guard.slot = slot;
                return Ok(guard);
            }
        }
        // No session lock was acquired; this connection can be recycled.
        guard.client.take();
        tracing::warn!(
            event = "StatisticsAdmissionRejected",
            reason = "cluster_slots_full",
            limit = CONCURRENCY
        );
        Err(Failure::busy())
    }
    pub async fn release(mut self) -> Result<(), Failure> {
        if let Some(client) = &self.client {
            let row = client
                .query_one("SELECT pg_advisory_unlock(1313686356,$1)", &[&self.slot])
                .await
                .map_err(|_| Failure("statistics_failed", "统计额度清理失败"))?;
            if !row.get::<_, bool>(0) {
                return Err(Failure("statistics_failed", "统计额度状态无效"));
            }
        }
        self.client.take();
        Ok(())
    }
}
impl Drop for ClusterSlot {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            drop(deadpool_postgres::Client::take(client));
        }
    }
}
struct Entry {
    body: Bytes,
    mode: String,
    created: Instant,
    accessed: u64,
}
struct Flight {
    sender: watch::Sender<Option<Outcome>>,
    user: i32,
}
struct State {
    config: CacheConfig,
    revision: i64,
    generation: u64,
    entries: HashMap<String, Entry>,
    flights: HashMap<String, Flight>,
    rate: HashMap<i32, (Instant, u32)>,
    bytes: usize,
    hits: u64,
    misses: u64,
    joined: u64,
    rejected: u64,
    evictions: u64,
    clock: u64,
    last_cleared_at: Option<String>,
}
#[derive(Clone)]
pub struct StatisticsService {
    state: Arc<Mutex<State>>,
    permits: Arc<Semaphore>,
    instance_id: String,
}
impl Default for StatisticsService {
    fn default() -> Self {
        Self::new()
    }
}
impl StatisticsService {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                config: CacheConfig::default(),
                revision: 0,
                generation: 0,
                entries: HashMap::new(),
                flights: HashMap::new(),
                rate: HashMap::new(),
                bytes: 0,
                hits: 0,
                misses: 0,
                joined: 0,
                rejected: 0,
                evictions: 0,
                clock: 0,
                last_cleared_at: None,
            })),
            permits: Arc::new(Semaphore::new(CONCURRENCY)),
            instance_id: uuid::Uuid::now_v7().to_string(),
        }
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn apply(&self, config: CacheConfig, revision: i64) {
        let mut s = self.lock();
        if revision <= s.revision {
            return;
        }
        // Every published revision invalidates entries, including instances that missed
        // intermediate revisions. Publishing an unchanged document clears the cluster.
        s.config = config;
        s.revision = revision;
        s.generation += 1;
        s.entries.clear();
        s.bytes = 0;
        s.last_cleared_at = Some(chrono::Utc::now().to_rfc3339());
        Self::prune(&mut s);
    }
    fn prune(s: &mut State) {
        let now = Instant::now();
        let before = s.entries.len();
        s.entries.retain(|_, e| {
            s.config.enabled
                && now.duration_since(e.created) < s.config.ttl(&e.mode)
                && e.body.len() <= s.config.max_entry_kib * 1024
        });
        s.evictions += (before - s.entries.len()) as u64;
        s.bytes = s.entries.values().map(|e| e.body.len()).sum();
        while s.entries.len() > s.config.max_entries
            || s.bytes > s.config.max_size_mib * 1024 * 1024
        {
            let Some(key) = s
                .entries
                .iter()
                .min_by_key(|(_, e)| e.accessed)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            if let Some(entry) = s.entries.remove(&key) {
                s.bytes -= entry.body.len();
                s.evictions += 1;
            }
        }
    }
    pub async fn refresh(&self, pool: &deadpool_postgres::Pool) -> Result<(), String> {
        let client = tokio::time::timeout(Duration::from_secs(2), pool.get())
            .await
            .map_err(|_| "配置连接超时")?
            .map_err(|e| e.to_string())?;
        let row = client
            .query_one(
                "SELECT document, revision FROM runtime_configuration WHERE namespace=$1",
                &[&NAMESPACE],
            )
            .await
            .map_err(|e| e.to_string())?;
        self.apply(parse_config(row.get("document"))?, row.get("revision"));
        Ok(())
    }
    pub fn status(&self) -> Value {
        let mut s = self.lock();
        Self::prune(&mut s);
        json!({"instance_id":self.instance_id,"revision":s.revision,"enabled":s.config.enabled,
            "entries":s.entries.len(),"bytes":s.bytes,"hits":s.hits,"misses":s.misses,"joined":s.joined,
            "rejected":s.rejected,"evictions":s.evictions,"running":CONCURRENCY-self.permits.available_permits(),
            "in_flight":s.flights.len(),"last_cleared_at":s.last_cleared_at,
            "hit_rate":if s.hits+s.misses>0 {Some(s.hits as f64/(s.hits+s.misses) as f64*100.0)} else {None}})
    }
    pub async fn publish_status(&self, pool: &deadpool_postgres::Pool) -> Result<(), String> {
        let client = pool.get().await.map_err(|e| e.to_string())?;
        client.execute("INSERT INTO statistics_instance(instance_id,status,updated_at) VALUES($1,$2,NOW()) ON CONFLICT(instance_id) DO UPDATE SET status=EXCLUDED.status,updated_at=NOW()", &[&self.instance_id,&self.status()]).await.map_err(|e|e.to_string())?;
        client
            .execute(
                "DELETE FROM statistics_instance WHERE updated_at < NOW()-INTERVAL '1 day'",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    pub async fn execute<F, Fut>(
        &self,
        key: String,
        user: i32,
        mode: String,
        work: F,
    ) -> Result<(Bytes, &'static str), Failure>
    where
        F: FnOnce(Instant) -> Fut + Send + 'static,
        Fut: Future<Output = Result<Value, Failure>> + Send + 'static,
    {
        let deadline = Instant::now() + Duration::from_secs(QUERY_SECONDS);
        let (mut receiver, leader, generation) = {
            let mut s = self.lock();
            s.clock += 1;
            let clock = s.clock;
            let ttl = s.config.ttl(&mode);
            if s.config.enabled {
                if let Some(e) = s
                    .entries
                    .get_mut(&key)
                    .filter(|e| e.created.elapsed() < ttl)
                {
                    e.accessed = clock;
                    let body = e.body.clone();
                    s.hits += 1;
                    return Ok((body, "hit"));
                }
                if let Some(e) = s.entries.remove(&key) {
                    s.bytes -= e.body.len();
                }
            }
            if let Some(f) = s.flights.get(&key) {
                if f.sender.receiver_count() >= 16 {
                    tracing::warn!(
                        event = "StatisticsAdmissionRejected",
                        reason = "subscribers_full",
                        subscribers = f.sender.receiver_count(),
                        limit = 16
                    );
                    s.rejected += 1;
                    return Err(Failure::busy());
                }
                let rx = f.sender.subscribe();
                s.joined += 1;
                (rx, false, s.generation)
            } else {
                if s.flights.len() >= CONCURRENCY + QUEUE {
                    tracing::warn!(
                        event = "StatisticsAdmissionRejected",
                        reason = "queue_full",
                        in_flight = s.flights.len(),
                        limit = CONCURRENCY + QUEUE
                    );
                    s.rejected += 1;
                    return Err(Failure::busy());
                }
                if s.flights.values().any(|f| f.user == user) {
                    tracing::warn!(
                        event = "StatisticsAdmissionRejected",
                        reason = "user_in_flight",
                        in_flight = s.flights.len()
                    );
                    s.rejected += 1;
                    return Err(Failure::busy());
                }
                s.rate
                    .retain(|_, (at, _)| at.elapsed() < Duration::from_secs(60));
                if s.rate.len() >= 4096 && !s.rate.contains_key(&user) {
                    tracing::warn!(
                        event = "StatisticsAdmissionRejected",
                        reason = "rate_registry_full",
                        tracked_users = s.rate.len(),
                        limit = 4096
                    );
                    s.rejected += 1;
                    return Err(Failure::busy());
                }
                let rate = s.rate.entry(user).or_insert((Instant::now(), 0));
                if rate.1 >= 12 {
                    tracing::warn!(
                        event = "StatisticsAdmissionRejected",
                        reason = "user_rate_limit",
                        cold_queries = rate.1,
                        limit = 12,
                        window_seconds = 60,
                        window_elapsed_ms = rate.0.elapsed().as_millis() as u64
                    );
                    s.rejected += 1;
                    return Err(Failure::busy());
                }
                rate.1 += 1;
                let (tx, rx) = watch::channel(None);
                s.flights.insert(key.clone(), Flight { sender: tx, user });
                s.misses += 1;
                (rx, true, s.generation)
            }
        };
        if leader {
            let service = self.clone();
            let worker = async move {
                let mut guard = FlightGuard {
                    service: service.clone(),
                    key: key.clone(),
                    armed: true,
                };
                let permit = tokio::time::timeout(
                    Duration::from_secs(2),
                    service.permits.clone().acquire_owned(),
                )
                .await;
                let outcome = match permit {
                    Ok(Ok(_permit)) => {
                        // Do not drop in-progress database work on HTTP timeout. The worker owns
                        // the permit until the bounded SQL operation and transaction cleanup finish.
                        if service
                            .lock()
                            .flights
                            .get(&key)
                            .is_none_or(|f| f.sender.receiver_count() == 0)
                        {
                            Err(Failure::timeout())
                        } else {
                            work(deadline).await.and_then(|v| {
                                serde_json::to_vec(&v)
                                    .map(Bytes::from)
                                    .map_err(|_| Failure("statistics_failed", "统计结果编码失败"))
                            })
                        }
                    }
                    _ => {
                        tracing::warn!(
                            event = "StatisticsAdmissionRejected",
                            reason = "permit_wait_failed",
                            wait_limit_ms = 2000
                        );
                        Err(Failure::busy())
                    }
                };
                let mut s = service.lock();
                if let Ok(body) = &outcome
                    && generation == s.generation
                    && s.config.enabled
                    && body.len() <= s.config.max_entry_kib * 1024
                {
                    s.clock += 1;
                    let accessed = s.clock;
                    if let Some(old) = s.entries.insert(
                        key.clone(),
                        Entry {
                            body: body.clone(),
                            mode,
                            created: deadline - Duration::from_secs(QUERY_SECONDS),
                            accessed,
                        },
                    ) {
                        s.bytes -= old.body.len();
                    }
                    Self::prune(&mut s);
                }
                if let Some(f) = s.flights.remove(&key) {
                    f.sender.send_replace(Some(outcome));
                }
                guard.armed = false;
                drop(s);
                drop(guard);
            };
            tokio::spawn(worker.in_current_span());
        }
        let wait = async {
            loop {
                if let Some(outcome) = receiver.borrow_and_update().clone() {
                    return outcome;
                }
                receiver
                    .changed()
                    .await
                    .map_err(|_| Failure("statistics_failed", "统计计算已中断"))?;
            }
        };
        let body = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), wait)
            .await
            .map_err(|_| Failure::timeout())??;
        Ok((body, if leader { "miss" } else { "joined" }))
    }
}
struct FlightGuard {
    service: StatisticsService,
    key: String,
    armed: bool,
}
impl Drop for FlightGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(f) = self.service.lock().flights.remove(&self.key) {
            f.sender
                .send_replace(Some(Err(Failure("statistics_failed", "统计计算已中断"))));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn rate_limit_log_identifies_cause_without_logging_query_key() {
        use std::io::{self, Write};
        use tracing_subscriber::prelude::*;

        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        struct Writer(Arc<Mutex<Vec<u8>>>);
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
            type Writer = Writer;
            fn make_writer(&'a self) -> Writer {
                Writer(self.0.clone())
            }
        }
        impl Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let output = Buffer::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(output.clone())
                .with_current_span(true),
        );
        let _default = tracing::subscriber::set_default(subscriber);
        let span = tracing::info_span!("http_request", request_id = "test-request");
        let _entered = span.enter();
        let service = StatisticsService::new();
        service.lock().rate.insert(1, (Instant::now(), 12));
        let error = service
            .execute(
                "sensitive-query-key".into(),
                1,
                "realtime".into(),
                |_| async { panic!("rate-limited query must not run") },
            )
            .await
            .unwrap_err();
        assert_eq!(error.0, "statistics_busy");
        let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        let event: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(event["fields"]["event"], "StatisticsAdmissionRejected");
        assert_eq!(event["fields"]["reason"], "user_rate_limit");
        assert_eq!(event["fields"]["cold_queries"], 12);
        assert_eq!(event["span"]["request_id"], "test-request");
        assert!(!text.contains("sensitive-query-key"));
    }

    #[test]
    fn validates_cache_ranges_and_types() {
        assert!(parse_config(json!({"enabled":false})).is_ok());
        assert!(parse_config(json!({"max_entries":0})).is_err());
        assert!(parse_config(json!({"max_entry_kib":9000})).is_err());
        assert!(parse_config(json!({"enabled":"false"})).is_err());
        assert!(parse_config(json!({"unexpected":1})).is_err());
    }
    #[tokio::test]
    async fn concurrent_identical_queries_share_one_computation() {
        let service = StatisticsService::new();
        service.apply(CacheConfig::default(), 1);
        let executions = Arc::new(AtomicUsize::new(0));
        let mut jobs = Vec::new();
        for _ in 0..8 {
            let service = service.clone();
            let executions = executions.clone();
            jobs.push(tokio::spawn(async move {
                service
                    .execute("same".into(), 1, "realtime".into(), move |_| async move {
                        executions.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        Ok(json!({"value":42}))
                    })
                    .await
                    .unwrap()
                    .0
            }));
        }
        for job in jobs {
            assert_eq!(job.await.unwrap(), Bytes::from_static(b"{\"value\":42}"));
        }
        assert_eq!(executions.load(Ordering::SeqCst), 1);
        let (_, kind) = service
            .execute("same".into(), 1, "realtime".into(), |_| async {
                panic!("cache hit must not compute")
            })
            .await
            .unwrap();
        assert_eq!(kind, "hit");
        assert_eq!(service.status()["in_flight"], 0);
    }
    #[tokio::test]
    async fn distinct_queries_bound_execution_and_reject_excess_queue() {
        let service = StatisticsService::new();
        let running = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Semaphore::new(0));
        let mut jobs = Vec::new();
        for user in 0..(CONCURRENCY + QUEUE) {
            let (worker, running, maximum, gate) = (
                service.clone(),
                running.clone(),
                maximum.clone(),
                gate.clone(),
            );
            jobs.push(tokio::spawn(async move {
                worker
                    .execute(
                        user.to_string(),
                        user as i32,
                        "realtime".into(),
                        move |_| async move {
                            let current = running.fetch_add(1, Ordering::SeqCst) + 1;
                            maximum.fetch_max(current, Ordering::SeqCst);
                            let permit = gate.acquire().await.unwrap();
                            permit.forget();
                            running.fetch_sub(1, Ordering::SeqCst);
                            Ok(json!(user))
                        },
                    )
                    .await
            }));
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while service.status()["in_flight"] != CONCURRENCY + QUEUE {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            service
                .execute("excess".into(), 100, "realtime".into(), |_| async {
                    Ok(json!(0))
                })
                .await
                .unwrap_err()
                .0,
            "statistics_busy"
        );
        gate.add_permits(CONCURRENCY + QUEUE);
        for job in jobs {
            job.await.unwrap().unwrap();
        }
        assert!(maximum.load(Ordering::SeqCst) <= CONCURRENCY);
        assert_eq!(service.status()["in_flight"], 0);
    }
    #[tokio::test]
    async fn clearing_during_computation_prevents_repopulation() {
        let service = StatisticsService::new();
        service.apply(CacheConfig::default(), 1);
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, gate) = tokio::sync::oneshot::channel();
        let worker = service.clone();
        let job = tokio::spawn(async move {
            worker
                .execute("old".into(), 1, "snapshot".into(), |_| async {
                    started.send(()).unwrap();
                    gate.await.unwrap();
                    Ok(json!(1))
                })
                .await
        });
        ready.await.unwrap();
        service.apply(CacheConfig::default(), 3);
        release.send(()).unwrap();
        job.await.unwrap().unwrap();
        assert_eq!(service.status()["entries"], 0);
    }
    #[tokio::test]
    async fn disabled_cache_still_merges_and_enforces_user_admission() {
        let service = StatisticsService::new();
        service.apply(
            CacheConfig {
                enabled: false,
                ..Default::default()
            },
            1,
        );
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, gate) = tokio::sync::oneshot::channel();
        let worker = service.clone();
        let job = tokio::spawn(async move {
            worker
                .execute("first".into(), 1, "realtime".into(), |_| async {
                    started.send(()).unwrap();
                    gate.await.unwrap();
                    Ok(json!(1))
                })
                .await
        });
        ready.await.unwrap();
        assert_eq!(
            service
                .execute("second".into(), 1, "realtime".into(), |_| async {
                    Ok(json!(2))
                })
                .await
                .unwrap_err()
                .0,
            "statistics_busy"
        );
        release.send(()).unwrap();
        job.await.unwrap().unwrap();
        assert_eq!(service.status()["entries"], 0);
    }
    #[tokio::test]
    async fn failed_and_panicking_queries_release_admission() {
        let service = StatisticsService::new();
        assert!(
            service
                .execute("error".into(), 1, "realtime".into(), |_| async {
                    Err(Failure::timeout())
                })
                .await
                .is_err()
        );
        assert!(
            service
                .execute("panic".into(), 1, "realtime".into(), |_| async {
                    panic!("worker failure")
                })
                .await
                .is_err()
        );
        assert_eq!(service.status()["in_flight"], 0);
        assert_eq!(service.status()["entries"], 0);
    }
    #[test]
    fn expiration_uses_original_age_and_eviction_respects_capacity() {
        let service = StatisticsService::new();
        let mut s = service.lock();
        s.config.max_entries = 16;
        for n in 0..20 {
            s.entries.insert(
                n.to_string(),
                Entry {
                    body: Bytes::from_static(b"a"),
                    mode: "realtime".into(),
                    created: Instant::now(),
                    accessed: n,
                },
            );
        }
        s.entries.insert(
            "expired".into(),
            Entry {
                body: Bytes::from_static(b"expired"),
                mode: "realtime".into(),
                created: Instant::now() - Duration::from_secs(31),
                accessed: 100,
            },
        );
        StatisticsService::prune(&mut s);
        assert_eq!(s.entries.len(), 16);
        assert_eq!(s.bytes, 16);
        assert!(!s.entries.contains_key("expired"));
        assert!(!s.entries.contains_key("0"));
    }
}

#[cfg(test)]
mod integration;
