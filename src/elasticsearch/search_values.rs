use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{Mutex, Semaphore, watch};

use crate::handlers::search_dsl::{Field, es_field};

use super::{
    ElasticsearchOperation, ElasticsearchService, asset_search_scope, validate_scan_search_response,
};

const VALUE_LIMIT: usize = 48;
const CACHE_LIMIT: usize = 1024;
const REFRESH_CONCURRENCY: usize = 4;
const REFRESH_INTERVAL: Duration = Duration::from_secs(120);
const RETRY_INTERVAL: Duration = Duration::from_secs(10);
const MAX_STALE_AGE: Duration = Duration::from_secs(600);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(try_from = "String")]
pub(crate) struct SearchValueField(Field);

impl TryFrom<String> for SearchValueField {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match Field::parse_canonical(&value) {
            Some(
                field @ (Field::Asn
                | Field::Country
                | Field::Protocol
                | Field::Service
                | Field::Source
                | Field::TlsMode
                | Field::TlsVersion
                | Field::TlsCipherSuite
                | Field::TlsSelfSigned
                | Field::OsFamily
                | Field::OsDistribution
                | Field::OsVersion
                | Field::OsConfidence
                | Field::OsStatus
                | Field::OsScore
                | Field::WebStatus
                | Field::Technology
                | Field::Product),
            ) => Ok(Self(field)),
            _ => Err("不支持该字段的值推荐"),
        }
    }
}

type CacheKey = (&'static str, i32, SearchValueField);
type PendingRefresh = watch::Receiver<Option<SearchValueSuggestions>>;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SearchValueSuggestions {
    values: Vec<String>,
    retry_after_ms: u64,
}

struct CacheEntry {
    values: Option<(Instant, Vec<String>)>,
    refresh: Option<PendingRefresh>,
    next_refresh: Instant,
    last_used: Instant,
}

impl CacheEntry {
    fn new(now: Instant) -> Self {
        Self {
            values: None,
            refresh: None,
            next_refresh: now,
            last_used: now,
        }
    }

    fn reply(&self, now: Instant) -> SearchValueSuggestions {
        let values = self
            .values
            .as_ref()
            .filter(|(refreshed, _)| now.duration_since(*refreshed) < MAX_STALE_AGE)
            .map(|(_, values)| values.clone())
            .unwrap_or_default();
        let retry_after_ms = self.next_refresh.saturating_duration_since(now).as_millis() as u64;
        SearchValueSuggestions {
            values,
            retry_after_ms,
        }
    }
}

pub(super) struct SearchValueCache {
    entries: Mutex<HashMap<CacheKey, CacheEntry>>,
    refresh_slots: Arc<Semaphore>,
}

impl Default for SearchValueCache {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            refresh_slots: Arc::new(Semaphore::new(REFRESH_CONCURRENCY)),
        }
    }
}

impl SearchValueCache {
    async fn get<F, Fut>(self: &Arc<Self>, key: CacheKey, load: F) -> SearchValueSuggestions
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<Vec<String>, String>> + Send + 'static,
    {
        let mut entries = self.entries.lock().await;
        let now = Instant::now();
        if entries.len() >= CACHE_LIMIT && !entries.contains_key(&key) {
            let oldest = entries
                .iter()
                .filter(|(_, entry)| entry.refresh.is_none())
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                entries.remove(&oldest);
            } else {
                return SearchValueSuggestions {
                    values: Vec::new(),
                    retry_after_ms: RETRY_INTERVAL.as_millis() as u64,
                };
            }
        }

        let entry = entries.entry(key).or_insert_with(|| CacheEntry::new(now));
        entry.last_used = now;
        if entry
            .refresh
            .as_ref()
            .is_some_and(|refresh| refresh.has_changed().is_err())
        {
            entry.refresh = None;
        }
        if entry.refresh.is_none() && entry.next_refresh <= now {
            entry.next_refresh = now + RETRY_INTERVAL;
            if let Ok(permit) = self.refresh_slots.clone().try_acquire_owned() {
                let (sender, receiver) = watch::channel(None);
                entry.refresh = Some(receiver);
                let cache = Arc::clone(self);
                tokio::spawn(async move {
                    let result = load().await;
                    let mut entries = cache.entries.lock().await;
                    if let Some(entry) = entries.get_mut(&key) {
                        let now = Instant::now();
                        entry.next_refresh = match result {
                            Ok(values) => {
                                entry.values = Some((now, values));
                                now + REFRESH_INTERVAL
                            }
                            Err(_) => now + RETRY_INTERVAL,
                        };
                        entry.refresh = None;
                        sender.send_replace(Some(entry.reply(now)));
                    }
                    drop(permit);
                });
            }
        }

        let current = entry.reply(now);
        if entry
            .values
            .as_ref()
            .is_some_and(|(refreshed, _)| now.duration_since(*refreshed) < MAX_STALE_AGE)
        {
            return current;
        }
        let Some(mut refresh) = entry.refresh.clone() else {
            return current;
        };
        drop(entries);
        // A cold lookup shares the bounded in-flight request. Cached lookups return immediately.
        match refresh.wait_for(Option::is_some).await {
            Ok(result) => result.clone().unwrap_or(current),
            Err(_) => current,
        }
    }
}

impl ElasticsearchService {
    pub(crate) async fn suggest_search_values(
        &self,
        role: i32,
        user_id: i32,
        field: SearchValueField,
    ) -> SearchValueSuggestions {
        let (scope_type, scope_id) = asset_search_scope(role, user_id);
        let key = (scope_type, scope_id, field);
        let service = self.clone();
        self.inner
            .search_value_cache
            .get(key, move || async move {
                service.fetch_search_values(key).await
            })
            .await
    }

    async fn fetch_search_values(&self, key: CacheKey) -> Result<Vec<String>, String> {
        if !self.can_read() {
            return Err("Elasticsearch 搜索读路径尚未就绪".to_owned());
        }
        let body = search_values_body(key);
        let index = &self.inner.config.current_endpoint_index;
        let response = self
            .send_json_request(
                ElasticsearchOperation::SearchValues,
                Method::POST,
                &format!("{index}/_search?allow_partial_search_results=false"),
                |request| request.timeout(REQUEST_TIMEOUT).json(&body),
            )
            .await?;
        validate_scan_search_response(&response)?;
        parse_search_values(key.2, &response)
    }
}

fn search_values_body((scope_type, scope_id, SearchValueField(field)): CacheKey) -> Value {
    let mut terms = json!({"field": es_field(field), "size": VALUE_LIMIT});
    if field == Field::Product {
        terms["exclude"] = json!(crate::service_products::RETIRED_PRODUCT_IDS);
    }
    let values = json!({"terms": terms});
    let aggregation = match field.nested_search_path() {
        Some(path) => json!({"nested": {"path": path}, "aggs": {"terms": values}}),
        None => values,
    };
    json!({
        "size": 0,
        "track_total_hits": false,
        "timeout": "350ms",
        "query": {"bool": {"filter": [
            {"term": {"scope_type": scope_type}},
            {"term": {"scope_id": scope_id}}
        ]}},
        "aggs": {"values": aggregation}
    })
}

fn parse_search_values(
    SearchValueField(field): SearchValueField,
    response: &Value,
) -> Result<Vec<String>, String> {
    let buckets_path = if field.nested_search_path().is_some() {
        "/aggregations/values/terms/buckets"
    } else {
        "/aggregations/values/buckets"
    };
    let buckets = response
        .pointer(buckets_path)
        .and_then(Value::as_array)
        .ok_or_else(|| "Elasticsearch 字段值响应缺少聚合桶".to_owned())?;
    Ok(buckets
        .iter()
        .filter_map(|bucket| match field {
            Field::OsScore => bucket["key"]
                .as_u64()
                .filter(|score| *score <= 100)
                .map(|score| score.to_string()),
            Field::TlsSelfSigned => bucket["key_as_string"]
                .as_str()
                .filter(|value| matches!(*value, "true" | "false"))
                .map(str::to_owned),
            _ => bucket["key"].as_str().map(str::to_owned),
        })
        .filter(|value| {
            !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
        })
        .take(VALUE_LIMIT)
        .collect())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    use super::*;

    fn key(user: i32) -> CacheKey {
        ("user", user, SearchValueField(Field::Service))
    }

    #[test]
    fn builds_bounded_scope_filters_and_whitelists_index_fields() {
        let scope = asset_search_scope(crate::access::USER, 7);
        let body = search_values_body((scope.0, scope.1, SearchValueField(Field::Service)));
        assert_eq!(body["size"], 0);
        assert_eq!(body["track_total_hits"], false);
        assert_eq!(body["timeout"], "350ms");
        assert_eq!(
            body["query"]["bool"]["filter"],
            json!([{"term":{"scope_type":"user"}}, {"term":{"scope_id":7}}])
        );
        assert_eq!(body["aggs"]["values"]["terms"]["size"], VALUE_LIMIT);
        let scope = asset_search_scope(crate::access::ADMIN, 7);
        let products = search_values_body((scope.0, scope.1, SearchValueField(Field::Product)));
        assert_eq!(
            products["query"]["bool"]["filter"],
            json!([{"term":{"scope_type":"global"}}, {"term":{"scope_id":0}}])
        );
        assert_eq!(products["aggs"]["values"]["nested"]["path"], "products");
        assert_eq!(
            products["aggs"]["values"]["aggs"]["terms"]["terms"]["exclude"],
            json!(crate::service_products::RETIRED_PRODUCT_IDS)
        );
        assert_eq!(
            serde_json::from_value::<SearchValueField>(json!("tls.cipher")).ok(),
            Some(SearchValueField(Field::TlsCipherSuite))
        );
        for invalid in [
            "ip",
            "domain",
            "port",
            "banner",
            "http.body",
            "scope_id",
            "products.id",
        ] {
            assert!(serde_json::from_value::<SearchValueField>(json!(invalid)).is_err());
        }
    }

    #[test]
    fn extracts_typed_and_nested_values_without_counts_or_malformed_values() {
        let response = json!({"aggregations":{"values":{"buckets":[
            {"key":79,"doc_count":42},{"key":0},{"key":101},{"key":"80"}
        ]}}});
        assert_eq!(
            parse_search_values(SearchValueField(Field::OsScore), &response).unwrap(),
            ["79", "0"]
        );
        let response = json!({"aggregations":{"values":{"buckets":[
            {"key":1,"key_as_string":"true"},{"key":0,"key_as_string":"false"}
        ]}}});
        assert_eq!(
            parse_search_values(SearchValueField(Field::TlsSelfSigned), &response).unwrap(),
            ["true", "false"]
        );
        let response = json!({"aggregations":{"values":{"terms":{"buckets":[
            {"key":"nginx","doc_count":12},{"key":""},{"key":"bad\nvalue"},{"key":"a".repeat(129)}
        ]}}}});
        assert_eq!(
            parse_search_values(SearchValueField(Field::Technology), &response).unwrap(),
            ["nginx"]
        );
        assert!(parse_search_values(SearchValueField(Field::Technology), &json!({})).is_err());
    }

    #[tokio::test]
    async fn coalesces_cold_reads_and_isolates_scopes_and_fields() {
        let cache = Arc::new(SearchValueCache::default());
        let loads = Arc::new(AtomicUsize::new(0));
        let load = {
            let loads = loads.clone();
            move || async move {
                loads.fetch_add(1, Ordering::Relaxed);
                tokio::task::yield_now().await;
                Ok(vec!["https".to_owned()])
            }
        };
        let (a, b) = tokio::join!(cache.get(key(7), load.clone()), cache.get(key(7), load));
        assert_eq!(a.values, ["https"]);
        assert_eq!(a.values, b.values);
        assert!(a.retry_after_ms > 100_000);
        assert_eq!(loads.load(Ordering::Relaxed), 1);
        assert_eq!(
            cache
                .get(key(8), || async { Ok(vec!["smtp".to_owned()]) })
                .await
                .values,
            ["smtp"]
        );
        assert_eq!(
            cache
                .get(("user", 7, SearchValueField(Field::Protocol)), || async {
                    Ok(vec!["tcp".to_owned()])
                })
                .await
                .values,
            ["tcp"]
        );
        assert_eq!(
            cache
                .get(("global", 0, SearchValueField(Field::Service)), || async {
                    Ok(vec!["ssh".to_owned()])
                })
                .await
                .values,
            ["ssh"]
        );
        assert_eq!(
            cache
                .get(key(7), || async { panic!("fresh entries do not reload") })
                .await
                .values,
            ["https"]
        );
    }

    #[tokio::test]
    async fn serves_stale_values_during_refresh_and_backs_off_on_errors() {
        let cache = Arc::new(SearchValueCache::default());
        cache
            .get(key(7), || async { Ok(vec!["https".to_owned()]) })
            .await;
        cache
            .entries
            .lock()
            .await
            .get_mut(&key(7))
            .unwrap()
            .next_refresh = Instant::now();
        let release = Arc::new(Notify::new());
        let stale = cache
            .get(key(7), {
                let release = release.clone();
                move || async move {
                    release.notified().await;
                    Err("temporary failure".to_owned())
                }
            })
            .await;
        assert_eq!(stale.values, ["https"]);
        let mut refresh = cache.entries.lock().await[&key(7)].refresh.clone().unwrap();
        assert_eq!(
            cache
                .get(key(7), || async { panic!("refresh is already in flight") })
                .await
                .values,
            ["https"]
        );
        release.notify_one();
        let refreshed = refresh.wait_for(Option::is_some).await.unwrap();
        assert_eq!(refreshed.as_ref().unwrap().values, ["https"]);
        assert!(refreshed.as_ref().unwrap().retry_after_ms <= 10_000);
        assert_eq!(
            cache
                .get(key(7), || async { panic!("failure is backed off") })
                .await
                .values,
            ["https"]
        );
    }

    #[tokio::test]
    async fn skips_refresh_when_at_capacity_and_never_serves_expired_values() {
        let cache = Arc::new(SearchValueCache::default());
        let permit = cache
            .refresh_slots
            .clone()
            .acquire_many_owned(REFRESH_CONCURRENCY as u32)
            .await
            .unwrap();
        let now = Instant::now();
        let mut entry = CacheEntry::new(now);
        entry.values = Some((now - MAX_STALE_AGE, vec!["expired".to_owned()]));
        cache.entries.lock().await.insert(key(7), entry);

        let saturated = cache
            .get(key(7), || async { panic!("no refresh slot is available") })
            .await;
        assert!(saturated.values.is_empty());
        assert_eq!(saturated.retry_after_ms, RETRY_INTERVAL.as_millis() as u64);
        drop(permit);
        let cooldown = cache
            .get(key(7), || async {
                panic!("saturation backs off before retrying")
            })
            .await;
        assert!(cooldown.values.is_empty());
    }
}
