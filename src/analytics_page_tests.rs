use super::*;
use crate::handlers::data_saa::AnalysisFilters;
use chrono::TimeZone;
use deadpool_postgres::Manager;
use tokio_postgres::NoTls;

fn test_now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 24, 12, 0, 0).unwrap()
}

fn request(now: DateTime<Utc>, zone: Tz) -> (Window, AnalysisFilters) {
    let window = Window::new(now.with_timezone(&zone).date_naive(), 12);
    let start_at = boundary(window.start, zone).unwrap();
    let end_at = boundary(window.end, zone).unwrap();
    (
        window,
        AnalysisFilters {
            timezone: zone.name().into(),
            start_at,
            end_at,
            start_ms: start_at.timestamp_millis(),
            end_ms: end_at.timestamp_millis(),
            scanner_id: None,
            task_source: None,
        },
    )
}

#[test]
fn page_windows_match_calendar_and_keep_arbitrary_ranges_on_compatibility_path() {
    let zone = chrono_tz::America::New_York;
    let now = Utc.with_ymd_and_hms(2026, 11, 1, 21, 30, 0).unwrap();
    let (window, filters) = request(now, zone);
    assert_eq!(
        filters.end_at,
        Utc.with_ymd_and_hms(2026, 11, 2, 5, 0, 0).unwrap()
    );
    assert_eq!(
        Window::for_request(filters.start_at, filters.end_at, zone.name(), now),
        Some(window)
    );
    assert_eq!(
        Window::for_request(
            filters.start_at + chrono::Duration::minutes(1),
            filters.end_at,
            zone.name(),
            now
        ),
        None
    );
    assert_eq!(
        Window::for_request(
            filters.start_at,
            filters.end_at,
            zone.name(),
            now + chrono::Duration::hours(11)
        ),
        Some(window)
    );
    assert_eq!(
        Window::for_request(
            filters.start_at,
            filters.end_at,
            zone.name(),
            now + chrono::Duration::days(2)
        ),
        None
    );
}

async fn database() -> (Pool, Pool, String) {
    let mut config: tokio_postgres::Config = std::env::var("ANALYTICS_TEST_DATABASE_URL")
        .expect("set ANALYTICS_TEST_DATABASE_URL to a disposable PostgreSQL database")
        .parse()
        .unwrap();
    let root_pool = Pool::builder(Manager::new(config.clone(), NoTls))
        .build()
        .unwrap();
    let schema = format!("page_snapshot_test_{}", uuid::Uuid::new_v4().simple());
    root_pool
        .get()
        .await
        .unwrap()
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    config.options(format!("-c search_path={schema},public"));
    let pool = Pool::builder(Manager::new(config, NoTls))
        .max_size(4)
        .build()
        .unwrap();
    let client = pool.get().await.unwrap();
    client.batch_execute("
        CREATE TABLE runtime_configuration (namespace TEXT PRIMARY KEY, document JSONB NOT NULL);
        CREATE TABLE analytics_watermark (watermark_key TEXT PRIMARY KEY, data_as_of TIMESTAMPTZ NOT NULL);
        CREATE TABLE executions (id INT PRIMARY KEY);
        CREATE TABLE analytics_discovery_fact (
            execution_id INT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
            day_start DATE NOT NULL, first_observed_at TIMESTAMPTZ,
            owner_id INT NOT NULL, scanner_id TEXT NOT NULL, task_source TEXT NOT NULL, ip_address INET NOT NULL,
            PRIMARY KEY (execution_id, day_start, ip_address)
        );
        CREATE INDEX ON analytics_discovery_fact (day_start, owner_id, scanner_id, task_source);
        CREATE INDEX ON analytics_discovery_fact (first_observed_at, owner_id, scanner_id, task_source);
        CREATE TABLE analytics_distribution_30m (
            execution_id INT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
            bucket_start TIMESTAMPTZ NOT NULL, owner_id INT NOT NULL, scanner_id TEXT NOT NULL,
            task_source TEXT NOT NULL, dimension TEXT NOT NULL, label TEXT NOT NULL, endpoint_count BIGINT NOT NULL,
            PRIMARY KEY (execution_id, bucket_start, dimension, label)
        );
        CREATE INDEX ON analytics_distribution_30m (bucket_start, owner_id, scanner_id, task_source, dimension);
        INSERT INTO runtime_configuration VALUES ('analytics_snapshot', '{\"mode\":\"snapshot\",\"page_rollups\":\"off\"}');
        INSERT INTO runtime_configuration VALUES ('general', '{\"timezone\":\"Asia/Shanghai\"}');
        INSERT INTO analytics_watermark VALUES ('scan_analysis', NOW());
    ").await.unwrap();
    let migration = include_str!("../source/database/migrate_analytics_page.sql");
    client.batch_execute(migration).await.unwrap();
    client.batch_execute(migration).await.unwrap();
    (pool, root_pool, schema)
}

async fn cleanup(root_pool: &Pool, schema: &str) {
    root_pool
        .get()
        .await
        .unwrap()
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

async fn page_mode(client: &deadpool_postgres::Client, mode: &str) {
    client.execute(
        "UPDATE runtime_configuration SET document = jsonb_set(document, '{page_rollups}', to_jsonb($1::TEXT))
         WHERE namespace = 'analytics_snapshot'",
        &[&mode],
    ).await.unwrap();
}

#[tokio::test]
#[ignore = "requires disposable ANALYTICS_TEST_DATABASE_URL"]
async fn published_charts_preserve_scope_and_refresh_on_changes() {
    let (pool, root_pool, schema) = database().await;
    let client = pool.get().await.unwrap();
    let now = test_now();
    let (window, mut filters) = request(now, Shanghai);
    client
        .batch_execute(
            "
        INSERT INTO executions SELECT generate_series(1,6);
        INSERT INTO analytics_discovery_fact VALUES
          (1,'2026-11-23','2026-11-23 00:00+08',1,'a','manual','192.0.2.1'),
          (2,'2026-11-23','2026-11-23 00:10+08',1,'b','manual','192.0.2.1'),
          (3,'2026-11-23','2026-11-23 00:20+08',2,'a','automatic','192.0.2.2'),
          (4,'2026-11-22',NULL,2,'b','search','192.0.2.3');
        INSERT INTO analytics_distribution_30m VALUES
          (1,'2026-11-23 00:00+08',1,'a','manual','port','80',2),
          (2,'2026-11-23 00:00+08',1,'b','manual','port','80',4),
          (3,'2026-11-23 00:00+08',2,'a','automatic','port','443',6),
          (4,'2026-11-22 23:30+08',2,'b','search','service','http',1);
    ",
        )
        .await
        .unwrap();

    page_mode(&client, "build").await;
    refresh(&pool, now).await.unwrap();
    page_mode(&client, "read").await;
    let global = read(&pool, window, &filters, None, Chart::Heatmap)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        global.data,
        json!([{"date":"2026-11-22","count":1},{"date":"2026-11-23","count":2}])
    );
    let distribution = read(&pool, window, &filters, None, Chart::Distribution("port"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(distribution.revision, global.revision);
    assert_eq!(
        distribution.data,
        json!({"total":12,"items":[{"label":"443","count":6},{"label":"80","count":6}]})
    );
    assert_eq!(
        read(&pool, window, &filters, Some(1), Chart::Heatmap)
            .await
            .unwrap()
            .unwrap()
            .data,
        json!([{"date":"2026-11-23","count":1}])
    );
    filters.scanner_id = Some("a".into());
    filters.task_source = Some("automatic".into());
    assert_eq!(
        read(&pool, window, &filters, Some(1), Chart::Heatmap)
            .await
            .unwrap()
            .unwrap()
            .data,
        json!([])
    );
    assert_eq!(
        read(&pool, window, &filters, None, Chart::Heatmap)
            .await
            .unwrap()
            .unwrap()
            .data,
        json!([{"date":"2026-11-23","count":1}])
    );
    filters.scanner_id = None;
    filters.task_source = None;

    // Inserts retain the last complete revision. A cascade invalidates it in the deleting transaction.
    client.batch_execute("
        INSERT INTO analytics_discovery_fact VALUES (5,'2026-11-23','2026-11-23 12:00+08',1,'a','search','2001:db8::1');
        INSERT INTO analytics_distribution_30m VALUES (5,'2026-11-23 12:00+08',1,'a','search','port','443',3);
    ").await.unwrap();
    assert_eq!(
        read(&pool, window, &filters, None, Chart::Heatmap)
            .await
            .unwrap()
            .unwrap()
            .revision,
        global.revision
    );
    client
        .execute("DELETE FROM executions WHERE id = 3", &[])
        .await
        .unwrap();
    assert!(
        read(&pool, window, &filters, None, Chart::Heatmap)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        read(&pool, window, &filters, None, Chart::Distribution("port"))
            .await
            .unwrap()
            .is_none()
    );
    refresh(&pool, now).await.unwrap();
    let updated = read(&pool, window, &filters, None, Chart::Distribution("port"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.revision, global.revision + 1);
    assert_eq!(
        updated.data,
        json!({"total":9,"items":[{"label":"80","count":6},{"label":"443","count":3}]})
    );

    client.execute("UPDATE runtime_configuration SET document = '{\"timezone\":\"America/New_York\"}' WHERE namespace='general'", &[]).await.unwrap();
    let (new_window, new_filters) = request(now, chrono_tz::America::New_York);
    assert!(
        read(&pool, new_window, &new_filters, None, Chart::Heatmap)
            .await
            .unwrap()
            .is_none()
    );
    refresh(&pool, now).await.unwrap();
    assert!(
        read(&pool, new_window, &new_filters, None, Chart::Heatmap)
            .await
            .unwrap()
            .unwrap()
            .legacy_timezone_error
    );
    assert!(
        !read(&pool, new_window, &new_filters, Some(1), Chart::Heatmap)
            .await
            .unwrap()
            .unwrap()
            .legacy_timezone_error
    );

    // Pausing capture and re-enabling invalidates the old generation even with no pending mutation events.
    page_mode(&client, "off").await;
    client
        .batch_execute("TRUNCATE analytics_distribution_30m")
        .await
        .unwrap();
    page_mode(&client, "read").await;
    assert!(
        read(
            &pool,
            new_window,
            &new_filters,
            None,
            Chart::Distribution("port")
        )
        .await
        .unwrap()
        .is_none()
    );
    refresh(&pool, now).await.unwrap();
    assert_eq!(
        read(
            &pool,
            new_window,
            &new_filters,
            None,
            Chart::Distribution("port")
        )
        .await
        .unwrap()
        .unwrap()
        .data,
        json!({"total":0,"items":[]})
    );
    drop(client);
    cleanup(&root_pool, &schema).await;
}

#[actix_web::test]
#[ignore = "loads production-sized synthetic data into disposable ANALYTICS_TEST_DATABASE_URL"]
async fn published_chart_performance() {
    use crate::{config::AnalyticsSnapshotMode, handlers::data_saa};
    use actix_web::{App, HttpMessage, dev::Service, test, web};
    use std::time::Instant;

    let (pool, root_pool, schema) = database().await;
    let client = pool.get().await.unwrap();
    let now = Utc::now();
    let (_, filters) = request(now, Shanghai);
    let anchor = now.with_timezone(&Shanghai).date_naive();
    client
        .execute(
            "INSERT INTO executions SELECT generate_series(0, 2920)",
            &[],
        )
        .await
        .unwrap();
    client.execute(
        "INSERT INTO analytics_discovery_fact
         SELECT n / 500, $1::DATE - 119 + (n / 500 % 120),
             (($1::DATE - 119 + (n / 500 % 120))::TIMESTAMP AT TIME ZONE 'Asia/Shanghai') + (n % 86300) * INTERVAL '1s',
             1 + (n / 500 % 2), 'scanner-' || (n / 500 % 3),
             (ARRAY['manual','automatic','search'])[1 + n / 500 % 3], '10.0.0.0'::INET + (n % 23000)::BIGINT
         FROM generate_series(0, 534654) AS input(n)", &[&anchor],
    ).await.unwrap();
    client.execute(
        "INSERT INTO analytics_distribution_30m
         SELECT n / 500,
             (($1::DATE - 119 + (n / 500 % 120))::TIMESTAMP AT TIME ZONE 'Asia/Shanghai') + (n / 500 % 48) * INTERVAL '30 min',
             1 + (n / 500 % 2), 'scanner-' || (n / 500 % 3),
             (ARRAY['manual','automatic','search'])[1 + n / 500 % 3],
             CASE WHEN n % 20 = 0 THEN 'service' ELSE 'port' END,
             CASE WHEN n % 20 = 0 THEN 'service-' || (n % 500 / 20)
                  ELSE ((n % 500) + (n / 500 % 24) * 500 + 1)::TEXT END, 1 + n % 3
        FROM generate_series(0, 1457999) AS input(n)", &[&anchor],
    ).await.unwrap();
    client
        .batch_execute("VACUUM ANALYZE analytics_discovery_fact;")
        .await
        .unwrap();
    client
        .batch_execute("VACUUM ANALYZE analytics_distribution_30m;")
        .await
        .unwrap();

    page_mode(&client, "build").await;
    let started = Instant::now();
    refresh(&pool, now).await.unwrap();
    eprintln!(
        "page initial publication: {:.2}s",
        started.elapsed().as_secs_f64()
    );
    let published_size: String = client
        .query_one(
            "SELECT pg_size_pretty(sum(pg_total_relation_size(quote_ident(tablename)::regclass))::BIGINT)
         FROM pg_tables WHERE schemaname = current_schema() AND tablename LIKE 'analytics_page_%'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    eprintln!("page projection size: {published_size}");
    page_mode(&client, "read").await;

    let settings = RuntimeConfig::new(
        AnalyticsSnapshotConfig {
            mode: AnalyticsSnapshotMode::Snapshot,
            ..Default::default()
        },
        1,
    );
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(settings.clone()))
            .app_data(web::Data::new(
                crate::elasticsearch::ElasticsearchService::new(Default::default()).unwrap(),
            ))
            .wrap_fn(|req, srv| {
                req.extensions_mut().insert(crate::admin::UserBaseI {
                    id: 1,
                    role: 1,
                    username: "benchmark".into(),
                    email: None,
                    limit_login: false,
                    enable_2fa: false,
                });
                srv.call(req)
            })
            .service(data_saa::get_analysis_distribution)
            .service(data_saa::get_analysis_discovery_heatmap),
    )
    .await;

    const SAMPLES: usize = 24;
    let utc = |value: DateTime<Utc>| value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let range = format!(
        "start_at={}&end_at={}&page_window=true",
        utc(filters.start_at),
        utc(filters.end_at)
    );
    for (name, path) in [
        (
            "heatmap",
            format!("/api/analysis/discovery-heatmap?{range}"),
        ),
        (
            "service",
            format!("/api/analysis/distribution?dimension=service&limit=5&{range}"),
        ),
        (
            "port",
            format!("/api/analysis/distribution?dimension=port&limit=10&{range}"),
        ),
    ] {
        let mut samples = [Vec::new(), Vec::new()];
        let mut original = Value::Null;
        // Alternate original and published reads over the same immutable generation.
        for trial in 0..=SAMPLES {
            for (index, mode) in [AnalyticsPageRollups::Off, AnalyticsPageRollups::Read]
                .into_iter()
                .enumerate()
            {
                settings
                    .replace(
                        AnalyticsSnapshotConfig {
                            mode: AnalyticsSnapshotMode::Snapshot,
                            page_rollups: mode,
                            ..Default::default()
                        },
                        settings.get().await.revision + 1,
                    )
                    .await;
                let request = test::TestRequest::get().uri(&path).to_request();
                let started = Instant::now();
                let response = test::call_service(&app, request).await;
                assert_eq!(response.status(), 200);
                let response: Value = test::read_body_json(response).await;
                if trial > 0 {
                    samples[index].push(started.elapsed().as_secs_f64() * 1000.0);
                }
                if index == 0 {
                    original = response["data"].clone();
                    assert!(response["meta"]["snapshot_revision"].is_null());
                } else {
                    assert_eq!(response["data"], original);
                    assert!(response["meta"]["snapshot_revision"].is_number());
                }
            }
        }
        for (index, values) in samples.iter_mut().enumerate() {
            values.sort_by(f64::total_cmp);
            let p50 = values[(SAMPLES * 50).div_ceil(100) - 1];
            let p95 = values[(SAMPLES * 95).div_ceil(100) - 1];
            eprintln!(
                "{name} {} p50={p50:.2} ms p95={p95:.2} ms",
                ["before", "after"][index]
            );
        }
    }
    client.execute(
        "INSERT INTO analytics_distribution_30m VALUES (2920, $1, 1,'scanner-0','manual','port','443',42)",
        &[&now],
    ).await.unwrap();
    let started = Instant::now();
    refresh(&pool, now).await.unwrap();
    eprintln!(
        "one changed day published: {:.2}s",
        started.elapsed().as_secs_f64()
    );
    drop(client);
    cleanup(&root_pool, &schema).await;
}
