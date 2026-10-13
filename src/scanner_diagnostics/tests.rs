use super::*;
use crate::admin::UserBaseI;
use crate::config::SecurityConfig;
use crate::middlewares::{ExpectedCsrfToken, csrfmiddleware::CsrfMiddleware};
use actix_web::{App, HttpMessage, dev::Service, http::StatusCode, test, web};

/// Uses a disposable PostgreSQL database only. Never point this at a deployed database.
#[actix_web::test]
#[ignore = "requires NM_DIAGNOSTICS_TEST_DATABASE_URL pointing to a disposable PostgreSQL database"]
async fn authenticated_transfer_deduplicates_errors_and_checks_ownership() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .try_init();
    let url = std::env::var("NM_DIAGNOSTICS_TEST_DATABASE_URL").expect("test database URL");
    assert!(
        url.contains("nm_diagnostics_test"),
        "use the disposable nm_diagnostics_test database"
    );
    let mut config = deadpool_postgres::Config::new();
    config.url = Some(url);
    let pool = config
        .create_pool(
            Some(deadpool_postgres::Runtime::Tokio1),
            tokio_postgres::NoTls,
        )
        .unwrap();
    let client = pool.get().await.unwrap();
    client
        .batch_execute(include_str!("../../source/database/init.sql"))
        .await
        .unwrap();
    client
        .batch_execute(include_str!(
            "../../source/database/migrate_scanner_diagnostics.sql"
        ))
        .await
        .unwrap();
    client
        .batch_execute(include_str!(
            "../../source/database/migrate_scanner_diagnostics.sql"
        ))
        .await
        .unwrap();
    let scanner = Uuid::now_v7();
    let other = Uuid::now_v7();
    let pepper = "test-only-pepper-at-least-thirty-two-bytes".to_owned();
    let token = format!("nm_run_diagnostics_test_{scanner}");
    let other_token = format!("nm_run_other_test_{other}");
    let hash = crate::identity::hash_scanner_token(&token, &pepper).unwrap();
    let other_hash = crate::identity::hash_scanner_token(&other_token, &pepper).unwrap();
    for (id, hash) in [(scanner, &hash), (other, &other_hash)] {
        client.execute("INSERT INTO scanner_info(scanner_id,create_user,is_enable,runtime_token_hash,diagnostics_capabilities) VALUES($1,7,true,$2,$3)", &[&id.to_string(),hash,&json!({"supported_versions":[1],"can_list_logs":true,"can_collect_logs":true,"can_report_errors":true})]).await.unwrap();
    }
    let directory = std::env::temp_dir().join(format!("server-diagnostics-{}", Uuid::now_v7()));
    let state = Diagnostics::new(DiagnosticsConfig {
        directory: directory.clone(),
        ..Default::default()
    })
    .await
    .unwrap();
    let maintenance = web::Data::new(
        crate::system_maintenance::SystemMaintenanceState::from_database(&pool)
            .await
            .unwrap(),
    );
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(state.clone()))
            .app_data(web::Data::new(SecurityConfig {
                scanner_token_pepper: pepper,
            }))
            .app_data(maintenance.clone())
            .wrap(CsrfMiddleware)
            .wrap(crate::api_response::ApiErrorMiddleware)
            .wrap_fn(|req, service| {
                let role = if req.headers().contains_key("X-Test-Reader") {
                    2
                } else {
                    1
                };
                req.extensions_mut().insert(UserBaseI {
                    id: 7,
                    username: "diagnostic-test".into(),
                    role,
                    email: None,
                    limit_login: false,
                    enable_2fa: true,
                });
                req.extensions_mut()
                    .insert(ExpectedCsrfToken::new("test-csrf".into()));
                service.call(req)
            })
            .configure(crate::handlers::scanner_diagnostics::configure),
    )
    .await;

    let events_path = "/api/scanner/diagnostics/events";
    let event = json!({"timestamp":Utc::now(),"level":"ERROR","fields":{"event_id":Uuid::now_v7(),"error_code":"masscan_nonzero_exit","engine":"masscan","operation":"execute_scan_plan","message":"password= hidden https://private.example"}});
    let body = json!({"scanner_id":scanner,"events":[event.clone()]});
    let unauthorized = test::TestRequest::post()
        .uri(events_path)
        .set_json(&body)
        .to_request();
    assert_eq!(
        test::call_service(&app, unauthorized).await.status(),
        StatusCode::UNAUTHORIZED
    );
    for _ in 0..2 {
        let request = test::TestRequest::post()
            .uri(events_path)
            .insert_header(("Authorization", format!("Bearer {token}")))
            .set_json(&body)
            .to_request();
        assert_eq!(
            test::call_service(&app, request).await.status(),
            StatusCode::OK
        );
    }
    let count: i64 = client
        .query_one(
            "SELECT occurrences FROM scanner_incident WHERE scanner_id=$1",
            &[&scanner.to_string()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    let mut oversized_event = event.clone();
    oversized_event["fields"]["message"] = json!("x".repeat(parser::MAX_LINE_BYTES));
    for invalid_events in [vec![event.clone(); 101], vec![oversized_event]] {
        let request = test::TestRequest::post()
            .uri(events_path)
            .insert_header(("Authorization", format!("Bearer {token}")))
            .set_json(json!({"scanner_id":scanner,"events":invalid_events}))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response: Value = test::read_body_json(response).await;
        assert_eq!(response["code"], "invalid_diagnostic_events");
    }
    // Check the actual POST route's wire-size limit as well as the isolated extractor tests.
    for (size, status) in [
        (8 * 1024 * 1024, StatusCode::OK),
        (8 * 1024 * 1024 + 1, StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let mut body = serde_json::to_vec(&json!({"scanner_id":scanner,"events":[]})).unwrap();
        body.resize(size, b' ');
        let request = test::TestRequest::post()
            .uri(events_path)
            .insert_header(("Authorization", format!("Bearer {token}")))
            .insert_header(("Content-Type", "application/json"))
            .set_payload(body)
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), status);
        if status == StatusCode::PAYLOAD_TOO_LARGE {
            let response: Value = test::read_body_json(response).await;
            assert_eq!(response["code"], "payload_too_large");
        }
    }
    let source = SourceFile {
        source_file_id: parser::digest(b"test-source-generation"),
        name: "scanner.log.2026-10-01".into(),
        size_bytes: 0,
        modified_at: Utc::now(),
        active: true,
    };
    client
        .execute(
            "INSERT INTO scanner_log_source(scanner_id,source_file_id,document) VALUES($1,$2,$3)",
            &[&scanner.to_string(), &source.source_file_id, &json!(source)],
        )
        .await
        .unwrap();
    let create_path = format!("/api/scanner/{scanner}/diagnostic-jobs");
    let create_body = json!({"type":"collect_logs","source_file_ids":[source.source_file_id]});
    let no_csrf = test::TestRequest::post()
        .uri(&create_path)
        .set_json(&create_body)
        .to_request();
    assert_eq!(
        test::call_service(&app, no_csrf).await.status(),
        StatusCode::FORBIDDEN
    );
    let reader = test::TestRequest::post()
        .uri(&create_path)
        .insert_header(("X-Test-Reader", "1"))
        .insert_header(("X-CSRF-Token", "test-csrf"))
        .set_json(&create_body)
        .to_request();
    assert_eq!(
        test::call_service(&app, reader).await.status(),
        StatusCode::FORBIDDEN
    );
    let create = test::TestRequest::post()
        .uri(&create_path)
        .insert_header(("X-CSRF-Token", "test-csrf"))
        .set_json(&create_body)
        .to_request();
    let response = test::call_service(&app, create).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let created: Value = test::read_body_json(response).await;
    let job_id: Uuid = serde_json::from_value(created["data"]["job_id"].clone()).unwrap();
    assert_eq!(
        pending_jobs(&pool, scanner).await.unwrap()[0].job_id,
        job_id
    );

    let file_id = Uuid::now_v7();
    let mut log = serde_json::to_vec(&event).unwrap();
    log.push(b'\n');
    // Include a historical format, a malformed line and an oversized line.
    let legacy = json!({"timestamp":"2026-09-30T08:00:00Z","level":"ERROR","fields":{"event":"SCAN-ERROR","message":"legacy failure"}});
    log.extend_from_slice(&serde_json::to_vec(&legacy).unwrap());
    log.extend_from_slice(b"\nmalformed\n");
    log.extend_from_slice(&vec![b'x'; parser::MAX_LINE_BYTES + 1]);
    log.push(b'\n');
    let info = b"{\"timestamp\":\"2026-10-01T00:00:00Z\",\"level\":\"INFO\",\"fields\":{\"message\":\"fixture\"}}\n";
    while log.len() <= CHUNK_BYTES + 123 {
        log.extend_from_slice(info);
    }
    let mut source = source;
    source.size_bytes = log.len() as u64;
    let snapshot = Snapshot {
        file_id,
        source,
        captured_at: Utc::now(),
        size_bytes: log.len() as u64,
        excluded_tail_bytes: 0,
        sha256: parser::digest(&log),
    };
    let manifest = Manifest {
        scanner_id: scanner,
        job_id,
        sources: vec![],
        files: vec![snapshot.clone()],
    };
    for _ in 0..2 {
        let request = test::TestRequest::post()
            .uri("/api/scanner/diagnostics/manifest")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .set_json(&manifest)
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    let mut changed_manifest = manifest.clone();
    changed_manifest.files[0].file_id = Uuid::now_v7();
    let conflict = test::TestRequest::post()
        .uri("/api/scanner/diagnostics/manifest")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(&changed_manifest)
        .to_request();
    assert_eq!(
        test::call_service(&app, conflict).await.status(),
        StatusCode::CONFLICT
    );
    let transfer = format!(
        "/api/scanner/diagnostics/chunk?scanner_id={scanner}&job_id={job_id}&file_id={file_id}&part_index=0"
    );
    let first = &log[..CHUNK_BYTES];
    let cross = test::TestRequest::put()
        .uri(&transfer)
        .insert_header(("Authorization", format!("Bearer {other_token}")))
        .set_payload(first.to_vec())
        .to_request();
    assert_eq!(
        test::call_service(&app, cross).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let too_large = test::TestRequest::put()
        .uri(&transfer)
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_payload(vec![b'x'; CHUNK_BYTES + 1])
        .to_request();
    assert_eq!(
        test::call_service(&app, too_large).await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    for _ in 0..2 {
        let request = test::TestRequest::put()
            .uri(&transfer)
            .insert_header(("Authorization", format!("Bearer {token}")))
            .set_payload(first.to_vec())
            .to_request();
        assert_eq!(
            test::call_service(&app, request).await.status(),
            StatusCode::OK
        );
    }
    let progress=test::TestRequest::get().uri(&format!("/api/scanner/diagnostics/upload-status?scanner_id={scanner}&job_id={job_id}&file_id={file_id}")).insert_header(("Authorization",format!("Bearer {token}"))).to_request();
    let progress: Value = test::call_and_read_body_json(&app, progress).await;
    assert_eq!(progress["parts"], json!([0]));
    let incomplete = test::TestRequest::post()
        .uri("/api/scanner/diagnostics/complete")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(json!({"scanner_id":scanner,"job_id":job_id}))
        .to_request();
    assert_eq!(
        test::call_service(&app, incomplete).await.status(),
        StatusCode::CONFLICT
    );
    let changed = test::TestRequest::put()
        .uri(&transfer)
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_payload(vec![b'x'; CHUNK_BYTES])
        .to_request();
    assert_eq!(
        test::call_service(&app, changed).await.status(),
        StatusCode::CONFLICT
    );
    let tail = &log[CHUNK_BYTES..];
    for (size, status, code) in [
        (
            tail.len() + 1,
            StatusCode::PAYLOAD_TOO_LARGE,
            "log_part_too_large",
        ),
        (
            tail.len() - 1,
            StatusCode::BAD_REQUEST,
            "log_part_incomplete",
        ),
    ] {
        let request = test::TestRequest::put()
            .uri(&transfer.replace("part_index=0", "part_index=1"))
            .insert_header(("Authorization", format!("Bearer {token}")))
            .set_payload(vec![b'x'; size])
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), status);
        let response: Value = test::read_body_json(response).await;
        assert_eq!(response["code"], code);
    }
    let second = test::TestRequest::put()
        .uri(&transfer.replace("part_index=0", "part_index=1"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_payload(log[CHUNK_BYTES..].to_vec())
        .to_request();
    assert_eq!(
        test::call_service(&app, second).await.status(),
        StatusCode::OK
    );
    for _ in 0..2 {
        let request = test::TestRequest::post()
            .uri("/api/scanner/diagnostics/complete")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .set_json(json!({"scanner_id":scanner,"job_id":job_id}))
            .to_request();
        assert_eq!(
            test::call_service(&app, request).await.status(),
            StatusCode::OK
        );
    }
    assert_eq!(std::fs::read(state.file_path(file_id)).unwrap(), log);
    parse_file(&pool, &state, file_id, scanner).await.unwrap();
    parse_file(&pool, &state, file_id, scanner).await.unwrap();
    let occurrences:i64=client.query_one("SELECT occurrences FROM scanner_incident WHERE scanner_id=$1 AND error_code='masscan_nonzero_exit'", &[&scanner.to_string()]).await.unwrap().get(0);
    assert_eq!(occurrences, 1);
    let summary: Value = client
        .query_one(
            "SELECT parse_summary FROM scanner_log_file WHERE file_id=$1",
            &[&file_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(summary["invalid_lines"], 1);
    assert_eq!(summary["oversized_lines"], 1);
    let error_request = test::TestRequest::get()
        .uri(&format!("/api/scanner/{scanner}/errors"))
        .to_request();
    let response = test::call_service(&app, error_request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let errors: Value = test::read_body_json(response).await;
    assert_eq!(errors["data"].as_array().unwrap().len(), 2);
    assert!(!errors.to_string().contains("hidden"));
    assert!(!errors.to_string().contains("private.example"));
    let download_path = format!("/api/scanner/{scanner}/log-files/{file_id}/download");
    let reader = test::TestRequest::get()
        .uri(&download_path)
        .insert_header(("X-Test-Reader", "1"))
        .to_request();
    assert_eq!(
        test::call_service(&app, reader).await.status(),
        StatusCode::FORBIDDEN
    );
    let download = test::TestRequest::get().uri(&download_path).to_request();
    let response = test::call_service(&app, download).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(test::read_body(response).await.as_ref(), log.as_slice());
    let wrong = test::TestRequest::get()
        .uri(&format!(
            "/api/scanner/{other}/log-files/{file_id}/download"
        ))
        .to_request();
    assert_eq!(
        test::call_service(&app, wrong).await.status(),
        StatusCode::NOT_FOUND
    );
    let recovery_time = Utc::now();
    let recovered = json!({"timestamp":recovery_time,"level":"INFO","fields":{"event_id":Uuid::now_v7(),"event":"ScannerOperationRecovered","operation":"send heartbeat"}});
    let late = json!({"timestamp":recovery_time-chrono::Duration::seconds(10),"level":"ERROR","fields":{"event_id":Uuid::now_v7(),"error_code":"server_connect_failed","operation":"send heartbeat"}});
    ingest(&pool, scanner, &[(recovered, None), (late, None)])
        .await
        .unwrap();
    let recovered:Option<chrono::DateTime<Utc>>=client.query_one("SELECT recovered_at FROM scanner_incident WHERE scanner_id=$1 AND error_code='server_connect_failed'", &[&scanner.to_string()]).await.unwrap().get(0);
    assert!(recovered.is_some());
    let newer = json!({"timestamp":recovery_time+chrono::Duration::seconds(1),"level":"ERROR","fields":{"event_id":Uuid::now_v7(),"error_code":"server_connect_failed","operation":"send heartbeat"}});
    ingest(&pool, scanner, &[(newer, None)]).await.unwrap();
    let recovered:Option<chrono::DateTime<Utc>>=client.query_one("SELECT recovered_at FROM scanner_incident WHERE scanner_id=$1 AND error_code='server_connect_failed'", &[&scanner.to_string()]).await.unwrap().get(0);
    assert!(recovered.is_none());
    let bad_job = Uuid::now_v7();
    let bad_file = Uuid::now_v7();
    client.execute("INSERT INTO scanner_diagnostic_job(job_id,scanner_id,kind,status) VALUES($1,$2,'collect_logs','uploading')", &[&bad_job,&scanner.to_string()]).await.unwrap();
    let mut bad_snapshot = snapshot.clone();
    bad_snapshot.file_id = bad_file;
    bad_snapshot.size_bytes = 3;
    bad_snapshot.sha256 = "0".repeat(64);
    client
        .execute(
            "INSERT INTO scanner_log_file(file_id,job_id,scanner_id,snapshot) VALUES($1,$2,$3,$4)",
            &[
                &bad_file,
                &bad_job,
                &scanner.to_string(),
                &json!(bad_snapshot),
            ],
        )
        .await
        .unwrap();
    std::fs::write(state.part_path(bad_file, 0), b"{}\n").unwrap();
    client.execute("INSERT INTO scanner_log_upload_part(file_id,part_index,size_bytes,sha256) VALUES($1,0,3,$2)", &[&bad_file,&parser::digest(b"{}\n")]).await.unwrap();
    let bad = test::TestRequest::post()
        .uri("/api/scanner/diagnostics/complete")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(json!({"scanner_id":scanner,"job_id":bad_job}))
        .to_request();
    assert_eq!(
        test::call_service(&app, bad).await.status(),
        StatusCode::BAD_REQUEST
    );
    let status: String = client
        .query_one(
            "SELECT status FROM scanner_diagnostic_job WHERE job_id=$1",
            &[&bad_job],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(status, "failed");
    drop(app);
    drop(state);
    std::fs::remove_dir_all(directory).unwrap();
}
