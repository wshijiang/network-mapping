use super::*;
use std::time::Duration;
use storage::Source;
use tracing::Instrument;

pub async fn run(
    pool: Pool,
    maintenance: actix_web::web::Data<crate::system_maintenance::SystemMaintenanceState>,
    encryption_key: String,
) {
    let sources = pool.clone();
    let ai = pool;
    let source_maintenance = maintenance.clone();
    let source_key = encryption_key.clone();
    tokio::join!(
        async move {
            loop {
                if !source_maintenance.snapshot().await.enabled {
                    match source_tick(&sources, &source_key).await {
                        Ok(true) => continue,
                        Ok(false) => {}
                        Err(e) => {
                            tracing::warn!(event = "IntelSourceWorkerFailed", code = e.code, diagnostic=%e.diagnostic)
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        },
        async move {
            loop {
                if !maintenance.snapshot().await.enabled
                    && let Err(e) = ai_tick(&ai, &encryption_key).await
                {
                    tracing::warn!(event = "IntelAiWorkerFailed", code = e.code, diagnostic=%e.diagnostic);
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    );
}
pub(super) async fn source_tick(pool: &Pool, encryption_key: &str) -> Result<bool> {
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    tx.execute("UPDATE intel_sync_run SET status='failed',error_code='intel_attempts_exhausted',finished_at=NOW() WHERE status='running' AND lease_until<NOW() AND attempts>=3",&[]).await?;
    tx.execute("UPDATE intel_sync_run j SET status='cancelled',error_code='intel_source_changed',finished_at=NOW() FROM intel_source s WHERE j.source_id=s.id AND j.status IN ('queued','running') AND (NOT s.enabled OR s.revision<>j.source_revision)",&[]).await?;
    let due=tx.query("SELECT s.id,s.revision,s.interval_seconds FROM intel_source s WHERE s.enabled AND s.next_check_at<=NOW() AND ((s.transport NOT IN ('upload','manual') AND s.kind<>'threatfox_export') OR EXISTS(SELECT 1 FROM intel_import_snapshot i WHERE i.source_id=s.id AND i.source_revision=s.revision AND i.stage<>'complete' AND NOT i.paused)) ORDER BY s.next_check_at FOR UPDATE OF s SKIP LOCKED LIMIT 20",&[]).await?;
    for row in due {
        let source: Uuid = row.get("id");
        let revision: i64 = row.get("revision");
        let interval: i32 = row.get("interval_seconds");
        tx.execute("INSERT INTO intel_sync_run(id,source_id,source_revision) VALUES($1,$2,$3) ON CONFLICT(source_id) WHERE status IN ('queued','running') DO NOTHING",&[&Uuid::now_v7(),&source,&revision]).await?;
        tx.execute("UPDATE intel_source SET next_check_at=NOW()+$2::INTEGER*INTERVAL '1 second' WHERE id=$1",&[&source,&interval]).await?;
    }
    let row=tx.query_opt("SELECT * FROM intel_sync_run WHERE ((status='queued' AND available_at<=NOW()) OR (status='running' AND lease_until<NOW())) AND attempts<3 ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1",&[]).await?;
    let Some(row) = row else {
        tx.commit().await?;
        return Ok(false);
    };
    let id: Uuid = row.get("id");
    let source_id: Uuid = row.get("source_id");
    let revision: i64 = row.get("source_revision");
    let token = Uuid::new_v4();
    tx.execute("UPDATE intel_sync_run SET status='running',attempts=attempts+1,claim_token=$2,lease_until=NOW()+INTERVAL '3 minutes' WHERE id=$1",&[&id,&token]).await?;
    tx.commit().await?;
    drop(c);
    let result = tokio::time::timeout(
        Duration::from_secs(150),
        sync(
            pool,
            source_id,
            revision,
            Some(storage::Fence::Sync(id, token)),
            encryption_key,
        ),
    )
    .await
    .unwrap_or_else(|_| Err(Error::bad("intel_sync_timeout")));
    let (state, summary, error) = match result {
        Ok((summary, partial)) => (if partial { "partial" } else { "succeeded" }, summary, None),
        Err(e) => {
            let code = e.code;
            let diagnostic = e.stage("source_sync").context(json!({
                "run_id":id,"source_id":source_id,"claim_token":token,"attempt":row.get::<_,i32>("attempts")+1
            })).report();
            tracing::warn!(event="IntelSourceSyncFailed",run_id=%id,source_id=%source_id,claim_token=%token,
                attempt=row.get::<_,i32>("attempts")+1,code,diagnostic=%diagnostic);
            ("failed", json!({"last_error":diagnostic}), Some(code))
        }
    };
    let c = pool.get().await?;
    c.execute("UPDATE intel_sync_run SET status=$3,summary=$4,error_code=$5,finished_at=NOW(),claim_token=NULL,lease_until=NULL WHERE id=$1 AND claim_token=$2 AND lease_until>NOW()",&[&id,&token,&state,&summary,&error]).await?;
    if state == "partial" {
        let delay = if summary.get("offline_import") == Some(&json!(true)) {
            0_i32
        } else {
            5
        };
        c.execute("UPDATE intel_source SET next_check_at=NOW()+$3::INTEGER*INTERVAL '1 second' WHERE id=$1 AND revision=$2",&[&source_id,&revision,&delay]).await?;
    }
    Ok(true)
}
pub(super) async fn sync(
    pool: &Pool,
    id: Uuid,
    revision: i64,
    fence: Option<storage::Fence>,
    encryption_key: &str,
) -> Result<(Value, bool)> {
    let mut s = storage::get_source(pool, id).await?;
    s.fence = fence;
    if s.revision != revision || !s.input.enabled {
        return Err(Error::conflict());
    }
    if s.input.transport == "upload" || s.input.kind == "threatfox_export" {
        return imports::sync(pool, &s).await;
    }
    if s.input.kind == "article" {
        return Err(Error::bad("intel_article_submission_required"));
    }
    let data = client::source_bytes(&s, encryption_key).await?;
    match s.input.kind.as_str() {
        "mitre_stix" => Ok((
            json!({"entities":storage::import_stix(pool,&s,&data).await?,"dataset_hash":digest(&data)}),
            false,
        )),
        "rss" => {
            let links = parse::rss(&data, &s.input.allowed_hosts)?;
            let mut c = pool.get().await?;
            let tx = c.transaction().await?;
            storage::validate_source(&tx, &s).await?;
            let mut added = 0;
            for mut link in links {
                link.url = articles::canonical_url(&link.url, &s.input)?;
                added+=tx.execute("INSERT INTO intel_article(id,source_id,source_revision,url,title,feed_hash) SELECT $1,$2,$3,$4,$5,$6 WHERE EXISTS(SELECT 1 FROM intel_source WHERE id=$2 AND revision=$3 AND enabled) ON CONFLICT(source_id,url,feed_hash,source_revision) DO NOTHING",&[&Uuid::now_v7(),&s.id,&s.revision,&link.url,&link.title,&link.fingerprint]).await?;
            }
            tx.commit().await?;
            drop(c);
            Ok((
                json!({"articles_added":added,"ai_enabled":storage::settings(pool).await?.0.ai_enabled}),
                false,
            ))
        }
        "eset_github" => github(pool, &s, &data).await,
        kind => {
            let (entries, validation) = if kind == "threatfox" {
                parse::threatfox_document(&data, kind, true)?
            } else {
                (parse::indicators(&data, kind)?, ValidationReport::default())
            };
            let total = entries.len();
            let added = batch::ingest_all(pool, &s, entries, "").await?;
            Ok((
                json!({"received":total as i64+validation.rejected,"accepted":total,"added":added,"validation":validation,"require_review":s.input.require_review}),
                false,
            ))
        }
    }
}
async fn github(pool: &Pool, s: &Source, data: &[u8]) -> Result<(Value, bool)> {
    let tree: Value =
        serde_json::from_slice(data).map_err(|_| Error::bad("intel_invalid_github_tree"))?;
    if tree.get("truncated") == Some(&json!(true)) {
        return Err(Error::bad("intel_github_tree_truncated"));
    }
    let files = tree
        .get("tree")
        .and_then(Value::as_array)
        .filter(|v| v.len() <= 100_000)
        .ok_or_else(|| Error::bad("intel_invalid_github_tree"))?;
    let tree_sha = tree
        .get("sha")
        .and_then(Value::as_str)
        .filter(|v| v.len() == 40 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| Error::bad("intel_invalid_github_tree"))?;
    let url = reqwest::Url::parse(&s.input.location)
        .map_err(|_| Error::bad("intel_invalid_github_tree"))?;
    let parts = url.path().split('/').collect::<Vec<_>>();
    if parts.len() < 7 {
        return Err(Error::bad("intel_invalid_github_tree"));
    }
    let owner = parts[2];
    let repo = parts[3];
    let c = pool.get().await?;
    let known = c
        .query(
            "SELECT path,content_hash,parser_version FROM intel_source_file WHERE source_id=$1",
            &[&s.id],
        )
        .await?
        .into_iter()
        .map(|r| {
            (
                r.get::<_, String>(0),
                (r.get::<_, String>(1), r.get::<_, i32>(2)),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    drop(c);
    let mut pending = vec![];
    for f in files {
        let path = f.get("path").and_then(Value::as_str).unwrap_or("");
        let lower = path.to_ascii_lowercase();
        if f.get("type").and_then(Value::as_str) != Some("blob")
            || lower.ends_with("readme.md")
            || ![".md5", ".sha1", ".sha256", ".csv", ".txt", ".md", ".json"]
                .iter()
                .any(|ext| lower.ends_with(ext))
        {
            continue;
        }
        let sha = f
            .get("sha")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::bad("intel_invalid_github_tree"))?;
        if !github_file_current(path, sha, known.get(path)) {
            pending.push((path, sha));
        }
    }
    let partial = pending.len() > 20;
    let mut added = 0;
    let mut parsed = 0;
    let mut unsupported = 0;
    let mut unsupported_paths = Vec::new();
    let mut validation = ValidationReport::default();
    for (path, sha) in pending.into_iter().take(20) {
        // URL path segments are encoded, not interpolated as a URL/query.
        let mut raw = reqwest::Url::parse("https://raw.githubusercontent.com/").unwrap();
        {
            let mut segments = raw
                .path_segments_mut()
                .map_err(|_| Error::bad("intel_invalid_github_path"))?;
            segments.clear();
            segments.push(owner).push(repo).push(parts[6]);
            for part in path.split('/') {
                segments.push(part);
            }
        }
        let data = client::request(raw.as_str(), &s.input.allowed_hosts, None, None).await?;
        let (count, supported, report) = github_file(pool, s, path, sha, &data).await?;
        validation.merge(report, path);
        added += count;
        if supported {
            parsed += 1;
        } else {
            unsupported += 1;
            unsupported_paths.push(path.chars().take(512).collect::<String>());
        }
    }
    Ok((
        json!({"added":added,"files_parsed":parsed,"unsupported_files":unsupported,"unsupported_paths":unsupported_paths,"validation":validation,"more_files":partial,"tree_sha":tree_sha}),
        partial,
    ))
}
pub(super) fn github_format(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".json") {
        "json"
    } else if lower.ends_with(".md") {
        "markdown"
    } else {
        "lines"
    }
}
pub(super) fn github_file_current(_path: &str, sha: &str, known: Option<&(String, i32)>) -> bool {
    let Some((hash, version)) = known else {
        return false;
    };
    // Version 3 repairs URL protocol, IDN, BOM and CSV compatibility, including
    // files older parsers marked processed after skipping their valid records.
    hash == sha && *version >= 3
}
pub(super) async fn github_file(
    pool: &Pool,
    s: &Source,
    path: &str,
    sha: &str,
    data: &[u8],
) -> Result<(usize, bool, ValidationReport)> {
    // The manifest carries a tree OID, not a commit OID. Verify the blob
    // before applying the case-insensitive format or marking its cursor.
    let mut blob = format!("blob {}\0", data.len()).into_bytes();
    blob.extend_from_slice(data);
    let actual = openssl::hash::hash(openssl::hash::MessageDigest::sha1(), &blob)
        .map_err(|_| Error::bad("intel_blob_hash_failed"))?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if actual != sha {
        return Err(Error::bad("intel_github_snapshot_changed"));
    }
    let mut added = 0;
    let entries = parse::github_indicators(data, github_format(path));
    let mut validation = ValidationReport::default();
    let supported = match entries {
        Ok((entries, report)) => {
            validation = report;
            added = batch::ingest_all(pool, s, entries, &format!("{path}#")).await?;
            true
        }
        Err(e)
            if matches!(
                e.code,
                "intel_no_supported_indicators"
                    | "intel_invalid_json"
                    | "intel_invalid_ioc_document"
                    | "intel_invalid_indicator"
                    | "intel_invalid_csv"
            ) =>
        {
            if e.code == "intel_invalid_json" {
                tracing::warn!(
                    path,
                    code = e.code,
                    "Skipping malformed JSON in IOC repository; no indicators from this file were published"
                );
            }
            false
        }
        Err(e) => return Err(e),
    };
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    storage::validate_source(&tx, s).await?;
    tx.execute("INSERT INTO intel_source_file(source_id,path,content_hash,parser_version) VALUES($1,$2,$3,3) ON CONFLICT(source_id,path) DO UPDATE SET content_hash=EXCLUDED.content_hash,parser_version=EXCLUDED.parser_version",&[&s.id,&path,&sha]).await?;
    tx.commit().await?;
    Ok((added, supported, validation))
}

pub(super) async fn ai_tick(pool: &Pool, encryption_key: &str) -> Result<bool> {
    let (settings, settings_revision) = storage::settings(pool).await?;
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    tx.execute("UPDATE intel_article a SET status='cancelled',error_code='intel_source_changed',claim_token=NULL,lease_until=NULL FROM intel_source s WHERE a.source_id=s.id AND a.status IN ('queued','running') AND (a.source_revision<>s.revision OR NOT s.enabled OR s.kind NOT IN ('rss','article'))",&[]).await?;
    if !settings.ai_enabled {
        tx.commit().await?;
        return Ok(false);
    }
    tx.execute("UPDATE intel_article SET status='failed',error_code='intel_attempts_exhausted' WHERE status='running' AND lease_until<NOW() AND attempts>=3",&[]).await?;
    let row=tx.query_opt("SELECT a.* FROM intel_article a JOIN intel_source s ON s.id=a.source_id WHERE s.enabled AND s.kind IN ('rss','article') AND a.source_revision=s.revision AND ((a.status='queued' AND a.available_at<=NOW()) OR (a.status='running' AND a.lease_until<NOW())) AND a.attempts<3 ORDER BY a.created_at FOR UPDATE OF a SKIP LOCKED LIMIT 1",&[]).await?;
    let Some(row) = row else {
        tx.commit().await?;
        return Ok(false);
    };
    let id: Uuid = row.get("id");
    let source_id: Uuid = row.get("source_id");
    let url: String = row.get("url");
    let token = Uuid::new_v4();
    tx.execute("UPDATE intel_article SET status='running',attempts=attempts+1,claim_token=$2,lease_until=NOW()+$3::INTEGER*INTERVAL '1 second' WHERE id=$1",&[&id,&token,&settings.ai_lease_seconds()]).await?;
    tx.commit().await?;
    drop(c);
    let result = extract(
        pool,
        id,
        source_id,
        &url,
        AiConfig {
            settings: &settings,
            revision: settings_revision,
            encryption_key,
        },
        token,
    )
    .instrument(
        tracing::info_span!("intel_article",article_id=%id,source_id=%source_id,claim_token=%token),
    )
    .await;
    let (state, error, diagnostic, summary) = match result {
        Ok(summary) => {
            tracing::info!(event="IntelArticleExtractionSucceeded",article_id=%id,source_id=%source_id,
                claim_token=%token,indicators=summary.parsed,inserted=summary.inserted,
                rejected=summary.validation.rejected);
            (summary.state(), None, Value::Null, json!(summary))
        }
        Err(e) => {
            let code = e.code;
            let diagnostic = e
                .context(json!({"article_id":id,"source_id":source_id,
                "claim_token":token,"attempt":row.get::<_,i32>("attempts")+1}))
                .report();
            tracing::warn!(event="IntelArticleExtractionFailed",article_id=%id,source_id=%source_id,
                claim_token=%token,attempt=row.get::<_,i32>("attempts")+1,code,diagnostic=%diagnostic);
            (
                if code == "intel_ai_disabled" {
                    "queued"
                } else {
                    "failed"
                },
                Some(code),
                diagnostic,
                Value::Null,
            )
        }
    };
    pool.get().await?.execute(r#"
        UPDATE intel_article a SET
          status=CASE WHEN a.source_revision<>s.revision OR NOT s.enabled OR s.kind NOT IN ('rss','article') THEN 'cancelled' ELSE $3 END,
          error_code=CASE WHEN a.source_revision<>s.revision OR NOT s.enabled OR s.kind NOT IN ('rss','article') THEN 'intel_source_changed' ELSE $4 END,
          attempts=CASE WHEN $3='queued' THEN GREATEST(a.attempts-1,0) ELSE a.attempts END,
          extraction_metadata=(a.extraction_metadata-'last_error'-'result') || CASE WHEN $5::JSONB='null'::JSONB THEN jsonb_build_object('result',$6::JSONB) ELSE jsonb_build_object('last_error',$5::JSONB) END,
          claim_token=NULL,lease_until=NULL
        FROM intel_source s WHERE a.source_id=s.id AND a.id=$1 AND a.claim_token=$2
          AND a.status='running' AND a.lease_until>NOW()
        "#, &[&id,&token,&state,&error,&diagnostic,&summary]).await?;
    Ok(true)
}
struct AiConfig<'a> {
    settings: &'a Settings,
    revision: i64,
    encryption_key: &'a str,
}
#[derive(Serialize)]
struct ExtractionSummary {
    parsed: usize,
    inserted: usize,
    validation: ValidationReport,
}
impl ExtractionSummary {
    fn state(&self) -> &'static str {
        if self.parsed == 0 {
            "succeeded"
        } else {
            "proposed"
        }
    }
}
async fn extract(
    pool: &Pool,
    id: Uuid,
    source_id: Uuid,
    url: &str,
    config: AiConfig<'_>,
    token: Uuid,
) -> Result<ExtractionSummary> {
    let started = std::time::Instant::now();
    let mut stage = "source_load";
    let processing_timeout = config.settings.ai_processing_timeout();
    let result = tokio::time::timeout(processing_timeout, async {
        let AiConfig {
            settings,
            revision: settings_revision,
            encryption_key,
        } = config;
        let mut source = storage::get_source(pool, source_id).await?;
        source.fence = Some(storage::Fence::Article(id, token));
        if !source.input.enabled || !matches!(source.input.kind.as_str(), "rss" | "article") {
            return Err(Error::bad("intel_source_disabled"));
        }
        stage = "article_load";
        let saved = pool
            .get()
            .await?
            .query_one(
                "SELECT body,source_revision,extraction_metadata FROM intel_article WHERE id=$1",
                &[&id],
            )
            .await?;
        if saved.get::<_, i64>("source_revision") != source.revision {
            return Err(Error::bad("intel_source_changed"));
        }
        let mut metadata: Value = saved.get("extraction_metadata");
        if let Some(fields) = metadata.as_object_mut() {
            // Previous run results are not part of a new proposal's identity.
            fields.remove("last_error");
            fields.remove("result");
            fields.remove("ai_usage");
        }
        let body = if let Some(body) = saved.get::<_, Option<String>>("body") {
            body
        } else {
            stage = "article_fetch";
            let data = client::request_bounded(
                url,
                &source.input.allowed_hosts,
                None,
                None,
                2 * 1024 * 1024,
            )
            .await?;
            stage = "article_parse";
            let (body, intake) = articles::body_snapshot(&data, url, &source.input.publisher_id)?;
            metadata["intake"] = intake;
            body
        };
        let body_hash = digest(body.as_bytes());
        stage = "body_store";
        let mut c = pool.get().await?;
        let tx = c.transaction().await?;
        storage::validate_source(&tx, &source).await?;
        metadata["model"] = json!(settings.ai_model);
        metadata["settings_revision"] = json!(settings_revision);
        metadata["prompt_version"] = json!(PROMPT_VERSION);
        metadata["evidence_version"] = json!("block-spans-v1");
        metadata["body_hash"] = json!(body_hash);
        metadata.as_object_mut().map(|fields| fields.remove("candidates_hash"));
        metadata["ai_protocol"] = json!(settings.ai_protocol);
        metadata["max_output_tokens"] = json!(settings.ai_max_output_tokens);
        metadata["reasoning_effort"] = json!(settings.ai_reasoning_effort);
        let changed=tx.execute("UPDATE intel_article SET body=$3,body_hash=$4,extraction_metadata=$5 WHERE id=$1 AND claim_token=$2 AND lease_until>NOW()",&[&id,&token,&body,&body_hash,&metadata]).await?;
        if changed == 0 {
            return Err(Error::bad("intel_ai_lease_lost"));
        }
        tx.commit().await?;
        drop(c);
        stage = "ai_settings";
        if !storage::settings(pool).await?.0.ai_enabled {
            return Err(Error::bad("intel_ai_disabled"));
        }
        let key = storage::ai_credential(pool, settings, settings_revision, encryption_key).await?;
        let blocks = evidence::Document::new(&body).prompt_blocks();
        stage = "ai_request";
        let (data, input_diagnostic) = ai::request(settings, &key, &blocks, url).await?;
        stage = "ai_response";
        let (content, mut response_diagnostic) = ai::response_content(&data, &settings.ai_protocol)
            .map_err(|error| error.context(input_diagnostic.clone()))?;
        if let (Some(target), Some(source)) = (response_diagnostic.as_object_mut(), input_diagnostic.as_object()) {
            target.extend(source.clone());
        }
        let c = pool.get().await?;
        c.execute("UPDATE intel_article SET extraction_metadata=extraction_metadata || jsonb_build_object('ai_usage',$3::JSONB) WHERE id=$1 AND claim_token=$2 AND lease_until>NOW()", &[&id,&token,&response_diagnostic]).await?;
        drop(c);
        stage = "ai_validate";
        let (entries, validation) = parse::ai_result_isolated(&content, &body)
            .map_err(|error| error.context(response_diagnostic))?;
        let count = entries.len();
        let (current, revision) = storage::settings(pool).await?;
        if !current.ai_enabled {
            return Err(Error::bad("intel_ai_disabled"));
        }
        if revision != settings_revision {
            return Err(Error::bad("intel_ai_settings_changed"));
        }
        let c = pool.get().await?;
        let active:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM intel_article WHERE id=$1 AND claim_token=$2 AND lease_until>NOW())",&[&id,&token]).await?.get(0);
        drop(c);
        if !active {
            return Err(Error::bad("intel_ai_lease_lost"));
        }
        stage = "indicator_store";
        let inserted = storage::ingest_ai_report(pool, &source, entries, id, settings_revision, url).await?;
        Ok(ExtractionSummary { parsed: count, inserted, validation })
    })
    .await
    .unwrap_or_else(|_| Err(Error::bad("intel_ai_timeout")));
    result.map_err(|e: Error| {
        let e = if e.diagnostic.get("stage").is_none() {
            e.stage(stage)
        } else {
            e
        };
        e.context(json!({
            "total_elapsed_ms":started.elapsed().as_millis() as u64,
            "processing_timeout_seconds":processing_timeout.as_secs()
        }))
    })
}

pub(super) fn ai_response_content(data: &[u8]) -> Result<(String, Value)> {
    let value: Value = serde_json::from_slice(data).map_err(|error| {
        Error::bad("intel_ai_invalid_response")
            .context(parse::json_error_diagnostic(&error))
            .context(json!({
                "reason":"invalid_json",
                "response_bytes":data.len()
            }))
    })?;
    // Only allowlisted classifications leave this function. Provider-controlled
    // finish reasons, refusal text, reasoning, and response content can hold secrets.
    let finish_reason = match value
        .pointer("/choices/0/finish_reason")
        .and_then(Value::as_str)
    {
        Some(reason @ ("stop" | "length" | "content_filter" | "tool_calls" | "function_call")) => {
            reason
        }
        None if value
            .pointer("/choices/0/finish_reason")
            .is_none_or(Value::is_null) =>
        {
            "missing"
        }
        _ => "other",
    };
    let refusal = ai_field_present(value.pointer("/choices/0/message/refusal"));
    let reasoning = ai_field_present(value.pointer("/choices/0/message/reasoning_content"))
        || ai_field_present(value.pointer("/choices/0/message/reasoning"));
    let content_value = value.pointer("/choices/0/message/content");
    let content = content_value.and_then(Value::as_str);
    let diagnostic = json!({"finish_reason":finish_reason,"response_bytes":data.len(),
        "content_bytes":content.map_or(0, str::len),"refusal_present":refusal,
        "reasoning_content_present":reasoning,"content_format":content.map(parse::ai_content_format).unwrap_or(if content_value.is_some_and(Value::is_null) {"empty"} else {"missing"})});
    let failure = match finish_reason {
        "length" => Some(("intel_ai_output_truncated", "output_limit")),
        "content_filter" => Some(("intel_ai_content_filtered", "content_filtered")),
        "tool_calls" | "function_call" => {
            Some(("intel_ai_invalid_response", "unexpected_tool_call"))
        }
        _ if refusal => Some(("intel_ai_refused", "model_refusal")),
        _ => None,
    };
    if let Some((code, reason)) = failure {
        return Err(Error::bad(code)
            .context(diagnostic)
            .context(json!({"reason":reason})));
    }
    if content_value.is_some_and(Value::is_null) {
        return Err(Error::bad("intel_ai_empty_content")
            .context(diagnostic)
            .context(json!({
                "reason":if reasoning {"reasoning_only"} else {"empty_content"}
            })));
    }
    let content = content.ok_or_else(|| {
        Error::bad("intel_ai_invalid_response")
            .context(diagnostic.clone())
            .context(json!({
                "reason":"missing_chat_content","expected_field":"choices[0].message.content",
                "responses_output_present":value.get("output").is_some()
            }))
    })?;
    if content.trim().is_empty() {
        return Err(Error::bad("intel_ai_empty_content")
            .context(diagnostic)
            .context(json!({
                "reason":if reasoning {"reasoning_only"} else {"empty_content"}
            })));
    }
    Ok((content.to_owned(), diagnostic))
}

fn ai_field_present(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::String(text)) => !text.trim().is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(fields)) => !fields.is_empty(),
        Some(_) => true,
    }
}

pub(super) fn ai_request_error(mut error: Error) -> Error {
    let cause = error.code;
    error.code = match cause {
        "intel_source_transport" => "intel_ai_transport",
        "intel_source_timeout" => "intel_ai_request_timeout",
        "intel_dns_failed" => "intel_ai_dns_failed",
        "intel_proxy_dns_failed" => "intel_ai_proxy_dns_failed",
        "intel_source_http_status" => "intel_ai_http_status",
        "intel_source_rate_limited" => "intel_ai_rate_limited",
        "intel_source_too_large" => "intel_ai_response_too_large",
        _ => "intel_ai_request_failed",
    };
    error.context(json!({"cause_code":cause}))
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn empty_extractions_are_completed_without_claiming_to_create_proposals() {
        let mut summary = ExtractionSummary {
            parsed: 0,
            inserted: 0,
            validation: ValidationReport::default(),
        };
        assert_eq!(summary.state(), "succeeded");
        summary.parsed = 2;
        assert_eq!(summary.state(), "proposed");
        assert_eq!(json!(summary)["inserted"], 0);
    }

    #[test]
    fn incompatible_ai_responses_have_safe_format_diagnostics() {
        let chat = br#"{"choices":[{"message":{"content":"{\"iocs\":[]}"}}]}"#;
        assert_eq!(ai_response_content(chat).unwrap().0, r#"{"iocs":[]}"#);
        let responses =
            br#"{"output":[{"content":[{"type":"output_text","text":"private report content"}]}]}"#;
        let error = ai_response_content(responses).unwrap_err();
        assert_eq!(error.code, "intel_ai_invalid_response");
        assert_eq!(error.diagnostic["responses_output_present"], true);
        assert_eq!(error.diagnostic["reason"], "missing_chat_content");
        assert!(
            !error
                .report()
                .to_string()
                .contains("private report content")
        );
        let error = ai_response_content(b"<html>private proxy error</html>").unwrap_err();
        assert_eq!(error.diagnostic["reason"], "invalid_json");
        assert!(error.diagnostic["json_line"].is_number());
        assert!(!error.report().to_string().contains("private proxy error"));
    }

    #[test]
    fn ai_completion_failures_are_distinct_and_never_accept_truncated_valid_json() {
        for (finish, message, code, reason) in [
            (
                "length",
                json!({"content":"{\"iocs\":[]}"}),
                "intel_ai_output_truncated",
                "output_limit",
            ),
            (
                "content_filter",
                json!({"content":null}),
                "intel_ai_content_filtered",
                "content_filtered",
            ),
            (
                "stop",
                json!({"content":"{\"iocs\":[]}","refusal":"private-refusal-text"}),
                "intel_ai_refused",
                "model_refusal",
            ),
            (
                "stop",
                json!({"content":" \n\t"}),
                "intel_ai_empty_content",
                "empty_content",
            ),
            (
                "stop",
                json!({"content":null,"reasoning_content":"private-reasoning-text"}),
                "intel_ai_empty_content",
                "reasoning_only",
            ),
            (
                "tool_calls",
                json!({"content":null,"tool_calls":[{"private":"private-tool-data"}]}),
                "intel_ai_invalid_response",
                "unexpected_tool_call",
            ),
        ] {
            let response = json!({"choices":[{"finish_reason":finish,"message":message}]});
            let error = ai_response_content(&serde_json::to_vec(&response).unwrap()).unwrap_err();
            assert_eq!(error.code, code);
            assert_eq!(error.diagnostic["reason"], reason);
            assert_eq!(error.diagnostic["finish_reason"], finish);
            assert!(error.diagnostic["content_bytes"].is_number());
            assert!(error.diagnostic["content_format"].is_string());
            assert!(!error.report().to_string().contains("private-"));
        }
    }

    #[test]
    fn ai_validation_errors_keep_safe_response_metadata_without_raw_provider_values() {
        let response = json!({"choices":[{"finish_reason":"private-provider-value","message":{
            "content":"```json\n{\"iocs\":[]}\n```", "reasoning_content":"private-reasoning-text"
        }}]});
        let (content, diagnostic) =
            ai_response_content(&serde_json::to_vec(&response).unwrap()).unwrap();
        let error = parse::ai_result_isolated(&content, "private-article-text")
            .map_err(|error| error.context(diagnostic))
            .unwrap_err();
        assert_eq!(error.code, "intel_ai_invalid_json");
        assert_eq!(error.diagnostic["finish_reason"], "other");
        assert_eq!(error.diagnostic["content_format"], "markdown_fence");
        assert_eq!(error.diagnostic["reasoning_content_present"], true);
        assert_eq!(error.diagnostic["refusal_present"], false);
        assert_eq!(error.diagnostic["content_bytes"], content.len());
        assert!(error.diagnostic["response_bytes"].is_number());
        assert!(error.diagnostic["json_line"].is_number());
        assert!(!error.report().to_string().contains("private-"));
        assert!(!error.report().to_string().contains("```"));
    }

    #[test]
    fn ai_network_failures_keep_cause_and_do_not_claim_article_fetch_failed() {
        for (cause, code) in [
            ("intel_source_transport", "intel_ai_transport"),
            ("intel_source_timeout", "intel_ai_request_timeout"),
            ("intel_dns_failed", "intel_ai_dns_failed"),
            ("intel_proxy_dns_failed", "intel_ai_proxy_dns_failed"),
            ("intel_source_http_status", "intel_ai_http_status"),
            ("intel_source_rate_limited", "intel_ai_rate_limited"),
            ("intel_source_too_large", "intel_ai_response_too_large"),
            ("intel_private_address_forbidden", "intel_ai_request_failed"),
        ] {
            let error = ai_request_error(Error::bad(cause).context(json!({"http_status":503})));
            assert_eq!(error.code, code);
            assert_eq!(error.diagnostic["cause_code"], cause);
            assert_eq!(error.diagnostic["http_status"], 503);
        }
    }
}
