//! Scanner diagnostics control plane, durable event ingestion and private log storage.
pub mod parser;
pub mod protocol;
#[cfg(test)]
mod tests;

use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use protocol::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{io, path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct DiagnosticsConfig {
    pub enabled: bool,
    pub directory: PathBuf,
    pub log_retention_days: u32,
    pub error_retention_days: u32,
    pub max_storage_bytes: u64,
    pub auto_collect: bool,
}

impl Default for DiagnosticsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            directory: "./diagnostics".into(),
            log_retention_days: 30,
            error_retention_days: 90,
            max_storage_bytes: 10 * MAX_JOB_BYTES,
            auto_collect: false,
        }
    }
}

impl DiagnosticsConfig {
    pub fn validate(&self) -> Result<()> {
        if self.directory.as_os_str().is_empty()
            || !(1..=3650).contains(&self.log_retention_days)
            || !(1..=3650).contains(&self.error_retention_days)
            || self.max_storage_bytes < MAX_JOB_BYTES
        {
            return Err("invalid scanner_diagnostics configuration".into());
        }
        Ok(())
    }
}

pub struct Diagnostics {
    _storage_lock: Option<std::fs::File>,
    pub config: DiagnosticsConfig,
    pub transfer_slots: Semaphore,
    locks: Vec<Mutex<()>>,
}

impl Diagnostics {
    pub async fn new(mut config: DiagnosticsConfig) -> io::Result<Arc<Self>> {
        let mut storage_lock = None;
        if config.enabled {
            tokio::fs::create_dir_all(&config.directory).await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(
                    &config.directory,
                    std::fs::Permissions::from_mode(0o700),
                )
                .await?;
            }
            config.directory = tokio::fs::canonicalize(&config.directory).await?;
            let lock = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(config.directory.join(".storage.lock"))?;
            fs2::FileExt::try_lock_exclusive(&lock)?;
            storage_lock = Some(lock);
        }
        Ok(Arc::new(Self {
            _storage_lock: storage_lock,
            config,
            transfer_slots: Semaphore::new(2),
            locks: (0..64).map(|_| Mutex::new(())).collect(),
        }))
    }

    pub async fn lock(&self, id: Uuid) -> tokio::sync::MutexGuard<'_, ()> {
        self.locks[(id.as_u128() % 64) as usize].lock().await
    }

    pub fn file_path(&self, id: Uuid) -> PathBuf {
        self.config.directory.join(format!("{id}.jsonl"))
    }
    pub fn part_path(&self, id: Uuid, part: u32) -> PathBuf {
        self.config.directory.join(format!("{id}.{part}.part"))
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Health {
    pub accepting_tasks: bool,
    pub status: String,
    pub dropped_events: u64,
}

pub async fn pending_jobs(pool: &Pool, scanner_id: Uuid) -> Result<Vec<Job>> {
    let client = pool.get().await?;
    let rows = client.query("SELECT job_id,kind,source_file_ids,expires_at FROM scanner_diagnostic_job \
        WHERE scanner_id=$1 AND status IN ('queued','accepted','uploading') AND expires_at>NOW() ORDER BY created_at LIMIT 2", &[&scanner_id.to_string()]).await?;
    rows.into_iter()
        .map(|row| {
            Ok(Job {
                job_id: row.get("job_id"),
                kind: serde_json::from_value(json!(row.get::<_, String>("kind")))?,
                protocol_version: VERSION,
                source_file_ids: serde_json::from_value(row.get("source_file_ids"))?,
                expires_at: row.get("expires_at"),
            })
        })
        .collect()
}

pub type EventRecord = (Value, Option<(Uuid, i64, i64)>);

pub async fn ingest(pool: &Pool, scanner_id: Uuid, records: &[EventRecord]) -> Result<Vec<String>> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let scanner = scanner_id.to_string();
    let mut confirmed = Vec::new();
    let mut source_cache = std::collections::HashMap::<Uuid, String>::new();
    for (value, evidence) in records {
        let fallback = if value
            .pointer("/fields/event_id")
            .and_then(Value::as_str)
            .is_some_and(|id| Uuid::parse_str(id).is_ok())
        {
            String::new()
        } else if let Some((file, _, offset)) = evidence {
            // A stable source generation + offset survives overlapping file snapshots.
            let source = if let Some(source) = source_cache.get(file) {
                source.clone()
            } else {
                let source:String=tx.query_one("SELECT snapshot->'source'->>'source_file_id' FROM scanner_log_file WHERE file_id=$1", &[file]).await?.get(0);
                source_cache.insert(*file, source.clone());
                source
            };
            parser::digest(
                format!(
                    "{source}:{offset}:{}",
                    parser::digest(value.to_string().as_bytes())
                )
                .as_bytes(),
            )
        } else {
            String::new()
        };
        if let Some((operation, occurred_at)) = parser::recovery(value) {
            tx.execute("INSERT INTO scanner_diagnostic_recovery(scanner_id,operation,recovered_at) VALUES($1,$2,$3) \
                ON CONFLICT(scanner_id,operation) DO UPDATE SET recovered_at=GREATEST(scanner_diagnostic_recovery.recovered_at,EXCLUDED.recovered_at)", &[&scanner,&operation,&occurred_at]).await?;
            tx.execute("UPDATE scanner_incident SET recovered_at=GREATEST(recovered_at,$3) WHERE scanner_id=$1 AND operation=$2 AND last_seen_at<=$3 \
                AND error_code IN ('server_connect_failed','server_request_timeout','server_transport_failed','server_retryable_status','scanner_engine_validation_failed','unclean_restart')", &[&scanner,&operation,&occurred_at]).await?;
        }
        if let Some(id) = value.pointer("/fields/event_id").and_then(Value::as_str) {
            confirmed.push(id.to_owned());
        }
        let Some(event) = parser::parse(value, &fallback) else {
            continue;
        };
        if event.event_id.is_empty() {
            return Err("missing event_id".into());
        }
        let changed = tx.execute("INSERT INTO scanner_error_event(scanner_id,event_id,occurred_at,level,error_code,category,fingerprint,document) \
            VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING", &[&scanner,&event.event_id,&event.occurred_at,&event.level,&event.error_code,&event.category,&event.fingerprint,&event.document]).await?;
        if changed > 0 {
            tx.execute("INSERT INTO scanner_incident(scanner_id,fingerprint,error_code,operation,first_seen_at,last_seen_at,recovered_at) \
                VALUES($1::varchar(36),$2,$3,$4,$5,$5,CASE WHEN $3 IN ('server_connect_failed','server_request_timeout','server_transport_failed','server_retryable_status','scanner_engine_validation_failed','unclean_restart') \
                    THEN (SELECT recovered_at FROM scanner_diagnostic_recovery WHERE scanner_id=$1::varchar(36) AND operation=$4 AND recovered_at >= $5) ELSE NULL END) \
                ON CONFLICT(scanner_id,fingerprint) DO UPDATE SET occurrences=scanner_incident.occurrences+1, \
                    first_seen_at=LEAST(scanner_incident.first_seen_at,EXCLUDED.first_seen_at),last_seen_at=GREATEST(scanner_incident.last_seen_at,EXCLUDED.last_seen_at), \
                    acknowledged_at=CASE WHEN scanner_incident.recovered_at IS NOT NULL AND EXCLUDED.last_seen_at>scanner_incident.recovered_at THEN NULL ELSE scanner_incident.acknowledged_at END, \
                    recovered_at=CASE WHEN scanner_incident.recovered_at IS NOT NULL AND EXCLUDED.last_seen_at>scanner_incident.recovered_at THEN NULL ELSE scanner_incident.recovered_at END",
                &[&scanner,&event.fingerprint,&event.error_code,&event.operation,&event.occurred_at]).await?;
        }
        if let Some((file, line, offset)) = evidence {
            tx.execute("INSERT INTO scanner_error_evidence(scanner_id,event_id,file_id,line_number,byte_offset) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING", &[&scanner,&event.event_id,file,line,offset]).await?;
        }
    }
    tx.commit().await?;
    Ok(confirmed)
}

pub async fn assemble(state: &Diagnostics, snapshot: Snapshot) -> Result<()> {
    let root = state.config.directory.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        use std::io::{Read, Write};
        let dest = root.join(format!("{}.jsonl", snapshot.file_id));
        let temporary = root.join(format!("{}.assembling", snapshot.file_id));
        let mut output = std::fs::File::create(&temporary)?;
        let mut hasher = openssl::sha::Sha256::new();
        let count = snapshot.size_bytes.div_ceil(CHUNK_BYTES as u64);
        let mut total = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024];
        for part in 0..count {
            let mut input =
                std::fs::File::open(root.join(format!("{}.{part}.part", snapshot.file_id)))?;
            loop {
                let read = input.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                total += read as u64;
                if total > snapshot.size_bytes {
                    return Err("log_size_mismatch".into());
                }
                hasher.update(&buffer[..read]);
                output.write_all(&buffer[..read])?;
            }
        }
        let actual: String = hasher.finish().iter().map(|b| format!("{b:02x}")).collect();
        if total != snapshot.size_bytes || actual != snapshot.sha256 {
            let _ = std::fs::remove_file(&temporary);
            return Err("log_checksum_mismatch".into());
        }
        output.sync_all()?;
        std::fs::rename(temporary, dest)?;
        Ok(())
    })
    .await??;
    Ok(())
}

async fn parse_file(
    pool: &Pool,
    state: &Diagnostics,
    file_id: Uuid,
    scanner_id: Uuid,
) -> Result<()> {
    let path = state.file_path(file_id);
    let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
    let reader = tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut reader = std::io::BufReader::new(std::fs::File::open(path)?);
        let mut buffer = Vec::new();
        let (mut line, mut offset, mut invalid, mut oversized) = (0_i64, 0_i64, 0_u64, 0_u64);
        let mut records = Vec::new();
        while let Some((size, too_large)) = parser::next_line(&mut reader, &mut buffer)? {
            line += 1;
            if too_large {
                oversized += 1;
            } else if let Ok(value) = serde_json::from_slice::<Value>(&buffer) {
                if parser::parse(&value, "candidate").is_some()
                    || parser::recovery(&value).is_some()
                {
                    records.push((value, Some((file_id, line, offset))));
                }
            } else {
                invalid += 1;
            }
            offset += size as i64;
            if records.len() >= 100 {
                sender
                    .blocking_send(std::mem::take(&mut records))
                    .map_err(|_| "parser_receiver_closed")?;
            }
        }
        if !records.is_empty() {
            sender
                .blocking_send(records)
                .map_err(|_| "parser_receiver_closed")?;
        }
        Ok(json!({"lines":line,"invalid_lines":invalid,"oversized_lines":oversized}))
    });
    while let Some(records) = receiver.recv().await {
        ingest(pool, scanner_id, &records).await?;
    }
    let summary = reader.await??;
    pool.get()
        .await?
        .execute(
            "UPDATE scanner_log_file SET parse_status='ready',parse_summary=$2 WHERE file_id=$1",
            &[&file_id, &summary],
        )
        .await?;
    Ok(())
}

async fn work(pool: &Pool, state: &Diagnostics) -> Result<()> {
    let client = pool.get().await?;
    client.execute("UPDATE scanner_diagnostic_job SET status='expired',updated_at=NOW(),error_code='diagnostic_job_expired' \
        WHERE status IN ('queued','accepted','uploading') AND expires_at<NOW()", &[]).await?;
    let pending = client.query("SELECT file_id,scanner_id FROM scanner_log_file WHERE ready AND parse_status='pending' AND (parse_retry_at IS NULL OR parse_retry_at<=NOW()) ORDER BY created_at LIMIT 2", &[]).await?;
    drop(client);
    for row in pending {
        let file_id = row.get("file_id");
        let _guard = state.lock(file_id).await;
        if let Err(error) = parse_file(
            pool,
            state,
            file_id,
            Uuid::parse_str(row.get::<_, &str>("scanner_id"))?,
        )
        .await
        {
            tracing::error!(event="ScannerLogParseFailed",%file_id,%error);
            pool.get().await?.execute("UPDATE scanner_log_file SET parse_attempts=parse_attempts+1,parse_retry_at=NOW()+INTERVAL '30 seconds',parse_status=CASE WHEN parse_attempts>=4 THEN 'failed' ELSE 'pending' END,parse_summary=$2 WHERE file_id=$1", &[&file_id,&json!({"error_code":"log_parse_failed"})]).await?;
        }
    }
    if state.config.auto_collect {
        pool.get().await?.execute("INSERT INTO scanner_diagnostic_job(job_id,scanner_id,kind,automatic) \
            SELECT gen_random_uuid(),s.scanner_id,'list_logs',true FROM scanner_info s \
            WHERE s.is_enable AND s.deleted_at IS NULL AND s.diagnostics_capabilities->'supported_versions' @> '[1]'::jsonb \
            AND EXISTS(SELECT 1 FROM scanner_error_event e WHERE e.scanner_id=s.scanner_id AND e.level='ERROR' \
                AND e.occurred_at>NOW()-INTERVAL '5 minutes' AND e.category IN ('scan_engine','configuration','storage','process','authentication')) \
            AND NOT EXISTS(SELECT 1 FROM scanner_diagnostic_job j WHERE j.scanner_id=s.scanner_id AND j.automatic AND j.created_at>NOW()-INTERVAL '30 minutes')", &[]).await?;
    }
    Ok(())
}

async fn retention(pool: &Pool, state: &Diagnostics) -> Result<()> {
    let client = pool.get().await?;
    let days = state.config.log_retention_days as i32;
    let rows = client.query("SELECT f.file_id FROM scanner_log_file f JOIN scanner_diagnostic_job j USING(job_id) \
        WHERE (f.ready AND f.created_at<NOW()-make_interval(days=>$1)) OR (NOT f.ready AND j.status IN ('failed','expired','cancelled'))", &[&days]).await?;
    drop(client);
    for row in rows {
        let id: Uuid = row.get(0);
        let _guard = state.lock(id).await;
        // IDs come from our database, never from path text supplied by a client.
        for suffix in ["jsonl", "assembling"] {
            match tokio::fs::remove_file(state.config.directory.join(format!("{id}.{suffix}")))
                .await
            {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        for part in 0..MAX_FILE_BYTES.div_ceil(CHUNK_BYTES as u64) {
            match tokio::fs::remove_file(state.part_path(id, part as u32)).await {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        pool.get()
            .await?
            .execute("DELETE FROM scanner_log_file WHERE file_id=$1", &[&id])
            .await?;
    }
    let client = pool.get().await?;
    client
        .execute(
            "DELETE FROM scanner_error_event WHERE received_at<NOW()-make_interval(days=>$1)",
            &[&(state.config.error_retention_days as i32)],
        )
        .await?;
    client
        .execute(
            "DELETE FROM scanner_incident WHERE last_seen_at<NOW()-make_interval(days=>$1)",
            &[&(state.config.error_retention_days as i32)],
        )
        .await?;
    client
        .execute(
            "DELETE FROM scanner_log_source WHERE reported_at<NOW()-INTERVAL '1 day'",
            &[],
        )
        .await?;
    client.execute("DELETE FROM scanner_diagnostic_job WHERE status IN ('ready','failed','expired','cancelled') \
        AND updated_at<NOW()-make_interval(days=>$1) AND NOT EXISTS(SELECT 1 FROM scanner_log_file f WHERE f.job_id=scanner_diagnostic_job.job_id)", &[&days]).await?;
    client.execute("DELETE FROM scanner_diagnostic_recovery WHERE recovered_at<NOW()-make_interval(days=>$1)", &[&(state.config.error_retention_days as i32)]).await?;
    // A crash can leave files without committed metadata. Remove only our UUID filenames.
    let mut entries = tokio::fs::read_dir(&state.config.directory).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some((prefix, suffix)) = name.split_once('.') else {
            continue;
        };
        let Ok(id) = Uuid::parse_str(prefix) else {
            continue;
        };
        if !entry.file_type().await?.is_file() {
            continue;
        }
        let age = entry
            .metadata()
            .await?
            .modified()?
            .elapsed()
            .unwrap_or_default();
        if age < std::time::Duration::from_secs(3600) {
            continue;
        }
        let owned = suffix == "jsonl"
            || suffix == "assembling"
            || suffix.ends_with(".part")
            || suffix.ends_with(".tmp");
        if !owned {
            continue;
        }
        let _guard = state.lock(id).await;
        let exists = client
            .query_opt(
                "SELECT ready FROM scanner_log_file WHERE file_id=$1",
                &[&id],
            )
            .await?;
        let disposable = suffix.ends_with(".tmp")
            || exists.is_none()
            || (suffix.ends_with(".part")
                && exists.as_ref().is_some_and(|row| row.get::<_, bool>(0)));
        if disposable {
            tokio::fs::remove_file(entry.path()).await?;
        }
    }
    Ok(())
}

pub async fn run_worker(
    pool: Pool,
    state: Arc<Diagnostics>,
    maintenance: actix_web::web::Data<crate::system_maintenance::SystemMaintenanceState>,
) {
    let mut counter = 0;
    loop {
        if state.config.enabled && !maintenance.snapshot().await.blocks_all_scanner_requests() {
            if let Err(error) = work(&pool, &state).await {
                tracing::error!(event="ScannerDiagnosticsWorkerFailed",%error);
            }
            if counter % 60 == 0
                && let Err(error) = retention(&pool, &state).await
            {
                tracing::error!(event="ScannerDiagnosticsRetentionFailed",%error);
            }
        }
        counter += 1;
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

pub fn job_json(row: &tokio_postgres::Row) -> Value {
    json!({"job_id":row.get::<_,Uuid>("job_id"),"type":row.get::<_,String>("kind"),"status":row.get::<_,String>("status"),
        "created_at":row.get::<_,DateTime<Utc>>("created_at"),"expires_at":row.get::<_,DateTime<Utc>>("expires_at"),
        "error_code":row.get::<_,Option<String>>("error_code"),"sources":row.get::<_,Value>("sources"),"automatic":row.get::<_,bool>("automatic")})
}
