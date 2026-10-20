//! Offline uploads and local exports. Incremental updates remain on the API worker.
use super::*;
use std::path::PathBuf;
use storage::Source;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

pub(super) const BATCH: usize = 1000;
pub(super) const FAST_BATCH: usize = 5000;
const BATCH_BYTES: usize = 8 * 1024 * 1024;
fn cache_error(path: &std::path::Path, operation: &str, error: std::io::Error) -> Error {
    tracing::warn!(path = %path.display(), operation, error = %error, "IOC import cache unavailable; check NM_INTEL_CACHE_ROOT and service account permissions");
    Error::bad("intel_import_cache_unavailable")
}
async fn root() -> Result<PathBuf> {
    let path = PathBuf::from(
        std::env::var_os("NM_INTEL_CACHE_ROOT")
            .unwrap_or_else(|| "/var/lib/network-mapping/intel-cache".into()),
    );
    cache_root(&path).await
}
async fn cache_root(path: &std::path::Path) -> Result<PathBuf> {
    tokio::fs::create_dir_all(path)
        .await
        .map_err(|error| cache_error(path, "create directory", error))?;
    tokio::fs::canonicalize(path)
        .await
        .map_err(|error| cache_error(path, "resolve directory", error))
}
pub(super) async fn temporary() -> Result<tempfile::NamedTempFile> {
    let path = root().await?;
    tempfile::NamedTempFile::new_in(&path)
        .map_err(|error| cache_error(&path, "create private file", error))
}
pub(super) async fn check_writable() -> Result<()> {
    probe(temporary().await?).await
}
async fn probe(temp: tempfile::NamedTempFile) -> Result<()> {
    let path = temp.path();
    let mut file = tokio::fs::File::from_std(
        temp.reopen()
            .map_err(|error| cache_error(path, "open probe", error))?,
    );
    file.write_all(b"IOC import cache probe\n")
        .await
        .map_err(|error| cache_error(path, "write probe", error))?;
    file.sync_all()
        .await
        .map_err(|error| cache_error(path, "sync probe", error))?;
    drop(file);
    Ok(())
}

pub(super) async fn install(
    pool: &Pool,
    s: &Source,
    temp: tempfile::NamedTempFile,
    hash: String,
    actor: Option<(&UserBaseI, &AuditContext)>,
) -> Result<Uuid> {
    install_claimed(pool, s, temp, hash, actor, None).await
}
pub(super) async fn install_claimed(
    pool: &Pool,
    s: &Source,
    temp: tempfile::NamedTempFile,
    hash: String,
    actor: Option<(&UserBaseI, &AuditContext)>,
    claim: Option<(Uuid, Uuid)>,
) -> Result<Uuid> {
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    storage::validate_source(&tx, s).await?;
    // Serialize file replacement against other uploads to this source.
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1,318))",
        &[&s.id.to_string()],
    )
    .await?;
    if actor.is_some() && tx.query_one("SELECT EXISTS(SELECT 1 FROM intel_sync_run WHERE source_id=$1 AND status IN ('queued','running'))",&[&s.id]).await?.get::<_,bool>(0) {
        return Err(Error {status:StatusCode::CONFLICT,code:"intel_import_busy"});
    }
    let old = tx
        .query_opt(
            "SELECT snapshot_id FROM intel_import_snapshot WHERE source_id=$1",
            &[&s.id],
        )
        .await?;
    let id = Uuid::now_v7();
    let directory = root().await?;
    let path = directory.join(format!("{id}.raw"));
    temp.persist(&path)
        .map_err(|_| Error::bad("intel_import_write_failed"))?;
    let result=async {
        tx.execute("INSERT INTO intel_import_snapshot(source_id,source_revision,snapshot_id,stage,content_hash) VALUES($1,$2,$3,'downloaded',$4) ON CONFLICT(source_id) DO UPDATE SET source_revision=EXCLUDED.source_revision,snapshot_id=EXCLUDED.snapshot_id,stage='downloaded',content_hash=EXCLUDED.content_hash,byte_offset=0,record_count=0,processed_count=0,paused=FALSE,validation_summary='{}',created_at=NOW()",&[&s.id,&s.revision,&id,&hash]).await?;
        if let Some((user,context))=actor {
            if let Some((job,token)) = claim {
                tx.execute("INSERT INTO intel_sync_run(id,source_id,source_revision,status,attempts,claim_token,lease_until) VALUES($1,$2,$3,'running',1,$4,NOW()+INTERVAL '3 minutes')",&[&job,&s.id,&s.revision,&token]).await?;
            } else {
                tx.execute("INSERT INTO intel_sync_run(id,source_id,source_revision) VALUES($1,$2,$3)",&[&Uuid::now_v7(),&s.id,&s.revision]).await?;
            }
            audit(&tx,user,context,"intel.source.import",&s.id.to_string(),json!({"snapshot_id":id,"source_revision":s.revision})).await?;
        }
        tx.commit().await?;Ok::<_,Error>(())
    }.await;
    if let Err(error) = result {
        let _ = tokio::fs::remove_file(path).await;
        return Err(error);
    }
    if let Some(row) = old {
        let old: Uuid = row.get(0);
        for suffix in ["raw", "ndjson"] {
            let _ = tokio::fs::remove_file(directory.join(format!("{old}.{suffix}"))).await;
        }
    }
    Ok(id)
}
pub(super) async fn sync(pool: &Pool, s: &Source) -> Result<(Value, bool)> {
    sync_batch(pool, s, BATCH).await
}
pub(super) async fn sync_batch(
    pool: &Pool,
    s: &Source,
    batch_size: usize,
) -> Result<(Value, bool)> {
    let snapshot = pool
        .get()
        .await?
        .query_opt(
            "SELECT * FROM intel_import_snapshot WHERE source_id=$1 AND source_revision=$2",
            &[&s.id, &s.revision],
        )
        .await?;
    let snapshot = match snapshot {
        Some(row)
            if row.get::<_, String>("stage") != "complete" || s.input.transport == "upload" =>
        {
            row
        }
        _ if s.input.transport == "local" => {
            let mut source = client::local_file(&s.input.location).await?;
            if source
                .metadata()
                .await
                .map_err(|_| Error::bad("intel_import_read_failed"))?
                .len()
                > import_parse::MAX_ARCHIVE
            {
                return Err(Error::bad("intel_import_too_large"));
            }
            let temp = temporary().await?;
            let mut output = tokio::fs::File::from_std(
                temp.reopen()
                    .map_err(|_| Error::bad("intel_import_write_failed"))?,
            );
            let mut hash = openssl::sha::Sha256::new();
            let mut buffer = vec![0; 64 * 1024];
            let mut size = 0;
            loop {
                let n = source
                    .read(&mut buffer)
                    .await
                    .map_err(|_| Error::bad("intel_import_read_failed"))?;
                if n == 0 {
                    break;
                }
                size += n as u64;
                if size > import_parse::MAX_ARCHIVE {
                    return Err(Error::bad("intel_import_too_large"));
                }
                hash.update(&buffer[..n]);
                output
                    .write_all(&buffer[..n])
                    .await
                    .map_err(|_| Error::bad("intel_import_write_failed"))?;
            }
            output
                .sync_all()
                .await
                .map_err(|_| Error::bad("intel_import_write_failed"))?;
            drop(output);
            let hash = hash.finish().iter().map(|b| format!("{b:02x}")).collect();
            install(pool, s, temp, hash, None).await?;
            return Ok((json!({"offline_import":true,"stage":"uploaded"}), true));
        }
        _ => return Err(Error::bad("intel_import_file_required")),
    };
    if snapshot.get::<_, bool>("paused") {
        return Err(Error::bad("intel_import_paused"));
    }
    let id: Uuid = snapshot.get("snapshot_id");
    let stage: String = snapshot.get("stage");
    let total: i64 = snapshot.get("record_count");
    let validation: Value = snapshot.get("validation_summary");
    let directory = root().await?;
    if stage == "complete" {
        return Ok((
            json!({"offline_import":true,"stage":"complete","processed":total,"total":total,"validation":validation}),
            false,
        ));
    }
    if stage == "downloaded" {
        let raw = std::fs::File::open(directory.join(format!("{id}.raw")))
            .map_err(|_| Error::bad("intel_import_cache_missing"))?;
        let temp = temporary().await?;
        let output = temp
            .reopen()
            .map_err(|_| Error::bad("intel_import_write_failed"))?;
        let official = s.input.kind == "threatfox_export";
        let (count, _, report) = tokio::task::spawn_blocking(move || {
            if official {
                import_parse::convert_official(raw, output)
            } else {
                import_parse::convert(raw, output)
                    .map(|(count, bytes)| (count, bytes, ValidationReport::default()))
            }
        })
        .await
        .map_err(|_| Error::bad("intel_invalid_ioc_document"))??;
        let mut c = pool.get().await?;
        let tx = c.transaction().await?;
        storage::validate_source(&tx, s).await?;
        temp.persist(directory.join(format!("{id}.ndjson")))
            .map_err(|_| Error::bad("intel_import_write_failed"))?;
        let validation = json!(report);
        tx.execute("UPDATE intel_import_snapshot SET stage='ready',record_count=$3,validation_summary=$4 WHERE source_id=$1 AND snapshot_id=$2",&[&s.id,&id,&count,&validation]).await?;
        tx.commit().await?;
        if report.rejected == 0 {
            let _ = tokio::fs::remove_file(directory.join(format!("{id}.raw"))).await;
        }
        return Ok((
            json!({"offline_import":true,"stage":"validated","total":count,"validation":validation}),
            true,
        ));
    }
    let offset: i64 = snapshot.get("byte_offset");
    let processed: i64 = snapshot.get("processed_count");
    let file = tokio::fs::File::open(directory.join(format!("{id}.ndjson")))
        .await
        .map_err(|_| Error::bad("intel_import_cache_missing"))?;
    let length = file
        .metadata()
        .await
        .map_err(|_| Error::bad("intel_import_cache_missing"))?
        .len();
    let mut reader = tokio::io::BufReader::new(file);
    reader
        .seek(std::io::SeekFrom::Start(offset as u64))
        .await
        .map_err(|_| Error::bad("intel_import_read_failed"))?;
    let mut position = offset;
    let mut items = 0_i64;
    let mut entries = Vec::new();
    let mut bytes = 0;
    for _ in 0..batch_size {
        let mut line = Vec::new();
        let n = reader
            .read_until(b'\n', &mut line)
            .await
            .map_err(|_| Error::bad("intel_import_read_failed"))?;
        if n == 0 {
            break;
        }
        if n > 1024 * 1024 {
            return Err(Error::bad("intel_import_too_large"));
        }
        let indicator: Indicator =
            serde_json::from_slice(&line).map_err(|_| Error::bad("intel_invalid_indicator"))?;
        entries.push(indicator);
        bytes += n;
        position += n as i64;
        items += 1;
        if bytes >= BATCH_BYTES {
            break;
        }
    }
    let complete = position as u64 >= length;
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    storage::validate_source(&tx, s).await?;
    let added = batch::ingest(&tx, s, entries, "").await?;
    let changed = tx.execute("UPDATE intel_import_snapshot SET byte_offset=$3,processed_count=processed_count+$4,stage=$5 WHERE source_id=$1 AND snapshot_id=$2 AND byte_offset=$6 AND stage='ready'",&[&s.id,&id,&position,&items,&if complete{"complete"}else{"ready"},&offset]).await?;
    if changed != 1 {
        return Err(Error::conflict());
    }
    storage::validate_source(&tx, s).await?;
    tx.commit().await?;
    if complete {
        let _ = tokio::fs::remove_file(directory.join(format!("{id}.ndjson"))).await;
    }
    Ok((
        json!({"offline_import":true,"stage":if complete{"complete"}else{"importing"},"processed":processed+items,"total":total,"added":added,"validation":validation}),
        !complete,
    ))
}

#[cfg(test)]
mod cache_tests {
    use super::*;

    #[tokio::test]
    async fn cache_probe_writes_and_removes_private_file_without_leaving_imports() {
        let directory = tempfile::tempdir().unwrap();
        let path = cache_root(&directory.path().join("persistent-cache"))
            .await
            .unwrap();
        let file = tempfile::NamedTempFile::new_in(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                file.as_file().metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        probe(file).await.unwrap();
        assert_eq!(std::fs::read_dir(path).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn invalid_cache_directory_reports_configuration_error_without_fallback() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let error = cache_root(&file.path().join("cache")).await.unwrap_err();
        assert_eq!(error.code, "intel_import_cache_unavailable");
    }
}
