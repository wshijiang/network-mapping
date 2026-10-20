//! Local operator commands, using the same validation, policy and durable cursor as Web imports.
use super::*;
use crate::cli_progress::{CliProgressReporter, ProgressReporter, ProgressUpdate};
use crate::config::IntelCommand;
use std::path::Path;
use storage::{Fence, Source};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Copy, Default)]
pub(super) struct Options {
    pub fast: bool,
    pub batch_size: Option<usize>,
    pub max_batches: Option<u32>,
}
impl Options {
    fn size(self) -> usize {
        self.batch_size.unwrap_or(if self.fast {
            imports::FAST_BATCH
        } else {
            imports::BATCH
        })
    }
}

pub async fn execute(
    command: &IntelCommand,
    pool: &Pool,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    if matches!(command, IntelCommand::Sources) {
        for row in pool.get().await?.query("SELECT id,name,kind,enabled,require_review FROM intel_source WHERE transport='upload' AND kind IN ('json','lines','threatfox_export') ORDER BY name",&[]).await? {
            println!("{}\t{}\t{}\t{}\t{}",row.get::<_,Uuid>(0),row.get::<_,String>(1),row.get::<_,String>(2),if row.get::<_,bool>(3){"enabled"}else{"disabled"},if row.get::<_,bool>(4){"review required"}else{"trusted"});
        }
        return Ok(());
    }
    let IntelCommand::Import {
        source,
        admin,
        file,
        resume: _,
        fast,
        batch_size,
        max_batches,
    } = command
    else {
        unreachable!()
    };
    let progress = CliProgressReporter::new("IOC import");
    match import(
        pool,
        *source,
        admin,
        file.as_deref(),
        Options {
            fast: *fast,
            batch_size: batch_size.map(|n| n as usize),
            max_batches: *max_batches,
        },
        &progress,
    )
    .await
    {
        Ok(summary) => {
            progress.finish(summary.to_string());
            Ok(())
        }
        Err(error) => {
            progress.fail(error.code);
            Err(std::io::Error::other(error.code).into())
        }
    }
}

async fn operator(pool: &Pool, name: &str) -> Result<UserBaseI> {
    let row=pool.get().await?.query_opt("SELECT id,username,email FROM users WHERE username=$1 AND role=1 AND disabled_at IS NULL AND deleted_at IS NULL",&[&name]).await?.ok_or_else(||Error::bad("intel_admin_required"))?;
    Ok(UserBaseI {
        id: row.get("id"),
        username: row.get("username"),
        email: row.get("email"),
        role: 1,
        limit_login: false,
        enable_2fa: false,
    })
}
async fn copy_file(
    path: &Path,
    progress: &impl ProgressReporter,
) -> Result<(tempfile::NamedTempFile, String)> {
    let mut input = tokio::fs::File::open(path)
        .await
        .map_err(|_| Error::bad("intel_import_read_failed"))?;
    let metadata = input
        .metadata()
        .await
        .map_err(|_| Error::bad("intel_import_read_failed"))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > import_parse::MAX_ARCHIVE {
        return Err(Error::bad("intel_import_too_large"));
    }
    let temp = imports::temporary().await?;
    let mut output = tokio::fs::File::from_std(
        temp.reopen()
            .map_err(|_| Error::bad("intel_import_write_failed"))?,
    );
    let mut hash = openssl::sha::Sha256::new();
    let mut buffer = vec![0; 128 * 1024];
    let mut size = 0_u64;
    loop {
        let n = input
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
        progress.report(ProgressUpdate::count(
            "copy",
            size,
            Some(metadata.len()),
            "bytes",
            "保存私有导入快照",
        ));
    }
    output
        .sync_all()
        .await
        .map_err(|_| Error::bad("intel_import_write_failed"))?;
    drop(output);
    Ok((
        temp,
        hash.finish().iter().map(|b| format!("{b:02x}")).collect(),
    ))
}

async fn claim_resume(
    pool: &Pool,
    s: &Source,
    user: &UserBaseI,
    context: &AuditContext,
) -> Result<(Uuid, Uuid)> {
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    // Job -> source -> snapshot lock order is shared with the worker. Never
    // steal a live claim, including a Web import currently validating its file.
    let active=tx.query_opt("SELECT id,status,source_revision,lease_until>clock_timestamp() AS live FROM intel_sync_run WHERE source_id=$1 AND status IN ('queued','running') FOR UPDATE",&[&s.id]).await?;
    storage::validate_source(&tx, s).await?;
    let token = Uuid::new_v4();
    let job = if let Some(row) = active {
        if row.get::<_, i64>("source_revision") != s.revision
            || (row.get::<_, String>("status") == "running"
                && row.get::<_, Option<bool>>("live").unwrap_or(false))
        {
            return Err(Error::bad("intel_import_busy"));
        }
        let job: Uuid = row.get("id");
        tx.execute("UPDATE intel_sync_run SET status='running',attempts=1,claim_token=$2,lease_until=NOW()+INTERVAL '3 minutes',error_code=NULL,finished_at=NULL WHERE id=$1",&[&job,&token]).await?;
        job
    } else {
        let job = Uuid::now_v7();
        if tx.execute("INSERT INTO intel_sync_run(id,source_id,source_revision,status,attempts,claim_token,lease_until) VALUES($1,$2,$3,'running',1,$4,NOW()+INTERVAL '3 minutes') ON CONFLICT(source_id) WHERE status IN ('queued','running') DO NOTHING",&[&job,&s.id,&s.revision,&token]).await?!=1 {return Err(Error::bad("intel_import_busy"));}
        job
    };
    if tx.query_opt("SELECT snapshot_id FROM intel_import_snapshot WHERE source_id=$1 AND source_revision=$2 FOR SHARE",&[&s.id,&s.revision]).await?.is_none(){return Err(Error::bad("intel_import_file_required"));}
    tx.execute(
        "UPDATE intel_import_snapshot SET paused=FALSE WHERE source_id=$1 AND source_revision=$2",
        &[&s.id, &s.revision],
    )
    .await?;
    audit(
        &tx,
        user,
        context,
        "intel.source.import.resume",
        &s.id.to_string(),
        json!({"job_id":job}),
    )
    .await?;
    tx.commit().await?;
    Ok((job, token))
}

pub(super) async fn import(
    pool: &Pool,
    id: Uuid,
    admin_name: &str,
    file: Option<&Path>,
    options: Options,
    progress: &impl ProgressReporter,
) -> Result<Value> {
    if !(1..=50000).contains(&options.size()) || options.max_batches == Some(0) {
        return Err(Error::bad("intel_invalid_batch_size"));
    }
    let user = operator(pool, admin_name).await?;
    let mut s = storage::get_source(pool, id).await?;
    if s.input.transport != "upload"
        || !matches!(s.input.kind.as_str(), "json" | "lines" | "threatfox_export")
    {
        return Err(Error::bad("intel_invalid_upload_source"));
    }
    if !s.input.enabled {
        return Err(Error::bad("intel_source_disabled"));
    }
    let context = AuditContext::cli("intel import");
    let (job, token) = if let Some(path) = file {
        if pool.get().await?.query_one("SELECT EXISTS(SELECT 1 FROM intel_sync_run WHERE source_id=$1 AND status IN ('queued','running'))",&[&id]).await?.get::<_,bool>(0){return Err(Error::bad("intel_import_busy"));}
        let (temp, hash) = copy_file(path, progress).await?;
        let job = Uuid::now_v7();
        let token = Uuid::new_v4();
        imports::install_claimed(
            pool,
            &s,
            temp,
            hash,
            Some((&user, &context)),
            Some((job, token)),
        )
        .await?;
        (job, token)
    } else {
        claim_resume(pool, &s, &user, &context).await?
    };
    s.fence = Some(Fence::Sync(job, token));
    let result = tokio::select! {
        result=drive(pool,&s,options,progress)=>result,
        _=tokio::signal::ctrl_c()=>Err(Error::bad("intel_import_interrupted")),
    };
    let mut c = pool.get().await?;
    match result {
        Ok(summary) => {
            let tx = c.transaction().await?;
            storage::validate_source(&tx, &s).await?;
            let paused = summary
                .get("paused")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if paused {
                tx.execute("UPDATE intel_import_snapshot SET paused=TRUE WHERE source_id=$1 AND source_revision=$2 AND stage='ready'", &[&s.id,&s.revision]).await?;
            }
            let state = if paused { "partial" } else { "succeeded" };
            if tx.execute("UPDATE intel_sync_run SET status=$4,summary=$3,finished_at=NOW(),claim_token=NULL,lease_until=NULL WHERE id=$1 AND claim_token=$2 AND status='running' AND lease_until>clock_timestamp()",&[&job,&token,&summary,&state]).await?!=1 {return Err(Error::conflict());}
            tx.commit().await?;
            Ok(summary)
        }
        Err(error) => {
            c.execute("UPDATE intel_sync_run SET status='failed',error_code=$3,finished_at=NOW(),claim_token=NULL,lease_until=NULL WHERE id=$1 AND claim_token=$2 AND status='running'",&[&job,&token,&error.code]).await?;
            Err(error)
        }
    }
}
async fn drive(
    pool: &Pool,
    s: &Source,
    options: Options,
    progress: &impl ProgressReporter,
) -> Result<Value> {
    let Some(Fence::Sync(job, token)) = s.fence else {
        return Err(Error::conflict());
    };
    let started = std::time::Instant::now();
    let mut added = 0_i64;
    let mut batches = 0_u32;
    loop {
        let (mut summary, more) = tokio::time::timeout(
            std::time::Duration::from_secs(150),
            imports::sync_batch(pool, s, options.size()),
        )
        .await
        .map_err(|_| Error::bad("intel_sync_timeout"))??;
        added += summary.get("added").and_then(Value::as_i64).unwrap_or(0);
        summary["added_total"] = json!(added);
        summary["fast"] = json!(options.fast);
        if summary.get("added").is_some() {
            batches += 1;
        }
        let paused = more && options.max_batches.is_some_and(|limit| batches >= limit);
        summary["paused"] = json!(paused);
        summary["batches_committed"] = json!(batches);
        summary["batch_size"] = json!(options.size());
        summary["elapsed_seconds"] = json!(started.elapsed().as_secs_f64());
        let processed = summary
            .get("processed")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let total = summary.get("total").and_then(Value::as_u64);
        progress.report(ProgressUpdate::count(
            summary["stage"].as_str().unwrap_or("import"),
            processed,
            total,
            "IOC",
            format!(
                "新增 {added}；{}",
                if options.fast { "fast" } else { "batch" }
            ),
        ));
        if pool.get().await?.execute("UPDATE intel_sync_run SET summary=$3,lease_until=NOW()+INTERVAL '3 minutes' WHERE id=$1 AND claim_token=$2 AND status='running' AND lease_until>clock_timestamp()",&[&job,&token,&summary]).await?!=1 {return Err(Error::conflict());}
        if !more || paused {
            return Ok(summary);
        }
    }
}
