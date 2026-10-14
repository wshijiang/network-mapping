//! Constant-sized upload checks; callers hold the execution row lock.
use super::model::SaveScannerResultsError;
use super::storage::scanner_result_database_error;
use tokio_postgres::{Row, Transaction};

// Deletes mark a stream dirty. Repair only those streams, never scan the normal
// execution's receipt history during identity checks.
pub(crate) async fn repair_deleted_receipts(
    tx: &Transaction<'_>,
    execution_id: i32,
) -> Result<(), SaveScannerResultsError> {
    let dirty = tx
        .query(
            "SELECT upload_id FROM scan_upload_stream WHERE execution_id=$1 AND dirty",
            &[&execution_id],
        )
        .await
        .map_err(scanner_result_database_error)?;
    for stream in dirty {
        let upload_id: String = stream.get(0);
        tx.execute(
            "UPDATE scan_upload_stream s SET batch_count=a.total, confirmed_count=a.confirmed, \
             pending_count=a.pending, first_batch=a.first_batch, last_batch=a.last_batch, \
             final_count=a.finals, final_batch=a.final_batch, confirmed_observations=a.observations, dirty=FALSE \
             FROM (SELECT COUNT(*) AS total, COUNT(*) FILTER(WHERE storage_backend<>'pending') AS confirmed, \
               COUNT(*) FILTER(WHERE storage_backend='pending') AS pending, MIN(batch_index) AS first_batch, \
               MAX(batch_index) AS last_batch, COUNT(*) FILTER(WHERE is_final) AS finals, \
               MIN(batch_index) FILTER(WHERE is_final) AS final_batch, \
               COALESCE(SUM(observation_count) FILTER(WHERE storage_backend<>'pending'),0) AS observations \
               FROM scan_result_batch WHERE execution_id=$1 AND upload_id=$2) a \
             WHERE s.execution_id=$1 AND s.upload_id=$2", &[&execution_id,&upload_id],
        ).await.map_err(scanner_result_database_error)?;
        tx.execute("DELETE FROM scan_upload_stream WHERE execution_id=$1 AND upload_id=$2 AND batch_count=0", &[&execution_id,&upload_id])
            .await.map_err(scanner_result_database_error)?;
        tracing::warn!(
            event = "ScanUploadStreamRepaired",
            execution_id,
            upload_id,
            "修复删除回执后的派生上传状态"
        );
    }
    Ok(())
}

pub(crate) async fn load(
    tx: &Transaction<'_>,
    execution_id: i32,
    upload_id: &str,
) -> Result<Option<Row>, SaveScannerResultsError> {
    tx.query_opt(
        "SELECT * FROM scan_upload_stream WHERE execution_id=$1 AND upload_id=$2",
        &[&execution_id, &upload_id],
    )
    .await
    .map_err(scanner_result_database_error)
}

fn invalid(
    execution_id: i32,
    upload_id: &str,
    batch_index: i32,
    content_kind: &'static str,
) -> SaveScannerResultsError {
    SaveScannerResultsError::NonContiguousFinalBatch {
        execution_id,
        upload_id: upload_id.into(),
        batch_index,
        content_kind,
    }
}

pub(crate) async fn validate_final(
    tx: &Transaction<'_>,
    execution_id: i32,
    upload_id: &str,
    batch_index: i32,
    content_kind: &'static str,
    confirmed: bool,
) -> Result<(), SaveScannerResultsError> {
    let stream = load(tx, execution_id, upload_id).await?;
    let current = tx.query_opt(
        "SELECT is_final,storage_backend FROM scan_result_batch WHERE execution_id=$1 AND upload_id=$2 AND batch_index=$3",
        &[&execution_id,&upload_id,&batch_index],
    ).await.map_err(scanner_result_database_error)?;
    let current_pending = current
        .as_ref()
        .is_some_and(|r| r.get::<_, String>("storage_backend") == "pending");
    let current_final = current
        .as_ref()
        .is_some_and(|r| r.get::<_, bool>("is_final"));
    let has_current = current.is_some();
    let expected_count = i64::from(batch_index) + i64::from(has_current);
    let valid = match stream {
        None => !confirmed && batch_index == 0 && !has_current,
        Some(s) => {
            !s.get::<_, bool>("dirty")
                && s.get::<_, i64>("batch_count") == expected_count
                && s.get::<_, Option<i32>>("first_batch") == Some(0)
                && s.get::<_, Option<i32>>("last_batch")
                    == Some(batch_index - i32::from(!has_current))
                && (!has_current || current_final)
                && s.get::<_, i64>("final_count") == i64::from(current_final)
                && s.get::<_, i64>("pending_count")
                    == if confirmed {
                        0
                    } else {
                        i64::from(current_pending)
                    }
                && (!confirmed
                    || (has_current && s.get::<_, i64>("confirmed_count") == expected_count))
        }
    };
    if valid {
        Ok(())
    } else {
        Err(invalid(execution_id, upload_id, batch_index, content_kind))
    }
}

pub(crate) async fn ensure_open(
    tx: &Transaction<'_>,
    execution_id: i32,
    upload_id: &str,
    batch_index: i32,
    content_kind: &'static str,
) -> Result<(), SaveScannerResultsError> {
    if load(tx, execution_id, upload_id)
        .await?
        .is_some_and(|s| s.get::<_, i64>("final_count") > 0)
    {
        return Err(invalid(execution_id, upload_id, batch_index, content_kind));
    }
    Ok(())
}
