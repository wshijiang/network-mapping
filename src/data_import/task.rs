//! 导入任务与批次台账的 PostgreSQL 持久化。

use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::Serialize;
use serde_json::{Value, json};
use tokio_postgres::Row;
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// 任务状态（与前端 8 态一致）。
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_VALIDATING: &str = "validating";
pub const STATUS_TYPE_CHECKING: &str = "type_checking";
pub const STATUS_IMPORTING: &str = "importing";
pub const STATUS_PAUSED: &str = "paused";
pub const STATUS_COMPLETED: &str = "completed";
pub const STATUS_ERROR: &str = "error";
pub const STATUS_CANCELLED: &str = "cancelled";

pub const ACTIVE_STATUSES: &[&str] = &[STATUS_VALIDATING, STATUS_TYPE_CHECKING, STATUS_IMPORTING];

fn millis(value: Option<DateTime<Utc>>) -> Option<i64> {
    value.map(|v| v.timestamp_millis())
}

#[derive(Clone, Debug, Serialize)]
pub struct Task {
    pub id: Uuid,
    pub file_name: String,
    pub file_size: i64,
    pub sha256: String,
    pub status: String,
    pub overwrite_policy: String,
    pub on_invalid: String,
    pub dry_run: bool,
    pub fast_mode: bool,
    pub batch_size: i32,
    pub concurrency: i32,
    pub total_rows: Option<i64>,
    pub processed_rows: i64,
    pub imported_rows: i64,
    pub invalid_rows: i64,
    pub duplicate_rows: i64,
    pub conflict_rows: i64,
    pub error_message: Option<String>,
    pub created_at: Option<i64>,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub header_mapping: Value,
    pub file_headers: Value,
    #[serde(skip_serializing)]
    pub storage_path: String,
    #[serde(skip_serializing)]
    pub created_by: i32,
    #[serde(skip_serializing)]
    pub scan_task_id: Option<i32>,
    #[serde(skip_serializing)]
    pub execution_id: Option<i32>,
    #[serde(skip_serializing)]
    pub upload_id: Option<Uuid>,
    #[serde(skip_serializing)]
    pub next_batch_index: i32,
    #[serde(skip_serializing)]
    pub committed_rows: i64,
}

pub fn row_to_task(row: &Row) -> Task {
    Task {
        id: row.get("id"),
        file_name: row.get("file_name"),
        file_size: row.get("file_size"),
        sha256: row.get("sha256"),
        status: row.get("status"),
        overwrite_policy: row.get("overwrite_policy"),
        on_invalid: row.get("on_invalid"),
        dry_run: row.get("dry_run"),
        fast_mode: row.get("fast_mode"),
        batch_size: row.get("batch_size"),
        concurrency: row.get("concurrency"),
        total_rows: row.get("total_rows"),
        processed_rows: row.get("processed_rows"),
        imported_rows: row.get("imported_rows"),
        invalid_rows: row.get("invalid_rows"),
        duplicate_rows: row.get("duplicate_rows"),
        conflict_rows: row.get("conflict_rows"),
        error_message: row.get("error_message"),
        created_at: millis(row.get("created_at")),
        started_at: millis(row.get("started_at")),
        finished_at: millis(row.get("finished_at")),
        header_mapping: row.get("header_mapping"),
        file_headers: row.get("file_headers"),
        storage_path: row.get("storage_path"),
        created_by: row.get("created_by"),
        scan_task_id: row.get("scan_task_id"),
        execution_id: row.get("execution_id"),
        upload_id: row.get("upload_id"),
        next_batch_index: row.get("next_batch_index"),
        committed_rows: row.get("committed_rows"),
    }
}

const SELECT_COLS: &str = "id, file_name, file_size, sha256, status, overwrite_policy, on_invalid, \
    dry_run, fast_mode, batch_size, concurrency, total_rows, processed_rows, imported_rows, \
    invalid_rows, duplicate_rows, conflict_rows, error_message, created_at, started_at, finished_at, \
    header_mapping, file_headers, storage_path, created_by, scan_task_id, execution_id, upload_id, \
    next_batch_index, committed_rows";

pub struct NewTask<'a> {
    pub id: Uuid,
    pub created_by: i32,
    pub file_name: &'a str,
    pub file_size: i64,
    pub sha256: &'a str,
    pub storage_path: &'a str,
    pub file_headers: Value,
    pub header_mapping: Value,
    pub on_invalid: &'a str,
    pub overwrite_policy: &'a str,
    pub dry_run: bool,
    pub fast_mode: bool,
    pub batch_size: i32,
    pub concurrency: i32,
}

pub async fn create_task(pool: &Pool, new: NewTask<'_>) -> Result<Task> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            &format!(
                "INSERT INTO data_import_task (id, created_by, file_name, file_size, sha256, storage_path, \
                 file_headers, header_mapping, on_invalid, overwrite_policy, dry_run, fast_mode, batch_size, concurrency) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING {SELECT_COLS}"
            ),
            &[
                &new.id, &new.created_by, &new.file_name, &new.file_size, &new.sha256,
                &new.storage_path, &new.file_headers, &new.header_mapping, &new.on_invalid,
                &new.overwrite_policy, &new.dry_run, &new.fast_mode, &new.batch_size, &new.concurrency,
            ],
        )
        .await?;
    Ok(row_to_task(&row))
}

pub async fn get_task(pool: &Pool, id: Uuid) -> Result<Option<Task>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            &format!("SELECT {SELECT_COLS} FROM data_import_task WHERE id=$1"),
            &[&id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_task))
}

pub async fn list_tasks(
    pool: &Pool,
    status: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<(Vec<Task>, i64)> {
    let client = pool.get().await?;
    let (rows, total) = if let Some(status) = status {
        let rows = client
            .query(
                &format!("SELECT {SELECT_COLS} FROM data_import_task WHERE status=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"),
                &[&status, &limit, &offset],
            )
            .await?;
        let total: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM data_import_task WHERE status=$1",
                &[&status],
            )
            .await?
            .get(0);
        (rows, total)
    } else {
        let rows = client
            .query(&format!("SELECT {SELECT_COLS} FROM data_import_task ORDER BY created_at DESC LIMIT $1 OFFSET $2"), &[&limit, &offset])
            .await?;
        let total: i64 = client
            .query_one("SELECT COUNT(*) FROM data_import_task", &[])
            .await?
            .get(0);
        (rows, total)
    };
    Ok((rows.iter().map(row_to_task).collect(), total))
}

/// 仅当处于允许的状态集合时迁移状态，返回是否成功。
pub async fn transition(
    pool: &Pool,
    id: Uuid,
    from: &[&str],
    to: &str,
    error_message: Option<&str>,
) -> Result<bool> {
    let client = pool.get().await?;
    let finished = matches!(to, STATUS_COMPLETED | STATUS_CANCELLED | STATUS_ERROR);
    let updated = client
        .execute(
            "UPDATE data_import_task SET status=$3, error_message=$4, updated_at=NOW(), \
             finished_at=CASE WHEN $5 THEN NOW() ELSE finished_at END, \
             started_at=CASE WHEN started_at IS NULL AND $3 <> 'pending' THEN NOW() ELSE started_at END \
             WHERE id=$1 AND status = ANY($2::TEXT[])",
            &[&id, &from.to_vec(), &to, &error_message, &finished],
        )
        .await?;
    Ok(updated == 1)
}

pub async fn pause(pool: &Pool, id: Uuid) -> Result<bool> {
    transition(
        pool,
        id,
        &[
            STATUS_PENDING,
            STATUS_VALIDATING,
            STATUS_TYPE_CHECKING,
            STATUS_IMPORTING,
        ],
        STATUS_PAUSED,
        None,
    )
    .await
}

pub async fn cancel(pool: &Pool, id: Uuid) -> Result<bool> {
    transition(
        pool,
        id,
        &[
            STATUS_PENDING,
            STATUS_VALIDATING,
            STATUS_TYPE_CHECKING,
            STATUS_IMPORTING,
            STATUS_PAUSED,
            STATUS_ERROR,
        ],
        STATUS_CANCELLED,
        None,
    )
    .await
}

/// 继续（仅 paused），可同时调整批次大小与并发。
pub async fn resume(
    pool: &Pool,
    id: Uuid,
    batch_size: Option<i32>,
    concurrency: Option<i32>,
) -> Result<bool> {
    let client = pool.get().await?;
    let updated = client
        .execute(
            "UPDATE data_import_task SET status='importing', \
             batch_size=COALESCE($2, batch_size), concurrency=COALESCE($3, concurrency), updated_at=NOW() \
             WHERE id=$1 AND status='paused'",
            &[&id, &batch_size, &concurrency],
        )
        .await?;
    Ok(updated == 1)
}

pub async fn delete_task(pool: &Pool, id: Uuid) -> Result<Option<String>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "DELETE FROM data_import_task WHERE id=$1 AND status IN ('completed','cancelled','error') RETURNING storage_path",
            &[&id],
        )
        .await?;
    Ok(row.map(|r| r.get("storage_path")))
}

/// 认领一个待执行或租约过期的任务（原子）。
pub async fn claim_next(pool: &Pool, worker_id: Uuid, lease_ms: i64) -> Result<Option<Task>> {
    let client = pool.get().await?;
    let now = Utc::now().timestamp_millis();
    let row = client
        .query_opt(
            &format!(
                "UPDATE data_import_task SET worker_id=$1, lease_expires_at=$2, updated_at=NOW(), \
                 started_at=COALESCE(started_at, NOW()) \
                 WHERE id = (SELECT id FROM data_import_task \
                    WHERE status='pending' OR (status = ANY($3::TEXT[]) AND (lease_expires_at IS NULL OR lease_expires_at < $4)) \
                    ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) \
                 RETURNING {SELECT_COLS}"
            ),
            &[&worker_id, &(now + lease_ms), &ACTIVE_STATUSES.to_vec(), &now],
        )
        .await?;
    Ok(row.as_ref().map(row_to_task))
}

pub async fn renew_lease(pool: &Pool, id: Uuid, worker_id: Uuid, lease_ms: i64) -> Result<bool> {
    let client = pool.get().await?;
    let now = Utc::now().timestamp_millis();
    let updated = client
        .execute(
            "UPDATE data_import_task SET lease_expires_at=$3, updated_at=NOW() WHERE id=$1 AND worker_id=$2",
            &[&id, &worker_id, &(now + lease_ms)],
        )
        .await?;
    Ok(updated == 1)
}

pub async fn release_lease(pool: &Pool, id: Uuid, worker_id: Uuid) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute("UPDATE data_import_task SET worker_id=NULL, lease_expires_at=NULL WHERE id=$1 AND worker_id=$2", &[&id, &worker_id])
        .await?;
    Ok(())
}

#[derive(Clone, Copy, Default)]
pub struct Progress {
    pub total_rows: Option<i64>,
    pub processed_rows: i64,
    pub imported_rows: i64,
    pub invalid_rows: i64,
    pub duplicate_rows: i64,
    pub conflict_rows: i64,
    pub committed_rows: i64,
    pub next_batch_index: i32,
}

pub async fn checkpoint(
    pool: &Pool,
    id: Uuid,
    status: &str,
    progress: Progress,
    error_samples: Option<&Value>,
) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE data_import_task SET status=$2, total_rows=COALESCE($3, total_rows), processed_rows=$4, \
             imported_rows=$5, invalid_rows=$6, duplicate_rows=$7, conflict_rows=$8, committed_rows=$9, \
             next_batch_index=$10, error_samples=COALESCE($11, error_samples), updated_at=NOW() WHERE id=$1 \
             AND status NOT IN ('paused','cancelled')",
            &[
                &id, &status, &progress.total_rows, &progress.processed_rows, &progress.imported_rows,
                &progress.invalid_rows, &progress.duplicate_rows, &progress.conflict_rows,
                &progress.committed_rows, &progress.next_batch_index, &error_samples,
            ],
        )
        .await?;
    Ok(())
}

pub async fn set_error(pool: &Pool, id: Uuid, message: &str) -> Result<()> {
    let client = pool.get().await?;
    let truncated: String = message.chars().take(2000).collect();
    client
        .execute(
            "UPDATE data_import_task SET status='error', error_message=$2, finished_at=NOW(), worker_id=NULL, lease_expires_at=NULL, updated_at=NOW() WHERE id=$1",
            &[&id, &truncated],
        )
        .await?;
    Ok(())
}

pub async fn link_scan_task(
    pool: &Pool,
    id: Uuid,
    scan_task_id: i32,
    execution_id: i32,
    upload_id: Uuid,
) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE data_import_task SET scan_task_id=$2, execution_id=$3, upload_id=$4 WHERE id=$1",
            &[&id, &scan_task_id, &execution_id, &upload_id],
        )
        .await?;
    Ok(())
}

pub async fn record_batch(
    pool: &Pool,
    task_id: Uuid,
    batch_index: i32,
    row_start: i64,
    row_end: i64,
    observation_count: i32,
    checksum: &str,
) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO data_import_batch (task_id, batch_index, row_start, row_end, status, observation_count, payload_checksum, committed_at) \
             VALUES ($1,$2,$3,$4,'committed',$5,$6,NOW()) \
             ON CONFLICT (task_id, batch_index) DO UPDATE SET status='committed', observation_count=EXCLUDED.observation_count, payload_checksum=EXCLUDED.payload_checksum, committed_at=NOW()",
            &[&task_id, &batch_index, &row_start, &row_end, &observation_count, &checksum],
        )
        .await?;
    Ok(())
}

/// 写入前登记批次（pending），固定行区间与 batch_index，保证崩溃重放校验和稳定。
pub async fn begin_batch(
    pool: &Pool,
    task_id: Uuid,
    batch_index: i32,
    row_start: i64,
    row_end: i64,
) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO data_import_batch (task_id, batch_index, row_start, row_end, status) \
             VALUES ($1,$2,$3,$4,'pending') ON CONFLICT (task_id, batch_index) DO NOTHING",
            &[&task_id, &batch_index, &row_start, &row_end],
        )
        .await?;
    Ok(())
}

pub async fn commit_batch(
    pool: &Pool,
    task_id: Uuid,
    batch_index: i32,
    observation_count: i32,
    checksum: &str,
) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE data_import_batch SET status='committed', observation_count=$3, payload_checksum=$4, committed_at=NOW() \
             WHERE task_id=$1 AND batch_index=$2",
            &[&task_id, &batch_index, &observation_count, &checksum],
        )
        .await?;
    Ok(())
}

/// 崩溃窗口内未确认的批次（需按原行区间重放）。
pub async fn pending_batch(pool: &Pool, task_id: Uuid) -> Result<Option<(i32, i64, i64)>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT batch_index, row_start, row_end FROM data_import_batch WHERE task_id=$1 AND status='pending' ORDER BY batch_index LIMIT 1",
            &[&task_id],
        )
        .await?;
    Ok(row.map(|r| (r.get("batch_index"), r.get("row_start"), r.get("row_end"))))
}

/// 续传光标：下一个 ES batch_index 与已连续提交的行数（最大已提交批次的 row_end）。
pub async fn resume_cursor(pool: &Pool, task_id: Uuid) -> Result<(i32, i64)> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT batch_index, row_end FROM data_import_batch WHERE task_id=$1 AND status='committed' ORDER BY batch_index DESC LIMIT 1",
            &[&task_id],
        )
        .await?;
    Ok(match row {
        Some(r) => (r.get::<_, i32>("batch_index") + 1, r.get("row_end")),
        None => (0, 0),
    })
}

pub async fn error_samples(pool: &Pool, id: Uuid) -> Result<Value> {
    let client = pool.get().await?;
    let row = client
        .query_one("SELECT error_samples, invalid_rows, duplicate_rows, conflict_rows FROM data_import_task WHERE id=$1", &[&id])
        .await?;
    Ok(json!({
        "samples": row.get::<_, Value>("error_samples"),
        "invalid_rows": row.get::<_, i64>("invalid_rows"),
        "duplicate_rows": row.get::<_, i64>("duplicate_rows"),
        "conflict_rows": row.get::<_, i64>("conflict_rows"),
    }))
}

/// 终态任务文件保留期清理（返回被删除任务的 storage_path）。
pub async fn purge_expired(pool: &Pool, retention_days: u32) -> Result<Vec<String>> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "DELETE FROM data_import_task WHERE status IN ('completed','cancelled','error') \
             AND finished_at < NOW() - ($1::TEXT || ' days')::INTERVAL RETURNING storage_path",
            &[&retention_days.to_string()],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get("storage_path")).collect())
}
