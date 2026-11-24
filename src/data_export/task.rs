//! 导出任务的 PostgreSQL 持久化（租约认领模式，与 data_import::task 一致）。

use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::Serialize;
use serde_json::Value;
use tokio_postgres::Row;
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub const STATUS_PENDING: &str = "pending";
pub const STATUS_RUNNING: &str = "running";
pub const STATUS_COMPLETED: &str = "completed";
pub const STATUS_ERROR: &str = "error";
pub const STATUS_CANCELLED: &str = "cancelled";

fn millis(value: Option<DateTime<Utc>>) -> Option<i64> {
    value.map(|v| v.timestamp_millis())
}

#[derive(Clone, Debug, Serialize)]
pub struct Task {
    pub id: Uuid,
    pub created_by: i32,
    pub query: String,
    pub scope: String,
    pub page_offset: Option<i64>,
    pub page_limit: Option<i64>,
    pub sort_field: String,
    pub sort_order: String,
    pub fields: Value,
    pub status: String,
    pub matched_total: Option<i64>,
    pub exported_rows: i64,
    pub file_size: Option<i64>,
    pub download_sources: Vec<&'static str>,
    pub s3_failed: bool,
    #[serde(skip_serializing)]
    pub storage_plan: Option<Value>,
    #[serde(skip_serializing)]
    pub s3_object: Option<Value>,
    pub sha256: Option<String>,
    pub error_message: Option<String>,
    pub created_at: Option<i64>,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    #[serde(skip_serializing)]
    pub scope_type: String,
    #[serde(skip_serializing)]
    pub scope_id: i32,
    #[serde(skip_serializing)]
    pub filter: Value,
    #[serde(skip_serializing)]
    pub file_path: Option<String>,
    #[serde(skip_serializing)]
    pub worker_id: Option<Uuid>,
    #[serde(skip_serializing)]
    pub lease_expires_at: Option<i64>,
}

const SELECT_COLS: &str = "id, created_by, query, scope, page_offset, page_limit, sort_field, \
    sort_order, fields, status, matched_total, exported_rows, file_size, sha256, error_message, \
    created_at, started_at, finished_at, scope_type, scope_id, filter, file_path, worker_id, \
    lease_expires_at, storage_plan, s3_object, s3_failed";

pub fn row_to_task(row: &Row) -> Task {
    let file_path: Option<String> = row.get("file_path");
    let s3_object: Option<Value> = row.get("s3_object");
    let download_sources = [
        file_path.as_ref().map(|_| "local"),
        s3_object.as_ref().map(|_| "s3"),
    ]
    .into_iter()
    .flatten()
    .collect();
    Task {
        id: row.get("id"),
        created_by: row.get("created_by"),
        query: row.get("query"),
        scope: row.get("scope"),
        page_offset: row.get("page_offset"),
        page_limit: row.get("page_limit"),
        sort_field: row.get("sort_field"),
        sort_order: row.get("sort_order"),
        fields: row.get("fields"),
        status: row.get("status"),
        matched_total: row.get("matched_total"),
        exported_rows: row.get("exported_rows"),
        file_size: row.get("file_size"),
        sha256: row.get("sha256"),
        error_message: row.get("error_message"),
        created_at: millis(row.get("created_at")),
        started_at: millis(row.get("started_at")),
        finished_at: millis(row.get("finished_at")),
        scope_type: row.get("scope_type"),
        scope_id: row.get("scope_id"),
        filter: row.get("filter"),
        file_path,
        download_sources,
        storage_plan: row.get("storage_plan"),
        s3_object,
        s3_failed: row.get("s3_failed"),
        worker_id: row.get("worker_id"),
        lease_expires_at: row.get("lease_expires_at"),
    }
}

pub struct NewTask<'a> {
    pub id: Uuid,
    pub created_by: i32,
    pub scope_type: &'a str,
    pub scope_id: i32,
    pub query: &'a str,
    pub filter: Value,
    pub scope: &'a str,
    pub page_offset: Option<i64>,
    pub page_limit: Option<i64>,
    pub sort_field: &'a str,
    pub sort_order: &'a str,
    pub fields: Value,
    pub matched_total: Option<i64>,
    pub storage_plan: super::settings::Plan,
}

pub async fn create_task(pool: &Pool, new: NewTask<'_>) -> Result<Task> {
    let client = pool.get().await?;
    let storage_plan = serde_json::to_value(&new.storage_plan)?;
    let row = client
        .query_one(
            &format!(
                "INSERT INTO data_export_task (id, created_by, scope_type, scope_id, query, filter, \
                 scope, page_offset, page_limit, sort_field, sort_order, fields, matched_total, storage_plan) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING {SELECT_COLS}"
            ),
            &[
                &new.id, &new.created_by, &new.scope_type, &new.scope_id, &new.query,
                &new.filter, &new.scope, &new.page_offset, &new.page_limit, &new.sort_field,
                &new.sort_order, &new.fields, &new.matched_total, &storage_plan,
            ],
        )
        .await?;
    Ok(row_to_task(&row))
}

pub async fn get_task(pool: &Pool, id: Uuid) -> Result<Option<Task>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            &format!("SELECT {SELECT_COLS} FROM data_export_task WHERE id=$1"),
            &[&id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_task))
}

/// `owner` 为 Some 时仅返回该用户的任务（普通用户）；None 返回全部（管理员）。
pub async fn list_tasks(
    pool: &Pool,
    owner: Option<i32>,
    status: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<(Vec<Task>, i64)> {
    let client = pool.get().await?;
    let rows = client
        .query(
            &format!(
                "SELECT {SELECT_COLS} FROM data_export_task \
                 WHERE ($1::INT IS NULL OR created_by=$1) AND ($2::TEXT IS NULL OR status=$2) \
                 ORDER BY created_at DESC LIMIT $3 OFFSET $4"
            ),
            &[&owner, &status, &limit, &offset],
        )
        .await?;
    let total: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM data_export_task \
             WHERE ($1::INT IS NULL OR created_by=$1) AND ($2::TEXT IS NULL OR status=$2)",
            &[&owner, &status],
        )
        .await?
        .get(0);
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
            "UPDATE data_export_task SET status=$3, error_message=$4, updated_at=NOW(), \
             finished_at=CASE WHEN $5 THEN NOW() ELSE finished_at END \
             WHERE id=$1 AND status = ANY($2::TEXT[])",
            &[&id, &from.to_vec(), &to, &error_message, &finished],
        )
        .await?;
    Ok(updated == 1)
}

pub async fn cancel(pool: &Pool, id: Uuid) -> Result<bool> {
    transition(
        pool,
        id,
        &[STATUS_PENDING, STATUS_RUNNING],
        STATUS_CANCELLED,
        None,
    )
    .await
}

/// Only terminal tasks can be deleted. Their artifacts remain in the cleanup ledger.
pub async fn delete_task(pool: &Pool, id: Uuid) -> Result<bool> {
    let client = pool.get().await?;
    Ok(client.execute(
        "DELETE FROM data_export_task WHERE id=$1 AND status IN ('completed','cancelled','error')",
        &[&id],
    ).await? == 1)
}

/// 认领一个待执行或租约过期的任务（原子）。租约过期的 running 任务从头重跑
/// （导出是只读幂等操作，worker 会重建文件）。
pub async fn claim_next(pool: &Pool, worker_id: Uuid, lease_ms: i64) -> Result<Option<Task>> {
    let client = pool.get().await?;
    let now = Utc::now().timestamp_millis();
    let row = client
        .query_opt(
            &format!(
                "UPDATE data_export_task SET worker_id=$1, lease_expires_at=$2, status='running', \
                 exported_rows=0, error_message=NULL, updated_at=NOW(), \
                 started_at=COALESCE(started_at, NOW()) \
                 WHERE id = (SELECT id FROM data_export_task \
                    WHERE (status='pending' OR (status='running' AND lease_expires_at < $3)) \
                      AND (lease_expires_at IS NULL OR lease_expires_at < $3) \
                    ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) \
                 RETURNING {SELECT_COLS}"
            ),
            &[&worker_id, &(now + lease_ms), &now],
        )
        .await?;
    Ok(row.as_ref().map(row_to_task))
}

pub async fn renew_lease(pool: &Pool, id: Uuid, worker_id: Uuid, lease_ms: i64) -> Result<bool> {
    let client = pool.get().await?;
    let now = Utc::now().timestamp_millis();
    let row = client
        .query_one(
            "WITH renewed AS (
                UPDATE data_export_task SET lease_expires_at=$3, updated_at=NOW()
                WHERE id=$1 AND worker_id=$2 AND status='running' AND lease_expires_at >= $4
                RETURNING worker_id
             ), deferred_cleanup AS (
                UPDATE data_export_attempt SET cleanup_after=NOW() + INTERVAL '10 minutes'
                WHERE id IN (SELECT worker_id FROM renewed)
             )
             SELECT EXISTS (SELECT 1 FROM renewed)",
            &[&id, &worker_id, &(now + lease_ms), &now],
        )
        .await?;
    Ok(row.get(0))
}

pub async fn release_lease(pool: &Pool, id: Uuid, worker_id: Uuid) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE data_export_task SET
                worker_id=CASE WHEN status='running' THEN worker_id END,
                lease_expires_at=CASE WHEN status='running' THEN 0 END
             WHERE id=$1 AND worker_id=$2",
            &[&id, &worker_id],
        )
        .await?;
    Ok(())
}

/// 批间进度落库（仅 running 且未被取消时生效）。
pub async fn checkpoint(
    pool: &Pool,
    id: Uuid,
    worker_id: Uuid,
    exported_rows: i64,
    matched_total: Option<i64>,
) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE data_export_task SET exported_rows=$2, \
             matched_total=COALESCE($3, matched_total), updated_at=NOW() \
             WHERE id=$1 AND status='running' AND worker_id=$4",
            &[&id, &exported_rows, &matched_total, &worker_id],
        )
        .await?;
    Ok(())
}

/// 完成登记；仅当任务仍为 running 且租约仍属于该 worker 时生效（防取消竞态）。
#[allow(clippy::too_many_arguments)]
pub async fn complete(
    pool: &Pool,
    id: Uuid,
    worker_id: Uuid,
    file_path: Option<&str>,
    s3_object: Option<&Value>,
    s3_failed: bool,
    file_size: i64,
    sha256: &str,
    exported_rows: i64,
    matched_total: Option<i64>,
) -> Result<bool> {
    let client = pool.get().await?;
    let updated = client
        .execute(
            "UPDATE data_export_task SET status='completed', file_path=$3, file_size=$4, sha256=$5, \
             exported_rows=$6, matched_total=COALESCE($7, matched_total), finished_at=NOW(), \
             s3_object=$8, s3_failed=$9, \
             worker_id=NULL, lease_expires_at=NULL, updated_at=NOW() \
             WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_expires_at >= $10",
            &[&id, &worker_id, &file_path, &file_size, &sha256, &exported_rows, &matched_total, &s3_object, &s3_failed, &Utc::now().timestamp_millis()],
        )
        .await?;
    Ok(updated == 1)
}

pub async fn set_error(pool: &Pool, id: Uuid, worker_id: Uuid, message: &str) -> Result<()> {
    let client = pool.get().await?;
    let truncated: String = message.chars().take(2000).collect();
    client
        .execute(
            "UPDATE data_export_task SET status='error', error_message=$2, finished_at=NOW(), \
             worker_id=NULL, lease_expires_at=NULL, updated_at=NOW() WHERE id=$1 AND status='running' AND worker_id=$3 AND lease_expires_at >= $4",
            &[&id, &truncated, &worker_id, &Utc::now().timestamp_millis()],
        )
        .await?;
    Ok(())
}

pub async fn purge_expired(pool: &Pool, retention_days: u32) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "DELETE FROM data_export_task WHERE id IN (
             SELECT id FROM data_export_task WHERE status IN ('completed','cancelled','error')
               AND finished_at < NOW() - ($1::TEXT || ' days')::INTERVAL
             ORDER BY finished_at LIMIT 100 FOR UPDATE SKIP LOCKED
         )",
            &[&retention_days.to_string()],
        )
        .await?;
    Ok(())
}

pub async fn register_attempt(
    pool: &Pool,
    id: Uuid,
    attempt: Uuid,
    local_path: &str,
    s3_object: Option<&Value>,
) -> Result<bool> {
    let client = pool.get().await?;
    Ok(client
        .execute(
            "INSERT INTO data_export_attempt (id, task_id, local_path, s3_object)
         SELECT $2, id, $3, $4 FROM data_export_task
         WHERE id=$1 AND worker_id=$2 AND status='running' FOR UPDATE",
            &[&id, &attempt, &local_path, &s3_object],
        )
        .await?
        == 1)
}

pub async fn record_multipart(pool: &Pool, attempt: Uuid, upload_id: Option<&str>) -> Result<()> {
    let client = pool.get().await?;
    let updated = client
        .execute(
            "UPDATE data_export_attempt SET multipart_upload_id=$2 WHERE id=$1",
            &[&attempt, &upload_id],
        )
        .await?;
    if updated != 1 {
        return Err("导出分片上传记录不存在".into());
    }
    Ok(())
}

pub struct Cleanup {
    pub id: Uuid,
    pub local_path: Option<String>,
    pub s3_object: Option<Value>,
    pub multipart_upload_id: Option<String>,
}

pub async fn claim_cleanup(pool: &Pool) -> Result<Option<Cleanup>> {
    let client = pool.get().await?;
    let row = client.query_opt(
        "WITH next AS (
             SELECT a.id,
                    CASE WHEN a.local_path IS DISTINCT FROM t.file_path THEN a.local_path END AS local_path,
                    CASE WHEN a.s3_object IS DISTINCT FROM t.s3_object THEN a.s3_object END AS s3_object,
                    a.multipart_upload_id
               FROM data_export_attempt a LEFT JOIN data_export_task t ON a.task_id=t.id
              WHERE a.cleanup_after < NOW()
                AND (t.worker_id IS DISTINCT FROM a.id OR t.lease_expires_at < $1)
                AND ((a.local_path IS NOT NULL AND a.local_path IS DISTINCT FROM t.file_path)
                   OR (a.s3_object IS NOT NULL AND a.s3_object IS DISTINCT FROM t.s3_object))
              ORDER BY a.cleanup_after LIMIT 1 FOR UPDATE OF a SKIP LOCKED
         )
         UPDATE data_export_attempt a SET cleanup_after=NOW() + INTERVAL '10 minutes'
         FROM next WHERE a.id=next.id RETURNING a.id, next.local_path, next.s3_object, next.multipart_upload_id",
        &[&Utc::now().timestamp_millis()],
    ).await?;
    Ok(row.map(|row| Cleanup {
        id: row.get(0),
        local_path: row.get(1),
        s3_object: row.get(2),
        multipart_upload_id: row.get(3),
    }))
}

pub async fn finish_cleanup(pool: &Pool, id: Uuid, local: bool, s3: bool) -> Result<()> {
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    transaction
        .execute(
            "UPDATE data_export_attempt SET
            local_path=CASE WHEN $2 THEN NULL ELSE local_path END,
            s3_object=CASE WHEN $3 THEN NULL ELSE s3_object END,
            multipart_upload_id=CASE WHEN $3 THEN NULL ELSE multipart_upload_id END
         WHERE id=$1",
            &[&id, &local, &s3],
        )
        .await?;
    transaction.execute(
        "DELETE FROM data_export_attempt WHERE id=$1 AND local_path IS NULL AND s3_object IS NULL",
        &[&id],
    ).await?;
    transaction.commit().await?;
    Ok(())
}
