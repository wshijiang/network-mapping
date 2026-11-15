//! 联测持久层：数据源（凭据/代理加密）与 run 台账。
//!
//! 凭据加密复用 `crate::notification::{encrypt, decrypt}`（AES-GCM，配置 encrypt_key）；
//! API/CLI 永不回显明文。run 租约认领与 data_import 同款（FOR UPDATE SKIP LOCKED）。

use deadpool_postgres::Pool;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::federation::model::{PaginationMode, SourceKind, WindowMode};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug)]
pub enum StorageError {
    Conflict,
    NotFound,
    Invalid(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict => f.write_str("revision conflict"),
            Self::NotFound => f.write_str("not found"),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for StorageError {}

// ---- 数据源 ----

#[derive(Clone, Debug)]
pub struct Source {
    pub id: Uuid,
    pub kind: SourceKind,
    pub name: String,
    pub enabled: bool,
    pub credential_ciphertext: Option<Vec<u8>>,
    pub proxy_mode: String,
    pub proxy_ciphertext: Option<Vec<u8>>,
    pub fields: Vec<String>,
    pub pagination_mode: PaginationMode,
    pub page_size: u32,
    pub max_pages: u32,
    pub window_mode: WindowMode,
    pub window_days: u32,
    pub timeout_seconds: u32,
    pub rate_limit_qps: f64,
    pub detected_capabilities: Option<Value>,
    pub revision: i64,
}

const SOURCE_COLS: &str = "id, kind, name, enabled, credential_ciphertext, proxy_mode, proxy_ciphertext, \
     fields, pagination_mode, page_size, max_pages, window_mode, window_days, timeout_seconds, \
     rate_limit_qps, detected_capabilities, revision";

fn row_to_source(row: &tokio_postgres::Row) -> Result<Source> {
    let kind: String = row.get("kind");
    let fields: Value = row.get("fields");
    Ok(Source {
        id: row.get("id"),
        kind: SourceKind::parse(&kind)
            .ok_or_else(|| StorageError::Invalid(format!("unknown source kind {kind}")))?,
        name: row.get("name"),
        enabled: row.get("enabled"),
        credential_ciphertext: row.get("credential_ciphertext"),
        proxy_mode: row.get("proxy_mode"),
        proxy_ciphertext: row.get("proxy_ciphertext"),
        fields: serde_json::from_value(fields)?,
        pagination_mode: serde_json::from_value(Value::String(row.get("pagination_mode")))?,
        page_size: row.get::<_, i32>("page_size") as u32,
        max_pages: row.get::<_, i32>("max_pages") as u32,
        window_mode: serde_json::from_value(Value::String(row.get("window_mode")))?,
        window_days: row.get::<_, i32>("window_days") as u32,
        timeout_seconds: row.get::<_, i32>("timeout_seconds") as u32,
        rate_limit_qps: row.get("rate_limit_qps"),
        detected_capabilities: row.get("detected_capabilities"),
        revision: row.get("revision"),
    })
}

pub async fn list_sources(pool: &Pool) -> Result<Vec<Source>> {
    let rows = pool
        .get()
        .await?
        .query(
            &format!(
                "SELECT {SOURCE_COLS} FROM federation_source WHERE deleted_at IS NULL ORDER BY created_at, id"
            ),
            &[],
        )
        .await?;
    rows.iter().map(row_to_source).collect()
}

pub async fn get_source(pool: &Pool, id: Uuid) -> Result<Option<Source>> {
    let row = pool
        .get()
        .await?
        .query_opt(
            &format!(
                "SELECT {SOURCE_COLS} FROM federation_source WHERE id=$1 AND deleted_at IS NULL"
            ),
            &[&id],
        )
        .await?;
    row.as_ref().map(row_to_source).transpose()
}

/// 创建/更新输入（凭据与代理 URL 为明文，落库前加密）。
#[derive(Clone, Debug)]
pub struct SourceInput {
    pub kind: SourceKind,
    pub name: String,
    pub enabled: bool,
    /// None = 不修改（更新时）；Some = 替换。
    pub credential: Option<Value>,
    pub clear_credential: bool,
    pub proxy_mode: String,
    pub proxy_url: Option<String>,
    pub fields: Vec<String>,
    pub pagination_mode: PaginationMode,
    pub page_size: u32,
    pub max_pages: u32,
    pub window_mode: WindowMode,
    pub window_days: u32,
    pub timeout_seconds: u32,
    pub rate_limit_qps: f64,
}

impl SourceInput {
    pub fn validate(&self) -> std::result::Result<(), String> {
        let name = self.name.trim();
        if name.is_empty() || name.chars().count() > 64 {
            return Err("数据源名称须为 1..64 字符".into());
        }
        if !matches!(self.proxy_mode.as_str(), "system" | "direct" | "custom") {
            return Err("proxy_mode 须为 system/direct/custom".into());
        }
        if self.proxy_mode == "custom" {
            let url = self.proxy_url.as_deref().unwrap_or("");
            crate::outbound_proxy::validate_url(url).map_err(|_| "代理 URL 无效")?;
        }
        if self.fields.is_empty() {
            return Err("fields 不能为空".into());
        }
        for field in &self.fields {
            if !crate::federation::model::FIELD_NAMES.contains(&field.as_str()) {
                return Err(format!("非法字段 {field}"));
            }
        }
        if !(1..=1000).contains(&self.page_size) {
            return Err("page_size 须在 1..=1000".into());
        }
        if !(1..=50).contains(&self.max_pages) {
            return Err("max_pages 须在 1..=50".into());
        }
        if !(1..=60).contains(&self.window_days) {
            return Err("window_days 须在 1..=60".into());
        }
        if !(3..=120).contains(&self.timeout_seconds) {
            return Err("timeout_seconds 须在 3..=120".into());
        }
        if !(0.0..=10.0).contains(&self.rate_limit_qps) || self.rate_limit_qps <= 0.0 {
            return Err("rate_limit_qps 须在 (0, 10]".into());
        }
        Ok(())
    }
}

fn secret_error() -> Box<dyn std::error::Error + Send + Sync> {
    "凭据加密切换失败（encrypt_key 无效）".into()
}

fn encrypt_json(value: &Value, key: &str) -> Result<Vec<u8>> {
    let raw = serde_json::to_string(value)?;
    crate::notification::encrypt(&raw, key).map_err(|_| secret_error())
}

pub fn decrypt_json(cipher: Option<&[u8]>, key: &str) -> Result<Option<Value>> {
    match cipher {
        Some(bytes) => {
            let raw = crate::notification::decrypt(bytes, key).map_err(|_| secret_error())?;
            Ok(Some(serde_json::from_str(&raw)?))
        }
        None => Ok(None),
    }
}

pub async fn create_source(pool: &Pool, input: &SourceInput, encrypt_key: &str) -> Result<Source> {
    input.validate().map_err(StorageError::Invalid)?;
    let id = Uuid::now_v7();
    let credential_cipher = match &input.credential {
        Some(value) => Some(encrypt_json(value, encrypt_key)?),
        None => None,
    };
    let proxy_cipher = match (&input.proxy_mode[..], &input.proxy_url) {
        ("custom", Some(url)) => {
            Some(crate::notification::encrypt(url, encrypt_key).map_err(|_| secret_error())?)
        }
        _ => None,
    };
    let fields = serde_json::to_value(&input.fields)?;
    let pagination_mode = serde_json::to_value(input.pagination_mode)?;
    let window_mode = serde_json::to_value(input.window_mode)?;
    let row = pool
        .get()
        .await?
        .query_one(
            &format!(
                "INSERT INTO federation_source (id, kind, name, enabled, credential_ciphertext, \
                 proxy_mode, proxy_ciphertext, fields, pagination_mode, page_size, max_pages, \
                 window_mode, window_days, timeout_seconds, rate_limit_qps) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING {SOURCE_COLS}"
            ),
            &[
                &id,
                &input.kind.as_str(),
                &input.name.trim(),
                &input.enabled,
                &credential_cipher,
                &input.proxy_mode,
                &proxy_cipher,
                &fields,
                &pagination_mode.as_str().unwrap_or("follow_local"),
                &(input.page_size as i32),
                &(input.max_pages as i32),
                &window_mode.as_str().unwrap_or("follow"),
                &(input.window_days as i32),
                &(input.timeout_seconds as i32),
                &input.rate_limit_qps,
            ],
        )
        .await?;
    row_to_source(&row)
}

pub async fn update_source(
    pool: &Pool,
    id: Uuid,
    expected_revision: i64,
    input: &SourceInput,
    encrypt_key: &str,
) -> std::result::Result<Source, StorageError> {
    input.validate().map_err(StorageError::Invalid)?;
    let existing = get_source(pool, id)
        .await
        .map_err(|e| StorageError::Invalid(e.to_string()))?
        .ok_or(StorageError::NotFound)?;
    let credential_cipher = if input.clear_credential {
        None
    } else {
        match &input.credential {
            Some(value) => Some(
                encrypt_json(value, encrypt_key)
                    .map_err(|e| StorageError::Invalid(e.to_string()))?,
            ),
            None => existing.credential_ciphertext.clone(),
        }
    };
    let proxy_cipher = match (&input.proxy_mode[..], &input.proxy_url) {
        ("custom", Some(url)) => {
            Some(crate::notification::encrypt(url, encrypt_key).map_err(|_| {
                StorageError::Invalid("凭据加密切换失败（encrypt_key 无效）".into())
            })?)
        }
        ("custom", None) => existing.proxy_ciphertext.clone(),
        _ => None,
    };
    let fields =
        serde_json::to_value(&input.fields).map_err(|e| StorageError::Invalid(e.to_string()))?;
    let pagination_mode = serde_json::to_value(input.pagination_mode)
        .map_err(|e| StorageError::Invalid(e.to_string()))?;
    let window_mode = serde_json::to_value(input.window_mode)
        .map_err(|e| StorageError::Invalid(e.to_string()))?;
    let row = pool
        .get()
        .await
        .map_err(|e| StorageError::Invalid(e.to_string()))?
        .query_opt(
            &format!(
                "UPDATE federation_source SET kind=$1, name=$2, enabled=$3, credential_ciphertext=$4, \
                 proxy_mode=$5, proxy_ciphertext=$6, fields=$7, pagination_mode=$8, page_size=$9, \
                 max_pages=$10, window_mode=$11, window_days=$12, timeout_seconds=$13, rate_limit_qps=$14, \
                 revision=revision+1, updated_at=NOW() \
                 WHERE id=$15 AND revision=$16 AND deleted_at IS NULL RETURNING {SOURCE_COLS}"
            ),
            &[
                &input.kind.as_str(),
                &input.name.trim(),
                &input.enabled,
                &credential_cipher,
                &input.proxy_mode,
                &proxy_cipher,
                &fields,
                &pagination_mode.as_str().unwrap_or("follow_local"),
                &(input.page_size as i32),
                &(input.max_pages as i32),
                &window_mode.as_str().unwrap_or("follow"),
                &(input.window_days as i32),
                &(input.timeout_seconds as i32),
                &input.rate_limit_qps,
                &id,
                &expected_revision,
            ],
        )
        .await
        .map_err(|e| StorageError::Invalid(e.to_string()))?;
    match row {
        Some(row) => row_to_source(&row).map_err(|e| StorageError::Invalid(e.to_string())),
        None => Err(StorageError::Conflict),
    }
}

pub async fn delete_source(
    pool: &Pool,
    id: Uuid,
    expected_revision: i64,
) -> std::result::Result<(), StorageError> {
    let affected = pool
        .get()
        .await
        .map_err(|e| StorageError::Invalid(e.to_string()))?
        .execute(
            "UPDATE federation_source SET deleted_at=NOW(), revision=revision+1 \
             WHERE id=$1 AND revision=$2 AND deleted_at IS NULL",
            &[&id, &expected_revision],
        )
        .await
        .map_err(|e| StorageError::Invalid(e.to_string()))?;
    if affected == 0 {
        return Err(StorageError::Conflict);
    }
    Ok(())
}

pub async fn update_capabilities(pool: &Pool, id: Uuid, capabilities: &Value) -> Result<()> {
    pool.get()
        .await?
        .execute(
            "UPDATE federation_source SET detected_capabilities=$1, updated_at=NOW() WHERE id=$2",
            &[capabilities, &id],
        )
        .await?;
    Ok(())
}

/// 脱敏公开视图（API/CLI 共用）。
pub fn source_public(source: &Source, encrypt_key: &str) -> Value {
    let proxy_endpoint = source
        .proxy_ciphertext
        .as_deref()
        .and_then(|cipher| crate::notification::decrypt(cipher, encrypt_key).ok())
        .and_then(|url| crate::outbound_proxy::endpoint(&url).ok())
        .unwrap_or_default();
    json!({
        "id": source.id,
        "kind": source.kind.as_str(),
        "kind_name": source.kind.display_name(),
        "name": source.name,
        "enabled": source.enabled,
        "credential_configured": source.credential_ciphertext.is_some(),
        "proxy_mode": source.proxy_mode,
        "proxy_endpoint": proxy_endpoint,
        "proxy_configured": source.proxy_ciphertext.is_some(),
        "fields": source.fields,
        "pagination_mode": source.pagination_mode,
        "page_size": source.page_size,
        "max_pages": source.max_pages,
        "window_mode": source.window_mode,
        "window_days": source.window_days,
        "timeout_seconds": source.timeout_seconds,
        "rate_limit_qps": source.rate_limit_qps,
        "capabilities": source.detected_capabilities,
        "revision": source.revision,
    })
}

// ---- run 台账 ----

#[derive(Clone, Debug)]
pub struct Run {
    pub id: Uuid,
    pub query_text: String,
    pub query_hash: String,
    pub trigger: String,
    pub mode: String,
    pub status: String,
    pub requested_by: i32,
    pub window_days: u32,
    pub local_state: String,
    pub selected_sources: Option<Vec<Uuid>>,
    pub local_limit: u32,
    pub local_offset: u32,
    pub persist_override: String,
    pub sources: Value,
    pub total_fetched: i32,
    pub total_merged: i32,
    pub total_persisted: i32,
    pub result_cache: Option<Value>,
    pub persist_decision: Option<Value>,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
}

const RUN_COLS: &str = "id, query_text, query_hash, trigger, mode, status, requested_by, window_days, \
     local_state, selected_sources, local_limit, local_offset, persist_override, sources, total_fetched, \
     total_merged, total_persisted, result_cache, persist_decision, \
     error_message, created_at, started_at, finished_at";

fn row_to_run(row: &tokio_postgres::Row) -> Run {
    Run {
        id: row.get("id"),
        query_text: row.get("query_text"),
        query_hash: row.get("query_hash"),
        trigger: row.get("trigger"),
        mode: row.get("mode"),
        status: row.get("status"),
        requested_by: row.get("requested_by"),
        window_days: row.get::<_, i32>("window_days") as u32,
        local_state: row.get("local_state"),
        selected_sources: row
            .get::<_, Option<Value>>("selected_sources")
            .map(serde_json::from_value)
            .transpose()
            .unwrap_or(None),
        local_limit: row.get::<_, i32>("local_limit") as u32,
        local_offset: row.get::<_, i32>("local_offset") as u32,
        persist_override: row.get("persist_override"),
        sources: row.get("sources"),
        total_fetched: row.get("total_fetched"),
        total_merged: row.get("total_merged"),
        total_persisted: row.get("total_persisted"),
        result_cache: row.get("result_cache"),
        persist_decision: row.get("persist_decision"),
        error_message: row.get("error_message"),
        created_at: row.get("created_at"),
        started_at: row.get("started_at"),
        finished_at: row.get("finished_at"),
    }
}

pub struct NewRun<'a> {
    pub query_text: &'a str,
    pub query_hash: &'a str,
    pub trigger: &'a str,
    pub mode: &'a str,
    pub requested_by: i32,
    pub window_days: u32,
    pub local_state: &'a str,
    pub selected_sources: Option<Vec<Uuid>>,
    pub local_limit: u32,
    pub local_offset: u32,
    pub persist_override: &'a str,
    /// search/web 触发立即 running（进程内执行）；CLI 触发 pending（worker 认领）。
    pub status: &'a str,
    pub worker_id: Option<Uuid>,
    pub lease_ms: i64,
}

pub async fn create_run(pool: &Pool, new: NewRun<'_>) -> Result<Run> {
    let id = Uuid::now_v7();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let lease = new.worker_id.map(|_| now_ms + new.lease_ms);
    let selected = new
        .selected_sources
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?;
    let row = pool
        .get()
        .await?
        .query_one(
            &format!(
                "INSERT INTO federation_run (id, query_text, query_hash, trigger, mode, status, \
                 requested_by, window_days, local_state, selected_sources, local_limit, local_offset, \
                 persist_override, worker_id, lease_expires_at, started_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,CASE WHEN $6='running' THEN NOW() ELSE NULL END) \
                 RETURNING {RUN_COLS}"
            ),
            &[
                &id,
                &new.query_text,
                &new.query_hash,
                &new.trigger,
                &new.mode,
                &new.status,
                &new.requested_by,
                &(new.window_days as i32),
                &new.local_state,
                &selected,
                &(new.local_limit as i32),
                &(new.local_offset as i32),
                &new.persist_override,
                &new.worker_id,
                &lease,
            ],
        )
        .await?;
    Ok(row_to_run(&row))
}

pub async fn get_run(pool: &Pool, id: Uuid) -> Result<Option<Run>> {
    let row = pool
        .get()
        .await?
        .query_opt(
            &format!("SELECT {RUN_COLS} FROM federation_run WHERE id=$1"),
            &[&id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_run))
}

pub async fn list_runs(
    pool: &Pool,
    status: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<(Vec<Run>, i64)> {
    let client = pool.get().await?;
    let (rows, total) = match status {
        Some(status) => (
            client
                .query(
                    &format!(
                        "SELECT {RUN_COLS} FROM federation_run WHERE status=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
                    ),
                    &[&status, &limit, &offset],
                )
                .await?,
            client
                .query_one(
                    "SELECT COUNT(*)::BIGINT FROM federation_run WHERE status=$1",
                    &[&status],
                )
                .await?
                .get::<_, i64>(0),
        ),
        None => (
            client
                .query(
                    &format!(
                        "SELECT {RUN_COLS} FROM federation_run ORDER BY created_at DESC LIMIT $1 OFFSET $2"
                    ),
                    &[&limit, &offset],
                )
                .await?,
            client
                .query_one("SELECT COUNT(*)::BIGINT FROM federation_run", &[])
                .await?
                .get::<_, i64>(0),
        ),
    };
    Ok((rows.iter().map(row_to_run).collect(), total))
}

/// 认领一个 pending 或租约过期的 running run（原子）。
pub async fn claim_next(pool: &Pool, worker_id: Uuid, lease_ms: i64) -> Result<Option<Run>> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let row = pool
        .get()
        .await?
        .query_opt(
            &format!(
                "UPDATE federation_run SET worker_id=$1, lease_expires_at=$2, status='running', \
                 started_at=COALESCE(started_at, NOW()) \
                 WHERE id = (SELECT id FROM federation_run \
                    WHERE status='pending' OR (status='running' AND lease_expires_at < $3) \
                    ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) \
                 RETURNING {RUN_COLS}"
            ),
            &[&worker_id, &(now_ms + lease_ms), &now_ms],
        )
        .await?;
    Ok(row.as_ref().map(row_to_run))
}

pub async fn renew_lease(pool: &Pool, id: Uuid, worker_id: Uuid, lease_ms: i64) -> Result<()> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    pool.get()
        .await?
        .execute(
            "UPDATE federation_run SET lease_expires_at=$1 WHERE id=$2 AND worker_id=$3 AND status='running'",
            &[&(now_ms + lease_ms), &id, &worker_id],
        )
        .await?;
    Ok(())
}

pub async fn count_active_runs(pool: &Pool) -> Result<i64> {
    Ok(pool
        .get()
        .await?
        .query_one(
            "SELECT COUNT(*)::BIGINT FROM federation_run WHERE status IN ('pending','running')",
            &[],
        )
        .await?
        .get(0))
}

/// 冷却窗口内最近终态 run（复用 result_cache）。
pub async fn recent_run_by_hash(
    pool: &Pool,
    query_hash: &str,
    cooldown_seconds: u64,
) -> Result<Option<Run>> {
    let row = pool
        .get()
        .await?
        .query_opt(
            &format!(
                "SELECT {RUN_COLS} FROM federation_run \
                 WHERE query_hash=$1 AND status IN ('completed','partial') \
                 AND finished_at > NOW() - ($2 || ' seconds')::INTERVAL \
                 ORDER BY finished_at DESC LIMIT 1"
            ),
            &[&query_hash, &cooldown_seconds.to_string()],
        )
        .await?;
    Ok(row.as_ref().map(row_to_run))
}

/// 在途同查询 run（在途去重）。
pub async fn running_run_by_hash(pool: &Pool, query_hash: &str) -> Result<Option<Run>> {
    let row = pool
        .get()
        .await?
        .query_opt(
            &format!(
                "SELECT {RUN_COLS} FROM federation_run \
                 WHERE query_hash=$1 AND status IN ('pending','running') \
                 ORDER BY created_at DESC LIMIT 1"
            ),
            &[&query_hash],
        )
        .await?;
    Ok(row.as_ref().map(row_to_run))
}

#[allow(clippy::too_many_arguments)]
pub async fn finish_run(
    pool: &Pool,
    id: Uuid,
    status: &str,
    sources: &Value,
    total_fetched: i32,
    total_merged: i32,
    total_persisted: i32,
    result_cache: Option<&Value>,
    persist_decision: Option<&Value>,
    error_message: Option<&str>,
) -> Result<()> {
    pool.get()
        .await?
        .execute(
            "UPDATE federation_run SET status=$1, sources=$2, total_fetched=$3, total_merged=$4, \
             total_persisted=$5, result_cache=$6, persist_decision=$7, error_message=$8, \
             finished_at=NOW(), lease_expires_at=NULL \
             WHERE id=$9 AND status IN ('pending','running')",
            &[
                &status,
                sources,
                &total_fetched,
                &total_merged,
                &total_persisted,
                &result_cache,
                &persist_decision,
                &error_message,
                &id,
            ],
        )
        .await?;
    Ok(())
}

/// 入库链接（scan_task/execution/upload），入库成功后记录。
pub async fn link_scan_task(
    pool: &Pool,
    id: Uuid,
    scan_task_id: i32,
    execution_id: i32,
    upload_id: Uuid,
) -> Result<()> {
    pool.get()
        .await?
        .execute(
            "UPDATE federation_run SET scan_task_id=$1, execution_id=$2, upload_id=$3 WHERE id=$4",
            &[&scan_task_id, &execution_id, &upload_id, &id],
        )
        .await?;
    Ok(())
}

pub async fn cancel_run(pool: &Pool, id: Uuid) -> std::result::Result<(), StorageError> {
    let affected = pool
        .get()
        .await
        .map_err(|e| StorageError::Invalid(e.to_string()))?
        .execute(
            "UPDATE federation_run SET status='cancelled', finished_at=NOW(), lease_expires_at=NULL \
             WHERE id=$1 AND status IN ('pending','running')",
            &[&id],
        )
        .await
        .map_err(|e| StorageError::Invalid(e.to_string()))?;
    if affected == 0 {
        return Err(StorageError::Conflict);
    }
    Ok(())
}

pub async fn delete_run(pool: &Pool, id: Uuid) -> std::result::Result<(), StorageError> {
    let affected = pool
        .get()
        .await
        .map_err(|e| StorageError::Invalid(e.to_string()))?
        .execute(
            "DELETE FROM federation_run WHERE id=$1 AND status IN ('completed','partial','failed','cancelled')",
            &[&id],
        )
        .await
        .map_err(|e| StorageError::Invalid(e.to_string()))?;
    if affected == 0 {
        return Err(StorageError::Conflict);
    }
    Ok(())
}

pub async fn purge_expired(pool: &Pool, retention_days: u32) -> Result<u64> {
    Ok(pool
        .get()
        .await?
        .execute(
            "DELETE FROM federation_run WHERE status IN ('completed','partial','failed','cancelled') \
             AND finished_at < NOW() - ($1 || ' days')::INTERVAL",
            &[&retention_days.to_string()],
        )
        .await?)
}

/// run 公开视图。
pub fn run_public(run: &Run, include_cache: bool) -> Value {
    let mut value = json!({
        "id": run.id,
        "query": run.query_text,
        "trigger": run.trigger,
        "mode": run.mode,
        "status": run.status,
        "requested_by": run.requested_by,
        "window_days": run.window_days,
        "local_state": run.local_state,
        "selected_sources": run.selected_sources,
        "local_limit": run.local_limit,
        "local_offset": run.local_offset,
        "persist_override": run.persist_override,
        "sources": run.sources,
        "total_fetched": run.total_fetched,
        "total_merged": run.total_merged,
        "total_persisted": run.total_persisted,
        "persist_decision": run.persist_decision,
        "error_message": run.error_message,
        "created_at": run.created_at.timestamp_millis(),
        "started_at": run.started_at.map(|t| t.timestamp_millis()),
        "finished_at": run.finished_at.map(|t| t.timestamp_millis()),
    });
    if include_cache {
        value["result_cache"] = run.result_cache.clone().unwrap_or(Value::Null);
    }
    value
}
