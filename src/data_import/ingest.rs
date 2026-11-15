//! 导入写入桥：预留扫描器身份 + 合成扫描任务/执行，复用 `save_scanner_results` 管道。
//!
//! 不重写 ingest 核心：PG 事实、各类 outbox、投影、分析、任务聚合均由既有管道处理。
//! CSV 优先富化经 [`ImportEnrichment`]  additive 携带，扫描器路径行为不变。

use deadpool_postgres::Pool;
use serde_json::json;
use uuid::Uuid;

use crate::data_import::csv::ImportRow;
use crate::data_import::task::Task;
use crate::data_import::{IMPORT_SCANNER_ID, IMPORT_SCANNER_NAME, IMPORT_SCANNER_REMARK};
use crate::dns_follow_up::DnsFollowUpConfig;
use crate::elasticsearch::ElasticsearchService;
use crate::identity::hash_scanner_token;
use crate::maxmind::MaxMindState;
use crate::result_ingest::model::ImportEnrichment;
use crate::result_ingest::{
    SaveScannerResultsError, ScannerObservation, ScannerResultUpload, save_scanner_results,
};

/// typed 协议单批观察上限（与 result_ingest 校验一致）。
pub const ES_BATCH_MAX: usize = 500;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn derive_token(encrypt_key: &str) -> String {
    let digest = openssl::sha::sha256(format!("nm-data-import:{encrypt_key}").as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// 确保预留扫描器存在并持有当前密钥派生的运行 token，返回原始 token。
pub async fn ensure_import_scanner(pool: &Pool, encrypt_key: &str, pepper: &str) -> Result<String> {
    let raw = derive_token(encrypt_key);
    let hash = hash_scanner_token(&raw, pepper)?;
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO scanner_info (name, scanner_id, create_user, runtime_token_hash, is_enable, is_run, remark, create_time, register_time) \
             VALUES ($1,$2,0,$3,true,false,$4,NOW(),NOW()) \
             ON CONFLICT (scanner_id) DO UPDATE SET runtime_token_hash=EXCLUDED.runtime_token_hash, is_enable=true, deleted_at=NULL",
            &[&IMPORT_SCANNER_NAME, &IMPORT_SCANNER_ID, &hash, &IMPORT_SCANNER_REMARK],
        )
        .await?;
    Ok(raw)
}

#[derive(Clone)]
pub struct ScanLink {
    pub scan_task_db_id: i32,
    pub execution_db_id: i32,
    pub public_task_id: Uuid,
    pub upload_id: Uuid,
}

/// 创建（或复用）导入对应的扫描任务与执行。
pub async fn ensure_scan_task(pool: &Pool, task: &Task) -> Result<ScanLink> {
    let mut client = pool.get().await?;
    if let (Some(scan_db), Some(exec_db), Some(upload)) =
        (task.scan_task_id, task.execution_id, task.upload_id)
        && let Some(row) = client
            .query_opt("SELECT task_id FROM scan_task WHERE id=$1", &[&scan_db])
            .await?
    {
        let public_task_id: Uuid = row.get::<_, String>("task_id").parse()?;
        return Ok(ScanLink {
            scan_task_db_id: scan_db,
            execution_db_id: exec_db,
            public_task_id,
            upload_id: upload,
        });
    }
    let public_task_id = Uuid::now_v7();
    let upload_id = Uuid::now_v7();
    let execution_public = Uuid::now_v7();
    let now = chrono::Utc::now().timestamp_millis();
    let metadata = json!({"import_task_id": task.id, "import_policy": task.overwrite_policy});
    let transaction = client.transaction().await?;
    let scan_task_db_id: i32 = transaction
        .query_one(
            "INSERT INTO scan_task (user_id, task_id, task_initiator, task_target, task_status, task_source, scan_profile, task_kind, generation_metadata, task_create_time) \
             VALUES ($1,$2,'data-import',ARRAY[]::INET[],'running','import','service_inventory','ip',$3,$4) RETURNING id",
            &[&task.created_by, &public_task_id.to_string(), &metadata, &now],
        )
        .await?
        .get(0);
    let execution_db_id: i32 = transaction
        .query_one(
            "INSERT INTO scan_task_execution (execution_id, task_id, requested_scanner_id, assigned_scanner_id, execution_status, task_start_time) \
             VALUES ($1,$2,$3,$3,'running',$4) RETURNING id",
            &[&execution_public.to_string(), &scan_task_db_id, &IMPORT_SCANNER_ID, &now],
        )
        .await?
        .get(0);
    transaction.commit().await?;
    Ok(ScanLink {
        scan_task_db_id,
        execution_db_id,
        public_task_id,
        upload_id,
    })
}

fn os_preset(row: &ImportRow) -> Option<serde_json::Value> {
    let family = row.os.clone()?;
    let confidence = row
        .os_confidence
        .clone()
        .unwrap_or_else(|| "high".to_owned());
    let inference = crate::os_detection::OsInference {
        status: "identified".into(),
        inference_scope: "csv_import".into(),
        family: Some(family.clone()),
        distribution: None,
        version: None,
        confidence,
        score: 100,
        candidates: vec![crate::os_detection::OsCandidate {
            family: family.clone(),
            score: 100,
        }],
        evidence: vec![crate::os_detection::OsEvidence {
            rule_id: "csv-import".into(),
            module: "import".into(),
            field_path: "/csv/os".into(),
            excerpt: family.clone(),
            family,
            distribution: None,
            version: None,
            port: row.port,
            observation_ref: None,
            scanner_id: None,
        }],
        ruleset_revision: crate::os_detection::RULESET_REVISION,
        ruleset_version: crate::os_detection::RULESET_VERSION.into(),
        observed_at: Some(row.observed_at),
        stale: false,
    };
    serde_json::to_value(inference).ok()
}

fn web_preset(row: &ImportRow) -> Option<serde_json::Value> {
    if row.tech.is_empty() {
        return None;
    }
    let technologies = row
        .tech
        .iter()
        .map(|entry| crate::web_detection::Technology {
            id: entry.id.clone(),
            name: entry.id.clone(),
            category: "other".into(),
            version: entry.version.clone(),
            version_conflict: false,
            confidence: "high".into(),
            basis: "import".into(),
            usage: "imported".into(),
            evidence: vec![crate::web_detection::WebEvidence {
                rule_id: "csv-import".into(),
                module: "import".into(),
                field_path: "/csv/tech".into(),
                excerpt: entry.id.clone(),
                observation_ref: None,
            }],
        })
        .collect();
    let inference = crate::web_detection::WebInference {
        status: "identified".into(),
        inference_scope: "csv_import".into(),
        technologies,
        truncated: false,
        ruleset_revision: crate::web_detection::RULESET_REVISION,
        ruleset_version: crate::web_detection::RULESET_VERSION.into(),
        observed_at: Some(row.observed_at),
        stale: false,
    };
    serde_json::to_value(inference).ok()
}

/// 将校验后的一行转为携带优先富化的观察。
pub fn build_observation(row: &ImportRow, policy: &str) -> ScannerObservation {
    let enrichment = ImportEnrichment {
        title: row.title.clone(),
        asn: row.asn.clone(),
        as_org: row.as_org.clone(),
        isp: None,
        country_code: row.country_code.clone(),
        country_name: row.country_name.clone(),
        region_name: row.region_name.clone(),
        city_name: row.city_name.clone(),
        latitude: row.latitude,
        longitude: row.longitude,
        os: os_preset(row),
        web: web_preset(row),
        import_policy: Some(policy.to_owned()),
        observation_discriminator: Some(row.content_hash()),
    };
    ScannerObservation::Service {
        ip: row.ip.clone(),
        port: row.port,
        protocol: row.protocol.clone(),
        service: row.service.clone(),
        banner: row.banner.clone(),
        source: row.source.clone(),
        data: None,
        observed_at: Some(row.observed_at),
        enrichment: Some(enrichment),
    }
}

/// 写入一个 ≤500 观察的 ES 批次（复用扫描器结果管道）。
#[allow(clippy::too_many_arguments)]
pub async fn write_es_batch(
    pool: &Pool,
    maxmind: &MaxMindState,
    elasticsearch: &ElasticsearchService,
    dns_follow_up: &DnsFollowUpConfig,
    link: &ScanLink,
    batch_index: i32,
    is_final: bool,
    observations: Vec<ScannerObservation>,
    token: &str,
    pepper: &str,
) -> std::result::Result<usize, SaveScannerResultsError> {
    let upload = ScannerResultUpload {
        protocol_version: 3,
        scanner_id: IMPORT_SCANNER_ID
            .parse()
            .expect("reserved scanner id is a valid UUID"),
        task_id: link.public_task_id,
        upload_id: Some(link.upload_id),
        batch_index: Some(batch_index as u32),
        is_final: Some(is_final),
        observations,
        results: Vec::new(),
    };
    save_scanner_results(
        pool,
        maxmind,
        elasticsearch,
        dns_follow_up,
        &upload,
        token,
        pepper,
    )
    .await
}
