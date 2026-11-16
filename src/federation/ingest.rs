//! 联测写入桥：预留扫描器身份 + 合成扫描任务/执行，复用 `save_scanner_results` 管道。
//!
//! 与 data_import/ingest.rs 同构，但使用 federation 身份与证据来源标记，
//! 合并策略固定 `overwrite`（observed_at 新者胜 + 服务时钟守卫，§9.4）。

use deadpool_postgres::Pool;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::data_import::csv::ImportRow;
use crate::dns_follow_up::DnsFollowUpConfig;
use crate::elasticsearch::ElasticsearchService;
use crate::federation::model::NormalizedRecord;
use crate::federation::{
    FEDERATION_SCANNER_ID, FEDERATION_SCANNER_NAME, FEDERATION_SCANNER_REMARK,
};
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
    let digest = openssl::sha::sha256(format!("nm-federation:{encrypt_key}").as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// 确保预留扫描器存在并持有当前密钥派生的运行 token，返回原始 token。
pub async fn ensure_federation_scanner(
    pool: &Pool,
    encrypt_key: &str,
    pepper: &str,
) -> Result<String> {
    let raw = derive_token(encrypt_key);
    let hash = hash_scanner_token(&raw, pepper)?;
    pool.get()
        .await?
        .execute(
            "INSERT INTO scanner_info (name, scanner_id, create_user, runtime_token_hash, is_enable, is_run, remark, create_time, register_time) \
             VALUES ($1,$2,0,$3,true,false,$4,NOW(),NOW()) \
             ON CONFLICT (scanner_id) DO UPDATE SET runtime_token_hash=EXCLUDED.runtime_token_hash, is_enable=true, deleted_at=NULL",
            &[&FEDERATION_SCANNER_NAME, &FEDERATION_SCANNER_ID, &hash, &FEDERATION_SCANNER_REMARK],
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

/// 创建联测对应的扫描任务与执行（task_source='federation'）。
pub async fn ensure_scan_task(pool: &Pool, run_id: Uuid, requested_by: i32) -> Result<ScanLink> {
    let mut client = pool.get().await?;
    let public_task_id = Uuid::now_v7();
    let upload_id = Uuid::now_v7();
    let execution_public = Uuid::now_v7();
    let now = chrono::Utc::now().timestamp_millis();
    let metadata = json!({"federation_run_id": run_id, "import_policy": "overwrite"});
    let transaction = client.transaction().await?;
    let scan_task_db_id: i32 = transaction
        .query_one(
            "INSERT INTO scan_task (user_id, task_id, task_initiator, task_target, task_status, task_source, scan_profile, task_kind, generation_metadata, task_create_time) \
             VALUES ($1,$2,'federation',ARRAY[]::INET[],'running','federation','service_inventory','ip',$3,$4) RETURNING id",
            &[&requested_by, &public_task_id.to_string(), &metadata, &now],
        )
        .await?
        .get(0);
    let execution_db_id: i32 = transaction
        .query_one(
            "INSERT INTO scan_task_execution (execution_id, task_id, requested_scanner_id, assigned_scanner_id, execution_status, task_start_time) \
             VALUES ($1,$2,$3,$3,'running',$4) RETURNING id",
            &[&execution_public.to_string(), &scan_task_db_id, &FEDERATION_SCANNER_ID, &now],
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

/// 归一化记录 → 导入行模型（复用校验/富化/幂等写入）。
pub fn record_to_row(record: &NormalizedRecord) -> ImportRow {
    let kind = if record.service.is_some() || record.title.is_some() || !record.tech.is_empty() {
        "service"
    } else {
        "port"
    };
    ImportRow {
        ip: record.ip.clone(),
        port: record.port,
        protocol: record.protocol.clone(),
        observed_at: record.observed_at,
        service: record.service.clone(),
        banner: record.banner.clone(),
        source: format!(
            "federation:{}",
            record
                .sources
                .first()
                .map(String::as_str)
                .unwrap_or("unknown")
        ),
        asn: record.asn.clone(),
        as_org: record.as_org.clone(),
        country_code: None,
        country_name: record.country_name.clone(),
        region_name: record.region_name.clone(),
        city_name: record.city_name.clone(),
        latitude: record.latitude,
        longitude: record.longitude,
        os: None,
        os_confidence: None,
        tech: record.tech.clone(),
        title: record.title.clone(),
        kind,
    }
}

fn web_preset(row: &ImportRow) -> Option<Value> {
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
            confidence: "medium".into(),
            basis: "federation".into(),
            usage: "imported".into(),
            evidence: vec![crate::web_detection::WebEvidence {
                rule_id: "federation".into(),
                module: "federation".into(),
                field_path: "/federation/tech".into(),
                excerpt: entry.id.clone(),
                observation_ref: None,
            }],
        })
        .collect();
    let inference = crate::web_detection::WebInference {
        status: "identified".into(),
        inference_scope: "federation".into(),
        technologies,
        truncated: false,
        ruleset_revision: crate::web_detection::RULESET_REVISION,
        ruleset_version: crate::web_detection::RULESET_VERSION.into(),
        observed_at: Some(row.observed_at),
        stale: false,
    };
    serde_json::to_value(inference).ok()
}

/// 携带优先富化的观察；合并策略固定 overwrite（新者胜）。
pub fn build_observation(row: &ImportRow) -> ScannerObservation {
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
        os: None,
        web: web_preset(row),
        import_policy: Some("overwrite".to_owned()),
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
        scanner_id: FEDERATION_SCANNER_ID
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
