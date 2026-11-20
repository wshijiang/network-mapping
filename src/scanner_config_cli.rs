//! 服务器 CLI：`network_mapping_server scanner-config …`。
//!
//! 管理扫描器运行时配置中的网页内容富化（favicon / JS / 落地页）参数，
//! 与 Web 控制台「扫描器配置」写入同一份 `scanner_runtime_configuration`
//! 文档：新修订、历史记录与审计一致，扫描器下一次拉取配置即生效。
//! 仅需 PostgreSQL。

use clap::Subcommand;
use deadpool_postgres::{GenericClient, Pool};
use serde_json::json;
use uuid::Uuid;

use crate::audit::{AuditContext, AuditEvent, write as write_audit};
use crate::scanner_config::{
    SCHEMA_VERSION, ScannerRuntimeConfig, WebContentRuntimeConfig, ensure_configuration,
    load_configuration,
};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Subcommand)]
pub enum ScannerConfigCommand {
    /// 查看扫描器运行时配置（含网页内容富化参数）
    Show {
        /// 扫描器 ID
        scanner_id: Uuid,
    },
    /// 修改网页内容富化参数（仅更新给出的字段，写入新修订）
    SetWebContent {
        /// 扫描器 ID
        scanner_id: Uuid,
        /// 总开关（true/false）
        #[arg(long, value_parser = clap::value_parser!(bool))]
        enabled: Option<bool>,
        /// 全局并发抓取上限（1..=256）
        #[arg(long)]
        concurrency: Option<usize>,
        /// 单请求超时秒数（1..=120）
        #[arg(long)]
        fetch_timeout_seconds: Option<u64>,
        /// 重定向上限（0..=10）
        #[arg(long)]
        max_redirects: Option<usize>,
        /// 块级富化总预算秒数（1..=3600）
        #[arg(long)]
        max_stage_seconds: Option<u64>,
        /// favicon 原始字节上限（1024..=1048576，默认 65536）
        #[arg(long)]
        max_favicon_bytes: Option<usize>,
        /// 每页外部 JS 抓取上限（0..=64，默认 10）
        #[arg(long)]
        max_js_files: Option<usize>,
        /// 单 JS 下载字节上限（1024..=4194304）
        #[arg(long)]
        max_js_bytes: Option<usize>,
        /// 落地页 body 字节上限（1024..=1048576）
        #[arg(long)]
        max_body_bytes: Option<usize>,
        /// 抓取 User-Agent（空字符串恢复默认）
        #[arg(long)]
        user_agent: Option<String>,
        /// 变更原因（记入历史与审计，≤500 字符）
        #[arg(long, default_value = "")]
        change_reason: String,
    },
}

pub async fn execute(command: &ScannerConfigCommand, pool: &Pool) -> CliResult {
    match command {
        ScannerConfigCommand::Show { scanner_id } => show(pool, scanner_id).await,
        ScannerConfigCommand::SetWebContent {
            scanner_id,
            enabled,
            concurrency,
            fetch_timeout_seconds,
            max_redirects,
            max_stage_seconds,
            max_favicon_bytes,
            max_js_files,
            max_js_bytes,
            max_body_bytes,
            user_agent,
            change_reason,
        } => {
            let override_values = WebContentOverride {
                enabled: *enabled,
                concurrency: *concurrency,
                fetch_timeout_seconds: *fetch_timeout_seconds,
                max_redirects: *max_redirects,
                max_stage_seconds: *max_stage_seconds,
                max_favicon_bytes: *max_favicon_bytes,
                max_js_files: *max_js_files,
                max_js_bytes: *max_js_bytes,
                max_body_bytes: *max_body_bytes,
                user_agent: user_agent.clone(),
            };
            set_web_content(pool, scanner_id, override_values, change_reason).await
        }
    }
}

struct WebContentOverride {
    enabled: Option<bool>,
    concurrency: Option<usize>,
    fetch_timeout_seconds: Option<u64>,
    max_redirects: Option<usize>,
    max_stage_seconds: Option<u64>,
    max_favicon_bytes: Option<usize>,
    max_js_files: Option<usize>,
    max_js_bytes: Option<usize>,
    max_body_bytes: Option<usize>,
    user_agent: Option<String>,
}

impl WebContentOverride {
    fn is_empty(&self) -> bool {
        self.enabled.is_none()
            && self.concurrency.is_none()
            && self.fetch_timeout_seconds.is_none()
            && self.max_redirects.is_none()
            && self.max_stage_seconds.is_none()
            && self.max_favicon_bytes.is_none()
            && self.max_js_files.is_none()
            && self.max_js_bytes.is_none()
            && self.max_body_bytes.is_none()
            && self.user_agent.is_none()
    }

    fn apply(self, web: &mut WebContentRuntimeConfig) {
        if let Some(value) = self.enabled {
            web.enabled = value;
        }
        if let Some(value) = self.concurrency {
            web.concurrency = value;
        }
        if let Some(value) = self.fetch_timeout_seconds {
            web.fetch_timeout_seconds = value;
        }
        if let Some(value) = self.max_redirects {
            web.max_redirects = value;
        }
        if let Some(value) = self.max_stage_seconds {
            web.max_stage_seconds = value;
        }
        if let Some(value) = self.max_favicon_bytes {
            web.max_favicon_bytes = value;
        }
        if let Some(value) = self.max_js_files {
            web.max_js_files = value;
        }
        if let Some(value) = self.max_js_bytes {
            web.max_js_bytes = value;
        }
        if let Some(value) = self.max_body_bytes {
            web.max_body_bytes = value;
        }
        if let Some(value) = self.user_agent {
            web.user_agent = (!value.is_empty()).then_some(value);
        }
    }
}

async fn show(pool: &Pool, scanner_id: &Uuid) -> CliResult {
    let client = pool.get().await?;
    let configuration = load_configuration(&client, &scanner_id.to_string())
        .await?
        .ok_or("扫描器不存在")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "scanner_id": scanner_id.to_string(),
            "revision": configuration.revision,
            "schema_version": configuration.schema_version,
            "document": configuration.document,
        }))?
    );
    Ok(())
}

async fn set_web_content(
    pool: &Pool,
    scanner_id: &Uuid,
    override_values: WebContentOverride,
    change_reason: &str,
) -> CliResult {
    if override_values.is_empty() {
        return Err("未给出任何要修改的参数（--help 查看可用字段）".into());
    }
    if change_reason.chars().count() > 500 {
        return Err("change_reason 不能超过 500 个字符".into());
    }
    let scanner_id_string = scanner_id.to_string();
    let mut client = pool.get().await?;
    let configuration = load_configuration(&client, &scanner_id_string)
        .await?
        .ok_or("扫描器不存在")?;
    let mut document: ScannerRuntimeConfig = configuration.document;
    override_values.apply(&mut document.service_detection.web_content);
    document.validate()?;
    let document_json = serde_json::to_value(&document)?;
    let transaction = client.transaction().await?;
    ensure_configuration(&transaction, &scanner_id_string).await?;
    let updated = transaction
        .query_opt(
            "UPDATE scanner_runtime_configuration SET document = $1, revision = revision + 1, schema_version = $2, \
             updated_at = NOW(), updated_by_user_id = NULL WHERE scanner_id = $3 AND revision = $4 \
             RETURNING revision;",
            &[
                &document_json,
                &SCHEMA_VERSION,
                &scanner_id_string,
                &configuration.revision,
            ],
        )
        .await?;
    let Some(row) = updated else {
        return Err("配置修订冲突：其他管理员或 CLI 刚刚修改过该扫描器配置，请重试".into());
    };
    let revision: i64 = row.get("revision");
    transaction
        .execute(
            "INSERT INTO scanner_runtime_configuration_revision (scanner_id, revision, schema_version, document, changed_by_user_id, change_reason) \
             VALUES ($1, $2, $3, $4, NULL, $5);",
            &[
                &scanner_id_string,
                &revision,
                &SCHEMA_VERSION,
                &document_json,
                &change_reason.trim(),
            ],
        )
        .await?;
    let mut event = AuditEvent::system("scanner", "scanner.configuration.update", "success")
        .resource("scanner", &scanner_id_string);
    event.changes = Some(json!({
        "revision": revision,
        "change_reason": change_reason.trim(),
        "web_content": document.service_detection.web_content,
        "source": "cli",
    }));
    write_audit(
        &transaction,
        &AuditContext::cli("scanner-config set-web-content"),
        &event,
    )
    .await?;
    transaction.commit().await?;
    println!(
        "已更新扫描器 {scanner_id} 网页内容富化配置（修订 {revision}）：\n{}",
        serde_json::to_string_pretty(&document.service_detection.web_content)?
    );
    Ok(())
}
