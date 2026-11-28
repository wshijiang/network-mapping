//! 服务器 CLI：`network_mapping_server scanner-config …`。
//!
//! 管理扫描器运行时配置中的网页内容富化和 JARM 主动采集参数，
//! 与 Web 控制台「扫描器配置」写入同一份 `scanner_runtime_configuration`
//! 文档：新修订、历史记录与审计一致，扫描器在下一任务边界应用。
//! 仅需 PostgreSQL。

use clap::Subcommand;
use deadpool_postgres::{GenericClient, Pool};
use serde_json::json;
use uuid::Uuid;

use crate::audit::{AuditContext, AuditEvent, write as write_audit};
use crate::scanner_config::{
    JarmRuntimeConfig, SCHEMA_VERSION, ScannerRuntimeConfig, WebContentRuntimeConfig,
    ensure_configuration, load_configuration,
};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Subcommand)]
pub enum ScannerConfigCommand {
    /// 查看扫描器运行时配置（含网页内容富化和 JARM 参数）
    Show {
        /// 扫描器 ID
        scanner_id: Uuid,
    },
    /// 修改 JARM 主动采集参数（仅更新给出的字段，写入新修订）
    SetJarm {
        /// 扫描器 ID
        scanner_id: Uuid,
        /// 总开关（true/false）；仍需节点本地显式允许 JARM
        #[arg(long, value_parser = clap::value_parser!(bool))]
        enabled: Option<bool>,
        /// 并发端点上限（1..=32）
        #[arg(long)]
        concurrency: Option<usize>,
        /// 单次握手超时秒数（1..=30）
        #[arg(long)]
        probe_timeout_seconds: Option<u64>,
        /// 每块 JARM 总预算秒数（1..=3600）
        #[arg(long)]
        max_stage_seconds: Option<u64>,
        /// 变更原因（记入历史与审计，≤500 字符）
        #[arg(long, default_value = "")]
        change_reason: String,
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
        ScannerConfigCommand::SetJarm {
            scanner_id,
            enabled,
            concurrency,
            probe_timeout_seconds,
            max_stage_seconds,
            change_reason,
        } => {
            let values = JarmOverride {
                enabled: *enabled,
                concurrency: *concurrency,
                probe_timeout_seconds: *probe_timeout_seconds,
                max_stage_seconds: *max_stage_seconds,
            };
            set_configuration(
                pool,
                scanner_id,
                ConfigurationUpdate::Jarm(values),
                change_reason,
            )
            .await
        }
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
            set_configuration(
                pool,
                scanner_id,
                ConfigurationUpdate::WebContent(override_values),
                change_reason,
            )
            .await
        }
    }
}

#[derive(Clone)]
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

#[derive(Clone, Default)]
struct JarmOverride {
    enabled: Option<bool>,
    concurrency: Option<usize>,
    probe_timeout_seconds: Option<u64>,
    max_stage_seconds: Option<u64>,
}
impl JarmOverride {
    fn is_empty(&self) -> bool {
        self.enabled.is_none()
            && self.concurrency.is_none()
            && self.probe_timeout_seconds.is_none()
            && self.max_stage_seconds.is_none()
    }
    fn apply(self, jarm: &mut JarmRuntimeConfig) {
        if let Some(value) = self.enabled {
            jarm.enabled = value;
        }
        if let Some(value) = self.concurrency {
            jarm.concurrency = value;
        }
        if let Some(value) = self.probe_timeout_seconds {
            jarm.probe_timeout_seconds = value;
        }
        if let Some(value) = self.max_stage_seconds {
            jarm.max_stage_seconds = value;
        }
    }
}

#[derive(Clone)]
enum ConfigurationUpdate {
    WebContent(WebContentOverride),
    Jarm(JarmOverride),
}
impl ConfigurationUpdate {
    fn is_empty(&self) -> bool {
        match self {
            Self::WebContent(value) => value.is_empty(),
            Self::Jarm(value) => value.is_empty(),
        }
    }
    fn field(&self) -> &'static str {
        match self {
            Self::WebContent(_) => "web_content",
            Self::Jarm(_) => "jarm",
        }
    }
    fn command(&self) -> &'static str {
        match self {
            Self::WebContent(_) => "scanner-config set-web-content",
            Self::Jarm(_) => "scanner-config set-jarm",
        }
    }
    fn apply(self, document: &mut ScannerRuntimeConfig) {
        match self {
            Self::WebContent(value) => value.apply(&mut document.service_detection.web_content),
            Self::Jarm(value) => value.apply(&mut document.service_detection.jarm),
        }
    }
    fn validate(&self, change_reason: &str) -> CliResult {
        if self.is_empty() {
            return Err("未给出任何要修改的参数（--help 查看可用字段）".into());
        }
        if change_reason.chars().count() > 500 {
            return Err("change_reason 不能超过 500 个字符".into());
        }
        // Reject invalid overrides before acquiring a database connection.
        let mut defaults = ScannerRuntimeConfig::default();
        self.clone().apply(&mut defaults);
        defaults.validate()?;
        Ok(())
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

async fn set_configuration(
    pool: &Pool,
    scanner_id: &Uuid,
    update: ConfigurationUpdate,
    change_reason: &str,
) -> CliResult {
    update.validate(change_reason)?;
    let field = update.field();
    let command = update.command();
    let scanner_id_string = scanner_id.to_string();
    let mut client = pool.get().await?;
    let configuration = load_configuration(&client, &scanner_id_string)
        .await?
        .ok_or("扫描器不存在")?;
    let mut document: ScannerRuntimeConfig = configuration.document;
    update.apply(&mut document);
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
    let mut changes = json!({
        "revision": revision,
        "change_reason": change_reason.trim(),
        "source": "cli",
    });
    changes[field] = document_json["service_detection"][field].clone();
    event.changes = Some(changes);
    write_audit(&transaction, &AuditContext::cli(command), &event).await?;
    transaction.commit().await?;
    println!(
        "已更新扫描器 {scanner_id} {field} 配置（修订 {revision}）：\n{}",
        serde_json::to_string_pretty(&document_json["service_detection"][field])?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: ScannerConfigCommand,
    }

    #[test]
    fn set_jarm_parses_explicit_false_and_all_runtime_fields() {
        let id = Uuid::nil().to_string();
        let cli = TestCli::try_parse_from([
            "scanner-config",
            "set-jarm",
            &id,
            "--enabled",
            "false",
            "--concurrency",
            "8",
            "--probe-timeout-seconds",
            "5",
            "--max-stage-seconds",
            "90",
            "--change-reason",
            "maintenance",
        ])
        .unwrap();
        let ScannerConfigCommand::SetJarm {
            scanner_id,
            enabled,
            concurrency,
            probe_timeout_seconds,
            max_stage_seconds,
            change_reason,
        } = cli.command
        else {
            panic!("wrong subcommand");
        };
        assert_eq!(scanner_id, Uuid::nil());
        assert_eq!(enabled, Some(false));
        assert_eq!(concurrency, Some(8));
        assert_eq!(probe_timeout_seconds, Some(5));
        assert_eq!(max_stage_seconds, Some(90));
        assert_eq!(change_reason, "maintenance");
        let root = crate::config::Clis::try_parse_from([
            "network_mapping_server",
            "scanner-config",
            "set-jarm",
            &id,
            "--enabled",
            "true",
        ])
        .unwrap();
        assert!(matches!(
            root.command,
            Some(crate::config::ServerCommand::ScannerConfig {
                command: ScannerConfigCommand::SetJarm {
                    enabled: Some(true),
                    ..
                }
            })
        ));

        assert!(TestCli::try_parse_from(["scanner-config", "set-jarm", &id, "--enabled"]).is_err());
        assert!(
            TestCli::try_parse_from(["scanner-config", "set-jarm", &id, "--enabled", "yes"])
                .is_err()
        );
    }

    #[test]
    fn partial_jarm_update_preserves_unrelated_runtime_configuration() {
        let mut document = ScannerRuntimeConfig::default();
        document.service_detection.jarm.enabled = true;
        document.service_detection.jarm.concurrency = 12;
        document.service_detection.web_content.max_js_files = 3;
        document.masscan.rate = 1234;
        let before = serde_json::to_value(&document).unwrap();
        let update = ConfigurationUpdate::Jarm(JarmOverride {
            enabled: Some(false),
            probe_timeout_seconds: Some(7),
            ..Default::default()
        });
        update.validate("controlled shutdown").unwrap();
        update.apply(&mut document);
        document.validate().unwrap();
        let mut expected = before;
        expected["service_detection"]["jarm"]["enabled"] = json!(false);
        expected["service_detection"]["jarm"]["probe_timeout_seconds"] = json!(7);
        assert_eq!(serde_json::to_value(document).unwrap(), expected);
    }

    #[test]
    fn invalid_or_empty_jarm_overrides_are_rejected_before_loading_configuration() {
        for values in [
            JarmOverride::default(),
            JarmOverride {
                concurrency: Some(0),
                ..Default::default()
            },
            JarmOverride {
                concurrency: Some(33),
                ..Default::default()
            },
            JarmOverride {
                probe_timeout_seconds: Some(0),
                ..Default::default()
            },
            JarmOverride {
                probe_timeout_seconds: Some(31),
                ..Default::default()
            },
            JarmOverride {
                max_stage_seconds: Some(0),
                ..Default::default()
            },
            JarmOverride {
                max_stage_seconds: Some(3601),
                ..Default::default()
            },
        ] {
            assert!(ConfigurationUpdate::Jarm(values).validate("").is_err());
        }
        let valid = ConfigurationUpdate::Jarm(JarmOverride {
            enabled: Some(true),
            ..Default::default()
        });
        assert!(valid.validate(&"改".repeat(500)).is_ok());
        assert!(valid.validate(&"改".repeat(501)).is_err());
        let help = TestCli::command().render_long_help().to_string();
        assert!(help.contains("set-jarm"));
        assert!(help.contains("set-web-content"));
        assert!(help.contains("show"));
    }
}
