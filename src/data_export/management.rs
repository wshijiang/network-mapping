use clap::{ArgAction, Args, Subcommand};
use deadpool_postgres::Pool;
use serde_json::json;
use std::io::Read;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write_standalone};
use crate::network_proxy::GlobalProxyState;
use crate::outbound_proxy::ProxyMode;

use super::DataExportConfig;
use super::cli::resolve_admin;
use super::settings::{self, Settings};
use super::storage::{CredentialUpdate, S3Config, S3Credentials, Storage};
use super::task::Result;

#[derive(Debug, Subcommand)]
pub enum SettingsCommand {
    /// 查看保存位置和性能配置
    Show {
        #[arg(long)]
        admin: String,
    },
    /// 更新指定的保存位置或性能参数
    Set {
        #[arg(long)]
        admin: String,
        #[command(flatten)]
        patch: PreferencesPatch,
    },
}

#[derive(Debug, Args)]
#[group(required = true, multiple = true)]
pub struct PreferencesPatch {
    /// 是否保存到本地
    #[arg(long, action = ArgAction::Set)]
    local: Option<bool>,
    /// 是否保存到 S3
    #[arg(long, action = ArgAction::Set)]
    s3: Option<bool>,
    #[arg(long)]
    batch_size: Option<u32>,
    #[arg(long)]
    workers: Option<usize>,
    #[arg(long)]
    upload_concurrency: Option<usize>,
}

impl PreferencesPatch {
    fn apply(&self, settings: &mut Settings) {
        settings.local = self.local.unwrap_or(settings.local);
        settings.s3 = self.s3.unwrap_or(settings.s3);
        settings.batch_size = self.batch_size.unwrap_or(settings.batch_size);
        settings.workers = self.workers.unwrap_or(settings.workers);
        settings.upload_concurrency = self
            .upload_concurrency
            .unwrap_or(settings.upload_concurrency);
    }
}

#[derive(Debug, Subcommand)]
pub enum S3Command {
    /// 查看生效的 S3 连接
    Show {
        #[arg(long)]
        admin: String,
    },
    /// 保存一套自定义 S3 连接
    Set {
        #[arg(long)]
        admin: String,
        #[command(flatten)]
        target: S3Args,
    },
    /// 管理独立的 S3 Access Key 凭据
    Credentials {
        #[command(subcommand)]
        command: S3CredentialsCommand,
    },
    /// 删除自定义连接并恢复部署配置（如有）
    Reset {
        #[arg(long)]
        admin: String,
    },
    /// 测试当前连接的写入、读取和删除
    Test {
        #[arg(long)]
        admin: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum S3CredentialsCommand {
    /// 从标准输入读取包含 access_key_id、secret_access_key 和可选 session_token 的 JSON
    Set {
        #[arg(long)]
        admin: String,
    },
    /// 改用服务器的 AWS 凭据链
    UseAwsChain {
        #[arg(long)]
        admin: String,
    },
}

#[derive(Debug, Args)]
pub struct S3Args {
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long)]
    download_endpoint: Option<String>,
    #[arg(long)]
    region: String,
    #[arg(long)]
    bucket: String,
    #[arg(long, default_value = "")]
    prefix: String,
    #[arg(long)]
    path_style: bool,
    /// 经服务器转发 S3 下载
    #[arg(long)]
    proxy_download: bool,
    /// 出站代理模式：system、direct 或 custom
    #[arg(long)]
    proxy_mode: Option<ProxyMode>,
    /// 自定义 HTTP(S) 或 SOCKS5(H) 代理，不含凭据
    #[arg(long, conflicts_with = "proxy_url_stdin")]
    proxy_url: Option<String>,
    /// 从标准输入读取自定义代理地址，适用于内嵌凭据的 URL
    #[arg(long)]
    proxy_url_stdin: bool,
}

impl From<&S3Args> for S3Config {
    fn from(args: &S3Args) -> Self {
        Self {
            endpoint: args.endpoint.clone(),
            download_endpoint: args.download_endpoint.clone(),
            region: args.region.clone(),
            bucket: args.bucket.clone(),
            prefix: args.prefix.clone(),
            path_style: args.path_style,
            proxy_download: args.proxy_download,
            proxy_url: args.proxy_url.clone(),
            proxy_mode: args.proxy_mode.or_else(|| {
                (args.proxy_url.is_none() && !args.proxy_url_stdin).then_some(ProxyMode::System)
            }),
            proxy_ciphertext: None,
            credential_ciphertext: None,
        }
    }
}

async fn audit(pool: &Pool, user: &UserBaseI, action: &str, outcome: &str, revision: i64) {
    let event = AuditEvent::user("data_export", action, outcome, user)
        .resource("data_export_settings", revision.to_string());
    write_standalone(pool, &AuditContext::cli("data export"), &event).await;
}

fn print_settings(config: &DataExportConfig, settings: &Settings, revision: i64) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "revision": revision,
            "local": settings.local,
            "s3": settings.s3,
            "s3_configured": settings.connection(config).is_some(),
            "batch_size": settings.batch_size,
            "workers": settings.workers,
            "upload_concurrency": settings.upload_concurrency,
        }))?
    );
    Ok(())
}

fn print_connection(config: &DataExportConfig, settings: &Settings, revision: i64) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "revision": revision,
            "enabled": settings.s3,
            "overridden": settings.s3_override.is_some(),
            "connection": settings.connection(config).map(S3Config::public),
        }))?
    );
    Ok(())
}

pub async fn execute_settings(
    command: &SettingsCommand,
    pool: &Pool,
    config: &DataExportConfig,
) -> Result<()> {
    let (admin, patch) = match command {
        SettingsCommand::Show { admin } => (admin, None),
        SettingsCommand::Set { admin, patch } => (admin, Some(patch)),
    };
    let user = resolve_admin(pool, admin).await?;
    if patch.is_some() {
        settings::init(pool, config).await?;
    }
    let mut current = settings::read(pool, config).await?;
    if let Some(patch) = patch {
        patch.apply(&mut current.value);
        let action = "cli.settings.update";
        current.revision = settings::save(
            pool,
            config,
            current.revision,
            &current.value,
            action,
            user.id,
        )
        .await?;
        audit(pool, &user, action, "success", current.revision).await;
    }
    print_settings(config, &current.value, current.revision)
}

pub async fn execute_s3(
    command: &S3Command,
    pool: &Pool,
    config: &DataExportConfig,
    encryption_key: &str,
) -> Result<()> {
    let admin = match command {
        S3Command::Show { admin }
        | S3Command::Set { admin, .. }
        | S3Command::Reset { admin }
        | S3Command::Test { admin } => admin,
        S3Command::Credentials { command } => match command {
            S3CredentialsCommand::Set { admin } | S3CredentialsCommand::UseAwsChain { admin } => {
                admin
            }
        },
    };
    let user = resolve_admin(pool, admin).await?;
    if matches!(
        command,
        S3Command::Set { .. } | S3Command::Reset { .. } | S3Command::Credentials { .. }
    ) {
        settings::init(pool, config).await?;
    }
    let mut current = settings::read(pool, config).await?;
    let action = match command {
        S3Command::Show { .. } => {
            return print_connection(config, &current.value, current.revision);
        }
        S3Command::Test { .. } => {
            let target = current
                .value
                .connection(config)
                .ok_or("请先保存 S3 连接设置")?;
            let global = GlobalProxyState::initialize(pool, encryption_key).await;
            let result = Storage::new(global, encryption_key).test(target).await;
            let outcome = if result.is_ok() { "success" } else { "failure" };
            audit(
                pool,
                &user,
                "cli.settings.test_s3",
                outcome,
                current.revision,
            )
            .await;
            if let Err(error) = result {
                let details = crate::logs::write::error_diagnostics(error.as_ref());
                return Err(format!("S3 连接测试失败：{}", details.error_chain).into());
            }
            println!("S3 连接测试通过");
            return Ok(());
        }
        S3Command::Set { target, .. } => {
            let mut connection = S3Config::from(target);
            if target.proxy_url_stdin {
                let mut input = String::new();
                std::io::stdin().take(2051).read_to_string(&mut input)?;
                let url = input.trim_end_matches(['\r', '\n']);
                if url.is_empty() || input.len() >= 2051 {
                    return Err("S3 代理地址无效".into());
                }
                connection.proxy_url = Some(url.to_owned());
            } else if let Some(url) = &connection.proxy_url {
                let url = crate::outbound_proxy::validate_url(url)?;
                if !url.username().is_empty() || url.password().is_some() {
                    return Err("含凭据的代理地址请通过 --proxy-url-stdin 提供".into());
                }
            }
            let previous = current.value.connection(config);
            current.value.s3_override = Some(
                connection
                    .with_proxy(previous, encryption_key)?
                    .with_credentials(previous, None, encryption_key)?,
            );
            "cli.settings.s3_update"
        }
        S3Command::Credentials { command } => {
            let connection = current
                .value
                .connection(config)
                .ok_or("请先保存 S3 连接设置")?;
            let (update, action) = match command {
                S3CredentialsCommand::Set { .. } => {
                    const MAX_INPUT: u64 = 32 * 1024;
                    let mut input = Vec::new();
                    std::io::stdin()
                        .take(MAX_INPUT + 1)
                        .read_to_end(&mut input)?;
                    if input.len() as u64 > MAX_INPUT {
                        return Err("S3 凭据 JSON 超出大小限制".into());
                    }
                    let values = serde_json::from_slice::<S3Credentials>(&input)
                        .map_err(|_| "S3 凭据 JSON 无效，请填写 access_key_id、secret_access_key 和可选 session_token")?;
                    (
                        CredentialUpdate::Static {
                            values: Some(values),
                        },
                        "cli.settings.s3_credentials_update",
                    )
                }
                S3CredentialsCommand::UseAwsChain { .. } => (
                    CredentialUpdate::AwsChain,
                    "cli.settings.s3_credentials_use_aws_chain",
                ),
            };
            // The effective connection may originate in TOML, so also seal
            // any deployment proxy URL before saving it to the database.
            let mut next = connection.clone();
            next.proxy_mode = Some(connection.proxy_mode());
            next.proxy_url = None;
            next = next.with_proxy(Some(connection), encryption_key)?;
            current.value.s3_override =
                Some(next.with_credentials(Some(connection), Some(update), encryption_key)?);
            action
        }
        S3Command::Reset { .. } => {
            current.value.s3_override = None;
            "cli.settings.s3_reset"
        }
    };
    let revision = settings::save(
        pool,
        config,
        current.revision,
        &current.value,
        action,
        user.id,
    )
    .await?;
    audit(pool, &user, action, "success", revision).await;
    print_connection(config, &current.value, revision)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{S3Command, SettingsCommand};
    use crate::config::{Clis, ServerCommand};
    use crate::data_export::{DataExportConfig, cli::ExportCommand, settings::Settings};

    #[test]
    fn export_settings_accept_partial_updates_and_explicit_false() {
        let args = Clis::try_parse_from([
            "networkm",
            "export",
            "settings",
            "set",
            "--admin",
            "admin",
            "--local",
            "false",
            "--s3",
            "true",
            "--workers",
            "2",
        ])
        .unwrap();
        let Some(ServerCommand::Export {
            command:
                ExportCommand::Settings {
                    command: SettingsCommand::Set { patch, .. },
                },
        }) = args.command
        else {
            panic!("expected export settings set");
        };
        let mut settings = Settings::defaults(&DataExportConfig::default());
        patch.apply(&mut settings);
        assert!(!settings.local);
        assert!(settings.s3);
        assert_eq!(settings.workers, 2);
        assert_eq!(settings.batch_size, 2_000);
        assert!(
            Clis::try_parse_from(["networkm", "export", "settings", "set", "--admin", "admin"])
                .is_err()
        );
    }

    #[test]
    fn s3_set_accepts_outbound_proxy() {
        let args = Clis::try_parse_from([
            "networkm",
            "export",
            "s3",
            "set",
            "--admin",
            "admin",
            "--bucket",
            "exports",
            "--region",
            "us-east-1",
            "--proxy-url",
            "http://proxy.example.invalid:8080",
        ])
        .unwrap();
        let Some(ServerCommand::Export {
            command:
                ExportCommand::S3 {
                    command: S3Command::Set { target, .. },
                },
        }) = args.command
        else {
            panic!("expected export s3 set");
        };
        let connection = super::S3Config::from(&target);
        assert_eq!(
            connection.proxy_url.as_deref(),
            Some("http://proxy.example.invalid:8080")
        );
        assert!(connection.validate().is_ok());
    }
}
