//! 服务器 CLI：`network_mapping_server federation …`。
//!
//! 除 `source test`（本地出站 HTTP）外仅需 PostgreSQL；run 由运行中的服务器执行。
//! 凭据支持 `--api-key -` 从 stdin 读取，避免 shell 历史泄露。

use std::io::Read;
use std::time::Duration;

use clap::Subcommand;
use deadpool_postgres::Pool;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::audit::{AuditContext, AuditEvent, write_standalone};
use crate::federation::adapters::{self, Adapter};
use crate::federation::model::{PaginationMode, SourceKind, WindowMode};
use crate::federation::policy::{FederationMode, FederationPolicy, FederationTrigger};
use crate::federation::storage::{self, NewRun, SourceInput};
use crate::federation::{executor, storage::StorageError};
use crate::outbound_proxy::{ProxyConfig, ProxyMode};
use crate::runtime_config::{PersistError, persist_with_actor};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Subcommand)]
pub enum FederationCommand {
    /// 数据源管理
    Source {
        #[command(subcommand)]
        command: SourceCommand,
    },
    /// 联测策略（runtime_configuration namespace federation）
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// 手动联测（创建 run，由运行中的服务器执行）
    Run {
        query: String,
        #[arg(long, value_enum, default_value = "async")]
        mode: CliMode,
        /// 限定数据源（可重复）
        #[arg(long = "source", value_name = "ID")]
        sources: Vec<Uuid>,
        /// 时间窗覆盖（1..=60 天）
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=60))]
        window_days: Option<u32>,
        /// 强制入库（忽略本地状态条件）
        #[arg(long, conflicts_with = "no_persist")]
        persist: bool,
        /// 不入库（仅拉取）
        #[arg(long)]
        no_persist: bool,
        /// 阻塞等待 run 终态
        #[arg(long)]
        wait: bool,
        #[arg(long)]
        admin: String,
    },
    /// 列出联测 run
    Runs {
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value = "20")]
        limit: i64,
        #[arg(long)]
        json: bool,
    },
    /// 查看 run 详情
    Status {
        run_id: Uuid,
        #[arg(long)]
        json: bool,
    },
    /// 取消活动 run（已入库数据保留）
    Cancel {
        run_id: Uuid,
        #[arg(long)]
        admin: String,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum CliMode {
    Async,
    Blocking,
}

#[derive(Debug, Subcommand)]
pub enum SourceCommand {
    /// 列出数据源（含剩余额度）
    List {
        #[arg(long)]
        json: bool,
    },
    /// 添加数据源
    Add {
        #[arg(long, value_enum)]
        kind: CliKind,
        #[arg(long)]
        name: String,
        /// API 凭据（hunter/shodan: key；quake: token；fofa: key）；`-` 从 stdin 读取
        #[arg(long)]
        api_key: Option<String>,
        /// FOFA 可选兼容 email
        #[arg(long)]
        email: Option<String>,
        /// 代理：system（跟随全局）/ direct / 自定义 URL
        #[arg(long, default_value = "system")]
        proxy: String,
        /// 逗号分隔字段（ip,port 恒选）
        #[arg(long, value_delimiter = ',')]
        fields: Option<Vec<String>>,
        #[arg(long, value_enum, default_value = "follow-local")]
        pagination: CliPagination,
        #[arg(long, default_value = "100", value_parser = clap::value_parser!(u32).range(1..=1000))]
        page_size: u32,
        #[arg(long, default_value = "5", value_parser = clap::value_parser!(u32).range(1..=50))]
        max_pages: u32,
        /// 时间窗单独设置（1..=60 天）
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=60), conflicts_with_all = ["window_follow", "window_none"])]
        window_days: Option<u32>,
        /// 时间窗跟随策略
        #[arg(long)]
        window_follow: bool,
        /// 时间窗不指定（平台默认）
        #[arg(long)]
        window_none: bool,
        #[arg(long, default_value = "15", value_parser = clap::value_parser!(u32).range(3..=120))]
        timeout: u32,
        #[arg(long)]
        qps: Option<f64>,
        #[arg(long)]
        enabled: bool,
        #[arg(long)]
        admin: String,
    },
    /// 更新数据源（未提供的选项保持原值）
    Update {
        id: Uuid,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        clear_credential: bool,
        #[arg(long)]
        proxy: Option<String>,
        #[arg(long, value_delimiter = ',')]
        fields: Option<Vec<String>>,
        #[arg(long, value_enum)]
        pagination: Option<CliPagination>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=1000))]
        page_size: Option<u32>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=50))]
        max_pages: Option<u32>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=60), conflicts_with_all = ["window_follow", "window_none"])]
        window_days: Option<u32>,
        #[arg(long)]
        window_follow: bool,
        #[arg(long)]
        window_none: bool,
        #[arg(long, value_parser = clap::value_parser!(u32).range(3..=120))]
        timeout: Option<u32>,
        #[arg(long)]
        qps: Option<f64>,
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long)]
        admin: String,
    },
    /// 删除数据源（软删除）
    Remove {
        id: Uuid,
        #[arg(long)]
        admin: String,
    },
    /// 测试连接（本地出站 HTTP，回显会员/配额/延迟）
    Test {
        id: Uuid,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum CliKind {
    Hunter,
    Quake,
    Fofa,
    Shodan,
}

impl CliKind {
    fn to_kind(self) -> SourceKind {
        match self {
            Self::Hunter => SourceKind::Hunter,
            Self::Quake => SourceKind::Quake,
            Self::Fofa => SourceKind::Fofa,
            Self::Shodan => SourceKind::Shodan,
        }
    }
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum CliPagination {
    FollowLocal,
    Fixed,
}

impl CliPagination {
    fn to_mode(self) -> PaginationMode {
        match self {
            Self::FollowLocal => PaginationMode::FollowLocal,
            Self::Fixed => PaginationMode::Fixed,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// 显示当前策略
    Show {
        #[arg(long)]
        json: bool,
    },
    /// 修改策略（未提供的选项保持原值）
    Set {
        #[arg(long, value_enum)]
        mode: Option<CliMode>,
        #[arg(long, value_enum)]
        trigger: Option<CliTrigger>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=3650))]
        stale_days: Option<u32>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=60))]
        query_window_days: Option<u32>,
        #[arg(long, value_delimiter = ',')]
        trigger_fields: Option<Vec<String>>,
        #[arg(long, value_parser = clap::value_parser!(u64).range(5..=120))]
        blocking_timeout: Option<u64>,
        #[arg(long)]
        persist: Option<bool>,
        #[arg(long)]
        persist_on_empty: Option<bool>,
        #[arg(long)]
        persist_on_stale: Option<bool>,
        #[arg(long)]
        persist_on_fresh: Option<bool>,
        #[arg(long, value_parser = clap::value_parser!(u64).range(0..=86400))]
        cooldown: Option<u64>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(10..=5000))]
        max_records: Option<u32>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=16))]
        max_runs: Option<u32>,
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long)]
        admin: String,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum CliTrigger {
    Always,
    EmptyOrStale,
}

async fn resolve_admin(pool: &Pool, name: &str) -> CliResult<i32> {
    let row = pool
        .get()
        .await?
        .query_opt(
            "SELECT id FROM users WHERE username=$1 AND role=1 AND disabled_at IS NULL AND deleted_at IS NULL",
            &[&name],
        )
        .await?
        .ok_or("需要有效的管理员用户名（--admin）")?;
    Ok(row.get("id"))
}

fn read_secret(value: &str) -> CliResult<String> {
    if value == "-" {
        let mut buffer = String::new();
        std::io::stdin().read_to_string(&mut buffer)?;
        Ok(buffer.trim().to_owned())
    } else {
        Ok(value.to_owned())
    }
}

fn parse_proxy(value: &str) -> CliResult<(String, Option<String>)> {
    match value {
        "system" => Ok(("system".into(), None)),
        "direct" => Ok(("direct".into(), None)),
        url => {
            crate::outbound_proxy::validate_url(url).map_err(|_| "代理 URL 无效")?;
            Ok(("custom".into(), Some(url.to_owned())))
        }
    }
}

async fn cli_audit(pool: &Pool, action: &str, resource: &str, id: &str) {
    let event = AuditEvent::system("federation", action, "success").resource(resource, id);
    write_standalone(
        pool,
        &AuditContext::cli(format!("federation {action}")),
        &event,
    )
    .await;
}

fn print_value(value: &Value, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_default()
        );
    } else if let Some(items) = value.get("items").and_then(Value::as_array) {
        for item in items {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                item.get("id").and_then(Value::as_str).unwrap_or(""),
                item.get("kind").and_then(Value::as_str).unwrap_or(""),
                item.get("name").and_then(Value::as_str).unwrap_or(""),
                if item
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    "enabled"
                } else {
                    "disabled"
                },
                item.get("capabilities")
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "-".into()),
            );
        }
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_default()
        );
    }
}

#[allow(clippy::too_many_lines)]
pub async fn execute(command: &FederationCommand, pool: &Pool, encrypt_key: &str) -> CliResult {
    match command {
        FederationCommand::Source { command } => execute_source(command, pool, encrypt_key).await,
        FederationCommand::Policy { command } => execute_policy(command, pool).await,
        FederationCommand::Run {
            query,
            mode,
            sources,
            window_days,
            persist,
            no_persist,
            wait,
            admin,
        } => {
            let admin_id = resolve_admin(pool, admin).await?;
            if crate::handlers::search_dsl::parse_query_ast(query).is_err() {
                return Err("查询语法无效".into());
            }
            let policy = load_policy(pool).await?;
            let window = window_days.unwrap_or(policy.query_window_days);
            let all = storage::list_sources(pool).await?;
            let enabled: Vec<_> = all
                .into_iter()
                .filter(|s| s.enabled)
                .filter(|s| sources.is_empty() || sources.contains(&s.id))
                .collect();
            if enabled.is_empty() {
                return Err("没有可用的启用数据源".into());
            }
            let resolved: Vec<(Uuid, Option<u32>)> = enabled
                .iter()
                .map(|s| (s.id, executor::resolve_source_window(s, window)))
                .collect();
            let query_hash = executor::compute_query_hash(query, &resolved, 100, 0);
            let persist_override = if *persist {
                "force"
            } else if *no_persist {
                "skip"
            } else {
                "auto"
            };
            let run = storage::create_run(
                pool,
                NewRun {
                    query_text: query,
                    query_hash: &query_hash,
                    trigger: "manual",
                    mode: match mode {
                        CliMode::Async => "async",
                        CliMode::Blocking => "blocking",
                    },
                    requested_by: admin_id,
                    window_days: window,
                    local_state: "unknown",
                    selected_sources: if sources.is_empty() {
                        None
                    } else {
                        Some(sources.clone())
                    },
                    local_limit: 100,
                    local_offset: 0,
                    persist_override,
                    status: "pending",
                    worker_id: None,
                    lease_ms: 120_000,
                },
            )
            .await?;
            cli_audit(pool, "run_create", "federation_run", &run.id.to_string()).await;
            println!("run 已创建：{}（待服务器执行）", run.id);
            if *wait {
                wait_run(pool, run.id).await?;
            }
            Ok(())
        }
        FederationCommand::Runs {
            status,
            limit,
            json,
        } => {
            let (runs, total) =
                storage::list_runs(pool, status.as_deref(), (*limit).clamp(1, 100), 0).await?;
            let items: Vec<Value> = runs.iter().map(|r| storage::run_public(r, false)).collect();
            let value = json!({"items": items, "total": total});
            if *json {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else {
                for item in &items {
                    println!(
                        "{}\t{}\t{}\t{}\tfetched={} merged={} persisted={}",
                        item["id"].as_str().unwrap_or(""),
                        item["status"].as_str().unwrap_or(""),
                        item["trigger"].as_str().unwrap_or(""),
                        item["query"].as_str().unwrap_or(""),
                        item["total_fetched"],
                        item["total_merged"],
                        item["total_persisted"],
                    );
                }
            }
            Ok(())
        }
        FederationCommand::Status { run_id, json } => {
            let run = storage::get_run(pool, *run_id).await?.ok_or("run 不存在")?;
            print_value(&storage::run_public(&run, true), *json);
            Ok(())
        }
        FederationCommand::Cancel { run_id, admin } => {
            resolve_admin(pool, admin).await?;
            storage::cancel_run(pool, *run_id).await.map_err(
                |e| -> Box<dyn std::error::Error + Send + Sync> {
                    match e {
                        StorageError::Conflict => "run 不在活动状态".into(),
                        other => other.to_string().into(),
                    }
                },
            )?;
            cli_audit(pool, "run_cancel", "federation_run", &run_id.to_string()).await;
            println!("run 已取消（已入库数据保留）");
            Ok(())
        }
    }
}

async fn wait_run(pool: &Pool, run_id: Uuid) -> CliResult {
    loop {
        let run = storage::get_run(pool, run_id).await?.ok_or("run 不存在")?;
        match run.status.as_str() {
            "completed" | "partial" | "failed" | "cancelled" | "unsupported" => {
                println!(
                    "run {}：fetched={} merged={} persisted={}",
                    run.status, run.total_fetched, run.total_merged, run.total_persisted
                );
                if let Some(error) = run.error_message {
                    println!("错误：{error}");
                }
                return Ok(());
            }
            _ => tokio::time::sleep(Duration::from_secs(2)).await,
        }
    }
}

async fn load_policy(pool: &Pool) -> CliResult<FederationPolicy> {
    let row = pool
        .get()
        .await?
        .query_opt(
            "SELECT document FROM runtime_configuration WHERE namespace='federation'",
            &[],
        )
        .await?;
    match row {
        Some(row) => Ok(serde_json::from_value(row.get("document"))?),
        None => Ok(FederationPolicy::default()),
    }
}

#[allow(clippy::too_many_lines)]
async fn execute_source(command: &SourceCommand, pool: &Pool, encrypt_key: &str) -> CliResult {
    match command {
        SourceCommand::List { json } => {
            let sources = storage::list_sources(pool).await?;
            let items: Vec<Value> = sources
                .iter()
                .map(|s| storage::source_public(s, encrypt_key))
                .collect();
            print_value(&json!({"items": items}), *json);
            Ok(())
        }
        SourceCommand::Add {
            kind,
            name,
            api_key,
            email,
            proxy,
            fields,
            pagination,
            page_size,
            max_pages,
            window_days,
            window_follow,
            window_none,
            timeout,
            qps,
            enabled,
            admin,
        } => {
            resolve_admin(pool, admin).await?;
            let kind = kind.to_kind();
            let credential = build_credential(kind, api_key.as_deref(), email.as_deref())?;
            let (proxy_mode, proxy_url) = parse_proxy(proxy)?;
            let window_mode = if *window_follow {
                WindowMode::Follow
            } else if *window_none {
                WindowMode::None
            } else if window_days.is_some() {
                WindowMode::Custom
            } else if kind == SourceKind::Hunter {
                WindowMode::Follow
            } else {
                WindowMode::None
            };
            let input = SourceInput {
                kind,
                name: name.clone(),
                enabled: *enabled,
                credential,
                clear_credential: false,
                proxy_mode,
                proxy_url,
                fields: fields.clone().unwrap_or_else(|| {
                    ["ip", "domain", "port", "service", "tech"]
                        .iter()
                        .map(|s| (*s).to_owned())
                        .collect()
                }),
                pagination_mode: pagination.to_mode(),
                page_size: *page_size,
                max_pages: *max_pages,
                window_mode,
                window_days: window_days.unwrap_or(30),
                timeout_seconds: *timeout,
                rate_limit_qps: qps
                    .unwrap_or_else(|| Adapter::for_kind(kind).capabilities().default_qps),
            };
            let source = storage::create_source(pool, &input, encrypt_key).await?;
            cli_audit(
                pool,
                "source_create",
                "federation_source",
                &source.id.to_string(),
            )
            .await;
            println!("数据源已创建：{}", source.id);
            Ok(())
        }
        SourceCommand::Update {
            id,
            name,
            api_key,
            email,
            clear_credential,
            proxy,
            fields,
            pagination,
            page_size,
            max_pages,
            window_days,
            window_follow,
            window_none,
            timeout,
            qps,
            enabled,
            admin,
        } => {
            resolve_admin(pool, admin).await?;
            let existing = storage::get_source(pool, *id)
                .await?
                .ok_or("数据源不存在")?;
            let credential = if *clear_credential {
                None
            } else {
                build_credential(existing.kind, api_key.as_deref(), email.as_deref())?
            };
            let (proxy_mode, proxy_url) = match proxy {
                Some(value) => parse_proxy(value)?,
                None => (existing.proxy_mode.clone(), None),
            };
            let window_mode = if *window_follow {
                WindowMode::Follow
            } else if *window_none {
                WindowMode::None
            } else if window_days.is_some() {
                WindowMode::Custom
            } else {
                existing.window_mode
            };
            let input = SourceInput {
                kind: existing.kind,
                name: name.clone().unwrap_or(existing.name.clone()),
                enabled: enabled.unwrap_or(existing.enabled),
                credential,
                clear_credential: *clear_credential,
                proxy_mode,
                proxy_url,
                fields: fields.clone().unwrap_or(existing.fields.clone()),
                pagination_mode: pagination
                    .map(|p| p.to_mode())
                    .unwrap_or(existing.pagination_mode),
                page_size: page_size.unwrap_or(existing.page_size),
                max_pages: max_pages.unwrap_or(existing.max_pages),
                window_mode,
                window_days: window_days.unwrap_or(existing.window_days),
                timeout_seconds: timeout.unwrap_or(existing.timeout_seconds),
                rate_limit_qps: qps.unwrap_or(existing.rate_limit_qps),
            };
            let source = storage::update_source(pool, *id, existing.revision, &input, encrypt_key)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    match e {
                        StorageError::Conflict => "配置已被其他管理员更新，请重试".into(),
                        other => other.to_string().into(),
                    }
                })?;
            cli_audit(pool, "source_update", "federation_source", &id.to_string()).await;
            println!(
                "数据源已更新：{}（revision {}）",
                source.id, source.revision
            );
            Ok(())
        }
        SourceCommand::Remove { id, admin } => {
            resolve_admin(pool, admin).await?;
            let existing = storage::get_source(pool, *id)
                .await?
                .ok_or("数据源不存在")?;
            storage::delete_source(pool, *id, existing.revision)
                .await
                .map_err(|e| e.to_string())?;
            cli_audit(pool, "source_delete", "federation_source", &id.to_string()).await;
            println!("数据源已删除");
            Ok(())
        }
        SourceCommand::Test { id, json } => {
            let source = storage::get_source(pool, *id)
                .await?
                .ok_or("数据源不存在")?;
            let credential =
                storage::decrypt_json(source.credential_ciphertext.as_deref(), encrypt_key)?
                    .ok_or("凭据未配置")?;
            let network_proxy =
                crate::network_proxy::GlobalProxyState::initialize(pool, encrypt_key).await;
            let local_proxy = ProxyConfig {
                mode: source
                    .proxy_mode
                    .parse::<ProxyMode>()
                    .unwrap_or(ProxyMode::System),
                url: storage::decrypt_json(source.proxy_ciphertext.as_deref(), encrypt_key)?
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default(),
            };
            let effective = network_proxy
                .resolve(&local_proxy)
                .await
                .map_err(|e| e.code)?;
            let client =
                adapters::http_client(&effective, Duration::from_secs(15)).map_err(|e| e.code)?;
            let started = std::time::Instant::now();
            let adapter = Adapter::for_kind(source.kind);
            match adapter.probe(&client, &credential).await {
                Ok(capabilities) => {
                    // 回显与入库同样走白名单，避免 CLI 泄露手机号/token 等。
                    let mut capabilities = storage::public_capabilities(source.kind, &capabilities);
                    capabilities["quota_updated_at"] = json!(chrono::Utc::now().timestamp_millis());
                    let _ =
                        storage::update_capabilities(pool, *id, source.kind, &capabilities).await;
                    let value = json!({
                        "ok": true, "latency_ms": started.elapsed().as_millis() as i64,
                        "capabilities": capabilities,
                    });
                    print_value(&value, *json);
                    Ok(())
                }
                Err(error) => {
                    let value = json!({
                        "ok": false, "latency_ms": started.elapsed().as_millis() as i64,
                        "error_code": error.code,
                    });
                    print_value(&value, *json);
                    Err(format!("测试失败：{}", error.code).into())
                }
            }
        }
    }
}

fn build_credential(
    kind: SourceKind,
    api_key: Option<&str>,
    email: Option<&str>,
) -> CliResult<Option<Value>> {
    let Some(api_key) = api_key else {
        return Ok(None);
    };
    let secret = read_secret(api_key)?;
    if secret.is_empty() {
        return Err("凭据不能为空".into());
    }
    Ok(Some(match kind {
        SourceKind::Hunter => json!({"api_key": secret}),
        SourceKind::Quake => json!({"token": secret}),
        SourceKind::Shodan => json!({"key": secret}),
        SourceKind::Fofa => {
            let mut value = json!({"key": secret});
            if let Some(email) = email {
                value["email"] = json!(email);
            }
            value
        }
    }))
}

async fn execute_policy(command: &PolicyCommand, pool: &Pool) -> CliResult {
    match command {
        PolicyCommand::Show { json } => {
            let policy = load_policy(pool).await?;
            print_value(&serde_json::to_value(&policy)?, *json);
            Ok(())
        }
        PolicyCommand::Set {
            mode,
            trigger,
            stale_days,
            query_window_days,
            trigger_fields,
            blocking_timeout,
            persist,
            persist_on_empty,
            persist_on_stale,
            persist_on_fresh,
            cooldown,
            max_records,
            max_runs,
            enabled,
            admin,
        } => {
            let admin_id = resolve_admin(pool, admin).await?;
            let mut policy = load_policy(pool).await?;
            if let Some(mode) = mode {
                policy.mode = match mode {
                    CliMode::Async => FederationMode::Async,
                    CliMode::Blocking => FederationMode::Blocking,
                };
            }
            if let Some(trigger) = trigger {
                policy.trigger = match trigger {
                    CliTrigger::Always => FederationTrigger::Always,
                    CliTrigger::EmptyOrStale => FederationTrigger::EmptyOrStale,
                };
            }
            if let Some(value) = stale_days {
                policy.stale_days = *value;
            }
            if let Some(value) = query_window_days {
                policy.query_window_days = *value;
            }
            if let Some(fields) = trigger_fields {
                policy.trigger_fields = fields.clone();
            }
            if let Some(value) = blocking_timeout {
                policy.blocking_timeout_seconds = *value;
            }
            if let Some(value) = persist {
                policy.persist.enabled = *value;
            }
            if let Some(value) = persist_on_empty {
                policy.persist.on_empty = *value;
            }
            if let Some(value) = persist_on_stale {
                policy.persist.on_stale = *value;
            }
            if let Some(value) = persist_on_fresh {
                policy.persist.on_fresh = *value;
            }
            if let Some(value) = cooldown {
                policy.cooldown_seconds = *value;
            }
            if let Some(value) = max_records {
                policy.max_records_per_run = *value;
            }
            if let Some(value) = max_runs {
                policy.max_concurrent_runs = *value;
            }
            if let Some(value) = enabled {
                policy.enabled = *value;
            }
            policy.validate()?;
            let row = pool
                .get()
                .await?
                .query_one(
                    "SELECT revision FROM runtime_configuration WHERE namespace='federation'",
                    &[],
                )
                .await?;
            let revision: i64 = row.get("revision");
            let new_revision = persist_with_actor(
                pool,
                crate::federation::policy::NAMESPACE,
                revision,
                &policy,
                "CLI federation policy set",
                Some(admin_id),
            )
            .await
            .map_err(|e| match e {
                PersistError::Conflict => "配置已被其他管理员更新，请重试".to_owned(),
                PersistError::Other(message) => message,
            })?;
            cli_audit(pool, "policy_update", "setting", "federation").await;
            println!("策略已发布（revision {new_revision}），服务器数秒内热生效");
            Ok(())
        }
    }
}
