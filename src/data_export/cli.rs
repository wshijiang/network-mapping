//! 服务器 CLI：`network_mapping_server export …`。
//!
//! 仅需 PostgreSQL，任务由运行中的服务器 worker 执行（与 Web 共用任务模型）。
//! CLI 可创建/查看/取消任务；**文件下载仅 Web 端提供**，CLI 只展示文件信息。

use clap::Subcommand;
use deadpool_postgres::Pool;
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write_standalone};
use crate::data_export::DataExportConfig;
use crate::data_export::fields;
use crate::data_export::management::{self, S3Command, SettingsCommand};
use crate::data_export::task::{self, NewTask};
use crate::handlers::search_dsl::{ElasticsearchCompilation, parse_and_compile_elasticsearch};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Subcommand)]
pub enum ExportCommand {
    /// 管理导出保存位置和性能
    Settings {
        #[command(subcommand)]
        command: SettingsCommand,
    },
    /// 管理 S3 兼容对象存储连接
    S3 {
        #[command(subcommand)]
        command: S3Command,
    },
    /// 按搜索语句创建导出任务（由运行中的服务器执行）
    Create {
        /// 用于授权与审计的管理员用户名
        #[arg(long)]
        admin: String,
        /// 搜索语句（与 Web 搜索同一 DSL）
        #[arg(long)]
        query: String,
        /// 导出范围：all=全部匹配，page=指定分页窗口
        #[arg(long, value_enum, default_value = "all")]
        scope: ExportScope,
        #[arg(long, default_value = "0")]
        offset: i64,
        #[arg(long, default_value = "50")]
        limit: i64,
        /// 导出字段（逗号分隔，如 ip,port,service）；缺省为全部字段
        #[arg(long, value_delimiter = ',')]
        fields: Option<Vec<String>>,
        #[arg(long, default_value = "last_seen")]
        sort_field: String,
        #[arg(long, default_value = "desc")]
        sort_order: String,
        /// 阻塞等待任务终态并显示进度
        #[arg(long)]
        wait: bool,
    },
    /// 列出导出任务
    List {
        #[arg(long)]
        status: Option<String>,
        /// 仅查看指定用户的任务（用户名）
        #[arg(long)]
        owner: Option<String>,
        #[arg(long, default_value = "100")]
        limit: i64,
        #[arg(long)]
        json: bool,
    },
    /// 查看任务详情与进度（含服务器上的文件路径）
    Status {
        task_id: Uuid,
        #[arg(long)]
        json: bool,
    },
    /// 取消任务
    Cancel {
        task_id: Uuid,
        #[arg(long)]
        admin: String,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum ExportScope {
    All,
    Page,
}

impl ExportScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Page => "page",
        }
    }
}

pub(super) async fn resolve_admin(pool: &Pool, name: &str) -> CliResult<UserBaseI> {
    let row = pool
        .get()
        .await?
        .query_opt(
            "SELECT id, username FROM users WHERE username=$1 AND role=1 AND disabled_at IS NULL AND deleted_at IS NULL",
            &[&name],
        )
        .await?
        .ok_or("需要有效的管理员用户名（--admin）")?;
    Ok(UserBaseI {
        id: row.get("id"),
        username: row.get("username"),
        role: 1,
        email: None,
        limit_login: false,
        enable_2fa: false,
    })
}

async fn audit(pool: &Pool, user: &UserBaseI, action: &str, id: Uuid) {
    let event = AuditEvent::user("data_export", action, "success", user)
        .resource("data_export_task", id.to_string());
    write_standalone(pool, &AuditContext::cli("data export"), &event).await;
}

fn compile(query: &str) -> CliResult<serde_json::Value> {
    match parse_and_compile_elasticsearch(query) {
        Ok(ElasticsearchCompilation::Supported(filter))
        | Ok(ElasticsearchCompilation::RequiresElasticsearch(filter)) => Ok(filter),
        Ok(ElasticsearchCompilation::Unsupported) => {
            Err("该查询暂不支持 Elasticsearch 读路径".into())
        }
        Err(error) => Err(format!(
            "{}（位置 {}–{}）",
            error.message,
            error.start + 1,
            error.end + 1
        )
        .into()),
    }
}

pub async fn execute(
    command: &ExportCommand,
    pool: &Pool,
    config: &DataExportConfig,
    encryption_key: &str,
) -> CliResult {
    if !config.enabled
        && !matches!(
            command,
            ExportCommand::Settings { .. } | ExportCommand::S3 { .. }
        )
    {
        return Err("数据导出功能未启用（data_export.enabled=false）".into());
    }
    match command {
        ExportCommand::Settings { command } => {
            management::execute_settings(command, pool, config).await
        }
        ExportCommand::S3 { command } => {
            management::execute_s3(command, pool, config, encryption_key).await
        }
        ExportCommand::Create {
            admin,
            query,
            scope,
            offset,
            limit,
            fields: field_keys,
            sort_field,
            sort_order,
            wait,
        } => {
            let user = resolve_admin(pool, admin).await?;
            let query = query.trim();
            let filter = compile(query)?;
            let keys = field_keys.clone().unwrap_or_else(fields::default_keys);
            fields::resolve_keys(&keys)?;
            let sort = crate::elasticsearch::SearchSort::parse(Some(sort_field), Some(sort_order))?;
            let (page_offset, page_limit) = match scope {
                ExportScope::Page => {
                    if *offset < 0 || !(1..=100).contains(limit) || offset + limit > 10_000 {
                        return Err(
                            "本页导出要求 offset ≥ 0、limit 1..=100 且 offset + limit ≤ 10000"
                                .into(),
                        );
                    }
                    (Some(*offset), Some(*limit))
                }
                ExportScope::All => (None, None),
            };
            let id = Uuid::now_v7();
            // CLI 无 ES 连接：匹配条数由 worker 首批统计并强制 max_rows 上限。
            task::create_task(
                pool,
                NewTask {
                    id,
                    created_by: user.id,
                    scope_type: "global",
                    scope_id: 0,
                    query,
                    filter,
                    scope: scope.as_str(),
                    page_offset,
                    page_limit,
                    sort_field: sort.field_name(),
                    sort_order: sort.order_name(),
                    fields: serde_json::json!(keys),
                    matched_total: None,
                    storage_plan: super::settings::plan(pool, config).await?,
                },
            )
            .await?;
            audit(pool, &user, "cli.create", id).await;
            println!("导出任务已创建：{id}");
            println!("提示：任务由运行中的服务器执行；文件下载请使用 Web「数据管理 → 导出」。");
            if *wait {
                wait_terminal(pool, id).await?;
            }
            Ok(())
        }
        ExportCommand::List {
            status,
            owner,
            limit,
            json,
        } => {
            let owner_id = match owner {
                Some(name) => Some(
                    pool.get()
                        .await?
                        .query_opt("SELECT id FROM users WHERE username=$1", &[name])
                        .await?
                        .ok_or("用户不存在")?
                        .get::<_, i32>("id"),
                ),
                None => None,
            };
            let (tasks, total) = task::list_tasks(
                pool,
                owner_id,
                status.as_deref(),
                (*limit).clamp(1, 1000),
                0,
            )
            .await?;
            if *json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"items": tasks, "total": total})
                    )?
                );
            } else {
                println!("共 {total} 个任务：");
                for t in tasks {
                    println!(
                        "  {}  {:<10} {:<4} 导出 {}/{}  {}",
                        t.id,
                        t.status,
                        t.scope,
                        t.exported_rows,
                        t.matched_total
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "?".into()),
                        t.query
                    );
                }
            }
            Ok(())
        }
        ExportCommand::Status { task_id, json } => {
            let t = task::get_task(pool, *task_id).await?.ok_or("任务不存在")?;
            if *json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "task": t,
                        "file_path": t.file_path,
                    }))?
                );
            } else {
                println!(
                    "任务：{}\n状态：{}\n语句：{}\n范围：{}{}\n进度：{}/{}\n字段：{}\n文件：{}\n大小：{}\nSHA-256：{}\n错误：{}",
                    t.id,
                    t.status,
                    t.query,
                    t.scope,
                    if t.scope == "page" {
                        format!(
                            "（offset {}，limit {}）",
                            t.page_offset.unwrap_or(0),
                            t.page_limit.unwrap_or(50)
                        )
                    } else {
                        String::new()
                    },
                    t.exported_rows,
                    t.matched_total
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".into()),
                    t.fields,
                    t.file_path.as_deref().unwrap_or("-"),
                    t.file_size
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "-".into()),
                    t.sha256.as_deref().unwrap_or("-"),
                    t.error_message.as_deref().unwrap_or("-"),
                );
                println!("提示：CLI 仅查看；文件下载请使用 Web「数据管理 → 导出」。");
            }
            Ok(())
        }
        ExportCommand::Cancel { task_id, admin } => {
            let user = resolve_admin(pool, admin).await?;
            if task::cancel(pool, *task_id).await? {
                audit(pool, &user, "cli.cancel", *task_id).await;
                println!("已取消：{task_id}");
            } else {
                println!("任务当前状态不允许取消：{task_id}");
            }
            Ok(())
        }
    }
}

async fn wait_terminal(pool: &Pool, id: Uuid) -> CliResult {
    loop {
        let t = task::get_task(pool, id).await?.ok_or("任务不存在")?;
        eprintln!(
            "[{}] 导出 {}/{}",
            t.status,
            t.exported_rows,
            t.matched_total
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".into()),
        );
        if matches!(t.status.as_str(), "completed" | "error" | "cancelled") {
            if t.status == "error" {
                return Err(format!("任务失败：{}", t.error_message.unwrap_or_default()).into());
            }
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}
