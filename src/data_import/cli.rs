//! 服务器 CLI：`network_mapping_server import …`。
//!
//! `check` 纯本地（无需数据库）；其余命令直连 PostgreSQL 创建/管理任务，
//! 由运行中的服务器 worker 执行（与 Web 共用任务模型）。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use deadpool_postgres::Pool;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::data_import::DataImportConfig;
use crate::data_import::csv;
use crate::data_import::schema;
use crate::data_import::task::{self, NewTask};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Subcommand)]
pub enum ImportCommand {
    /// 本地检查 CSV 头部配对（无需数据库）；退出码 0=可直接导入，2=需要映射
    Check {
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// 校验头部并创建导入任务（由运行中的服务器执行）
    Run {
        file: PathBuf,
        /// 用于授权与审计的管理员用户名
        #[arg(long)]
        admin: String,
        /// 头部映射 internal:file（可重复），如 -m ip:主机地址
        #[arg(short = 'm', long = "header-mapping", value_name = "INTERNAL:FILE")]
        header_mapping: Vec<String>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=50000))]
        batch_size: Option<u32>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=8))]
        concurrency: Option<u32>,
        #[arg(long, value_enum, default_value = "skip")]
        on_invalid: OnInvalid,
        /// 覆盖本地（按时间新者胜）；默认仅新增/补缺
        #[arg(long)]
        overwrite: bool,
        /// 只校验不写入
        #[arg(long)]
        dry_run: bool,
        /// 单遍快速模式（校验合并进导入）
        #[arg(long)]
        fast: bool,
        /// 阻塞等待任务终态并显示进度
        #[arg(long)]
        wait: bool,
    },
    /// 列出导入任务
    List {
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// 查看任务详情与进度
    Status {
        task_id: Uuid,
        #[arg(long)]
        json: bool,
    },
    /// 暂停任务
    Pause {
        task_id: Uuid,
        #[arg(long)]
        admin: String,
    },
    /// 继续任务（可调整批次大小与并发）
    Resume {
        task_id: Uuid,
        #[arg(long)]
        admin: String,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=50000))]
        batch_size: Option<u32>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=8))]
        concurrency: Option<u32>,
    },
    /// 取消任务（已导入数据保留）
    Cancel {
        task_id: Uuid,
        #[arg(long)]
        admin: String,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum OnInvalid {
    Skip,
    Abort,
}

impl OnInvalid {
    fn as_str(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::Abort => "abort",
        }
    }
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

fn read_file_headers(path: &Path) -> CliResult<Vec<String>> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("无法打开文件 {}：{e}", path.display()))?;
    Ok(csv::read_headers(file)?)
}

fn apply_overrides(
    file_headers: &[String],
    mut mapping: BTreeMap<String, String>,
    overrides: &[String],
) -> CliResult<BTreeMap<String, String>> {
    let normalized: Vec<String> = file_headers
        .iter()
        .map(|h| schema::normalize_header(h))
        .collect();
    for entry in overrides {
        let (internal, file_header) = entry
            .split_once(':')
            .ok_or_else(|| format!("映射格式应为 internal:file，收到：{entry}"))?;
        if schema::field(internal).is_none() {
            return Err(format!("未知的内部头部：{internal}").into());
        }
        let norm = schema::normalize_header(file_header);
        let original = file_headers
            .iter()
            .find(|h| schema::normalize_header(h) == norm)
            .ok_or_else(|| format!("文件头部不存在：{file_header}"))?;
        let _ = &normalized;
        mapping.insert(internal.to_owned(), original.clone());
    }
    Ok(mapping)
}

pub async fn execute(command: &ImportCommand, pool: &Pool, config: &DataImportConfig) -> CliResult {
    match command {
        ImportCommand::Check { file, json } => {
            let headers = read_file_headers(file)?;
            let result = schema::auto_match(&headers);
            let ok = result.unmatched_required.is_empty() && result.conflicts.is_empty();
            if *json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "file_headers": headers,
                        "mapping": result.mapping,
                        "unmatched_required": result.unmatched_required,
                        "conflicts": result.conflicts,
                        "ignored_file_headers": result.ignored_file_headers,
                        "ready": ok,
                    }))?
                );
            } else {
                println!("文件头部：{}", headers.join(", "));
                println!("自动配对：");
                for (internal, file_header) in &result.mapping {
                    println!("  {internal} <- {file_header}");
                }
                if !result.unmatched_required.is_empty() {
                    println!("缺少必须头部：{}", result.unmatched_required.join(", "));
                }
                if !result.conflicts.is_empty() {
                    println!(
                        "冲突（多列匹配同一内部头部）：{}",
                        result.conflicts.join(", ")
                    );
                }
                if !result.ignored_file_headers.is_empty() {
                    println!("将忽略的列：{}", result.ignored_file_headers.join(", "));
                }
                println!(
                    "{}",
                    if ok {
                        "头部符合要求，可直接导入。"
                    } else {
                        "请用 -m internal:file 指定映射后导入。"
                    }
                );
            }
            if !ok {
                std::process::exit(2);
            }
            Ok(())
        }
        ImportCommand::Run {
            file,
            admin,
            header_mapping,
            batch_size,
            concurrency,
            on_invalid,
            overwrite,
            dry_run,
            fast,
            wait,
        } => {
            let user_id = resolve_admin(pool, admin).await?;
            let headers = read_file_headers(file)?;
            let matched = schema::auto_match(&headers);
            let mapping = apply_overrides(&headers, matched.mapping, header_mapping)?;
            schema::validate_mapping(&headers, &mapping)?;

            let bytes = std::fs::read(file)?;
            if bytes.len() as u64 > config.max_upload_bytes {
                return Err(format!("文件超过大小上限 {} 字节", config.max_upload_bytes).into());
            }
            let sha256: String = Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            tokio::fs::create_dir_all(&config.directory).await?;
            let id = Uuid::now_v7();
            let stored = config.directory.join(format!("{id}.csv"));
            tokio::fs::write(&stored, &bytes).await?;
            let file_name = file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "import.csv".to_owned());

            let _created = task::create_task(
                pool,
                NewTask {
                    id,
                    created_by: user_id,
                    file_name: &file_name,
                    file_size: bytes.len() as i64,
                    sha256: &sha256,
                    storage_path: &stored.to_string_lossy(),
                    file_headers: serde_json::json!(headers),
                    header_mapping: serde_json::json!(mapping),
                    on_invalid: on_invalid.as_str(),
                    overwrite_policy: if *overwrite { "overwrite" } else { "fill" },
                    dry_run: *dry_run,
                    fast_mode: *fast,
                    batch_size: batch_size.unwrap_or(config.default_batch_size) as i32,
                    concurrency: concurrency.unwrap_or(config.default_concurrency) as i32,
                },
            )
            .await?;
            println!("导入任务已创建：{id}");
            println!("提示：任务由运行中的服务器执行；若服务器未启动，任务将在启动后继续。");
            if *wait {
                wait_terminal(pool, id).await?;
            }
            Ok(())
        }
        ImportCommand::List { status, json } => {
            let (tasks, total) = task::list_tasks(pool, status.as_deref(), 100, 0).await?;
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
                        "  {}  {:<12} {:<10} 导入 {}/{}  {}",
                        t.id,
                        t.status,
                        t.overwrite_policy,
                        t.imported_rows,
                        t.total_rows
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "?".into()),
                        t.file_name
                    );
                }
            }
            Ok(())
        }
        ImportCommand::Status { task_id, json } => {
            let t = task::get_task(pool, *task_id).await?.ok_or("任务不存在")?;
            if *json {
                println!("{}", serde_json::to_string_pretty(&t)?);
            } else {
                println!(
                    "任务：{}\n状态：{}\n文件：{}\n进度：{}/{}（导入 {}，无效 {}，重复 {}，冲突 {}）\n批次/并发：{}/{}\n错误：{}",
                    t.id,
                    t.status,
                    t.file_name,
                    t.processed_rows,
                    t.total_rows
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "?".into()),
                    t.imported_rows,
                    t.invalid_rows,
                    t.duplicate_rows,
                    t.conflict_rows,
                    t.batch_size,
                    t.concurrency,
                    t.error_message.unwrap_or_else(|| "-".into())
                );
            }
            Ok(())
        }
        ImportCommand::Pause { task_id, admin } => {
            resolve_admin(pool, admin).await?;
            if task::pause(pool, *task_id).await? {
                println!("已请求暂停：{task_id}");
            } else {
                println!("任务当前状态不允许暂停：{task_id}");
            }
            Ok(())
        }
        ImportCommand::Resume {
            task_id,
            admin,
            batch_size,
            concurrency,
        } => {
            resolve_admin(pool, admin).await?;
            if task::resume(
                pool,
                *task_id,
                batch_size.map(|v| v as i32),
                concurrency.map(|v| v as i32),
            )
            .await?
            {
                println!("已继续：{task_id}");
            } else {
                println!("任务当前状态不允许继续（仅 paused）：{task_id}");
            }
            Ok(())
        }
        ImportCommand::Cancel { task_id, admin } => {
            resolve_admin(pool, admin).await?;
            if task::cancel(pool, *task_id).await? {
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
            "[{}] {}/{} 导入 {} 无效 {}",
            t.status,
            t.processed_rows,
            t.total_rows
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".into()),
            t.imported_rows,
            t.invalid_rows
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
