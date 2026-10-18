use crate::config::DatabaseConfig;
use crate::web_support::path_secure_join;
use actix_web::web;
use deadpool_postgres::{ManagerConfig, RecyclingMethod, Runtime};
use std::time::Duration;
use std::time::Instant;
use tokio::fs;
use tracing::{debug, error, info};

use crate::logs::write::error_diagnostics;

/// Instrument only write-path leases, without logging SQL, payloads or credentials.
pub(crate) struct WriteConnection {
    connection: deadpool_postgres::Object,
    acquired_at: Instant,
    operation: &'static str,
}

impl std::ops::Deref for WriteConnection {
    type Target = deadpool_postgres::Object;
    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl std::ops::DerefMut for WriteConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}

impl Drop for WriteConnection {
    fn drop(&mut self) {
        info!(
            event = "ScanWriteConnectionReleased",
            operation = self.operation,
            hold_ms = self.acquired_at.elapsed().as_millis() as u64
        );
    }
}

pub(crate) async fn acquire_write_connection(
    pool: &deadpool_postgres::Pool,
    operation: &'static str,
) -> Result<WriteConnection, deadpool_postgres::PoolError> {
    let started = Instant::now();
    let result = pool.get().await;
    info!(
        event = "ScanWriteConnectionAcquired",
        operation,
        wait_ms = started.elapsed().as_millis() as u64,
        success = result.is_ok()
    );
    Ok(WriteConnection {
        connection: result?,
        acquired_at: Instant::now(),
        operation,
    })
}

pub struct SqlFile {
    pub root_path: String,
    pub file_name: String,
}

impl SqlFile {
    pub fn new(root: String, name: String) -> Self {
        Self {
            root_path: root,
            file_name: name,
        }
    }
}

pub async fn create_postgresql_pool(
    config: &DatabaseConfig,
) -> Result<deadpool_postgres::Pool, Box<dyn std::error::Error>> {
    let mut db_poll_cfg = deadpool_postgres::Config::new();
    db_poll_cfg.user = Some(config.username.clone());
    db_poll_cfg.password = Some(config.password.clone());
    db_poll_cfg.dbname = Some(config.db_name.clone());
    db_poll_cfg.host = Some(config.host.clone());
    db_poll_cfg.port = Some(config.port);
    db_poll_cfg.options = Some("-c timezone=UTC".into());
    db_poll_cfg.manager = Some(ManagerConfig {
        recycling_method: RecyclingMethod::Verified,
    });
    db_poll_cfg.pool = Some(deadpool_postgres::PoolConfig {
        max_size: config.pool_max_size,
        timeouts: deadpool::managed::Timeouts {
            wait: Some(Duration::from_millis(config.pool_wait_timeout_ms)),
            create: Some(Duration::from_millis(config.pool_create_timeout_ms)),
            recycle: Some(Duration::from_millis(config.pool_recycle_timeout_ms)),
        },
        queue_mode: deadpool::managed::QueueMode::Lifo,
    });
    info!(
        target: "server::startup",
        event = "DatabasePoolCreateStarted",
        database_host = %config.host,
        database_port = config.port,
        database_name = %config.db_name,
        pool_max_size = config.pool_max_size,
        runtime = "tokio1",
        recycling_method = "verified",
        "正在创建 PostgreSQL 连接池"
    );
    let pool = db_poll_cfg
        .create_pool(Some(Runtime::Tokio1), tokio_postgres::NoTls)
        .map_err(|error| {
            let diagnostics = error_diagnostics(&error);
            error!(
                target: "server::startup",
                event = "DatabasePoolCreateFailed",
                operation = "create_database_pool",
                error_kind = "database",
                error_code = "database_pool_create_failed",
                error_message = %diagnostics.error_message,
                error_chain = %diagnostics.error_chain,
                root_cause = %diagnostics.root_cause,
                error_truncated = diagnostics.error_truncated,
                retryable = false,
                outcome = "process_stopping",
                runtime = "tokio1",
                "PostgreSQL 连接池创建失败"
            );
            Box::new(error) as Box<dyn std::error::Error>
        })?;
    info!(
        target: "server::startup",
        pool_max_size = config.pool_max_size,
        pool_wait_timeout_ms = config.pool_wait_timeout_ms,
        pool_create_timeout_ms = config.pool_create_timeout_ms,
        pool_recycle_timeout_ms = config.pool_recycle_timeout_ms,
        "正在检查数据库连接"
    );
    match pool.get().await {
        Ok(_conn) => {
            // _conn 是一个 deadpool::managed::Object，它会在离开作用域时自动返回池中
            info!(
                target: "server::startup",
                event = "DatabasePoolConnectionVerified",
                database_host = %config.host,
                database_port = config.port,
                database_name = %config.db_name,
                pool_max_size = config.pool_max_size,
                "数据库连接成功，连接池可用"
            );
        }
        Err(e) => {
            let diagnostics = error_diagnostics(&e);
            error!(
                target: "server::startup",
                event = "DatabasePoolConnectionCheckFailed",
                operation = "verify_database_pool_connection",
                error_kind = "database",
                error_code = "database_pool_connection_check_failed",
                error_message = %diagnostics.error_message,
                error_chain = %diagnostics.error_chain,
                root_cause = %diagnostics.root_cause,
                error_truncated = diagnostics.error_truncated,
                retryable = false,
                outcome = "process_stopping",
                pool_wait_timeout_ms = config.pool_wait_timeout_ms,
                pool_create_timeout_ms = config.pool_create_timeout_ms,
                pool_recycle_timeout_ms = config.pool_recycle_timeout_ms,
                "数据库连接池连通性检查失败"
            );
            return Err(Box::new(e));
        }
    }
    Ok(pool)
}

pub async fn exec_sql(
    pool: web::Data<deadpool_postgres::Pool>,
    sql: &str,
    params: Option<&[&(dyn tokio_postgres::types::ToSql + Sync)]>,
) -> Result<&'static str, Box<dyn std::error::Error>> {
    // 从连接池获取客户端
    let mut client = pool.get().await?; // PoolError 自动转成 Box<dyn Error>

    // 开启事务
    let transaction = client.transaction().await?;

    // 预编译 SQL
    let stmt = transaction.prepare(sql).await?;

    // 执行 SQL
    match params {
        Some(values) => transaction.query(&stmt, values).await?,
        None => transaction.query(&stmt, &[]).await?,
    };

    // 提交事务
    transaction.commit().await?;

    Ok("OK")
}

///初始化数据库表结构
pub async fn init_database_table(
    cpool: &deadpool_postgres::Pool,
    file_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let sql = fs::read_to_string(file_path).await?;
    let mut client = cpool.get().await?;
    let transaction = client.transaction().await?;
    debug!(init_database_file = file_path, "开始执行数据库初始化事务");
    transaction.batch_execute(&sql).await?;
    transaction
        .batch_execute(include_str!(
            "../../source/database/migrate_search_target_ip.sql"
        ))
        .await?;
    transaction
        .batch_execute(include_str!(
            "../../source/database/migrate_scan_upload_stream.sql"
        ))
        .await?;
    transaction
        .batch_execute(include_str!(
            "../../source/database/migrate_scan_projection.sql"
        ))
        .await?;
    transaction
        .batch_execute(include_str!(
            "../../source/database/migrate_scanner_diagnostics.sql"
        ))
        .await?;
    transaction
        .batch_execute(include_str!("../../source/database/migrate_reports.sql"))
        .await?;
    transaction
        .batch_execute(include_str!(
            "../../source/database/migrate_report_mail_assets.sql"
        ))
        .await?;
    transaction
        .batch_execute(include_str!(
            "../../source/database/migrate_system_time.sql"
        ))
        .await?;
    transaction
        .batch_execute(include_str!("../../source/database/migrate_statistics.sql"))
        .await?;
    transaction
        .batch_execute(include_str!(
            "../../source/database/migrate_smart_scanning.sql"
        ))
        .await?;
    transaction
        .batch_execute(include_str!("../../source/database/migrate_open_api.sql"))
        .await?;
    transaction
        .batch_execute(include_str!(
            "../../source/database/migrate_notifications.sql"
        ))
        .await?;
    transaction
        .batch_execute(include_str!(
            "../../source/database/migrate_os_detection.sql"
        ))
        .await?;
    transaction
        .batch_execute(include_str!(
            "../../source/database/migrate_notification_templates.sql"
        ))
        .await?;
    transaction
        .batch_execute(include_str!(
            "../../source/database/migrate_web_detection.sql"
        ))
        .await?;
    transaction.commit().await?;

    Ok(())
}

//TODO 完成获取数据库数据的函数

//TODO 完成调用该函数，将所有需要sql语句的地方使用该函数
///该函数用于从文件中读取内容并以 String 类型返回。这不是一个安全的函数，因为他需要你自己处理错误，他只会将错误向上传。
pub async fn get_sql_from_file(
    file_path: &str,
    file_name: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let path = path_secure_join(file_path, file_name);
    match path {
        Some(s) => Ok(fs::read_to_string(s).await?),
        None => {
            let message = "SQL file path failed security validation";
            error!(
                event = "SqlFilePathRejected",
                operation = "resolve_sql_file_path",
                error_kind = "validation",
                error_code = "sql_file_path_rejected",
                error_message = message,
                retryable = false,
                outcome = "operation_failed",
            );
            Err(message.into())
        }
    }
}
