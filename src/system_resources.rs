//! system_resources domain implementation, migrated from the library root.

use actix_web::web;
use deadpool_postgres::GenericClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_postgres::types::ToSql;
use tracing::{error, warn};

use crate::db::get_sql_from_file;
use crate::elasticsearch::ElasticsearchService;
use crate::logs::write::error_diagnostics;

use crate::{elasticsearch, system_resource_cache};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DbResource {
    pub db_library_size: String,
    pub db_table_size: BTreeMap<String, DbTableSizeInfo>,
    pub db_conn: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DbTableSizeInfo {
    pub total: i64,
    pub data: i64,
    pub index: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemCPU {
    pub cpu_usage: f32,            //cpu总体使用率
    pub cpu: HashMap<String, f32>, //单个cpu使用率
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemRAM {
    pub total_ram: u64,
    pub used_ram: u64,
    pub ram_usage: f32,
    pub total_swap: u64,
    pub use_swap: u64,
    pub swap_usage: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemDisk {
    pub disk_total_space: u64,
    pub disk_total_usage: u64,
    pub disk: HashMap<String, Vec<u64>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemNetInfo {
    pub send: String,
    pub receive: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemNetwork {
    pub net: BTreeMap<String, SystemNetInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemResource {
    pub server_run_time: i64,
    pub cpu: SystemCPU,
    pub ram: SystemRAM,
    pub disk: SystemDisk,
    pub db_postgresql: DbResource,
    pub network: SystemNetwork,
    pub create_at: Option<i64>,
}

#[derive(Clone)]
pub struct Systems {
    pub sys: Arc<Mutex<sysinfo::System>>,
    pub disk: Arc<Mutex<sysinfo::Disks>>,
    pub network: Arc<Mutex<sysinfo::Networks>>,
}

#[derive(Serialize, Deserialize)]
pub struct SystemDetails {
    pub host_name: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub kernel_version: Option<String>,
    pub architecture: String,
    pub cpu_model: Option<String>,
    pub cpu_vendor: Option<String>,
    pub cpu_frequency_mhz: Option<u64>,
    pub physical_core_count: Option<usize>,
    pub logical_cpu_count: usize,
}

impl Systems {
    pub fn new() -> Self {
        Self {
            sys: Arc::new(Mutex::new(sysinfo::System::new_all())),
            disk: Arc::new(Mutex::new(sysinfo::Disks::new_with_refreshed_list())),
            network: Arc::new(Mutex::new(sysinfo::Networks::new_with_refreshed_list())),
        }
    }
}

impl Default for Systems {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemDetails {
    pub fn new(systems: &Systems) -> Self {
        let sys = systems
            .sys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let first_cpu = sys.cpus().first();

        Self {
            host_name: sysinfo::System::host_name(),
            os_name: sysinfo::System::name(),
            os_version: sysinfo::System::long_os_version(),
            kernel_version: sysinfo::System::kernel_version(),
            architecture: sysinfo::System::cpu_arch(),
            cpu_model: first_cpu
                .map(|cpu| cpu.brand().trim().to_string())
                .filter(|value| !value.is_empty()),
            cpu_vendor: first_cpu
                .map(|cpu| cpu.vendor_id().trim().to_string())
                .filter(|value| !value.is_empty()),
            cpu_frequency_mhz: first_cpu.map(sysinfo::Cpu::frequency),
            physical_core_count: sysinfo::System::physical_core_count(),
            logical_cpu_count: sys.cpus().len(),
        }
    }
}

impl SystemCPU {
    pub fn new(sys: Arc<Mutex<sysinfo::System>>) -> Self {
        let mut cpu_usages = sys.lock().unwrap();
        cpu_usages.refresh_cpu_all();
        // let mut c_hash: HashMap<&str, f32> = HashMap::new();
        // cpu_usages.cpus().iter().map(|cpu| c_hash.insert(cpu.name(), cpu.cpu_usage()));

        let c_hash: HashMap<String, f32> = cpu_usages
            .cpus()
            .iter()
            .map(|cpu| (cpu.name().to_string(), cpu.cpu_usage()))
            .collect();

        Self {
            cpu_usage: cpu_usages.global_cpu_usage(),
            cpu: c_hash,
        }
    }
}

fn usage_percentage(used: u64, total: u64) -> f32 {
    if total == 0 {
        return 0.0;
    }

    (used as f64 / total as f64 * 100.0) as f32
}

impl SystemRAM {
    pub fn new(sys: Arc<Mutex<sysinfo::System>>) -> Self {
        let mut sys = sys.lock().unwrap();
        sys.refresh_memory();
        let total_m = sys.total_memory();
        let used_m = sys.used_memory();
        let total_s = sys.total_swap();
        let used_s = sys.used_swap();
        Self {
            ram_usage: usage_percentage(used_m, total_m),
            total_ram: total_m,
            used_ram: used_m,
            total_swap: total_s,
            use_swap: used_s,
            swap_usage: usage_percentage(used_s, total_s),
        }
    }
}

#[cfg(test)]
mod system_ram_tests {
    use super::usage_percentage;

    #[test]
    fn zero_total_has_zero_usage() {
        assert_eq!(usage_percentage(128, 0), 0.0);
    }

    #[test]
    fn usage_preserves_fractional_values() {
        assert_eq!(usage_percentage(1, 4), 25.0);
    }
}

impl SystemDisk {
    pub fn new(disk: Arc<Mutex<sysinfo::Disks>>) -> Self {
        let mut disk = disk.lock().unwrap();
        disk.refresh(true);
        let mut disk_total: u64 = 0;
        let mut disk_total_usage: u64 = 0;
        let mut d_h: HashMap<String, Vec<u64>> = HashMap::new();
        // disk.list().iter().map( |disk|
        //     disk_w(&mut disk_total, &mut disk_total_usage, &mut d_h, disk)
        // );
        // let d_h: HashMap<&str, Vec<u64>> = disk.list().iter().map( |disk|
        //     (disk.name(), ver!<disk.total_space(), disk.available_space()>)

        // )
        for d in disk.list() {
            disk_total += d.total_space();
            disk_total_usage += d.total_space() - d.available_space();
            d_h.insert(
                d.name().to_string_lossy().to_string(),
                vec![d.total_space(), d.available_space()],
            );
        }

        Self {
            disk_total_space: disk_total,
            disk_total_usage,
            disk: d_h,
        }
    }
}

impl SystemNetwork {
    pub fn new(net: Arc<Mutex<sysinfo::Networks>>) -> Self {
        let mut net = net.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        net.refresh(true);
        // The dashboard displays counters accumulated since system boot. The
        // received/transmitted methods only contain the latest refresh delta.
        let n_h: BTreeMap<String, SystemNetInfo> = net
            .list()
            .iter()
            .map(|(net_name, net_data)| {
                (
                    net_name.to_string(),
                    SystemNetInfo {
                        send: net_data.total_transmitted().to_string(),
                        receive: net_data.total_received().to_string(),
                    },
                )
            })
            .collect();

        Self { net: n_h }
    }
}

impl DbResource {
    pub async fn new(pool: &deadpool_postgres::Pool, sql_file_path: &str, db_name: &str) -> Self {
        let client = pool.get().await;
        // let mut db_h: HashMap<String, String> = HashMap::new();

        // let default_dbresource = DbResource {
        //     db_library_size: "null".to_string(),
        //     db_table_size: db_h.clone(),
        //     db_conn: "null".to_string()
        // };
        match client {
            Ok(o) => {
                //返回值的单位均为字节

                let db_table_size_sql =
                    get_sql_from_file(sql_file_path, "get_table_size.sql").await;
                let db_conn_sql = "SELECT COUNT(*) AS db_conn FROM pg_stat_activity;";
                let db_table_size = match db_table_size_sql {
                    Ok(sql) => get_db_table_size_byte(&o, &sql, &[]).await,
                    Err(e) => {
                        let diagnostics = error_diagnostics(e.as_ref());
                        error!(
                            event = "DatabaseMetricsSqlLoadError",
                            operation = "load_table_size_query",
                            error_kind = "filesystem",
                            error_code = "database_metrics_sql_load_failed",
                            error_message = %diagnostics.error_message,
                            error_chain = %diagnostics.error_chain,
                            root_cause = %diagnostics.root_cause,
                            error_truncated = diagnostics.error_truncated,
                            retryable = true,
                            outcome = "table_metrics_unavailable",
                            sql_file = "get_table_size.sql",
                        );
                        BTreeMap::from([("error".to_owned(), DbTableSizeInfo::default())])
                    }
                };

                Self {
                    db_library_size: get_db_library_size_byte(&o, db_name).await,
                    db_table_size,
                    db_conn: get_db_conn(&o, db_conn_sql, &[]).await,
                }
            }
            Err(e) => {
                let diagnostics = error_diagnostics(&e);
                error!(
                    event = "DatabaseMetricsPoolError",
                    operation = "acquire_metrics_connection",
                    error_kind = "database",
                    error_code = "database_metrics_pool_failed",
                    error_message = %diagnostics.error_message,
                    error_chain = %diagnostics.error_chain,
                    root_cause = %diagnostics.root_cause,
                    error_truncated = diagnostics.error_truncated,
                    retryable = true,
                    outcome = "database_metrics_unavailable",
                );
                //返回默认值
                DbResource::default()
            }
        }
    }
}

impl Default for DbResource {
    fn default() -> Self {
        let tmp = vec![("error".to_string(), DbTableSizeInfo::default())];
        let h: BTreeMap<String, DbTableSizeInfo> = tmp.into_iter().collect();
        Self {
            db_library_size: "none".to_string(),
            db_table_size: h,
            db_conn: "none".to_string(),
        }
    }
}

impl Default for DbTableSizeInfo {
    fn default() -> Self {
        Self {
            total: -1,
            data: -1,
            index: -1,
        }
    }
}

impl SystemResource {
    pub async fn new(sys: Systems, pool: &deadpool_postgres::Pool, db_name: &str) -> Self {
        Self {
            server_run_time: get_server_uptime() as i64,
            cpu: SystemCPU::new(sys.sys.clone()),
            ram: SystemRAM::new(sys.sys.clone()),
            disk: SystemDisk::new(sys.disk.clone()),
            db_postgresql: DbResource::new(pool, "source/database/", db_name).await,
            network: SystemNetwork::new(sys.network.clone()),
            create_at: None,
        }
    }
}

///获取数据库表的大小，单位为字节
async fn get_db_table_size_byte(
    pool: &deadpool::managed::Object<deadpool_postgres::Manager>,
    // db_h: &mut HashMap<String, DbTableSizeInfo>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> BTreeMap<String, DbTableSizeInfo> {
    let result = pool.query(sql, params).await;
    match result {
        Ok(rows) => {
            rows.iter()
                .map(|row| {
                    (
                        row.get("table_name"),
                        DbTableSizeInfo {
                            total: row.get("total_size"),
                            data: row.get("data_size"),
                            index: row.get("index_size"),
                        },
                    )
                })
                .collect()
            // for row in rows {
            //     let key = row.get("table_name");
            //     let value: i64 = row.get("total_size");
            //     // let value = values.to_s
            //     db_h.insert(key, value.to_string());
            // }
        }
        Err(e) => {
            let diagnostics = error_diagnostics(&e);
            let database = diagnostics.database.as_ref();
            error!(
                event = "DatabaseMetricsQueryError",
                operation = "query_table_sizes",
                error_kind = "database",
                error_code = "database_table_metrics_query_failed",
                error_message = %diagnostics.error_message,
                error_chain = %diagnostics.error_chain,
                root_cause = %diagnostics.root_cause,
                error_truncated = diagnostics.error_truncated,
                retryable = true,
                outcome = "table_metrics_unavailable",
                sqlstate = ?database.map(|value| value.sqlstate.as_str()),
                db_constraint = ?database.and_then(|value| value.constraint.as_deref()),
            );
            vec![("error".to_string(), DbTableSizeInfo::default())]
                .into_iter()
                .collect()
        }
    }
}

///获取数据库的大小，单位为字节
async fn get_db_library_size_byte(
    pool: &deadpool::managed::Object<deadpool_postgres::Manager>,
    db_name: &str,
) -> String {
    let sql = "SELECT pg_database_size($1::text::name) AS db_size;";
    match pool.query_opt(sql, &[&db_name]).await {
        Ok(Some(row)) => {
            let r: i64 = row.get("db_size");
            r.to_string()
        }
        Ok(None) => {
            warn!(
                event = "DatabaseMetricsEmptyResult",
                operation = "query_database_size",
                database = db_name,
                "database size query returned no row"
            );
            "null".to_string()
        }
        Err(error_value) => {
            let diagnostics = error_diagnostics(&error_value);
            let database = diagnostics.database.as_ref();
            error!(
                event = "DatabaseMetricsQueryError",
                operation = "query_database_size",
                error_kind = "database",
                error_code = "database_size_query_failed",
                error_message = %diagnostics.error_message,
                error_chain = %diagnostics.error_chain,
                root_cause = %diagnostics.root_cause,
                error_truncated = diagnostics.error_truncated,
                retryable = true,
                outcome = "database_size_metric_unavailable",
                sqlstate = ?database.map(|value| value.sqlstate.as_str()),
                db_constraint = ?database.and_then(|value| value.constraint.as_deref()),
            );
            "null".to_string()
        }
    }
}

///获取数据库的连接数
async fn get_db_conn(
    pool: &deadpool::managed::Object<deadpool_postgres::Manager>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> String {
    match pool.query_opt(sql, params).await {
        Ok(Some(row)) => {
            let r: i64 = row.get("db_conn");
            r.to_string()
        }
        Ok(None) => {
            warn!(
                event = "DatabaseMetricsEmptyResult",
                operation = "query_connection_count",
                "database connection count query returned no row"
            );
            "null".to_string()
        }
        Err(error_value) => {
            let diagnostics = error_diagnostics(&error_value);
            let database = diagnostics.database.as_ref();
            error!(
                event = "DatabaseMetricsQueryError",
                operation = "query_connection_count",
                error_kind = "database",
                error_code = "database_connection_count_query_failed",
                error_message = %diagnostics.error_message,
                error_chain = %diagnostics.error_chain,
                root_cause = %diagnostics.root_cause,
                error_truncated = diagnostics.error_truncated,
                retryable = true,
                outcome = "connection_count_metric_unavailable",
                sqlstate = ?database.map(|value| value.sqlstate.as_str()),
                db_constraint = ?database.and_then(|value| value.constraint.as_deref()),
            );
            "null".to_string()
        }
    }
}

///获取服务器运行时间
fn get_server_uptime() -> u64 {
    sysinfo::System::uptime()
}

///系统信息api基准测试
pub async fn benchmark(
    sys: web::Data<Systems>,
    pool: web::Data<&deadpool_postgres::Pool>,
    db_name: String,
) {
    let total_start = Instant::now();
    let pool = pool.get_ref();

    // CPU
    let start = Instant::now();
    let cpu = SystemCPU::new(sys.sys.clone());
    let cpu_elapsed = start.elapsed();

    // RAM
    let start = Instant::now();
    let ram = SystemRAM::new(sys.sys.clone());
    let ram_elapsed = start.elapsed();

    // Disk
    let start = Instant::now();
    let disk = SystemDisk::new(sys.disk.clone());
    let disk_elapsed = start.elapsed();

    // DB
    let start = Instant::now();
    let db = DbResource::new(pool, "source/database/", &db_name).await;
    let db_elapsed = start.elapsed();

    //Network
    let start = Instant::now();
    let net = SystemNetwork::new(sys.network.clone());
    let net_elapsed = start.elapsed();

    let total_elapsed = total_start.elapsed();

    println!("================= Benchmark =================");
    println!("CPU   : {:>6} µs", cpu_elapsed.as_micros());
    println!("RAM   : {:>6} µs", ram_elapsed.as_micros());
    println!("Disk  : {:>6} µs", disk_elapsed.as_micros());
    println!("DB    : {:>6} µs", db_elapsed.as_micros());
    println!("Net   : {:>6} µs", net_elapsed.as_micros());
    println!("---------------------------------------------");
    println!("Total : {:>6} µs", total_elapsed.as_micros());
    println!("=============================================");

    // 防止编译器优化掉
    let _ = (cpu, ram, disk, db, net);
}

///向数据库插入系统数据
pub async fn insert_system_status(
    pool: &deadpool_postgres::Pool,
    db_name: String,
    sys: Systems,
    elasticsearch: &ElasticsearchService,
    cache: &system_resource_cache::SystemResourceCache,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 数据库指标是系统快照的附加信息，最多等待 3 秒；不能让其拖住 CPU/RAM 等
    // 实时数据的发布。连接池自身还有更短的 wait timeout 作为第一层保护。
    let mut s = match tokio::time::timeout(
        Duration::from_secs(3),
        SystemResource::new(sys.clone(), pool, &db_name),
    )
    .await
    {
        Ok(resource) => resource,
        Err(_) => {
            warn!(
                event = "SystemDatabaseMetricsTimeout",
                timeout_seconds = 3,
                "PostgreSQL 指标采集超时，本周期使用默认数据库指标"
            );
            SystemResource {
                server_run_time: get_server_uptime() as i64,
                cpu: SystemCPU::new(sys.sys.clone()),
                ram: SystemRAM::new(sys.sys.clone()),
                disk: SystemDisk::new(sys.disk.clone()),
                db_postgresql: DbResource::default(),
                network: SystemNetwork::new(sys.network.clone()),
                create_at: None,
            }
        }
    };
    s.create_at = Some(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
    );
    // 发布内存快照早于持久化。即使数据库正忙，仪表盘仍能读取本周期采集结果；
    // 随后的 INSERT 继续作为重启恢复和长期审计的权威数据源。
    cache.record(s.clone());
    // Elasticsearch 容量采集可能触发网络超时，必须发生在内存快照发布之后，且不能
    // 推迟 PostgreSQL 持久化。失败只使本周期 ES 容量字段标记为 unavailable。
    let elasticsearch_metrics =
        match tokio::time::timeout(Duration::from_secs(3), elasticsearch.storage_metrics()).await {
            Ok(metrics) => metrics,
            Err(_) => {
                warn!(
                    event = "ElasticsearchStorageMetricsTimeout",
                    timeout_seconds = 3,
                    "Elasticsearch 容量指标采集超时"
                );
                elasticsearch::ElasticsearchStorageMetrics::unavailable(elasticsearch.enabled())
            }
        };
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    let sql = get_sql_from_file("source/database/", "insert_system_status.sql").await?;
    let statement = transaction.prepare(&sql).await?;
    let server_run_time = s.server_run_time;
    let cpu = serde_json::to_value(&s.cpu).unwrap();
    let ram = serde_json::to_value(&s.ram).unwrap();
    let disk = serde_json::to_value(&s.disk).unwrap();
    let db_postgresql = serde_json::to_value(&s.db_postgresql).unwrap();
    let db_elasticsearch = serde_json::to_value(elasticsearch_metrics).unwrap();
    let network = serde_json::to_value(&s.network).unwrap();
    let raw = transaction
        .execute(
            &statement,
            &[
                &server_run_time,
                &cpu,
                &ram,
                &disk,
                &db_postgresql,
                &db_elasticsearch,
                &network,
            ],
        )
        .await?;
    if raw == 1 {
        transaction.commit().await?;
        Ok(())
    } else {
        let message = format!("插入表影响行数为 {}", raw);
        transaction.rollback().await?;
        warn!(
            event = "DATABASE-WARNING",
            path = "fn insert_system_status",
            message
        );
        Err(message.into())
    }
}

#[derive(Serialize, Deserialize)]
pub struct SystemStatusJson {
    pub total_c: i32,
    pub status_item: Vec<SystemResource>,
    pub system_info: SystemDetails,
}

/// 获取系统状态信息
pub async fn get_system_status_info(
    start_at: Option<i64>,
    end_at: Option<i64>,
    count: i64,
    pool: &deadpool_postgres::Pool,
) -> Result<(Vec<SystemResource>, i32), Box<dyn std::error::Error>> {
    let connect = pool.get().await?;

    let row = if start_at.is_some() || end_at.is_some() {
        connect
            .query(
                "SELECT *
                        FROM system_status
                        WHERE create_time BETWEEN
                            COALESCE($1::BIGINT, (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT)
                            AND
                            COALESCE($2::BIGINT, (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT)
                        ORDER BY id DESC
                        LIMIT $3;",
                &[&start_at, &end_at, &count],
            )
            .await?
    } else {
        connect
            .query(
                "SELECT * FROM system_status ORDER BY id DESC LIMIT $1;",
                &[&count],
            )
            .await?
    };

    let mut vec_status: Vec<SystemResource> = Vec::new();
    let mut tmp_count: i32 = 0;

    for r in row {
        let tmp = SystemResource {
            server_run_time: r.get::<_, i64>("server_run_time"),
            cpu: serde_json::from_value(r.get::<_, Value>("cpu"))?,
            ram: serde_json::from_value(r.get::<_, Value>("ram"))?,
            disk: serde_json::from_value(r.get::<_, Value>("disk"))?,
            db_postgresql: serde_json::from_value(r.get::<_, Value>("db_postgresql"))?,
            network: serde_json::from_value(r.get::<_, Value>("network"))?,
            create_at: Some(r.get::<_, i64>("create_time")),
        };
        tmp_count += 1;
        vec_status.push(tmp);
    }
    Ok((vec_status, tmp_count))
}
