//! scan_control / query domain implementation, migrated from the library root.

use deadpool_postgres::GenericClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_postgres::types::ToSql;

use super::creation::display_scan_profile;
use super::dispatch::refresh_task_aggregate;
use crate::identity::Permission;

/// 表示单个任务条目
#[derive(Serialize)]
pub struct TaskItem {
    pub task_id: String,
    pub task_target: Vec<String>,
    pub task_kind: String,
    pub task_initiator: String,
    pub task_port: String,
    pub task_create_time: i64,
    pub task_level: i32,
    pub scanner_id: Option<String>,
    pub task_status: String,
    pub lease_expires_at: Option<i64>,
    pub attempt_count: i32,
    pub failure_reason: Option<String>,
    pub start_at: Option<i64>,
    pub end_at: Option<i64>,
    pub remarks: Option<String>,
    pub task_source: String,
    pub address_family: String,
    pub scan_profile: String,
    pub scan_plan: Value,
}

/// 表示 Json 格式的任务列表
#[derive(Serialize)]
pub struct TaskItemJson {
    pub total: i64,
    pub page_size: i64,
    pub next_cursor: Option<i32>,
    pub has_more: bool,
    pub items: Vec<TaskItem>,
}

/// 该结构体表示接收查询任务列表信息
#[derive(Deserialize)]
pub struct ReceiveTaskItemQueryInfo {
    #[serde(alias = "start")]
    pub cursor: Option<i32>,
    #[serde(alias = "count")]
    pub limit: Option<i64>,
    pub include_system: Option<bool>,
    pub task_id: Option<String>,
    pub target: Option<String>,
    pub status: Option<String>,
    pub operator: Option<String>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub scanner_id: Option<String>,
}

pub struct TaskListFilters {
    pub cursor: Option<i32>,
    pub limit: i64,
    pub include_system: bool,
    pub task_id: Option<String>,
    pub target: Option<String>,
    pub status: Option<String>,
    pub operator: Option<String>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub scanner_id: Option<String>,
}

pub struct TaskListPage {
    pub items: Vec<TaskItem>,
    pub total: i64,
    pub page_size: i64,
    pub next_cursor: Option<i32>,
    pub has_more: bool,
}

fn task_list_filter<'a>(
    filters: &'a TaskListFilters,
    owner_id: &'a Option<i32>,
    include_cursor: bool,
) -> (String, Vec<&'a (dyn ToSql + Sync)>) {
    let mut conditions = Vec::new();
    let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();

    if let Some(owner_id) = owner_id {
        params.push(owner_id);
        conditions.push(format!("t.user_id = ${}", params.len()));
    }
    if !filters.include_system {
        conditions.push("t.task_source <> 'automatic'".to_owned());
    }
    if let Some(task_id) = filters.task_id.as_ref() {
        params.push(task_id);
        conditions.push(format!("t.task_id ILIKE '%' || ${} || '%'", params.len()));
    }
    if let Some(target) = filters.target.as_ref() {
        params.push(target);
        conditions.push(format!(
            "(EXISTS (SELECT 1 FROM unnest(t.task_target) AS targets(target) \
                WHERE targets.target::TEXT ILIKE '%' || ${} || '%') \
              OR EXISTS (SELECT 1 FROM unnest(t.dns_targets) AS targets(target) \
                WHERE targets.target ILIKE '%' || ${} || '%'))",
            params.len(),
            params.len()
        ));
    }
    if let Some(status) = filters.status.as_ref() {
        params.push(status);
        conditions.push(format!("t.task_status = ${}", params.len()));
    }
    if let Some(operator) = filters.operator.as_ref() {
        params.push(operator);
        conditions.push(format!(
            "t.task_initiator ILIKE '%' || ${} || '%'",
            params.len()
        ));
    }
    if let Some(start_time) = filters.start_time.as_ref() {
        params.push(start_time);
        conditions.push(format!("t.task_create_time >= ${}", params.len()));
    }
    if let Some(end_time) = filters.end_time.as_ref() {
        params.push(end_time);
        conditions.push(format!("t.task_create_time <= ${}", params.len()));
    }
    if let Some(scanner_id) = filters.scanner_id.as_ref() {
        params.push(scanner_id);
        conditions.push(format!(
            "COALESCE(t.assigned_scanner_id, '') ILIKE '%' || ${} || '%'",
            params.len()
        ));
    }
    if include_cursor && let Some(cursor) = filters.cursor.as_ref() {
        params.push(cursor);
        conditions.push(format!("t.id < ${}", params.len()));
    }

    let clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };
    (clause, params)
}

/// 该函数用于获取所有的扫描任务记录，需要鉴权，普通用户只能获取到自己创建的任务，管理员则可以获取所有的
///
/// 接收多个参数，分别为
#[deprecated(note = "use get_filtered_task_page for stable pagination and server-side filters")]
pub async fn get_task_item(
    pool: &deadpool_postgres::Pool,
    s_count: i64,
    start_id: Option<i32>,
    include_system: bool,
    permissions: Permission,
) -> Result<(Vec<TaskItem>, i64, i64, i32), Box<dyn std::error::Error>> {
    let mut c = pool.get().await?;
    let s_count = s_count.clamp(1, 100);
    let transaction = c.transaction().await?;
    let expired = transaction.query(
        "UPDATE scan_task_execution SET execution_status = CASE WHEN cancel_requested THEN 'cancelled' ELSE 'pending' END, \
         assigned_scanner_id = CASE WHEN cancel_requested THEN assigned_scanner_id ELSE NULL END, lease_expires_at = NULL, \
         task_start_time = CASE WHEN cancel_requested THEN task_start_time ELSE NULL END, \
         task_end_time = CASE WHEN cancel_requested THEN (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT ELSE NULL END, \
         cancel_requested = false, failure_reason = CASE WHEN cancel_requested THEN NULL ELSE 'task lease expired' END \
         WHERE execution_status = 'running' AND lease_expires_at IS NOT NULL \
           AND lease_expires_at < (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT RETURNING task_id;", &[]).await?;
    let expired_tasks: std::collections::HashSet<i32> =
        expired.iter().map(|row| row.get("task_id")).collect();
    for task_id in expired_tasks {
        refresh_task_aggregate(&transaction, task_id).await?;
    }
    transaction.commit().await?;

    let row = match permissions {
        Permission::Administrator(_id) => {
            if let Some(st) = start_id {
                c.query(
                    "SELECT scan_task.*, CASE WHEN task_kind = 'dns' THEN dns_targets ELSE task_target::TEXT[] END AS display_targets, COUNT(*) OVER() AS total_count FROM scan_task \
                     WHERE id <= $1 AND ($2::boolean OR task_source <> 'automatic') \
                     ORDER BY id DESC LIMIT $3;",
                    &[&st, &include_system, &s_count],
                )
                .await?
            } else {
                c.query(
                    "SELECT scan_task.*, CASE WHEN task_kind = 'dns' THEN dns_targets ELSE task_target::TEXT[] END AS display_targets, COUNT(*) OVER() AS total_count FROM scan_task \
                     WHERE $1::boolean OR task_source <> 'automatic' ORDER BY id DESC LIMIT $2;",
                    &[&include_system, &s_count],
                )
                .await?
            }
        }
        Permission::Users(u_id) => {
            if let Some(st) = start_id {
                c.query(
                    "SELECT scan_task.*, CASE WHEN task_kind = 'dns' THEN dns_targets ELSE task_target::TEXT[] END AS display_targets, COUNT(*) OVER() AS total_count FROM scan_task \
                     WHERE user_id = $1 AND id <= $2 AND ($3::boolean OR task_source <> 'automatic') \
                     ORDER BY id DESC LIMIT $4;",
                    &[&u_id, &st, &include_system, &s_count]
                ).await?
            } else {
                c.query(
                    "SELECT scan_task.*, CASE WHEN task_kind = 'dns' THEN dns_targets ELSE task_target::TEXT[] END AS display_targets, COUNT(*) OVER() AS total_count FROM scan_task \
                     WHERE user_id = $1 AND ($2::boolean OR task_source <> 'automatic') \
                     ORDER BY id DESC LIMIT $3;",
                    &[&u_id, &include_system, &s_count],
                )
                .await?
            }
        }
    };

    let mut task_item_r: Vec<TaskItem> = Vec::new();
    let mut total_count_item: i64 = 0;
    let mut count: i64 = 0;
    let mut start_id: i32 = 0;

    for (index, r) in row.iter().enumerate() {
        if index == 0 {
            start_id = r.get::<_, i32>("id");
        }
        total_count_item = r.get::<_, i64>("total_count");
        let titem = TaskItem {
            task_id: r.get::<_, String>("task_id"),
            task_target: r.get("display_targets"),
            task_kind: r.get("task_kind"),
            task_initiator: r.get::<_, String>("task_initiator"),
            task_level: r.get::<_, i32>("task_level"),
            task_port: r.get::<_, String>("task_port"),
            task_create_time: r.get::<_, i64>("task_create_time"),
            scanner_id: r.get::<_, Option<String>>("assigned_scanner_id"),
            task_status: r.get::<_, String>("task_status"),
            lease_expires_at: r.get::<_, Option<i64>>("lease_expires_at"),
            attempt_count: r.get::<_, i32>("attempt_count"),
            failure_reason: r.get::<_, Option<String>>("failure_reason"),
            start_at: r.get::<_, Option<i64>>("task_start_time"),
            end_at: r.get::<_, Option<i64>>("task_end_time"),
            remarks: r.get::<_, Option<String>>("remarks"),
            task_source: r.get::<_, String>("task_source"),
            address_family: r.get::<_, String>("address_family"),
            scan_profile: r.get::<_, String>("scan_profile"),
            scan_plan: r.get::<_, Value>("scan_plan"),
        };
        task_item_r.push(titem);
        count += 1;
    }
    Ok((task_item_r, total_count_item, count, start_id))
}

/// 使用服务端筛选和排他游标分页获取任务，单次最多返回 100 条记录。
pub async fn get_filtered_task_page(
    pool: &deadpool_postgres::Pool,
    filters: &TaskListFilters,
    permissions: Permission,
) -> Result<TaskListPage, Box<dyn std::error::Error>> {
    let mut connection = pool.get().await?;
    let transaction = connection.transaction().await?;
    let expired = transaction
        .query(
            "UPDATE scan_task_execution SET execution_status = CASE WHEN cancel_requested THEN 'cancelled' ELSE 'pending' END, \
             assigned_scanner_id = CASE WHEN cancel_requested THEN assigned_scanner_id ELSE NULL END, lease_expires_at = NULL, \
             task_start_time = CASE WHEN cancel_requested THEN task_start_time ELSE NULL END, \
             task_end_time = CASE WHEN cancel_requested THEN (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT ELSE NULL END, \
             cancel_requested = false, failure_reason = CASE WHEN cancel_requested THEN NULL ELSE 'task lease expired' END \
             WHERE execution_status = 'running' AND lease_expires_at IS NOT NULL \
               AND lease_expires_at < (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT RETURNING task_id;",
            &[],
        )
        .await?;
    let expired_tasks: std::collections::HashSet<i32> =
        expired.iter().map(|row| row.get("task_id")).collect();
    for task_id in expired_tasks {
        refresh_task_aggregate(&transaction, task_id).await?;
    }
    transaction.commit().await?;

    let owner_id = match permissions {
        Permission::Administrator(_) => None,
        Permission::Users(id) => Some(id),
    };
    let (count_filter, count_params) = task_list_filter(filters, &owner_id, false);
    let count_sql = format!("SELECT COUNT(*)::BIGINT AS total FROM scan_task t{count_filter}");
    let total = connection
        .query_one(&count_sql, &count_params)
        .await?
        .get("total");

    let page_size = filters.limit.clamp(1, 100);
    let fetch_limit = page_size + 1;
    let (page_filter, mut page_params) = task_list_filter(filters, &owner_id, true);
    page_params.push(&fetch_limit);
    let page_sql = format!(
        "SELECT t.*, CASE WHEN t.task_kind = 'dns' THEN t.dns_targets ELSE t.task_target::TEXT[] END AS display_targets FROM scan_task t{page_filter} \
         ORDER BY t.id DESC LIMIT ${}",
        page_params.len()
    );
    let mut rows = connection.query(&page_sql, &page_params).await?;
    let has_more = rows.len() > page_size as usize;
    if has_more {
        rows.truncate(page_size as usize);
    }
    let next_cursor = if has_more {
        rows.last().map(|row| row.get::<_, i32>("id"))
    } else {
        None
    };
    let items = rows
        .into_iter()
        .map(|row| {
            let stored_profile: String = row.get("scan_profile");
            let generation_metadata: Option<Value> = row.get("generation_metadata");
            TaskItem {
                task_id: row.get("task_id"),
                task_target: row.get("display_targets"),
                task_kind: row.get("task_kind"),
                task_initiator: row.get("task_initiator"),
                task_port: row.get("task_port"),
                task_create_time: row.get("task_create_time"),
                task_level: row.get("task_level"),
                scanner_id: row.get("assigned_scanner_id"),
                task_status: row.get("task_status"),
                lease_expires_at: row.get("lease_expires_at"),
                attempt_count: row.get("attempt_count"),
                failure_reason: row.get("failure_reason"),
                start_at: row.get("task_start_time"),
                end_at: row.get("task_end_time"),
                remarks: row.get("remarks"),
                task_source: row.get("task_source"),
                address_family: row.get("address_family"),
                scan_profile: display_scan_profile(&stored_profile, generation_metadata.as_ref()),
                scan_plan: row.get("scan_plan"),
            }
        })
        .collect();
    Ok(TaskListPage {
        items,
        total,
        page_size,
        next_cursor,
        has_more,
    })
}

#[cfg(test)]
mod task_list_filter_tests {
    use super::{TaskListFilters, task_list_filter};

    fn filters() -> TaskListFilters {
        TaskListFilters {
            cursor: None,
            limit: 20,
            include_system: true,
            task_id: None,
            target: None,
            status: None,
            operator: None,
            start_time: None,
            end_time: None,
            scanner_id: None,
        }
    }

    #[test]
    fn administrator_without_filters_has_no_where_clause() {
        let filters = filters();
        let owner_id = None;
        let (sql, params) = task_list_filter(&filters, &owner_id, false);
        assert!(sql.is_empty());
        assert!(params.is_empty());
    }

    #[test]
    fn user_filters_use_contiguous_parameters() {
        let mut filters = filters();
        filters.include_system = false;
        filters.status = Some("running".to_owned());
        filters.scanner_id = Some("scanner-a".to_owned());
        filters.cursor = Some(100);
        let owner_id = Some(7);

        let (sql, params) = task_list_filter(&filters, &owner_id, true);

        assert_eq!(params.len(), 4);
        assert!(sql.contains("t.user_id = $1"));
        assert!(sql.contains("t.task_source <> 'automatic'"));
        assert!(sql.contains("t.task_status = $2"));
        assert!(sql.contains("assigned_scanner_id, '') ILIKE '%' || $3 || '%'"));
        assert!(sql.contains("t.id < $4"));
        assert!(!sql.contains("OR"));
    }
}
