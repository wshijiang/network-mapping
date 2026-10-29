//! Interactive statistics: all rows and exports share one query result.
use crate::statistics::{Failure, StatisticsService};
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc};
use deadpool_postgres::{GenericClient, Pool};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use std::time::{Duration as StdDuration, Instant};
use tokio_postgres::IsolationLevel;

use super::data_saa::{
    AnalysisFilterQuery, AnalysisFilters, analysis_es_filters, normalize_filters,
};
use crate::{
    admin::UserBaseI,
    config::AnalyticsSnapshotConfig,
    elasticsearch::{ElasticsearchService, ScanQueryIndex},
    runtime_config::RuntimeConfig,
};

const MAX_ES_BUCKETS: usize = 50_000;

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct StatisticsQuery {
    #[serde(flatten)]
    filters: AnalysisFilterQuery,
    data_type: String,
    group_by: String,
    timezone: String,
    #[serde(default)]
    metrics: Option<Vec<String>>,
    #[serde(default)]
    comparison: Option<String>,
}

fn definitions() -> Value {
    json!([
        {"id":"discovery","label":"IP 发现","groups":["day","week","month","scanner","task_source"],"metrics":["count"],"charts":["line","bar","heatmap"]},
        {"id":"port","label":"端口分布","groups":["port"],"metrics":["count","percentage"],"charts":["bar","donut"]},
        {"id":"service","label":"服务分布","groups":["service"],"metrics":["count","percentage"],"charts":["bar","donut"]},
        {"id":"tasks","label":"任务执行","groups":["day","week","month","task_source"],"metrics":["created","completed","succeeded","failed","partial","cancelled","success_rate"],"charts":["bar","line","stacked"]},
        {"id":"scanners","label":"扫描器表现","groups":["scanner","day","week","month","task_source"],"metrics":["completed","succeeded","failed","partial","cancelled","success_rate","avg_duration_ms","p50_ms","p95_ms"],"charts":["bar","line","stacked"]}
    ])
}

#[get("/api/analysis/statistics/catalog")]
pub(crate) async fn catalog(_user: UserBaseI) -> HttpResponse {
    HttpResponse::Ok()
        .json(json!({"success":true,"data":{"types":definitions(),"max_range_days":366}}))
}

fn valid_combination(kind: &str, group: &str) -> bool {
    definitions().as_array().is_some_and(|types| {
        types.iter().any(|t| {
            t["id"] == kind
                && t["groups"]
                    .as_array()
                    .is_some_and(|groups| groups.iter().any(|g| g == group))
        })
    })
}

fn failure(message: &str) -> HttpResponse {
    HttpResponse::ServiceUnavailable().json(json!({"success":false,"message":message}))
}

#[get("/api/analysis/statistics/cache")]
pub(crate) async fn cache_status(
    pool: web::Data<Pool>,
    service: web::Data<StatisticsService>,
    user: UserBaseI,
) -> HttpResponse {
    if user.role != 1 {
        return HttpResponse::Forbidden().finish();
    }
    if service.refresh(&pool).await.is_err() {
        return failure("缓存配置读取失败");
    }
    let client = match pool.get().await {
        Ok(c) => c,
        Err(_) => return failure("缓存状态读取失败"),
    };
    let rows=match client.query("SELECT status, updated_at FROM statistics_instance WHERE updated_at>NOW()-INTERVAL '2 minutes' ORDER BY instance_id", &[]).await {Ok(r)=>r,Err(_)=>return failure("实例状态读取失败")};
    HttpResponse::Ok().json(json!({"success":true,"data":{"current":service.status(),"instances":rows.iter().map(|r|json!({"status":r.get::<_,Value>("status"),"updated_at":r.get::<_,DateTime<Utc>>("updated_at")})).collect::<Vec<_>>(),
        "limits":{"realtime_ttl_seconds":[5,300],"history_ttl_seconds":[5,300],"snapshot_ttl_seconds":[10,900],"max_entries":[16,4096],"max_size_mib":[8,256],"max_entry_kib":[256,8192],"max_groups":[1,65536]}}}))
}

#[derive(Deserialize)]
pub(crate) struct ClearCache {
    expected_revision: i64,
}
#[post("/api/analysis/statistics/cache/clear")]
pub(crate) async fn clear_cache(
    req: actix_web::HttpRequest,
    body: web::Json<ClearCache>,
    pool: web::Data<Pool>,
    service: web::Data<StatisticsService>,
    user: UserBaseI,
) -> HttpResponse {
    if user.role != 1 {
        return HttpResponse::Forbidden().finish();
    }
    let client = match pool.get().await {
        Ok(c) => c,
        Err(_) => return failure("缓存配置读取失败"),
    };
    let row = match client
        .query_one(
            "SELECT document FROM runtime_configuration WHERE namespace=$1",
            &[&crate::statistics::NAMESPACE],
        )
        .await
    {
        Ok(r) => r,
        Err(_) => return failure("缓存配置读取失败"),
    };
    let config = match crate::statistics::parse_config(row.get("document")) {
        Ok(v) => v,
        Err(_) => return failure("缓存配置无效"),
    };
    drop(client);
    let revision = match crate::runtime_config::persist(
        &pool,
        crate::statistics::NAMESPACE,
        body.expected_revision,
        &config,
        "清空统计缓存",
        user.id,
    )
    .await
    {
        Ok(r) => r,
        Err(crate::runtime_config::PersistError::Conflict) => {
            return HttpResponse::Conflict()
                .json(json!({"success":false,"message":"配置已变化，请重新加载后清理"}));
        }
        Err(_) => return failure("缓存清理失败"),
    };
    // Refresh first so applying the same settings always invalidates retained entries.
    service.apply(config.clone(), body.expected_revision);
    service.apply(config.clone(), revision);
    let event =
        crate::audit::AuditEvent::user("configuration", "statistics_cache_clear", "success", &user)
            .resource("setting", crate::statistics::NAMESPACE);
    crate::audit::write_standalone(
        &pool,
        &crate::audit::AuditContext::from_request(&req),
        &event,
    )
    .await;
    HttpResponse::Ok().json(json!({"success":true,"data":{"namespace":crate::statistics::NAMESPACE,"revision":revision,"document":config}}))
}

#[post("/api/analysis/statistics/query")]
pub(crate) async fn query(
    req: HttpRequest,
    body: web::Json<StatisticsQuery>,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    config: web::Data<RuntimeConfig<AnalyticsSnapshotConfig>>,
    service: web::Data<StatisticsService>,
    user: UserBaseI,
) -> HttpResponse {
    let mut body = body.into_inner();
    if !valid_combination(&body.data_type, &body.group_by)
        || body.comparison.as_deref().is_some_and(|v| v != "previous")
    {
        return HttpResponse::BadRequest()
            .json(json!({"success":false,"message":"不支持的数据类型、汇总维度或对比方式"}));
    }
    // Quantiles require sorting all matching durations; calculate them only on request.
    if body.metrics.is_none() {
        body.metrics = definitions().as_array().and_then(|types| {
            types.iter().find(|t| t["id"] == body.data_type).map(|t| {
                t["metrics"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .filter(|m| !matches!(*m, "p50_ms" | "p95_ms"))
                    .map(str::to_owned)
                    .collect()
            })
        });
    }
    if let Some(ref mut metrics) = body.metrics {
        let type_catalog = definitions();
        let Some(definition) = type_catalog
            .as_array()
            .and_then(|types| types.iter().find(|t| t["id"] == body.data_type))
        else {
            return HttpResponse::BadRequest().finish();
        };
        if metrics.is_empty()
            || metrics.len() > 16
            || metrics.iter().any(|m| {
                !definition["metrics"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|v| v == m))
            })
        {
            return HttpResponse::BadRequest()
                .json(json!({"success":false,"message":"统计指标无效"}));
        }
        metrics.sort();
        metrics.dedup();
    }
    let filters = match normalize_filters(&body.filters) {
        Ok(f) => f,
        Err(e) => return HttpResponse::BadRequest().json(json!({"success":false,"message":e})),
    };
    if body.timezone != filters.timezone {
        return HttpResponse::Conflict()
            .json(json!({"success":false,"message":"系统时区已改变，请重新生成统计"}));
    }
    if let Err(error) = service.refresh(&pool).await {
        tracing::warn!(event = "StatisticsConfigurationReadFailed", request_id = %crate::logs::write::request_id(&req), error_message = %error);
        return error_response(
            &req,
            Failure("statistics_config_unavailable", "统计配置暂不可用"),
            &body.data_type,
            Some(&body.group_by),
        );
    }
    let max_groups = service.max_groups();
    let settings = config.get().await;
    let is_scan = matches!(body.data_type.as_str(), "discovery" | "port" | "service");
    let snapshot = is_scan && settings.value.mode.reads_snapshot();
    let mode = if snapshot {
        "snapshot"
    } else if is_scan {
        "realtime"
    } else {
        "retained_history"
    };
    let key=json!({"user":user.id,"role":user.role,"type":body.data_type,"group":body.group_by,"metrics":body.metrics,
        "comparison":body.comparison,"start":filters.start_at,"end":filters.end_at,"timezone":filters.timezone,
        "scanner":filters.scanner_id,"source":filters.task_source,"mode":mode,"mode_revision":settings.revision,"max_groups":max_groups,"version":2}).to_string();
    let data_type = body.data_type.clone();
    let group_by = body.group_by.clone();
    let start_at = filters.start_at;
    let end_at = filters.end_at;
    let has_scanner_filter = filters.scanner_id.is_some();
    let has_source_filter = filters.task_source.is_some();
    let comparison = body.comparison.is_some();
    let result=service.execute(key,user.id,mode.to_owned(),move |deadline| async move {
        let mut cluster_slot=crate::statistics::ClusterSlot::acquire(&pool).await?;
        let output=async {
        let mut buckets=0;
        let mut value=compute(&body,&filters,cluster_slot.client()?,&elasticsearch,&user,snapshot,deadline,&mut buckets,max_groups).await?;
        if body.comparison.is_some() {
            let previous=previous_filters(&filters)?;
            let other=compute(&body,&previous,cluster_slot.client()?,&elasticsearch,&user,snapshot,deadline,&mut buckets,max_groups).await?;
            value["comparison"]=json!({"period":"previous","data":other["data"],"meta":other["meta"],"basis":"retained_data",
                "note":"基于保留数据的前一等长日历周期；历史完整性未确认，差异不代表资产新增。"});
        }
        Ok(value)
        }.await;
        cluster_slot.release().await?;
        output
    }).await;
    match result {
        Ok((bytes, cache)) => HttpResponse::Ok()
            .insert_header(("X-Statistics-Cache", cache))
            .content_type("application/json; charset=utf-8")
            .body(bytes),
        Err(e) => {
            tracing::warn!(event = "StatisticsQueryContext", request_id = %crate::logs::write::request_id(&req),
                data_type, group_by, mode, %start_at, %end_at, has_scanner_filter, has_source_filter, comparison, error_code = e.0);
            error_response(&req, e, &data_type, Some(&group_by))
        }
    }
}
pub(super) fn error_response(
    req: &HttpRequest,
    error: Failure,
    data_type: &str,
    group_by: Option<&str>,
) -> HttpResponse {
    let status = if error.0 == "statistics_busy" {
        actix_web::http::StatusCode::TOO_MANY_REQUESTS
    } else {
        actix_web::http::StatusCode::SERVICE_UNAVAILABLE
    };
    crate::request_log::set_reason(req, error.0);
    tracing::warn!(
        event = "StatisticsRequestRejected",
        request_id = %crate::logs::write::request_id(req),
        path = req.path(),
        data_type,
        group_by = ?group_by,
        error_code = error.0,
        error_message = error.1,
        http_status = status.as_u16(),
    );
    HttpResponse::build(status)
        .insert_header(("Retry-After", "5"))
        .json(json!({"success":false,"code":error.0,"message":error.1}))
}
fn remaining(deadline: Instant) -> Result<StdDuration, Failure> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(Failure::timeout)
}

fn budget_exceeded(
    kind: &str,
    group: &str,
    mode: &str,
    reason: &str,
    observed: usize,
    limit: usize,
    f: &AnalysisFilters,
) -> String {
    tracing::warn!(event = "StatisticsBudgetExceeded", data_type = kind, group_by = group, mode, reason,
        observed, limit, start_at = %f.start_at, end_at = %f.end_at);
    "too_large".into()
}
fn previous_filters(f: &AnalysisFilters) -> Result<AnalysisFilters, Failure> {
    let tz = f
        .timezone
        .parse::<chrono_tz::Tz>()
        .map_err(|_| Failure("statistics_failed", "统计时区无效"))?;
    let start = f.start_at.with_timezone(&tz);
    let end = f.end_at.with_timezone(&tz);
    let days = (end.date_naive() - start.date_naive()).num_days();
    if days < 1 {
        return Err(Failure("statistics_failed", "周期对比需要完整日历日期"));
    }
    let previous = start
        .checked_sub_days(chrono::Days::new(days as u64))
        .ok_or(Failure("statistics_failed", "无法计算上期日期"))?
        .with_timezone(&Utc);
    let mut result = f.clone();
    result.start_at = previous;
    result.end_at = f.start_at;
    result.start_ms = previous.timestamp_millis();
    result.end_ms = f.start_ms;
    Ok(result)
}
#[allow(clippy::too_many_arguments)]
async fn compute(
    body: &StatisticsQuery,
    filters: &AnalysisFilters,
    client: &mut deadpool_postgres::Client,
    es: &ElasticsearchService,
    user: &UserBaseI,
    snapshot: bool,
    deadline: Instant,
    buckets: &mut usize,
    max_groups: usize,
) -> Result<Value, Failure> {
    remaining(deadline)?;
    let generated_at = Utc::now();
    let is_scan = matches!(body.data_type.as_str(), "discovery" | "service" | "port");
    let mut data_as_of = None;
    let output = if is_scan && !snapshot {
        scan_realtime(
            es,
            filters,
            user,
            &body.data_type,
            &body.group_by,
            deadline,
            buckets,
            max_groups,
        )
        .await
    } else {
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await
            .map_err(|_| Failure("statistics_failed", "统计事务暂不可用"))?;
        let calculation=async {
        let milliseconds = remaining(deadline)?.as_millis().clamp(1, 8000);
        tx.batch_execute(&format!("SET LOCAL statement_timeout = '{milliseconds}ms'; SET LOCAL lock_timeout = '500ms'; SET LOCAL max_parallel_workers_per_gather = 0;")).await.map_err(|_|Failure("statistics_failed","统计预算设置失败"))?;
        if snapshot {
            data_as_of=tx.query_opt("SELECT data_as_of FROM analytics_watermark WHERE watermark_key='scan_analysis'",&[]).await.map_err(|_|Failure("statistics_failed","快照状态暂不可用"))?.map(|r|r.get::<_,DateTime<Utc>>("data_as_of"));
            if data_as_of.is_none() {
                return Err(Failure(
                    "statistics_snapshot_pending",
                    "分析快照尚未就绪，请稍后重试",
                ));
            }
        }
        let percentiles = body
            .metrics
            .as_ref()
            .is_some_and(|m| m.iter().any(|m| m == "p50_ms" || m == "p95_ms"));
        let milliseconds = remaining(deadline)?.as_millis().clamp(1,8000);
        tx.batch_execute(&format!("SET LOCAL statement_timeout = '{milliseconds}ms'")).await.map_err(|_|Failure::timeout())?;
        let result = if is_scan {
            scan_snapshot(&tx, filters, user, &body.data_type, &body.group_by, max_groups).await
        } else {
            operations(
                &tx,
                filters,
                user,
                &body.data_type,
                &body.group_by,
                percentiles,
                max_groups,
            )
            .await
        };
        Ok::<_,Failure>(result)
        }.await;
        // Await cleanup before returning the connection or releasing the computation permit.
        tx.rollback()
            .await
            .map_err(|_| Failure("statistics_failed", "统计事务清理失败"))?;
        calculation?
    };
    let (mut rows, summary) = output.map_err(|error| match error.as_str() {
        "too_large" => Failure(
            "statistics_budget_exceeded",
            "统计量超过在线预算，请缩小范围或增加筛选",
        ),
        "timeout" => Failure::timeout(),
        "legacy_timezone" => Failure("statistics_failed", "旧快照无法换算时区，请联系管理员重建"),
        _ => {
            tracing::warn!(event="StatisticsQueryFailed",%error);
            Failure("statistics_failed", "统计查询暂不可用，请稍后重试")
        }
    })?;
    remaining(deadline)?;
    if matches!(body.group_by.as_str(), "day" | "week" | "month") {
        fill_dates(&mut rows, filters, &body.group_by, &body.data_type);
    }
    let notes = if is_scan {
        if snapshot {
            vec![
                "扫描统计基于已处理且保留的统计事实；处理水位不保证查询范围完整。",
                "IP 在每个分组内去重，周期去重数独立计算，不能累加分组数量。",
                "端口、服务按执行内代表性端点计数，跨执行累加，不代表当前资产存量。",
            ]
        } else {
            vec![
                "扫描统计基于查询时保留且已索引的观测，按 IP 或执行端点精确去重。",
                "IP 在每个分组内去重，周期去重数独立计算，不能累加分组数量。",
                "端口、服务计数不代表当前资产存量。",
            ]
        }
    } else {
        vec![
            "新建任务按创建时间归属，完成任务及执行按结束时间归属，取消单列。",
            "成功率 = 成功 /（成功 + 失败 + 部分完成），无分母显示 --。",
            "任务按逻辑任务去重；扫描器按执行实例计数。耗时仅包含有效起止时间的成功执行。",
            "统计基于查询时保留的历史。",
        ]
    };

    Ok(
        json!({"success":true,"data":{"rows":rows,"summary":summary},"meta":{
            "data_type":body.data_type,"group_by":body.group_by,"start_at":filters.start_at,"end_at":filters.end_at,
            "timezone":filters.timezone,"scanner_id":filters.scanner_id,"task_source":filters.task_source,
            "generated_at":generated_at,"period_complete":filters.end_at <= generated_at,"data_as_of":data_as_of,"mode":if snapshot {"snapshot"} else if is_scan {"realtime"} else {"retained_history"},
            "completeness":"retained_data","notes":notes,"metric_version":2,"metrics":body.metrics
        }}),
    )
}

fn rate(succeeded: i64, failed: i64, partial: i64) -> Option<f64> {
    let denominator = succeeded + failed + partial;
    (denominator > 0).then(|| (succeeded as f64 / denominator as f64 * 1000.0).round() / 10.0)
}

fn counts(mut value: Value) -> Value {
    let n = |key: &str| value[key].as_i64().unwrap_or(0);
    let succeeded = n("succeeded");
    let failed = n("failed");
    let partial = n("partial");
    value["completed"] = json!(succeeded + failed + partial + n("cancelled"));
    value["success_rate"] = json!(rate(succeeded, failed, partial));
    value
}

// These SQL fragments are only selected after catalog validation, never interpolated from input.
fn time_group(expression: &str, group: &str) -> String {
    format!("to_char(date_trunc('{group}', {expression}), 'YYYY-MM-DD')")
}

async fn operations<C: GenericClient + Sync>(
    client: &C,
    f: &AnalysisFilters,
    user: &UserBaseI,
    kind: &str,
    group: &str,
    percentiles: bool,
    max_groups: usize,
) -> Result<(Vec<Value>, Value), String> {
    let owner = (user.role != 1).then_some(user.id);
    let scope = "($3::INT IS NULL OR t.user_id = $3) AND ($4::TEXT IS NULL OR EXISTS(SELECT 1 FROM scan_task_execution se WHERE se.task_id = t.id AND se.assigned_scanner_id = $4)) AND ($5::TEXT IS NULL OR t.task_source = $5)";
    let row_limit = max_groups + 2; // one total row and one overflow sentinel
    let sql = if kind == "tasks" {
        let label = if group == "task_source" {
            "task_source".to_owned()
        } else {
            time_group("to_timestamp(at / 1000.0) AT TIME ZONE $6", group)
        };
        format!("WITH events AS (
            SELECT t.task_create_time AS at, t.task_source, 'created' AS status FROM scan_task t WHERE {scope} AND t.task_create_time >= $1 AND t.task_create_time < $2
            UNION ALL SELECT t.task_end_time, t.task_source, t.task_status FROM scan_task t WHERE {scope} AND t.task_end_time >= $1 AND t.task_end_time < $2 AND t.task_status IN ('succeeded','failed','partial','cancelled')
        ) SELECT {label} AS label, GROUPING({label}) AS is_total,
            jsonb_build_object('created',COUNT(*) FILTER(WHERE status='created'), 'succeeded',COUNT(*) FILTER(WHERE status='succeeded'),
            'failed',COUNT(*) FILTER(WHERE status='failed'),'partial',COUNT(*) FILTER(WHERE status='partial'),'cancelled',COUNT(*) FILTER(WHERE status='cancelled')) AS metrics
          FROM events WHERE $6::TEXT IS NOT NULL GROUP BY GROUPING SETS (({label}),()) ORDER BY is_total DESC, label LIMIT {row_limit}")
    } else {
        let label = match group {
            "scanner" => "COALESCE(s.name, e.assigned_scanner_id, '未分配') || ' [' || COALESCE(e.assigned_scanner_id, 'unassigned') || ']'".to_owned(),
            "task_source" => "t.task_source".to_owned(),
            _ => time_group("to_timestamp(e.task_end_time / 1000.0) AT TIME ZONE $6", group),
        };
        let duration = if percentiles {
            "percentile_cont(ARRAY[0.5,0.95]::FLOAT8[]) WITHIN GROUP(ORDER BY (e.task_end_time-e.task_start_time)::FLOAT8) FILTER(WHERE e.execution_status='succeeded' AND e.task_start_time IS NOT NULL AND e.task_end_time>=e.task_start_time)"
        } else {
            "NULL::FLOAT8[]"
        };
        format!("SELECT {label} AS label, GROUPING({label}) AS is_total, {duration} AS percentiles,
          jsonb_build_object('succeeded',COUNT(*) FILTER(WHERE e.execution_status='succeeded'),
          'failed',COUNT(*) FILTER(WHERE e.execution_status='failed'),'partial',COUNT(*) FILTER(WHERE e.execution_status='partial'),'cancelled',COUNT(*) FILTER(WHERE e.execution_status='cancelled'),
          'avg_duration_ms',AVG(e.task_end_time-e.task_start_time) FILTER(WHERE e.execution_status='succeeded' AND e.task_start_time IS NOT NULL AND e.task_end_time>=e.task_start_time)) AS metrics
          FROM scan_task_execution e JOIN scan_task t ON t.id=e.task_id LEFT JOIN scanner_info s ON s.scanner_id=e.assigned_scanner_id
          WHERE ($3::INT IS NULL OR t.user_id=$3) AND ($4::TEXT IS NULL OR e.assigned_scanner_id=$4) AND ($5::TEXT IS NULL OR t.task_source=$5) AND $6::TEXT IS NOT NULL
          AND e.task_end_time >= $1 AND e.task_end_time < $2 AND e.execution_status IN ('succeeded','failed','partial','cancelled')
          GROUP BY GROUPING SETS (({label}),()) ORDER BY is_total DESC, label LIMIT {row_limit}")
    };
    let result = client
        .query(
            &sql,
            &[
                &f.start_ms,
                &f.end_ms,
                &owner,
                &f.scanner_id,
                &f.task_source,
                &f.timezone,
            ],
        )
        .await
        .map_err(|e| e.to_string())?;
    if result.len().saturating_sub(1) > max_groups {
        return Err(budget_exceeded(
            kind,
            group,
            "retained_history",
            "groups",
            result.len().saturating_sub(1),
            max_groups,
            f,
        ));
    }
    let mut rows = Vec::new();
    let mut summary = json!({});
    for row in result {
        let mut value = counts(row.get("metrics"));
        if kind == "scanners" {
            let quantiles: Option<Vec<f64>> = row.get("percentiles");
            value["p50_ms"] = json!(quantiles.as_ref().and_then(|q| q.first()));
            value["p95_ms"] = json!(quantiles.as_ref().and_then(|q| q.get(1)));
        }
        if row.get::<_, i32>("is_total") == 1 {
            summary = value;
        } else {
            value["label"] = json!(row.get::<_, String>("label"));
            rows.push(value);
        }
    }
    Ok((rows, summary))
}

async fn scan_snapshot<C: GenericClient + Sync>(
    client: &C,
    f: &AnalysisFilters,
    user: &UserBaseI,
    kind: &str,
    group: &str,
    max_groups: usize,
) -> Result<(Vec<Value>, Value), String> {
    let owner = (user.role != 1).then_some(user.id);
    let scope = "($3::INT IS NULL OR owner_id=$3) AND ($4::TEXT IS NULL OR scanner_id=$4) AND ($5::TEXT IS NULL OR task_source=$5)";
    if kind != "discovery" {
        let row_limit = max_groups + 1;
        let rows = client.query(&format!("SELECT label, SUM(endpoint_count)::BIGINT AS count FROM analytics_distribution_30m WHERE {scope} AND bucket_start >= $1 AND bucket_start < $2 AND dimension=$6 GROUP BY label ORDER BY count DESC,label LIMIT {row_limit}"), &[&f.start_at,&f.end_at,&owner,&f.scanner_id,&f.task_source,&kind]).await.map_err(|e|e.to_string())?;
        if rows.len() > max_groups {
            return Err(budget_exceeded(
                kind,
                group,
                "snapshot",
                "groups",
                rows.len(),
                max_groups,
                f,
            ));
        }
        return Ok(distribution(
            rows.iter()
                .map(|r| (r.get::<_, String>("label"), r.get::<_, i64>("count")))
                .collect(),
        ));
    }
    let range = "((first_observed_at >= $1 AND first_observed_at < $2) OR (first_observed_at IS NULL AND day_start >= ($1 AT TIME ZONE 'Asia/Shanghai')::DATE AND day_start < ($2 AT TIME ZONE 'Asia/Shanghai')::DATE))";
    let params: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
        &f.start_at,
        &f.end_at,
        &owner,
        &f.scanner_id,
        &f.task_source,
        &f.timezone,
    ];
    if f.timezone != crate::system_time::DEFAULT_TIMEZONE {
        let row = client.query_one(&format!("SELECT EXISTS(SELECT 1 FROM analytics_discovery_fact WHERE {scope} AND {} AND first_observed_at IS NULL AND $6::TEXT IS NOT NULL) AS legacy", range.replace("day_start < ($2", "day_start <= ($2")), params).await.map_err(|e|e.to_string())?;
        if row.get::<_, bool>("legacy") {
            return Err("legacy_timezone".into());
        }
    }
    let label = match group {
        "scanner" => "COALESCE(scanner_id, '未分配')".to_owned(),
        "task_source" => "task_source".to_owned(),
        _ => time_group(
            "COALESCE(first_observed_at AT TIME ZONE $6, day_start::TIMESTAMP)",
            group,
        ),
    };
    let row_limit = max_groups + 2;
    let result = client.query(&format!("SELECT {label} AS label, GROUPING({label}) AS is_total, COUNT(DISTINCT ip_address)::BIGINT AS count FROM analytics_discovery_fact WHERE {scope} AND {range} AND $6::TEXT IS NOT NULL GROUP BY GROUPING SETS (({label}),()) ORDER BY is_total DESC, label LIMIT {row_limit}"),params).await.map_err(|e|e.to_string())?;
    if result.len().saturating_sub(1) > max_groups {
        return Err(budget_exceeded(
            kind,
            group,
            "snapshot",
            "groups",
            result.len().saturating_sub(1),
            max_groups,
            f,
        ));
    }
    let mut rows = Vec::new();
    let mut total = 0;
    for row in result {
        if row.get::<_, i32>("is_total") == 1 {
            total = row.get::<_, i64>("count");
        } else {
            rows.push(
                json!({"label":row.get::<_,String>("label"),"count":row.get::<_,i64>("count")}),
            );
        }
    }
    Ok((rows, json!({"unique_ips":total})))
}

fn distribution(items: Vec<(String, i64)>) -> (Vec<Value>, Value) {
    let total: i64 = items.iter().map(|(_, n)| n).sum();
    let categories = items.len();
    let mut items = items;
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    (items.into_iter().map(|(label,count)|json!({"label":label,"count":count,"percentage":if total>0 {(count as f64/total as f64*1000.0).round()/10.0} else {0.0}})).collect(),json!({"count":total,"categories":categories}))
}

#[allow(clippy::too_many_arguments)]
async fn scan_realtime(
    es: &ElasticsearchService,
    f: &AnalysisFilters,
    user: &UserBaseI,
    kind: &str,
    group: &str,
    deadline: Instant,
    processed: &mut usize,
    max_groups: usize,
) -> Result<(Vec<Value>, Value), String> {
    let mut filters = analysis_es_filters(f, user);
    let sources = if kind == "discovery" {
        let group_source = match group {
            "scanner" => json!({"terms":{"field":"scanner_id","missing_bucket":true}}),
            "task_source" => json!({"terms":{"field":"task_source","missing_bucket":true}}),
            _ => {
                json!({"date_histogram":{"field":"observed_at","calendar_interval":match group {"week"=>"1w","month"=>"1M",_=>"1d"},"time_zone":f.timezone}})
            }
        };
        json!([{"label":group_source},{"address":{"terms":{"field":"ip_address"}}}])
    } else {
        if kind == "service" {
            filters.push(json!({"term":{"kind":"service"}}));
            filters.push(json!({"exists":{"field":"service"}}));
        }
        json!([{"label":{"terms":{"field":kind}}},{"endpoint":{"terms":{"field":"endpoint_id"}}}])
    };
    let mut after: Option<Value> = None;
    let mut counts = BTreeMap::<String, i64>::new();
    let mut unique = HashSet::new();

    let tz = f
        .timezone
        .parse::<chrono_tz::Tz>()
        .map_err(|e| e.to_string())?;
    loop {
        let mut composite = json!({"size":1000,"sources":sources});
        if let Some(ref cursor) = after {
            composite["after"] = cursor.clone();
        }
        if *processed >= MAX_ES_BUCKETS {
            return Err(budget_exceeded(
                kind,
                group,
                "realtime",
                "es_buckets",
                *processed,
                MAX_ES_BUCKETS,
                f,
            ));
        }
        let budget = deadline
            .checked_duration_since(Instant::now())
            .ok_or("timeout")?
            .min(StdDuration::from_secs(3));
        let request = json!({"size":0,"track_total_hits":false,"timeout":format!("{}ms",budget.as_millis().saturating_sub(200).max(1)),"query":{"bool":{"filter":filters}},"aggs":{"groups":{"composite":composite}}});
        let result = tokio::time::timeout(
            budget,
            es.scan_query(ScanQueryIndex::Observations, &request),
        )
        .await
        .map_err(|_| "timeout".to_string())??;
        let buckets = result
            .pointer("/aggregations/groups/buckets")
            .and_then(Value::as_array)
            .ok_or("missing aggregation")?;
        *processed += buckets.len();
        if *processed > MAX_ES_BUCKETS {
            return Err(budget_exceeded(
                kind,
                group,
                "realtime",
                "es_buckets",
                *processed,
                MAX_ES_BUCKETS,
                f,
            ));
        }
        for bucket in buckets {
            let key = bucket.get("key").ok_or("missing key")?;
            let label = if kind == "discovery" && matches!(group, "day" | "week" | "month") {
                DateTime::from_timestamp_millis(key["label"].as_i64().ok_or("invalid date bucket")?)
                    .ok_or("invalid timestamp")?
                    .with_timezone(&tz)
                    .format("%Y-%m-%d")
                    .to_string()
            } else {
                key["label"].as_str().map(str::to_owned).unwrap_or_else(|| {
                    if key["label"].is_null() {
                        "未分配".into()
                    } else {
                        key["label"].to_string()
                    }
                })
            };
            if kind == "discovery" {
                unique.insert(
                    key["address"]
                        .as_str()
                        .ok_or("missing IP address")?
                        .to_owned(),
                );
            }
            *counts.entry(label).or_default() += 1;
        }
        if counts.len() > max_groups {
            return Err(budget_exceeded(
                kind,
                group,
                "realtime",
                "groups",
                counts.len(),
                max_groups,
                f,
            ));
        }
        let next = result.pointer("/aggregations/groups/after_key").cloned();
        if buckets.is_empty() || next.is_none() {
            break;
        }
        if next == after {
            return Err("non-advancing aggregation cursor".into());
        }
        after = next;
    }
    if kind == "discovery" {
        Ok((
            counts
                .into_iter()
                .map(|(label, count)| json!({"label":label,"count":count}))
                .collect(),
            json!({"unique_ips":unique.len()}),
        ))
    } else {
        Ok(distribution(counts.into_iter().collect()))
    }
}

fn date_bucket(date: NaiveDate, group: &str) -> NaiveDate {
    match group {
        "week" => date - Duration::days(i64::from(date.weekday().num_days_from_monday())),
        "month" => date - Duration::days(i64::from(date.day() - 1)),
        _ => date,
    }
}

fn fill_dates(rows: &mut Vec<Value>, f: &AnalysisFilters, group: &str, kind: &str) {
    let Ok(tz) = f.timezone.parse::<chrono_tz::Tz>() else {
        return;
    };
    let mut date = f.start_at.with_timezone(&tz).date_naive();
    let last = (f.end_at - Duration::milliseconds(1))
        .with_timezone(&tz)
        .date_naive();
    let mut values: BTreeMap<String, Value> = rows
        .drain(..)
        .filter_map(|r| Some((r["label"].as_str()?.to_owned(), r)))
        .collect();
    while date <= last {
        let key = date_bucket(date, group).to_string();
        values.entry(key.clone()).or_insert_with(||if kind=="discovery" {json!({"label":key,"count":0})} else {let mut r=counts(json!({"created":0,"succeeded":0,"failed":0,"partial":0,"cancelled":0,"avg_duration_ms":null,"p95_ms":null})); r["label"]=json!(key);r});
        let Some(next) = date.succ_opt() else {
            break;
        };
        date = next;
    }
    *rows = values.into_values().collect();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_log_records_limit_and_request_without_filter_values() {
        use std::io::{self, Write};
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::prelude::*;

        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        struct Writer(Arc<Mutex<Vec<u8>>>);
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
            type Writer = Writer;
            fn make_writer(&'a self) -> Writer {
                Writer(self.0.clone())
            }
        }
        impl Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let output = Buffer::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(output.clone())
                .with_current_span(true),
        );
        let _default = tracing::subscriber::set_default(subscriber);
        let span = tracing::info_span!("http_request", request_id = "test-request");
        let _entered = span.enter();
        let start_at = Utc::now();
        let end_at = start_at + Duration::days(1);
        let filters = AnalysisFilters {
            timezone: "UTC".into(),
            start_at,
            end_at,
            start_ms: start_at.timestamp_millis(),
            end_ms: end_at.timestamp_millis(),
            scanner_id: Some("private-scanner".into()),
            task_source: None,
        };
        assert_eq!(
            budget_exceeded(
                "port",
                "port",
                "realtime",
                "es_buckets",
                50_000,
                MAX_ES_BUCKETS,
                &filters
            ),
            "too_large"
        );
        let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        let event: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(event["fields"]["event"], "StatisticsBudgetExceeded");
        assert_eq!(event["fields"]["reason"], "es_buckets");
        assert_eq!(event["fields"]["observed"], 50_000);
        assert_eq!(event["fields"]["limit"], 50_000);
        assert_eq!(event["span"]["request_id"], "test-request");
        assert!(!text.contains("private-scanner"));
    }

    #[actix_web::test]
    async fn statistics_failures_reach_client_with_reason_and_retry_contract() {
        use crate::api_response::ApiErrorMiddleware;
        use actix_web::{App, HttpMessage, HttpRequest, http::StatusCode, test::TestRequest};
        use std::sync::{Arc, Mutex};
        use uuid::Uuid;

        for path in [
            "/api/analysis/statistics/query",
            "/api/analysis/statistics/details",
        ] {
            for code in [
                "statistics_timeout",
                "statistics_budget_exceeded",
                "statistics_snapshot_pending",
                "statistics_config_unavailable",
                "statistics_failed",
            ] {
                let request_id = Uuid::new_v4();
                let reason = Arc::new(Mutex::new(None));
                let slot = crate::request_log::RequestReason(reason.clone());
                let app = actix_web::test::init_service(App::new().wrap(ApiErrorMiddleware).route(
                    path,
                    web::post().to(move |req: HttpRequest| {
                        req.extensions_mut()
                            .insert(crate::audit::RequestId(request_id));
                        req.extensions_mut().insert(slot.clone());
                        std::future::ready(crate::handlers::statistics::error_response(
                            &req,
                            crate::statistics::Failure(code, "password=secret"),
                            "port",
                            Some("port"),
                        ))
                    }),
                ))
                .await;
                let response =
                    actix_web::test::call_service(&app, TestRequest::post().uri(path).to_request())
                        .await;
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(response.headers().get("Retry-After").unwrap(), "5");
                assert_eq!(response.headers().get("Cache-Control").unwrap(), "no-store");
                let value: Value = actix_web::test::read_body_json(response).await;
                assert_eq!(value["code"], code);
                assert_eq!(value["request_id"], request_id.to_string());
                assert_eq!(value["success"], false);
                assert_ne!(value["message"], "服务暂时不可用，请稍后重试");
                assert!(!value.to_string().contains("secret"));
                assert_eq!(reason.lock().unwrap().as_deref(), Some(code));
            }
        }
    }

    #[test]
    fn success_rate_excludes_cancellations_and_empty_denominators() {
        assert_eq!(rate(2, 1, 1), Some(50.0));
        assert_eq!(rate(0, 0, 0), None);
        let r = counts(json!({"succeeded":2,"failed":1,"partial":1,"cancelled":9}));
        assert_eq!(r["completed"], 13);
        assert_eq!(r["success_rate"], 50.0);
    }
    #[test]
    fn catalog_rejects_invalid_sql_dimensions() {
        assert!(!valid_combination("tasks", "scanner"));
        assert!(!valid_combination(
            "discovery",
            "day'); DROP TABLE users;--"
        ));
        assert!(valid_combination("scanners", "week"));
    }
    #[test]
    fn calendar_buckets_cross_years() {
        let d = NaiveDate::from_ymd_opt(2026, 1, 1).expect("date");
        assert_eq!(date_bucket(d, "week").to_string(), "2025-12-29");
        assert_eq!(date_bucket(d, "month").to_string(), "2026-01-01");
    }
    #[test]
    fn distribution_is_sorted_and_preserves_total() {
        let (rows, summary) = distribution(vec![("https".into(), 2), ("ssh".into(), 1)]);
        assert_eq!(summary["count"], 3);
        assert_eq!(rows[0]["percentage"], 66.7);
    }

    #[test]
    fn date_gaps_use_calendar_boundaries_and_null_rates() {
        let f = AnalysisFilters {
            timezone: "America/New_York".into(),
            start_at: "2026-03-08T05:00:00Z".parse().expect("start"),
            end_at: "2026-03-10T04:00:00Z".parse().expect("end"),
            start_ms: 0,
            end_ms: 0,
            scanner_id: None,
            task_source: None,
        };
        let mut rows =
            vec![json!({"label":"2026-03-08","created":1,"completed":0,"success_rate":null})];
        fill_dates(&mut rows, &f, "day", "tasks");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1]["label"], "2026-03-09");
        assert_eq!(rows[1]["completed"], 0);
        assert_eq!(rows[1]["success_rate"], Value::Null);
        assert_eq!(rows[1]["p95_ms"], Value::Null);
    }

    #[tokio::test]
    #[ignore = "requires disposable ANALYTICS_TEST_DATABASE_URL"]
    async fn database_statistics_preserve_scope_distinct_ips_and_execution_metrics() {
        use deadpool_postgres::Manager;
        let config = std::env::var("ANALYTICS_TEST_DATABASE_URL")
            .expect("test database")
            .parse::<tokio_postgres::Config>()
            .expect("config");
        let pool = Pool::builder(Manager::new(config, tokio_postgres::NoTls))
            .max_size(1)
            .build()
            .expect("pool");
        let client = pool.get().await.expect("client");
        client.batch_execute("CREATE TEMP TABLE scan_task(id INT, user_id INT, task_source TEXT, task_create_time BIGINT, task_end_time BIGINT, task_status TEXT);
          CREATE TEMP TABLE scan_task_execution(task_id INT, assigned_scanner_id TEXT, execution_status TEXT, task_start_time BIGINT, task_end_time BIGINT);
          CREATE TEMP TABLE scanner_info(scanner_id TEXT,name TEXT);
          CREATE TEMP TABLE analytics_discovery_fact(day_start DATE,first_observed_at TIMESTAMPTZ,owner_id INT,scanner_id TEXT,task_source TEXT,ip_address INET);
          CREATE TEMP TABLE analytics_distribution_30m(bucket_start TIMESTAMPTZ,owner_id INT,scanner_id TEXT,task_source TEXT,dimension TEXT,label TEXT,endpoint_count BIGINT);
          INSERT INTO scan_task VALUES (1,1,'manual',1788192000000,1788192001000,'succeeded'),(2,1,'manual',1788278400000,1788278401000,'partial'),(3,2,'automatic',1788192000000,1788192001000,'failed'),(4,1,'manual',1788364800000,1788364801000,'cancelled');
          INSERT INTO scanner_info VALUES ('a','同名'),('b','同名');
          INSERT INTO scan_task_execution VALUES (1,'a','succeeded',1788192000000,1788192001000),(1,'b','succeeded',1788192000000,1788192003000),(2,'a','partial',1788278400000,1788278401000),(3,'b','failed',1788192000000,1788192001000);
          INSERT INTO analytics_discovery_fact VALUES ('2026-09-01','2026-09-01T00:00:00Z',1,'a','manual','192.0.2.1'),('2026-09-02','2026-09-02T00:00:00Z',1,'b','manual','192.0.2.1'),('2026-09-02','2026-09-02T00:00:00Z',2,'b','automatic','192.0.2.2');
          INSERT INTO analytics_distribution_30m VALUES ('2026-09-01T00:00:00Z',1,'a','manual','port','443',2),('2026-09-02T00:00:00Z',1,'b','manual','port','443',3),('2026-09-02T00:00:00Z',2,'b','automatic','port','80',9);").await.expect("fixtures");
        let user = UserBaseI {
            id: 1,
            username: "test".into(),
            role: 2,
            email: None,
            limit_login: false,
            enable_2fa: false,
        };
        let mut f = AnalysisFilters {
            timezone: "UTC".into(),
            start_at: "2026-09-01T00:00:00Z".parse().expect("start"),
            end_at: "2026-09-03T00:00:00Z".parse().expect("end"),
            start_ms: 1788192000000,
            end_ms: 1788364800000,
            scanner_id: None,
            task_source: None,
        };
        let (rows, summary) = operations(&client, &f, &user, "tasks", "day", true, 20_000)
            .await
            .expect("tasks");
        assert_eq!(summary["created"], 2);
        assert_eq!(summary["completed"], 2);
        assert_eq!(summary["success_rate"], 50.0);
        assert_eq!(rows.len(), 2);
        let (rows, summary) = operations(&client, &f, &user, "scanners", "scanner", true, 20_000)
            .await
            .expect("scanners");
        assert_eq!(rows.len(), 2, "same scanner names remain separate");
        assert_eq!(summary["completed"], 3);
        assert_eq!(summary["avg_duration_ms"], 2000.0);
        assert_eq!(summary["p95_ms"], 2900.0);
        let (rows, summary) = scan_snapshot(&client, &f, &user, "discovery", "day", 20_000)
            .await
            .expect("IP");
        assert_eq!(summary["unique_ips"], 1);
        assert_eq!(
            rows.iter()
                .map(|r| r["count"].as_i64().expect("count"))
                .sum::<i64>(),
            2
        );
        let (rows, summary) = scan_snapshot(&client, &f, &user, "port", "port", 20_000)
            .await
            .expect("ports");
        assert_eq!(summary["count"], 5);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            scan_snapshot(&client, &f, &user, "port", "port", 1)
                .await
                .unwrap()
                .0
                .len(),
            1
        );
        assert_eq!(
            scan_snapshot(&client, &f, &user, "discovery", "day", 2)
                .await
                .unwrap()
                .0
                .len(),
            2
        );
        assert_eq!(
            scan_snapshot(&client, &f, &user, "discovery", "day", 1)
                .await
                .unwrap_err(),
            "too_large"
        );
        assert_eq!(
            operations(&client, &f, &user, "tasks", "day", false, 2)
                .await
                .unwrap()
                .0
                .len(),
            2
        );
        assert_eq!(
            operations(&client, &f, &user, "tasks", "day", false, 1)
                .await
                .unwrap_err(),
            "too_large"
        );
        let admin_for_budget = UserBaseI {
            role: 1,
            ..user.clone()
        };
        assert_eq!(
            scan_snapshot(&client, &f, &admin_for_budget, "port", "port", 1)
                .await
                .unwrap_err(),
            "too_large"
        );
        assert_eq!(
            scan_snapshot(&client, &f, &admin_for_budget, "port", "port", 2)
                .await
                .unwrap()
                .0
                .len(),
            2
        );
        for group in ["week", "month", "task_source"] {
            operations(&client, &f, &user, "tasks", group, true, 20_000)
                .await
                .expect("task groups");
            operations(&client, &f, &user, "scanners", group, true, 20_000)
                .await
                .expect("scanner groups");
            scan_snapshot(&client, &f, &user, "discovery", group, 20_000)
                .await
                .expect("discovery groups");
        }
        scan_snapshot(&client, &f, &user, "discovery", "scanner", 20_000)
            .await
            .expect("scanner IP");
        f.scanner_id = Some("b".into());
        f.task_source = Some("manual".into());
        let (_, summary) = operations(&client, &f, &user, "tasks", "day", true, 20_000)
            .await
            .expect("filter tasks");
        assert_eq!(
            summary["created"], 1,
            "EXISTS does not duplicate multi-scanner tasks"
        );
        let (_, summary) = operations(&client, &f, &user, "scanners", "day", true, 20_000)
            .await
            .expect("filter scanner");
        assert_eq!(summary["completed"], 1);
        let (_, summary) = scan_snapshot(&client, &f, &user, "port", "port", 20_000)
            .await
            .expect("filter ports");
        assert_eq!(summary["count"], 3);
        let admin = UserBaseI { role: 1, ..user };
        f.scanner_id = None;
        f.task_source = None;
        let (_, summary) = operations(&client, &f, &admin, "tasks", "task_source", true, 20_000)
            .await
            .expect("admin");
        assert_eq!(summary["failed"], 1);
        client.batch_execute("INSERT INTO analytics_discovery_fact VALUES ('2026-09-02',NULL,9,'c','manual','192.0.2.9')").await.expect("legacy");
        assert_eq!(
            scan_snapshot(&client, &f, &admin, "discovery", "day", 20_000)
                .await
                .expect_err("legacy rejected"),
            "legacy_timezone"
        );
        // Another owner's legacy facts cannot block a scoped user.
        scan_snapshot(
            &client,
            &f,
            &UserBaseI { role: 2, ..admin },
            "discovery",
            "day",
            20_000,
        )
        .await
        .expect("scoped legacy");
    }
}
