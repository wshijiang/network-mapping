//! On-demand, keyset-paginated evidence behind statistics. Never count all rows.
use super::data_saa::{AnalysisFilterQuery, analysis_es_filters, normalize_filters};
use crate::{
    admin::UserBaseI,
    config::AnalyticsSnapshotConfig,
    elasticsearch::{ElasticsearchService, ScanQueryIndex},
    runtime_config::RuntimeConfig,
    statistics::{ClusterSlot, Failure, StatisticsService},
};
use actix_web::{HttpResponse, post, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct DetailsQuery {
    #[serde(flatten)]
    filters: AnalysisFilterQuery,
    data_type: String,
    timezone: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    after: Option<Value>,
    #[serde(default = "page_size")]
    page_size: i64,
}
fn page_size() -> i64 {
    50
}
fn failed() -> Failure {
    Failure("statistics_failed", "统计明细暂不可用")
}

#[post("/api/analysis/statistics/details")]
pub(crate) async fn details(
    req: actix_web::HttpRequest,
    body: web::Json<DetailsQuery>,
    pool: web::Data<Pool>,
    es: web::Data<ElasticsearchService>,
    config: web::Data<RuntimeConfig<AnalyticsSnapshotConfig>>,
    service: web::Data<StatisticsService>,
    user: UserBaseI,
) -> HttpResponse {
    let body = body.into_inner();
    if !matches!(
        body.data_type.as_str(),
        "discovery" | "port" | "service" | "tasks" | "scanners"
    ) || !(1..=100).contains(&body.page_size)
        || body
            .category
            .as_ref()
            .is_some_and(|c| c.is_empty() || c.len() > 256)
        || body
            .after
            .as_ref()
            .is_some_and(|c| c.to_string().len() > 1024)
    {
        return HttpResponse::BadRequest().json(json!({"success":false,"message":"明细参数无效"}));
    }
    let f = match normalize_filters(&body.filters) {
        Ok(f) => f,
        Err(e) => return HttpResponse::BadRequest().json(json!({"success":false,"message":e})),
    };
    if body.timezone != f.timezone {
        return HttpResponse::Conflict()
            .json(json!({"success":false,"message":"系统时区已改变，请重新生成统计"}));
    }
    if let Err(error) = service.refresh(&pool).await {
        tracing::warn!(event = "StatisticsConfigurationReadFailed", request_id = %crate::logs::write::request_id(&req), error_message = %error);
        return super::statistics::error_response(
            &req,
            Failure("statistics_config_unavailable", "统计配置暂不可用"),
            &body.data_type,
            None,
        );
    }
    let mode = config.get().await;
    let scan = matches!(body.data_type.as_str(), "discovery" | "port" | "service");
    let snapshot = scan && mode.value.mode.reads_snapshot();
    let data_mode = if snapshot {
        "snapshot"
    } else if scan {
        "realtime"
    } else {
        "retained_history"
    };
    if body.mode.as_ref().is_some_and(|mode| mode != data_mode) {
        return HttpResponse::Conflict()
            .json(json!({"success":false,"message":"统计数据源已改变，请重新生成统计"}));
    }
    let key=json!({"details":body,"user":user.id,"role":user.role,"mode":data_mode,"mode_revision":mode.revision,"start":f.start_at,"end":f.end_at}).to_string();
    let data_type = body.data_type.clone();
    let result=service.execute(key,user.id,data_mode.into(),move |deadline|async move {
        let mut slot=ClusterSlot::acquire(&pool).await?;
        let output=async {
            let mut rows=Vec::new();
            let mut cursors=Vec::new();
            if scan && !snapshot {
                let mut filters=analysis_es_filters(&f,&user);
                if body.data_type=="port" {
                    if let Some(c)=&body.category {let port=c.parse::<u16>().map_err(|_|failed())?;filters.push(json!({"term":{"port":port}}));}
                } else if body.data_type=="service" {
                    filters.push(json!({"term":{"kind":"service"}}));
                    if let Some(c)=&body.category {filters.push(json!({"term":{"service":c}}));}
                }
                let mut request=json!({"size":body.page_size+1,"track_total_hits":false,"timeout":"2s","_source":["ip_address","port","service","observed_at","execution_id","task_id","scanner_id","task_source"],"query":{"bool":{"filter":filters}},"sort":[{"observed_at":{"order":"asc","format":"epoch_millis"}},{"observation_key":"asc"}]});
                if let Some(after)=&body.after {
                    if !after.as_array().is_some_and(|a|a.len()==2 && (a[0].is_i64()||a[0].is_string()) && a[1].is_string()) {return Err(failed());}
                    request["search_after"]=after.clone();
                }
                let remaining=deadline.checked_duration_since(std::time::Instant::now()).ok_or_else(Failure::timeout)?.min(std::time::Duration::from_secs(3));
                let response=tokio::time::timeout(remaining,es.scan_query(ScanQueryIndex::Observations,&request)).await.map_err(|_|Failure::timeout())?.map_err(|_|failed())?;
                for hit in response.pointer("/hits/hits").and_then(Value::as_array).ok_or_else(failed)? {
                    rows.push(hit["_source"].clone());cursors.push(hit["sort"].clone());
                }
            } else {
                let client=slot.client()?;
                let tx=client.build_transaction().read_only(true).start().await.map_err(|_|failed())?;
                let calculation=async {
                    let milliseconds=deadline.checked_duration_since(std::time::Instant::now()).ok_or_else(Failure::timeout)?.as_millis().clamp(1,8000);
                    tx.batch_execute(&format!("SET LOCAL statement_timeout='{milliseconds}ms'; SET LOCAL lock_timeout='500ms'; SET LOCAL max_parallel_workers_per_gather=0")).await.map_err(|_|failed())?;
                    let owner=(user.role!=1).then_some(user.id);
                    let limit=body.page_size+1;
                    if !scan {
                        let after=body.after.as_ref().map(|v|v.as_i64().filter(|v|*v>=0 && *v<=i32::MAX as i64).ok_or_else(failed)).transpose()?.unwrap_or(0) as i32;
                        let sql=if body.data_type=="tasks" {
                            "SELECT t.id, jsonb_build_object('task_id',t.task_id,'status',t.task_status,'task_source',t.task_source,'created_at',t.task_create_time,'ended_at',t.task_end_time,'created_in_period',t.task_create_time >= $1 AND t.task_create_time < $2,'completed_in_period',t.task_end_time >= $1 AND t.task_end_time < $2 AND t.task_status IN ('succeeded','failed','partial','cancelled')) AS item FROM scan_task t WHERE ($3::INT IS NULL OR t.user_id=$3) AND ($4::TEXT IS NULL OR EXISTS(SELECT 1 FROM scan_task_execution e WHERE e.task_id=t.id AND e.assigned_scanner_id=$4)) AND ($5::TEXT IS NULL OR t.task_source=$5) AND ((t.task_create_time >= $1 AND t.task_create_time < $2) OR (t.task_end_time >= $1 AND t.task_end_time < $2 AND t.task_status IN ('succeeded','failed','partial','cancelled'))) AND t.id>$6 ORDER BY t.id LIMIT $7"
                        } else {
                            "SELECT e.id, jsonb_build_object('task_id',t.task_id,'execution_id',e.execution_id,'scanner_id',e.assigned_scanner_id,'status',e.execution_status,'task_source',t.task_source,'started_at',e.task_start_time,'ended_at',e.task_end_time) AS item FROM scan_task_execution e JOIN scan_task t ON t.id=e.task_id WHERE ($3::INT IS NULL OR t.user_id=$3) AND ($4::TEXT IS NULL OR e.assigned_scanner_id=$4) AND ($5::TEXT IS NULL OR t.task_source=$5) AND e.task_end_time >= $1 AND e.task_end_time < $2 AND e.execution_status IN ('succeeded','failed','partial','cancelled') AND e.id>$6 ORDER BY e.id LIMIT $7"
                        };
                        let result=tx.query(sql,&[&f.start_ms,&f.end_ms,&owner,&f.scanner_id,&f.task_source,&after,&limit]).await.map_err(|_|failed())?;
                        for row in result {rows.push(row.get("item"));cursors.push(json!(row.get::<_,i32>("id")));}
                    } else {
                        // Snapshot rows are retained facts, not a live asset inventory.
                        let after_id=body.after.as_ref().map(|v|v[0].as_i64().filter(|v|*v>=0 && *v<=i32::MAX as i64).ok_or_else(failed)).transpose()?.unwrap_or(0) as i32;
                        let after_at=body.after.as_ref().map(|v|v[1].as_str().ok_or_else(failed)).transpose()?.unwrap_or("1970-01-01T00:00:00Z");
                        let after_time=after_at.parse::<DateTime<Utc>>().map_err(|_|failed())?;
                        let after_value=body.after.as_ref().map(|v|v[2].as_str().ok_or_else(failed)).transpose()?.unwrap_or("");
                        let discovery=body.data_type=="discovery";
                        let (table,time,value,range,extra)=if discovery {
                            ("analytics_discovery_fact","f.day_start::TIMESTAMP AT TIME ZONE 'UTC'","host(f.ip_address)","((f.first_observed_at >= $1 AND f.first_observed_at < $2) OR (f.first_observed_at IS NULL AND f.day_start >= ($1 AT TIME ZONE 'Asia/Shanghai')::DATE AND f.day_start < ($2 AT TIME ZONE 'Asia/Shanghai')::DATE))","'ip_address',host(f.ip_address),'observed_at',f.first_observed_at")
                        } else {
                            ("analytics_distribution_30m","f.bucket_start","f.label","f.bucket_start >= $1 AND f.bucket_start < $2","'category',f.label,'count',f.endpoint_count,'observed_at',f.bucket_start")
                        };
                        if discovery && f.timezone != crate::system_time::DEFAULT_TIMEZONE {
                            let legacy=tx.query_one("SELECT EXISTS(SELECT 1 FROM analytics_discovery_fact f WHERE f.first_observed_at IS NULL AND f.day_start >= ($1::TIMESTAMPTZ AT TIME ZONE 'Asia/Shanghai')::DATE AND f.day_start <= ($2::TIMESTAMPTZ AT TIME ZONE 'Asia/Shanghai')::DATE AND ($3::INT IS NULL OR f.owner_id=$3) AND ($4::TEXT IS NULL OR f.scanner_id=$4) AND ($5::TEXT IS NULL OR f.task_source=$5))", &[&f.start_at,&f.end_at,&owner,&f.scanner_id,&f.task_source]).await.map_err(|_|failed())?;
                            if legacy.get::<_,bool>(0) {return Err(Failure("statistics_failed","旧快照无法换算时区，请联系管理员重建"));}
                        }
                        let dimension=if discovery {"$10::TEXT='discovery' AND $11::TEXT IS NULL"} else {"f.dimension=$10 AND ($11::TEXT IS NULL OR f.label=$11)"};
                        let sql=format!("SELECT f.execution_id, {time} AS at, {value} AS label, jsonb_build_object('execution_id',e.execution_id,'task_id',t.task_id,'scanner_id',f.scanner_id,'task_source',f.task_source,{extra}) AS item FROM {table} f JOIN scan_task_execution e ON e.id=f.execution_id JOIN scan_task t ON t.id=e.task_id WHERE {range} AND ($3::INT IS NULL OR f.owner_id=$3) AND ($4::TEXT IS NULL OR f.scanner_id=$4) AND ($5::TEXT IS NULL OR f.task_source=$5) AND (f.execution_id,{time},{value}) > ($6,$7,$8) AND {dimension} ORDER BY f.execution_id,{time},{value} LIMIT $9");
                        let result=tx.query(&sql,&[&f.start_at,&f.end_at,&owner,&f.scanner_id,&f.task_source,&after_id,&after_time,&after_value,&limit,&body.data_type,&body.category]).await.map_err(|error|{tracing::warn!(%error,"StatisticsDetailsFailed");failed()})?;
                        for row in result {rows.push(row.get("item"));cursors.push(json!([row.get::<_,i32>("execution_id"),row.get::<_,DateTime<Utc>>("at"),row.get::<_,String>("label")]));}
                    }
                    Ok::<_,Failure>(())
                }.await;
                tx.rollback().await.map_err(|_|failed())?;
                calculation?;
            }
            let more=rows.len()>body.page_size as usize;
            rows.truncate(body.page_size as usize);
            let next=if more {cursors.get(rows.len().saturating_sub(1)).cloned()} else {None};
            Ok(json!({"success":true,"data":{"rows":rows,"next_cursor":next,"has_more":more},"meta":{"mode":data_mode,"note":if snapshot {"明细为保留的快照事实；IP 可能在不同执行中重复出现。"} else if scan {"明细为保留的原始观测，可能重复且会随索引更新；不等于去重汇总条数。"} else {"任务按创建或结束时间入选；执行按结束时间入选。"}}}))
        }.await;
        slot.release().await?;
        output
    }).await;
    match result {
        Ok((bytes, cache)) => HttpResponse::Ok()
            .insert_header(("X-Statistics-Cache", cache))
            .content_type("application/json; charset=utf-8")
            .body(bytes),
        Err(error) => super::statistics::error_response(&req, error, &data_type, None),
    }
}
