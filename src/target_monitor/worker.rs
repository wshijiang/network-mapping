//! 目标监控调度：租约清扫 → 到期规则派发扫描任务 → 终态 diff 收尾 → 事件与清理。
use crate::elasticsearch::{ElasticsearchService, ScanQueryIndex};
use crate::maxmind::MaxMindState;
use crate::system_maintenance::SystemMaintenanceState;
use chrono::Utc;
use deadpool_postgres::Pool;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::sync::watch;
use uuid::Uuid;

use super::diff::{self, Change, DnsSnapshot, IpSnapshot, MAX_EVENT_CHANGES, MAX_RUN_CHANGES};

type Error = Box<dyn std::error::Error + Send + Sync>;

pub(crate) async fn run(
    pool: Pool,
    elasticsearch: ElasticsearchService,
    maxmind: actix_web::web::Data<MaxMindState>,
    maintenance: actix_web::web::Data<SystemMaintenanceState>,
    mut stopping: watch::Receiver<bool>,
) {
    loop {
        if *stopping.borrow() {
            return;
        }
        if !maintenance.snapshot().await.enabled
            && let Err(error) = tick(&pool, &elasticsearch, &maxmind).await
        {
            tracing::warn!(event="TargetMonitorTickFailed", error_message=%error, "目标监控调度周期失败");
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(60)) => {},
            _ = stopping.changed() => {},
        }
    }
}

pub(super) async fn tick(
    pool: &Pool,
    elasticsearch: &ElasticsearchService,
    maxmind: &MaxMindState,
) -> Result<(), Error> {
    crate::scan_control::dispatch::sweep_expired_leases(pool).await?;
    dispatch_due(pool, maxmind).await?;
    finalize_runs(pool, elasticsearch).await?;
    cleanup(pool).await?;
    Ok(())
}

struct DueRule {
    rule_id: Uuid,
    run_id: Uuid,
    name: String,
    owner_id: i32,
    owner_name: String,
    owner_role: i32,
    target_type: String,
    targets: Vec<String>,
    ports: String,
    profile: String,
}

pub(super) async fn dispatch_due(pool: &Pool, maxmind: &MaxMindState) -> Result<(), Error> {
    let due: Vec<DueRule> = {
        let mut conn = pool.get().await?;
        let tx = conn.transaction().await?;
        let rows = tx.query(
            "SELECT r.*, u.username, u.role FROM target_monitor_rule r JOIN users u ON u.id=r.created_by \
             WHERE r.enabled AND r.deleted_at IS NULL AND r.next_run_at<=NOW() \
             AND u.deleted_at IS NULL AND u.disabled_at IS NULL AND NOT u.limit_login \
             AND (u.role=1 OR (u.role=2 AND u.access_policy IS NULL)) \
             AND NOT EXISTS(SELECT 1 FROM target_monitor_run run WHERE run.rule_id=r.id AND run.status IN ('pending','running')) \
             ORDER BY r.next_run_at LIMIT 8 FOR UPDATE OF r SKIP LOCKED",
            &[],
        ).await?;
        let mut due = Vec::new();
        for row in rows {
            let rule_id: Uuid = row.get("id");
            let interval: i64 = row.get::<_, i32>("interval_seconds") as i64;
            // 先推进调度时间，任务创建失败不会卡住后续周期。
            tx.execute(
                "UPDATE target_monitor_rule SET next_run_at=NOW()+$2::BIGINT*INTERVAL '1 second' WHERE id=$1",
                &[&rule_id, &interval],
            ).await?;
            let run_id = Uuid::now_v7();
            // 冻结本次派发时的规则配置：运行期间编辑规则不改变收尾所用的
            // 目标类型与基线，避免拿新目标 diff 旧任务的结果。
            tx.execute(
                "INSERT INTO target_monitor_run(id,rule_id,status,started_at,target_type,targets,baseline) VALUES($1,$2,'pending',NOW(),$3,$4,$5)",
                &[&run_id, &rule_id, &row.get::<_, String>("target_type"), &row.get::<_, Vec<String>>("targets"), &row.get::<_, Option<Value>>("baseline")],
            ).await?;
            due.push(DueRule {
                rule_id,
                run_id,
                name: row.get("name"),
                owner_id: row.get("created_by"),
                owner_name: row.get("username"),
                owner_role: row.get("role"),
                target_type: row.get("target_type"),
                targets: row.get("targets"),
                ports: row.get("ports"),
                profile: row.get("scan_profile"),
            });
        }
        tx.commit().await?;
        due
    };
    for rule in due {
        match create_monitor_task(pool, maxmind, &rule).await {
            Ok(task_id) => {
                let metadata =
                    json!({"target_monitor": {"rule_id": rule.rule_id, "run_id": rule.run_id}});
                let conn = pool.get().await?;
                conn.execute(
                    "UPDATE scan_task SET task_source='monitor', generation_metadata=$2 WHERE task_id=$1",
                    &[&task_id, &metadata],
                ).await?;
                conn.execute(
                    "UPDATE target_monitor_run SET task_id=$2,status='running' WHERE id=$1",
                    &[&rule.run_id, &task_id],
                )
                .await?;
            }
            Err(reason) => {
                let conn = pool.get().await?;
                conn.execute(
                    "UPDATE target_monitor_run SET status='skipped',skip_reason=$2,finished_at=NOW() WHERE id=$1",
                    &[&rule.run_id, &reason],
                ).await?;
                notify_skip(pool, &rule, reason).await?;
            }
        }
    }
    Ok(())
}

async fn create_monitor_task(
    pool: &Pool,
    maxmind: &MaxMindState,
    rule: &DueRule,
) -> Result<String, &'static str> {
    let capable: bool = pool.get().await.map_err(|_| "database_unavailable")?.query_one(
        "SELECT EXISTS(SELECT 1 FROM scanner_info WHERE is_enable AND deleted_at IS NULL AND scan_capabilities->'profiles' ? $1)",
        &[&rule.profile],
    ).await.map_err(|_| "database_unavailable")?.get(0);
    if !capable {
        return Err("no_scanner");
    }
    let remark = format!("目标监控：{}", rule.name);
    if rule.target_type == "domain" {
        let plan = crate::scan_control::creation::build_scan_plan("dns_records")
            .map_err(|_| "invalid_plan")?;
        let task_id = Uuid::now_v7().to_string();
        let metadata = json!({"target_monitor": {"rule_id": rule.rule_id, "run_id": rule.run_id}});
        let mut conn = pool.get().await.map_err(|_| "database_unavailable")?;
        let tx = conn
            .transaction()
            .await
            .map_err(|_| "database_unavailable")?;
        crate::access::ensure_scan_authorized(&tx, rule.owner_id, None)
            .await
            .map_err(|error| match error {
                crate::access::UpdateError::Forbidden => "authorization_changed",
                _ => "database_unavailable",
            })?;
        let db_id: i32 = tx.query_one(
            "INSERT INTO scan_task(user_id,task_id,task_initiator,task_target,task_port,task_level,remarks,dispatch_mode,address_family,scan_profile,scan_plan,task_kind,dns_targets,dns_resolvers,generation_metadata,task_source) \
             VALUES($1,$2,$3,ARRAY[]::INET[],'53',1,$4,'automatic','ipv4','dns_records',$5,'dns',$6,'[]'::JSONB,$7,'monitor') RETURNING id",
            &[&rule.owner_id,&task_id,&rule.owner_name,&remark,&plan,&rule.targets,&metadata],
        ).await.map_err(|_| "database_unavailable")?.get(0);
        tx.execute(
            "INSERT INTO scan_task_execution(execution_id,task_id,requested_scanner_id) VALUES($1,$2,NULL)",
            &[&Uuid::now_v7().to_string(), &db_id],
        ).await.map_err(|_| "database_unavailable")?;
        tx.commit().await.map_err(|_| "database_unavailable")?;
        return Ok(task_id);
    }
    let task = crate::scan_control::creation::STask::new(
        crate::scan_control::target::TargetIP::S(&rule.targets.join(",")),
        &rule.owner_name,
        Some(&rule.ports),
        Some(&remark),
    )
    .map_err(|_| "invalid_targets")?;
    let plan = crate::scan_control::creation::build_scan_plan(&rule.profile)
        .map_err(|_| "invalid_plan")?;
    let actor = crate::admin::UserBaseI {
        id: rule.owner_id,
        username: rule.owner_name.clone(),
        role: rule.owner_role,
        email: None,
        limit_login: false,
        enable_2fa: false,
    };
    let created = task
        .add(
            pool,
            1,
            rule.owner_id,
            "manual",
            &[None],
            &rule.profile,
            &plan,
            None,
            &crate::audit::AuditContext::cli("target-monitor"),
            &actor,
            maxmind,
        )
        .await
        .map_err(|error| {
            if matches!(
                error.downcast_ref::<crate::access::UpdateError>(),
                Some(crate::access::UpdateError::Forbidden)
            ) {
                "authorization_changed"
            } else {
                "create_failed"
            }
        })?;
    created.task_ids.into_iter().next().ok_or("create_failed")
}

async fn notify_skip(pool: &Pool, rule: &DueRule, reason: &str) -> Result<(), Error> {
    let mut conn = pool.get().await?;
    let tx = conn.transaction().await?;
    let hour_bucket = Utc::now().timestamp() / 3600;
    crate::notification::enqueue_inbox_only(
        &tx,
        "monitor.change",
        "warning",
        &format!("monitor-skip:{}:{hour_bucket}", rule.rule_id),
        "监控规则跳过：无可用扫描器",
        &format!(
            "规则：{}\n原因：{reason}\n请启用支持该扫描模式的扫描器后等待下一周期。",
            rule.name
        ),
        None,
        json!({"rule_id": rule.rule_id, "run_id": rule.run_id, "recipient_ids": [rule.owner_id]}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

fn kind_label(kind: &str) -> &'static str {
    match kind {
        "port_opened" => "端口开放",
        "port_closed" => "端口关闭",
        "service_changed" => "服务变化",
        "title_changed" => "标题变化",
        "cert_changed" => "证书变化",
        "cert_expiring" => "证书即将到期",
        "target_down" => "目标离线",
        "target_up" => "目标恢复",
        "dns_changed" => "解析变化",
        _ => "变化",
    }
}

fn severity_max<'a>(changes: &[&'a Change]) -> &'static str {
    if changes.iter().any(|c| c.severity == "critical") {
        "critical"
    } else if changes.iter().any(|c| c.severity == "warning") {
        "warning"
    } else {
        "info"
    }
}

fn change_mail_row(change: &Change) -> Value {
    json!({
        "kind": change.kind,
        "kind_label": kind_label(change.kind),
        "severity": change.severity,
        "target": change.target,
        "port": change.port,
        "detail": change.detail,
    })
}

/// 只读取本监控任务自身执行产出的端点投影：按 task_id 过滤执行端点索引，
/// 并按 endpoint_key 折叠取最新观测。共享的 CurrentEndpoints 会被并发扫描
/// 更新，不能用来判断本次监控实际观测到了什么。
async fn ip_snapshot(
    elasticsearch: &ElasticsearchService,
    task_id: &str,
) -> Result<(IpSnapshot, bool), String> {
    let body = json!({
        "size": diff::MAX_SNAPSHOT_PORTS + 1,
        "_source": false,
        "query": {"term": {"task_id": task_id}},
        "collapse": {
            "field": "endpoint_key",
            "inner_hits": {
                "name": "latest",
                "size": 1,
                "sort": [{"observed_at_ms": "desc"}],
                "_source": ["ip", "port", "service", "product", "version", "title", "tls_fingerprint_sha256", "tls_not_after"]
            }
        },
        "sort": [{"endpoint_key": "asc"}]
    });
    let hits = elasticsearch
        .scan_query(ScanQueryIndex::ExecutionEndpoints, &body)
        .await?;
    Ok((
        diff::snapshot_from_collapsed_hits(&hits),
        diff::hits_exceed_capacity(&hits),
    ))
}

struct Finalized {
    snapshot: Value,
    changes: Vec<Change>,
    snapshot_truncated: bool,
}

async fn observe(
    elasticsearch: &ElasticsearchService,
    row: &tokio_postgres::Row,
) -> Result<Finalized, String> {
    let target_type: String = row.get("target_type");
    let baseline: Option<Value> = row.get("baseline");
    let now_ms = Utc::now().timestamp_millis();
    let task_id: String = row.get("task_id");
    elasticsearch
        .refresh_monitor_source(target_type == "domain")
        .await?;
    if target_type == "domain" {
        let hits = elasticsearch.dns_task_observations(&task_id).await?;
        let current = diff::dns_snapshot_from_hits(&hits);
        let previous: Option<DnsSnapshot> = baseline
            .as_ref()
            .filter(|value| value["kind"] == "dns")
            .and_then(|value| serde_json::from_value(value["data"].clone()).ok());
        let changes = diff::diff_dns(previous.as_ref(), &current);
        return Ok(Finalized {
            snapshot: json!({"kind": "dns", "data": current}),
            changes,
            snapshot_truncated: false,
        });
    }
    let (current, truncated) = ip_snapshot(elasticsearch, &task_id).await?;
    let previous: Option<IpSnapshot> = baseline
        .as_ref()
        .filter(|value| value["kind"] == "ip")
        .and_then(|value| serde_json::from_value(value["data"].clone()).ok());
    // 此前基线若也是截断快照，同样只能做部分 diff，直到一次完整快照重建基线。
    let previous_truncated = baseline
        .as_ref()
        .is_some_and(|value| value["truncated"].as_bool() == Some(true));
    let changes = if truncated || previous_truncated {
        diff::diff_ip_partial(previous.as_ref(), &current, now_ms)
    } else {
        diff::diff_ip(previous.as_ref(), &current, now_ms)
    };
    Ok(Finalized {
        snapshot: json!({"kind": "ip", "data": current, "truncated": truncated}),
        changes,
        snapshot_truncated: truncated,
    })
}

pub(super) async fn finalize_runs(
    pool: &Pool,
    elasticsearch: &ElasticsearchService,
) -> Result<(), Error> {
    // 逐条 FOR UPDATE SKIP LOCKED 认领：多实例不会重复收尾同一运行（变化行重复插入）。
    // 行锁覆盖 ES 观测与收尾事务；观测耗时受 ES 请求超时约束，其他实例跳过被锁行。
    for _ in 0..64 {
        let mut conn = pool.get().await?;
        let tx = conn.transaction().await?;
        let row = tx.query_opt(
            "SELECT run.id AS run_id, run.rule_id, run.task_id, \
             COALESCE(run.target_type, r.target_type) AS target_type, \
             COALESCE(run.baseline, r.baseline) AS baseline, \
             r.name AS rule_name, r.created_by, r.recipient_ids, t.task_status \
             FROM target_monitor_run run JOIN target_monitor_rule r ON r.id=run.rule_id \
             JOIN scan_task t ON t.task_id=run.task_id \
             WHERE run.status IN ('pending','running') AND t.task_status IN ('succeeded','partial','failed','cancelled') \
             ORDER BY run.id LIMIT 1 FOR UPDATE OF run SKIP LOCKED",
            &[],
        ).await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(());
        };
        let run_id: Uuid = row.get("run_id");
        let task_status: String = row.get("task_status");
        if task_status == "failed" || task_status == "cancelled" {
            tx.execute(
                "UPDATE target_monitor_run SET status=$2,finished_at=NOW() WHERE id=$1",
                &[&run_id, &task_status],
            )
            .await?;
            tx.commit().await?;
            continue;
        }
        let finalized = match observe(elasticsearch, &row).await {
            Ok(finalized) => finalized,
            Err(message) => {
                tracing::warn!(event="TargetMonitorObserveUnavailable", run_id=%run_id, error_message=%message, "目标监控观测降级，保留基线");
                tx.execute(
                    "UPDATE target_monitor_run SET status='succeeded',skip_reason='es_unavailable',finished_at=NOW() WHERE id=$1",
                    &[&run_id],
                ).await?;
                tx.commit().await?;
                continue;
            }
        };
        finalize_one(&tx, &row, finalized).await?;
        tx.commit().await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn emit_monitor_event(
    tx: &deadpool_postgres::Transaction<'_>,
    event_type: &'static str,
    dedup: String,
    title: String,
    group: Vec<&Change>,
    base_context: &Value,
    rule_name: &str,
    detail_path: &str,
) -> std::result::Result<(), tokio_postgres::Error> {
    let severity = severity_max(&group);
    let mail_rows: Vec<Value> = group
        .iter()
        .take(MAX_EVENT_CHANGES)
        .map(|c| change_mail_row(c))
        .collect();
    let summary = group
        .iter()
        .take(5)
        .map(|c| {
            format!(
                "{} {}:{}",
                kind_label(c.kind),
                c.target,
                c.port.map(|p| p.to_string()).unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut context = base_context.clone();
    context["changes"] = json!(mail_rows);
    context["change_count"] = json!(group.len());
    context["mail_template"] = json!(crate::mail_template::MONITOR_ALERT_TEMPLATE_KEY);
    context["mail_context"] = json!({
        "system_name": "Network Mapping",
        "rule_name": rule_name,
        "event_label": kind_label(group[0].kind),
        "severity": severity,
        "change_count": group.len(),
        "changes": mail_rows,
        "occurred_at": crate::system_time::format_now(),
        "detail_path": detail_path,
    });
    let body = format!("规则：{rule_name}\n变化数：{}\n{summary}", group.len());
    crate::notification::enqueue_with_context(
        tx, event_type, severity, &dedup, &title, &body, None, context,
    )
    .await
}

async fn finalize_one(
    tx: &deadpool_postgres::Transaction<'_>,
    row: &tokio_postgres::Row,
    finalized: Finalized,
) -> Result<(), Error> {
    let run_id: Uuid = row.get("run_id");
    let rule_id: Uuid = row.get("rule_id");
    let rule_name: String = row.get("rule_name");
    let created_by: i32 = row.get("created_by");
    let recipient_ids: Vec<i32> = row.get("recipient_ids");
    let recipients = if recipient_ids.is_empty() {
        vec![created_by]
    } else {
        recipient_ids
    };
    let total = finalized.changes.len();
    let mut changes = finalized.changes;
    let snapshot_truncated = finalized.snapshot_truncated;
    let truncated = snapshot_truncated || total > MAX_RUN_CHANGES;
    changes.truncate(MAX_RUN_CHANGES);
    if snapshot_truncated {
        tracing::warn!(
            event = "TargetMonitorSnapshotTruncated",
            run_id = %run_id,
            rule_id = %rule_id,
            "目标监控快照超过端点上限，本次只按已观测端点做部分比对"
        );
    }

    for change in &changes {
        tx.execute(
            "INSERT INTO target_monitor_change(id,run_id,rule_id,kind,severity,target,port,detail) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            &[&Uuid::now_v7(),&run_id,&rule_id,&change.kind,&change.severity,&change.target,&change.port.map(i32::from),&change.detail],
        ).await?;
    }
    let notify_enabled: bool = tx.query_opt(
        "SELECT value::boolean FROM setting WHERE item_type='notification' AND key='monitor_notify_enabled'",
        &[],
    ).await?.map(|r| r.get::<_, bool>(0)).unwrap_or(true);
    if notify_enabled && !changes.is_empty() {
        let detail_path = format!("/monitor?run={run_id}");
        let base_context = json!({
            "rule_id": rule_id, "rule_name": rule_name, "run_id": run_id, "recipient_ids": recipients,
        });

        let availability: Vec<&Change> = changes
            .iter()
            .filter(|c| matches!(c.kind, "target_down" | "target_up"))
            .collect();
        if !availability.is_empty() {
            let down = availability.iter().any(|c| c.kind == "target_down");
            let title = if down {
                format!("目标离线：{rule_name}")
            } else {
                format!("目标恢复：{rule_name}")
            };
            emit_monitor_event(
                &tx,
                "monitor.availability",
                format!("monitor:{run_id}:availability"),
                title,
                availability,
                &base_context,
                &rule_name,
                &detail_path,
            )
            .await?;
        }
        let certs: Vec<&Change> = changes
            .iter()
            .filter(|c| c.kind == "cert_expiring")
            .collect();
        for cert in certs {
            let bucket = cert.detail["bucket"].as_str().unwrap_or("14d");
            let not_after = cert.detail["not_after"].as_i64().unwrap_or(0);
            let dedup = format!(
                "monitor-cert:{rule_id}:{}:{}:{not_after}:{bucket}",
                cert.target,
                cert.port.unwrap_or(0)
            );
            let title = format!("证书即将到期：{}:{}", cert.target, cert.port.unwrap_or(0));
            emit_monitor_event(
                &tx,
                "monitor.cert_expiring",
                dedup,
                title,
                vec![cert],
                &base_context,
                &rule_name,
                &detail_path,
            )
            .await?;
        }
        let other: Vec<&Change> = changes
            .iter()
            .filter(|c| !matches!(c.kind, "target_down" | "target_up" | "cert_expiring"))
            .collect();
        if !other.is_empty() {
            let title = format!("目标监控变化：{rule_name}");
            emit_monitor_event(
                &tx,
                "monitor.change",
                format!("monitor:{run_id}:change"),
                title,
                other,
                &base_context,
                &rule_name,
                &detail_path,
            )
            .await?;
        }
    }
    let summary =
        json!({"truncated": truncated, "total": total, "snapshot_truncated": snapshot_truncated});
    tx.execute(
        "UPDATE target_monitor_run SET status='succeeded',finished_at=NOW(),snapshot=$2,change_count=$3,summary=$4 WHERE id=$1",
        &[&run_id, &finalized.snapshot, &(total as i32), &summary],
    ).await?;
    tx.execute(
        "UPDATE target_monitor_rule SET baseline=$2,last_run_at=NOW() WHERE id=$1",
        &[&rule_id, &finalized.snapshot],
    )
    .await?;
    Ok(())
}

pub(super) async fn cleanup(pool: &Pool) -> Result<(), Error> {
    let conn = pool.get().await?;
    conn.execute(
        "DELETE FROM target_monitor_run WHERE finished_at<NOW()-INTERVAL '180 days'",
        &[],
    )
    .await?;
    // 任务被删除或长期无进展的运行标记跳过，避免规则被永久占用。
    conn.execute(
        "UPDATE target_monitor_run run SET status='skipped',skip_reason='task_missing',finished_at=NOW() \
         WHERE run.status IN ('pending','running') AND run.started_at<NOW()-INTERVAL '1 hour' \
         AND (run.task_id IS NULL OR NOT EXISTS(SELECT 1 FROM scan_task t WHERE t.task_id=run.task_id))",
        &[],
    ).await?;
    conn.execute(
        "UPDATE target_monitor_run SET status='skipped',skip_reason='stale',finished_at=NOW() WHERE status IN ('pending','running') AND started_at<NOW()-INTERVAL '30 days'",
        &[],
    ).await?;
    Ok(())
}
