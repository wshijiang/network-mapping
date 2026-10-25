use super::*;
use std::sync::atomic::AtomicU64;

pub(super) async fn run(
    service: &ElasticsearchService,
    pool: &Pool,
    reporter: &dyn ProgressReporter,
    stop: &AtomicBool,
) -> Result<u64, String> {
    reporter.report(ProgressUpdate::phase("[1/6] 检查重建身份与数据配套"));
    let target = service.rebuild_target();
    let previous = load(pool, "elasticsearch_runtime").await?;
    let saved = load(pool, STATE_KEY).await?;
    let mut run = if let Some(saved) = saved.as_ref().filter(|s| s.get("target") == Some(&target)) {
        let run: Run = serde_json::from_value(saved.clone())
            .map_err(|e| format!("旧格式或损坏的重建断点无法安全恢复，请使用新的目标索引：{e}"))?;
        if run.format_version != FORMAT_VERSION {
            return Err("不支持此重建断点版本".into());
        }
        run
    } else {
        if saved.as_ref().is_some_and(|v| {
            v.get("format_version").is_some() && v.get("phase") != Some(&json!("complete"))
        }) {
            return Err("存在另一组目标的未完成重建，请使用原配置恢复".into());
        }
        for old in [
            previous.as_ref(),
            load(pool, "transport_endpoints_previous_runtime")
                .await?
                .as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            for name in ["execution_endpoint_index", "current_endpoint_index"] {
                for candidate in target.as_object().ok_or("重建目标无效")?.values() {
                    if old.get(name) == Some(candidate) {
                        return Err("重建必须使用新索引名，保留当前及回滚目标".into());
                    }
                }
            }
        }
        if target["execution_endpoint_index"] == target["current_endpoint_index"] {
            return Err("两个重建目标不能同名".into());
        }
        if let Some(old) = &previous {
            let desired = service.rebuild_runtime();
            for key in [
                "observation_index_prefix",
                "dns_observation_data_stream",
                "dns_record_index",
            ] {
                if old.get(key) != desired.get(key) {
                    return Err("端点重建不能同时切换扫描事实或 DNS 存储目标".into());
                }
            }
        }
        for value in target.as_object().ok_or("重建目标无效")?.values() {
            let name = value.as_str().ok_or("目标名称无效")?;
            if name.starts_with(&format!(
                "{}-",
                service.inner.config.observation_index_prefix
            )) || name == service.inner.config.dns_record_index
                || name == service.inner.config.dns_observation_data_stream
            {
                return Err("重建目标不能占用扫描事实或 DNS 索引命名空间".into());
            }

            if service
                .rebuild_index(value.as_str().ok_or("目标名称无效")?)
                .await?
                .is_some()
            {
                return Err("重建目标已存在且不属于可信断点，请使用新索引名".into());
            }
        }
        let jobs = executions(pool).await?;
        let source = service.rebuild_source().await?;
        service
            .preflight_rebuild(&jobs, &source, reporter, stop)
            .await?;
        let run = Run {
            format_version: FORMAT_VERSION,
            run_id: Uuid::new_v4(),
            target: target.clone(),
            previous_runtime: previous.clone(),
            receipts_hash: receipts_hash(&jobs)?,
            source,
            target_uuids: BTreeMap::new(),
            phase: Phase::Initializing,
            tag_cursor: None,
            tagged: 0,
            tag_changes: 0,
            tag_total: None,
            tags_hash: tags_hash(pool).await?,
        };
        if let Some(saved) = saved {
            save(
                pool,
                &format!("transport_endpoints_rebuild_archive:{}", run.run_id),
                &saved,
            )
            .await?;
        }
        save(pool, STATE_KEY, &run).await?;
        run
    };
    *service
        .inner
        .maintenance_run_id
        .write()
        .expect("maintenance identity lock poisoned") = Some(run.run_id.to_string());
    service.drain_rebuild_requests(&run, reporter, stop).await?;
    if run.phase == Phase::Complete {
        if previous != Some(service.rebuild_runtime()) {
            return Err("已完成重建的运行配置已变化，拒绝重复切换".into());
        }
        service.prepare_rebuild_targets(pool, &mut run).await?;
        return Ok(0);
    }
    let jobs = executions(pool).await?;
    if previous != run.previous_runtime
        || receipts_hash(&jobs)? != run.receipts_hash
        || service.rebuild_source().await? != run.source
    {
        return Err("PG 回执、运行配置或 ES 源身份已变化，拒绝沿用旧断点".into());
    }
    service.prepare_rebuild_targets(pool, &mut run).await?;
    let current_tags = tags_hash(pool).await?;
    if current_tags != run.tags_hash {
        run.tags_hash = current_tags;
        run.tag_cursor = None;
        run.tagged = 0;
        run.tag_changes = 0;
        run.tag_total = None;
        if matches!(run.phase, Phase::Tags | Phase::RefreshTags | Phase::Cutover) {
            run.phase = Phase::Tags;
        }
        save(pool, STATE_KEY, &run).await?;
    }
    loop {
        cancelled(stop)?;
        match run.phase {
            Phase::Initializing => run.phase = Phase::Replaying,
            Phase::Replaying => {
                let total = jobs.iter().map(Execution::expected).sum();
                let mut base = 0;
                for job in &jobs {
                    base += checkpoint(pool, &run, job.id).await?.replayed;
                }
                let completed = AtomicU64::new(base);
                // Only execution-local writes run concurrently. Shared current projections remain ordered.
                let concurrency = service
                    .inner
                    .config
                    .scan_migration_concurrency
                    .min(service.inner.config.bulk_max_concurrency)
                    .clamp(1, 2);
                let mut work = stream::iter(jobs.iter().map(|job| {
                    service.replay_rebuild_execution(
                        pool,
                        &run,
                        job,
                        (&completed, total),
                        reporter,
                        stop,
                    )
                }))
                .buffer_unordered(concurrency);
                while let Some(result) = work.next().await {
                    result?;
                }
                drop(work);
                run.phase = Phase::RefreshExecution;
            }
            Phase::RefreshExecution => {
                reporter.report(ProgressUpdate::phase("[2/6] 刷新并核对执行端点"));
                service
                    .refresh_rebuild_index(&service.inner.config.execution_endpoint_index)
                    .await?;
                for job in &jobs {
                    cancelled(stop)?;
                    let summary = service
                        .execution_summary(&job.context.execution_id, &[])
                        .await?;
                    let mut cp = checkpoint(pool, &run, job.id).await?;
                    cp.ip_count = Some(summary.ip_count);
                    cp.port_count = Some(summary.port_count);
                    save(pool, &checkpoint_key(&run, job.id), &cp).await?;
                }
                run.phase = Phase::Publishing;
            }
            Phase::Publishing => {
                let mut total = 0;
                for job in jobs.iter().filter(|j| j.succeeded) {
                    total += u64::try_from(
                        checkpoint(pool, &run, job.id)
                            .await?
                            .port_count
                            .ok_or("缺少发布总量")?,
                    )
                    .map_err(|e| e.to_string())?;
                }
                let mut base = 0;
                for job in &jobs {
                    base += service
                        .publish_rebuild_execution(pool, &run, job, (base, total), reporter, stop)
                        .await?;
                }
                run.phase = Phase::RefreshCurrent;
            }
            Phase::RefreshCurrent => {
                reporter.report(ProgressUpdate::phase("[3/6] 刷新当前端点"));
                service
                    .refresh_rebuild_index(&service.inner.config.current_endpoint_index)
                    .await?;
                run.phase = Phase::Tags;
            }
            Phase::Tags => {
                service.rebuild_tags(pool, &mut run, reporter, stop).await?;
                run.phase = Phase::RefreshTags;
            }
            Phase::RefreshTags => {
                reporter.report(ProgressUpdate::phase("[5/6] 刷新标签并验证源身份"));
                service
                    .refresh_rebuild_index(&service.inner.config.current_endpoint_index)
                    .await?;
                run.phase = Phase::Cutover;
            }
            Phase::Cutover => {
                reporter.report(ProgressUpdate::phase("[6/6] 校验并原子切换"));
                if service.rebuild_source().await? != run.source
                    || receipts_hash(&executions(pool).await?)? != run.receipts_hash
                {
                    return Err("重建期间事实或 PG 回执发生变化，拒绝切换".into());
                }
                if tags_hash(pool).await? != run.tags_hash {
                    return Err("标签在重建期间变化，请重新运行以同步最新标签".into());
                }
                service.prepare_rebuild_targets(pool, &mut run).await?;
                cutover(service, pool, &mut run, &jobs).await?;
                return Ok(jobs.len() as u64);
            }
            Phase::Complete => return Ok(0),
        }
        save(pool, STATE_KEY, &run).await?;
    }
}

async fn cutover(
    service: &ElasticsearchService,
    pool: &Pool,
    run: &mut Run,
    jobs: &[Execution],
) -> Result<(), String> {
    let mut summaries = Vec::new();
    for job in jobs.iter().filter(|j| j.succeeded) {
        let cp = checkpoint(pool, run, job.id).await?;
        if !cp.replay_complete || !cp.publish_complete {
            return Err("重建执行尚未完成，拒绝切换".into());
        }
        summaries.push((
            job.id,
            cp.ip_count.ok_or("缺少 IP 数量")?,
            cp.port_count.ok_or("缺少端点数量")?,
        ));
    }
    let mut connection = pool.get().await.map_err(|e| e.to_string())?;
    let tx = connection.transaction().await.map_err(|e| e.to_string())?;
    let current=tx.query_opt("SELECT state_value FROM scan_storage_state WHERE state_key='elasticsearch_runtime' FOR UPDATE",&[]).await.map_err(|e|e.to_string())?.map(|r|r.get::<_,Value>(0));
    if current != run.previous_runtime {
        return Err("切换前运行配置变化".into());
    }
    for (id, ips, ports) in summaries {
        tx.execute(
            "UPDATE scan_task_execution SET result_ip_count=$2,result_port_count=$3 WHERE id=$1",
            &[&id, &ips, &ports],
        )
        .await
        .map_err(|e| e.to_string())?;
        for (table, revision) in [
            ("os_detection_outbox", crate::os_detection::RULESET_REVISION),
            (
                "web_detection_outbox",
                crate::web_detection::RULESET_REVISION,
            ),
        ] {
            tx.execute(&format!("INSERT INTO {table}(execution_id,ruleset_revision) VALUES($1,$2) ON CONFLICT(execution_id,ruleset_revision) DO UPDATE SET processed_at=NULL,cursor=NULL,claim_token=NULL,lease_expires_at=NULL,attempts=0,available_at=NOW()"),&[&id,&revision]).await.map_err(|e|e.to_string())?;
        }
        tx.execute("INSERT INTO scan_projection_outbox(execution_id,phase,cursor,processed_at,processed_endpoints) VALUES($1,'refreshing',NULL,clock_timestamp(),$2) ON CONFLICT(execution_id) DO UPDATE SET phase='refreshing',cursor=NULL,processed_at=clock_timestamp(),processed_endpoints=EXCLUDED.processed_endpoints,claim_token=NULL,lease_expires_at=NULL,attempts=0,last_error=NULL,updated_at=clock_timestamp()",&[&id,&ports]).await.map_err(|e|e.to_string())?;
    }
    if let Some(previous) = &run.previous_runtime {
        tx.execute("INSERT INTO scan_storage_state(state_key,state_value) VALUES('transport_endpoints_previous_runtime',$1) ON CONFLICT DO NOTHING",&[previous]).await.map_err(|e|e.to_string())?;
    }
    tx.execute("INSERT INTO scan_storage_state(state_key,state_value) VALUES('elasticsearch_runtime',$1) ON CONFLICT(state_key) DO UPDATE SET state_value=EXCLUDED.state_value,updated_at=clock_timestamp()",&[&service.rebuild_runtime()]).await.map_err(|e|e.to_string())?;
    run.phase = Phase::Complete;
    tx.execute("UPDATE scan_storage_state SET state_value=$1,updated_at=clock_timestamp() WHERE state_key=$2",&[&serde_json::to_value(run).map_err(|e|e.to_string())?,&STATE_KEY]).await.map_err(|e|e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())
}
