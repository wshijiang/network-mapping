use super::*;

impl ElasticsearchService {
    pub(super) async fn rebuild_tags(
        &self,
        pool: &Pool,
        run: &mut Run,
        reporter: &dyn ProgressReporter,
        stop: &AtomicBool,
    ) -> Result<(), String> {
        let index = &self.inner.config.current_endpoint_index;
        let response = self
            .send_json_request(
                ElasticsearchOperation::ScanQuery,
                Method::POST,
                &format!("/{index}/_count"),
                |r| r.json(&json!({"query":{"match_all":{}}})),
            )
            .await?;
        validate_scan_search_response(&response)?;
        let total = response
            .get("count")
            .and_then(Value::as_u64)
            .ok_or("当前端点缺少精确数量")?;
        if run.tag_total.is_some_and(|v| v != total)
            || run.tagged > total
            || run.tag_changes > run.tagged
        {
            return Err("标签阶段的目标数量与断点不匹配".into());
        }
        run.tag_total = Some(total);
        save(pool, STATE_KEY, run).await?;
        loop {
            cancelled(stop)?;
            reporter.report(ProgressUpdate::count(
                "[4/6] 标签同步",
                run.tagged,
                Some(total),
                "文档",
                format!(
                    "修改 {}，无需修改 {}，等待读取页",
                    run.tag_changes,
                    run.tagged - run.tag_changes
                ),
            ));
            let mut query = json!({"size":self.inner.config.projection_page_size,"track_total_hits":false,
              "_source":["ip","tags","tag_names","tag_ids","tag_kinds"],
              "sort":[{"scope_type":"asc"},{"scope_id":"asc"},{"endpoint_key":"asc"}]});
            if let Some(cursor) = &run.tag_cursor {
                query["search_after"] = cursor.clone();
            }
            let response = self
                .send_json_request(
                    ElasticsearchOperation::ScanQuery,
                    Method::POST,
                    &format!("/{index}/_search?allow_partial_search_results=false"),
                    |r| r.json(&query),
                )
                .await?;
            validate_scan_search_response(&response)?;
            let hits = response
                .pointer("/hits/hits")
                .and_then(Value::as_array)
                .ok_or("标签分页缺少 hits")?;
            if hits.is_empty() {
                break;
            }
            if run.tagged + hits.len() as u64 > total {
                return Err("标签页数量超过目标清单".into());
            }
            let ips = hits
                .iter()
                .map(|h| {
                    h.pointer("/_source/ip")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .ok_or("端点缺少 IP")
                })
                .collect::<Result<BTreeSet<_>, _>>()?
                .into_iter()
                .collect::<Vec<_>>();
            let tags = load_tags(pool, &ips).await?;
            let next = hits
                .last()
                .and_then(|h| h.get("sort"))
                .filter(|v| v.as_array().is_some_and(|a| a.len() == 3))
                .cloned()
                .ok_or("标签页缺少稳定游标")?;
            if run.tag_cursor.as_ref() == Some(&next) {
                return Err("标签分页没有前进".into());
            }
            let mut bulk = Bulk::new(index);
            let mut changed = 0;
            for hit in hits {
                let source = hit.get("_source").ok_or("端点缺少 _source")?;
                let ip = source
                    .get("ip")
                    .and_then(Value::as_str)
                    .ok_or("端点缺少 IP")?;
                let patch = tag_patch(tags.get(ip).cloned().unwrap_or_else(|| json!([])))?;
                if patch
                    .as_object()
                    .ok_or("标签补丁无效")?
                    .iter()
                    .all(|(k, v)| source.get(k) == Some(v))
                {
                    continue;
                }
                let id = hit
                    .get("_id")
                    .and_then(Value::as_str)
                    .ok_or("端点缺少 _id")?
                    .to_owned();
                let action = format!(
                    "{}\n{}\n",
                    json!({"update":{"_index":index,"_id":id}}),
                    json!({"doc":patch})
                );
                bulk.push(self, id, action).await?;
                changed += 1;
            }
            bulk.flush(self).await?;
            run.tagged += hits.len() as u64;
            run.tag_changes += changed;
            run.tag_cursor = Some(next);
            save(pool, STATE_KEY, run).await?;
        }
        if run.tagged != total {
            return Err(format!("标签扫描不完整：预期 {total}，实际 {}", run.tagged));
        }
        Ok(())
    }
}

async fn load_tags(pool: &Pool, ips: &[String]) -> Result<BTreeMap<String, Value>, String> {
    let connection = pool.get().await.map_err(|e| e.to_string())?;
    let rows=connection.query(
        "SELECT host(a.ip_address),jsonb_agg(jsonb_build_object('id',t.id,'name',t.name,'kind',t.kind,
          'description',t.description,'category_id',c.id,'category_name',c.name) ORDER BY c.sort_order,LOWER(c.name),t.id)
         FROM asset_ip_tag a JOIN asset_tag t ON t.id=a.tag_id AND t.is_active
         JOIN asset_tag_category c ON c.id=t.category_id AND c.is_active
         WHERE a.ip_address=ANY($1::text[]::inet[]) GROUP BY a.ip_address", &[&ips]).await.map_err(|e|e.to_string())?;
    Ok(rows.into_iter().map(|r| (r.get(0), r.get(1))).collect())
}

pub(super) fn tag_patch(tags: Value) -> Result<Value, String> {
    let list = tags.as_array().ok_or("PG 标签不是数组")?;
    let names = list
        .iter()
        .map(|t| t.get("name").cloned().ok_or("标签缺少 name"))
        .collect::<Result<Vec<_>, _>>()?;
    let ids = list
        .iter()
        .map(|t| t.get("id").cloned().ok_or("标签缺少 id"))
        .collect::<Result<Vec<_>, _>>()?;
    let kinds = list
        .iter()
        .map(|t| t.get("kind").cloned().ok_or("标签缺少 kind"))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({"tags":tags,"tag_names":names,"tag_ids":ids,"tag_kinds":kinds}))
}
