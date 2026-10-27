use super::*;

const TAG_PIT_KEEP_ALIVE: &str = "24h";

struct FetchedTagPage {
    hits: Vec<Value>,
    cursor: Option<Value>,
    done: bool,
    pit_id: String,
}

impl ElasticsearchService {
    pub(super) async fn rebuild_tags(
        &self,
        pool: &Pool,
        run: &mut Run,
        reporter: &dyn ProgressReporter,
        stop: &AtomicBool,
    ) -> Result<(), String> {
        if run.tag_complete {
            return Ok(());
        }
        let index = self.inner.config.current_endpoint_index.clone();
        // Cursors persisted by the previous scope-sorted scan are not valid for
        // the PIT `_shard_doc` scan. Restarting is safe because tag patches are
        // idempotent.
        if run.tag_cursor.is_some() && run.tag_pit_id.is_none() {
            reset_tag_scan(run);
            save(pool, STATE_KEY, run).await?;
        }
        loop {
            let pit_id = match run.tag_pit_id.clone() {
                Some(pit_id) => pit_id,
                None => {
                    let pit_id = self.open_tag_pit(&index).await?;
                    run.tag_pit_id = Some(pit_id.clone());
                    save(pool, STATE_KEY, run).await?;
                    pit_id
                }
            };
            match self
                .scan_rebuild_tags(pool, run, &index, reporter, stop)
                .await
            {
                Ok(()) => {
                    self.close_tag_pit(run.tag_pit_id.as_deref().unwrap_or(&pit_id))
                        .await;
                    run.tag_pit_id = None;
                    run.tag_complete = true;
                    save(pool, STATE_KEY, run).await?;
                    return Ok(());
                }
                Err(error) if tag_pit_missing(&error) => {
                    warn!(event = "TransportRebuildTagPitExpired", error_message = %error,
                        "标签扫描 PIT 已失效，重新开始扫描");
                    self.close_tag_pit(run.tag_pit_id.as_deref().unwrap_or(&pit_id))
                        .await;
                    reset_tag_scan(run);
                    save(pool, STATE_KEY, run).await?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn scan_rebuild_tags(
        &self,
        pool: &Pool,
        run: &mut Run,
        index: &str,
        reporter: &dyn ProgressReporter,
        stop: &AtomicBool,
    ) -> Result<(), String> {
        if run.tag_total.is_none() {
            run.tag_total = Some(self.count_tag_documents(index).await?);
            save(pool, STATE_KEY, run).await?;
        }
        let page_size = self.inner.config.projection_page_size;
        loop {
            cancelled(stop)?;
            let total = run.tag_total.unwrap_or(0);
            reporter.report(ProgressUpdate::count(
                "[4/6] 标签同步",
                run.tagged,
                Some(total),
                "文档",
                format!(
                    "修改 {}，无需修改 {}，等待读取页",
                    run.tag_changes,
                    run.tagged.saturating_sub(run.tag_changes)
                ),
            ));
            let page = self
                .fetch_tag_page(
                    run.tag_pit_id.as_deref().ok_or("标签扫描缺少 PIT ID")?,
                    run.tag_cursor.as_ref(),
                    page_size,
                )
                .await?;
            let FetchedTagPage {
                hits,
                cursor,
                done,
                pit_id: response_pit_id,
            } = page;
            run.tag_pit_id = Some(response_pit_id);
            let hit_count = hits.len() as u64;
            if hits.is_empty() {
                run.tag_cursor = cursor;
                save(pool, STATE_KEY, run).await?;
                break;
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
            let mut bulk = Bulk::new(index);
            let mut changed = 0;
            for hit in hits {
                let source = hit.get("_source").ok_or("端点缺少 _source")?;
                let ip = source
                    .get("ip")
                    .and_then(Value::as_str)
                    .ok_or("端点缺少 IP")?;
                let patch = tag_patch(tags.get(ip).cloned().unwrap_or_else(|| json!([])))?;
                if tag_patch_matches(source, &patch)? {
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
            run.tagged += hit_count;
            run.tag_changes += changed;
            run.tag_cursor = cursor;
            save(pool, STATE_KEY, run).await?;
            if done {
                break;
            }
        }
        Ok(())
    }

    async fn count_tag_documents(&self, index: &str) -> Result<u64, String> {
        let response = self
            .send_json_request(
                ElasticsearchOperation::ScanQuery,
                Method::POST,
                &format!("/{index}/_count"),
                |r| r.json(&json!({"query":{"match_all":{}}})),
            )
            .await?;
        validate_scan_search_response(&response)?;
        response
            .get("count")
            .and_then(Value::as_u64)
            .ok_or_else(|| "当前端点缺少精确数量".into())
    }

    async fn open_tag_pit(&self, index: &str) -> Result<String, String> {
        let response = self
            .send_json_request(
                ElasticsearchOperation::IndexAdmin,
                Method::POST,
                &format!("/{index}/_pit?keep_alive={TAG_PIT_KEEP_ALIVE}"),
                |r| r,
            )
            .await?;
        response
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| "标签扫描 PIT 缺少 id".into())
    }

    async fn close_tag_pit(&self, pit_id: &str) {
        if let Err(error) = self
            .send_json_request(
                ElasticsearchOperation::IndexAdmin,
                Method::DELETE,
                "/_pit",
                |r| r.json(&json!({"id": pit_id})),
            )
            .await
        {
            warn!(event = "TransportRebuildTagPitCloseFailed", error_message = %error,
                "标签扫描 PIT 关闭失败");
        }
    }

    async fn fetch_tag_page(
        &self,
        pit_id: &str,
        cursor: Option<&Value>,
        page_size: usize,
    ) -> Result<FetchedTagPage, String> {
        let mut query = json!({
            "size": page_size,
            "track_total_hits": false,
            "pit": {"id": pit_id, "keep_alive": TAG_PIT_KEEP_ALIVE},
            "sort": [{"_shard_doc": "asc"}],
            "_source": ["ip","tags","tag_names","tag_ids","tag_kinds"]
        });
        if let Some(cursor) = cursor {
            query["search_after"] = cursor.clone();
        }
        let response = self
            .send_json_request(
                ElasticsearchOperation::ScanQuery,
                Method::POST,
                "/_search?allow_partial_search_results=false&filter_path=timed_out,_shards.failed,pit_id,hits.hits",
                |r| r.json(&query),
            )
            .await?;
        validate_scan_search_response(&response)?;
        let hits = response
            .pointer("/hits/hits")
            .and_then(Value::as_array)
            .ok_or_else(|| "标签分页缺少 hits".to_owned())?
            .clone();
        let next = if let Some(hit) = hits.last() {
            let sort = hit
                .get("sort")
                .filter(|v| v.as_array().is_some_and(|a| a.len() == 1 && a[0].is_i64()))
                .ok_or_else(|| "标签页缺少稳定游标".to_owned())?;
            if Some(sort) == cursor {
                return Err("标签分页没有前进".into());
            }
            Some(sort.clone())
        } else {
            cursor.cloned()
        };
        let pit_id = response
            .get("pit_id")
            .and_then(Value::as_str)
            .unwrap_or(pit_id)
            .to_owned();
        Ok(FetchedTagPage {
            done: hits.len() < page_size,
            hits,
            cursor: next,
            pit_id,
        })
    }
}

fn reset_tag_scan(run: &mut Run) {
    run.tag_pit_id = None;
    run.tag_cursor = None;
    run.tagged = 0;
    run.tag_changes = 0;
    run.tag_total = None;
    run.tag_complete = false;
}

fn tag_pit_missing(error: &str) -> bool {
    error.contains("search_context_missing_exception")
        || error.contains("No search context found")
        || error.contains("no such pit")
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

/// Canonicalize arrays as multisets so PG tag order changes do not rewrite
/// every tagged endpoint on each rebuild.
fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Array(items) => {
            let mut items = items.iter().map(canonical_json).collect::<Vec<_>>();
            items.sort_by(|left, right| {
                serde_json::to_string(left)
                    .unwrap_or_default()
                    .cmp(&serde_json::to_string(right).unwrap_or_default())
            });
            Value::Array(items)
        }
        Value::Object(object) => {
            let mut fields = object
                .iter()
                .map(|(key, value)| (key.clone(), canonical_json(value)))
                .collect::<Vec<_>>();
            fields.sort_by(|left, right| left.0.cmp(&right.0));
            Value::Object(fields.into_iter().collect())
        }
        _ => value.clone(),
    }
}

pub(super) fn tag_patch_matches(source: &Value, patch: &Value) -> Result<bool, String> {
    let patch = patch.as_object().ok_or("标签补丁无效")?;
    Ok(patch.iter().all(|(key, expected)| {
        source
            .get(key)
            .is_some_and(|actual| canonical_json(actual) == canonical_json(expected))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(id: i64, name: &str) -> Value {
        json!({"id":id,"name":name,"kind":"info","category_id":1,"category_name":"category"})
    }

    #[test]
    fn tag_patch_comparison_ignores_array_order() {
        let first = tag(1, "alpha");
        let second = tag(2, "beta");
        let patch = tag_patch(json!([first.clone(), second.clone()])).unwrap();
        let source = json!({
            "tags": [second, first],
            "tag_names": ["beta", "alpha"],
            "tag_ids": [2, 1],
            "tag_kinds": ["info", "info"]
        });
        assert!(tag_patch_matches(&source, &patch).unwrap());
    }

    #[test]
    fn tag_patch_comparison_detects_content_changes() {
        let patch = tag_patch(json!([tag(1, "alpha")])).unwrap();
        let source = json!({
            "tags": [tag(1, "renamed")],
            "tag_names": ["renamed"],
            "tag_ids": [1],
            "tag_kinds": ["info"]
        });
        assert!(!tag_patch_matches(&source, &patch).unwrap());
    }
}
