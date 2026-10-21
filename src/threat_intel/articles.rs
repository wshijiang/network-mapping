//! Administrator article intake. Every extraction remains AI evidence.
use super::*;
use storage::Source;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArticleInput {
    pub source_id: Uuid,
    pub expected_revision: i64,
    pub url: String,
    pub title: String,
    pub body: Option<String>,
}

pub(super) fn canonical_url(raw: &str, source: &SourceInput) -> Result<String> {
    let mut url = validate_url(raw.trim(), &source.allowed_hosts)?;
    if url.host_str() == Some("mp.weixin.qq.com") {
        if url.path() != "/s" && !url.path().starts_with("/s/") {
            return Err(Error::bad("intel_invalid_article_url"));
        }
        let mut identity = Vec::new();
        for (key, value) in url.query_pairs() {
            if key == "__biz" && !source.publisher_id.is_empty() && value != source.publisher_id {
                return Err(Error::bad("intel_article_publisher_mismatch"));
            }
            if matches!(key.as_ref(), "__biz" | "mid" | "idx" | "sn") {
                identity.push((key.into_owned(), value.into_owned()));
            }
        }
        identity.sort();
        url.set_query(None);
        if !identity.is_empty() {
            url.query_pairs_mut().extend_pairs(identity);
        }
    }
    Ok(url.to_string())
}

pub(super) fn body_snapshot(data: &[u8], url: &str, publisher: &str) -> Result<(String, Value)> {
    let parsed = reqwest::Url::parse(url).ok();
    if parsed
        .as_ref()
        .and_then(|url| url.host_str())
        .is_some_and(|host| matches!(host, "www.welivesecurity.com" | "welivesecurity.com"))
    {
        return article_body::extract(data, Some(".article-body"));
    }
    let wechat = reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .as_deref()
        == Some("mp.weixin.qq.com");
    if !wechat {
        return article_body::extract(data, None);
    }
    if publisher.is_empty() {
        return Err(Error::bad("intel_article_publisher_required"));
    }
    let input = std::str::from_utf8(data).map_err(|_| Error::bad("intel_article_not_utf8"))?;
    let html = scraper::Html::parse_document(input);
    let script = scraper::Selector::parse("script").expect("static selector");
    let pattern =
        regex::Regex::new(r#"\bbiz\s*=\s*["']([A-Za-z0-9+/=]{1,128})["']"#).expect("static regex");
    let ids = html
        .select(&script)
        .flat_map(|node| {
            let script = node.text().collect::<String>();
            pattern
                .captures_iter(&script)
                .map(|c| c[1].to_owned())
                .collect::<Vec<_>>()
        })
        .collect::<std::collections::BTreeSet<_>>();
    if ids.len() != 1 || !ids.contains(publisher) {
        return Err(Error::bad("intel_article_publisher_mismatch"));
    }
    let body = parse::article_text_with_selector(data, "#js_content")?;
    Ok((
        body,
        json!({"method":"remote_wechat","publisher_id":publisher,"publisher_verification":"page_account_match"}),
    ))
}

pub(super) async fn submit(
    pool: &Pool,
    input: ArticleInput,
    user: &UserBaseI,
    context: &AuditContext,
) -> Result<Value> {
    save(pool, None, input, user, context).await
}

pub(super) async fn save(
    pool: &Pool,
    edit: Option<(Uuid, i64)>,
    input: ArticleInput,
    user: &UserBaseI,
    context: &AuditContext,
) -> Result<Value> {
    admin(user)?;
    let source: Source = storage::get_source(pool, input.source_id).await?;
    if source.revision != input.expected_revision {
        return Err(Error::conflict());
    }
    if (edit.is_none() && (source.input.kind != "article" || source.input.transport != "manual"))
        || !matches!(source.input.kind.as_str(), "rss" | "article")
    {
        return Err(Error::bad("intel_invalid_article_source"));
    }
    let url = canonical_url(&input.url, &source.input)?;
    let title = input.title.trim();
    if title.is_empty() || title.chars().count() > 500 || title.chars().any(char::is_control) {
        return Err(Error::bad("intel_invalid_article"));
    }
    let body = input
        .body
        .map(|body| body.trim().to_owned())
        .filter(|body| !body.is_empty());
    if body
        .as_ref()
        .is_some_and(|body| body.len() < 40 || body.len() > MAX_ARTICLE || body.contains('\0'))
    {
        return Err(Error::bad("intel_invalid_article"));
    }
    if body.is_none()
        && reqwest::Url::parse(&url)
            .ok()
            .is_some_and(|u| u.host_str() == Some("mp.weixin.qq.com"))
        && source.input.publisher_id.is_empty()
    {
        return Err(Error::bad("intel_article_publisher_required"));
    }
    // Plain text is explicitly administrator supplied, never claimed to be a
    // network-verified official publication or a structured trusted feed.
    let intake = if body.is_some() {
        json!({"method":"manual_text","publisher_verification":"administrator_supplied"})
    } else {
        json!({"method":"remote_pending"})
    };
    let hash = digest(
        json!({"url":url,"title":title,"body":body})
            .to_string()
            .as_bytes(),
    );
    let body_hash = body.as_ref().map(|body| digest(body.as_bytes()));
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    if let Some((id, revision)) = edit {
        let old = tx.query_opt("SELECT source_id,revision FROM intel_article WHERE id=$1 AND deleted_at IS NULL FOR UPDATE", &[&id]).await?.ok_or_else(Error::missing)?;
        if old.get::<_, Uuid>("source_id") != source.id || old.get::<_, i64>("revision") != revision
        {
            return Err(Error::conflict());
        }
        tx.execute("UPDATE intel_article SET deleted_at=NOW(),revision=revision+1,status='cancelled',claim_token=NULL,lease_until=NULL WHERE id=$1", &[&id]).await?;
    }
    storage::validate_source(&tx, &source).await?;
    let metadata = json!({"intake":intake,"edit_of":edit.map(|(id,_)|id)});
    let id = Uuid::now_v7();
    let inserted = tx.query_opt("INSERT INTO intel_article(id,source_id,source_revision,url,title,feed_hash,body,body_hash,extraction_metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(source_id,url,feed_hash,source_revision) WHERE deleted_at IS NULL DO NOTHING RETURNING id", &[&id,&source.id,&source.revision,&url,&title,&hash,&body,&body_hash,&metadata]).await?;
    let id: Uuid = if let Some(row) = inserted {
        row.get(0)
    } else {
        if edit.is_some() {
            return Err(Error::conflict());
        }
        tx.query_one("SELECT id FROM intel_article WHERE source_id=$1 AND url=$2 AND feed_hash=$3 AND source_revision=$4 AND deleted_at IS NULL", &[&source.id,&url,&hash,&source.revision]).await?.get(0)
    };
    audit(
        &tx,
        user,
        context,
        if edit.is_some() {
            "intel.article.update"
        } else {
            "intel.article.submit"
        },
        &id.to_string(),
        json!({"source_id":source.id,"snapshot_supplied":body.is_some()}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"id":id,"queued":true,"ai_review_required":true}))
}
