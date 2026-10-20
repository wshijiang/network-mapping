//! Report review groups reuse immutable IOC versions across extraction attempts.
use super::*;
use std::collections::BTreeSet;

pub(super) async fn queue(pool: &Pool, user: &UserBaseI, q: &storage::ListQuery) -> Result<Value> {
    admin(user)?;
    let query = q.q.as_deref().unwrap_or("");
    let kind = q.kind.as_deref().unwrap_or("");
    let attack = q.attack_type.as_deref().unwrap_or("");
    let offset = q.offset.unwrap_or(0);
    if query.len() > 200
        || !(0..=1_000_000).contains(&offset)
        || !matches!(
            kind,
            "" | "ip" | "ip_port" | "domain" | "url" | "md5" | "sha1" | "sha256" | "asn"
        )
        || (!attack.is_empty() && !ATTACK_TYPES.contains(&attack))
    {
        return Err(Error::bad("intel_invalid_query"));
    }
    let rows = pool.get().await?.query(
        "WITH pending AS (
           SELECT r.*,latest.article_id AS review_article FROM intel_record_state r
           LEFT JOIN LATERAL (
             SELECT a.id AS article_id FROM intel_article_record l JOIN intel_article a ON a.id=l.article_id
             WHERE l.record_id=r.id AND a.source_id=r.source_id ORDER BY a.created_at DESC,a.id DESC LIMIT 1
           ) latest ON r.origin='ai'
           WHERE r.status='pending' AND ($1::UUID IS NULL OR r.source_id=$1)
         ), grouped AS (
           SELECT COALESCE(review_article,id) AS group_id,review_article,
             MIN(id::TEXT)::UUID AS representative_id,COUNT(*) AS pending_count,MAX(created_at) AS group_created_at
           FROM pending GROUP BY COALESCE(review_article,id),review_article
           HAVING BOOL_OR(($2='' OR value ILIKE '%'||$2||'%' OR payload->>'actor_name' ILIKE '%'||$2||'%' OR payload->>'malware' ILIKE '%'||$2||'%')
             AND ($3='' OR kind=$3) AND ($4='' OR (payload->'attack_types') ? $4))
         )
         SELECT r.*,g.group_id,g.review_article,g.pending_count,g.group_created_at,a.title,a.url,COUNT(*) OVER() AS total
         FROM grouped g JOIN intel_record_state r ON r.id=g.representative_id LEFT JOIN intel_article a ON a.id=g.review_article
         ORDER BY g.group_created_at DESC,g.group_id DESC LIMIT 50 OFFSET $5",
        &[&q.source_id,&query,&kind,&attack,&offset],
    ).await?;
    Ok(json!({"items":rows.iter().map(|row| json!({
        "id":row.get::<_,Uuid>("group_id"),"article_id":row.get::<_,Option<Uuid>>("review_article"),
        "title":row.get::<_,Option<String>>("title"),"url":row.get::<_,Option<String>>("url"),
        "pending_count":row.get::<_,i64>("pending_count"),"record":storage::record_json(row)
    })).collect::<Vec<_>>(),"total":rows.first().map(|r|r.get::<_,i64>("total")).unwrap_or(0),"offset":offset}))
}

pub(super) async fn report(pool: &Pool, id: Uuid, user: &UserBaseI) -> Result<Value> {
    admin(user)?;
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    let article = tx
        .query_opt("SELECT * FROM intel_article WHERE id=$1 FOR SHARE", &[&id])
        .await?
        .ok_or_else(Error::missing)?;
    let body: Option<String> = article.get("body");
    let rows = tx.query("SELECT r.*,COALESCE(rv.attribution,'{}'::JSONB) AS reviewed_attribution FROM intel_article_record l JOIN intel_record_state r ON r.id=l.record_id LEFT JOIN intel_review rv ON rv.id=r.review_id AND rv.record_id=r.id WHERE l.article_id=$1 AND r.source_id=$2 AND r.origin='ai' AND r.status<>'superseded' ORDER BY r.kind,r.value,r.created_at DESC", &[&id,&article.get::<_,Uuid>("source_id")]).await?;
    let result = json!({"article":{"id":id,"title":article.get::<_,String>("title"),"url":article.get::<_,String>("url"),"body_hash":digest(body.as_deref().unwrap_or("").as_bytes()),"body":body,"extraction_metadata":article.get::<_,Value>("extraction_metadata")},"records":rows.iter().map(storage::record_json).collect::<Vec<_>>()});
    tx.commit().await?;
    Ok(result)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BatchItem {
    pub id: Uuid,
    pub content_hash: String,
    pub decision: String,
    #[serde(default)]
    pub attribution: Option<attribution::ActorDecision>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BatchInput {
    pub body_hash: String,
    pub reason: String,
    pub items: Vec<BatchItem>,
}
impl BatchInput {
    fn validate(&self) -> Result<()> {
        let mut ids = BTreeSet::new();
        if self.reason.trim().is_empty()
            || self.reason.len() > 1000
            || self.body_hash.len() != 64
            || self.items.is_empty()
            || self.items.len() > MAX_AI_IOCS
            || self.items.iter().any(|item| {
                !ids.insert(item.id)
                    || item.content_hash.len() != 64
                    || !matches!(item.decision.as_str(), "approved" | "rejected")
                    || (item.decision != "approved" && item.attribution.is_some())
            })
        {
            return Err(Error::bad("intel_invalid_review"));
        }
        Ok(())
    }
}

pub(super) async fn submit(
    pool: &Pool,
    id: Uuid,
    input: BatchInput,
    user: &UserBaseI,
    context: &AuditContext,
) -> Result<Value> {
    admin(user)?;
    input.validate()?;
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    // Serialize against extraction completion before acquiring any IOC locks.
    let article = tx
        .query_opt(
            "SELECT source_id,body FROM intel_article WHERE id=$1 FOR UPDATE",
            &[&id],
        )
        .await?
        .ok_or_else(Error::missing)?;
    let body: Option<String> = article.get("body");
    if digest(body.as_deref().unwrap_or("").as_bytes()) != input.body_hash {
        return Err(Error::conflict());
    }
    if input.items.iter().any(|item| item.decision == "approved")
        && body.as_deref().is_none_or(|text| text.trim().is_empty())
    {
        return Err(Error::bad("intel_article_body_missing"));
    }
    let ids = input.items.iter().map(|item| item.id).collect::<Vec<_>>();
    let rows = tx.query("SELECT r.id,r.external_key FROM intel_article_record l JOIN intel_record r ON r.id=l.record_id WHERE l.article_id=$1 AND r.source_id=$2 AND r.origin='ai' AND r.status='pending' AND r.id=ANY($3) ORDER BY r.external_key,r.id", &[&id,&article.get::<_,Uuid>("source_id"),&ids]).await?;
    if rows.len() != input.items.len() {
        return Err(Error::conflict());
    }
    for row in &rows {
        let record: Uuid = row.get("id");
        let item = input
            .items
            .iter()
            .find(|item| item.id == record)
            .ok_or_else(Error::conflict)?;
        storage::review_in(
            &tx,
            record,
            &storage::ReviewInput {
                content_hash: item.content_hash.clone(),
                decision: item.decision.clone(),
                reason: input.reason.clone(),
                attribution: item.attribution.clone(),
            },
            user,
            context,
        )
        .await?;
    }
    audit(
        &tx,
        user,
        context,
        "intel.article.review",
        &id.to_string(),
        json!({"record_ids":ids,"count":ids.len(),"body_hash":input.body_hash}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"article_id":id,"reviewed":ids.len()}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batch_review_requires_unique_versioned_items_and_a_deliberate_decision() {
        let mut input: BatchInput = serde_json::from_value(json!({"body_hash":"a".repeat(64),"reason":"checked report","items":[{"id":Uuid::now_v7(),"content_hash":"b".repeat(64),"decision":"approved"}]})).unwrap();
        assert!(input.validate().is_ok());
        input.items.push(
            serde_json::from_value(
                json!({"id":input.items[0].id,"content_hash":"b".repeat(64),"decision":"rejected"}),
            )
            .unwrap(),
        );
        assert!(input.validate().is_err());
        input.items.pop();
        input.items[0].decision = "revoked".into();
        assert!(input.validate().is_err());
    }
}
