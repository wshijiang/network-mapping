//! Logical deletion keeps immutable evidence and audit history available.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeleteInput {
    pub expected_revision: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArticleUpdate {
    pub expected_article_revision: i64,
    #[serde(flatten)]
    pub article: articles::ArticleInput,
}

pub(super) async fn delete_source(
    pool: &Pool,
    id: Uuid,
    expected: i64,
    user: &UserBaseI,
    context: &AuditContext,
) -> Result<Value> {
    admin(user)?;
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    // Workers lock jobs before sources. Invalidate their tokens in that order.
    tx.execute("UPDATE intel_sync_run SET status='cancelled',claim_token=NULL,lease_until=NULL,finished_at=NOW() WHERE source_id=$1 AND status IN ('queued','running')", &[&id]).await?;
    tx.execute("UPDATE intel_article SET deleted_at=NOW(),revision=revision+1,status=CASE WHEN status IN ('queued','running') THEN 'cancelled' ELSE status END,claim_token=NULL,lease_until=NULL WHERE source_id=$1 AND deleted_at IS NULL", &[&id]).await?;
    let source = tx
        .query_opt(
            "SELECT revision FROM intel_source WHERE id=$1 AND deleted_at IS NULL FOR UPDATE",
            &[&id],
        )
        .await?
        .ok_or_else(Error::missing)?;
    if source.get::<_, i64>(0) != expected {
        return Err(Error::conflict());
    }
    tx.execute("UPDATE intel_source SET deleted_at=NOW(),enabled=FALSE,revision=revision+1,credential_ciphertext=NULL,updated_at=NOW() WHERE id=$1", &[&id]).await?;
    tx.execute(
        "UPDATE intel_entity SET active=FALSE WHERE source_id=$1",
        &[&id],
    )
    .await?;
    tx.execute(
        "UPDATE intel_relationship SET active=FALSE WHERE source_id=$1",
        &[&id],
    )
    .await?;
    tx.execute("DELETE FROM intel_name_mapping WHERE source_id=$1", &[&id])
        .await?;
    tx.execute(
        "UPDATE intel_import_snapshot SET paused=TRUE WHERE source_id=$1",
        &[&id],
    )
    .await?;
    audit(
        &tx,
        user,
        context,
        "intel.source.delete",
        &id.to_string(),
        json!({"revision":expected}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"id":id}))
}

pub(super) async fn delete_article(
    pool: &Pool,
    id: Uuid,
    expected: i64,
    user: &UserBaseI,
    context: &AuditContext,
) -> Result<Value> {
    admin(user)?;
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    let row = tx
        .query_opt(
            "SELECT revision FROM intel_article WHERE id=$1 AND deleted_at IS NULL FOR UPDATE",
            &[&id],
        )
        .await?
        .ok_or_else(Error::missing)?;
    if row.get::<_, i64>(0) != expected {
        return Err(Error::conflict());
    }
    tx.execute("UPDATE intel_article SET deleted_at=NOW(),revision=revision+1,status='cancelled',claim_token=NULL,lease_until=NULL WHERE id=$1", &[&id]).await?;
    audit(
        &tx,
        user,
        context,
        "intel.article.delete",
        &id.to_string(),
        json!({"revision":expected}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"id":id}))
}
