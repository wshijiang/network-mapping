//! Set-based structured ingestion. AI publication continues through its existing gate.
use super::*;
use deadpool_postgres::GenericClient;
use storage::Source;

pub(super) async fn ingest_all(
    pool: &Pool,
    source: &Source,
    entries: Vec<Indicator>,
    namespace: &str,
) -> Result<usize> {
    let mut batch = Vec::new();
    let mut bytes = 0;
    let mut added = 0;
    for item in entries {
        bytes += serde_json::to_vec(&item)
            .map_err(|_| Error::bad("intel_invalid_indicator"))?
            .len();
        batch.push(item);
        if batch.len() >= imports::BATCH || bytes >= 8 * 1024 * 1024 {
            let mut c = pool.get().await?;
            let tx = c.transaction().await?;
            added += ingest(&tx, source, std::mem::take(&mut batch), namespace).await? as usize;
            tx.commit().await?;
            bytes = 0;
        }
    }
    if !batch.is_empty() {
        let mut c = pool.get().await?;
        let tx = c.transaction().await?;
        added += ingest(&tx, source, batch, namespace).await? as usize;
        tx.commit().await?;
    }
    Ok(added)
}

pub(super) async fn ingest<C: GenericClient + Sync>(
    c: &C,
    s: &Source,
    mut items: Vec<Indicator>,
    namespace: &str,
) -> Result<i64> {
    let review = storage::validate_source(c, s).await?;
    if items.is_empty() {
        return Ok(0);
    }
    for i in &mut items {
        i.normalize()?;
    }
    // Resolve only actual attribution candidates, in one query with the same
    // exact-name / explicit-ID rules as the single-record path.
    let candidates = items.iter().enumerate().filter(|(_,i)| !i.actor_name.trim().is_empty() || (i.actor_id.is_some() && i.reference.is_some() && !i.evidence.is_empty())).map(|(index,i)|json!({"index":index,"name":i.actor_name.trim(),"id":i.actor_id,"explicit":i.reference.is_some()&&!i.evidence.is_empty()})).collect::<Vec<_>>();
    let mut actors = std::collections::BTreeMap::new();
    if !candidates.is_empty() {
        for row in c.query("SELECT v.index,(SELECT MIN(e.attack_id) FROM intel_entity e WHERE e.kind='actor' AND e.active AND (LOWER(e.name)=LOWER(v.name) OR (v.explicit AND v.name='' AND e.attack_id=v.id)) HAVING COUNT(*)=1) AS actor_id FROM jsonb_to_recordset($1) v(index INTEGER,name TEXT,id TEXT,explicit BOOLEAN)",&[&json!(candidates)]).await? {
            actors.insert(row.get::<_,i32>(0) as usize,row.get::<_,Option<String>>(1));
        }
    }
    let mut rows = Vec::with_capacity(items.len());
    let mut locks = Vec::with_capacity(items.len());
    for (index, mut i) in items.into_iter().enumerate() {
        i.actor_id = if i.reference.is_some() && !i.evidence.is_empty() {
            actors.remove(&index).flatten()
        } else {
            None
        };
        let payload = json!(i);
        let hash = digest(
            &serde_json::to_vec(&payload).map_err(|_| Error::bad("intel_invalid_indicator"))?,
        );
        let key = format!(
            "{namespace}{}",
            if i.external_id.is_empty() {
                format!("{}:{}", i.kind, i.value)
            } else {
                i.external_id.clone()
            }
        );
        locks.push(format!("{}:{key}", s.id));
        rows.push(json!({"id":Uuid::now_v7(),"external_key":key,"content_hash":hash,"kind":i.kind,"value":i.value,"payload":payload,"actor_id":i.actor_id,"valid_until":i.valid_until,"position":index}));
    }
    // Stable lock ordering across overlapping batches and the single-record/review path.
    c.query("SELECT pg_advisory_xact_lock(k) FROM (SELECT DISTINCT hashtextextended(v,317) k FROM unnest($1::TEXT[]) v ORDER BY k) locks",&[&locks]).await?;
    let rows = json!(rows);
    if !review {
        c.execute("INSERT INTO intel_ioc(id,kind,value) SELECT DISTINCT ON (kind,value) id,kind,value FROM jsonb_to_recordset($1) b(id UUID,kind TEXT,value TEXT) ORDER BY kind,value ON CONFLICT(kind,value) DO NOTHING",&[&rows]).await?;
    }
    let status = if review { "pending" } else { "approved" };
    let added=c.execute(r#"
INSERT INTO intel_record(id,source_id,source_revision,external_key,content_hash,origin,status,kind,value,payload,actor_id,ioc_id,valid_until,observed_at)
SELECT b.id,$2,$3,b.external_key,b.content_hash,'structured',$4,b.kind,b.value,b.payload,b.actor_id,
 CASE WHEN $4='approved' THEN i.id END,b.valid_until,
 LEAST(NOW(),COALESCE(intel_observed_time(b.payload->>'last_seen'),intel_observed_time(b.payload->>'first_seen'),NOW()))
FROM jsonb_to_recordset($1) b(id UUID,external_key TEXT,content_hash TEXT,kind TEXT,value TEXT,payload JSONB,actor_id TEXT,valid_until TIMESTAMPTZ)
LEFT JOIN intel_ioc i ON $4='approved' AND i.kind=b.kind AND i.value=b.value
ON CONFLICT(source_id,external_key,content_hash,origin) DO NOTHING
"#,&[&rows,&s.id,&s.revision,&status]).await?;
    if !review {
        // Reject/revoke decisions remain final for this exact content version.
        c.execute(
            r#"
UPDATE intel_record r SET status='approved',ioc_id=i.id,updated_at=NOW()
FROM jsonb_to_recordset($1) b(external_key TEXT,content_hash TEXT,kind TEXT,value TEXT)
JOIN intel_ioc i ON i.kind=b.kind AND i.value=b.value
WHERE r.source_id=$2 AND r.external_key=b.external_key AND r.content_hash=b.content_hash
 AND r.origin='structured' AND r.status IN ('pending','superseded')
"#,
            &[&rows, &s.id],
        )
        .await?;
        // Keep every version, but only the last eligible occurrence for a source
        // record remains approved, exactly as sequential ingestion would do.
        c.execute(r#"
WITH winners AS (
 SELECT DISTINCT ON (b.external_key) b.external_key,r.id
 FROM jsonb_to_recordset($1) b(external_key TEXT,content_hash TEXT,position INTEGER)
 JOIN intel_record r ON r.source_id=$2 AND r.external_key=b.external_key AND r.content_hash=b.content_hash
  AND r.origin='structured' AND r.status='approved'
 ORDER BY b.external_key,b.position DESC
)
UPDATE intel_record r SET status='superseded',updated_at=NOW() FROM winners w
WHERE r.source_id=$2 AND r.external_key=w.external_key AND r.origin='structured'
 AND r.status='approved' AND r.id<>w.id
"#,&[&rows,&s.id]).await?;
    }
    // A batch must not commit after its lease expired while statements ran.
    storage::validate_source(c, s).await?;
    Ok(added as i64)
}
