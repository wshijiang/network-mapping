use super::*;
use crate::system_maintenance::SystemMaintenanceState;
use std::time::Duration;

pub async fn run(
    pool: Pool,
    es: ElasticsearchService,
    maintenance: actix_web::web::Data<SystemMaintenanceState>,
) {
    let client = match client::http_client() {
        Ok(c) => c,
        Err(_) => return,
    };
    loop {
        if !maintenance.snapshot().await.enabled
            && es.enabled()
            && process_one(&pool, &es, &client).await.is_err()
        {
            tracing::warn!(
                event = "DomainDiscoveryWorkerFailed",
                "域名发现作业稍后重试"
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
pub(super) async fn process_one(
    pool: &Pool,
    es: &ElasticsearchService,
    client: &reqwest::Client,
) -> Result<bool> {
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    tx.execute("UPDATE domain_discovery_job SET status='failed',last_error='attempts_exhausted',updated_at=NOW() WHERE attempts>=3 AND (status='pending' OR (status='running' AND lease_until<NOW()))", &[]).await?;
    tx.execute("UPDATE domain_discovery_job j SET status='cancelled',last_error='owner_unavailable',claim_token=NULL,lease_until=NULL,updated_at=NOW() FROM users u WHERE j.owner_id=u.id AND (u.disabled_at IS NOT NULL OR u.deleted_at IS NOT NULL) AND j.status IN ('pending','running')", &[]).await?;
    let row=tx.query_opt("SELECT j.* FROM domain_discovery_job j JOIN users u ON u.id=j.owner_id WHERE u.disabled_at IS NULL AND u.deleted_at IS NULL AND ((j.status='pending' AND j.available_at<=NOW()) OR (j.status='running' AND j.lease_until<NOW())) AND j.attempts<3 ORDER BY j.created_at FOR UPDATE OF j SKIP LOCKED LIMIT 1", &[]).await?;
    let Some(row) = row else { return Ok(false) };
    let id: Uuid = row.get("id");
    let owner: i32 = row.get("owner_id");
    let seed: String = row.get("seed");
    let related: bool = row.get("include_related");
    let attempt: i64 = i64::from(row.get::<_, i32>("attempts")) + 1;
    let token = Uuid::new_v4();
    tx.execute("UPDATE domain_discovery_job SET status='running',attempts=attempts+1,claim_token=$2,lease_until=NOW()+INTERVAL '3 minutes',updated_at=NOW() WHERE id=$1", &[&id,&token]).await?;
    tx.commit().await?;
    drop(c);
    match client::collect(client, &seed, related).await {
        Ok(evidence) => {
            if es
                .discovery_write(id, owner, attempt, &evidence)
                .await
                .is_err()
            {
                retry(pool, id, token, "evidence_storage").await?;
                return Ok(true);
            }
            let state = if evidence.truncated
                || evidence.incomplete_certificates > 0
                || !evidence.source_errors.is_empty()
            {
                "partial"
            } else {
                "succeeded"
            };
            pool.get().await?.execute("UPDATE domain_discovery_job SET status=$3,summary=$4,last_error=NULL,claim_token=NULL,lease_until=NULL,updated_at=NOW() WHERE id=$1 AND claim_token=$2 AND status='running' AND lease_until>NOW()", &[&id,&token,&state,&json!({"domains":evidence.candidates.len(),"certificates":evidence.certificates.len(),"truncated":evidence.truncated,"incomplete_certificates":evidence.incomplete_certificates,"source_errors":evidence.source_errors})]).await?;
        }
        Err(reason) => retry(pool, id, token, reason).await?,
    }
    Ok(true)
}
async fn retry(pool: &Pool, id: Uuid, token: Uuid, reason: &str) -> Result<()> {
    pool.get().await?.execute("UPDATE domain_discovery_job SET status=CASE WHEN attempts>=3 THEN 'failed' ELSE 'pending' END,last_error=$3,available_at=NOW()+INTERVAL '30 seconds'*attempts,claim_token=NULL,lease_until=NULL,updated_at=NOW() WHERE id=$1 AND claim_token=$2 AND status='running' AND lease_until>NOW()", &[&id,&token,&reason]).await?;
    Ok(())
}
