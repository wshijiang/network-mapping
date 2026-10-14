//! Successful refresh time and retry admission outlive deletable scan tasks.
use serde_json::Value;
use tokio_postgres::Transaction;

pub fn plan_key(profile: &str, ports: &str) -> String {
    crate::scan_control::routing::target_key(&[], "refresh-v1", profile, ports)
}

/// Endpoint identity is independent of batch/observation order and timestamps.
/// Volatile banners and GeoIP data do not trigger a change refresh.
pub(crate) fn fingerprint(rows: &[Value]) -> String {
    let mut combined = [0_u8; 32];
    for row in rows {
        let identity = serde_json::json!([
            row["kind"],
            row["ip"],
            row["port"],
            row["protocol"],
            row["service"],
            row["source"],
            row["data"]["template_id"],
            row["data"]["matcher_name"]
        ]);
        let digest =
            openssl::sha::sha256(&serde_json::to_vec(&identity).expect("serializable identity"));
        for (acc, byte) in combined.iter_mut().zip(digest) {
            *acc ^= byte;
        }
    }
    combined.iter().map(|byte| format!("{byte:08b}")).collect()
}

pub async fn eligible(
    tx: &deadpool_postgres::Transaction<'_>,
    key: &str,
    profile: &str,
    ports: &str,
    repeat_ms: i64,
    now: i64,
) -> Result<bool, tokio_postgres::Error> {
    let active:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM scan_task WHERE generation_key=$1 AND scan_profile=$2 AND scan_port_set(task_port)=scan_port_set($3) AND task_status IN ('pending','running')) AS active", &[&key,&profile,&ports]).await?.get("active");
    if active {
        return Ok(false);
    }
    if let Some(row)=tx.query_opt("SELECT last_success_at,next_attempt_at,next_refresh_at,change_detected FROM automatic_target_history WHERE generation_key=$1 AND plan_key=$2", &[&key,&plan_key(profile,ports)]).await? {
        let refresh:i64=row.get("next_refresh_at");
        let deadline=row.get::<_,Option<i64>>("last_success_at").map(|last|{let normal=last.saturating_add(repeat_ms);if row.get::<_,bool>("change_detected"){normal.min(refresh)}else{normal}});
        return Ok(row.get::<_,i64>("next_attempt_at")<=now && deadline.is_none_or(|deadline|now>=deadline));
    }
    // Upgrade old deployments using successful completion, not creation time.
    let last:Option<i64>=tx.query_one("SELECT MAX(task_end_time) AS last FROM scan_task WHERE generation_key=$1 AND scan_profile=$2 AND scan_port_set(task_port)=scan_port_set($3) AND task_status='succeeded'", &[&key,&profile,&ports]).await?.get("last");
    Ok(last.is_none_or(|last| now - last >= repeat_ms))
}

pub async fn created(
    tx: &deadpool_postgres::Transaction<'_>,
    key: &str,
    family: &str,
    target: &str,
    profile: &str,
    ports: &str,
    now: i64,
) -> Result<(), tokio_postgres::Error> {
    tx.execute("INSERT INTO automatic_target_history(generation_key,plan_key,address_family,target,last_attempt_at,next_attempt_at) VALUES($1,$2,$3,$4,$5::BIGINT,$5::BIGINT+30000) \
        ON CONFLICT(generation_key,plan_key) DO UPDATE SET last_attempt_at=EXCLUDED.last_attempt_at,next_attempt_at=EXCLUDED.next_attempt_at", &[&key,&plan_key(profile,ports),&family,&target,&now]).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)] // bounded queue admission and authorized scope
pub async fn due(
    tx: &deadpool_postgres::Transaction<'_>,
    family: &str,
    profile: &str,
    ports: &str,
    repeat_ms: i64,
    now: i64,
    limit: i64,
    scope: (&[ipnet::IpNet], &[ipnet::IpNet], u8),
) -> Result<Vec<(String, String)>, tokio_postgres::Error> {
    let authorized: Vec<String> = scope.0.iter().map(ToString::to_string).collect();
    let excluded: Vec<String> = scope.1.iter().map(ToString::to_string).collect();
    Ok(tx.query("SELECT generation_key,target FROM automatic_target_history WHERE address_family=$1 AND plan_key=$2 AND next_attempt_at<=$3 \
        AND (last_success_at IS NULL OR (change_detected AND LEAST(next_refresh_at,last_success_at+$4)<=$3) OR (NOT change_detected AND last_success_at<=$3-$4)) AND EXISTS(SELECT 1 FROM UNNEST($6::TEXT[]) p(net) WHERE target::INET <<= p.net::INET) \
        AND NOT EXISTS(SELECT 1 FROM UNNEST($7::TEXT[]) e(net) WHERE target::INET && e.net::INET) \
        AND NOT EXISTS(SELECT 1 FROM scan_task t WHERE t.generation_key=automatic_target_history.generation_key \
            AND t.scan_profile=$9 AND scan_port_set(t.task_port)=scan_port_set($10) AND t.task_status IN ('pending','running')) \
        AND masklen(target::INET)=$8::INT ORDER BY last_success_at NULLS FIRST,next_refresh_at,next_attempt_at,generation_key LIMIT $5", &[&family,&plan_key(profile,ports),&now,&repeat_ms,&limit,&authorized,&excluded,&i32::from(scope.2),&profile,&ports]).await?.into_iter().map(|r|(r.get("generation_key"),r.get("target"))).collect())
}

pub fn backoff_ms(failures: i32, base_seconds: u64) -> i64 {
    let multiplier = 1_u64 << failures.saturating_sub(1).clamp(0, 10);
    base_seconds
        .saturating_mul(multiplier)
        .min(86400)
        .saturating_mul(1000) as i64
}

/// Task-level receipt prevents repeated final uploads and multiple executions
/// from advancing the refresh clock twice. Empty successful scans are valid.
pub async fn record_result(tx: &Transaction<'_>, task: i32) -> Result<(), tokio_postgres::Error> {
    let Some(row)=tx.query_opt("SELECT generation_key,task_status,address_family,task_target::TEXT[] AS targets,scan_profile,task_port,task_end_time, (SELECT asset_signature::TEXT FROM scan_task_execution WHERE task_id=scan_task.id AND execution_status='succeeded' ORDER BY id LIMIT 1) AS signature FROM scan_task WHERE id=$1 AND task_source='automatic'", &[&task]).await? else{return Ok(());};
    let status: &str = row.get("task_status");
    if !matches!(status, "succeeded" | "failed") {
        return Ok(());
    }
    let Some(key) = row.get::<_, Option<String>>("generation_key") else {
        return Ok(());
    };
    if tx
        .execute(
            "INSERT INTO automatic_target_outcome(task_id) VALUES($1) ON CONFLICT DO NOTHING",
            &[&task],
        )
        .await?
        == 0
    {
        return Ok(());
    }
    let targets: Vec<String> = row.get("targets");
    let Some(target) = targets.first() else {
        return Ok(());
    };
    let plan = plan_key(row.get("scan_profile"), row.get("task_port"));
    let now = row
        .get::<_, Option<i64>>("task_end_time")
        .unwrap_or_else(crate::clock::get_unix_epoch_ms);
    let policy: Option<Value> = tx
        .query_opt(
            "SELECT document FROM runtime_configuration WHERE namespace='automatic_target'",
            &[],
        )
        .await?
        .map(|r| r.get("document"));
    let base = policy
        .as_ref()
        .and_then(|p| p.get("failure_backoff_seconds"))
        .and_then(Value::as_u64)
        .unwrap_or(300)
        .clamp(30, 86400);
    if status == "succeeded" {
        let signature: Option<String> = row.get("signature");
        let previous:Option<String>=tx.query_opt("SELECT last_asset_signature FROM automatic_target_history WHERE generation_key=$1 AND plan_key=$2 FOR UPDATE", &[&key,&plan]).await?.and_then(|r|r.get("last_asset_signature"));
        let changed = previous
            .as_ref()
            .zip(signature.as_ref())
            .is_some_and(|(a, b)| a != b);
        let repeat = policy
            .as_ref()
            .and_then(|p| p.get("repeat_after_seconds"))
            .and_then(Value::as_u64)
            .unwrap_or(604800)
            .clamp(1, 315360000);
        let delay = if changed {
            policy
                .as_ref()
                .and_then(|p| p.get("change_refresh_seconds"))
                .and_then(Value::as_u64)
                .unwrap_or(3600)
                .min(repeat)
        } else {
            repeat
        };
        tx.execute("INSERT INTO automatic_target_history(generation_key,plan_key,address_family,target,last_success_at,last_attempt_at,next_attempt_at) VALUES($1,$2,$3,$4,$5,$5,0) \
            ON CONFLICT(generation_key,plan_key) DO UPDATE SET last_success_at=EXCLUDED.last_success_at,failure_count=0,next_attempt_at=0", &[&key,&plan,&row.get::<_,String>("address_family"),&target,&now]).await?;
        tx.execute("UPDATE automatic_target_history SET last_asset_signature=$3,next_refresh_at=$4,change_detected=$5 WHERE generation_key=$1 AND plan_key=$2", &[&key,&plan,&signature,&(now+(delay*1000) as i64),&changed]).await?;
    } else {
        let failures:i32=tx.query_one("INSERT INTO automatic_target_history(generation_key,plan_key,address_family,target,last_attempt_at,failure_count) VALUES($1,$2,$3,$4,$5,1) \
            ON CONFLICT(generation_key,plan_key) DO UPDATE SET failure_count=LEAST(automatic_target_history.failure_count+1,1000) RETURNING failure_count", &[&key,&plan,&row.get::<_,String>("address_family"),&target,&now]).await?.get("failure_count");
        tx.execute("UPDATE automatic_target_history SET next_attempt_at=$3 WHERE generation_key=$1 AND plan_key=$2", &[&key,&plan,&(now+backoff_ms(failures,base))]).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failure_delay_grows_but_is_bounded_and_scan_plans_are_isolated() {
        assert_eq!(backoff_ms(1, 300), 300000);
        assert_eq!(backoff_ms(3, 300), 1200000);
        assert_eq!(backoff_ms(1000, 300), 86400000);
        assert_ne!(
            plan_key("port_only", "443"),
            plan_key("vulnerability_scan", "443")
        );
        assert_ne!(plan_key("port_only", "443"), plan_key("port_only", "80"));
    }
    #[test]
    fn asset_identity_ignores_time_and_order_but_detects_same_count_port_changes() {
        let a = serde_json::json!({"kind":"port","ip":"192.0.2.1","port":80,"protocol":"tcp","source":"masscan","observed_at":1});
        let b = serde_json::json!({"kind":"port","ip":"192.0.2.1","port":443,"protocol":"tcp","source":"masscan","observed_at":1});
        assert_eq!(
            fingerprint(&[a.clone(), b.clone()]),
            fingerprint(&[b.clone(), a.clone()])
        );
        let mut later = a.clone();
        later["observed_at"] = serde_json::json!(2);
        assert_eq!(fingerprint(std::slice::from_ref(&a)), fingerprint(&[later]));
        assert_ne!(fingerprint(&[a]), fingerprint(&[b]));
        assert_eq!(fingerprint(&[]), "0".repeat(256));
    }
}
