use super::{ApiError, Policy, Principal, Result, request_id};
use actix_web::{HttpRequest, http::StatusCode};
use chrono::{DateTime, Utc};
use deadpool_postgres::{GenericClient, Pool};
use ipnet::IpNet;
use serde_json::Value;
use std::{net::IpAddr, time::Duration};
use uuid::Uuid;

pub(crate) fn unauthorized() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "invalid_credential",
        "凭据无效、已撤销或已过期",
    )
}
pub(crate) fn generate_key(id: Uuid) -> Result<String> {
    let mut bytes = [0u8; 32];
    openssl::rand::rand_bytes(&mut bytes).map_err(|_| ApiError::unavailable())?;
    Ok(format!("nm_api_{id}.{}", super::model::fingerprint(&bytes)))
}
pub(crate) fn key_id(token: &str) -> Result<Uuid> {
    let (id, secret) = token
        .strip_prefix("nm_api_")
        .and_then(|s| s.split_once('.'))
        .ok_or_else(unauthorized)?;
    if secret.len() != 64 || !secret.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(unauthorized());
    }
    Uuid::parse_str(id).map_err(|_| unauthorized())
}
pub(crate) async fn load(pool: &Pool, id: Uuid) -> Result<(Principal, String, Vec<String>)> {
    let c = pool.get().await?;
    let row=c.query_opt("SELECT a.id,a.client_id,a.owner_user_id,a.name,a.environment,a.revision,a.policy,k.id AS credential_id,k.secret_hash,k.scopes,k.ip_allowlist,k.expires_at \
        FROM api_credential k JOIN api_client a ON a.id=k.client_id JOIN users u ON u.id=a.owner_user_id \
        CROSS JOIN api_platform_settings s WHERE k.id=$1 AND k.revoked_at IS NULL AND k.expires_at>NOW() \
        AND a.status='active' AND (a.expires_at IS NULL OR a.expires_at>NOW()) AND u.deleted_at IS NULL AND u.disabled_at IS NULL AND NOT u.limit_login AND (u.role=1 OR (u.role=2 AND u.access_policy IS NULL)) AND COALESCE((s.document->>'enabled')::BOOLEAN,FALSE)", &[&id]).await?.ok_or_else(unauthorized)?;
    let policy: Policy = serde_json::from_value(row.get::<_, Value>("policy"))
        .map_err(|_| ApiError::unavailable())?;
    policy.validate()?;
    Ok((
        Principal {
            client_pk: row.get("id"),
            client_id: row.get("client_id"),
            credential_id: row.get("credential_id"),
            owner_id: row.get("owner_user_id"),
            name: row.get("name"),
            environment: row.get("environment"),
            revision: row.get("revision"),
            policy,
            scopes: row.get("scopes"),
            expires_at: row.get::<_, DateTime<Utc>>("expires_at"),
        },
        row.get("secret_hash"),
        row.get("ip_allowlist"),
    ))
}
pub(crate) fn source_allowed(ranges: &[String], ip: Option<IpAddr>) -> bool {
    ranges.is_empty()
        || ip.is_some_and(|ip| {
            ranges
                .iter()
                .filter_map(|n| n.parse::<IpNet>().ok())
                .any(|n| n.contains(&ip))
        })
}
pub(crate) async fn authenticate(req: &HttpRequest, pool: &Pool) -> Result<Principal> {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(unauthorized)?;
    let id = key_id(token)?;
    let (p, hash, ranges) = load(pool, id).await?;
    let candidate = super::model::fingerprint(token.as_bytes());
    if hash.len() != candidate.len() || !openssl::memcmp::eq(hash.as_bytes(), candidate.as_bytes())
    {
        return Err(unauthorized());
    }
    let ip = crate::client_ip::request_ip(req);
    if !source_allowed(&p.policy.ip_allowlist, ip) || !source_allowed(&ranges, ip) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "source_not_allowed",
            "请求来源未授权",
        ));
    }
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    consume(
        &tx,
        p.client_pk,
        "requests.minute",
        p.policy.requests_per_minute,
        1,
        false,
    )
    .await?;
    consume(
        &tx,
        p.client_pk,
        "requests.day",
        p.policy.requests_per_day,
        1,
        true,
    )
    .await?;
    tx.execute(
        "UPDATE api_credential SET last_used_at=NOW() WHERE id=$1",
        &[&id],
    )
    .await?;
    tx.commit().await?;
    Ok(p)
}
pub(crate) async fn consume<C: GenericClient + Sync>(
    c: &C,
    client: i32,
    category: &str,
    limit: i64,
    units: i64,
    day: bool,
) -> Result<()> {
    let bucket = if day { "day" } else { "minute" };
    let row=c.query_opt("INSERT INTO api_usage_bucket(client_id,category,bucket_start,units) \
        SELECT $1,$2,date_trunc($3,NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',$4::BIGINT WHERE $4::BIGINT <= $5::BIGINT \
        ON CONFLICT(client_id,category,bucket_start) DO UPDATE SET units=api_usage_bucket.units+EXCLUDED.units \
        WHERE api_usage_bucket.units+EXCLUDED.units <= $5 RETURNING units",&[&client,&category,&bucket,&units,&limit]).await?;
    if row.is_none() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "quota_exceeded",
            "调用或业务额度已耗尽",
        ));
    }
    Ok(())
}
pub(crate) async fn category_quota(
    pool: &Pool,
    p: &Principal,
    category: &str,
    limit: i64,
    day: bool,
) -> Result<()> {
    consume(&pool.get().await?, p.client_pk, category, limit, 1, day).await
}
pub(crate) async fn log_call(
    pool: &Pool,
    req: &HttpRequest,
    p: Option<&Principal>,
    route: &str,
    status: u16,
    reason: Option<&str>,
    elapsed: Duration,
) {
    let operation = async {
        let c = pool.get().await?;
        c.execute("INSERT INTO api_call_log(request_id,client_id,credential_id,method,route,status,duration_ms,reason_code,source_ip) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",&[&request_id(req),&p.map(|p|p.client_pk),&p.map(|p|p.credential_id),&req.method().as_str(),&route,&(status as i16),&(elapsed.as_millis().min(i64::MAX as u128) as i64),&reason,&crate::client_ip::request_ip(req)]).await?;
        Ok::<_, ApiError>(())
    };
    if let Err(e) = operation.await {
        tracing::warn!(event="OpenApiCallLogFailed",code=e.code,request_id=%request_id(req));
    }
}
#[allow(clippy::too_many_arguments)]
pub(crate) async fn audit<C: GenericClient + Sync>(
    c: &C,
    client: Option<i32>,
    actor_type: &str,
    actor: &str,
    action: &str,
    resource: Option<&str>,
    request: Option<Uuid>,
    changes: &Value,
) -> Result<()> {
    c.execute("INSERT INTO api_audit(client_id,actor_type,actor_id,action,resource_id,request_id,changes) VALUES($1,$2,$3,$4,$5,$6,$7)",&[&client,&actor_type,&actor,&action,&resource,&request,&changes]).await?;
    Ok(())
}
