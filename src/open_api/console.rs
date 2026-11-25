use super::{ApiError, Policy, Result, auth, catalog, model, request_id, response};
use crate::admin::UserBaseI;
use actix_web::{HttpRequest, HttpResponse, http::StatusCode, web};
use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::{GenericClient, Pool};
use serde_json::{Value, json};
use tokio_postgres::Row;
use uuid::Uuid;

pub(crate) fn json_body(body: &[u8]) -> Result<Value> {
    if body.is_empty() {
        return Ok(json!({}));
    }
    let value: Value =
        serde_json::from_slice(body).map_err(|_| ApiError::bad("请求体必须为 JSON"))?;
    if !value.is_object() {
        return Err(ApiError::bad("请求体必须为对象"));
    }
    Ok(value)
}
pub(crate) fn text(v: &Value, key: &str, max: usize) -> Result<String> {
    let s = v
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad(format!("缺少 {key}")))?
        .trim();
    if s.is_empty() || s.chars().count() > max || s.chars().any(|c| c.is_control() && c != '\n') {
        return Err(ApiError::bad(format!("{key} 长度或内容无效")));
    }
    Ok(s.to_owned())
}
pub(crate) fn allowed_keys(v: &Value, keys: &[&str]) -> Result<()> {
    if v.as_object()
        .is_none_or(|o| o.keys().any(|k| !keys.contains(&k.as_str())))
    {
        return Err(ApiError::bad("请求含有不支持的字段"));
    }
    Ok(())
}
fn application(row: &Row) -> Value {
    json!({"id":row.get::<_,Uuid>("client_id"),"name":row.get::<_,String>("name"),"kind":row.get::<_,String>("kind"),"environment":row.get::<_,String>("environment"),"purpose":row.get::<_,String>("purpose"),"status":row.get::<_,String>("status"),"policy":row.get::<_,Value>("policy"),"requested_policy":row.get::<_,Value>("requested_policy"),"revision":row.get::<_,i64>("version"),"policy_revision":row.get::<_,i64>("revision"),"expires_at":row.get::<_,Option<DateTime<Utc>>>("expires_at"),"created_at":row.get::<_,DateTime<Utc>>("created_at"),"updated_at":row.get::<_,DateTime<Utc>>("updated_at")})
}
pub(crate) async fn console_role(pool: &Pool, user: &UserBaseI) -> Result<String> {
    if user.role == 1 {
        return Ok("admin".into());
    }
    Ok(pool
        .get()
        .await?
        .query_opt(
            "SELECT role FROM api_console_grant WHERE user_id=$1",
            &[&user.id],
        )
        .await?
        .map(|r| r.get("role"))
        .unwrap_or_else(|| "developer".into()))
}
async fn app<C: GenericClient + Sync>(
    c: &C,
    id: Uuid,
    user: &UserBaseI,
    role: &str,
    lock: bool,
) -> Result<Row> {
    let sql = format!(
        "SELECT * FROM api_client WHERE client_id=$1 AND ($2 OR owner_user_id=$3) {}",
        if lock { "FOR UPDATE" } else { "" }
    );
    c.query_opt(
        &sql,
        &[
            &id,
            &matches!(role, "admin" | "operator" | "auditor"),
            &user.id,
        ],
    )
    .await?
    .ok_or_else(ApiError::missing)
}
fn require_admin(role: &str) -> Result<()> {
    if role != "admin" {
        Err(ApiError::forbidden())
    } else {
        Ok(())
    }
}
fn can_operate(row: &Row, user: &UserBaseI, role: &str) -> Result<()> {
    if role == "auditor"
        || (!matches!(role, "admin" | "operator") && row.get::<_, i32>("owner_user_id") != user.id)
    {
        Err(ApiError::forbidden())
    } else {
        Ok(())
    }
}
fn revision(row: &Row, v: &Value) -> Result<()> {
    if v.get("expected_revision").and_then(Value::as_i64) != Some(row.get("version")) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "revision_conflict",
            "配置已变更，请刷新后重试",
        ));
    }
    Ok(())
}
pub(crate) async fn handle(
    req: HttpRequest,
    body: web::Bytes,
    pool: web::Data<Pool>,
    es: web::Data<crate::elasticsearch::ElasticsearchService>,
    user: UserBaseI,
) -> HttpResponse {
    let role = match console_role(&pool, &user).await {
        Ok(r) => r,
        Err(e) => return response(&req, Err(e)),
    };
    let tail = req.match_info().get("tail").unwrap_or("").trim_matches('/');
    if tail == "openapi.json" && req.method().as_str() == "GET" {
        return HttpResponse::Ok().json(catalog::openapi());
    }
    if req.method().as_str() == "GET" && tail.starts_with("documentation/") {
        let markdown = match tail {
            "documentation/integration" => include_str!("../../docs/OPEN_API.md"),
            "documentation/management" => include_str!("../../docs/OPEN_API_MANAGEMENT.md"),
            "documentation/implementation" => include_str!("../../docs/OPEN_API_IMPLEMENTATION.md"),
            _ => return response(&req, Err(ApiError::missing())),
        };
        return response(&req, Ok(json!({"markdown":markdown})));
    }
    let value = match json_body(&body) {
        Ok(v) => v,
        Err(e) => return response(&req, Err(e)),
    };
    if tail == "step-up" && req.method().as_str() == "POST" {
        return response(&req, step_up(&req, &pool, &user, &value).await);
    }
    let sensitive = req.method().as_str() != "GET"
        && (tail.contains("/credentials")
            || tail.ends_with("/review")
            || tail.ends_with("/state")
            || tail == "settings"
            || tail.starts_with("roles/")
            || (value.get("policy").is_some() || value.get("expires_at").is_some())
                && req.method().as_str() == "PATCH");
    if sensitive && let Err(e) = require_step_up(&req, &pool, &user).await {
        return response(&req, Err(e));
    }
    let result = if let ["apps", id, "invoke"] = tail
        .trim_matches('/')
        .split('/')
        .collect::<Vec<_>>()
        .as_slice()
    {
        invoke(&req, &pool, &es, &user, &role, id, &value)
            .await
            .map_err(|mut error| {
                // An unavailable application credential does not expire the Web session.
                if error.status == StatusCode::UNAUTHORIZED {
                    error.status = StatusCode::FORBIDDEN;
                }
                error
            })
    } else {
        dispatch(&req, &pool, &user, &role, tail, &value).await
    };
    if let Ok(value) = &result
        && let Some(download) = super::business::download_response(&req, value)
    {
        return download;
    }
    response(&req, result)
}
fn session_hash(req: &HttpRequest) -> Result<String> {
    use actix_web::HttpMessage;
    let session = req
        .extensions()
        .get::<crate::admin::UserSession>()
        .cloned()
        .ok_or_else(auth::unauthorized)?;
    Ok(model::fingerprint(session.session.as_bytes()))
}
pub(crate) async fn require_step_up(
    req: &HttpRequest,
    pool: &Pool,
    user: &UserBaseI,
) -> Result<()> {
    if pool.get().await?.query_opt("SELECT user_id FROM api_console_verification WHERE session_hash=$1 AND user_id=$2 AND expires_at>NOW()",&[&session_hash(req)?,&user.id]).await?.is_none(){return Err(ApiError::new(StatusCode::FORBIDDEN,"step_up_required","请重新验证密码及已启用的 2FA，验证有效期为 5 分钟"));}
    Ok(())
}
pub(crate) async fn step_up(
    req: &HttpRequest,
    pool: &Pool,
    user: &UserBaseI,
    v: &Value,
) -> Result<Value> {
    allowed_keys(v, &["password", "totp"])?;
    let password = v["password"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .ok_or_else(|| ApiError::bad("请输入密码"))?;
    let c = pool.get().await?;
    if c.query_opt("INSERT INTO api_console_verification_attempt(user_id,bucket_start,attempts) VALUES($1,date_trunc('minute',NOW()),1) ON CONFLICT(user_id,bucket_start) DO UPDATE SET attempts=api_console_verification_attempt.attempts+1 WHERE api_console_verification_attempt.attempts<5 RETURNING attempts",&[&user.id]).await?.is_none(){return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS,"verification_rate_limited","验证次数过多，请一分钟后重试"));}
    drop(c);
    let info = crate::identity::get_password_and_id_from_database(pool, &user.username)
        .await
        .map_err(|_| ApiError::unavailable())?
        .ok_or_else(auth::unauthorized)?;
    if info.0 != user.id || !crate::identity::verify_password(password, &info.1) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "verification_failed",
            "密码或验证码无效",
        ));
    }
    if user.enable_2fa {
        let config = req
            .app_data::<web::Data<crate::config::ServerConfig>>()
            .ok_or_else(ApiError::unavailable)?;
        let totp = crate::admin::totp_struct(user.username.clone(), &config.encrypt_key, pool)
            .await
            .map_err(|_| ApiError::unavailable())?
            .ok_or_else(auth::unauthorized)?;
        if !totp
            .check_current(v["totp"].as_str().unwrap_or(""))
            .map_err(|_| ApiError::unavailable())?
        {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "verification_failed",
                "密码或验证码无效",
            ));
        }
    }
    let c = pool.get().await?;
    c.execute("INSERT INTO api_console_verification(session_hash,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '5 minutes') ON CONFLICT(session_hash) DO UPDATE SET expires_at=EXCLUDED.expires_at",&[&session_hash(req)?,&user.id]).await?;
    auth::audit(
        &c,
        None,
        "user",
        &user.id.to_string(),
        "console.step_up",
        None,
        Some(request_id(req)),
        &json!({"verified":true}),
    )
    .await?;
    Ok(json!({"verified":true,"expires_in":300}))
}
async fn invoke(
    req: &HttpRequest,
    pool: &Pool,
    es: &crate::elasticsearch::ElasticsearchService,
    user: &UserBaseI,
    role: &str,
    id: &str,
    v: &Value,
) -> Result<Value> {
    allowed_keys(v, &["credential_id", "method", "path", "payload"])?;
    let c = pool.get().await?;
    let row = app(&c, model::parse_uuid(id)?, user, role, false).await?;
    can_operate(&row, user, role)?;
    let credential = model::parse_uuid(
        v["credential_id"]
            .as_str()
            .ok_or_else(|| ApiError::bad("请选择有效凭据"))?,
    )?;
    let (p, _, ranges) = auth::load(pool, credential).await?;
    if p.client_pk != row.get::<_, i32>("id") {
        return Err(ApiError::missing());
    }
    let ip = crate::client_ip::request_ip(req);
    if !auth::source_allowed(&ranges, ip) || !auth::source_allowed(&p.policy.ip_allowlist, ip) {
        return Err(ApiError::forbidden());
    }
    let path = text(v, "path", 2048)?;
    if !path.starts_with('/') || path.contains(['?', '#']) {
        return Err(ApiError::bad("path 必须为接口相对路径，不含查询串"));
    }
    let method = text(v, "method", 10)?;
    let endpoint =
        catalog::resolve(&method, path.trim_start_matches('/')).ok_or_else(ApiError::missing)?;
    if !p.has(endpoint.scope) {
        return Err(ApiError::forbidden());
    }
    let payload = v.get("payload").cloned().unwrap_or_else(|| json!({}));
    drop(c);
    auth::category_quota(
        pool,
        &p,
        "requests.minute",
        p.policy.requests_per_minute,
        false,
    )
    .await?;
    auth::category_quota(pool, &p, "requests.day", p.policy.requests_per_day, true).await?;
    let started = std::time::Instant::now();
    let result = super::business::dispatch_at(
        req,
        payload.to_string().as_bytes(),
        pool,
        es,
        &p,
        &endpoint,
        &path,
    )
    .await;
    let (status, reason) = match &result {
        Ok(_) => (200, None),
        Err(e) => (e.status.as_u16(), Some(e.code)),
    };
    auth::log_call(
        pool,
        req,
        Some(&p),
        endpoint.path,
        status,
        reason,
        started.elapsed(),
    )
    .await;
    let c = pool.get().await?;
    auth::audit(
        &c,
        Some(p.client_pk),
        "user",
        &user.id.to_string(),
        "console.invoke",
        Some(endpoint.path),
        Some(request_id(req)),
        &json!({"method":method,"credential_id":credential,"status":status}),
    )
    .await?;
    result
}
async fn dispatch(
    req: &HttpRequest,
    pool: &Pool,
    user: &UserBaseI,
    role: &str,
    tail: &str,
    v: &Value,
) -> Result<Value> {
    let parts = tail.trim_matches('/').split('/').collect::<Vec<_>>();
    let method = req.method().as_str();
    let mut c = pool.get().await?;
    match (method, parts.as_slice()) {
        ("GET", ["session"]) => Ok(
            json!({"role":role,"can_manage":matches!(role,"admin"|"operator"),"can_approve":role=="admin"}),
        ),
        ("GET", ["catalog"]) => Ok(
            json!({"endpoints":catalog::ENDPOINTS,"scopes":model::SCOPES,"fields":model::FIELDS,"event_types":model::EVENT_TYPES,"default_policy":Policy::default()}),
        ),
        ("GET", ["settings"]) => {
            require_admin(role)?;
            let row = c
                .query_one("SELECT document,revision FROM api_platform_settings", &[])
                .await?;
            Ok(
                json!({"document":row.get::<_,Value>("document"),"revision":row.get::<_,i64>("revision")}),
            )
        }
        ("PUT", ["settings"]) => {
            require_admin(role)?;
            allowed_keys(v, &["document", "expected_revision"])?;
            let document = v
                .get("document")
                .ok_or_else(|| ApiError::bad("缺少 document"))?;
            allowed_keys(
                document,
                &[
                    "enabled",
                    "retention_days",
                    "audit_retention_days",
                    "webhook_allowed_hosts",
                ],
            )?;
            if document["enabled"].as_bool().is_none()
                || document["retention_days"]
                    .as_i64()
                    .is_none_or(|n| !(1..=90).contains(&n))
                || document["audit_retention_days"]
                    .as_i64()
                    .is_none_or(|n| !(30..=730).contains(&n))
            {
                return Err(ApiError::bad("平台设置无效"));
            }
            let hosts: Vec<String> = serde_json::from_value(
                document
                    .get("webhook_allowed_hosts")
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            )
            .map_err(|_| ApiError::bad("回调域名列表无效"))?;
            if hosts.len() > 100 || hosts.iter().any(|h| model::normalize_domain(h).is_err()) {
                return Err(ApiError::bad("回调域名必须为明确域名，最多 100 项"));
            }
            let tx = c.transaction().await?;
            let row=tx.query_opt("UPDATE api_platform_settings SET document=$1,revision=revision+1,updated_at=NOW() WHERE revision=$2 RETURNING revision",&[document,&v["expected_revision"].as_i64().unwrap_or(-1)]).await?.ok_or_else(||ApiError::new(StatusCode::CONFLICT,"revision_conflict","设置已被修改"))?;
            auth::audit(
                &tx,
                None,
                "user",
                &user.id.to_string(),
                "platform.settings",
                None,
                Some(request_id(req)),
                document,
            )
            .await?;
            tx.commit().await?;
            Ok(json!({"revision":row.get::<_,i64>("revision")}))
        }
        ("GET", ["apps"]) => {
            let rows=c.query("SELECT * FROM api_client WHERE $1 OR owner_user_id=$2 ORDER BY created_at DESC LIMIT 200",&[&matches!(role,"admin"|"operator"|"auditor"),&user.id]).await?;
            Ok(json!({"items":rows.iter().map(application).collect::<Vec<_>>(),"limit":200}))
        }
        ("POST", ["apps"]) => {
            if role == "auditor" {
                return Err(ApiError::forbidden());
            }
            allowed_keys(
                v,
                &[
                    "name",
                    "purpose",
                    "kind",
                    "environment",
                    "owner_user_id",
                    "policy",
                ],
            )?;
            let name = text(v, "name", 100)?;
            let purpose = text(v, "purpose", 2000)?;
            let kind = v["kind"].as_str().unwrap_or("personal");
            let environment = v["environment"].as_str().unwrap_or("production");
            if !matches!(kind, "personal" | "partner")
                || !matches!(environment, "production" | "sandbox")
            {
                return Err(ApiError::bad("应用类型或环境无效"));
            }
            let owner = v["owner_user_id"]
                .as_i64()
                .map(i32::try_from)
                .transpose()
                .map_err(|_| ApiError::bad("owner_user_id 无效"))?
                .unwrap_or(user.id);
            if (kind == "partner" || owner != user.id) && role != "admin" {
                return Err(ApiError::forbidden());
            }
            let policy: Policy = serde_json::from_value(
                v.get("policy")
                    .cloned()
                    .unwrap_or_else(|| json!(Policy::default())),
            )
            .map_err(|_| ApiError::bad("策略格式无效"))?;
            policy.validate()?;
            let tx = c.transaction().await?;
            tx.query_opt("SELECT id FROM users WHERE id=$1 AND disabled_at IS NULL AND deleted_at IS NULL AND NOT limit_login AND (role=1 OR (role=2 AND access_policy IS NULL))",&[&owner]).await?.ok_or_else(||ApiError::bad("责任用户不可用"))?;
            tx.execute("SELECT pg_advisory_xact_lock(912311,$1)", &[&owner])
                .await?;
            let count: i64 = tx
                .query_one(
                    "SELECT COUNT(*) FROM api_client WHERE owner_user_id=$1 AND status<>'archived'",
                    &[&owner],
                )
                .await?
                .get(0);
            if count >= 20 {
                return Err(ApiError::bad("每个用户最多 20 个未归档应用"));
            }
            let id = Uuid::now_v7();
            let requested = json!(policy);
            let empty = json!({"scopes":[],"fields":[],"data_mode":"application"});
            let row=tx.query_one("INSERT INTO api_client(client_id,owner_user_id,name,kind,environment,purpose,policy,requested_policy) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *",&[&id,&owner,&name,&kind,&environment,&purpose,&empty,&requested]).await?;
            let pk: i32 = row.get("id");
            tx.execute("INSERT INTO api_approval_request(id,client_id,requested_by,requested_policy,reason) VALUES($1,$2,$3,$4,$5)",&[&Uuid::now_v7(),&pk,&user.id,&requested,&purpose]).await?;
            auth::audit(
                &tx,
                Some(pk),
                "user",
                &user.id.to_string(),
                "application.request",
                Some(&id.to_string()),
                Some(request_id(req)),
                &requested,
            )
            .await?;
            tx.commit().await?;
            Ok(application(&row))
        }
        ("GET", ["apps", id]) => {
            let row = app(&c, model::parse_uuid(id)?, user, role, false).await?;
            let pk: i32 = row.get("id");
            let keys=c.query("SELECT id,name,scopes,ip_allowlist,expires_at,revoked_at,last_used_at,created_at FROM api_credential WHERE client_id=$1 ORDER BY created_at DESC LIMIT 100",&[&pk]).await?;
            Ok(
                json!({"application":application(&row),"credentials":keys.iter().map(|r|json!({"id":r.get::<_,Uuid>("id"),"name":r.get::<_,String>("name"),"scopes":r.get::<_,Vec<String>>("scopes"),"ip_allowlist":r.get::<_,Vec<String>>("ip_allowlist"),"expires_at":r.get::<_,DateTime<Utc>>("expires_at"),"revoked_at":r.get::<_,Option<DateTime<Utc>>>("revoked_at"),"last_used_at":r.get::<_,Option<DateTime<Utc>>>("last_used_at"),"created_at":r.get::<_,DateTime<Utc>>("created_at")})).collect::<Vec<_>>()}),
            )
        }
        ("PATCH", ["apps", id]) => {
            allowed_keys(
                v,
                &[
                    "name",
                    "purpose",
                    "policy",
                    "expected_revision",
                    "expires_at",
                ],
            )?;
            let tx = c.transaction().await?;
            let row = app(&tx, model::parse_uuid(id)?, user, role, true).await?;
            can_operate(&row, user, role)?;
            revision(&row, v)?;
            let pk: i32 = row.get("id");
            let before = application(&row);
            let name = v
                .get("name")
                .map(|_| text(v, "name", 100))
                .transpose()?
                .unwrap_or_else(|| row.get("name"));
            let purpose = v
                .get("purpose")
                .map(|_| text(v, "purpose", 2000))
                .transpose()?
                .unwrap_or_else(|| row.get("purpose"));
            let policy = if let Some(p) = v.get("policy") {
                require_admin(role)?;
                let policy: Policy =
                    serde_json::from_value(p.clone()).map_err(|_| ApiError::bad("策略格式无效"))?;
                policy.validate()?;
                json!(policy)
            } else {
                row.get("policy")
            };
            let expires: Option<DateTime<Utc>> = if let Some(e) = v.get("expires_at") {
                require_admin(role)?;
                if e.is_null() {
                    None
                } else {
                    Some(
                        serde_json::from_value(e.clone())
                            .map_err(|_| ApiError::bad("expires_at 格式无效"))?,
                    )
                }
            } else {
                row.get("expires_at")
            };
            let updated=tx.query_one("UPDATE api_client SET name=$2,purpose=$3,policy=$4,expires_at=$5,version=version+1,revision=revision+CASE WHEN policy IS DISTINCT FROM $4 OR expires_at IS DISTINCT FROM $5 THEN 1 ELSE 0 END,updated_at=NOW() WHERE id=$1 RETURNING *",&[&pk,&name,&purpose,&policy,&expires]).await?;
            if updated.get::<_, i64>("revision") != row.get::<_, i64>("revision") {
                tx.execute("INSERT INTO api_policy_revision(client_id,revision,policy,changed_by) VALUES($1,$2,$3,$4)",&[&pk,&updated.get::<_,i64>("revision"),&policy,&user.id]).await?;
            }
            auth::audit(
                &tx,
                Some(pk),
                "user",
                &user.id.to_string(),
                "application.update",
                Some(id),
                Some(request_id(req)),
                &json!({"before":before,"after":application(&updated)}),
            )
            .await?;
            tx.commit().await?;
            Ok(application(&updated))
        }
        ("POST", ["apps", id, "state"]) => {
            allowed_keys(v, &["status", "expected_revision"])?;
            let tx = c.transaction().await?;
            let row = app(&tx, model::parse_uuid(id)?, user, role, true).await?;
            can_operate(&row, user, role)?;
            revision(&row, v)?;
            let status = text(v, "status", 20)?;
            if !matches!(status.as_str(), "active" | "paused" | "archived") {
                return Err(ApiError::bad("状态无效"));
            }
            if status == "active"
                && (role != "admin"
                    || matches!(
                        row.get::<_, String>("status").as_str(),
                        "pending" | "archived"
                    ))
            {
                return Err(ApiError::forbidden());
            }
            let pk: i32 = row.get("id");
            let updated=tx.query_one("UPDATE api_client SET status=$2,revision=revision+1,version=version+1,updated_at=NOW() WHERE id=$1 RETURNING *",&[&pk,&status]).await?;
            if status == "archived" {
                tx.execute("UPDATE api_credential SET revoked_at=COALESCE(revoked_at,NOW()) WHERE client_id=$1",&[&pk]).await?;
            }
            auth::audit(
                &tx,
                Some(pk),
                "user",
                &user.id.to_string(),
                "application.state",
                Some(id),
                Some(request_id(req)),
                &json!({"before":row.get::<_,String>("status"),"after":status}),
            )
            .await?;
            tx.commit().await?;
            Ok(application(&updated))
        }
        ("POST", ["apps", id, "requests"]) => {
            allowed_keys(v, &["policy", "reason"])?;
            let tx = c.transaction().await?;
            let row = app(&tx, model::parse_uuid(id)?, user, role, true).await?;
            can_operate(&row, user, role)?;
            let policy: Policy = serde_json::from_value(v["policy"].clone())
                .map_err(|_| ApiError::bad("策略格式无效"))?;
            policy.validate()?;
            let reason = text(v, "reason", 2000)?;
            let pk: i32 = row.get("id");
            let policy = json!(policy);
            let id = Uuid::now_v7();
            if tx
                .query_opt(
                    "SELECT id FROM api_approval_request WHERE client_id=$1 AND status='pending'",
                    &[&pk],
                )
                .await?
                .is_some()
            {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "request_pending",
                    "已有待审核申请",
                ));
            }
            tx.execute("INSERT INTO api_approval_request(id,client_id,requested_by,requested_policy,reason) VALUES($1,$2,$3,$4,$5)",&[&id,&pk,&user.id,&policy,&reason]).await?;
            tx.execute(
                "UPDATE api_client SET requested_policy=$2 WHERE id=$1",
                &[&pk, &policy],
            )
            .await?;
            auth::audit(
                &tx,
                Some(pk),
                "user",
                &user.id.to_string(),
                "policy.request",
                Some(&id.to_string()),
                Some(request_id(req)),
                &policy,
            )
            .await?;
            tx.commit().await?;
            Ok(json!({"id":id,"status":"pending"}))
        }
        ("GET", ["approvals"]) => {
            let rows=c.query("SELECT r.*,a.client_id AS public_client_id,a.name FROM api_approval_request r JOIN api_client a ON a.id=r.client_id WHERE $1 OR a.owner_user_id=$2 ORDER BY r.created_at DESC LIMIT 200",&[&matches!(role,"admin"|"operator"|"auditor"),&user.id]).await?;
            Ok(
                json!({"items":rows.iter().map(|r|json!({"id":r.get::<_,Uuid>("id"),"client_id":r.get::<_,Uuid>("public_client_id"),"name":r.get::<_,String>("name"),"requested_policy":r.get::<_,Value>("requested_policy"),"reason":r.get::<_,String>("reason"),"status":r.get::<_,String>("status"),"review_note":r.get::<_,Option<String>>("review_note"),"created_at":r.get::<_,DateTime<Utc>>("created_at")})).collect::<Vec<_>>()}),
            )
        }
        ("POST", ["approvals", id, "review"]) => {
            require_admin(role)?;
            allowed_keys(v, &["approved", "policy", "note"])?;
            let tx = c.transaction().await?;
            let id = model::parse_uuid(id)?;
            let r=tx.query_opt("SELECT * FROM api_approval_request WHERE id=$1 AND status='pending' FOR UPDATE",&[&id]).await?.ok_or_else(ApiError::missing)?;
            let approved = v["approved"]
                .as_bool()
                .ok_or_else(|| ApiError::bad("缺少 approved"))?;
            let pk: i32 = r.get("client_id");
            let status = if approved { "approved" } else { "rejected" };
            let note = v["note"].as_str().unwrap_or("");
            if note.len() > 2000 {
                return Err(ApiError::bad("审批意见过长"));
            }
            if approved {
                let policy: Policy = serde_json::from_value(
                    v.get("policy")
                        .cloned()
                        .unwrap_or_else(|| r.get("requested_policy")),
                )
                .map_err(|_| ApiError::bad("策略无效"))?;
                policy.validate()?;
                let policy = json!(policy);
                let updated=tx.query_opt("UPDATE api_client SET policy=$2,status='active',revision=revision+1,version=version+1,updated_at=NOW() WHERE id=$1 AND status<>'archived' RETURNING revision",&[&pk,&policy]).await?.ok_or_else(ApiError::missing)?;
                tx.execute("INSERT INTO api_policy_revision(client_id,revision,policy,changed_by) VALUES($1,$2,$3,$4)",&[&pk,&updated.get::<_,i64>("revision"),&policy,&user.id]).await?;
            }
            tx.execute("UPDATE api_approval_request SET status=$2,reviewed_by=$3,review_note=$4,reviewed_at=NOW() WHERE id=$1",&[&id,&status,&user.id,&note]).await?;
            auth::audit(
                &tx,
                Some(pk),
                "user",
                &user.id.to_string(),
                "policy.review",
                Some(&id.to_string()),
                Some(request_id(req)),
                &json!({"approved":approved,"note":note,"policy":v.get("policy")}),
            )
            .await?;
            tx.commit().await?;
            Ok(json!({"id":id,"status":status}))
        }
        ("POST", ["apps", id, "credentials"]) => {
            issue(req, &mut c, user, role, model::parse_uuid(id)?, v, None).await
        }
        ("POST", ["apps", id, "credentials", key, "rotate"]) => {
            issue(
                req,
                &mut c,
                user,
                role,
                model::parse_uuid(id)?,
                v,
                Some(model::parse_uuid(key)?),
            )
            .await
        }
        ("POST", ["apps", id, "credentials", key, "revoke"]) => {
            let tx = c.transaction().await?;
            let row = app(&tx, model::parse_uuid(id)?, user, role, true).await?;
            can_operate(&row, user, role)?;
            let pk: i32 = row.get("id");
            let key = model::parse_uuid(key)?;
            if tx.execute("UPDATE api_credential SET revoked_at=COALESCE(revoked_at,NOW()) WHERE id=$1 AND client_id=$2",&[&key,&pk]).await?==0{return Err(ApiError::missing());}
            auth::audit(
                &tx,
                Some(pk),
                "user",
                &user.id.to_string(),
                "credential.revoke",
                Some(&key.to_string()),
                Some(request_id(req)),
                &json!({}),
            )
            .await?;
            tx.commit().await?;
            Ok(json!({"revoked":true}))
        }
        ("GET", ["overview"]) => {
            let all = matches!(role, "admin" | "operator" | "auditor");
            let apps=c.query_one("SELECT COUNT(*) AS total,COUNT(*) FILTER(WHERE status='active') AS active,COUNT(*) FILTER(WHERE status='pending') AS pending FROM api_client WHERE $1 OR owner_user_id=$2",&[&all,&user.id]).await?;
            let calls=c.query_one("SELECT COUNT(*) AS calls,COUNT(*) FILTER(WHERE l.status>=400) AS errors,COALESCE(percentile_cont(0.95) WITHIN GROUP(ORDER BY duration_ms),0)::FLOAT8 AS p95 FROM api_call_log l JOIN api_client a ON a.id=l.client_id WHERE l.created_at>NOW()-INTERVAL '24 hours' AND ($1 OR a.owner_user_id=$2)",&[&all,&user.id]).await?;
            Ok(
                json!({"applications":apps.get::<_,i64>("total"),"active":apps.get::<_,i64>("active"),"pending":apps.get::<_,i64>("pending"),"calls":calls.get::<_,i64>("calls"),"errors":calls.get::<_,i64>("errors"),"p95_ms":calls.get::<_,f64>("p95")}),
            )
        }
        ("GET", ["logs"])
        | ("GET", ["audit"])
        | ("GET", ["jobs"])
        | ("GET", ["deliveries"])
        | ("GET", ["usage"]) => {
            let query = web::Query::<std::collections::HashMap<String, String>>::from_query(
                req.query_string(),
            )
            .map_err(|_| ApiError::bad("查询参数无效"))?;
            let client = query
                .get("client_id")
                .map(|s| model::parse_uuid(s))
                .transpose()?;
            let after = query
                .get("after")
                .map(|s| s.parse::<i64>().map_err(|_| ApiError::bad("after 无效")))
                .transpose()?
                .unwrap_or(i64::MAX);
            let all = matches!(role, "admin" | "operator" | "auditor");
            let table = match parts[0] {
                "logs" => "api_call_log",
                "audit" => "api_audit",
                "jobs" => "api_job",
                "usage" => "api_usage_bucket",
                _ => "api_webhook_delivery",
            };
            let sql=match parts[0] {
                "deliveries"=>"SELECT jsonb_build_object('id',d.id,'client_id',a.client_id,'status',d.status,'attempt_count',d.attempt_count,'response_status',d.response_status,'last_error',d.last_error,'created_at',d.created_at) AS item FROM api_webhook_delivery d JOIN api_webhook w ON w.id=d.webhook_id JOIN api_client a ON a.id=w.client_id WHERE ($1 OR a.owner_user_id=$2) AND ($3::UUID IS NULL OR a.client_id=$3) ORDER BY d.created_at DESC LIMIT 100".to_string(),
                "jobs"=>"SELECT (to_jsonb(d)-'artifact'-'spec'-'result'-'claim_token'-'credential_id'-'client_id')||jsonb_build_object('client_id',a.client_id) AS item FROM api_job d JOIN api_client a ON a.id=d.client_id WHERE ($1 OR a.owner_user_id=$2) AND ($3::UUID IS NULL OR a.client_id=$3) ORDER BY d.created_at DESC LIMIT 100".to_string(),
                "usage"=>"SELECT (to_jsonb(d)-'client_id')||jsonb_build_object('client_id',a.client_id) AS item FROM api_usage_bucket d JOIN api_client a ON a.id=d.client_id WHERE ($1 OR a.owner_user_id=$2) AND ($3::UUID IS NULL OR a.client_id=$3) AND d.bucket_start>NOW()-INTERVAL '31 days' ORDER BY d.bucket_start DESC LIMIT 500".to_string(),
                _=>format!("SELECT (to_jsonb(d)-'client_id')||jsonb_build_object('client_id',a.client_id) AS item FROM {table} d JOIN api_client a ON a.id=d.client_id WHERE ($1 OR a.owner_user_id=$2) AND ($3::UUID IS NULL OR a.client_id=$3) AND d.id<$4 ORDER BY d.id DESC LIMIT 100"),
            };
            let rows = if matches!(parts[0], "logs" | "audit") {
                c.query(&sql, &[&all, &user.id, &client, &after]).await?
            } else {
                c.query(&sql, &[&all, &user.id, &client]).await?
            };
            let items = rows
                .iter()
                .map(|r| r.get::<_, Value>("item"))
                .collect::<Vec<_>>();
            let next = items.last().and_then(|v| v["id"].as_i64());
            Ok(json!({"items":items,"next_after":next}))
        }
        ("GET", ["roles"]) => {
            require_admin(role)?;
            let rows=c.query("SELECT g.user_id,g.role,u.username FROM api_console_grant g JOIN users u ON u.id=g.user_id ORDER BY g.user_id",&[]).await?;
            Ok(
                json!({"items":rows.iter().map(|r|json!({"user_id":r.get::<_,i32>("user_id"),"role":r.get::<_,String>("role"),"username":r.get::<_,String>("username")})).collect::<Vec<_>>()}),
            )
        }
        ("PUT", ["roles", id]) => {
            require_admin(role)?;
            allowed_keys(v, &["role"])?;
            let uid = id
                .parse::<i32>()
                .map_err(|_| ApiError::bad("用户 ID 无效"))?;
            let role = v["role"].as_str().unwrap_or("");
            if !matches!(role, "operator" | "auditor" | "developer") {
                return Err(ApiError::bad("管理角色无效"));
            }
            let tx = c.transaction().await?;
            tx.query_opt(
                "SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL",
                &[&uid],
            )
            .await?
            .ok_or_else(|| ApiError::bad("用户不存在"))?;
            if role == "developer" {
                tx.execute("DELETE FROM api_console_grant WHERE user_id=$1", &[&uid])
                    .await?;
            } else {
                tx.execute("INSERT INTO api_console_grant(user_id,role) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET role=EXCLUDED.role",&[&uid,&role]).await?;
            }
            auth::audit(
                &tx,
                None,
                "user",
                &user.id.to_string(),
                "console.role",
                Some(&uid.to_string()),
                Some(request_id(req)),
                &json!({"role":role}),
            )
            .await?;
            tx.commit().await?;
            Ok(json!({"role":role}))
        }
        _ => Err(ApiError::missing()),
    }
}
async fn issue(
    req: &HttpRequest,
    c: &mut deadpool_postgres::Object,
    user: &UserBaseI,
    role: &str,
    app_id: Uuid,
    v: &Value,
    rotate: Option<Uuid>,
) -> Result<Value> {
    allowed_keys(
        v,
        &[
            "name",
            "scopes",
            "ip_allowlist",
            "expires_days",
            "overlap_hours",
        ],
    )?;
    let tx = c.transaction().await?;
    let row = app(&tx, app_id, user, role, true).await?;
    can_operate(&row, user, role)?;
    if row.get::<_, String>("status") != "active" {
        return Err(ApiError::bad("应用尚未激活"));
    }
    let pk: i32 = row.get("id");
    let policy: Policy =
        serde_json::from_value(row.get("policy")).map_err(|_| ApiError::unavailable())?;
    let name = text(v, "name", 100)?;
    let scopes: Vec<String> = serde_json::from_value(
        v.get("scopes")
            .cloned()
            .unwrap_or_else(|| json!(policy.scopes)),
    )
    .map_err(|_| ApiError::bad("权限格式无效"))?;
    if scopes.is_empty() || scopes.iter().any(|s| !policy.scopes.contains(s)) {
        return Err(ApiError::forbidden());
    }
    let ips: Vec<String> =
        serde_json::from_value(v.get("ip_allowlist").cloned().unwrap_or_else(|| json!([])))
            .map_err(|_| ApiError::bad("来源限制无效"))?;
    if ips.len() > 64 || ips.iter().any(|s| s.parse::<ipnet::IpNet>().is_err()) {
        return Err(ApiError::bad("来源 CIDR 无效"));
    }
    let days = v["expires_days"].as_i64().unwrap_or(90);
    if !(1..=365).contains(&days) {
        return Err(ApiError::bad("有效期必须为 1–365 天"));
    }
    let count:i64=tx.query_one("SELECT COUNT(*) FROM api_credential WHERE client_id=$1 AND revoked_at IS NULL AND expires_at>NOW()",&[&pk]).await?.get(0);
    if count >= 20 && rotate.is_none() {
        return Err(ApiError::bad("活跃凭据最多 20 个"));
    }
    if let Some(old) = rotate {
        let overlap = v["overlap_hours"].as_i64().unwrap_or(0);
        if !(0..=24).contains(&overlap) {
            return Err(ApiError::bad("轮换重叠期最多 24 小时"));
        }
        let changed = if overlap == 0 {
            tx.execute("UPDATE api_credential SET revoked_at=NOW() WHERE id=$1 AND client_id=$2 AND revoked_at IS NULL",&[&old,&pk]).await?
        } else {
            tx.execute("UPDATE api_credential SET expires_at=LEAST(expires_at,NOW()+$3*INTERVAL '1 hour') WHERE id=$1 AND client_id=$2 AND revoked_at IS NULL",&[&old,&pk,&(overlap as f64)]).await?
        };
        if changed == 0 {
            return Err(ApiError::missing());
        }
    }
    let id = Uuid::now_v7();
    let secret = auth::generate_key(id)?;
    let hash = model::fingerprint(secret.as_bytes());
    let expires = Utc::now() + Duration::days(days);
    tx.execute("INSERT INTO api_credential(id,client_id,name,secret_hash,scopes,ip_allowlist,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)",&[&id,&pk,&name,&hash,&scopes,&ips,&expires]).await?;
    auth::audit(
        &tx,
        Some(pk),
        "user",
        &user.id.to_string(),
        if rotate.is_some() {
            "credential.rotate"
        } else {
            "credential.create"
        },
        Some(&id.to_string()),
        Some(request_id(req)),
        &json!({"name":name,"scopes":scopes,"expires_at":expires,"rotates":rotate}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"id":id,"token":secret,"expires_at":expires,"display_once":true}))
}
