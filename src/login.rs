use actix_web::HttpRequest;
use openssl::base64;
use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::{error, info};
use uuid::Uuid;

use crate::admin::{UserBaseI, get_session_ttl_seconds_from_database};
use crate::identity::UserLoginInfo;
use crate::login_allowlist::login_ip_is_allowed;
use crate::logs::write::error_diagnostics;
use crate::{
    clock::get_unix_epoch_ms, identity::get_password_and_id_from_database,
    identity::verify_password,
};

const SESSION_EXPIRATION_INTERVAL: Duration = Duration::from_secs(60 * 60);
const SESSION_EXPIRATION_BATCH_SIZE: i64 = 5_000;

/// 定期把已过期的活动 Session 标记为软删除，保留记录供安全审计追溯。
pub async fn run_session_expiration(pool: deadpool_postgres::Pool) {
    let mut ticker = tokio::time::interval(SESSION_EXPIRATION_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        match soft_delete_expired_sessions(&pool).await {
            Ok(expired) if expired > 0 => {
                info!(
                    event = "SessionExpiration",
                    expired_sessions = expired,
                    "已将过期会话标记为软删除"
                );
            }
            Ok(_) => {}
            Err(error_value) => {
                let diagnostics = error_diagnostics(error_value.as_ref());
                error!(
                    event = "SessionExpirationError",
                    operation = "expire_sessions",
                    error_kind = "database",
                    error_code = "session_expiration_failed",
                    error_message = %diagnostics.error_message,
                    error_chain = %diagnostics.error_chain,
                    root_cause = %diagnostics.root_cause,
                    error_truncated = diagnostics.error_truncated,
                    retryable = true,
                    outcome = "expired_sessions_retained",
                    batch_size = SESSION_EXPIRATION_BATCH_SIZE,
                    retry_after_ms = SESSION_EXPIRATION_INTERVAL.as_millis() as u64,
                    "标记过期会话失败"
                );
            }
        }
    }
}

async fn soft_delete_expired_sessions(
    pool: &deadpool_postgres::Pool,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let client = pool.get().await?;
    let mut total = 0_u64;

    loop {
        let affected = client
            .execute(
                "WITH expired AS (\
                 SELECT id FROM session \
                 WHERE is_enable = TRUE AND deleted_at IS NULL \
                   AND create_time + ttl::BIGINT * 1000 <= \
                       (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT \
                 ORDER BY (create_time + ttl::BIGINT * 1000) ASC, id ASC \
                 LIMIT $1 FOR UPDATE SKIP LOCKED) \
                 UPDATE session AS s SET is_enable = FALSE, deleted_at = NOW(), \
                     deletion_reason = 'expired', deleted_by_user_id = NULL \
                 FROM expired WHERE s.id = expired.id;",
                &[&SESSION_EXPIRATION_BATCH_SIZE],
            )
            .await?;
        total += affected;
        if affected < SESSION_EXPIRATION_BATCH_SIZE as u64 {
            return Ok(total);
        }
    }
}

pub struct LoginToken {
    pub pool: deadpool_postgres::Pool,
}

pub struct LoginResult {
    pub session: String,
    pub csrf_token: String,
    pub enable_2fa: bool,
    pub session_ttl_seconds: i32,
    pub user_id: i32,
}

#[derive(Debug)]
pub struct LoginIpNotAllowlisted {
    pub user_id: i32,
}

impl fmt::Display for LoginIpNotAllowlisted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("登录来源 IP 不在白名单中")
    }
}

impl Error for LoginIpNotAllowlisted {}

#[derive(Debug)]
pub struct LoginInvalidCredentials;

impl fmt::Display for LoginInvalidCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("登录失败")
    }
}

impl Error for LoginInvalidCredentials {}

pub(crate) struct SessionAuthentication {
    pub(crate) user: UserBaseI,
    pub(crate) csrf_token: String,
}

pub(crate) enum SessionCheck {
    Valid(SessionAuthentication),
    Rejected(&'static str),
}

pub struct SessionInfo<'a> {
    session: String,
    create_time: i64,
    ttl: i32,
    username: &'a str,
}

impl LoginToken {
    ///生成一个session 和 csrftoken 并保存
    pub async fn create_session<'a>(
        &self,
        ttl: i32,
        u_name: &'a str,
        enable_2fa: bool,
    ) -> Result<(SessionInfo<'a>, String), Box<dyn std::error::Error>> {
        let session = SessionInfo {
            session: Uuid::new_v4().to_string(),
            create_time: get_unix_epoch_ms(),
            ttl,
            username: u_name,
        };

        let mut tmp_csrf_token_buffer: [u8; 32] = [0; 32];
        let csrf_token_base64 = match openssl::rand::rand_bytes(&mut tmp_csrf_token_buffer) {
            Ok(_) => base64::encode_block(&tmp_csrf_token_buffer),
            Err(e) => {
                error!(
                    event = "GenerateCSRFTokenError",
                    operation = "generate_csrf_token",
                    error_kind = "cryptography",
                    error_code = "csrf_random_generation_failed",
                    error_message = %e,
                    retryable = false,
                    outcome = "login_failed",
                    username = u_name,
                );
                return Err(e.into());
            }
        };
        match self.save(&session, &csrf_token_base64, enable_2fa).await {
            Ok(_o) => {
                info!(
                    event = "SuccessfulSaveSession",
                    message = "Successful Save Session "
                );
                Ok((session, csrf_token_base64))
            }
            Err(e) => {
                let diagnostics = error_diagnostics(e.as_ref());
                error!(
                    event = "SaveSessionFailed",
                    operation = "create_login_session",
                    error_kind = "database",
                    error_code = "login_session_create_failed",
                    error_message = %diagnostics.error_message,
                    error_chain = %diagnostics.error_chain,
                    root_cause = %diagnostics.root_cause,
                    error_truncated = diagnostics.error_truncated,
                    retryable = false,
                    outcome = "login_failed",
                    username = u_name,
                );
                Err(e)
            }
        }
    }

    ///将token设置为未启用状态
    pub async fn delete(&self, session: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;
        let stmt = transaction
            .prepare(
                "UPDATE session SET is_enable = FALSE, deleted_at = NOW(), \
                 deletion_reason = 'expired', deleted_by_user_id = NULL \
                 WHERE token = $1 AND is_enable = TRUE AND deleted_at IS NULL;",
            )
            .await?;
        transaction.execute(&stmt, &[&session]).await?;
        transaction.commit().await?;
        Ok(())
    }

    ///保存一个token,
    /// 返回result，当成功时为OK
    pub async fn save(
        &self,
        sessioninfo: &SessionInfo<'_>,
        csrftoken: &str,
        enable_2fa: bool,
    ) -> Result<(i32, i32), Box<dyn std::error::Error>> {
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;

        //查找用户的id
        let row = transaction
            .query_opt(
                "SELECT id FROM users WHERE username = $1;",
                &[&sessioninfo.username],
            )
            .await?;

        let row = match row {
            Some(o) => o,
            None => {
                info!(
                    event = "SearchUserIDError",
                    message = "未找到用户或其他错误",
                    data = ?row                           //将返回的row结构化的输出到日志中
                );
                return Err("用户不存在或其他错误".into());
            }
        };

        let userid: i32 = row.get("id");
        //插入一条session,其中包括了用户id token 有效时间，创建时间
        if let Some(r_rows) = transaction.query_opt(
            "INSERT INTO session (user_id, token, csrf_token, ttl, totp_verify_successful, create_time) VALUES ( $1, $2, $3, $4, $5, $6 ) RETURNING id, user_id;",
            &[
                &userid,
                &sessioninfo.session,
                &csrftoken,
                &sessioninfo.ttl,
                &!enable_2fa,
                &sessioninfo.create_time
            ]
        ).await? {
            transaction.commit().await?;
            Ok((r_rows.get::<_, i32>("id"), r_rows.get::<_, i32>("user_id")))
        }
        else {
            error!(
                event = "SaveSessionFailed",
                operation = "insert_login_session",
                error_kind = "data_integrity",
                error_code = "login_session_insert_returned_no_row",
                error_message = "session insert returned no row",
                retryable = false,
                outcome = "login_failed",
                user_id = userid,
            );
            Err("插入数据不正确".into())
        }
    }

    /// 一次只读查询完成 Session、TOTP 与用户状态验证，并返回请求鉴权所需数据。
    /// 已过期 Session 立即拒绝访问，由后台批处理标记为软删除。
    pub(crate) async fn check_token(
        &self,
        session: &str,
        require_totp: bool,
    ) -> Result<SessionCheck, Box<dyn std::error::Error>> {
        let now = get_unix_epoch_ms();
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT u.id, u.username, u.role, u.email, u.limit_login, u.enable_2fa, \
                        u.disabled_at IS NOT NULL AS user_disabled, \
                        u.deleted_at IS NOT NULL AS user_deleted, \
                        s.csrf_token, s.is_enable, s.deleted_at IS NOT NULL AS session_deleted, \
                        s.create_time, s.ttl, s.totp_verify_successful \
                 FROM session s LEFT JOIN users u ON u.id = s.user_id \
                 WHERE s.token = $1 ORDER BY s.is_enable DESC, s.id DESC LIMIT 1;",
                &[&session],
            )
            .await?;

        let Some(row) = row else {
            return Ok(SessionCheck::Rejected("session_not_found"));
        };

        let reason = if !row.get::<_, bool>("is_enable") || row.get::<_, bool>("session_deleted") {
            Some("session_inactive")
        } else if row
            .get::<_, Option<i64>>("create_time")
            .zip(row.get::<_, Option<i32>>("ttl"))
            .and_then(|(created, ttl)| created.checked_add(i64::from(ttl) * 1000))
            .is_none_or(|expires| expires <= now)
        {
            Some("session_expired")
        } else if require_totp && !row.get::<_, bool>("totp_verify_successful") {
            Some("session_totp_pending")
        } else if row.get::<_, Option<i32>>("id").is_none() {
            Some("session_user_missing")
        } else if row.get::<_, bool>("user_disabled")
            || row.get::<_, bool>("user_deleted")
            || row.get::<_, bool>("limit_login")
        {
            Some("session_user_inactive")
        } else {
            None
        };
        if let Some(reason) = reason {
            return Ok(SessionCheck::Rejected(reason));
        }

        Ok(SessionCheck::Valid(SessionAuthentication {
            user: UserBaseI {
                id: row.get("id"),
                username: row.get("username"),
                role: row.get("role"),
                email: row.get("email"),
                limit_login: row.get("limit_login"),
                enable_2fa: row.get("enable_2fa"),
            },
            csrf_token: row.get("csrf_token"),
        }))
    }

    // pub async fn update_session_ttl(&self, session: &str) -> Result<(), Box<dyn std::error::Error>> {
    //     let mut client = self.pool.get().await?;
    //     let transaction = client.transaction().await?;
    //     let stmt = transaction.prepare("UPDATE token FROM session WHERE token = $1 AND ").await?;

    // }
}

/// 该函数用于处理用户登录，接受一个用户名和密码，如果密码校验成功则返回一个session，失败则传递错误
pub async fn user_login(
    username: &str,
    password: &str,
    source_ip: Option<IpAddr>,
    pool: &deadpool_postgres::Pool,
) -> Result<LoginResult, Box<dyn std::error::Error>> {
    let start = Instant::now();

    // 即使用户名不存在也校验密码，预防时序攻击
    let identity = get_password_and_id_from_database(pool, username).await?;
    let identity_found = identity.is_some();
    let (user_id, pwd_hash, user_login_info) = match identity {
        Some(value) => value,
        None => {
            let t = UserLoginInfo {
                username: String::new(),
                role: -1,
                email_address: None,
                twofa: None,
                login_ip_allowlist: Vec::new(),
            };
            // 用户不存在时仍执行 Argon2 校验，避免直接按用户名暴露明显的时序差异。
            (-1_i32, "$argon2id$v=19$m=65536,t=2,p=2$nuz5oKNAIFXP1wPaVW3aQw$9piWt9X5WVTIbCnq2DQuNDbGDhW5s2UnTe9rVWtx3II".to_string(), t)
        }
    };
    tracing::debug!(
        event = "LoginIdentityLoaded",
        duration_ms = start.elapsed().as_millis() as u64
    );

    // 当用户不存在或者是查找用户错误时使用提供的默认密文校验密码
    if verify_password(password, &pwd_hash) && identity_found {
        if !login_ip_is_allowed(&user_login_info.login_ip_allowlist, source_ip) {
            return Err(Box::new(LoginIpNotAllowlisted { user_id }));
        }
        let start = Instant::now();
        let enable_2fa = user_login_info.twofa.map(|_| true).unwrap_or(false);

        let session_ttl_seconds = get_session_ttl_seconds_from_database(pool).await?;
        let login_token = LoginToken { pool: pool.clone() };
        let (session, csrf_token) = login_token
            .create_session(session_ttl_seconds, username, enable_2fa)
            .await?;
        tracing::debug!(
            event = "LoginSessionCreated",
            duration_ms = start.elapsed().as_millis() as u64
        );

        Ok(LoginResult {
            session: session.session,
            csrf_token,
            enable_2fa,
            session_ttl_seconds,
            user_id,
        })
    } else {
        Err(Box::new(LoginInvalidCredentials))
    }
}

/// 该函数用于从 req 中获取 session
///
/// **需要注意生命周期，返回一个 Option<&str> ，其生命周期于传入的 cookie_n 一致**
///
/// 我认为该函数不需要做日志，日志就交给调用者了
pub fn get_session_from_req(req: &HttpRequest, cookie_n: &str) -> Option<String> {
    req.cookie(cookie_n)
        .map(|cookie| cookie.value().to_string())
}
