use chrono::{DateTime, Utc};
use cidr::IpInet;
use deadpool_postgres::Pool;
use lettre::transport::smtp::Error as LettreSmtpError;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use openssl::rand;
use postgres_from_row::FromRow;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
use tokio_postgres::Row;
use totp_rs::{Algorithm, Secret, TOTP};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::audit::{AuditContext, AuditEvent, write as write_audit};
use crate::client_ip::display_ip;
use crate::config::{
    DEFAULT_SESSION_TTL_SECONDS, EmailConfig, MAX_SESSION_TTL_MINUTES, MIN_SESSION_TTL_MINUTES,
    MailSettingsRequest, MailSettingsResponse, NotificationPreferences, PasswordHashConfig,
    ScanSettingsRequest, ScanSettingsResponse, SessionSettingsRequest, SessionSettingsResponse,
    SystemConfig, session_ttl_seconds_from_minutes,
};
use crate::{identity::decrypt_data, identity::encrypt_data};
use crate::{
    identity::generate_hash_password, identity::generate_scanner_token,
    identity::hash_scanner_token,
};

const DEFAULT_ADMIN_USERNAME: &str = "admin";
const DEFAULT_ADMIN_USERNAME_ENV: &str = "NM_DEFAULT_ADMIN_USERNAME";
const DEFAULT_ADMIN_PASSWORD_LEN: usize = 18;
const DEFAULT_ADMIN_PASSWORD_CHARS: &[u8] =
    b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";
const SMTP_SETTING_TYPE: &str = "smtp";
const NOTIFICATION_SETTING_TYPE: &str = "notification";
const SMTP_SENDER_KEY: &str = "sender_key";
const SECURITY_SETTING_TYPE: &str = "security";
const SESSION_TTL_SETTING_KEY: &str = "session_ttl_seconds";
const SCAN_SETTING_TYPE: &str = "scan";
const DEFAULT_SCAN_PROFILE_SETTING_KEY: &str = "default_profile";
const FALLBACK_SCAN_PROFILE: &str = "legacy";
const MAX_CONCURRENT_SMTP_SENDS: usize = 4;
const BACKGROUND_RETRY_DELAYS: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(4)];
const INTERACTIVE_RETRY_DELAYS: [Duration; 1] = [Duration::from_secs(1)];
static SMTP_SEND_SEMAPHORE: Semaphore = Semaphore::const_new(MAX_CONCURRENT_SMTP_SENDS);

pub enum UserRole {
    System = 0,
    Administrator = 1,
    User = 2,
}

/// TOTP 相关信息
pub struct TotpInfo {
    pub username: String,
    // pub email_address: String,
    pub totp_secret: String,
}

#[derive(Deserialize)]
pub struct VerifyTotp {
    pub token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpBindingRejection {
    SessionIneligible,
    PendingSecretMissing,
    PendingBindingExpired,
    CodeMismatch,
}

impl TotpBindingRejection {
    pub fn reason_code(self) -> &'static str {
        match self {
            Self::SessionIneligible => "totp_bind_session_ineligible",
            Self::PendingSecretMissing => "totp_bind_pending_secret_missing",
            Self::PendingBindingExpired => "totp_bind_expired",
            Self::CodeMismatch => "totp_bind_code_mismatch",
        }
    }
}

pub struct TotpBindingAttempt {
    pub url: String,
    pub attempt_id: Uuid,
    pub expires_at_ms: i64,
}

pub struct TotpBindingConfirmation {
    pub attempt_id: Option<Uuid>,
    pub expires_in_ms: Option<i64>,
    pub rejection: Option<TotpBindingRejection>,
}

/// 接受解绑 2FA 信息
#[derive(Deserialize)]
pub struct Unbind2FAH {
    pub username: String,
}

/// web 添加扫描器
#[derive(Deserialize)]
pub struct AddScanner {
    pub name: String,
    pub location: Option<String>,
    pub remark: Option<String>,
    pub tag: Option<String>,
}

/// 扫描器注册
#[derive(Deserialize, Serialize)]
pub struct ScannerRegisterData {
    pub scanner_id: String,
}

/// web 端创建扫描器后返回的一次性注册凭据
#[derive(Serialize)]
pub struct ScannerRegisterSecret {
    pub scanner_id: String,
    pub registration_token: String,
}

/// 扫描器注册成功后返回的运行凭据
#[derive(Serialize)]
pub struct ScannerRuntimeSecret {
    pub runtime_token: String,
}

#[derive(Debug)]
pub struct ScannerRegistrationUnauthorized;

impl fmt::Display for ScannerRegistrationUnauthorized {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("scanner unauthorized")
    }
}

impl Error for ScannerRegistrationUnauthorized {}

#[derive(Serialize)]
pub struct ScannerInfo {
    pub diagnostics_capabilities: serde_json::Value,
    pub accepting_tasks: bool,
    pub diagnostic_health: String,
    pub diagnostic_dropped_events: i64,
    pub scanner_id: String,
    pub name: Option<String>,
    pub creator: Option<String>,
    pub location: Option<String>,
    pub ip_address: Option<String>,
    pub system_version: Option<String>,
    pub scanner_version: Option<String>,
    pub cpu_model: Option<String>,
    pub cpus: Option<i32>,
    pub ram: Option<i32>,
    pub uptime: Option<i32>,
    pub create_time: Option<DateTime<Utc>>,
    pub register_time: Option<DateTime<Utc>>,
    pub update_time: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub runtime_state: String,
    pub is_online: bool,
    pub current_task_id: Option<String>,
    pub is_run: Option<bool>,
    pub is_enable: Option<bool>,
    pub remark: Option<String>,
    pub tag: Option<String>,
    pub supports_ipv4: bool,
    pub supports_ipv6: bool,
    pub ipv4_ready: bool,
    pub ipv6_ready: bool,
    pub public_ipv4: Option<String>,
    pub public_ipv6: Option<String>,
    pub network_status_reason: Option<serde_json::Value>,
    pub network_capabilities_updated_at: Option<DateTime<Utc>>,
    pub scan_capabilities: serde_json::Value,
    pub scan_capabilities_updated_at: Option<DateTime<Utc>>,
    pub latency: Option<ScannerLatencyInfo>,
}

#[derive(Serialize)]
pub struct ScannerLatencyInfo {
    pub rtt_ms: f64,
    pub network_rtt_ms: f64,
    pub server_processing_ms: f64,
    pub measured_at: DateTime<Utc>,
    pub stale: bool,
    pub severity: String,
}

pub enum ScannerEvent {
    Start = 0,
    Shutdown = 1,
    Normal = 2,
}

/// 扫描器健康数据
#[derive(Deserialize)]
pub struct ScannerHealthData {
    pub scanner_id: Uuid,
    pub status: String,
    pub uptime: u32,
    pub event: String,
}

/// 该函数通过 cookie 获取用户名与其 ID
///
/// FIXME 需要解决 pool 类型错误问题
pub async fn get_user_id_and_name(
    session: &str,
    pool: &deadpool_postgres::Pool,
) -> Result<(i32, i32, String), Box<dyn std::error::Error>> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "SELECT s.user_id, u.username, u.role FROM session s JOIN users u ON s.user_id = u.id \
         WHERE s.token = $1 AND s.is_enable = TRUE AND s.deleted_at IS NULL \
         AND u.limit_login = FALSE \
         AND u.disabled_at IS NULL AND u.deleted_at IS NULL;",
            &[&session],
        )
        .await?;

    Ok((
        row.get::<_, i32>("user_id"),
        row.get::<_, i32>("role"),
        row.get::<_, String>("username"),
    ))
}

/// 检查系统用户数量，该操作在系统启动前执行。
///
/// 一个系统只能有一个系统用户，且为必须项，所以该函数出现错误时则应当直接 panic
pub async fn check_system_user(pool: &deadpool_postgres::Pool) {
    let c = &pool.get().await.unwrap();
    match c
        .query("SELECT * FROM users WHERE role = 0;", &[])
        .await
        .unwrap()
        .len()
    {
        0 => {
            // 创建系统用户
            warn!(
                event = "SystemRoleNotFound",
                path = "fn check_system_role",
                message = "没有找到系统用户，正在创建一个新的系统用户"
            );
            create_system_user(pool).await;
        }
        1 => {
            info!(target: "server::startup", event = "SystemRoleFound", "系统用户检查通过")
        }
        _ => {
            panic!("找到多个系统用户，请手动清理多余的系统用户!");
        }
    }
}

/// 创建系统角色
///
pub async fn create_system_user(pool: &deadpool_postgres::Pool) {
    let mut c = pool.get().await.unwrap();
    let transaction = c.transaction().await.unwrap();
    transaction
        .execute(
            "INSERT INTO users (username, password, role, limit_login) VALUES ($1, $2, $3, $4);",
            &[&"system", &"No Password", &0, &true],
        )
        .await
        .unwrap();
    info!(target: "server::startup",
        event = "CreateSystemUser",
        path = "fn create_system_user",
        message = "创建系统用户成功"
    );
    transaction.commit().await.unwrap();
}

/// 检查管理员用户数量，该操作在系统启动前执行。
///
/// 当没有任何管理员用户时，自动创建一个默认管理员。默认用户名可通过环境变量
/// `NM_DEFAULT_ADMIN_USERNAME` 覆盖，密码会自动生成。
pub async fn check_default_admin_user(
    pool: &deadpool_postgres::Pool,
    pwd_hash_config: PasswordHashConfig,
) {
    let admin_count = {
        let c = pool.get().await.unwrap();
        let row = c
            .query_one("SELECT COUNT(*) AS count FROM users WHERE role = 1;", &[])
            .await
            .unwrap();
        row.get::<_, i64>("count")
    };

    match admin_count {
        0 => {
            warn!(
                event = "AdminRoleNotFound",
                path = "fn check_default_admin_user",
                message = "没有找到管理员用户，正在创建一个默认管理员用户"
            );
            create_default_admin_user(pool, pwd_hash_config).await;
        }
        _ => info!(target: "server::startup", event = "AdminRoleFound", "管理员用户检查通过"),
    }
}

fn default_admin_username() -> String {
    env::var(DEFAULT_ADMIN_USERNAME_ENV)
        .ok()
        .filter(|username| !username.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_ADMIN_USERNAME.to_string())
}

fn generate_admin_password() -> String {
    let mut random_bytes = [0u8; DEFAULT_ADMIN_PASSWORD_LEN];
    rand::rand_bytes(&mut random_bytes).unwrap();

    random_bytes
        .iter()
        .map(|byte| {
            let index = *byte as usize % DEFAULT_ADMIN_PASSWORD_CHARS.len();
            DEFAULT_ADMIN_PASSWORD_CHARS[index] as char
        })
        .collect()
}

/// 重置指定管理员的密码，并使该用户的全部既有会话失效。
///
/// 仅允许重置 `role = 1` 的管理员账户，避免影响系统账户或普通用户。
/// 成功时返回仅应在当前终端显示一次的明文随机密码。
pub async fn reset_admin_password(
    username: &str,
    pool: &deadpool_postgres::Pool,
    pwd_hash_config: PasswordHashConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    let password = generate_admin_password();
    let password_hash = generate_hash_password(&password, pwd_hash_config)
        .map_err(|error| format!("生成密码哈希失败：{:?}", error))?;

    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    let admin = transaction
        .query_opt(
            "SELECT id FROM users WHERE username = $1 AND role = 1 FOR UPDATE;",
            &[&username],
        )
        .await?;

    let Some(admin) = admin else {
        return Err(format!("未找到管理员用户：{}", username).into());
    };
    let admin_id: i32 = admin.get("id");

    let updated = transaction
        .execute(
            "UPDATE users SET password = $1, limit_login = false, limit_at = NULL, \
             limit_time = NULL, login_error_count = 0, last_error_at = NULL \
             WHERE id = $2 AND role = 1;",
            &[&password_hash, &admin_id],
        )
        .await?;
    if updated != 1 {
        return Err(format!("重置管理员密码影响了 {} 行", updated).into());
    }

    transaction
        .execute(
            "UPDATE session SET is_enable = FALSE, deleted_at = NOW(), \
             deletion_reason = 'password_reset', deleted_by_user_id = NULL \
             WHERE user_id = $1 AND is_enable = TRUE AND deleted_at IS NULL;",
            &[&admin_id],
        )
        .await?;
    transaction.commit().await?;

    info!(
        event = "ResetAdminPassword",
        path = "fn reset_admin_password",
        username,
        message = "管理员密码已重置，既有会话已失效"
    );

    Ok(password)
}
/// 创建默认管理员角色。
///
/// 如果默认用户名已被占用，会使用 admin_1、admin_2 等后缀创建用户，避免修改已有账号。
pub async fn create_default_admin_user(
    pool: &deadpool_postgres::Pool,
    pwd_hash_config: PasswordHashConfig,
) {
    let username_prefix = default_admin_username();
    let password = generate_admin_password();
    let password_hash = generate_hash_password(&password, pwd_hash_config).unwrap();

    let mut c = pool.get().await.unwrap();
    let transaction = c.transaction().await.unwrap();
    transaction
        .execute("LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE;", &[])
        .await
        .unwrap();

    let row = transaction
        .query_one("SELECT COUNT(*) AS count FROM users WHERE role = 1;", &[])
        .await
        .unwrap();
    if row.get::<_, i64>("count") > 0 {
        info!(target: "server::startup", event = "AdminRoleFound", "管理员用户已由其他进程创建");
        transaction.commit().await.unwrap();
        return;
    }

    let mut username = username_prefix.clone();

    for index in 0..1000 {
        let candidate = if index == 0 {
            username_prefix.clone()
        } else {
            format!("{}_{}", username_prefix, index)
        };

        if transaction
            .query_opt("SELECT id FROM users WHERE username = $1;", &[&candidate])
            .await
            .unwrap()
            .is_none()
        {
            username = candidate;
            break;
        }

        if index == 999 {
            panic!("默认管理员用户名均已被占用，请调整环境变量 NM_DEFAULT_ADMIN_USERNAME");
        }
    }

    transaction
        .execute(
            "INSERT INTO users (username, password, role, limit_login) VALUES ($1, $2, $3, $4);",
            &[&username, &password_hash, &1, &false],
        )
        .await
        .unwrap();

    info!(target: "server::startup",
        event = "CreateDefaultAdminUser",
        path = "fn create_default_admin_user",
        username,
        message = "创建默认管理员用户成功"
    );

    println!(
        "\n┌─ 初始管理员凭据 ─────────────────────────\n│ 用户名：{username}\n│ 密码：  {password}\n│ 请登录后尽快修改；该密码不会写入日志。\n└──────────────────────────────────────────\n"
    );

    transaction.commit().await.unwrap();
}

/// 区分后台通知和交互式测试，避免测试接口因多次长超时而阻塞过久。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailRetryPolicy {
    Background,
    Interactive,
}

#[derive(Clone, Copy, Debug)]
struct MailRetrySettings {
    max_attempts: u32,
    timeout: Duration,
    retry_delays: &'static [Duration],
    jitter_ms: u64,
}

impl MailRetryPolicy {
    const fn settings(self) -> MailRetrySettings {
        match self {
            Self::Background => MailRetrySettings {
                max_attempts: 3,
                timeout: Duration::from_secs(15),
                retry_delays: &BACKGROUND_RETRY_DELAYS,
                jitter_ms: 250,
            },
            Self::Interactive => MailRetrySettings {
                max_attempts: 2,
                timeout: Duration::from_secs(8),
                retry_delays: &INTERACTIVE_RETRY_DELAYS,
                jitter_ms: 100,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MailFailureKind {
    TransientResponse,
    PermanentResponse,
    Timeout,
    Tls,
    Client,
    InvalidResponse,
    TransportShutdown,
    ConnectionOrNetwork,
    Internal,
}

impl MailFailureKind {
    const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::TransientResponse
                | Self::Timeout
                | Self::TransportShutdown
                | Self::ConnectionOrNetwork
        )
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::TransientResponse => "transient_response",
            Self::PermanentResponse => "permanent_response",
            Self::Timeout => "timeout",
            Self::Tls => "tls",
            Self::Client => "client",
            Self::InvalidResponse => "invalid_response",
            Self::TransportShutdown => "transport_shutdown",
            Self::ConnectionOrNetwork => "connection_or_network",
            Self::Internal => "internal",
        }
    }
}

fn classify_smtp_error(error: &LettreSmtpError) -> MailFailureKind {
    // 先判定协议级永久错误，避免把响应文本中的 "timeout" 误判成网络超时。
    if error.is_permanent() {
        MailFailureKind::PermanentResponse
    } else if error.is_tls() {
        MailFailureKind::Tls
    } else if error.is_client() {
        MailFailureKind::Client
    } else if error.is_response() {
        MailFailureKind::InvalidResponse
    } else if error.is_transient() {
        MailFailureKind::TransientResponse
    } else if error.is_timeout() {
        MailFailureKind::Timeout
    } else if error.is_transport_shutdown() {
        MailFailureKind::TransportShutdown
    } else {
        // Lettre 0.11 没有公开 is_connection/is_network；排除上述类型后只剩连接或网络错误。
        MailFailureKind::ConnectionOrNetwork
    }
}

#[derive(Debug)]
struct RetryFailure<E> {
    error: E,
    attempts: u32,
    kind: MailFailureKind,
}

async fn retry_operation<E, F, Fut, C>(
    settings: MailRetrySettings,
    delivery_id: Uuid,
    mut operation: F,
    classify: C,
) -> Result<u32, RetryFailure<E>>
where
    E: fmt::Display,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(), E>>,
    C: Fn(&E) -> MailFailureKind,
{
    for attempt in 1..=settings.max_attempts {
        match operation().await {
            Ok(()) => return Ok(attempt),
            Err(error_value) => {
                let kind = classify(&error_value);
                if !kind.is_retryable() || attempt == settings.max_attempts {
                    return Err(RetryFailure {
                        error: error_value,
                        attempts: attempt,
                        kind,
                    });
                }

                let base_delay = settings
                    .retry_delays
                    .get((attempt - 1) as usize)
                    .copied()
                    .unwrap_or(Duration::ZERO);
                let jitter_ms = if settings.jitter_ms == 0 {
                    0
                } else {
                    ::rand::random_range(0..=settings.jitter_ms)
                };
                let delay = base_delay + Duration::from_millis(jitter_ms);
                warn!(
                    event = "MailSendRetryScheduled",
                    %delivery_id,
                    attempt,
                    max_attempts = settings.max_attempts,
                    delay_ms = delay.as_millis() as u64,
                    error_kind = kind.as_str(),
                    message = %error_value,
                    "邮件发送失败，等待重试"
                );
                tokio::time::sleep(delay).await;
            }
        }
    }

    unreachable!("邮件重试至少会执行一次")
}

/// 邮件发送最终失败，保留底层错误供现有接口生成管理员可读提示。
#[derive(Debug)]
pub struct MailSendError {
    source: Box<dyn Error + Send + Sync>,
    attempts: u32,
    kind: MailFailureKind,
}

impl MailSendError {
    fn new<E>(error_value: E, attempts: u32, kind: MailFailureKind) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self {
            source: Box::new(error_value),
            attempts,
            kind,
        }
    }

    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    pub const fn is_retryable(&self) -> bool {
        self.kind.is_retryable()
    }
}

impl fmt::Display for MailSendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl Error for MailSendError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// 按调用场景执行有限重试，并将最终的连接或发送错误返回给调用方。
pub async fn try_send_email(
    emailconf: &EmailConfig,
    port: u16,
    mail: Message,
    retry_policy: MailRetryPolicy,
) -> Result<(), MailSendError> {
    let settings = retry_policy.settings();
    let delivery_id = Uuid::now_v7();
    let creds = Credentials::new(
        emailconf.account_username.to_string(),
        emailconf.account_password.to_string(),
    );

    // relay 使用 SMTPS，并允许设置页指定服务器端口。每次重试重新建立 transport，
    // 避免复用已处于异常状态的 SMTP 连接。
    let mailer_builder = AsyncSmtpTransport::<Tokio1Executor>::relay(&emailconf.host)
        .map_err(|error_value| {
            MailSendError::new(
                std::io::Error::other(format!("邮件服务器配置无效: {error_value}")),
                0,
                MailFailureKind::Internal,
            )
        })?
        .port(port)
        .credentials(creds)
        .timeout(Some(settings.timeout));

    let _permit = SMTP_SEND_SEMAPHORE
        .acquire()
        .await
        .map_err(|error_value| MailSendError::new(error_value, 0, MailFailureKind::Internal))?;
    let result = retry_operation(
        settings,
        delivery_id,
        || {
            let mailer = mailer_builder.clone().build();
            let mail = mail.clone();
            async move { mailer.send(mail).await.map(|_| ()) }
        },
        classify_smtp_error,
    )
    .await;

    match result {
        Ok(attempts) => {
            info!(
                event = "SendEmailSuccessfully",
                path = "fn try_send_email",
                %delivery_id,
                attempts,
                message = "Email sent successfully!"
            );
            Ok(())
        }
        Err(failure) => {
            error!(
                event = "SendEmailFailed",
                operation = "send_email",
                %delivery_id,
                attempts = failure.attempts,
                error_kind = failure.kind.as_str(),
                error_code = "email_delivery_failed",
                error_message = %failure.error,
                retryable = failure.kind.is_retryable(),
                outcome = "email_not_delivered",
                "邮件发送最终失败"
            );
            Err(MailSendError::new(
                failure.error,
                failure.attempts,
                failure.kind,
            ))
        }
    }
}

/// 将 SMTP 发送错误映射为面向管理员的中文提示。
///
/// lettre 透传的 SMTP 服务器响应文本（如 `permanent error (535): authentication failed`、
/// `permanent error (500): plugin timeout`）对用户不直观，这里按关键字归类成可执行的中文提示。
/// 无法识别时回退为原始错误文本，保证细节不丢失。
pub fn smtp_send_error_message(error: &dyn std::error::Error) -> String {
    let raw = error.to_string();
    let lower = raw.to_lowercase();

    // 模板校验（Tera）错误通常是超长的上下文转储，这里单独识别，避免误当成 SMTP 错误。
    if raw.len() > 500 || lower.contains("tera") {
        return "模板校验失败，请检查 Tera 语法和变量".to_owned();
    }

    if lower.contains("authentication")
        || lower.contains("auth failed")
        || lower.contains("invalid credentials")
        || lower.contains("incorrect password")
        || lower.contains("login failed")
        || lower.contains("535")
        || lower.contains("530")
    {
        "认证失败：请检查发件邮箱密钥（授权码）是否正确".to_owned()
    } else if lower.contains("tls") || lower.contains("certificate") || lower.contains("handshake")
    {
        "邮件服务器 TLS/证书校验失败：请确认端口使用 SMTPS（隐式 TLS）".to_owned()
    } else if lower.contains("plugin timeout")
        || lower.contains("timed out")
        || lower.contains("timeout")
    {
        "邮件服务器处理超时：认证后端未响应，请稍后重试或检查邮件服务器状态".to_owned()
    } else if lower.contains("connection refused")
        || lower.contains("could not resolve")
        || lower.contains("failed to lookup")
        || lower.contains("dns")
        || lower.contains("no route")
        || lower.contains("network")
    {
        "无法连接邮件服务器：请检查服务器地址与端口".to_owned()
    } else if lower.contains("relay")
        || lower.contains("rejected")
        || lower.contains("sender")
        || lower.contains("550")
        || lower.contains("554")
    {
        "邮件被服务器拒绝：请检查发件人地址或服务器白名单".to_owned()
    } else {
        raw
    }
}

// 创建 TOTP 结构体
//
pub async fn totp_struct(
    username: String,
    d_key: &str,
    pool: &deadpool_postgres::Pool,
) -> Result<Option<TOTP>, Box<dyn std::error::Error>> {
    let c = pool.get().await?;

    match c.query_opt(
        "SELECT id, totp_secret FROM users WHERE limit_login = false AND enable_2fa = true AND username = $1;",
        &[&username]
    ).await? {
        Some(r) => {
            // 从数据库中获取 base64 编码后的数据
            let tmp_secret = r.get::<_, String>("totp_secret");
            let t_d_key = openssl::base64::decode_block(d_key)?;
            // 将 secret 解码
            let decode_secret = openssl::base64::decode_block(&tmp_secret)?;
            // 解密 secret
            let decrypt_result = decrypt_data(&decode_secret, &t_d_key)?;
            Ok(Some(
                TOTP::new(
                Algorithm::SHA1,
                6,
                1,
                30,
                decrypt_result,
                Some("Network Mapping".to_string()),
                username
            )?))
        },
        None => {
            Ok(None)
        }
    }
}

/// 检查 2FA 是否已绑定
///
pub async fn check_twofa_bind(
    username: &str,
    pool: &deadpool_postgres::Pool,
) -> Result<bool, Box<dyn std::error::Error>> {
    let database_conn = pool.get().await?;
    if let Some(_r) = database_conn.query_opt(
        "SELECT username FROM users WHERE username = $1 AND enable_2fa = true AND totp_secret IS NOT NULL;",
        &[&username]
    ).await? {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// TOTP 密钥创建
///
pub async fn bind_twofa(
    username: String,
    session: &str,
    pool: &deadpool_postgres::Pool,
    e_key: &str,
) -> Result<TotpBindingAttempt, Box<dyn std::error::Error>> {
    let secret32 = Secret::generate_secret();
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret32.to_bytes()?,
        Some("Network Mapping".to_string()),
        username.clone(),
    )?;
    let url = totp.get_url();
    let mut c = pool.get().await?;
    let transaction = c.transaction().await?;
    let encryption_key = openssl::base64::decode_block(e_key)?;
    let (nonce, tag, ciphertext) = encrypt_data(&secret32.to_bytes()?, &encryption_key)?;
    let mut encrypted = Vec::new();
    encrypted.extend_from_slice(&nonce);
    encrypted.extend_from_slice(&tag);
    encrypted.extend_from_slice(&ciphertext);
    let encrypted_secret = openssl::base64::encode_block(&encrypted);
    let expires_at =
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64 + 10 * 60 * 1000;
    let attempt_id = Uuid::new_v4();
    let updated = transaction
        .execute(
            "UPDATE session SET pending_totp_secret = $1, pending_totp_expires_at = $2, pending_totp_attempt_id = $5 \
         WHERE token = $3 AND is_enable = true AND deleted_at IS NULL \
         AND totp_verify_successful = true \
         AND user_id = (SELECT id FROM users WHERE username = $4 AND enable_2fa = false);",
            &[&encrypted_secret, &expires_at, &session, &username, &attempt_id],
        )
        .await?;
    if updated != 1 {
        return Err("当前会话不可用于绑定 2FA，或 2FA 已启用".into());
    }
    transaction.commit().await?;
    Ok(TotpBindingAttempt {
        url,
        attempt_id,
        expires_at_ms: expires_at,
    })
}

/// 验证当前会话中的临时 TOTP 密钥，并在成功后正式启用 2FA。
pub async fn confirm_twofa_binding(
    username: &str,
    session: &str,
    token: &str,
    pool: &deadpool_postgres::Pool,
    d_key: &str,
) -> Result<TotpBindingConfirmation, Box<dyn std::error::Error>> {
    let mut conn = pool.get().await?;
    let transaction = conn.transaction().await?;
    let row = transaction
        .query_opt(
            "SELECT u.id, s.pending_totp_secret, s.pending_totp_expires_at, s.pending_totp_attempt_id \
         FROM session s JOIN users u ON u.id = s.user_id \
         WHERE s.token = $1 AND s.is_enable = true AND s.deleted_at IS NULL \
         AND s.totp_verify_successful = true \
         AND u.username = $2 AND u.enable_2fa = false FOR UPDATE;",
            &[&session, &username],
        )
        .await?;
    let Some(row) = row else {
        return Ok(TotpBindingConfirmation {
            attempt_id: None,
            expires_in_ms: None,
            rejection: Some(TotpBindingRejection::SessionIneligible),
        });
    };
    let attempt_id = row.get::<_, Option<Uuid>>("pending_totp_attempt_id");
    let Some(pending_secret) = row.get::<_, Option<String>>("pending_totp_secret") else {
        return Ok(TotpBindingConfirmation {
            attempt_id,
            expires_in_ms: None,
            rejection: Some(TotpBindingRejection::PendingSecretMissing),
        });
    };
    let Some(expires_at) = row.get::<_, Option<i64>>("pending_totp_expires_at") else {
        return Ok(TotpBindingConfirmation {
            attempt_id,
            expires_in_ms: None,
            rejection: Some(TotpBindingRejection::PendingSecretMissing),
        });
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
    let expires_in_ms = expires_at - now;
    if now > expires_at {
        return Ok(TotpBindingConfirmation {
            attempt_id,
            expires_in_ms: Some(expires_in_ms),
            rejection: Some(TotpBindingRejection::PendingBindingExpired),
        });
    }

    let encrypted_secret = openssl::base64::decode_block(&pending_secret)?;
    let decrypt_key = openssl::base64::decode_block(d_key)?;
    let secret = decrypt_data(&encrypted_secret, &decrypt_key)?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        Some("Network Mapping".to_string()),
        username.to_string(),
    )?;
    if !totp_token_verify(totp, token).await? {
        return Ok(TotpBindingConfirmation {
            attempt_id,
            expires_in_ms: Some(expires_in_ms),
            rejection: Some(TotpBindingRejection::CodeMismatch),
        });
    }

    let user_id: i32 = row.get("id");
    let enabled = transaction.execute(
        "UPDATE users SET totp_secret = $1, enable_2fa = true WHERE id = $2 AND enable_2fa = false;",
        &[&pending_secret, &user_id],
    ).await?;
    if enabled != 1 {
        return Err("启用 2FA 影响的用户数量异常".into());
    }
    invalidate_user_sessions_in_transaction(
        &transaction,
        Some(username),
        "totp_enabled",
        Some(user_id),
    )
    .await?;
    transaction.commit().await?;
    Ok(TotpBindingConfirmation {
        attempt_id,
        expires_in_ms: Some(expires_in_ms),
        rejection: None,
    })
}

async fn invalidate_user_sessions_in_transaction(
    transaction: &tokio_postgres::Transaction<'_>,
    username: Option<&str>,
    reason: &str,
    deleted_by_user_id: Option<i32>,
) -> Result<u64, tokio_postgres::Error> {
    match username {
        Some(username) => {
            transaction
                .execute(
                    "UPDATE session SET is_enable = FALSE, deleted_at = NOW(), \
                 deletion_reason = $2, deleted_by_user_id = $3 \
                 WHERE is_enable = TRUE AND deleted_at IS NULL \
                   AND user_id = (SELECT id FROM users WHERE username = $1);",
                    &[&username, &reason, &deleted_by_user_id],
                )
                .await
        }
        None => {
            transaction
                .execute(
                    "UPDATE session SET is_enable = FALSE, deleted_at = NOW(), \
                 deletion_reason = $1, deleted_by_user_id = $2 \
                 WHERE is_enable = TRUE AND deleted_at IS NULL;",
                    &[&reason, &deleted_by_user_id],
                )
                .await
        }
    }
}

/// 使指定用户（`Some`）或所有用户（`None`）的有效会话失效。
pub async fn invalidate_user_sessions(
    pool: &deadpool_postgres::Pool,
    username: Option<&str>,
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut conn = pool.get().await?;
    let transaction = conn.transaction().await?;
    let affected = invalidate_user_sessions_in_transaction(
        &transaction,
        username,
        "security_policy_changed",
        None,
    )
    .await?;
    transaction.commit().await?;
    Ok(affected)
}

/// 验证 TOTP token///
///
pub async fn totp_token_verify(
    totp: TOTP,
    token: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if totp.check(token, seconds) {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// totp 验证状态更改
pub async fn totp_verify_status_change(
    session: &str,
    pool: &deadpool_postgres::Pool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut conn = pool.get().await?;
    let db_transaction = conn.transaction().await?;
    let r = db_transaction
        .execute(
            "UPDATE session SET totp_verify_successful = true \
             WHERE token = $1 AND is_enable = TRUE AND deleted_at IS NULL;",
            &[&session],
        )
        .await?;
    if r == 0 {
        warn!(
            event = "ChangeTotpStatus",
            path = "fn totp_verify_status_change",
            message = "没有更改 totp verify 状态"
        );
        Ok(())
    } else if r == 1 {
        db_transaction.commit().await?;
        Ok(())
    } else {
        Err(format!("更改 totp verify status 影响 {} 行", r).into())
    }
}

/// 解除 2FA 绑定
///
/// **该操作只能由管理员操作**,
/// 且需要调用者做权限判断
pub async fn unbind_2fa(
    username: &str,
    pool: &deadpool_postgres::Pool,
    actor_user_id: i32,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut c = pool.get().await?;
    let db_transaction = c.transaction().await?;
    let r = db_transaction
        .execute(
            "UPDATE users SET enable_2fa = false, totp_secret = NULL WHERE username = $1;",
            &[&username],
        )
        .await?;
    if r == 1 {
        invalidate_user_sessions_in_transaction(
            &db_transaction,
            Some(username),
            "totp_disabled",
            Some(actor_user_id),
        )
        .await?;
        info!(
            event = "Unbind2FASuccessful",
            path = "fn unbind_2fa",
            message = format!("用户 {} 解绑 2FA 成功", username)
        );
        db_transaction.commit().await?;
        Ok(true)
    } else if r == 0 {
        warn!(
            event = "Unbind2FAWarning",
            path = "fn unbind_2fa",
            message = format!("用户 {} 没有绑定 2FA", username)
        );
        Ok(false)
    } else {
        error!(
            event = "Unbind2FAFailed",
            operation = "unbind_totp",
            error_kind = "data_integrity",
            error_code = "totp_unbind_affected_multiple_rows",
            error_message = "TOTP unbind affected more than one user row",
            retryable = false,
            outcome = "transaction_rolled_back",
            username,
            affected_rows = r,
        );
        Err("数据库更新条目数不等于 0 和 1".into())
    }
}

#[derive(Deserialize)]
pub struct GetUserInfoH {
    pub username: Option<String>,
    pub list: Option<bool>,
    pub count: Option<u32>, // 通过限制数据类型避免负数
}

#[derive(Deserialize, FromRow, Serialize)]
pub struct UserInfo {
    pub id: i32,
    pub username: String,
    pub role: i32,
    pub email: Option<String>,
    pub create_time: i64,
    pub limit_login: bool,
    pub limit_at: Option<i64>,
    pub limit_time: Option<i32>,
    pub enable_2fa: bool,
    pub last_login_at: Option<i64>,
    pub last_login_ip: Option<IpInet>,
    pub login_error_count: Option<i32>,
    pub last_error_at: Option<i64>,
}

impl Default for UserInfo {
    fn default() -> Self {
        Self {
            id: -1,
            username: String::new(),
            role: -1,
            email: None,
            create_time: -1,
            limit_login: true,
            limit_at: None,
            limit_time: None,
            enable_2fa: true,
            last_login_at: None,
            last_login_ip: None,
            login_error_count: None,
            last_error_at: None,
        }
    }
}

/// 获取用户信息
///
/// 当权限足够时可以通过将 username 设置为 None 来获取所有用户信息，
/// 条目限制默认 5 条
pub async fn get_user_info(
    role: i32,
    username: Option<&str>,
    limit_items: Option<i64>,
    pool: &deadpool_postgres::Pool,
) -> Result<Vec<UserInfo>, Box<dyn std::error::Error>> {
    const USER_SELECT_S: &str = "SELECT \
            id, username, role, email, create_time, limit_login, limit_at, limit_time, \
            enable_2fa, last_login_at, last_login_ip, login_error_count, last_error_at \
        FROM users";

    let database_conn = pool.get().await?;
    let limit_i = limit_items.unwrap_or(5);

    let r = match (role, username) {
        (1, None) => {
            database_conn
                .query(&format!("{USER_SELECT_S} LIMIT $1;"), &[&limit_i])
                .await?
        }
        (1 | 2, Some(username_t)) => {
            database_conn
                .query(
                    &format!("{USER_SELECT_S} WHERE username = $1 LIMIT 1;"),
                    &[&username_t],
                )
                .await?
        }
        _ => return Err("没有对应的权限".into()),
    };

    Ok(r.iter()
        .map(|row| -> UserInfo { FromRow::from_row(row) })
        .collect())
}

/// 用户基础信息
#[derive(Deserialize)]
pub struct UserBaseInfo {
    pub username: String,
    pub email: String,
}

/// 更新用户信息
///
pub async fn update_user_info(
    username: &str,
    role: i32,
    new_user_info: &UserBaseInfo,
    pool: &deadpool_postgres::Pool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut database_conn = pool.get().await?;
    let conn_transaction = database_conn.transaction().await?;

    let result = conn_transaction
        .execute(
            "UPDATE users SET username = $1, email = $2 WHERE username = $3 AND role = $4;",
            &[
                &new_user_info.username,
                &new_user_info.email,
                &username,
                &role,
            ],
        )
        .await?;

    match result {
        // 更改成功
        1 => {
            conn_transaction.commit().await?;
            Ok(())
        }

        // 没有更改任何条目
        0 => {
            warn!(
                event = "UpdateUserInfo",
                path = "fn update_user_info",
                message = "没有更改任何条目，可能是该用户不存在或数据异常"
            );
            Ok(())
        }

        // 更改了多行，这是不允许的，所以不会提交事务
        affected_rows => {
            error!(
                event = "UpdateUserInfoError",
                operation = "update_user_info",
                error_kind = "data_integrity",
                error_code = "user_update_affected_multiple_rows",
                error_message = "user update affected more than one row",
                retryable = false,
                outcome = "transaction_rolled_back",
                username,
                affected_rows,
            );
            Err("更改了多行".into())
        }
    }
}

/// 从数据库中获取系统配置
pub async fn get_config_from_database(
    pool: &deadpool_postgres::Pool,
    item_type: &str,
    key: Option<&str>,
) -> Result<Vec<SystemConfig>, Box<dyn std::error::Error>> {
    const GET_CONFIG_SELECT_S: &str =
        "SELECT item_type, key, value, create_at, update_at FROM setting WHERE item_type = ";

    let conn = pool.get().await?;
    let result = match key {
        Some(k) => {
            conn.query(
                &format!("{GET_CONFIG_SELECT_S} $1 AND key = $2 LIMIT 1;"),
                &[&item_type, &k],
            )
            .await?
        }
        None => {
            conn.query(&format!("{GET_CONFIG_SELECT_S} $1;"), &[&item_type])
                .await?
        }
    };

    if result.is_empty() {
        Ok(vec![SystemConfig::new()])
    } else {
        Ok(result
            .iter()
            .map(SystemConfig::try_from_row)
            .collect::<Result<Vec<_>, _>>()?)
    }
}

/// 向数据库写入系统配置
///
pub async fn write_config_to_database(
    pool: &deadpool_postgres::Pool,
    sys_conf: &SystemConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut conn = pool.get().await?;
    let transaction = conn.transaction().await?;

    match transaction
        .execute(
            "INSERT INTO setting (item_type, key, value) VALUES ($1, $2, $3) \
             ON CONFLICT (item_type, key) DO UPDATE SET value = EXCLUDED.value, update_at = NOW();",
            &[&sys_conf.item_type, &sys_conf.key, &sys_conf.value],
        )
        .await?
    {
        1 => {
            transaction.commit().await?;
            Ok(())
        }

        _ => Err("插入数据异常".into()),
    }
}

/// Read the scan profile used when a task does not explicitly select one.
/// Invalid legacy values are ignored so task creation always has a safe fallback.
pub async fn get_default_scan_profile_from_database(
    pool: &deadpool_postgres::Pool,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let conn = pool.get().await?;
    let row = conn
        .query_opt(
            "SELECT value FROM setting WHERE item_type = $1 AND key = $2 LIMIT 1;",
            &[&SCAN_SETTING_TYPE, &DEFAULT_SCAN_PROFILE_SETTING_KEY],
        )
        .await?;
    Ok(row
        .map(|row| row.get::<_, String>("value").trim().to_lowercase())
        .filter(|profile| crate::scan_control::creation::is_ip_scan_profile(profile))
        .unwrap_or_else(|| FALLBACK_SCAN_PROFILE.to_owned()))
}

pub async fn get_scan_settings_from_database(
    pool: &deadpool_postgres::Pool,
) -> Result<ScanSettingsResponse, Box<dyn std::error::Error + Send + Sync>> {
    Ok(ScanSettingsResponse {
        default_scan_profile: get_default_scan_profile_from_database(pool).await?,
    })
}

pub async fn write_scan_settings_to_database(
    pool: &deadpool_postgres::Pool,
    settings: &ScanSettingsRequest,
) -> Result<ScanSettingsResponse, Box<dyn std::error::Error>> {
    let profile = settings.default_scan_profile.trim().to_lowercase();
    if !crate::scan_control::creation::is_ip_scan_profile(&profile) {
        return Err("unsupported default IP scan profile".into());
    }
    let conn = pool.get().await?;
    conn.execute(
        "INSERT INTO setting (item_type, key, value) VALUES ($1, $2, $3) \
         ON CONFLICT (item_type, key) DO UPDATE SET value = EXCLUDED.value, update_at = NOW();",
        &[
            &SCAN_SETTING_TYPE,
            &DEFAULT_SCAN_PROFILE_SETTING_KEY,
            &profile,
        ],
    )
    .await?;
    Ok(ScanSettingsResponse {
        default_scan_profile: profile,
    })
}

/// 读取用于新登录会话的绝对有效期。缺失或损坏的设置回退到 45 分钟。
pub async fn get_session_ttl_seconds_from_database(
    pool: &deadpool_postgres::Pool,
) -> Result<i32, Box<dyn std::error::Error>> {
    let conn = pool.get().await?;
    let row = conn
        .query_opt(
            "SELECT value FROM setting WHERE item_type = $1 AND key = $2 LIMIT 1;",
            &[&SECURITY_SETTING_TYPE, &SESSION_TTL_SETTING_KEY],
        )
        .await?;
    let minimum_seconds = MIN_SESSION_TTL_MINUTES * 60;
    let maximum_seconds = MAX_SESSION_TTL_MINUTES * 60;
    Ok(row
        .and_then(|row| row.get::<_, String>("value").parse::<i32>().ok())
        .filter(|seconds| {
            seconds % 60 == 0 && (minimum_seconds..=maximum_seconds).contains(seconds)
        })
        .unwrap_or(DEFAULT_SESSION_TTL_SECONDS))
}

pub async fn get_session_settings_from_database(
    pool: &deadpool_postgres::Pool,
) -> Result<SessionSettingsResponse, Box<dyn std::error::Error>> {
    Ok(SessionSettingsResponse::new(
        get_session_ttl_seconds_from_database(pool).await?,
        0,
    ))
}

/// 原子保存会话策略，并按管理员选择注销除当前会话外的其他活动会话。
pub async fn write_session_settings_to_database(
    pool: &deadpool_postgres::Pool,
    settings: &SessionSettingsRequest,
    current_session: &str,
) -> Result<SessionSettingsResponse, Box<dyn std::error::Error>> {
    let ttl_seconds = session_ttl_seconds_from_minutes(settings.session_ttl_minutes)?;
    let value = ttl_seconds.to_string();
    let mut conn = pool.get().await?;
    let transaction = conn.transaction().await?;
    transaction
        .execute(
            "INSERT INTO setting (item_type, key, value) VALUES ($1, $2, $3) \
             ON CONFLICT (item_type, key) DO UPDATE SET value = EXCLUDED.value, update_at = NOW();",
            &[&SECURITY_SETTING_TYPE, &SESSION_TTL_SETTING_KEY, &value],
        )
        .await?;
    let invalidated_session_count = if settings.invalidate_other_sessions {
        transaction
            .execute(
                "UPDATE session SET is_enable = FALSE, deleted_at = NOW(), \
                 deletion_reason = 'session_policy_changed', \
                 deleted_by_user_id = (SELECT user_id FROM session \
                                       WHERE token = $1 AND deleted_at IS NULL LIMIT 1) \
                 WHERE is_enable = TRUE AND deleted_at IS NULL AND token <> $1;",
                &[&current_session],
            )
            .await?
    } else {
        0
    };
    transaction.commit().await?;
    Ok(SessionSettingsResponse::new(
        ttl_seconds,
        invalidated_session_count,
    ))
}

/// 读取设置页需要的邮件与通知配置。
///
/// 邮箱密钥只返回是否已配置，绝不通过接口回传密文或明文。
pub async fn get_mail_settings_from_database(
    pool: &deadpool_postgres::Pool,
) -> Result<MailSettingsResponse, Box<dyn std::error::Error>> {
    let conn = pool.get().await?;
    let rows = conn
        .query(
            "SELECT item_type, key, value FROM setting WHERE item_type IN ($1, $2);",
            &[&SMTP_SETTING_TYPE, &NOTIFICATION_SETTING_TYPE],
        )
        .await?;
    let values = rows
        .iter()
        .map(|row| {
            (
                (
                    row.get::<_, String>("item_type"),
                    row.get::<_, String>("key"),
                ),
                row.get::<_, String>("value"),
            )
        })
        .collect::<HashMap<_, _>>();

    let smtp_value = |key: &str| {
        values
            .get(&(SMTP_SETTING_TYPE.to_owned(), key.to_owned()))
            .cloned()
            .unwrap_or_default()
    };
    let notification_value = |key: &str, default: bool| {
        values
            .get(&(NOTIFICATION_SETTING_TYPE.to_owned(), key.to_owned()))
            .and_then(|value| value.parse::<bool>().ok())
            .unwrap_or(default)
    };
    let defaults = NotificationPreferences::default();

    Ok(MailSettingsResponse {
        recipient: smtp_value("recipient"),
        smtp_host: smtp_value("host"),
        smtp_port: smtp_value("port").parse::<u16>().unwrap_or(465),
        sender: smtp_value("sender"),
        sender_key_configured: !smtp_value(SMTP_SENDER_KEY).is_empty(),
        notification_prefs: NotificationPreferences {
            login_notify_enabled: notification_value(
                "login_notify_enabled",
                defaults.login_notify_enabled,
            ),
            notify_on_stuck: notification_value("notify_on_stuck", defaults.notify_on_stuck),
            notify_on_complete: notification_value(
                "notify_on_complete",
                defaults.notify_on_complete,
            ),
            report_daily: notification_value("report_daily", defaults.report_daily),
            report_weekly: notification_value("report_weekly", defaults.report_weekly),
            report_monthly: notification_value("report_monthly", defaults.report_monthly),
            health_alert_enabled: notification_value(
                "health_alert_enabled",
                defaults.health_alert_enabled,
            ),
            scanner_offline_enabled: notification_value(
                "scanner_offline_enabled",
                defaults.scanner_offline_enabled,
            ),
            scanner_recovery_enabled: notification_value(
                "scanner_recovery_enabled",
                defaults.scanner_recovery_enabled,
            ),
        },
    })
}

fn encrypt_setting_secret(
    plaintext: &str,
    encoded_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let encryption_key = openssl::base64::decode_block(encoded_key)?;
    let (nonce, tag, ciphertext) = encrypt_data(plaintext.as_bytes(), &encryption_key)?;
    let mut encrypted = Vec::with_capacity(nonce.len() + tag.len() + ciphertext.len());
    encrypted.extend_from_slice(&nonce);
    encrypted.extend_from_slice(&tag);
    encrypted.extend_from_slice(&ciphertext);
    Ok(openssl::base64::encode_block(&encrypted))
}

fn decrypt_setting_secret(
    encrypted_value: &str,
    encoded_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let encrypted = openssl::base64::decode_block(encrypted_value)?;
    if encrypted.len() < 28 {
        return Err("邮件密钥密文格式错误".into());
    }
    let decryption_key = openssl::base64::decode_block(encoded_key)?;
    let plaintext = decrypt_data(&encrypted, &decryption_key)?;
    Ok(String::from_utf8(plaintext)?)
}

/// 读取并解密已保存的发件邮箱密钥，供邮件测试使用。
pub async fn get_mail_sender_key_from_database(
    pool: &deadpool_postgres::Pool,
    encoded_key: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let conn = pool.get().await?;
    let row = conn
        .query_opt(
            "SELECT value FROM setting WHERE item_type = $1 AND key = $2 LIMIT 1;",
            &[&SMTP_SETTING_TYPE, &SMTP_SENDER_KEY],
        )
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let encrypted_value = row.get::<_, String>("value");
    if encrypted_value.is_empty() {
        return Ok(None);
    }
    Ok(Some(decrypt_setting_secret(&encrypted_value, encoded_key)?))
}

/// 原子写入设置页中的邮件配置和通知偏好。
pub async fn write_mail_settings_to_database(
    pool: &deadpool_postgres::Pool,
    settings: &MailSettingsRequest,
    encoded_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut conn = pool.get().await?;
    let transaction = conn.transaction().await?;
    let smtp_values = [
        ("recipient", settings.recipient.trim().to_owned()),
        ("host", settings.smtp_host.trim().to_owned()),
        ("port", settings.smtp_port.to_string()),
        ("sender", settings.sender.trim().to_owned()),
    ];
    let notification_values = [
        (
            "login_notify_enabled",
            settings.notification_prefs.login_notify_enabled.to_string(),
        ),
        (
            "notify_on_stuck",
            settings.notification_prefs.notify_on_stuck.to_string(),
        ),
        (
            "notify_on_complete",
            settings.notification_prefs.notify_on_complete.to_string(),
        ),
        (
            "report_daily",
            settings.notification_prefs.report_daily.to_string(),
        ),
        (
            "report_weekly",
            settings.notification_prefs.report_weekly.to_string(),
        ),
        (
            "report_monthly",
            settings.notification_prefs.report_monthly.to_string(),
        ),
        (
            "health_alert_enabled",
            settings.notification_prefs.health_alert_enabled.to_string(),
        ),
        (
            "scanner_offline_enabled",
            settings
                .notification_prefs
                .scanner_offline_enabled
                .to_string(),
        ),
        (
            "scanner_recovery_enabled",
            settings
                .notification_prefs
                .scanner_recovery_enabled
                .to_string(),
        ),
    ];
    const UPSERT_SETTING: &str = "INSERT INTO setting (item_type, key, value) VALUES ($1, $2, $3) \
         ON CONFLICT (item_type, key) DO UPDATE SET value = EXCLUDED.value, update_at = NOW();";

    for (key, value) in smtp_values {
        transaction
            .execute(UPSERT_SETTING, &[&SMTP_SETTING_TYPE, &key, &value])
            .await?;
    }
    if !settings.sender_key.is_empty() {
        let encrypted_sender_key = encrypt_setting_secret(&settings.sender_key, encoded_key)?;
        transaction
            .execute(
                UPSERT_SETTING,
                &[&SMTP_SETTING_TYPE, &SMTP_SENDER_KEY, &encrypted_sender_key],
            )
            .await?;
    }
    for (key, value) in notification_values {
        transaction
            .execute(UPSERT_SETTING, &[&NOTIFICATION_SETTING_TYPE, &key, &value])
            .await?;
    }

    transaction.commit().await?;
    Ok(())
}

#[cfg(test)]
mod mail_setting_tests {
    use super::{decrypt_setting_secret, encrypt_setting_secret};

    #[test]
    fn mail_sender_key_encryption_round_trips() {
        let encoded_key = openssl::base64::encode_block(&[7_u8; 32]);
        let plaintext = "smtp-app-password-测试";

        let encrypted = encrypt_setting_secret(plaintext, &encoded_key).unwrap();
        assert_ne!(encrypted, plaintext);
        assert_eq!(
            decrypt_setting_secret(&encrypted, &encoded_key).unwrap(),
            plaintext
        );
    }

    #[test]
    fn malformed_mail_sender_key_ciphertext_is_rejected() {
        let encoded_key = openssl::base64::encode_block(&[7_u8; 32]);
        let malformed = openssl::base64::encode_block(&[1_u8; 12]);

        assert!(decrypt_setting_secret(&malformed, &encoded_key).is_err());
    }
}

#[cfg(test)]
mod mail_retry_tests {
    use super::{MailFailureKind, MailRetryPolicy, MailRetrySettings, retry_operation};
    use std::fmt;
    use std::time::Duration;
    use uuid::Uuid;

    const TEST_RETRY_DELAYS: [Duration; 2] = [Duration::ZERO, Duration::ZERO];

    #[derive(Clone, Copy, Debug)]
    struct FakeError;

    impl fmt::Display for FakeError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("fake send error")
        }
    }

    fn test_settings(max_attempts: u32) -> MailRetrySettings {
        MailRetrySettings {
            max_attempts,
            timeout: Duration::from_secs(1),
            retry_delays: &TEST_RETRY_DELAYS,
            jitter_ms: 0,
        }
    }

    #[test]
    fn retry_policies_bound_attempts_and_timeouts() {
        let background = MailRetryPolicy::Background.settings();
        assert_eq!(background.max_attempts, 3);
        assert_eq!(background.timeout, Duration::from_secs(15));

        let interactive = MailRetryPolicy::Interactive.settings();
        assert_eq!(interactive.max_attempts, 2);
        assert_eq!(interactive.timeout, Duration::from_secs(8));
    }

    #[tokio::test]
    async fn retryable_error_is_retried_until_success() {
        let mut calls = 0_u32;
        let attempts = retry_operation(
            test_settings(3),
            Uuid::nil(),
            || {
                calls += 1;
                let current_call = calls;
                async move {
                    if current_call < 3 {
                        Err(FakeError)
                    } else {
                        Ok(())
                    }
                }
            },
            |_| MailFailureKind::Timeout,
        )
        .await
        .unwrap();

        assert_eq!(attempts, 3);
        assert_eq!(calls, 3);
    }

    #[tokio::test]
    async fn permanent_error_is_not_retried() {
        let mut calls = 0_u32;
        let failure = retry_operation(
            test_settings(3),
            Uuid::nil(),
            || {
                calls += 1;
                async { Err(FakeError) }
            },
            |_| MailFailureKind::PermanentResponse,
        )
        .await
        .unwrap_err();

        assert_eq!(failure.attempts, 1);
        assert_eq!(failure.kind, MailFailureKind::PermanentResponse);
        assert_eq!(calls, 1);
    }

    #[tokio::test]
    async fn retryable_error_stops_at_attempt_limit() {
        let mut calls = 0_u32;
        let failure = retry_operation(
            test_settings(3),
            Uuid::nil(),
            || {
                calls += 1;
                async { Err(FakeError) }
            },
            |_| MailFailureKind::ConnectionOrNetwork,
        )
        .await
        .unwrap_err();

        assert_eq!(failure.attempts, 3);
        assert_eq!(calls, 3);
    }
}

/// 用户基础信息，主要用于中间件注入
///
/// 只允许存储常用的基础信息，不会存储机密信息
#[derive(FromRow, Clone)]
pub struct UserBaseI {
    pub id: i32,
    pub username: String,
    pub role: i32,
    pub email: Option<String>,
    pub limit_login: bool,
    pub enable_2fa: bool,
}

#[derive(Clone)]
pub struct UserSession {
    pub session: String,
}

/// 获取用户基础信息，返回的数据主要用于注入请求
pub async fn get_user_base_info(
    pool: &Pool,
    user_id: i32,
) -> Result<UserBaseI, Box<dyn std::error::Error>> {
    let conn = pool.get().await?;

    let row = conn.query_opt(
        "SELECT id, username, role, email, limit_login, enable_2fa FROM users \
         WHERE id = $1 AND limit_login = FALSE AND disabled_at IS NULL AND deleted_at IS NULL LIMIT 1;",
        &[&user_id]
    ).await?;

    row.map(|value| FromRow::try_from_row(&value))
        .transpose()?
        .ok_or_else(|| "用户不存在、已锁定、已禁用或已删除".into())
}

/// web 端添加扫描器
///
/// 返回 ScannerRegisterData
pub async fn web_add_scanner(
    pool: &Pool,
    user: &UserBaseI,
    audit_context: &AuditContext,
    add_data: &AddScanner,
    token_pepper: &str,
) -> Result<ScannerRegisterSecret, Box<dyn std::error::Error>> {
    let mut db_conn = pool.get().await?;
    let db_transaction = db_conn.transaction().await?;

    // 生成扫描器 id （uuid v7）
    let scanner_id = Uuid::now_v7().to_string();
    let registration_token = generate_scanner_token("nm_reg")?;
    let registration_token_hash = hash_scanner_token(&registration_token, token_pepper)?;

    match db_transaction.execute(
        "INSERT INTO scanner_info \
         (name, scanner_id, create_user, registration_token_hash, registration_token_expires_at, location, create_time, remark, tag, is_enable) \
         VALUES ($1, $2, $3, $4, NOW() + INTERVAL '24 hours', $5, NOW(), $6, $7, false);",
        &[&add_data.name, &scanner_id, &user.id, &registration_token_hash, &add_data.location, &add_data.remark, &add_data.tag]
    ).await? {
        1 => {
            let mut audit_event = AuditEvent::user("scanner", "scanner.create", "success", user)
                .resource("scanner", scanner_id.clone());
            audit_event.response_status = Some(200);
            write_audit(&db_transaction, audit_context, &audit_event).await?;
            db_transaction.commit().await?;
            Ok(ScannerRegisterSecret {
                scanner_id,
                registration_token,
            })
        },
        _ => Err("创建影响多行".into())
    }
}

/// 扫描器注册
///
pub async fn scanner_register(
    pool: &Pool,
    register_data: &ScannerRegisterData,
    registration_token: &str,
    token_pepper: &str,
    audit_context: &AuditContext,
) -> Result<ScannerRuntimeSecret, Box<dyn std::error::Error>> {
    let mut db_conn = pool.get().await?;
    let db_transaction = db_conn.transaction().await?;
    let registration_token_hash = hash_scanner_token(registration_token, token_pepper)?;

    let row = db_transaction
        .query_opt(
            "SELECT id FROM scanner_info \
         WHERE scanner_id = $1 \
           AND registration_token_hash = $2 \
           AND registration_consumed_at IS NULL \
           AND registration_token_expires_at > NOW() \
         FOR UPDATE;",
            &[&register_data.scanner_id, &registration_token_hash],
        )
        .await?;

    let Some(row) = row else {
        return Err(Box::new(ScannerRegistrationUnauthorized));
    };

    let scanner_pk: i32 = row.get("id");
    let runtime_token = generate_scanner_token("nm_run")?;
    let runtime_token_hash = hash_scanner_token(&runtime_token, token_pepper)?;

    match db_transaction
        .execute(
            "UPDATE scanner_info SET \
            registration_token_hash = NULL, \
            registration_consumed_at = NOW(), \
            runtime_token_hash = $1, \
            runtime_token_rotated_at = NOW(), \
            register_time = NOW(), \
            update_time = NOW(), \
            is_enable = true \
         WHERE id = $2;",
            &[&runtime_token_hash, &scanner_pk],
        )
        .await?
    {
        1 => {
            let mut audit_event = AuditEvent::anonymous("scanner", "scanner.register", "success");
            audit_event.actor_type = "scanner".to_owned();
            audit_event.actor_id = Some(register_data.scanner_id.clone());
            audit_event.resource_type = Some("scanner".to_owned());
            audit_event.resource_id = Some(register_data.scanner_id.clone());
            audit_event.response_status = Some(200);
            write_audit(&db_transaction, audit_context, &audit_event).await?;
            db_transaction.commit().await?;
            Ok(ScannerRuntimeSecret { runtime_token })
        }
        0 => Err(Box::new(ScannerRegistrationUnauthorized)),
        _ => Err("更新影响多行".into()),
    }
}

const SCANNER_INFO_SELECT: &str = "\
    SELECT s.diagnostic_dropped_events, s.diagnostics_capabilities, s.accepting_tasks, s.diagnostic_health, s.scanner_id, s.name, u.username AS creator, s.location, \
           s.ip_address, s.system_version, s.scanner_version, \
           s.cpu_model, s.cpus, s.ram, s.uptime, s.create_time, s.register_time, s.update_time, \
           s.last_seen_at, s.runtime_state, \
           (s.is_enable = TRUE AND s.runtime_state <> 'stopping' AND s.last_seen_at IS NOT NULL \
              AND s.last_seen_at >= NOW() - (@offline_seconds@) * INTERVAL '1 second') AS is_online, \
           (SELECT t.task_id FROM scan_task_execution e JOIN scan_task t ON t.id = e.task_id \
              WHERE e.assigned_scanner_id = s.scanner_id AND e.execution_status = 'running' \
              AND e.lease_expires_at > (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT \
              ORDER BY e.task_start_time DESC NULLS LAST LIMIT 1) AS current_task_id, \
           s.is_run, s.is_enable, s.remark, s.tag, s.supports_ipv4, s.supports_ipv6, \
           s.ipv4_ready, s.ipv6_ready, s.public_ipv4, s.public_ipv6, s.network_status_reason, \
           s.network_capabilities_updated_at, s.scan_capabilities, s.scan_capabilities_updated_at, \
           s.latency_rtt_us, s.latency_network_rtt_us, s.latency_server_processing_us, \
           s.latency_measured_at, \
           (s.latency_measured_at IS NULL OR s.latency_measured_at < NOW() - (@latency_stale_seconds@) * INTERVAL '1 second') \
              AS latency_stale, \
           CASE WHEN s.latency_network_rtt_us >= (@latency_critical_ms@) * 1000 THEN 'critical' \
                WHEN s.latency_network_rtt_us >= (@latency_warning_ms@) * 1000 THEN 'warning' ELSE 'normal' END AS latency_severity \
    FROM scanner_info s \
    LEFT JOIN users u ON u.id = s.create_user";

fn scanner_info_select() -> String {
    SCANNER_INFO_SELECT
        .replace("@offline_seconds@", &crate::scanner_health::seconds_sql())
        .replace(
            "@latency_stale_seconds@",
            &crate::scanner_health::latency_stale_seconds_sql(),
        )
        .replace(
            "@latency_warning_ms@",
            &crate::scanner_health::latency_warning_sql(),
        )
        .replace(
            "@latency_critical_ms@",
            &crate::scanner_health::latency_critical_sql(),
        )
}

fn scanner_info_from_row(row: &Row) -> ScannerInfo {
    let latency = match (
        row.get::<_, Option<i64>>("latency_rtt_us"),
        row.get::<_, Option<i64>>("latency_network_rtt_us"),
        row.get::<_, Option<i64>>("latency_server_processing_us"),
        row.get::<_, Option<DateTime<Utc>>>("latency_measured_at"),
    ) {
        (Some(rtt), Some(network), Some(processing), Some(measured_at)) => {
            Some(ScannerLatencyInfo {
                rtt_ms: rtt as f64 / 1_000.0,
                network_rtt_ms: network as f64 / 1_000.0,
                server_processing_ms: processing as f64 / 1_000.0,
                measured_at,
                stale: row.get("latency_stale"),
                severity: row.get("latency_severity"),
            })
        }
        _ => None,
    };
    ScannerInfo {
        diagnostics_capabilities: row.get("diagnostics_capabilities"),
        accepting_tasks: row.get("accepting_tasks"),
        diagnostic_health: row.get("diagnostic_health"),
        diagnostic_dropped_events: row.get("diagnostic_dropped_events"),
        scanner_id: row.get("scanner_id"),
        name: row.get("name"),
        creator: row.get("creator"),
        location: row.get("location"),
        ip_address: display_ip(row.get("ip_address")),
        system_version: row.get("system_version"),
        scanner_version: row.get("scanner_version"),
        cpu_model: row.get("cpu_model"),
        cpus: row.get("cpus"),
        ram: row.get("ram"),
        uptime: row.get("uptime"),
        create_time: row.get("create_time"),
        register_time: row.get("register_time"),
        update_time: row.get("update_time"),
        last_seen_at: row.get("last_seen_at"),
        runtime_state: row.get("runtime_state"),
        is_online: row.get("is_online"),
        current_task_id: row.get("current_task_id"),
        is_run: row.get("is_run"),
        is_enable: row.get("is_enable"),
        remark: row.get("remark"),
        tag: row.get("tag"),
        supports_ipv4: row.get("supports_ipv4"),
        supports_ipv6: row.get("supports_ipv6"),
        ipv4_ready: row.get("ipv4_ready"),
        ipv6_ready: row.get("ipv6_ready"),
        public_ipv4: display_ip(row.get("public_ipv4")),
        public_ipv6: display_ip(row.get("public_ipv6")),
        network_status_reason: row.get("network_status_reason"),
        network_capabilities_updated_at: row.get("network_capabilities_updated_at"),
        scan_capabilities: row.get("scan_capabilities"),
        scan_capabilities_updated_at: row.get("scan_capabilities_updated_at"),
        latency,
    }
}

pub async fn get_scanners(pool: &Pool) -> Result<Vec<ScannerInfo>, Box<dyn std::error::Error>> {
    let connection = pool.get().await?;
    let query = format!(
        "{} WHERE s.deleted_at IS NULL ORDER BY s.create_time DESC NULLS LAST, s.id DESC;",
        scanner_info_select()
    );
    let rows = connection.query(&query, &[]).await?;
    Ok(rows.iter().map(scanner_info_from_row).collect())
}

pub async fn get_scanner(
    pool: &Pool,
    scanner_id: Uuid,
) -> Result<Option<ScannerInfo>, Box<dyn std::error::Error>> {
    let connection = pool.get().await?;
    let query = format!(
        "{} WHERE s.scanner_id = $1 AND s.deleted_at IS NULL LIMIT 1;",
        scanner_info_select()
    );
    let row = connection
        .query_opt(&query, &[&scanner_id.to_string()])
        .await?;
    Ok(row.as_ref().map(scanner_info_from_row))
}

// 扫描器健康检查
//
// pub async fn scanner_health(
//     pool: &Pool,

// )
