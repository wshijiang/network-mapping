//! Local user-administration commands.

use std::collections::{BTreeSet, HashSet};
use std::io::{self, IsTerminal, Read, Write};
use std::net::IpAddr;
use std::process::{Command, Stdio};

use chrono::{DateTime, Duration, Utc};
use cidr::IpCidr;
use deadpool_postgres::Pool;
use lettre::message::Mailbox;
use serde_json::{Value, json};
use tokio_postgres::error::SqlState;

use crate::audit::{AuditContext, AuditEvent, write as write_audit, write_standalone};
use crate::client_ip::display_ip;
use crate::config::{
    AllowlistCommand, LoginAccessCommand, LoginOutcome, OutputFormat, PagerMode, PasswordCommand,
    PasswordHashConfig, ServerCommand, SessionSelection, TwoFactorCommand, UserCommand,
};
use crate::identity::generate_hash_password;
use crate::login_allowlist::{display_login_allowlist, normalize_login_allowlist};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub async fn execute(
    command: &ServerCommand,
    pool: &Pool,
    password_config: PasswordHashConfig,
) -> CliResult {
    match command {
        ServerCommand::User { command } => execute_user(command, pool, password_config).await,
    }
}

async fn execute_user(
    command: &UserCommand,
    pool: &Pool,
    password_config: PasswordHashConfig,
) -> CliResult {
    match command {
        UserCommand::Password { command } => match command {
            PasswordCommand::Set {
                username,
                password_stdin,
                generate,
            } => set_password(pool, &password_config, username, *password_stdin, *generate).await,
        },
        UserCommand::TwoFactor { command } => match command {
            TwoFactorCommand::Clear { username, yes } => {
                clear_two_factor(pool, username, *yes).await
            }
        },
        UserCommand::Allowlist { command } => manage_allowlist(pool, command).await,
        UserCommand::Login { command } => manage_login_access(pool, command).await,
        UserCommand::Create {
            username,
            role,
            email,
            password_stdin,
            generate,
        } => {
            create_user(
                pool,
                &password_config,
                username,
                role.database_value(),
                email.as_deref(),
                *password_stdin,
                *generate,
            )
            .await
        }
        UserCommand::Show { username, sessions } => show_user(pool, username, *sessions).await,
        UserCommand::LoginLog {
            username,
            outcome,
            since,
            until,
            limit,
            all,
            format,
            pager,
        } => {
            show_login_log(
                pool,
                username,
                *outcome,
                since.as_deref(),
                until.as_deref(),
                if *all { None } else { Some(*limit) },
                *format,
                *pager,
            )
            .await
        }
    }
}

fn validate_username(username: &str) -> CliResult<String> {
    let username = username.trim();
    if !(3..=64).contains(&username.chars().count())
        || !username
            .chars()
            .all(|value| value.is_alphanumeric() || matches!(value, '_' | '-' | '.'))
    {
        return Err("用户名需为 3-64 个字母、数字、下划线、连字符或点".into());
    }
    Ok(username.to_owned())
}

fn read_password(password_stdin: bool, generate: bool) -> CliResult<(String, bool)> {
    if generate {
        let mut bytes = [0u8; 24];
        openssl::rand::rand_bytes(&mut bytes)?;
        const ALPHABET: &[u8] =
            b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";
        let password = bytes
            .iter()
            .map(|value| ALPHABET[*value as usize % ALPHABET.len()] as char)
            .collect();
        return Ok((password, true));
    }
    if password_stdin {
        let mut password = String::new();
        io::stdin().read_to_string(&mut password)?;
        return Ok((password.trim_end_matches(['\r', '\n']).to_owned(), false));
    }
    if !io::stdin().is_terminal() {
        return Err("标准输入不是终端；请使用 --password-stdin 或 --generate".into());
    }
    let password = rpassword::prompt_password("新密码：")?;
    let confirmation = rpassword::prompt_password("再次输入新密码：")?;
    if password != confirmation {
        return Err("两次输入的密码不一致".into());
    }
    Ok((password, false))
}

fn validate_password(password: &str) -> CliResult {
    if !(12..=256).contains(&password.chars().count()) {
        return Err("密码长度必须为 12-256 个字符".into());
    }
    Ok(())
}

async fn set_password(
    pool: &Pool,
    config: &PasswordHashConfig,
    username: &str,
    password_stdin: bool,
    generate: bool,
) -> CliResult {
    let username = validate_username(username)?;
    let (password, generated) = read_password(password_stdin, generate)?;
    validate_password(&password)?;
    let password_hash = generate_hash_password(&password, config.clone())
        .map_err(|error| format!("生成密码哈希失败：{error:?}"))?;
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    let row = transaction
        .query_opt(
            "SELECT id FROM users WHERE username = $1 AND role IN (1, 2) AND deleted_at IS NULL FOR UPDATE",
            &[&username],
        )
        .await?
        .ok_or("用户不存在或已删除")?;
    let user_id: i32 = row.get("id");
    transaction.execute(
        "UPDATE users SET password=$1, limit_login=FALSE, limit_at=NULL, limit_time=NULL, login_error_count=0, last_error_at=NULL, update_at=NOW() WHERE id=$2",
        &[&password_hash, &user_id],
    ).await?;
    let sessions = invalidate_sessions(&transaction, user_id, "password_reset").await?;
    let mut event = AuditEvent::system("user_security", "cli.user.password_set", "success")
        .resource("user", user_id.to_string());
    event.changes = Some(json!({"username": username, "invalidated_session_count": sessions}));
    write_audit(
        &transaction,
        &AuditContext::cli("user password set"),
        &event,
    )
    .await?;
    transaction.commit().await?;
    println!("用户 {username} 的密码已修改；已失效会话 {sessions} 个。");
    if generated {
        println!("新密码：{password}\n该密码只显示本次，请立即妥善保存。");
    }
    Ok(())
}

async fn create_user(
    pool: &Pool,
    config: &PasswordHashConfig,
    username: &str,
    role: i32,
    email: Option<&str>,
    password_stdin: bool,
    generate: bool,
) -> CliResult {
    let username = validate_username(username)?;
    let email = email.map(str::trim).filter(|value| !value.is_empty());
    if email.is_some_and(|value| value.len() > 320 || value.parse::<Mailbox>().is_err()) {
        return Err("邮箱格式不正确".into());
    }
    let (password, generated) = read_password(password_stdin, generate)?;
    validate_password(&password)?;
    let password_hash = generate_hash_password(&password, config.clone())
        .map_err(|error| format!("生成密码哈希失败：{error:?}"))?;
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    let row = match transaction.query_one(
        "INSERT INTO users(username,password,role,email,limit_login,login_error_count) VALUES($1,$2,$3,$4,FALSE,0) RETURNING id",
        &[&username, &password_hash, &role, &email],
    ).await {
        Ok(row) => row,
        Err(error) if error.code() == Some(&SqlState::UNIQUE_VIOLATION) => return Err("用户名已存在，已删除用户名也不能重复使用".into()),
        Err(error) => return Err(error.into()),
    };
    let user_id: i32 = row.get("id");
    let mut event = AuditEvent::system("user_security", "cli.user.create", "success")
        .resource("user", user_id.to_string());
    event.changes = Some(json!({"username": username, "role": role, "email": email}));
    write_audit(&transaction, &AuditContext::cli("user create"), &event).await?;
    transaction.commit().await?;
    println!("用户已创建：id={user_id} username={username}");
    if generated {
        println!("初始密码：{password}\n该密码只显示本次，请立即妥善保存。");
    }
    Ok(())
}

fn confirm_destructive(prompt: &str, yes: bool) -> CliResult {
    if yes {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        return Err("非交互环境执行该操作必须使用 --yes".into());
    }
    eprint!("{prompt} [y/N] ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        return Err("操作已取消".into());
    }
    Ok(())
}

async fn clear_two_factor(pool: &Pool, username: &str, yes: bool) -> CliResult {
    let username = validate_username(username)?;
    confirm_destructive(
        &format!("确认清除用户 {username} 的 2FA 并使其会话失效？"),
        yes,
    )?;
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    let row = transaction.query_opt(
        "SELECT id, enable_2fa FROM users WHERE username=$1 AND role IN (1,2) AND deleted_at IS NULL FOR UPDATE",
        &[&username],
    ).await?.ok_or("用户不存在或已删除")?;
    let user_id: i32 = row.get("id");
    let was_enabled: bool = row.get("enable_2fa");
    transaction
        .execute(
            "UPDATE users SET enable_2fa=FALSE, totp_secret=NULL, update_at=NOW() WHERE id=$1",
            &[&user_id],
        )
        .await?;
    let sessions = invalidate_sessions(&transaction, user_id, "totp_disabled").await?;
    transaction
        .execute(
            "UPDATE session SET pending_totp_secret=NULL, pending_totp_expires_at=NULL WHERE user_id=$1",
            &[&user_id],
        )
        .await?;
    let mut event = AuditEvent::system("user_security", "cli.user.2fa_clear", "success")
        .resource("user", user_id.to_string());
    event.changes = Some(
        json!({"username": username, "was_enabled": was_enabled, "invalidated_session_count": sessions}),
    );
    write_audit(&transaction, &AuditContext::cli("user 2fa clear"), &event).await?;
    transaction.commit().await?;
    println!("用户 {username} 的 2FA 已清除；已失效会话 {sessions} 个。");
    Ok(())
}

async fn invalidate_sessions(
    transaction: &tokio_postgres::Transaction<'_>,
    user_id: i32,
    reason: &str,
) -> Result<u64, tokio_postgres::Error> {
    transaction.execute(
        "UPDATE session SET is_enable=FALSE, deleted_at=NOW(), deletion_reason=$2, deleted_by_user_id=NULL WHERE user_id=$1 AND is_enable=TRUE AND deleted_at IS NULL",
        &[&user_id, &reason],
    ).await
}

async fn resolve_user_for_update(
    transaction: &tokio_postgres::Transaction<'_>,
    username: &str,
) -> CliResult<(i32, Vec<IpCidr>)> {
    let row = transaction.query_opt(
        "SELECT id, login_ip_allowlist FROM users WHERE username=$1 AND role IN (1,2) AND deleted_at IS NULL FOR UPDATE",
        &[&username],
    ).await?.ok_or("用户不存在或已删除")?;
    Ok((row.get("id"), row.get("login_ip_allowlist")))
}

async fn manage_allowlist(pool: &Pool, command: &AllowlistCommand) -> CliResult {
    match command {
        AllowlistCommand::List { username } => {
            let username = validate_username(username)?;
            let client = pool.get().await?;
            let row = client.query_opt(
                "SELECT login_ip_allowlist FROM users WHERE username=$1 AND role IN (1,2) AND deleted_at IS NULL",
                &[&username],
            ).await?.ok_or("用户不存在或已删除")?;
            let entries: Vec<IpCidr> = row.get("login_ip_allowlist");
            if entries.is_empty() {
                println!("用户 {username} 未启用登录 IP 白名单。");
            } else {
                for entry in display_login_allowlist(&entries) {
                    println!("{entry}");
                }
                println!("({} entries)", entries.len());
            }
            Ok(())
        }
        AllowlistCommand::Add { username, entries } => {
            update_allowlist(pool, username, entries, true, false).await
        }
        AllowlistCommand::Remove {
            username,
            entries,
            ignore_missing,
        } => update_allowlist(pool, username, entries, false, *ignore_missing).await,
    }
}

async fn update_allowlist(
    pool: &Pool,
    username: &str,
    requested: &[String],
    add: bool,
    ignore_missing: bool,
) -> CliResult {
    let username = validate_username(username)?;
    let requested = normalize_login_allowlist(requested)?;
    let requested_names = display_login_allowlist(&requested)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    let (user_id, old) = resolve_user_for_update(&transaction, &username).await?;
    let mut names = display_login_allowlist(&old)
        .into_iter()
        .collect::<BTreeSet<_>>();
    if add {
        names.extend(requested_names.iter().cloned());
    } else {
        let missing = requested_names
            .difference(&names)
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() && !ignore_missing {
            return Err(format!("白名单中不存在：{}", missing.join(", ")).into());
        }
        names.retain(|value| !requested_names.contains(value));
    }
    let new = normalize_login_allowlist(&names.into_iter().collect::<Vec<_>>())?;
    transaction
        .execute(
            "UPDATE users SET login_ip_allowlist=$2, update_at=NOW() WHERE id=$1",
            &[&user_id, &new],
        )
        .await?;
    let mut event = AuditEvent::system(
        "user_security",
        "cli.user.login_ip_allowlist_update",
        "success",
    )
    .resource("user", user_id.to_string());
    event.changes = Some(
        json!({"username": username, "old": display_login_allowlist(&old), "new": display_login_allowlist(&new)}),
    );
    write_audit(
        &transaction,
        &AuditContext::cli("user allowlist update"),
        &event,
    )
    .await?;
    transaction.commit().await?;
    println!("用户 {username} 的登录白名单已更新（{} 条）。", new.len());
    Ok(())
}

async fn manage_login_access(pool: &Pool, command: &LoginAccessCommand) -> CliResult {
    let (users, restrict, dry_run) = match command {
        LoginAccessCommand::Restrict { users, dry_run } => (users, true, *dry_run),
        LoginAccessCommand::Unrestrict { users, dry_run } => (users, false, *dry_run),
    };
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();
    for username in users {
        let username = validate_username(username)?;
        if seen.insert(username.clone()) {
            normalized.push(username);
        }
    }
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    let rows = transaction.query(
        "SELECT id, username, role, disabled_at IS NOT NULL AS disabled, limit_login FROM users WHERE username=ANY($1) AND role IN (1,2) AND deleted_at IS NULL FOR UPDATE",
        &[&normalized],
    ).await?;
    if rows.len() != normalized.len() {
        let found = rows
            .iter()
            .map(|row| row.get::<_, String>("username"))
            .collect::<HashSet<_>>();
        let missing = normalized
            .iter()
            .filter(|name| !found.contains(*name))
            .cloned()
            .collect::<Vec<_>>();
        return Err(format!("用户不存在或已删除：{}", missing.join(", ")).into());
    }
    if restrict {
        transaction
            .query(
                "SELECT id FROM users WHERE role=1 AND deleted_at IS NULL FOR UPDATE",
                &[],
            )
            .await?;
        let target_active_admins = rows
            .iter()
            .filter(|row| {
                row.get::<_, i32>("role") == 1
                    && !row.get::<_, bool>("disabled")
                    && !row.get::<_, bool>("limit_login")
            })
            .count() as i64;
        let active_admins: i64 = transaction.query_one(
            "SELECT COUNT(*) FROM users WHERE role=1 AND deleted_at IS NULL AND disabled_at IS NULL AND limit_login=FALSE",
            &[],
        ).await?.get(0);
        if active_admins - target_active_admins < 1 {
            return Err("不能限制最后一个有效管理员".into());
        }
    }
    println!(
        "将{}登录：{}",
        if restrict { "限制" } else { "解除限制" },
        normalized.join(", ")
    );
    if dry_run {
        transaction.rollback().await?;
        println!("dry-run：未修改数据库。");
        return Ok(());
    }
    let mut invalidated = 0u64;
    for row in &rows {
        let user_id: i32 = row.get("id");
        if restrict {
            transaction.execute("UPDATE users SET disabled_at=COALESCE(disabled_at,NOW()), update_at=NOW() WHERE id=$1", &[&user_id]).await?;
            invalidated += invalidate_sessions(&transaction, user_id, "user_disabled").await?;
        } else {
            transaction
                .execute(
                    "UPDATE users SET disabled_at=NULL, update_at=NOW() WHERE id=$1",
                    &[&user_id],
                )
                .await?;
        }
    }
    let mut event = AuditEvent::system(
        "user_security",
        if restrict {
            "cli.user.login_restrict"
        } else {
            "cli.user.login_unrestrict"
        },
        "success",
    );
    event.changes =
        Some(json!({"usernames": normalized, "invalidated_session_count": invalidated}));
    write_audit(
        &transaction,
        &AuditContext::cli("user login access"),
        &event,
    )
    .await?;
    transaction.commit().await?;
    println!("操作完成；已失效会话 {invalidated} 个。");
    Ok(())
}

async fn show_user(pool: &Pool, username: &str, sessions: SessionSelection) -> CliResult {
    let username = validate_username(username)?;
    let client = pool.get().await?;
    let row = client.query_opt(
        "SELECT id,username,email,role,create_time,limit_login,enable_2fa,last_login_at,last_login_ip,login_ip_allowlist,disabled_at,deleted_at FROM users WHERE username=$1 AND role IN (1,2)",
        &[&username],
    ).await?.ok_or("用户不存在")?;
    let user_id: i32 = row.get("id");
    let allowlist: Vec<IpCidr> = row.get("login_ip_allowlist");
    let disabled: Option<DateTime<Utc>> = row.get("disabled_at");
    let deleted: Option<DateTime<Utc>> = row.get("deleted_at");
    println!("ID              : {user_id}");
    println!("用户名          : {}", row.get::<_, String>("username"));
    println!(
        "角色            : {}",
        if row.get::<_, i32>("role") == 1 {
            "admin"
        } else {
            "user"
        }
    );
    println!(
        "邮箱            : {}",
        row.get::<_, Option<String>>("email")
            .unwrap_or_else(|| "-".into())
    );
    println!(
        "状态            : {}",
        if deleted.is_some() {
            "deleted"
        } else if disabled.is_some() {
            "restricted"
        } else if row.get::<_, bool>("limit_login") {
            "locked"
        } else {
            "active"
        }
    );
    println!(
        "2FA             : {}",
        if row.get::<_, bool>("enable_2fa") {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "创建时间        : {}",
        format_epoch_ms(row.get::<_, Option<i64>>("create_time"))
    );
    println!(
        "最后登录        : {}",
        format_epoch_ms(row.get::<_, Option<i64>>("last_login_at"))
    );
    println!(
        "最后登录 IP     : {}",
        display_ip(row.get::<_, Option<IpAddr>>("last_login_ip")).unwrap_or_else(|| "-".into())
    );
    println!(
        "登录白名单      : {}",
        if allowlist.is_empty() {
            "未启用".into()
        } else {
            display_login_allowlist(&allowlist).join(", ")
        }
    );
    if matches!(sessions, SessionSelection::None) {
        return Ok(());
    }
    let active_only = matches!(sessions, SessionSelection::Active);
    let rows = client.query(
        "SELECT id,create_time,ttl,totp_verify_successful,is_enable,deleted_at,deletion_reason, create_time + ttl::BIGINT*1000 > (EXTRACT(EPOCH FROM NOW())*1000)::BIGINT AS unexpired FROM session WHERE user_id=$1 AND (NOT $2 OR (is_enable=TRUE AND deleted_at IS NULL AND create_time + ttl::BIGINT*1000 > (EXTRACT(EPOCH FROM NOW())*1000)::BIGINT)) ORDER BY id DESC",
        &[&user_id, &active_only],
    ).await?;
    let body = rows
        .iter()
        .map(|session| {
            vec![
                session.get::<_, i32>("id").to_string(),
                format_epoch_ms(Some(session.get("create_time"))),
                format_epoch_ms(Some(
                    session.get::<_, i64>("create_time")
                        + i64::from(session.get::<_, i32>("ttl")) * 1000,
                )),
                session.get::<_, bool>("totp_verify_successful").to_string(),
                if session.get::<_, bool>("is_enable")
                    && session
                        .get::<_, Option<DateTime<Utc>>>("deleted_at")
                        .is_none()
                    && session.get::<_, bool>("unexpired")
                {
                    "active".into()
                } else {
                    "inactive".into()
                },
                session
                    .get::<_, Option<String>>("deletion_reason")
                    .unwrap_or_else(|| "-".into()),
            ]
        })
        .collect::<Vec<_>>();
    println!(
        "\n{}",
        render_table(
            &[
                "session_id",
                "created_at",
                "expires_at",
                "2fa_ok",
                "status",
                "reason"
            ],
            &body
        )
    );
    Ok(())
}

fn format_epoch_ms(value: Option<i64>) -> String {
    value
        .and_then(DateTime::<Utc>::from_timestamp_millis)
        .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| "-".into())
}

fn parse_time(value: Option<&str>, relative: bool) -> CliResult<Option<DateTime<Utc>>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if relative && value.len() >= 2 {
        let (number, unit) = value.split_at(value.len() - 1);
        if let Ok(number) = number.parse::<i64>() {
            let duration = match unit {
                "d" => Duration::days(number),
                "h" => Duration::hours(number),
                "m" => Duration::minutes(number),
                _ => Duration::zero(),
            };
            if duration != Duration::zero() {
                return Ok(Some(Utc::now() - duration));
            }
        }
    }
    Ok(Some(
        DateTime::parse_from_rfc3339(value)
            .map_err(|_| format!("无效时间：{value}"))?
            .with_timezone(&Utc),
    ))
}

#[allow(clippy::too_many_arguments)]
async fn show_login_log(
    pool: &Pool,
    username: &str,
    outcome: Option<LoginOutcome>,
    since: Option<&str>,
    until: Option<&str>,
    limit: Option<usize>,
    format: OutputFormat,
    pager: PagerMode,
) -> CliResult {
    let username = validate_username(username)?;
    let since = parse_time(since, true)?;
    let until = parse_time(until, false)?;
    if since.zip(until).is_some_and(|(start, end)| start > end) {
        return Err("--since 不能晚于 --until".into());
    }
    let limit = limit
        .map(i64::try_from)
        .transpose()
        .map_err(|_| "--limit 过大")?;
    if limit == Some(0) {
        return Err("--limit 必须大于 0".into());
    }
    let client = pool.get().await?;
    let user = client
        .query_opt(
            "SELECT id FROM users WHERE username=$1 AND role IN (1,2)",
            &[&username],
        )
        .await?
        .ok_or("用户不存在")?;
    let user_id: i32 = user.get("id");
    let actor_id = user_id.to_string();
    let outcome = outcome.map(|value| match value {
        LoginOutcome::Success => "success",
        LoginOutcome::Failure => "failure",
    });
    let rows = client.query(
        "SELECT event_id,occurred_at,outcome,COALESCE(metadata->>'auth_method','password') AS auth_method,source_ip,reason_code,user_agent FROM audit_event WHERE category='authentication' AND action='auth.login' AND (actor_id=$1 OR (actor_id IS NULL AND COALESCE(actor_name,metadata->>'attempted_username')=$2)) AND ($3::text IS NULL OR outcome=$3) AND ($4::timestamptz IS NULL OR occurred_at >= $4) AND ($5::timestamptz IS NULL OR occurred_at <= $5) ORDER BY occurred_at DESC,id DESC LIMIT $6",
        &[&actor_id, &username, &outcome, &since, &until, &limit],
    ).await?;
    let values = rows
        .iter()
        .map(|row| {
            json!({
                "event_id": row.get::<_, uuid::Uuid>("event_id"),
                "occurred_at": row.get::<_, DateTime<Utc>>("occurred_at"),
                "outcome": row.get::<_, String>("outcome"),
                "auth_method": row.get::<_, String>("auth_method"),
                "source_ip": display_ip(row.get::<_, Option<IpAddr>>("source_ip")),
                "reason_code": row.get::<_, Option<String>>("reason_code"),
                "user_agent": row.get::<_, Option<String>>("user_agent"),
            })
        })
        .collect::<Vec<Value>>();
    drop(client);
    let output = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&values)?,
        OutputFormat::Csv => render_login_csv(&values),
        OutputFormat::Table => {
            let body = values
                .iter()
                .map(|value| {
                    vec![
                        value["occurred_at"].as_str().unwrap_or("-").to_owned(),
                        value["outcome"].as_str().unwrap_or("-").to_owned(),
                        value["auth_method"].as_str().unwrap_or("-").to_owned(),
                        value["source_ip"].as_str().unwrap_or("-").to_owned(),
                        value["reason_code"].as_str().unwrap_or("-").to_owned(),
                        value["user_agent"].as_str().unwrap_or("-").to_owned(),
                    ]
                })
                .collect::<Vec<_>>();
            render_table(
                &[
                    "occurred_at",
                    "outcome",
                    "auth_method",
                    "source_ip",
                    "reason_code",
                    "user_agent",
                ],
                &body,
            )
        }
    };
    let mut audit = AuditEvent::system("audit", "cli.user.login_records_query", "success")
        .resource("user", user_id.to_string());
    audit.metadata = json!({"username": username, "result_count": values.len()});
    write_standalone(pool, &AuditContext::cli("user login-log"), &audit).await;
    output_with_pager(&output, pager)?;
    Ok(())
}

fn render_login_csv(values: &[Value]) -> String {
    let mut output =
        "occurred_at,outcome,auth_method,source_ip,reason_code,user_agent\n".to_owned();
    for value in values {
        let fields = [
            "occurred_at",
            "outcome",
            "auth_method",
            "source_ip",
            "reason_code",
            "user_agent",
        ];
        output.push_str(
            &fields
                .iter()
                .map(|field| csv_field(value[*field].as_str().unwrap_or("")))
                .collect::<Vec<_>>()
                .join(","),
        );
        output.push('\n');
    }
    output
}

fn csv_field(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let widths = headers
        .iter()
        .enumerate()
        .map(|(index, header)| {
            rows.iter()
                .filter_map(|row| row.get(index))
                .map(|value| value.chars().count())
                .chain(std::iter::once(header.chars().count()))
                .max()
                .unwrap_or(0)
        })
        .collect::<Vec<_>>();
    let line = |cells: Vec<String>| {
        cells
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                format!(
                    " {:width$} ",
                    value.replace(['\n', '\r'], " "),
                    width = widths[index]
                )
            })
            .collect::<Vec<_>>()
            .join("|")
    };
    let mut output = line(headers.iter().map(|value| (*value).to_owned()).collect());
    output.push('\n');
    output.push_str(
        &widths
            .iter()
            .map(|width| "-".repeat(width + 2))
            .collect::<Vec<_>>()
            .join("+"),
    );
    output.push('\n');
    for row in rows {
        output.push_str(&line(row.clone()));
        output.push('\n');
    }
    output.push_str(&format!(
        "({} {})",
        rows.len(),
        if rows.len() == 1 { "row" } else { "rows" }
    ));
    output
}

fn output_with_pager(output: &str, mode: PagerMode) -> CliResult {
    let use_pager = match mode {
        PagerMode::Always => true,
        PagerMode::Never => false,
        PagerMode::Auto => io::stdout().is_terminal() && output.lines().count() > 24,
    };
    if !use_pager {
        println!("{output}");
        return Ok(());
    }
    let pager = std::env::var("PAGER").unwrap_or_else(|_| "less".into());
    let mut child = Command::new(&pager)
        .arg("-FRSX")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| format!("无法启动分页器 {pager}：{error}"))?;
    child
        .stdin
        .as_mut()
        .ok_or("无法写入分页器")?
        .write_all(output.as_bytes())?;
    child.wait()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_and_rfc3339_times_are_accepted() {
        assert!(parse_time(Some("7d"), true).unwrap().is_some());
        assert!(
            parse_time(Some("2026-09-12T12:00:00Z"), false)
                .unwrap()
                .is_some()
        );
        assert!(parse_time(Some("nope"), true).is_err());
    }

    #[test]
    fn table_and_csv_escape_output() {
        assert!(render_table(&["a"], &[vec!["x\ny".into()]]).contains("x y"));
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
    }
}
