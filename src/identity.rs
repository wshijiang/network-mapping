//! identity domain implementation, migrated from the library root.

use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use deadpool_postgres::GenericClient;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rand;
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};
use password_hash::rand_core::OsRng;
use password_hash::{PasswordHash, SaltString};
use std::io;
use std::time::Instant;
use tokio_postgres::Row;
use tracing::{error, info};

use crate::admin::TotpInfo;
use crate::config::PasswordHashConfig;

pub fn generate_scanner_token(prefix: &str) -> Result<String, io::Error> {
    let mut token_buffer = [0u8; 36];
    rand::rand_bytes(&mut token_buffer).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(format!(
        "{}_{}",
        prefix,
        openssl::base64::encode_block(&token_buffer)
    ))
}

pub fn hash_scanner_token(token: &str, pepper: &str) -> Result<String, io::Error> {
    let key = PKey::hmac(pepper.as_bytes()).map_err(|e| io::Error::other(e.to_string()))?;
    let mut signer =
        Signer::new(MessageDigest::sha256(), &key).map_err(|e| io::Error::other(e.to_string()))?;
    signer
        .update(token.as_bytes())
        .map_err(|e| io::Error::other(e.to_string()))?;
    let digest = signer
        .sign_to_vec()
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(openssl::base64::encode_block(&digest))
}

pub struct UserLoginInfo {
    pub username: String,
    pub role: i32,
    pub email_address: Option<String>,
    pub twofa: Option<TotpInfo>,
    pub login_ip_allowlist: Vec<cidr::IpCidr>,
}

/// 生成 Argon2id 哈希
///
/// 用于添加用户
pub fn generate_hash_password(
    password: &str,
    config: PasswordHashConfig,
) -> Result<String, password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(config.m * 1024, config.t, config.p, None)?; // 配置文件中默认 64 MiB, 2 次迭代, 2 并行
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

/// 用于从数据库中获得用户的密码哈希值和在表中的 ID ，返回一个 Result<(i32, String), Error>
pub async fn get_password_and_id_from_database(
    pool: &deadpool_postgres::Pool,
    username: &str,
) -> Result<Option<(i32, String, UserLoginInfo)>, Box<dyn std::error::Error>> {
    let client = pool.get().await?;
    if let Some(row) = client.query_opt(
        "SELECT id, username, password, role, email, enable_2fa, totp_secret, login_ip_allowlist FROM users \
         WHERE limit_login = FALSE AND disabled_at IS NULL AND deleted_at IS NULL AND username = $1",
        &[&username]
    ).await? {
        // TODO 需要改进，避免闭包获得所有权
        let get_twofa_info = |row: Row| -> Option<TotpInfo> {
            if row.get::<_, bool>("enable_2fa") {
                Some(TotpInfo {
                    username: row.get::<_, String>("username"),
                    // email_address: row.get::<_, String>("email"),
                    totp_secret: row.get::<_, String>("totp_secret")
                })
            } else {
                None
            }
        };

        let u_id = row.get::<_, i32>("id");
        let u_pwd = row.get::<_, String>("password");

        let userinfo = UserLoginInfo {
            username: username.to_string(),
            role: row.get::<_, i32>("role"),
            email_address: row.get::<_, Option<String>>("email"),
            login_ip_allowlist: row.get("login_ip_allowlist"),
            twofa: get_twofa_info(row),
        };

        Ok(Some((u_id, u_pwd, userinfo)))
    }
    else {
        Ok(None)
    }
}

/// 校验密码
pub fn verify_password(password: &str, hash: &str) -> bool {
    let start = Instant::now();

    match PasswordHash::new(hash) {
        Ok(parsed_hash) => {
            let argon2 = Argon2::default();
            let result = argon2
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok();
            tracing::debug!(
                event = "PasswordHashVerified",
                duration_ms = start.elapsed().as_millis() as u64
            );
            result
        }
        Err(e) => {
            error!(
                event = "ParsedHashError",
                operation = "parse_password_hash",
                error_kind = "credential_storage",
                error_code = "stored_password_hash_invalid",
                error_message = %e,
                retryable = false,
                outcome = "authentication_failed_closed",
            );
            tracing::debug!(
                event = "PasswordHashVerificationFailed",
                duration_ms = start.elapsed().as_millis() as u64
            );
            false
        }
    }
}

/// 该函数用于退出登录
///
/// 返回一个 Result<bool> ，返回 true 代表该 token 已被正常销毁，返回 false 代表 token 本身就是无效的。
pub async fn log_out(
    session: &str,
    pool: &deadpool_postgres::Pool,
    reason: &str,
    deleted_by_user_id: Option<i32>,
) -> Result<bool, Box<dyn std::error::Error>> {
    let c = pool.get().await?;
    if let Some(tmp_r) = c
        .query_opt(
            "UPDATE session SET is_enable = FALSE, deleted_at = NOW(), \
             deletion_reason = $2, deleted_by_user_id = $3 \
             WHERE token = $1 AND is_enable = TRUE AND deleted_at IS NULL RETURNING id;",
            &[&session, &reason, &deleted_by_user_id],
        )
        .await?
    {
        info!(
            event = "UserLogout",
            path = "fn log_out",
            message = "用户已退出登录"
        );
        let t_l = tmp_r.len();
        if t_l != 1 {
            error!(
                event = "LogoutSessionShapeError",
                operation = "disable_login_session",
                error_kind = "data_integrity",
                error_code = "logout_session_return_shape_invalid",
                error_message = "logout update returned an unexpected column count",
                retryable = false,
                outcome = "session_disabled_with_unexpected_response",
                deleted_by_user_id = ?deleted_by_user_id,
                deletion_reason = reason,
                returned_column_count = t_l,
            );
        }
        Ok(true)
    } else {
        info!(
            event = "TokenInvaild",
            path = "fn log_out",
            message = "Token 无效"
        );
        Ok(false)
    }
}

/// 该枚举定义了权限，其中系统权限最高，该级别的用户由初始化数据库时创建，且该权限的用户无法查看其他用户的数据，该权限主要用于系统自动创建的扫描任务
/// Administrator 为管理员权限，该权限可以查看所有的任务
/// 使用枚举时需要传入一个用户id
pub enum Permission {
    Administrator(i32),
    Users(i32),
}

pub fn encrypt_data(
    plaintext: &[u8],
    key: &[u8],
) -> Result<EncryptedData, openssl::error::ErrorStack> {
    // 32 字节密钥，且初始化为 1
    // let mut key = [1u8; 32];
    // rand::rand_bytes(&mut key)?;

    // 12 字节nonce ，初始化为 0
    let mut nonce = [0u8; 12];
    rand::rand_bytes(&mut nonce)?;

    let cipher = Cipher::aes_256_gcm();

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(&nonce))?;

    // GCM 不需要 padding
    crypter.pad(false);

    let mut ciphertext = vec![0u8; plaintext.len() + cipher.block_size()];

    let count = crypter.update(plaintext, &mut ciphertext)?;

    let rest = crypter.finalize(&mut ciphertext[count..])?;

    ciphertext.truncate(count + rest);

    let mut tag = [0u8; 16];
    crypter.get_tag(&mut tag)?;

    Ok((nonce.to_vec(), tag.to_vec(), ciphertext))
}

/// 解密
///
pub fn decrypt_data(
    // value: &[u8],
    value: &[u8],
    // ciphertext: &[u8],
    key: &[u8],
    // nonce: &[u8],
    // tag: &[u8],
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let nonce = &value[..12];
    let tag = &value[12..28];
    let ciphertext = &value[28..];

    let cipher = Cipher::aes_256_gcm();

    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(nonce))?;

    crypter.pad(false);

    crypter.set_tag(tag)?;

    let mut plaintext = vec![0u8; ciphertext.len() + cipher.block_size()];

    let count = crypter.update(ciphertext, &mut plaintext)?;

    let rest = crypter.finalize(&mut plaintext[count..])?;

    plaintext.truncate(count + rest);

    Ok(plaintext)
}

type EncryptedData = (Vec<u8>, Vec<u8>, Vec<u8>);
