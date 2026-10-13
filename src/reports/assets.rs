use super::{chart, mail_config::ReportMailConfig};
use chrono::{DateTime, Utc};
use deadpool_postgres::GenericClient;
use uuid::Uuid;

pub const IMAGE_PREFIX: &str = "/mail/report-images/";

pub fn redact_path(path: &str) -> &str {
    if path.starts_with(IMAGE_PREFIX) {
        "/mail/report-images/[redacted]/trend.png"
    } else {
        path
    }
}

pub fn digest(bytes: &[u8]) -> Result<String, String> {
    openssl::hash::hash(openssl::hash::MessageDigest::sha256(), bytes)
        .map(|hash| hash.iter().map(|b| format!("{b:02x}")).collect())
        .map_err(|e| e.to_string())
}

pub fn token_hash(token: &str) -> Option<String> {
    if token.len() != 64
        || !token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    digest(token.as_bytes()).ok()
}

pub(crate) struct PreparedAsset {
    pub url: String,
    png: Vec<u8>,
    hash: String,
    sha256: String,
    lifetime_days: i32,
    expires: DateTime<Utc>,
}

impl PreparedAsset {
    pub fn prepare(
        png: Vec<u8>,
        config: &ReportMailConfig,
        at: DateTime<Utc>,
    ) -> Result<Self, String> {
        if png.len() > chart::MAX_PNG_BYTES {
            return Err("趋势图片超过大小限制".into());
        }
        let mut secret = [0u8; 32];
        openssl::rand::rand_bytes(&mut secret).map_err(|e| e.to_string())?;
        let token: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self {
            url: config.url(&format!("{IMAGE_PREFIX}{token}/trend.png")),
            hash: digest(token.as_bytes())?,
            sha256: digest(&png)?,
            png,
            lifetime_days: config.image_lifetime_days,
            expires: at + chrono::Duration::days(i64::from(config.image_lifetime_days)),
        })
    }

    pub async fn commit<C: GenericClient + Sync>(
        &self,
        client: &C,
        id: Uuid,
    ) -> Result<(), String> {
        client.execute("INSERT INTO report_mail_asset(report_id,renderer_version,width,height,png_bytes,sha256,token_hash,lifetime_days,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            &[&id, &chart::RENDERER_VERSION, &(chart::WIDTH as i32), &(chart::HEIGHT as i32), &self.png, &self.sha256, &self.hash, &self.lifetime_days, &self.expires]).await.map_err(|e|e.to_string())?;
        Ok(())
    }
}

/// Re-sending extends access without changing any archived bytes or reviving revocation.
pub async fn renew<C: GenericClient + Sync>(client: &C, id: Uuid) -> Result<(), String> {
    let revoked = client
        .query_opt(
            "SELECT revoked_at FROM report_mail_asset WHERE report_id = $1 FOR UPDATE",
            &[&id],
        )
        .await
        .map_err(|e| e.to_string())?;
    if revoked.is_some_and(|r| r.get::<_, Option<DateTime<Utc>>>("revoked_at").is_some()) {
        return Err("报告趋势图片已撤销，请生成修订版后发送".into());
    }
    client.execute("UPDATE report_mail_asset SET expires_at = GREATEST(expires_at, NOW() + lifetime_days * INTERVAL '1 day') WHERE report_id = $1 AND revoked_at IS NULL", &[&id])
        .await.map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tokens_are_scoped_secrets_and_paths_are_redacted() {
        let token = "a".repeat(64);
        assert!(token_hash(&token).is_some());
        assert_ne!(token_hash(&token).unwrap(), token);
        for value in ["../secret", "", &"g".repeat(64)] {
            assert!(token_hash(value).is_none());
        }
        assert_eq!(
            redact_path(&format!("{IMAGE_PREFIX}{token}/trend.png")),
            "/mail/report-images/[redacted]/trend.png"
        );
        assert_eq!(redact_path("/api/reports"), "/api/reports");
    }
}
