use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::runtime_config::{PersistError, Versioned, load_namespace, persist};

use super::{DataExportConfig, storage::S3Config, task::Result};

pub const NAMESPACE: &str = "data_export";
pub const MAX_WORKERS: usize = 4;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub local: bool,
    pub s3: bool,
    pub batch_size: u32,
    pub workers: usize,
    pub upload_concurrency: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s3_override: Option<S3Config>,
}

impl Settings {
    pub fn defaults(config: &DataExportConfig) -> Self {
        Self {
            local: true,
            s3: false,
            batch_size: config.batch_size,
            workers: 1,
            upload_concurrency: 2,
            s3_override: None,
        }
    }

    pub fn validate(&self) -> std::result::Result<(), String> {
        if !self.local && !self.s3 {
            return Err("至少选择一个导出保存位置".into());
        }
        if !(1..=10_000).contains(&self.batch_size) {
            return Err("每批读取行数须在 1 到 10000 之间".into());
        }
        if !(1..=MAX_WORKERS).contains(&self.workers) {
            return Err("导出任务并发须在 1 到 4 之间".into());
        }
        if !(1..=8).contains(&self.upload_concurrency) {
            return Err("S3 分片上传并发须在 1 到 8 之间".into());
        }
        if let Some(connection) = &self.s3_override {
            connection.validate()?;
        }
        Ok(())
    }

    pub fn connection<'a>(&'a self, config: &'a DataExportConfig) -> Option<&'a S3Config> {
        self.s3_override.as_ref().or(config.s3.as_ref())
    }
}

#[derive(Debug)]
pub enum SaveError {
    Invalid(String),
    Conflict,
    Database(String),
}

impl std::fmt::Display for SaveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::Database(message) => formatter.write_str(message),
            Self::Conflict => formatter.write_str("设置已被修改，请重新加载后再保存"),
        }
    }
}

impl std::error::Error for SaveError {}

pub async fn save(
    pool: &Pool,
    config: &DataExportConfig,
    expected_revision: i64,
    document: &Settings,
    reason: &str,
    actor_id: i32,
) -> std::result::Result<i64, SaveError> {
    document.validate().map_err(SaveError::Invalid)?;
    if document.s3 && document.connection(config).is_none() {
        return Err(SaveError::Invalid(
            "启用 S3 保存位置前需要配置 S3 连接".into(),
        ));
    }
    persist(
        pool,
        NAMESPACE,
        expected_revision,
        document,
        reason,
        actor_id,
    )
    .await
    .map_err(|error| match error {
        PersistError::Conflict => SaveError::Conflict,
        PersistError::Other(message) => SaveError::Database(message),
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plan {
    pub revision: i64,
    pub local: bool,
    pub s3: Option<S3Config>,
    pub batch_size: u32,
    pub upload_concurrency: usize,
}

pub async fn init(pool: &Pool, config: &DataExportConfig) -> Result<()> {
    let defaults = Settings::defaults(config);
    load_namespace(
        pool,
        NAMESPACE,
        defaults.clone(),
        defaults,
        Settings::validate,
    )
    .await?;
    Ok(())
}

pub async fn read(pool: &Pool, config: &DataExportConfig) -> Result<Versioned<Settings>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT document, revision FROM runtime_configuration WHERE namespace=$1",
            &[&NAMESPACE],
        )
        .await?;
    let Some(row) = row else {
        return Ok(Versioned {
            value: Settings::defaults(config),
            revision: 0,
        });
    };
    let document: Value = row.get(0);
    let value = serde_json::from_value::<Settings>(document)?;
    value.validate()?;
    Ok(Versioned {
        value,
        revision: row.get(1),
    })
}

pub async fn plan(pool: &Pool, config: &DataExportConfig) -> Result<Plan> {
    let current = read(pool, config).await?;
    let s3 = if current.value.s3 {
        Some(
            current
                .value
                .connection(config)
                .cloned()
                .ok_or("S3 连接配置不可用")?,
        )
    } else {
        None
    };
    Ok(Plan {
        revision: current.revision,
        local: current.value.local,
        s3,
        batch_size: current.value.batch_size,
        upload_concurrency: current.value.upload_concurrency,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_and_performance_limits_are_enforced() {
        let mut settings = Settings::defaults(&DataExportConfig::default());
        assert!(settings.validate().is_ok());
        settings.local = false;
        assert!(settings.validate().is_err());
        settings.s3 = true;
        settings.workers = MAX_WORKERS;
        settings.batch_size = 10_000;
        settings.upload_concurrency = 8;
        assert!(settings.validate().is_ok());
        settings.workers += 1;
        assert!(settings.validate().is_err());
    }
}
