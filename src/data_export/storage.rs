use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;

use aws_sdk_s3::Client;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::{ByteStream, Length};
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use deadpool_postgres::Pool;
use futures_util::stream::{self, StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::task::{self, Result};

const PART_SIZE: u64 = 16 * 1024 * 1024;
const MAX_PARTS: u64 = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct S3Config {
    pub endpoint: Option<String>,
    pub download_endpoint: Option<String>,
    pub region: String,
    pub bucket: String,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub path_style: bool,
    #[serde(default)]
    pub proxy_download: bool,
}

impl S3Config {
    pub fn validate(&self) -> std::result::Result<(), String> {
        for address in [&self.endpoint, &self.download_endpoint]
            .into_iter()
            .flatten()
        {
            let url = reqwest::Url::parse(address).map_err(|_| "S3 endpoint URL 无效")?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/"
            {
                return Err("S3 endpoint 必须是 HTTP(S) 服务地址".into());
            }
        }
        if self.region.is_empty()
            || !self
                .region
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || self.bucket.is_empty()
            || !self
                .bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
            || self.prefix.len() > 800
            || self.prefix.chars().any(char::is_control)
            || self
                .prefix
                .split('/')
                .any(|segment| matches!(segment, "." | ".."))
        {
            return Err("S3 region、bucket 或 prefix 无效".into());
        }
        Ok(())
    }

    pub fn object(&self, task: Uuid, attempt: Uuid) -> Object {
        let prefix = self.prefix.trim_matches('/');
        let key = format!("{task}/{attempt}.csv");
        Object {
            target: self.clone(),
            key: if prefix.is_empty() {
                key
            } else {
                format!("{prefix}/{key}")
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Object {
    pub target: S3Config,
    pub key: String,
}

#[derive(Clone, Default)]
pub struct Storage {
    sdk: Arc<OnceCell<aws_config::SdkConfig>>,
}

impl Storage {
    async fn client(&self, target: &S3Config, download: bool) -> Result<Client> {
        target.validate()?;
        let sdk = self
            .sdk
            .get_or_init(|| async {
                aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .region(Region::new(target.region.clone()))
                    .timeout_config(
                        aws_sdk_s3::config::timeout::TimeoutConfig::builder()
                            .operation_attempt_timeout(Duration::from_secs(90))
                            .operation_timeout(Duration::from_secs(300))
                            .build(),
                    )
                    .load()
                    .await
            })
            .await;
        let mut config = aws_sdk_s3::config::Builder::from(sdk)
            .region(Region::new(target.region.clone()))
            .force_path_style(target.path_style)
            .request_checksum_calculation(
                aws_sdk_s3::config::RequestChecksumCalculation::WhenRequired,
            )
            .response_checksum_validation(
                aws_sdk_s3::config::ResponseChecksumValidation::WhenRequired,
            );
        let endpoint = if download {
            target
                .download_endpoint
                .as_ref()
                .or(target.endpoint.as_ref())
        } else {
            target.endpoint.as_ref()
        };
        if let Some(endpoint) = endpoint {
            config = config.endpoint_url(endpoint);
        }
        Ok(Client::from_conf(config.build()))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upload(
        &self,
        pool: &Pool,
        attempt: Uuid,
        object: &Object,
        path: &Path,
        size: u64,
        concurrency: usize,
        cancel: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let client = self.client(&object.target, false).await?;
        let bucket = &object.target.bucket;
        let key = &object.key;
        if *cancel.borrow() {
            return Err("导出已取消".into());
        }
        if size <= PART_SIZE {
            let send = client
                .put_object()
                .bucket(bucket)
                .key(key)
                .content_type("text/csv; charset=utf-8")
                .body(ByteStream::from_path(path).await?)
                .send();
            tokio::select! {
                result = send => { result?; }
                _ = cancel.changed() => return Err("导出已取消".into()),
            }
            return Ok(());
        }

        let part_size = PART_SIZE.max(size.div_ceil(MAX_PARTS));
        let initiated = client
            .create_multipart_upload()
            .bucket(bucket)
            .key(key)
            .content_type("text/csv; charset=utf-8")
            .send()
            .await?;
        let upload_id = initiated.upload_id().ok_or("S3 未返回分片上传 ID")?;
        let transfer = async {
            task::record_multipart(pool, attempt, Some(upload_id)).await?;
            let mut parts: Vec<CompletedPart> = stream::iter(0..size.div_ceil(part_size))
                .map(|index| {
                    let client = &client;
                    async move {
                        let offset = index * part_size;
                        let part_number = (index + 1) as i32;
                        let body = ByteStream::read_from()
                            .path(path)
                            .offset(offset)
                            .length(Length::Exact(part_size.min(size - offset)))
                            .build()
                            .await?;
                        let part = client
                            .upload_part()
                            .bucket(bucket)
                            .key(key)
                            .upload_id(upload_id)
                            .part_number(part_number)
                            .body(body)
                            .send()
                            .await?;
                        let etag = part.e_tag().ok_or("S3 未返回分片 ETag")?;
                        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                            CompletedPart::builder()
                                .part_number(part_number)
                                .e_tag(etag)
                                .build(),
                        )
                    }
                })
                .buffer_unordered(concurrency)
                .try_collect()
                .await?;
            parts.sort_unstable_by_key(|part| part.part_number());
            client
                .complete_multipart_upload()
                .bucket(bucket)
                .key(key)
                .upload_id(upload_id)
                .multipart_upload(
                    CompletedMultipartUpload::builder()
                        .set_parts(Some(parts))
                        .build(),
                )
                .send()
                .await?;
            Ok(())
        };
        let upload = tokio::select! {
            result = transfer => result,
            _ = cancel.changed() => Err("导出已取消".into()),
        };
        if upload.is_err()
            && let Err(error) = abort_multipart(&client, object, upload_id).await
        {
            tracing::warn!(event = "DataExportAbortUploadFailed", %error);
            return upload;
        }
        // An already completed or aborted multipart upload is harmless if its
        // ID survives a transient database error here.
        if let Err(error) = task::record_multipart(pool, attempt, None).await {
            tracing::warn!(event = "DataExportClearUploadFailed", %error);
        }
        upload
    }

    pub async fn check_object(&self, object: &Object) -> Result<()> {
        self.client(&object.target, false)
            .await?
            .head_object()
            .bucket(&object.target.bucket)
            .key(&object.key)
            .send()
            .await?;
        Ok(())
    }

    pub async fn download(
        &self,
        object: &Object,
    ) -> Result<aws_sdk_s3::operation::get_object::GetObjectOutput> {
        Ok(self
            .client(&object.target, false)
            .await?
            .get_object()
            .bucket(&object.target.bucket)
            .key(&object.key)
            .send()
            .await?)
    }

    pub async fn link(&self, object: &Object, disposition: String) -> Result<String> {
        let request = self
            .client(&object.target, true)
            .await?
            .get_object()
            .bucket(&object.target.bucket)
            .key(&object.key)
            .response_content_disposition(disposition)
            .presigned(PresigningConfig::expires_in(Duration::from_secs(60))?)
            .await?;
        Ok(request.uri().to_owned())
    }

    pub async fn delete(&self, object: &Object, upload_id: Option<&str>) -> Result<()> {
        let client = self.client(&object.target, false).await?;
        if let Some(upload_id) = upload_id {
            abort_multipart(&client, object, upload_id).await?;
        }
        client
            .delete_object()
            .bucket(&object.target.bucket)
            .key(&object.key)
            .send()
            .await?;
        Ok(())
    }

    pub async fn test(&self, target: &S3Config) -> Result<()> {
        let object = target.object(Uuid::new_v4(), Uuid::new_v4());
        let client = self.client(target, false).await?;
        let uploaded = client
            .put_object()
            .bucket(&target.bucket)
            .key(&object.key)
            .body(ByteStream::from_static(
                b"network-mapping export storage check",
            ))
            .send()
            .await;
        let checked = match uploaded {
            Ok(_) => match self.download(&object).await {
                Ok(output) => output.body.collect().await.map(|_| ()).map_err(Into::into),
                Err(error) => Err(error),
            },
            Err(error) => Err(error.into()),
        };
        let deleted = self.delete(&object, None).await;
        checked.and(deleted)
    }
}

async fn abort_multipart(client: &Client, object: &Object, upload_id: &str) -> Result<()> {
    let result = client
        .abort_multipart_upload()
        .bucket(&object.target.bucket)
        .key(&object.key)
        .upload_id(upload_id)
        .send()
        .await;
    match result {
        Ok(_) => Ok(()),
        Err(error)
            if error
                .as_service_error()
                .is_some_and(|service| service.is_no_such_upload()) =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> S3Config {
        S3Config {
            endpoint: Some("http://127.0.0.1:9000".into()),
            download_endpoint: Some("https://download.example.invalid".into()),
            region: "us-east-1".into(),
            bucket: "exports".into(),
            prefix: "/data/exports/".into(),
            path_style: true,
            proxy_download: false,
        }
    }

    #[test]
    fn attempt_keys_isolate_reclaimed_tasks() {
        let target = target();
        let task = Uuid::new_v4();
        let attempt = Uuid::new_v4();
        assert_eq!(
            target.object(task, attempt).key,
            format!("data/exports/{task}/{attempt}.csv")
        );
        assert_ne!(
            target.object(task, attempt).key,
            target.object(task, Uuid::new_v4()).key
        );
    }

    #[tokio::test]
    async fn signs_path_style_download_for_browser_endpoint() {
        let sdk = aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .credentials_provider(aws_sdk_s3::config::SharedCredentialsProvider::new(
                aws_sdk_s3::config::Credentials::new("test-key", "test-secret", None, None, "test"),
            ))
            .build();
        let storage = Storage {
            sdk: Arc::new(OnceCell::new_with(Some(sdk))),
        };
        let object = target().object(Uuid::new_v4(), Uuid::new_v4());
        let link = storage
            .link(&object, "attachment; filename=export.csv".into())
            .await
            .unwrap();
        let url = reqwest::Url::parse(&link).unwrap();
        assert_eq!(url.host_str(), Some("download.example.invalid"));
        assert_eq!(url.path(), format!("/exports/{}", object.key));
        let params: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert_eq!(
            params.get("X-Amz-Expires").map(|value| value.as_ref()),
            Some("60")
        );
        assert_eq!(
            params
                .get("response-content-disposition")
                .map(|value| value.as_ref()),
            Some("attachment; filename=export.csv")
        );
        assert!(params.contains_key("X-Amz-Signature"));
    }
}
