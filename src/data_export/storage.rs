use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;

use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::{ByteStream, Length, SdkBody};
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use aws_smithy_runtime_api::client::{
    http::{HttpConnector, HttpConnectorFuture, SharedHttpConnector, http_client_fn},
    orchestrator::{HttpRequest, HttpResponse},
    result::ConnectorError,
};
use deadpool_postgres::Pool;
use futures_util::stream::{self, StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::network_proxy::GlobalProxyState;
use crate::outbound_proxy::{self, ProxyConfig, ProxyMode};

use super::task::{self, Result};

const PART_SIZE: u64 = 16 * 1024 * 1024;
const MAX_PARTS: u64 = 10_000;

#[derive(Clone, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_mode: Option<ProxyMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) proxy_ciphertext: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) credential_ciphertext: Option<Vec<u8>>,
}

const CREDENTIALS_UNAVAILABLE: &str = "无法读取 S3 凭据，请检查服务器加密密钥或重新保存凭据";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct S3Credentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

impl S3Credentials {
    fn validate(&self) -> std::result::Result<(), String> {
        let valid = |value: &str, max| {
            !value.is_empty()
                && value.len() <= max
                && value.bytes().all(|byte| byte.is_ascii_graphic())
        };
        if !valid(&self.access_key_id, 256)
            || !valid(&self.secret_access_key, 1024)
            || self
                .session_token
                .as_deref()
                .is_some_and(|token| !valid(token, 16_384))
        {
            return Err(
                "请输入有效的 S3 Access Key ID、Secret Access Key 和可选 Session Token".into(),
            );
        }
        Ok(())
    }

    fn into_sdk(self) -> Credentials {
        Credentials::new(
            self.access_key_id,
            self.secret_access_key,
            self.session_token,
            None,
            "data-export",
        )
    }
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CredentialUpdate {
    AwsChain,
    Static { values: Option<S3Credentials> },
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.public().fmt(formatter)
    }
}

impl S3Config {
    pub fn validate(&self) -> std::result::Result<(), String> {
        for address in [&self.endpoint, &self.download_endpoint]
            .into_iter()
            .flatten()
        {
            let url = reqwest::Url::parse(address).map_err(|_| "S3 连接 URL 无效")?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/"
            {
                return Err("S3 连接 URL 必须是不含凭据与路径的 HTTP(S) 服务地址".into());
            }
        }
        if self.proxy_mode() == ProxyMode::Custom && self.proxy_ciphertext.is_none() {
            self.proxy_config("").map_err(|_| "S3 代理地址无效")?;
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

    pub(super) fn proxy_mode(&self) -> ProxyMode {
        self.proxy_mode.unwrap_or(if self.proxy_url.is_some() {
            ProxyMode::Custom
        } else {
            ProxyMode::Direct
        })
    }

    fn proxy_config(&self, key: &str) -> Result<ProxyConfig> {
        let mode = self.proxy_mode();
        let url = if mode != ProxyMode::Custom {
            String::new()
        } else if let Some(ciphertext) = &self.proxy_ciphertext {
            crate::secret::decrypt(ciphertext, key).map_err(|_| crate::secret::UNAVAILABLE)?
        } else {
            self.proxy_url.clone().ok_or("请输入 S3 代理地址")?
        };
        let config = ProxyConfig { mode, url };
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn with_proxy(
        mut self,
        current: Option<&S3Config>,
        key: &str,
    ) -> std::result::Result<Self, String> {
        let mode = self.proxy_mode();
        let input = self.proxy_url.take();
        self.proxy_mode = Some(mode);
        self.proxy_ciphertext = None;
        if mode != ProxyMode::Custom && input.is_some() {
            return Err("仅自定义模式允许填写 S3 代理地址".into());
        }
        if let Some(url) = input {
            self.store_proxy(&url, key)?;
        } else if let Some(previous) = current {
            if previous.proxy_ciphertext.is_some() {
                self.proxy_url = previous.proxy_url.clone();
                self.proxy_ciphertext = previous.proxy_ciphertext.clone();
            } else if let Some(url) = &previous.proxy_url {
                self.store_proxy(url, key)?;
            }
        }
        if mode == ProxyMode::Custom && self.proxy_ciphertext.is_none() {
            return Err("请输入 S3 代理地址".into());
        }
        self.validate()?;
        Ok(self)
    }

    fn store_proxy(&mut self, url: &str, key: &str) -> std::result::Result<(), String> {
        self.proxy_url = Some(outbound_proxy::endpoint(url).map_err(|_| "S3 代理地址无效")?);
        self.proxy_ciphertext = Some(crate::secret::encrypt(url, key).map_err(str::to_owned)?);
        Ok(())
    }

    pub(super) fn seal_proxy(mut self, key: &str) -> std::result::Result<Self, String> {
        if let Some(url) = self.proxy_url.take() {
            if self.proxy_ciphertext.is_some() {
                self.proxy_url =
                    Some(outbound_proxy::endpoint(&url).map_err(|_| "S3 代理地址无效")?);
            } else {
                self.store_proxy(&url, key)?;
            }
        }
        Ok(self)
    }

    pub(crate) fn with_credentials(
        mut self,
        current: Option<&S3Config>,
        update: Option<CredentialUpdate>,
        key: &str,
    ) -> std::result::Result<Self, String> {
        self.credential_ciphertext = match update {
            Some(CredentialUpdate::AwsChain) => None,
            Some(CredentialUpdate::Static {
                values: Some(credentials),
            }) => {
                credentials.validate()?;
                let serialized =
                    serde_json::to_string(&credentials).map_err(|_| CREDENTIALS_UNAVAILABLE)?;
                Some(
                    crate::secret::encrypt(&serialized, key)
                        .map_err(|_| CREDENTIALS_UNAVAILABLE)?,
                )
            }
            update => {
                let previous = current.and_then(|config| config.credential_ciphertext.clone());
                if update.is_some() && previous.is_none() {
                    return Err("请填写 S3 Access Key ID 和 Secret Access Key".into());
                }
                previous
            }
        };
        Ok(self)
    }

    fn credentials(&self, key: &str) -> Result<Option<Credentials>> {
        let Some(ciphertext) = &self.credential_ciphertext else {
            return Ok(None);
        };
        let serialized =
            crate::secret::decrypt(ciphertext, key).map_err(|_| CREDENTIALS_UNAVAILABLE)?;
        let credentials = serde_json::from_str::<S3Credentials>(&serialized)
            .map_err(|_| CREDENTIALS_UNAVAILABLE)?;
        credentials.validate()?;
        Ok(Some(credentials.into_sdk()))
    }

    pub fn public(&self) -> serde_json::Value {
        serde_json::json!({
            "endpoint": self.endpoint, "download_endpoint": self.download_endpoint,
            "region": self.region, "bucket": self.bucket, "prefix": self.prefix,
            "path_style": self.path_style, "proxy_download": self.proxy_download,
            "proxy_mode": self.proxy_mode(),
            "proxy_endpoint": self.proxy_url.as_deref().and_then(|url| outbound_proxy::endpoint(url).ok()),
            "proxy_configured": self.proxy_url.is_some() || self.proxy_ciphertext.is_some(),
            "credential_mode": if self.credential_ciphertext.is_some() { "static" } else { "aws_chain" },
        })
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

#[derive(Clone)]
pub struct Storage {
    sdk: Arc<OnceCell<aws_config::SdkConfig>>,
    global_proxy: GlobalProxyState,
    encryption_key: Arc<str>,
}

impl Storage {
    pub(crate) fn new(global_proxy: GlobalProxyState, encryption_key: &str) -> Self {
        Self {
            sdk: Arc::new(OnceCell::new()),
            global_proxy,
            encryption_key: Arc::from(encryption_key),
        }
    }

    pub(super) fn task_object(
        &self,
        target: S3Config,
        task: Uuid,
        attempt: Uuid,
    ) -> Result<Object> {
        // A queued task may predate encryption of deployment proxy snapshots.
        Ok(target
            .seal_proxy(&self.encryption_key)?
            .object(task, attempt))
    }

    pub(crate) fn prepare_connection(
        &self,
        connection: S3Config,
        current: Option<&S3Config>,
        credentials: Option<CredentialUpdate>,
    ) -> std::result::Result<S3Config, String> {
        connection
            .with_proxy(current, &self.encryption_key)?
            .with_credentials(current, credentials, &self.encryption_key)
    }

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
        if let Some(credentials) = target.credentials(&self.encryption_key)? {
            config = config.credentials_provider(credentials);
        }
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
        if !download {
            let proxy = self
                .global_proxy
                .resolve(&target.proxy_config(&self.encryption_key)?)
                .await?;
            if proxy.mode != ProxyMode::Direct {
                let connector = SharedHttpConnector::new(ProxyConnector(
                    proxy
                        .apply_to(
                            reqwest::Client::builder()
                                .redirect(reqwest::redirect::Policy::none())
                                .connect_timeout(Duration::from_secs(10)),
                        )?
                        .build()?,
                ));
                config = config.http_client(http_client_fn(move |_, _| connector.clone()));
            }
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

#[derive(Debug)]
struct ProxyConnector(reqwest::Client);

impl HttpConnector for ProxyConnector {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let client = self.0.clone();
        HttpConnectorFuture::new(async move {
            let request = request
                .try_into_http1x()
                .map_err(|error| ConnectorError::user(error.into()))?;
            let request = reqwest::Request::try_from(request.map(reqwest::Body::wrap))
                .map_err(|error| ConnectorError::user(error.without_url().into()))?;
            let response = client.execute(request).await.map_err(|error| {
                let timeout = error.is_timeout();
                let error = error.without_url().into();
                if timeout {
                    ConnectorError::timeout(error)
                } else {
                    ConnectorError::io(error)
                }
            })?;
            let response: http::Response<reqwest::Body> = response.into();
            HttpResponse::try_from(response.map(SdkBody::from_body_1_x))
                .map_err(|error| ConnectorError::user(error.into()))
        })
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
            proxy_url: None,
            proxy_mode: None,
            proxy_ciphertext: None,
            credential_ciphertext: None,
        }
    }

    fn storage() -> Storage {
        let sdk = aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .credentials_provider(aws_sdk_s3::config::SharedCredentialsProvider::new(
                aws_sdk_s3::config::Credentials::new("test-key", "test-secret", None, None, "test"),
            ))
            .build();
        Storage {
            sdk: Arc::new(OnceCell::new_with(Some(sdk))),
            ..Storage::new(GlobalProxyState::system(), "")
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
        let storage = storage();
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

    #[test]
    fn proxy_credentials_are_sealed_and_retained_across_mode_changes() {
        let key = openssl::base64::encode_block(&[7; 32]);
        let url = "socks5h://user:fixture-password@proxy.example.invalid:1080";
        let mut custom = target();
        custom.proxy_url = Some(url.to_owned());
        let custom = custom.with_proxy(None, &key).unwrap();
        assert_eq!(custom.proxy_config(&key).unwrap().url, url);
        assert!(!custom.public().to_string().contains("fixture-password"));
        assert!(
            !serde_json::to_string(&custom)
                .unwrap()
                .contains("fixture-password")
        );

        let mut direct = target();
        direct.proxy_mode = Some(ProxyMode::Direct);
        let direct = direct.with_proxy(Some(&custom), &key).unwrap();
        assert_eq!(direct.proxy_config(&key).unwrap().mode, ProxyMode::Direct);

        let mut restored = target();
        restored.proxy_mode = Some(ProxyMode::Custom);
        let restored = restored.with_proxy(Some(&direct), &key).unwrap();
        assert_eq!(restored.proxy_config(&key).unwrap().url, url);
    }

    #[test]
    fn worker_object_seals_legacy_proxy_and_preserves_encrypted_snapshots() {
        let key = openssl::base64::encode_block(&[8; 32]);
        let storage = Storage::new(GlobalProxyState::system(), &key);
        let url = "http://fixture-user:fixture-password@proxy.example.invalid:8080";
        let mut legacy = target();
        legacy.proxy_url = Some(url.into());
        let task = Uuid::new_v4();
        let attempt = Uuid::new_v4();

        let object = storage.task_object(legacy, task, attempt).unwrap();
        let locator = serde_json::to_value(&object).unwrap();
        assert_eq!(
            locator["target"]["proxy_url"],
            "http://proxy.example.invalid:8080/"
        );
        assert_eq!(object.target.proxy_config(&key).unwrap().url, url);
        assert_eq!(
            serde_json::to_value(storage.task_object(object.target, task, attempt).unwrap())
                .unwrap(),
            locator
        );
    }

    #[tokio::test]
    async fn saved_credentials_override_aws_chain_without_public_exposure() {
        let encryption_key = openssl::base64::encode_block(&[9; 32]);
        let configured = target()
            .with_credentials(
                None,
                Some(CredentialUpdate::Static {
                    values: Some(S3Credentials {
                        access_key_id: "managed-test-key".into(),
                        secret_access_key: "managed-test-secret".into(),
                        session_token: Some("managed-test-token".into()),
                    }),
                }),
                &encryption_key,
            )
            .unwrap();
        let retained = target()
            .with_credentials(Some(&configured), None, &encryption_key)
            .unwrap();
        assert_eq!(retained.public()["credential_mode"], "static");
        assert!(!retained.public().to_string().contains("managed-test-"));
        assert!(
            !serde_json::to_string(&retained)
                .unwrap()
                .contains("managed-test-")
        );

        let storage = Storage {
            encryption_key: Arc::from(encryption_key.as_str()),
            ..storage()
        };
        let object = retained.object(Uuid::new_v4(), Uuid::new_v4());
        let link = storage.link(&object, "attachment".into()).await.unwrap();
        let url = reqwest::Url::parse(&link).unwrap();
        let params: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert!(params["X-Amz-Credential"].starts_with("managed-test-key/"));
        assert_eq!(params["X-Amz-Security-Token"], "managed-test-token");

        let reset = target()
            .with_credentials(
                Some(&retained),
                Some(CredentialUpdate::AwsChain),
                &encryption_key,
            )
            .unwrap();
        assert_eq!(reset.public()["credential_mode"], "aws_chain");
        assert!(reset.credentials(&encryption_key).unwrap().is_none());
    }

    #[tokio::test]
    async fn sends_server_requests_through_configured_proxy() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut target = target();
        target.endpoint = Some("http://export-fixture.invalid".into());
        target.proxy_url = Some(format!("http://{}", listener.local_addr().unwrap()));
        let object = target.object(Uuid::new_v4(), Uuid::new_v4());
        let expected = format!("HEAD http://export-fixture.invalid/exports/{}", object.key);
        let proxy = async {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = BufReader::new(socket);
            let mut line = String::new();
            socket.read_line(&mut line).await.unwrap();
            assert!(line.starts_with(&expected), "{line}");
            loop {
                line.clear();
                assert_ne!(socket.read_line(&mut line).await.unwrap(), 0);
                if line == "\r\n" {
                    break;
                }
            }
            socket
                .get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        };
        let storage = storage();
        let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(storage.check_object(&object), proxy)
        })
        .await
        .unwrap();
        result.unwrap();
    }
}
