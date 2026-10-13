//! Production report-render selection, publication and configuration reconciliation.
use super::render_module::{INPUT_SCHEMA, LocalReportRenderModule, MODULE_ID, OUTPUT_SCHEMA};
use crate::module_runtime::{
    Module, ModuleError, ModuleRegistry, ModuleSlot, PreparedModule, process::ProcessModule,
};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::sync::Mutex;

pub const NAMESPACE: &str = "report_renderer";
const SCHEMA_VERSION: i32 = 1;

#[derive(Debug)]
pub enum PublishError {
    InvalidCandidate(String),
    Persistence(crate::runtime_config::PersistError),
    Activation { revision: i64, error: String },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RendererStatus {
    pub applied_revision: u64,
    pub applied_release_id: Option<String>,
    pub available: bool,
    pub last_refresh_error: Option<String>,
}

impl RendererStatus {
    pub fn converged(&self, desired_revision: i64) -> bool {
        self.available && u64::try_from(desired_revision).ok() == Some(self.applied_revision)
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReportRendererConfig {
    pub releases_directory: Option<PathBuf>,
}

impl ReportRendererConfig {
    pub(crate) fn resolve_relative_to(&mut self, config: &Path) {
        if let Some(directory) = &mut self.releases_directory
            && directory.is_relative()
        {
            *directory = config
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .join(&*directory);
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RendererSelection {
    pub release_id: String,
}

impl Default for RendererSelection {
    fn default() -> Self {
        Self {
            release_id: "builtin".into(),
        }
    }
}

impl RendererSelection {
    pub fn validate(&self) -> Result<(), String> {
        if !self
            .release_id
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
            || self.release_id.len() > 128
            || self.release_id.contains("..")
            || !self
                .release_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
        {
            return Err("releaseId 必须是有效制品名称，不能包含路径".into());
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseManifest {
    release_id: String,
    artifact_sha256: String,
}

struct Inner {
    registry: Arc<ModuleRegistry>,
    config: ReportRendererConfig,
    changes: Mutex<()>,
    last_refresh_error: RwLock<Option<String>>,
}

#[derive(Clone)]
pub struct ReportRenderService(Arc<Inner>);

impl ReportRenderService {
    fn empty(config: ReportRendererConfig) -> Result<Self, String> {
        let slot = ModuleSlot {
            rpc_version: 1,
            input_schema: INPUT_SCHEMA.into(),
            output_schema: OUTPUT_SCHEMA.into(),
            methods: BTreeSet::from(["render".into()]),
            max_inflight: 8,
            max_payload_bytes: 1024 * 1024,
            request_timeout: Duration::from_secs(5),
            prepare_timeout: Duration::from_secs(15),
        };
        let registry = ModuleRegistry::new(BTreeMap::from([(MODULE_ID.into(), slot)]))
            .map_err(|e| e.to_string())?;
        Ok(Self(Arc::new(Inner {
            registry: Arc::new(registry),
            config,
            changes: Mutex::new(()),
            last_refresh_error: RwLock::new(None),
        })))
    }

    #[cfg(test)]
    pub(crate) async fn builtin() -> Self {
        let service = Self::empty(Default::default()).unwrap();
        service
            .0
            .registry
            .publish(0, Arc::new(LocalReportRenderModule))
            .await
            .unwrap();
        service
    }

    pub fn registry(&self) -> &Arc<ModuleRegistry> {
        &self.0.registry
    }

    pub async fn status(&self) -> RendererStatus {
        let lease = self.0.registry.acquire(MODULE_ID).await.ok();
        RendererStatus {
            // Derive both identity and revision from one pinned generation,
            // so a racing publication cannot combine two different versions.
            applied_revision: lease.as_ref().map_or(0, |lease| lease.generation()),
            applied_release_id: lease.as_ref().map(|lease| lease.release_id().to_owned()),
            available: lease.as_ref().is_some_and(|lease| lease.is_available()),
            last_refresh_error: self.0.last_refresh_error.read().unwrap().clone(),
        }
    }

    pub async fn from_database(pool: &Pool, config: ReportRendererConfig) -> Result<Self, String> {
        let service = Self::empty(config)?;
        let client = pool.get().await.map_err(|e| e.to_string())?;
        let document =
            serde_json::to_value(RendererSelection::default()).map_err(|e| e.to_string())?;
        client.execute("INSERT INTO runtime_configuration(namespace,document) VALUES($1,$2) ON CONFLICT(namespace) DO NOTHING", &[&NAMESPACE,&document]).await.map_err(|e| e.to_string())?;
        client.execute("INSERT INTO runtime_configuration_revision(namespace,revision,schema_version,document,change_reason) SELECT namespace,revision,schema_version,document,'initial renderer seed' FROM runtime_configuration WHERE namespace=$1 ON CONFLICT(namespace,revision) DO NOTHING", &[&NAMESPACE]).await.map_err(|e| e.to_string())?;
        drop(client);
        // The database is required by the host, but this optional renderer is
        // not. Keep its desired selection unchanged and let reconciliation
        // retry; do not silently use another renderer under the same revision.
        if let Err(error) = service.refresh(pool).await {
            tracing::warn!(event="ReportRendererStartupDegraded", %error);
        }
        Ok(service)
    }

    async fn prepare(&self, selection: &RendererSelection) -> Result<PreparedModule, String> {
        selection.validate()?;
        let implementation: Arc<dyn Module> = if selection.release_id == "builtin" {
            Arc::new(LocalReportRenderModule)
        } else {
            let root = self
                .0
                .config
                .releases_directory
                .clone()
                .ok_or("尚未配置 report_renderer.releases_directory")?;
            let release = selection.release_id.clone();
            let executable = tokio::task::spawn_blocking(move || resolve_artifact(&root, &release))
                .await
                .map_err(|e| e.to_string())??;
            Arc::new(
                ProcessModule::spawn(&executable, &selection.release_id)
                    .await
                    .map_err(|e| e.to_string())?,
            )
        };
        self.0
            .registry
            .prepare(implementation)
            .await
            .map_err(|e| e.to_string())
    }

    async fn apply(&self, revision: i64, candidate: PreparedModule) -> Result<(), String> {
        let revision = u64::try_from(revision).map_err(|e| e.to_string())?;
        match self.0.registry.apply_prepared(revision, candidate).await {
            Ok(publication) => {
                if let Some(retired) = publication.retired
                    && let Err(error) = retired.shutdown(Duration::from_secs(30)).await
                {
                    tracing::warn!(event="ReportRendererDrainFailed", generation=retired.generation(), %error);
                }
                Ok(())
            }
            Err(ModuleError::RevisionConflict { actual, .. }) if actual >= revision => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }

    pub async fn refresh(&self, pool: &Pool) -> Result<(), String> {
        let _change = self.0.changes.lock().await;
        let result = match Self::desired(pool).await {
            Ok((selection, revision)) => self.reconcile(&selection, revision).await,
            Err(error) => Err(error),
        };
        *self.0.last_refresh_error.write().unwrap() = result.as_ref().err().cloned();
        result
    }

    async fn reconcile(&self, selection: &RendererSelection, revision: i64) -> Result<(), String> {
        let available = self
            .0
            .registry
            .acquire(MODULE_ID)
            .await
            .is_ok_and(|lease| lease.is_available());
        if available && u64::try_from(revision).ok() == Some(self.0.registry.revision().await) {
            return Ok(());
        }
        let candidate = self.prepare(selection).await?;
        self.apply(revision, candidate).await
    }

    pub async fn desired(pool: &Pool) -> Result<(RendererSelection, i64), String> {
        let client = pool.get().await.map_err(|e| e.to_string())?;
        let row = client
            .query_one(
                "SELECT document,revision,schema_version FROM runtime_configuration WHERE namespace=$1",
                &[&NAMESPACE],
            )
            .await
            .map_err(|e| e.to_string())?;
        decode_selection(
            row.get("document"),
            row.get("revision"),
            row.get("schema_version"),
        )
    }

    pub async fn publish(
        &self,
        pool: &Pool,
        expected: i64,
        selection: RendererSelection,
        reason: &str,
        actor: i32,
    ) -> Result<i64, PublishError> {
        use crate::runtime_config::PersistError;
        let _change = self.0.changes.lock().await;
        let (_, actual) = Self::desired(pool)
            .await
            .map_err(|error| PublishError::Persistence(PersistError::Other(error)))?;
        if expected != actual {
            return Err(PublishError::Persistence(PersistError::Conflict));
        }
        let candidate = self
            .prepare(&selection)
            .await
            .map_err(PublishError::InvalidCandidate)?;
        let revision =
            crate::runtime_config::persist(pool, NAMESPACE, expected, &selection, reason, actor)
                .await
                .map_err(PublishError::Persistence)?;
        self.apply(revision, candidate)
            .await
            .map_err(|error| PublishError::Activation { revision, error })?;
        *self.0.last_refresh_error.write().unwrap() = None;
        Ok(revision)
    }
}

fn decode_selection(
    document: serde_json::Value,
    revision: i64,
    schema_version: i32,
) -> Result<(RendererSelection, i64), String> {
    if schema_version != SCHEMA_VERSION || revision < 1 {
        return Err("渲染器配置 schema_version 或 revision 不受支持".into());
    }
    let selection: RendererSelection =
        serde_json::from_value(document).map_err(|e| e.to_string())?;
    selection.validate()?;
    Ok((selection, revision))
}

fn resolve_artifact(root: &Path, release: &str) -> Result<PathBuf, String> {
    use std::io::Read;
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let directory = root
        .join(release)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    if !directory.starts_with(&root) {
        return Err("制品目录超出允许范围".into());
    }
    let manifest_path = directory
        .join("manifest.json")
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let executable = directory
        .join("nm-report-render-worker")
        .canonicalize()
        .map_err(|e| e.to_string())?;
    if !manifest_path.starts_with(&directory) || !executable.starts_with(&directory) {
        return Err("制品文件超出发布目录".into());
    }
    let mut manifest_bytes = Vec::new();
    std::fs::File::open(manifest_path)
        .map_err(|e| e.to_string())?
        .take(65537)
        .read_to_end(&mut manifest_bytes)
        .map_err(|e| e.to_string())?;
    if manifest_bytes.len() > 65536 {
        return Err("manifest 超过大小限制".into());
    }
    let manifest: ReleaseManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|e| e.to_string())?;
    if manifest.release_id != release
        || manifest.artifact_sha256.len() != 64
        || !manifest
            .artifact_sha256
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("制品身份或摘要无效".into());
    }
    let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256())
        .map_err(|e| e.to_string())?;
    let mut file = std::fs::File::open(&executable).map_err(|e| e.to_string())?;
    let mut chunk = [0u8; 65536];
    loop {
        let count = file.read(&mut chunk).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        hasher.update(&chunk[..count]).map_err(|e| e.to_string())?;
    }
    let actual: String = hasher
        .finish()
        .map_err(|e| e.to_string())?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if actual != manifest.artifact_sha256 {
        return Err("制品 SHA-256 校验失败".into());
    }
    Ok(executable)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn unavailable_selection_is_isolated_and_can_recover_without_restarting_the_host() {
        let service = ReportRenderService::empty(Default::default()).unwrap();
        let missing = RendererSelection {
            release_id: "missing-release".into(),
        };
        assert!(service.reconcile(&missing, 4).await.is_err());
        let status = service.status().await;
        assert!(!status.available);
        assert!(!status.converged(4));
        assert!(status.applied_release_id.is_none());

        service
            .reconcile(&RendererSelection::default(), 5)
            .await
            .unwrap();
        assert!(service.status().await.converged(5));
        // A rejected subsequent candidate must leave the live route intact.
        assert!(service.reconcile(&missing, 6).await.is_err());
        assert!(service.status().await.converged(5));
        assert!(!service.status().await.converged(6));
        service
            .registry()
            .shutdown(Duration::from_secs(1))
            .await
            .unwrap();
        assert!(!service.status().await.converged(5));
    }

    #[test]
    fn configuration_rejects_unknown_schema_and_invalid_revisions() {
        let document = serde_json::json!({"release_id":"builtin"});
        assert!(decode_selection(document.clone(), 1, SCHEMA_VERSION).is_ok());
        assert!(decode_selection(document.clone(), 1, SCHEMA_VERSION + 1).is_err());
        assert!(decode_selection(document, 0, SCHEMA_VERSION).is_err());
    }

    #[test]
    fn matching_revision_is_not_converged_when_the_worker_is_unavailable() {
        let status = RendererStatus {
            applied_revision: 3,
            applied_release_id: Some("release-3".into()),
            available: false,
            last_refresh_error: None,
        };
        assert!(!status.converged(3));
    }

    #[test]
    fn artifact_identity_and_checksum_are_checked_before_execution() {
        let dir =
            Directory(std::env::temp_dir().join(format!("nm-renderer-{}", uuid::Uuid::new_v4())));
        let release = dir.0.join("release-1");
        std::fs::create_dir_all(&release).unwrap();
        let bytes = b"trusted sample artifact";
        let executable = release.join("nm-report-render-worker");
        std::fs::write(&executable, bytes).unwrap();
        let checksum = super::super::assets::digest(bytes).unwrap();
        let manifest = serde_json::json!({"release_id":"release-1","artifact_sha256":checksum});
        std::fs::write(
            release.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert_eq!(
            resolve_artifact(&dir.0, "release-1").unwrap(),
            executable.canonicalize().unwrap()
        );
        std::fs::write(&executable, b"changed artifact").unwrap();
        assert!(
            resolve_artifact(&dir.0, "release-1")
                .unwrap_err()
                .contains("SHA-256")
        );
    }

    #[test]
    fn selections_reject_paths_and_relative_directory_names() {
        for release in [
            "",
            ".",
            "..",
            "../release",
            "release/1",
            "/bin/x",
            "a\\b",
            "a b",
        ] {
            assert!(
                RendererSelection {
                    release_id: release.into()
                }
                .validate()
                .is_err(),
                "{release}"
            );
        }
        for release in ["builtin", "renderer-1.0.0", "renderer_2"] {
            assert!(
                RendererSelection {
                    release_id: release.into()
                }
                .validate()
                .is_ok()
            );
        }
    }
}
