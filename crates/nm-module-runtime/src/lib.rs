//! Versioned capability routing with local and managed-process implementations.
//! The application persists its desired state and injects this registry into
//! production services; the process adapter owns private IPC and child lifetime.
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{Notify, RwLock, Semaphore, oneshot};

pub mod process;

pub type ModuleFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ModuleError>> + Send + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleContract {
    pub module_id: String,
    pub release_id: String,
    pub rpc_version: u32,
    pub input_schema: String,
    pub output_schema: String,
    pub methods: BTreeSet<String>,
}

/// Trusted implementations only. The registry validates the declared contract;
/// artifact authentication and remote response validation belong to IPC adapters.
pub trait Module: Send + Sync {
    fn is_available(&self) -> bool {
        true
    }
    fn contract(&self) -> ModuleContract;
    fn self_test(&self) -> ModuleFuture<'_, ()>;
    fn invoke<'a>(&'a self, method: &'a str, payload: Value) -> ModuleFuture<'a, Value>;
    fn shutdown(&self) -> ModuleFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Clone, Debug)]
pub struct ModuleSlot {
    pub rpc_version: u32,
    pub input_schema: String,
    pub output_schema: String,
    pub methods: BTreeSet<String>,
    pub max_inflight: usize,
    pub max_payload_bytes: usize,
    pub request_timeout: Duration,
    pub prepare_timeout: Duration,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ModuleError {
    InvalidSlot,
    IncompatibleContract,
    RevisionConflict {
        expected: u64,
        actual: u64,
    },
    RevisionExhausted,
    NotReady,
    UnsupportedMethod,
    PayloadTooLarge,
    Busy,
    DeadlineExceeded,
    DrainTimeout,
    /// Infrastructure failure; retry after the capability becomes available.
    Unavailable(String),
    /// The implementation rejected an input or failed its business validation.
    Execution(String),
}

impl ModuleError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::NotReady | Self::Busy | Self::DeadlineExceeded | Self::Unavailable(_)
        )
    }
}

impl std::fmt::Display for ModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RevisionConflict { expected, actual } => {
                write!(
                    f,
                    "module revision conflict: expected {expected}, actual {actual}"
                )
            }
            Self::Execution(message) | Self::Unavailable(message) => f.write_str(message),
            other => write!(f, "{other:?}"),
        }
    }
}
impl std::error::Error for ModuleError {}

struct Generation {
    number: u64,
    contract: ModuleContract,
    implementation: Arc<dyn Module>,
    slot: ModuleSlot,
    capacity: Arc<Semaphore>,
    held_leases: AtomicUsize,
    released: Notify,
}

#[derive(Default)]
struct Routes {
    revision: u64,
    modules: BTreeMap<String, Arc<Generation>>,
}

pub struct ModuleRegistry {
    slots: BTreeMap<String, ModuleSlot>,
    routes: RwLock<Routes>,
}

pub struct PreparedModule {
    contract: ModuleContract,
    implementation: Arc<dyn Module>,
    slot: ModuleSlot,
}

pub struct Publication {
    pub revision: u64,
    pub generation: u64,
    pub retired: Option<RetiredGeneration>,
}

/// Holds the retired implementation while the supervisor checks drain progress.
pub struct RetiredGeneration(Arc<Generation>);

impl RetiredGeneration {
    pub async fn shutdown(&self, deadline: Duration) -> Result<(), ModuleError> {
        self.wait_drained(deadline).await?;
        tokio::time::timeout(deadline, self.0.implementation.shutdown())
            .await
            .map_err(|_| ModuleError::DrainTimeout)?
    }
    pub fn generation(&self) -> u64 {
        self.0.number
    }

    pub fn held_leases(&self) -> usize {
        self.0.held_leases.load(Ordering::Acquire)
    }

    pub async fn wait_drained(&self, deadline: Duration) -> Result<(), ModuleError> {
        tokio::time::timeout(deadline, async {
            loop {
                let notified = self.0.released.notified();
                tokio::pin!(notified);
                // Register before checking the count to avoid a missed last release.
                notified.as_mut().enable();
                if self.held_leases() == 0 {
                    return;
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| ModuleError::DrainTimeout)
    }
}

/// A request pins this handle once and retains it for its entire operation.
pub struct ModuleLease(Arc<Generation>);

impl Drop for ModuleLease {
    fn drop(&mut self) {
        if self.0.held_leases.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.released.notify_waiters();
        }
    }
}

impl ModuleLease {
    pub fn is_available(&self) -> bool {
        self.0.implementation.is_available()
    }
    fn new(generation: Arc<Generation>) -> Self {
        generation.held_leases.fetch_add(1, Ordering::AcqRel);
        Self(generation)
    }

    pub fn generation(&self) -> u64 {
        self.0.number
    }

    pub fn release_id(&self) -> &str {
        &self.0.contract.release_id
    }

    pub async fn invoke(&self, method: &str, payload: Value) -> Result<Value, ModuleError> {
        if !self.0.contract.methods.contains(method) {
            return Err(ModuleError::UnsupportedMethod);
        }
        if serde_json::to_vec(&payload)
            .map_err(|e| ModuleError::Execution(e.to_string()))?
            .len()
            > self.0.slot.max_payload_bytes
        {
            return Err(ModuleError::PayloadTooLarge);
        }
        let permit = self
            .0
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| ModuleError::Busy)?;
        let execution = Self::new(self.0.clone());
        let method = method.to_owned();
        let (sender, result) = oneshot::channel();
        // Track accepted work independently of caller cancellation. The permit
        // and execution lease stay alive until the backend actually finishes.
        // An unresponsive backend occupies bounded capacity and blocks retirement;
        // the supervisor must explicitly restart/stop such a process adapter.
        tokio::spawn(async move {
            let _permit = permit;
            let response = execution.0.implementation.invoke(&method, payload).await;
            let response = response.and_then(|value| {
                let size = serde_json::to_vec(&value)
                    .map_err(|e| ModuleError::Execution(e.to_string()))?
                    .len();
                if size > execution.0.slot.max_payload_bytes {
                    Err(ModuleError::PayloadTooLarge)
                } else {
                    Ok(value)
                }
            });
            let _ = sender.send(response);
        });
        tokio::time::timeout(self.0.slot.request_timeout, result)
            .await
            .map_err(|_| ModuleError::DeadlineExceeded)?
            .map_err(|_| ModuleError::Unavailable("module execution task stopped".into()))?
    }
}

impl ModuleRegistry {
    pub async fn shutdown(&self, deadline: Duration) -> Result<(), ModuleError> {
        let retired: Vec<_> = {
            let mut routes = self.routes.write().await;
            std::mem::take(&mut routes.modules)
                .into_values()
                .map(RetiredGeneration)
                .collect()
        };
        for module in retired {
            module.shutdown(deadline).await?;
        }
        Ok(())
    }
    pub fn new(slots: BTreeMap<String, ModuleSlot>) -> Result<Self, ModuleError> {
        if slots.iter().any(|(id, slot)| {
            id.is_empty()
                || slot.rpc_version == 0
                || slot.input_schema.is_empty()
                || slot.output_schema.is_empty()
                || slot.methods.is_empty()
                || slot.methods.iter().any(String::is_empty)
                || slot.max_inflight == 0
                || slot.max_inflight > Semaphore::MAX_PERMITS
                || slot.max_payload_bytes == 0
                || slot.request_timeout.is_zero()
                || slot.prepare_timeout.is_zero()
        }) {
            return Err(ModuleError::InvalidSlot);
        }
        Ok(Self {
            slots,
            routes: RwLock::new(Routes::default()),
        })
    }

    pub async fn revision(&self) -> u64 {
        self.routes.read().await.revision
    }

    pub async fn prepare(
        &self,
        implementation: Arc<dyn Module>,
    ) -> Result<PreparedModule, ModuleError> {
        let contract = implementation.contract();
        let slot = self
            .slots
            .get(&contract.module_id)
            .ok_or(ModuleError::IncompatibleContract)?;
        if contract.release_id.is_empty()
            || contract.rpc_version != slot.rpc_version
            || contract.input_schema != slot.input_schema
            || contract.output_schema != slot.output_schema
            || contract.methods != slot.methods
        {
            return Err(ModuleError::IncompatibleContract);
        }
        tokio::time::timeout(slot.prepare_timeout, implementation.self_test())
            .await
            .map_err(|_| ModuleError::DeadlineExceeded)??;
        Ok(PreparedModule {
            contract,
            implementation,
            slot: slot.clone(),
        })
    }

    fn install(routes: &mut Routes, revision: u64, prepared: PreparedModule) -> Publication {
        let PreparedModule {
            contract,
            implementation,
            slot,
        } = prepared;
        let id = contract.module_id.clone();
        let capacity = Arc::new(Semaphore::new(slot.max_inflight));
        let generation = Arc::new(Generation {
            number: revision,
            contract,
            implementation,
            slot,
            capacity,
            held_leases: AtomicUsize::new(0),
            released: Notify::new(),
        });
        let retired = routes.modules.insert(id, generation).map(RetiredGeneration);
        routes.revision = revision;
        Publication {
            revision,
            generation: revision,
            retired,
        }
    }

    pub async fn publish(
        &self,
        expected_revision: u64,
        implementation: Arc<dyn Module>,
    ) -> Result<Publication, ModuleError> {
        let actual = self.revision().await;
        if actual != expected_revision {
            return Err(ModuleError::RevisionConflict {
                expected: expected_revision,
                actual,
            });
        }
        let prepared = self.prepare(implementation).await?;
        let mut routes = self.routes.write().await;
        if routes.revision != expected_revision {
            return Err(ModuleError::RevisionConflict {
                expected: expected_revision,
                actual: routes.revision,
            });
        }
        let revision = routes
            .revision
            .checked_add(1)
            .ok_or(ModuleError::RevisionExhausted)?;
        Ok(Self::install(&mut routes, revision, prepared))
    }

    /// Apply an authoritative newer revision; this supports skipped DB revisions
    /// and restoration after restart. Use one registry per persisted configuration domain.
    pub async fn apply_prepared(
        &self,
        revision: u64,
        prepared: PreparedModule,
    ) -> Result<Publication, ModuleError> {
        let mut routes = self.routes.write().await;
        let replaces_failed = revision == routes.revision
            && routes
                .modules
                .get(&prepared.contract.module_id)
                .is_some_and(|current| !current.implementation.is_available());
        if revision < routes.revision || (revision == routes.revision && !replaces_failed) {
            return Err(ModuleError::RevisionConflict {
                expected: revision,
                actual: routes.revision,
            });
        }
        Ok(Self::install(&mut routes, revision, prepared))
    }

    pub async fn acquire(&self, module_id: &str) -> Result<ModuleLease, ModuleError> {
        let routes = self.routes.read().await;
        let generation = routes.modules.get(module_id).ok_or(ModuleError::NotReady)?;
        Ok(ModuleLease::new(generation.clone()))
    }
}

#[cfg(test)]
mod tests;
