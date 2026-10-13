//! Managed process adapter over private, length-prefixed JSON pipes.
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

use crate::{Module, ModuleContract, ModuleError, ModuleFuture};

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
const RPC_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RpcRequest {
    pub request_id: u64,
    pub rpc_version: u32,
    pub method: String,
    pub payload: Value,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RpcResponse {
    pub request_id: u64,
    pub rpc_version: u32,
    pub release_id: String,
    pub output: Value,
    pub error: Option<String>,
}

pub async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
) -> Result<T, ModuleError> {
    let size = reader.read_u32().await.map_err(wire_error)? as usize;
    if size == 0 || size > MAX_FRAME_BYTES {
        return Err(ModuleError::PayloadTooLarge);
    }
    let mut bytes = vec![0; size];
    reader.read_exact(&mut bytes).await.map_err(wire_error)?;
    serde_json::from_slice(&bytes).map_err(wire_error)
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<(), ModuleError> {
    let bytes = encode_frame(value)?;
    write_encoded_frame(writer, &bytes).await
}

fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, ModuleError> {
    let bytes = serde_json::to_vec(value).map_err(wire_error)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ModuleError::PayloadTooLarge);
    }
    Ok(bytes)
}

async fn write_encoded_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
) -> Result<(), ModuleError> {
    writer
        .write_u32(bytes.len() as u32)
        .await
        .map_err(wire_error)?;
    writer.write_all(bytes).await.map_err(wire_error)?;
    writer.flush().await.map_err(wire_error)
}

fn wire_error(error: impl std::fmt::Display) -> ModuleError {
    ModuleError::Execution(format!("module IPC error: {error}"))
}

pub struct ProcessModule {
    contract: ModuleContract,
    child: Mutex<Child>,
    io: Mutex<(ChildStdin, ChildStdout)>,
    sequence: std::sync::Mutex<u64>,
    stopped: AtomicBool,
}

impl ProcessModule {
    /// Callers resolve immutable artifacts and verify their checksum before spawn.
    pub async fn spawn(executable: &Path, release_id: &str) -> Result<Self, ModuleError> {
        let mut child = Command::new(executable)
            .env_clear()
            .env("NM_MODULE_RELEASE_ID", release_id)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(wire_error)?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| wire_error("missing stdin"))?;
        let mut output = child
            .stdout
            .take()
            .ok_or_else(|| wire_error("missing stdout"))?;
        let ready =
            tokio::time::timeout(RPC_TIMEOUT, read_frame::<_, ModuleContract>(&mut output)).await;
        let contract = match ready {
            Ok(Ok(contract)) if contract.release_id == release_id && contract.rpc_version == 1 => {
                contract
            }
            other => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(match other {
                    Err(_) => ModuleError::DeadlineExceeded,
                    Ok(Err(error)) => error,
                    _ => ModuleError::IncompatibleContract,
                });
            }
        };
        Ok(Self {
            contract,
            child: Mutex::new(child),
            io: Mutex::new((input, output)),
            sequence: std::sync::Mutex::new(1),
            stopped: AtomicBool::new(false),
        })
    }

    async fn stop(&self) -> Result<(), ModuleError> {
        self.stopped.store(true, Ordering::Release);
        let mut child = self.child.lock().await;
        if child.try_wait().map_err(wire_error)?.is_none() {
            child.kill().await.map_err(wire_error)?;
        }
        child.wait().await.map_err(wire_error)?;
        Ok(())
    }

    async fn rpc(&self, method: &str, payload: Value) -> Result<Value, ModuleError> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(wire_error("worker stopped"));
        }
        let request_id = {
            let mut counter = self
                .sequence
                .lock()
                .map_err(|_| wire_error("request counter poisoned"))?;
            let value = *counter;
            *counter = counter
                .checked_add(1)
                .ok_or(ModuleError::RevisionExhausted)?;
            value
        };
        // Reject local encoding/size errors before touching the pipe. Payload
        // limits do not include the RPC envelope; rejection must not stop an
        // otherwise healthy worker or leave a partial frame on its stdin.
        let request = encode_frame(&RpcRequest {
            request_id,
            rpc_version: 1,
            method: method.into(),
            payload,
        })?;
        let exchange = async {
            let mut io = self.io.lock().await;
            if self.stopped.load(Ordering::Acquire) {
                return Err(wire_error("worker stopped"));
            }
            write_encoded_frame(&mut io.0, &request).await?;
            let response: RpcResponse = read_frame(&mut io.1).await?;
            if response.request_id != request_id
                || response.rpc_version != 1
                || response.release_id != self.contract.release_id
            {
                return Err(ModuleError::IncompatibleContract);
            }
            match (response.output, response.error) {
                (output, None) => Ok(Ok(output)),
                (Value::Null, Some(message)) => Ok(Err(ModuleError::Execution(message))),
                _ => Err(ModuleError::IncompatibleContract),
            }
        };
        match tokio::time::timeout(RPC_TIMEOUT, exchange).await {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                let _ = self.stop().await;
                Err(error)
            }
            Err(_) => {
                let _ = self.stop().await;
                Err(ModuleError::DeadlineExceeded)
            }
        }
    }
}

impl Module for ProcessModule {
    fn is_available(&self) -> bool {
        if self.stopped.load(Ordering::Acquire) {
            return false;
        }
        if let Ok(mut child) = self.child.try_lock()
            && !matches!(child.try_wait(), Ok(None))
        {
            self.stopped.store(true, Ordering::Release);
            return false;
        }
        true
    }
    fn contract(&self) -> ModuleContract {
        self.contract.clone()
    }
    fn self_test(&self) -> ModuleFuture<'_, ()> {
        Box::pin(async { self.rpc("__self_test", Value::Null).await.map(|_| ()) })
    }
    fn invoke<'a>(&'a self, method: &'a str, payload: Value) -> ModuleFuture<'a, Value> {
        Box::pin(self.rpc(method, payload))
    }
    fn shutdown(&self) -> ModuleFuture<'_, ()> {
        Box::pin(self.stop())
    }
}
