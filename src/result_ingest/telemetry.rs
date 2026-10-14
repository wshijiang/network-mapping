//! Upload stages inherit the request's identity span; never log result payloads.
use std::time::Instant;

tokio::task_local! {
    pub(crate) static UPLOAD_REQUEST_ID: uuid::Uuid;
}

pub(crate) struct WriteStage {
    stage: &'static str,
    started: Instant,
    success: bool,
}

impl WriteStage {
    pub(crate) fn new(stage: &'static str) -> Self {
        Self {
            stage,
            started: Instant::now(),
            success: false,
        }
    }

    pub(crate) fn finish(mut self, success: bool) {
        self.success = success;
    }
}

impl Drop for WriteStage {
    fn drop(&mut self) {
        tracing::info!(
            event = "ScanWriteStageCompleted",
            stage = self.stage,
            duration_us = self.started.elapsed().as_micros() as u64,
            success = self.success,
        );
    }
}
