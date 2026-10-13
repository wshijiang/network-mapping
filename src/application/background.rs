//! Explicit ownership and shutdown of application background services.
use std::{future::Future, time::Duration};
use tokio::{sync::watch, task::JoinSet};

pub struct BackgroundServices {
    stopping: watch::Sender<bool>,
    tasks: JoinSet<&'static str>,
}

impl Default for BackgroundServices {
    fn default() -> Self {
        let (stopping, _) = watch::channel(false);
        Self {
            stopping,
            tasks: JoinSet::new(),
        }
    }
}

impl BackgroundServices {
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.stopping.subscribe()
    }

    pub fn spawn(&mut self, name: &'static str, task: impl Future<Output = ()> + Send + 'static) {
        let mut stopping = self.subscribe();
        self.tasks.spawn(async move {
            tokio::select! {
                _=task => tracing::warn!(event="BackgroundServiceExited",component=name),
                _=stopping.changed() => {},
            }
            name
        });
    }

    /// Cooperative jobs receive subscribe() and finish current work on shutdown.
    pub fn spawn_draining(
        &mut self,
        name: &'static str,
        task: impl Future<Output = ()> + Send + 'static,
    ) {
        self.tasks.spawn(async move {
            task.await;
            name
        });
    }

    pub async fn shutdown(&mut self, grace: Duration) {
        self.stopping.send_replace(true);
        if tokio::time::timeout(grace, async {
            while let Some(result) = self.tasks.join_next().await {
                if let Err(error) = result {
                    tracing::warn!(event="BackgroundServiceJoinFailed",%error);
                }
            }
        })
        .await
        .is_err()
        {
            tracing::warn!(
                event = "BackgroundShutdownTimeout",
                "后台服务排空超时，取消剩余任务；持久化作业由租约恢复"
            );
            self.tasks.abort_all();
            while self.tasks.join_next().await.is_some() {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    #[tokio::test]
    async fn shutdown_signals_and_joins_cooperative_work() {
        let mut services = BackgroundServices::default();
        let mut stopping = services.subscribe();
        let finished = Arc::new(AtomicBool::new(false));
        let result = finished.clone();
        services.spawn_draining("test", async move {
            stopping.changed().await.unwrap();
            result.store(true, Ordering::Release);
        });
        services.shutdown(Duration::from_secs(1)).await;
        assert!(finished.load(Ordering::Acquire));
    }
}
