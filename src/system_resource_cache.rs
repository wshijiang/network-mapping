//! 进程内系统资源明细缓存。
//!
//! 历史趋势由 PostgreSQL 的 `system_status` 聚合提供；这里只保留仪表盘近期请求所需的
//! 完整快照，并使用固定容量避免服务长时间运行后无界增长。

use std::sync::{Arc, RwLock};

use crate::system_resources::SystemResource;

#[derive(Default)]
struct CacheInner {
    latest: Option<SystemResource>,
}

#[derive(Clone, Default)]
pub struct SystemResourceCache {
    inner: Arc<RwLock<CacheInner>>,
}

impl SystemResourceCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// 替换为最新的完整快照。
    pub fn record(&self, resource: SystemResource) {
        if resource.create_at.is_none() {
            return;
        }
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(|error| error.into_inner());
        inner.latest = Some(resource);
    }

    pub fn latest(&self) -> Option<SystemResource> {
        let inner = self.inner.read().unwrap_or_else(|error| error.into_inner());
        inner.latest.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        system_resources::DbResource, system_resources::SystemCPU, system_resources::SystemDisk,
        system_resources::SystemNetwork, system_resources::SystemRAM,
    };
    use std::collections::{BTreeMap, HashMap};

    fn resource(timestamp: i64, cpu: f32, ram: f32, disk_used: u64) -> SystemResource {
        SystemResource {
            server_run_time: 1,
            cpu: SystemCPU {
                cpu_usage: cpu,
                cpu: HashMap::new(),
            },
            ram: SystemRAM {
                total_ram: 100,
                used_ram: ram as u64,
                ram_usage: ram,
                total_swap: 0,
                use_swap: 0,
                swap_usage: 0.0,
            },
            disk: SystemDisk {
                disk_total_space: 100,
                disk_total_usage: disk_used,
                disk: HashMap::new(),
            },
            db_postgresql: DbResource::default(),
            network: SystemNetwork {
                net: BTreeMap::new(),
            },
            create_at: Some(timestamp),
        }
    }

    #[test]
    fn newest_snapshot_is_read_from_memory() {
        let cache = SystemResourceCache::new();
        cache.record(resource(100, 10.0, 20.0, 30));
        cache.record(resource(105, 30.0, 40.0, 50));

        assert_eq!(cache.latest().unwrap().create_at, Some(105));
    }
}
