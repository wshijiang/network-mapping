# Elasticsearch 9.5.x 扫描结果存储

版本策略默认 `expected_version = "9.5.x"`，接受任意正式版 `9.5.N`。
兼容旧配置中的 `expected_version = "9.5.3"` 等 `9.5.N` 值，这些值同样表示支持整个
9.5 系列，不再锁定补丁版本。因此，已有 9.5.3 配置可以直接连接 ES 9.5.4，无需修改
配置文件。其他主次版本、预发布版和非法版本均会在启动索引初始化前被拒绝；状态接口
保留原配置值并显示实际服务端版本。

版本范围放行不等同于所有补丁版本均通过真实集群验收。HTTP fixture 验证启动检查和
请求协议；生产采用的补丁版本仍需在隔离集群验证 mapping、Painless、Data Stream、
Bulk、搜索聚合及恢复流程。此次范围调整未新增真实 ES 集群验收记录。

服务端正常运行仅支持 Elasticsearch 扫描结果存储。PostgreSQL 保留用户、权限、标签、
任务、执行状态、扫描器、上传回执、补偿队列和紧凑分析快照，不再读写完整扫描事实。
`postgres`、`dual` 配置已不支持；PG 历史结果仅通过离线 PG → ES 迁移读取。

端点身份升级为 IP + 端口 + 传输协议。既有部署必须按[服务协议部署](SERVICE_PROTOCOLS.md#存储升级与回滚)停服重建投影，不能仅修改索引名启动。

## 配置与新安装

```toml
[elasticsearch]
enabled = true
read_enabled = true
scan_storage = "elasticsearch"
fallback_to_postgres = false
url = "https://127.0.0.1:9200"
observation_index_prefix = "network-mapping-scan-observations-v1"
execution_endpoint_index = "network-mapping-execution-endpoints-v2"
current_endpoint_index = "network-mapping-endpoints-current-v3"
dns_observation_data_stream = "network-mapping-dns-observations"
dns_record_index = "network-mapping-dns-records-v1"
dns_observation_retention_days = 180
scan_number_of_replicas = 1
write_wait_for_active_shards = "all"
expected_version = "9.5.x"
# api_key 和 CA 路径由部署环境提供。
```

ES 是必需依赖；禁用 ES、禁用读取或启用 PG 回退会被配置检查拒绝。旧 `index` 配置已无用途，
应删除。开发默认允许零副本并等待主分片；生产应配置至少一份副本和相应故障域，并实测
`write_wait_for_active_shards` 对故障期间可写性的影响。持久化保持 `translog.durability=request`。

新安装的 `init.sql` 只创建 PG 业务结构，不创建 `ips`、`ports`、`scan_observation`、
`asset_endpoint_current` 或旧搜索视图。空库直接初始化 ES，并记录目标索引；无需执行空迁移。
已经初始化的运行实例重启时校验目标与回执引用的索引。索引丢失或目标改变会拒绝启动，
不能静默按空库恢复。正常 ES pending 上传和投影积压允许后台/扫描器恢复，不再阻断重启。

## 历史 PG → ES 迁移

1. 备份 PG，并准备 ES 快照仓库。停止旧服务和结果上传，迁移期间不得运行其他写入实例。新版进程使用 PG 共享/独占咨询锁互斥正常服务与迁移；旧版不持有该锁，仍需人工确认已停服。
2. 将配置改为上面的 ES 配置；不要尝试用新版服务运行 `postgres` 或 `dual`。
3. 在停止常规服务的维护窗口运行：

   ```sh
   cargo run --release -- --config /etc/network-mapping/config.toml \
     --migrate-scan-data-to-elasticsearch
   ```

4. 迁移命令独立执行内嵌 `prepare_pg_scan_migration.sql`，补齐旧结构、将遗留 `scaninfo`
   幂等转换为迁移批次，并提取旧 evidence 搜索内容。正常启动不会执行这些步骤。
5. 按 execution 有界并行、执行内按批次顺序迁移。逐批核对 PG 观察数与回执，写 ES 并记录
   校验和、真实索引引用及执行计数；失败保留断点，修复后可重跑。新迁移回执标记为
   `elasticsearch`，既有 `dual` 标记仅作为历史迁移回执识别，不恢复双写。
6. 存在 ES `pending` 回执时，先让原 ES 服务与扫描器完成重试；迁移拒绝将其当作 PG 空批次。
7. 迁移完成后核对批次内容、执行计数、普通用户/管理员权限、资产、任务详情、导出和分析；
   完成配对备份恢复演练后启动新版服务。历史 PG 事实表暂时保留，后续归档/删除独立安排。

若要在导入前补充旧 PG IP 情报，使用
`--refresh-ip-intel --migrate-scan-data-to-elasticsearch`。该选项仅用于迁移前准备，不能单独
维护 PG 结果，也不修改已经迁入 ES 的历史情报。旧 `--rebuild-elasticsearch` 命令已移除，
避免重建已退役搜索副本或误以为它能恢复原始扫描结果。

迁移是单向能力；没有 ES → PG 回填工具。上线后优先回滚到支持 ES 的应用版本；不能只修改
配置回 PG。恢复到迁移前备份会丢失之后的数据，必须明确共同恢复边界。

## 索引与提交协议

- `network-mapping-scan-observations-v1-YYYY.MM`：不可变原始观察，月份由扫描器 `observed_at` 确定。
- `network-mapping-execution-endpoints-v2`：每次执行的端点投影。
- `network-mapping-endpoints-current-v3`：`global/user` 权限范围内的当前端点投影。
- `network-mapping-dns-observations`：DNS 查询证据 Data Stream。
- `network-mapping-dns-records-v1`：当前 DNS RR 投影。

旧 `network-mapping-assets-v1` 不再创建、同步或查询。原始 observation 的确定性 `_id` 和内容
校验和保持兼容；Bulk 响应逐项校验，409 通过 `_mget` 核对原始内容和批次校验和。
原始 evidence 保留在 `_source`，不任意展开 mapping。IP/CIDR 继续分别使用 `ip` / `ip_range`。

上传先提交 PG pending 回执，再释放事务和连接后写 ES，成功后重新检查执行归属并确认回执。
ES 成功而 PG 确认失败时，相同身份重试收敛；完成后的重复批次也要核对内容。final 要求此前
批次已完成、从 0 连续且唯一 final；空 final 同样刷新原始观察和执行投影后再读取计数，避免
最后一批没有触及早先月份/分片造成漏计。执行成功、任务聚合和 outbox 在同一 PG 事务提交。

当前端点发布在该事务之后，失败由 outbox 补偿；执行成功不代表所有投影/分析同时可见。
当前投影只由后台分段发布，上传及重复 final 不等待整批资产发布；任务详情提供独立的
`projection_status`。领取令牌、续租和分页检查点见[扫描写入与后台资产发布](WRITE_SPEED.md)。
状态接口统计扫描投影和标签两个队列，不再将旧副本事件计为运行积压。

DNS observation 始终通过 Data Stream 名执行 `create`，不直接写 backing index。同一 pending
批次先获取 PG 事务级 advisory lock，再刷新并按确定性文档 ID 对账整个 Data Stream，只补写
缺失事实；网络结果未知或 Bulk 部分成功后也先重新对账，不盲目重发整批。因此 ES 写成功而
PG 尚未确认、并发重试或 Data Stream rollover 都不会产生重复事实。完成回执保存搜索返回的
实际 backing index 和 DNS RR 索引；升级前已经保存 `.ds-*` 的 pending 回执会在成功时自动
覆写。若发现同一文档 ID 已跨 backing index 重复，拒绝继续并要求先对账。

## 查询、备份与验收

搜索、资产、历史、任务结果/漏洞、导出统一读取 ES；用户、任务元数据和标签仍读取 PG。
分析快照继续使用 PG 紧凑统计，后台从 ES 获取事实，参见[分析快照](ANALYTICS_SNAPSHOTS.md)。
索引不可用返回 503，不回退旧 PG 事实，也不将失败分片作为完整统计。

ES 快照和 PG 备份必须配对恢复，并对回执、事实与投影对账。定期快照、磁盘监控和恢复演练
属于部署运维要求。索引过期前需定义可恢复归档，
否则完整历史查询及全量重建不再有保证。

自动验证：

```sh
cargo fmt --check
cargo clippy --all-targets
cargo test
# 下面的连接只能指向可创建/删除测试 schema 的隔离 PG。
STORAGE_TEST_DATABASE_URL='host=127.0.0.1 port=5432 dbname=storage_test user=test' \
  cargo test elasticsearch::storage_tests -- --ignored
ANALYTICS_TEST_DATABASE_URL='host=127.0.0.1 port=5432 dbname=storage_test user=test' \
  cargo test postgres_backfill_publication_retry_and_batch_writes -- --ignored
```

存储集成测试使用真实 PG 隔离 schema 与本地 ES HTTP fixture，验证协议和恢复边界；它不替代
实际 ES 9.5.x 的 mapping、Painless、rollover、副本故障、性能和 Snapshot/Restore 验收。

## 慢查询诊断

服务端会为 ES 请求记录端到端耗时，并注入有限集合的 `X-Opaque-Id` 和唯一 W3C
`traceparent`。达到 `[monitor]` 阈值、超时、HTTP 失败或分片失败时，事件进入现有
`health_alert` 与邮件链路。应用不会记录 DSL、Bulk 正文或认证信息。

Elasticsearch 9.4+ 推荐同时开启统一 Query Logging。该设置应由运维账号执行，不要给业务
API Key 增加集群设置权限：

```json
PUT /_cluster/settings
{
  "persistent": {
    "elasticsearch.querylog.enabled": true,
    "elasticsearch.querylog.threshold": "1s",
    "elasticsearch.querylog.include.user": true,
    "elasticsearch.querylog.include.system_indices": false
  }
}
```

自托管集群还需启用 Filebeat Elasticsearch module 的 `querylog` fileset，或 Elastic Agent
Elasticsearch integration，将各协调节点的 `*_querylog.json` 收集到内置
`logs-elasticsearch.querylog-default` data stream。Query Logging 可能保存完整查询正文，必须
限制该数据流的读取权限并设置短保留期；高流量时提高 threshold，避免异步日志队列丢弃。

Query Logging 记录协调节点端到端查询。需要定位具体慢分片时，再对业务索引临时设置 Search
Slow Log 的 query/fetch 阈值。写入不受 Query Logging 覆盖，Bulk/索引问题使用 Indexing Slow
Log，并将 `index.indexing.slowlog.source` 设为 `0`，避免扫描证据进入日志。`profile: true`
只用于脱敏查询的受控复现，不得在生产请求中默认开启。
