# 扫描分析快照

扫描分析页面原先在每次请求时聚合全部 observation。该行为在 Elasticsearch 成为扫描事实源后，
会因高基数 composite aggregation 而明显变慢。现在可以将统计改为后台快照：扫描事实仅保留在
Elasticsearch，分析接口只读取 PostgreSQL 中的紧凑统计事实。

## 升级步骤

升级后的默认配置是 `mode = "realtime"`，接口行为不变。请按以下顺序切换：

1. 部署服务，让数据库初始化新增 `analytics_*` 表。
2. 在管理员运行时设置中将模式改为 `shadow`。后台 worker 会自动补偿升级前所有已成功的 IP 扫描执行；
   新版本服务会在 execution 成功的同一事务中写入 outbox。
3. 正常升级无需手动全量重建。仅在需要重新计算已完成的统计事实时，在维护窗口运行：

   ```sh
   cargo run --release -- --config /etc/network-mapping/config.toml \
     --rebuild-analytics-snapshots
   ```

   命令只替换 `analytics_*` 紧凑统计事实，不会删除或修改扫描 observation、任务或资产数据。
   已有可读水位会保留；失败会报告错误，不会把尚未完成的队列报告为重建成功。
4. 使用原有 `/api/analysis/distribution` 和 `/api/analysis/discovery-heatmap` 对典型用户、扫描器、
   任务来源和时间范围做结果核验。
5. 确认首次回填水位已生成后，在运行时设置中改为 `snapshot`。首次快照尚未完整时接口返回 503，
   不会静默回退到可能很慢的实时 ES 聚合。

## 配置

```toml
[analytics_snapshot]
# realtime: 保持旧实时查询；shadow: 后台构建、接口仍实时；snapshot: 接口只读快照。
mode = "realtime"
# 历史补偿检查及下一轮固定回填范围的建立周期；不是队列消费休眠时间。
interval_minutes = 30
# 单执行最长处理时间（分钟，30–1440），包括读取、暂存和发布。
execution_timeout_minutes = 360
# 单执行临时去重表及索引的大小上限（MiB，256–65536）。
max_staging_mib = 4096
```

TOML 仅首次初始化 `runtime_configuration`。数据库已有 `analytics_snapshot` 配置后，修改 TOML
并重启不会覆盖运行时设置。以管理员接口 `GET /api/config/runtime/analytics_snapshot` 返回的
`data.document` 和 `data.revision` 为准；调整新增限制时先读取完整 document，再按[运行时配置 API](RUNTIME_CONFIGURATION.md#api-与权限)发布完整文档。现有控制台没有这两个字段的输入项。多实例配置同步限制见该文档。重建命令在运行时配置加载前执行，使用启动 TOML 的限制。

worker 每批最多处理 100 个 execution，有积压时只让出 1 秒后继续，空闲时每 5 秒检查新任务及重试。
历史全量补偿不再发生在每次领取任务时。普通失败延迟重试，间隔从 30 秒指数增长至最多 30 分钟。
全局同时只处理一个执行；处理期间按页更新心跳，60 分钟没有心跳的领取可重新处理。

每个执行通过 Elasticsearch PIT 和 `search_after` 固定视图分页读取，在 PostgreSQL 会话临时表
分批去重，最后一个事务替换该执行的统计事实并完成队列。内存随分页批次增长；临时表、索引、
最终写入和 WAL 需要数据库磁盘空间。每页结束后检查临时表及索引大小，超出 `max_staging_mib`
会停止该项并设置 `available_at = infinity`；单页写入可能使实际空间短暂超过限制。查询、临时表写入
及最终发布分别受数据库语句超时约束（5 分钟），ES 每页请求最多等待 5 分钟，单执行总时限由
`execution_timeout_minutes` 控制。临时空间限制不是磁盘预留，也不包括 WAL、最终统计表或数据库
排序等开销；部署前应根据压测预留足够空间并监控磁盘。超时、资源不足和数据缺失都不会发布半成品。

首次启动固定当前待处理执行集合到 `analytics_snapshot_build_execution`。之后新增执行不会扩张
这一集合。每个执行的统计事实、队列完成标记和集合移除在同一事务中提交；集合清空时发布水位。
下一轮集合的建立及处理不删除已有水位。空数据库也会生成有效空快照。历史失败任务仍会阻止其所属
回填范围完成，系统不会通过跳过失败来伪造完整性。

领取使用 `FOR UPDATE SKIP LOCKED`，写入前校验领取时间并加锁，防止重试或重新上传后旧计算覆盖
新任务。统计事实从临时表在单个事务中写入；写入失败整笔事务回滚，保留旧事实。ES 超时、失败分片、PIT
失效、分页游标异常或读取观察数少于执行记录的计数时，不发布该执行的统计结果。临时表随数据库
会话清理，中断后的任务从头处理；读取超时的 PIT 由 Elasticsearch 按 keep-alive 到期释放。

## 进度与排错

管理员接口 `GET /api/config/runtime/analytics_snapshot` 除配置外返回 `progress`：

- `data_as_of`：最近完成的回填范围水位，首次尚未完成时为空。
- `build_started_at` / `build_completed_at`：当前固定范围的建立和完成时间。
- `remaining`：当前范围剩余执行数，后续新任务不计入。
- `pending` / `running` / `completed` / `retrying`：整个统计队列状态。
- `failed_execution_id` / `last_error`：最近一个未完成失败任务及原因。

首次快照不可读时，分析接口对管理员返回相同进度，页面显示剩余数量及最近失败原因。
普通用户只收到通用回填提示，不暴露其他用户的任务或错误。
水位 SQL 出错与回填未完成使用不同错误码，不再把数据库错误伪装成未回填。

升级时部署更新后的 `source/database/init.sql`，服务初始化会幂等创建回填范围表并迁移心跳字段。
**先升级全部服务实例，再恢复大执行**：旧 worker 不识别新心跳，混跑时可能把处理超过 60 分钟的
任务视为失效。无需清空统计表或重新运行全量重建；开启 `shadow` / `snapshot` 后普通待重试任务
自动接续。

旧版因 `statistics_resource_limit: 执行去重集合超过 200000` 被设置为 `infinity` 的任务不会自动
恢复。确认全部实例已升级、源 observation 仍保留且 PostgreSQL 有足够磁盘后，先记录任务原状态，
针对核实过的执行逐个重新排队，例如：

```sql
UPDATE analytics_outbox
   SET available_at = NOW(), updated_at = NOW()
 WHERE execution_id = 51983 -- 替换成已核实的执行数据库 ID
   AND status = 'pending'
   AND available_at = 'infinity'::timestamptz
   AND last_error LIKE 'statistics_resource_limit: 执行去重集合超过 200000%'
RETURNING execution_id, status, available_at;
```

没有返回行时先检查当前状态，不要覆盖正在运行的领取。查看日志 `AnalyticsSnapshotProgress`、
`AnalyticsSnapshotExecutionFailed` 和队列 `last_error`；资源不足时先处理容量，不能仅反复排队。
待报告的全部本期执行都完成后，在报告详情点击重试；报告输入计数已变化时核实后创建修订版。
不应为了单个失败执行运行 `--rebuild-analytics-snapshots`，该命令会重新排队全部成功的 IP 执行。

## 统计口径

- 服务/端口分布按执行内的代表性端点计数；同一 endpoint 的首次 observation 决定其 30 分钟窗口。
- 服务名以 `LOWER(BTRIM(service))` 归一化；空服务名不进入服务分布。
- 发现 IP 按执行和上海自然日记录，并在接口查询时按 IP 去重。
- 统计响应的 `meta.data_as_of` 表示最近完成的固定执行集合的建立时间，是后台处理进度水位，
  不是 ES refresh 时间或任意 observation 时间范围的完整性保证。统计表按执行原子更新，可能已含
  水位之后处理完成的执行；它不是按全局版本冻结的历史数据库视图。

Elasticsearch 权威模式会按 `execution_id` 读取 observation 文档。旧索引缺少该字段或必要元数据时，
应先完成现有的扫描事实迁移，再执行快照重建。

## 大执行集成验证

`analytics_snapshot::tests::postgres_backfill_publication_retry_and_batch_writes` 使用一次性 PostgreSQL
连接的临时表验证超过 20 万去重键、事务回滚、过期领取、PIT 协议及缺失观察数；其中 PIT 协议使用
本地 HTTP fixture，不代表真实 ES 验收。默认忽略的可选真实 ES 测试可在**独立、可丢弃**的
PostgreSQL 和 Elasticsearch 9.5.x 环境中运行：

```sh
# 仅接受 127.0.0.1；创建全新测试索引，如索引已存在则失败，不自动删除索引。
python3 scripts/prepare-analytics-es-fixture.py http://127.0.0.1:19200
ANALYTICS_TEST_DATABASE_URL='host=127.0.0.1 port=5432 user=test dbname=test' \
ANALYTICS_REAL_ES_URL='http://127.0.0.1:19200' \
ANALYTICS_REAL_ES_INDEX='network-mapping-scan-observations-v1-2099.01' \
cargo test --locked --lib analytics_snapshot::tests::real_elasticsearch_large_execution -- --ignored
```

该测试读取 610,512 条合成观察，校验 210,001 个 IP 和 420,002 个端点维度事实；测试结束后由
操作人员清理一次性 ES 环境。生产容量与性能仍需使用代表性硬件和数据单独测量。
