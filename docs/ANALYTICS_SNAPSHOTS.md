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

## 扫描分析页图表快照

图表发布器使用现有 PostgreSQL 扫描快照事实，按系统时区计算页面的 4／8／12 周查询。
热力图保存各权限及筛选范围的每日精确唯一 IP 数。分布保存预设窗口的总数和 Top 10，
接口直接截取所选 Top N。管理员全局和用户自身范围分别计算；全部扫描器或来源的唯一 IP
在后台跨执行去重。图表结果以同一发布版本提交，两条接口返回 `meta.snapshot_revision` 和
`meta.data_as_of`。任意时间范围、专项统计和报告继续使用各自已有的统计口径。

### 启用和回滚

1. 基础快照已发布后，在设置的运行策略中，将「分析图表快照」设置为「后台生成」
   （`analytics_snapshot.page_rollups = "build"`）。保持现有读取路径，等待首次发布。
2. 重新加载设置，确认 `GET /api/config/runtime/analytics_snapshot` 的 `page_progress.ready`
   为 `true`，核对时区和数据时间。在 `mode = "snapshot"` 下切换为「读取已发布图表」
   （`page_rollups = "read"`）。页面窗口未准备好时接口返回
   `503 analytics_page_snapshot_pending`，响应含 `Retry-After`。
3. 需要恢复旧查询时，切回「后台生成」并保留后台发布，或切为「关闭」
   （`page_rollups = "off"`）同时停止发布。重新启用后等待新一轮回填。历史事实和已生成结果无需删除。

发布器每 15 秒检查一次，数据库事务锁保证同一时间只有一个发布器。事实新增、替换、级联删除、
截断和历史补传写入变更记录。一次发布读取固定的数据库视图并原子更新结果，计算期间的新变更留给
下一次发布。新增可以继续使用上一个完整版本。受删除或替换影响的窗口在新版本提交前返回准备中，
以免展示已失效的数据。发布器会为跨午夜后的预设范围提前生成结果。更改时区后，在匹配新时区的
版本就绪前返回准备中。非上海时区遇到仅保留上海日期的旧事实时，热力图沿用原来的历史兼容提示。

排查时查看 `page_progress` 中的 `revision`、`timezone`、`data_as_of`、`ready` 和
`pending_changes`，以及服务日志 `AnalysisPageSnapshotPublished`、
`AnalysisPagePublicationFailed`、`AnalysisPagePublicationTimedOut`。调试级别的
`AnalysisPageSnapshotRead` 提供连接获取和主 SQL 耗时。

### 前后性能对比

在本地 PostgreSQL 18 使用 534,655 条发现事实、1,458,000 条分布事实，
以管理员无筛选的默认 12 周窗口交替执行新旧 HTTP 处理路径。每条路径预热一次后取 24 个样本，
逐次对照响应 `data`。计时包含实际查询、连接池获取和响应序列化，测试注入管理员身份，
未计入真实登录鉴权、网络和反向代理。未启用响应缓存。

| 请求 | 原路径 P50 / P95 | 图表快照 P50 / P95 |
| --- | ---: | ---: |
| 发现 IP 热力图 | 207.31 / 211.69 ms | 1.46 / 1.70 ms |
| 服务分布 Top 5 | 36.43 / 39.20 ms | 0.82 / 1.02 ms |
| 端口分布 Top 10 | 76.63 / 78.60 ms | 0.93 / 1.20 ms |

本轮首次发布耗时 7.31 秒，图表表及索引合计约 55 MB。一次影响一天的分布变更重新发布耗时 3.08 秒。
这些数据来自本地压测，生产切换后应继续观察上传延迟、连接池等待、发布耗时和请求 P95。

复测时将 `ANALYTICS_TEST_DATABASE_URL` 指向一次性 PostgreSQL 数据库，执行：

```sh
cargo test --locked --lib analytics_page::tests -- --include-ignored --nocapture --test-threads=1
```

## 配置

```toml
[analytics_snapshot]
# realtime: 保持旧实时查询；shadow: 后台构建、接口仍实时；snapshot: 接口只读快照。
mode = "realtime"
# off: 关闭；build: 只后台生成；read: snapshot 模式下读取已发布图表。
page_rollups = "off"
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
**先升级全部服务实例**：旧 worker 不识别新心跳，混跑时可能把处理超过 60 分钟的
任务视为失效。无需清空统计表或重新运行全量重建；开启 `shadow` / `snapshot` 后普通待重试任务
与下述挂起任务自动接续。

旧版因 `statistics_resource_limit: 执行去重集合超过 200000` 被设置为 `infinity` 的任务，会在
每轮 reconcile（`shadow` / `snapshot` 模式，默认 30 分钟，含启动首轮）**自动重新排队**，
无需手动 SQL：新版已改为临时表分批去重，不再受该上限约束。重新排队只影响 `pending` 且
`available_at = infinity` 的匹配行，不覆盖正在运行的领取，`last_error` 保留供排查、处理成功
后清除（事件 `AnalyticsSnapshotLegacyParkedRecovered`）。混跑期间旧实例可能把重新排队的任务
再次挂起，下一轮 reconcile 会继续收敛，无需重启；源 observation 仍需保留且 PostgreSQL 有
足够磁盘。

因 `statistics_resource_limit: 统计暂存空间超过 N MiB` 挂起的任务，在运行时配置把
`max_staging_mib` 调大到超过挂起时的上限 N 后自动重新排队（事件
`AnalyticsSnapshotStagingParkedRecovered`）；上限未变时不会反复重试容量不足的任务。
资源不足时先处理容量，不能仅反复排队。查看日志 `AnalyticsSnapshotProgress`、
`AnalyticsSnapshotExecutionFailed` 和队列 `last_error`。
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
