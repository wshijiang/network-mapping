# 统计分析

入口：数据分析 → 统计分析，路由 `/analysis/statistics`。所有登录用户可访问，普通用户仅查询自己的任务及扫描事实，管理员可查询全局数据。Scanner 无需升级。服务端启动自动创建轻量的 `statistics_instance` 状态表，并在 `runtime_configuration` 中初始化 `statistics_cache` 配置域。

## 页面能力

- 总览：依次加载五类基础统计，不并行触发聚合，也不默认计算分位数或上期对比。
- IP 发现：按日、周、月、扫描器、任务来源统计分组去重 IP，另算整个范围的去重 IP。
- 端口、服务分布：按类别汇总执行端点，Top 5/10/20，剩余合并为“其他”。
- 任务执行：按日、周、月、来源统计新建、完成、成功、失败、部分完成、取消及成功率。
- 扫描器表现：按扫描器、日、周、月、来源统计完成执行、状态、成功率、成功执行平均耗时及可选 P50/P95。
- 图表：折线、柱状、环形、堆叠柱状、IP 每日热力图；仅提供适合当前指标和维度的类型。
- 图片：PNG（2 倍像素）、SVG，宽度 960/1400/1920，白色或透明背景；带标题、范围、时区、来源、生成时间、水位及口径说明。
- 数据：图表 CSV，完整汇总 CSV/JSON。完整导出不受 Top N 和表格分页影响，包含原始精度数值、筛选条件、总计和说明。CSV 兼容中文并防止文本公式解释。

- 专项分析：每日均值、峰值、有观测天数、Top 5 集中度、失败率及部分完成率；表格支持搜索和分页。
- 对比：可选前一等长日历周期，绝对差值和百分点差值分别展示。未结束周期及历史保留限制单独提示。
- 明细：点击分组按需读取游标分页，每页最多 100 条（页面默认 50），支持当前页导出；任务/执行链接复用已有详情页。扫描明细为原始观测或保留事实，可能重复，不作为去重总数。

## 口径与一致性

时间筛选遵循系统业务时区；结束日期包含当天，API 使用 `[start_at,end_at)`。周一为周起点。查询范围上限 366 天。日期缺口显示 0，无成功率分母或有效耗时样本时为 `null`，页面显示 `--`。

任务按逻辑任务计数，新建按创建时间、终态按结束时间归属。指定扫描器时，任务筛选使用执行存在性检查；同一任务分配多个扫描器仍只计一个任务。扫描器表现按执行实例计数，取消包含在完成数量中，成功率分母为成功＋失败＋部分完成。耗时仅包含成功且起止时间有效的执行；总体平均值、P95 和成功率直接按全体样本计算，不累加或平均分组指标。

IP 各组独立去重，周期去重直接计算，不能累加每天或各扫描器数量。实时模式使用观测索引，端口/服务按执行端点去重。快照模式沿用现有首次发现和代表性端点事实及 30 分钟窗口；服务归一化等差异与原扫描分析一致。扫描结果不代表当前资产存量。

任务、扫描器及快照查询在 PostgreSQL repeatable-read 只读事务内计算。实时扫描查询采用 Elasticsearch composite 分页，拒绝失败分片、异常游标和超出上限的结果；索引可能在分页过程中更新，结果不提供跨请求历史归档保证。页面、图表和导出使用同一份返回数据；修改筛选后需重新生成。时区改变时取消旧请求并清空旧结果。

快照模式要求已有可读水位；首次回填未完成返回 503。处理水位不是整个查询范围完整性的保证，页面明确标注基于保留数据。其他时区遇到尚未回填的上海日期旧事实返回明确错误，不伪造日期。

## 接口

- `GET /api/analysis/statistics/catalog`：数据类型、允许维度、指标和图表类型。
- `POST /api/analysis/statistics/query`：复用认证、CSRF 和限流；请求示例：

```json
{
  "data_type": "discovery",
  "group_by": "day",
  "start_at": "2026-09-01T16:00:00Z",
  "end_at": "2026-10-01T16:00:00Z",
  "timezone": "Asia/Shanghai"
}
```

可选 `scanner_id`（UUID）及 `task_source`（manual/automatic/search）。拒绝任意维度与系统时区不一致的查询。返回 `data.rows`、`data.summary`、`meta`，包括筛选条件、口径版本、水位、数据模式和说明。不允许调用者指定其他用户身份。

可选 `metrics` 控制请求的指标，省略时只计算基础指标；P50/P95 需要显式请求。可选 `comparison: "previous"` 复用相同筛选和计算预算。`POST /api/analysis/statistics/details` 接受相同时间/筛选、`data_type`、可选 `mode`、`category`、`after` 游标和 `page_size`，不执行全量明细计数。

## 计算保护

- 每个进程共享统计服务；最多运行 2 个计算，另有 8 个排队位置，最多等待 2 秒。PostgreSQL 会话 advisory lock 将多个服务实例的在线统计总并发限制为 2；不同数据库之间独立计算。
- 每个用户最多一个不同条件的冷查询在途，每 60 秒最多发起 12 个冷查询；相同条件合并执行，单次计算最多 16 个订阅者。关闭缓存仍保留这些限制。
- HTTP 计算等待预算 15 秒，SQL 每条最多 8 秒（根据剩余预算缩短），锁等待 500 毫秒，禁用统计事务内 PostgreSQL 并行扫描。请求超时后保留计算许可，直到有界数据库操作和事务清理结束，防止旧查询尚未停止就放入新查询。
- Elasticsearch 每页 1000 个组合桶、单次调用最多 3 秒、当前期加上期合计最多 50000 桶；汇总分组默认最多 20000 个，可在运行策略调整为 1–65536 个。超限返回明确错误，不把截断结果作为完整统计。
- 过载返回 429，超时/预算耗尽返回 503，均携带 `Retry-After`；前端手动重试，不循环刷新聚合。明细也复用相同计算限额。
- 统计查询及明细的 503 保留固定公开原因码和提示：`statistics_timeout`、`statistics_budget_exceeded`、`statistics_snapshot_pending`、`statistics_config_unavailable`、`statistics_failed`；底层数据库与 Elasticsearch 诊断不进入响应。拒绝日志 `StatisticsRequestRejected` 记录请求 ID、统计类型、汇总维度（明细为空）及原因码，并写入请求日志的 `reason_code`。统计后台任务继承发起请求的 tracing span，便于关联底层失败日志。
- 查询失败时，`StatisticsQueryContext` 记录请求 ID、数据类型、维度、数据模式、半开时间范围、是否启用扫描器或来源筛选及上期对比；不记录筛选值或结果。`StatisticsBudgetExceeded` 记录 `reason`（`es_buckets` 或 `groups`）、已处理数量 `observed`、`limit` 和发生超限的周期范围。实时桶数在本期和上期之间累计；SQL 查询最多读取上限加一个溢出分组（以及适用时的总计行），达到上限时观测数量不代表实际总分组数。
- `StatisticsAdmissionRejected` 的 `reason` 区分 `user_rate_limit`、`user_in_flight`、`queue_full`、`subscribers_full`、`rate_registry_full`、`permit_wait_failed`、`cluster_slots_full`、`cluster_lock_error`、`pool_timeout` 和 `pool_unavailable`。限频日志含窗口内冷查询数与已过时间；其他拒绝记录可用的容量信息。用 JSON 日志中的 `span.request_id` 与请求日志关联；合并的相同查询共享后台计算，后台事件属于发起计算的请求。
- 后台快照回填分页间隔至少 100 毫秒；每轮启动任务时间窗口 2 秒（已开始任务继续完成）。失败指数退避 30 秒至 30 分钟；单执行去重集合超过 200000 条时暂停自动重试，保留错误和已有事实，拆分任务或离线处理后再手动重建。此限制不等于进程 RSS 硬上限。

## Web 缓存配置

管理员入口：设置 → 运行策略 → 数据分析 → 统计缓存。普通用户不能读取配置、状态或清空缓存。

| 字段 | 默认值 | 允许范围 |
| --- | --- | --- |
| 启用结果缓存 | 开启 | 开启/关闭 |
| 实时统计 TTL | 30 秒 | 5–300 秒 |
| 任务历史 TTL | 30 秒 | 5–300 秒 |
| 快照统计 TTL | 60 秒 | 10–900 秒 |
| 最大条目 | 256 | 16–4096 |
| 每实例结果容量 | 32 MiB | 8–256 MiB |
| 单条结果容量 | 2048 KiB | 256–8192 KiB |
| 统计分组上限 | 20000 | 1–65536 |

分组上限适用于实时、快照和任务历史查询，不改变 Elasticsearch 的 50000 桶预算或查询超时。旧配置缺少该字段时自动采用默认值；升级时先更新全部服务端实例，再更新控制台或保存新配置，旧服务端不认识新字段；修改后新查询生效，已开始的查询使用原值。调高可能增加查询时间、内存、响应大小和浏览器处理开销，仍可能触发其他预算。超限不会返回截断结果。

缓存保存序列化响应，命中直接共享字节；按 TTL 和最近访问顺序淘汰。容量统计为响应正文大小，不包含键、容器及计算中的临时内存；配置上限也不是整机内存上限。部署在小内存环境时应按实际余量选择容量。缓存键包含用户、角色、筛选、指标、时区、数据模式和模式版本。结果允许在 TTL 内滞后，数据清理或变化不会逐条同步失效。

配置读取/保存复用 `/api/config/runtime/statistics_cache`，保存必须携带 `expected_revision`，冲突返回 409 并保留页面草稿。恢复默认值仅修改草稿。每次发布（含清空操作）递增持久化版本并清理旧缓存；清理前的在途结果不能重新填充缓存。不预热、不自动重新计算。

`GET /api/analysis/statistics/cache` 提供命中、合并、拒绝、容量和近两分钟实例状态。`POST /api/analysis/statistics/cache/clear` 接受 `{ "expected_revision": 1 }`，执行权限和审计检查。实例每 5 秒同步配置并上报状态，统计请求也先校验配置；页面可见时每 30 秒刷新状态，隐藏或卸载时停止轮询。各实例缓存独立，总容量为每实例配置之和。

这些预算约束统计造成的并发和工作量，不能保证任意数据量下 CPU 始终低于某个百分比。实际收益需在目标部署按冷/热查询、数据库执行计划和 CPU 指标验收；本次未在生产数据或真实 Elasticsearch 集群上压测。继续沿用现有时间/归属索引，不在启动期间创建重型索引。

## 验证

```sh
cargo fmt --check
cargo clippy --all-targets
cargo test
ANALYTICS_TEST_DATABASE_URL='host=/tmp port=55448 dbname=statistics_test user=test' cargo test --lib handlers::statistics::tests -- --include-ignored
ANALYTICS_TEST_DATABASE_URL='host=/tmp port=55448 dbname=statistics_test user=test' cargo test --lib statistics::integration -- --ignored --test-threads=1
```

集成测试仅连接一次性测试库，使用会话临时表或独立 schema，覆盖逻辑任务与执行计数、权限、多扫描器、同名扫描器、跨日 IP 去重、半开边界、所有汇总维度、筛选、P95 和旧时区事实拒绝。

前端：`pnpm test:statistics`、`pnpm test:charts`、`pnpm test:time`、`pnpm test:theme`、`pnpm build`，并检查桌面/移动端、深浅色、加载/空/错误状态，以及 CSV/JSON/PNG/SVG 实际下载。
