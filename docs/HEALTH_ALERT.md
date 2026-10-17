# 健康监控与告警

管理员通过[统一通知渠道](NOTIFICATIONS.md)订阅邮件、飞书或 Telegram，可同时开启多种方式。
健康告警历史和各渠道投递同事务保存，冷却由数据库协调；入库前仍使用有界内存队列。

系统在后台持续检测五类健康信号，命中阈值后按渠道订阅发送通知：

1. **慢请求**：响应耗时超过阈值。
2. **5xx 错误**：服务端处理异常（500–599）。
3. **慢 SQL**：当前轮询窗口平均执行耗时超过阈值的近期慢查询。
4. **慢 Elasticsearch 查询/写入**：应用观察到的 ES 端到端耗时超过分级阈值。
5. **Elasticsearch 异常**：网络、HTTP、超时或分片失败。

这些信号共享同一套通知链路：去重冷却 → 写入事件与各渠道投递 → 统一 worker 发送。邮件渠道沿用 `health_alert` 模板，机器人接收不含原始 SQL/IP 的摘要。

## 目标

- 异常耗时请求与 5xx 错误**实时**告警（请求响应即判定，不依赖轮询）。
- 慢 SQL **零业务侵入**告警（轮询 PostgreSQL 系统视图，不改动任何查询调用点）。
- 通过冷却去重避免告警风暴。

## 检测机制

| 信号 | 检测源 | 判定条件 | 去重 key |
| --- | --- | --- | --- |
| 慢请求 | `main.rs` 请求中间件 `wrap_fn` 的 `duration_ms` | `duration_ms ≥ slow_request_threshold_ms` | `slow_request:{method}:{path}` |
| 5xx 错误 | 同一中间件的 `status_code`（复用 `classify_status`，5xx 归为 `server_error`） | `500 ≤ status ≤ 599` 且 `server_error_enabled` | `server_error:{path}:{status}` |
| 慢 SQL | 后台任务轮询 `pg_stat_statements` | 相邻轮询间的 `Δtotal_exec_time / Δcalls ≥ slow_sql_threshold_ms` | `slow_sql:{queryid}` |
| 慢 ES 查询/写入 | `ElasticsearchService` 统一请求入口 | 按 query/write 阈值判定，同时检查 `timed_out`、HTTP 状态和失败分片 | `{alert_type}:{operation}` |

说明：

- 慢请求与 5xx 复用 `request_log` 采集点已经算好的 `status` / `duration_ms`，只在命中阈值时才克隆字符串，正常请求零额外分配。
- 慢 SQL 使用相邻轮询间的累计计数差计算窗口平均值，过滤掉「历史上慢、但当前已恢复或不再执行」的查询；告警同时记录本周期总耗时、返回行数、共享块命中/读取和临时块读写。首轮轮询只建立基线，不告警。
- ES 请求使用有限集合的 `X-Opaque-Id` 标识操作类型，使用唯一 W3C `traceparent` 关联应用告警、Query Logging、Slow Log 和任务 API。告警只记录操作名、耗时、ES `took`、状态、分片和 trace ID，不记录查询或 Bulk 正文。

## 通知机制

- **渠道**：邮件（复用现有 SMTP 与邮件模板系统，无新增依赖）。
- **收件人**：所有 `role = 1`（管理员）且未禁用、未删除、邮箱非空且格式合法的用户，逐人各发一封。
- **模板**：`health_alert` 邮件模板，可在「设置 → 邮件模板」中像登录通知模板一样编辑、预览、发布；未发布时使用内置默认模板（HTML + 纯文本，含 `{% for d in details %}` 详情列表）。
- **冷却去重**：同一去重 key 在 `alert_cooldown_seconds` 窗口内只发一次，重复事件丢弃并记 `debug` 日志。
- **历史持久化**：每条通过冷却去重的告警写入 `health_alert` 表（`alert_type` / `alert_key` / `severity` / `summary` / `detail` JSONB），供告警历史页与后续去重复用。
- `monitor.enabled = false` 时不产生告警。产生事件后，只向已启用、订阅健康告警且级别匹配的渠道投递。
- SMTP 和管理员邮箱只影响邮件渠道；飞书和 Telegram 可独立工作。邮件没有有效收件人时，在投递记录中显示公开失败原因。

## 使用方法

1. **在「设置 → 通知渠道」配置渠道**：选择邮件、飞书或 Telegram，订阅「健康告警」并启用；可同时开启多个渠道。邮件可填写收件人或使用默认管理员邮箱。

2. **在「设置 → 运行时配置 → 健康监控」发布配置**，按需调整阈值与冷却时间。`config.toml` 的 `[monitor]` 只在数据库中缺少该配置域时用于初始化。

3. **（慢 SQL 必需）启用 `pg_stat_statements`**（见「前提」）。

4. **保存后在处理请求的服务进程内生效**，无需重启 Web 服务；慢 SQL 循环在下一轮读取新阈值和间隔。多实例部署的其他实例需重启加载数据库中的最新配置。发布时拒绝非法阈值；启动时仍会校验 TOML。

5. **选择通知方式**：在统一页面启停渠道或更改「健康告警」订阅。旧 `health_alert_enabled` 仅用于一次性迁移，不再充当所有通知的全局开关。

## 前提

- **邮件**：SMTP 已配置、发件邮箱密钥已配置、至少一名管理员已填邮箱。
- **慢 SQL**：依赖 PostgreSQL 的 `pg_stat_statements` 扩展，需要数据库管理员操作：

  ```sql
  -- postgresql.conf
  shared_preload_libraries = 'pg_stat_statements'   -- 需重启 PostgreSQL
  ```

  ```sql
  -- 重启后执行一次
  CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
  ```

  - 未启用该扩展时，慢 SQL 检测**不影响**慢请求 / 5xx 告警，只会在首轮记录一次 `warn` 后跳过，后续失败记 `error`。
  - 时间单位为**毫秒**（`pg_stat_statements.total_exec_time` / `max_exec_time` 本身即毫秒）。
  - PostgreSQL 15+ 中 `query` 文本可能对无权限用户返回 NULL，此时告警以 `queryid` 作为标识，不影响告警产生。
  - `queryid` 本身也可能为 NULL（如关闭 `compute_query_id` 时未被计数的 utility 语句）；这类语句无法用 `queryid` 去重，慢 SQL 检测会跳过、不产生告警。

## 配置

以下是首次初始化使用的 TOML 配置示例。数据库已有 `monitor` 记录后，应通过管理页面或 `POST /api/config/runtime/monitor` 发布；修改 TOML 并重启不会覆盖数据库值。接口、版本冲突和多实例限制参见[服务端运行时配置](RUNTIME_CONFIGURATION.md)。

```toml
[monitor]
enabled = true                      # 是否启用健康监控与告警（默认 true）
slow_request_threshold_ms = 3000    # 慢请求阈值（毫秒）
server_error_enabled = true         # 是否对 5xx 告警
slow_sql_threshold_ms = 3000        # 慢 SQL 阈值（毫秒，基于当前轮询窗口平均耗时）
slow_sql_check_interval_seconds = 60# 慢 SQL 轮询间隔（秒）
elasticsearch_query_warning_threshold_ms = 1000
elasticsearch_query_critical_threshold_ms = 3000
elasticsearch_write_warning_threshold_ms = 5000
elasticsearch_write_critical_threshold_ms = 15000
alert_cooldown_seconds = 300        # 同一告警 key 的冷却时间（秒）
```

字段均带默认值（`#[serde(default)]`）。数据库没有 `monitor` 记录时，省略 TOML 段会使用默认开启的配置初始化；已有记录时沿用数据库中的开关和阈值。

## 注意事项

- **首次初始化默认开启**：省略 TOML `[monitor]` 时 `enabled` 默认为 `true`；已有数据库配置不会因升级或重启被重新开启。若 SMTP 未配或没有管理员邮箱，告警会被静默跳过。
- **慢 SQL 告警是「当前窗口确实慢」**：使用 `total_exec_time` 和 `calls` 的增量计算当前窗口平均值；停止执行、当前窗口恢复正常或统计计数重置后不会告警。
- **冷却状态在内存中**：重启后去重窗口清零，重启后短时间内可能重复收到一批告警。告警事件已持久化到 `health_alert` 历史表，但冷却去重仍基于内存，尚未用历史表做跨重启去重。
- **每次告警给每位管理员各发一封**：管理员较多时一封事件对应多封邮件。
- **告警邮件不记录 HTTP 请求体或 ES DSL/Bulk 正文**：慢请求与 5xx 只携带 method、path（不含 query）、状态码、耗时、请求 ID、来源 IP、操作者；ES 告警只携带脱敏的固定元数据。PostgreSQL 慢 SQL 仍携带查询文本（截断到 2000 字符），若文本不可见则回退为 `queryid`。
