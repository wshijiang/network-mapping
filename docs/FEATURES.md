# 服务端功能指南

可信来源 IOC 自动标记、Web 来源管理与必须人工审核的 AI 补充提取见
[威胁情报、可信 IOC 与 AI 审核](THREAT_INTELLIGENCE.md)。
独立 LLM 导航提供供应商／模型单选、全局与局部配置及在线对话调试，见 [LLM 配置](LLM.md)。

[返回项目首页](../README.md) · [文档索引](README.md)

本指南汇总功能入口、关键行为与配置示例。首次部署见[部署指南](DEPLOYMENT.md)，完整协议和运维步骤通过各节链接查阅。

[资产高级搜索](#资产高级搜索) · [扫描器调度](#扫描器调度) · [运行时配置](#运行时配置) · [自动目标生成](#自动目标生成) · [健康监控与告警](#健康监控与告警) · [PostgreSQL 备份](#postgresql-备份) · [开源项目清单](#开源项目清单) · [扫描器错误与日志诊断](#扫描器错误与日志诊断)

## 资产高级搜索

搜索页支持 IP/CIDR、端口、协议、服务、Banner、HTTP 标题/正文、TLS Subject、ASN、地理信息、扫描器、观察时间和资产
标签的组合查询。可以使用 `AND`、`OR`、`NOT`、括号、比较运算、包含匹配、`IN`、
`EXISTS`，并通过 `has_endpoint(...)` 表达同一个 IP 上存在多个不同端点。

```text
ip IN 192.0.2.0/24
AND port IN (80, 443)
AND service ~ "http"
AND tag = "生产环境"
```

统一接口为 `POST /api/search/v2`；裸 IP、裸 CIDR、`port:443`、`service:https` 和
`banner:nginx` 等旧输入仍然兼容。完整字段表、标签否定语义、逻辑优先级、跨端点查询、
API 请求响应和限制参见[资产搜索语法与 API](SEARCH_SYNTAX.md)。

服务端仅支持 Elasticsearch 9.5.x 存储扫描结果，PostgreSQL 保留用户、权限、任务、标签、
上传回执和派生分析快照。PG 旧结果仅支持通过独立命令迁移到 ES。幂等回填、启动检查、
查询覆盖、快照和回滚流程参见[Elasticsearch 9.5.x 扫描存储与搜索](ELASTICSEARCH.md)。

## 扫描器调度

创建任务接口 `POST /api/task/create` 支持 `dispatch_mode`：`automatic` 由下一台可用扫描器领取一次，`selected` 配合 `scanner_ids` 指定一台或多台扫描器，`all` 会为创建时所有已启用扫描器分别创建执行实例。离线的指定扫描器会在重新上线后领取任务。

创建页统一提供四种扫描模式：“全部”对应 `vulnerability_scan`，“仅端口”对应
`port_only`，“服务识别”对应 `service_inventory`，“仅 DNS”对应 `dns_records`。
前三种可用于 IP/CIDR 或域名；域名会先解析 A/AAAA，再按地址族创建授权范围内的扫描任务。
“仅 DNS”只能用于域名，前端与服务端都会拒绝 IP/CIDR 目标或附带端口的请求。`legacy`
继续作为旧节点和系统默认值的兼容 profile。非 legacy 任务会根据心跳中的扫描能力选择节点。
任务计划、能力字段、类型化观察结果和幂等分批上传参见
[扫描计划与结果协议](SCAN_PIPELINE.md)。

任务会根据目标自动标记为 `ipv4` 或 `ipv6`。同一任务不能混合两种地址族；服务端只允许对应协议当前就绪的扫描器领取任务。旧版扫描器未上报网络能力时按仅支持 IPv4 兼容。

任务详情接口 `GET /api/task/{task_id}` 返回 `executions`，并可通过 `execution_id` 查询参数选择某个执行实例的分页结果。同一个逻辑任务下，各扫描器的状态、失败原因和扫描结果相互独立；导出的 CSV/JSON 也包含执行实例和扫描器标识。

## 运行时配置

请求日志、健康监控、自动目标、DNS 后续任务和分析快照配置以数据库已发布值为准；对应 TOML 段仅在数据库记录缺失时初始化。管理员在“设置 → 运行时配置”保存，接口为 `POST /api/config/runtime/{namespace}`。首次初始化沿用 TOML 的扫描开关，应预先核对授权范围。生效规则、多实例限制见[服务端运行时配置](RUNTIME_CONFIGURATION.md)。

## 自动目标生成

以下 TOML 仅用于数据库记录缺失时初始化；已有配置应通过“设置 → 运行时配置”发布。

服务端可以从明确授权的 IPv4/IPv6 CIDR 中顺序生成扫描任务。两个地址族使用独立的
队列水位和生成游标，并且只有存在对应协议在线扫描器时才补充任务。默认只配置 IPv4，
IPv6 自动生成保持关闭：

```toml
[automatic_target]
enabled = true
strategy = "sequential_subnet"
interval_seconds = 30
pending_low_watermark = 2
pending_high_watermark = 5
priority = 0
authorized_cidrs = ["198.51.100.0/24"]
excluded_cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"]
ipv4_task_prefix = 24
ipv6_enabled = false
ipv6_authorized_cidrs = []
ipv6_excluded_cidrs = ["fc00::/7", "fe80::/10", "::1/128"]
ipv6_task_prefix = 120
ipv6_pending_low_watermark = 1
ipv6_pending_high_watermark = 2
common_ports = "21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,1433,1521,2049,2375,2376,3000,3306,3389,5432,5900,6379,8080,8443,9200,11211,27017"
repeat_after_seconds = 604800
```

`enabled` 是兼容已有配置保留的 IPv4 开关，`ipv6_enabled` 单独控制 IPv6。IPv6 默认按
`/120` 生成，每个任务最多包含 256 个地址；不建议直接把完整 `/64` 作为扫描任务。
网络测绘场景允许将 `ipv6_authorized_cidrs` 配置为 `["::/0"]`；系统仍按 `/120` 逐个生成
小任务，不会把整个 `/0` 作为单个任务下发。IPv6 游标使用 128 位计数，并在数据库与状态
接口中表示为十进制字符串，以避免 JSON 大整数精度损失。
生成候选网段与任一排除 CIDR 相交时会跳过整个任务，因此即使授权范围很大也不会把排除
地址夹带进扫描任务。排除项默认值在代码层为空，示例配置显式排除了常见私网、回环和
链路本地范围。
生成游标存储在数据库中，服务重启后继续；同一目标在冷却期内不会重复生成。管理员可通过
`GET /api/automatic-target/status` 查看两个地址族各自的队列、游标和可用扫描器数量。

完整的心跳载荷、数据库字段、调度规则、升级兼容和故障排查参见
[双栈扫描与自动目标文档](DUAL_STACK_SCANNING.md)。

搜索时按需创建更新任务的配置、去重和故障行为见 [搜索触发目标更新](SEARCH_TARGET_GENERATION.md)。

## 健康监控与告警

服务端内置健康监控，实时检测慢请求、5xx 服务端错误和 Elasticsearch 慢查询/写入，并轮询
`pg_stat_statements` 检测 PostgreSQL 慢 SQL，命中阈值后通过邮件通知所有启用中的管理员。`monitor` 运行时配置控制阈值、
轮询间隔与冷却时间，通知偏好中的 `health_alert_enabled`（默认开启）控制是否发送。
慢 SQL 检测需要数据库预先启用 `pg_stat_statements` 扩展。完整的使用方法、前提与
注意事项参见
[健康监控与告警](HEALTH_ALERT.md)。

请求级性能观测和错误分类见[请求日志](REQUEST_LOG.md)；资源读取、连接池等待与上传事务的
排查见[系统资源读取与慢依赖隔离](SYSTEM_RESOURCE_RESILIENCE.md)。

## PostgreSQL 备份

服务端可通过管理员页面查询 pgBackRest stanza 和备份集、手动执行全量/差异/增量备份、
运行 WAL 归档检查并查看任务日志。功能默认关闭；定时备份使用独立 systemd timer，避免
依赖 Web 进程存活。部署、权限、配置和恢复验证步骤参见
[pgBackRest 备份管理](PGBACKREST_BACKUP.md)。

## 开源项目清单

`GET /api/open-source/projects` 返回编译进服务端的第三方直接包依赖清单，包含构建与开发依赖。升级 `Cargo.toml`、扫描器依赖或前端 `package.json` 后，应同步复核 `source/open_source_projects.json` 中的声明范围、许可证和上游链接，并运行 `python3 scripts/check-open-source-catalog.py`。范围、复核依据与维护步骤见[第三方依赖清单维护](OPEN_SOURCE_CATALOG.md)。

## 扫描器错误与日志诊断

管理员可在扫描器详情刷新固定日志目录、采集文件快照并下载，查看扫描端主动上报和日志解析得到的错误、证据行号及聚合告警。诊断通过已有心跳和 HTTPS 通道工作，支持分块续传、去重、权限审计及留存清理。配置、接口、升级和验证参见[扫描器错误诊断与日志采集](SCANNER_DIAGNOSTICS.md)。

## 操作系统识别

服务端异步处理已有服务证据，在任务、资产和搜索页面提供系统线索与可解释证据。
资产摘要在当前调用者权限范围内融合多个端口，保留未知、冲突与过期标识。
查看步骤、支持范围及搜索字段见[操作系统识别](OS_DETECTION.md)。

## Web 框架与组件识别

服务端异步解析已有 HTTP/HTTPS 证据，识别服务器、框架、CMS 和前端组件及明确版本。
搜索、任务详情和资产端口列表展示可追溯结果；支持版本关联搜索和历史重算。
识别对象为 IP 端点，详见 [Web 框架与组件识别](WEB_DETECTION.md)。

技术覆盖、MinIO/S3 与 GitLab/Git 服务区分及分批扩展见 [Web 技术目录](WEB_TECHNOLOGY_CATALOG.md)。
