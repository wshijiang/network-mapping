# 服务端运行时配置

本文说明配置来源、发布接口、生效规则与多实例限制。

## 配置来源与边界

启动链路、密钥和本机资源仍由 `config.toml` 提供，包括监听地址与请求体上限、数据库连接、TLS、日志、模板/前端/MaxMind 路径、Elasticsearch 和 pgBackRest 配置。SMTP 等既有设置仍沿用原有存储和接口。

运行策略保存到 PostgreSQL 的 `runtime_configuration`，进程读取经过校验的内存快照：

| namespace | 首次初始化来源 | 管理入口 |
| --- | --- | --- |
| `general` | 内置默认值 | 常规设置中的系统时间配置 |
| `requests` | TOML `[requests]` | 运行时配置 → 请求日志 |
| `monitor` | TOML `[monitor]` | 运行时配置 → 健康监控 |
| `automatic_target` | TOML `[automatic_target]` | 运行时配置 → 自动目标 |
| `dns_follow_up` | TOML `[dns_follow_up]` | 运行时配置 → DNS 后续任务 |
| `dns_resolvers` | 内置默认值 | 运行时配置 → DNS 服务器 |
| `analytics_snapshot` | TOML `[analytics_snapshot]` | 运行时配置 → 分析快照 |
| `report_mail` | TOML `[report_mail]`，默认关闭图片 | 运行时配置 → 报告邮件 |

数据库中已有的配置不会被启动时的 TOML 覆盖。文件中的这些策略段只在对应数据库记录缺失时作为种子；修改文件并重启不能替代发布运行时配置。启动时仍会校验 TOML，文件必须保持合法。

**当前首次初始化会沿用 TOML 的启用状态。** `automatic_target` 和 `dns_follow_up` 没有额外的“首次强制禁用”步骤；部署前应检查文件中的开关和授权范围。希望管理员确认后才开启时，应先在 TOML 中禁用，再通过管理页面发布。

## 初始化、持久化与失败行为

1. 启动时连接数据库、初始化 schema，再加载运行时配置。
2. 当前表缺失记录时使用种子插入，`ON CONFLICT DO NOTHING` 保留已有配置，并补存初始修订历史。
3. 当前配置保存在 `runtime_configuration`，修订文档保存在 `runtime_configuration_revision`。发布时在同一事务内更新当前文档、递增 revision 并插入历史。
4. 保存前按配置域解析并校验完整 document。`expectedRevision` 不匹配返回 HTTP 409；客户端重新读取后再保存，响应不附带当前 revision。
5. 成功发布后替换当前进程的内存快照，再单独写入操作审计。配置事务与审计写入不是同一事务；审计记录包含配置域、revision 和变更原因。

数据库配置反序列化或校验失败时：`automatic_target`、`dns_follow_up` 和 `dns_resolvers` 回退到各自内置默认值；`requests`、`monitor` 和 `analytics_snapshot` 回退到启动时的 TOML 值，并记录警告。`general` 无效时启动加载报错，避免使用不确定的业务时区。数据库连接或 SQL 加载失败会使启动失败，不会绕过数据库继续运行。

## API 与权限

当前提供：

- `GET /api/config/runtime/{namespace}`：读取当前 document 和 revision。
- `POST /api/config/runtime/{namespace}`：发布完整配置文档。

接口要求管理员身份，并沿用现有登录与 CSRF 保护。发布请求采用 camelCase：

```json
{
  "expectedRevision": 12,
  "document": { "enabled": true, "retention_days": 30 },
  "changeReason": "调整请求日志保留期"
}
```

上例用于 `requests` 域；其他域应先读取当前完整 document，再修改所需字段。成功响应的 `data` 包含 `namespace`、新 `revision` 和 `document`。未知配置域返回 404，非法参数或配置返回 400，版本冲突返回 409。

当前没有修订历史查询或回滚 HTTP API。修订表已保存历史，但不能将尚未实现的 `/revisions`、`/rollback/{revision}` 地址作为可用接口。

## 生效与多实例限制

发布成功后，处理请求的进程立即替换配置快照。请求日志、自动目标、DNS 后续任务和分析快照由相应处理路径或后台循环读取；新策略按这些路径的读取时机生效。监控发布还会更新 `MonitorHandle`，慢 SQL 循环在下一轮读取新配置，已开始的等待不会被立即中断。

`general` 另有每 5 秒刷新数据库的后台循环。其他运行策略目前没有通用的 15 秒 revision 轮询，也没有 PostgreSQL `NOTIFY` 同步机制。多实例部署时不能假定一次发布会自动同步所有实例；其他实例需重新启动加载数据库中的配置。直接修改数据库也不会立即更新这些域的进程内快照。

## 扫描器运行配置

扫描器运行参数是另一套独立配置，按扫描器保存到 `scanner_runtime_configuration` 及其修订表，不属于上面的全局 namespace：

- `GET /api/scanner/{scanner_id}/configuration`：管理员读取配置及应用状态。
- `PUT /api/scanner/{scanner_id}/configuration`：管理员发布扫描器配置。
- `GET /api/scanner/runtime-config?scannerid={scanner_id}`：扫描器使用运行凭据获取下发文档。

前端入口是 `/scanner/{id}/configuration`。本地部署开关、速率限制和任务边界应用规则见扫描器仓库的 `docs/MAINTENANCE.md`“本地部署配置与远程运行配置”。

`report_mail` 在每次报告生成时读取数据库权威文档，读取该配置接口也刷新本实例快照；多实例无需重启即可在新报告中使用已发布配置。归档邮件与图片不会随配置变化而改写。详见 [报告邮件](reports.md#完整邮件与远程趋势图片)。

## 报表渲染模块选择

`report_renderer` 是模块管理服务使用的独立 namespace，复用 `runtime_configuration` 和修订表。它通过 `GET/POST /api/modules/report-render` 管理，不属于通用运行配置保存接口。默认使用 `builtin`，已发布选择在启动时恢复，并每五秒刷新；制品缺失或校验失败不会替换活跃实现。完整制品部署与版本切换见[模块实现](MODULE_RUNTIME_IMPLEMENTATION.md)。
