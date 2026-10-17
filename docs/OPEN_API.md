# 外部 API v1 接入文档

该 API 面向合作方服务和现有用户的个人工具。业务前缀为 `/open-api/v1`，公开规范为 `GET /open-api/openapi.json`，管理与调试入口为 `/open-platform`。接口目录和 OpenAPI 从服务器同一份 80 项路由白名单生成。

## 接入步骤

1. 使用现有 Web 账号登录，在「开放平台 → 应用与凭据」申请个人应用。合作方应用由管理员创建并绑定一个现有责任用户。
2. 填写用途、需要的 scopes、字段、数据来源、CIDR/域名范围及配额。管理员在「申请与审批」批准；申请本身不授予访问权限。
3. 审批后创建凭据，完成密码及已启用的 2FA 验证。完整密钥仅显示一次，存入调用方的秘密管理系统。
4. 管理员启用平台后，先调用 `/me`、`/me/scopes`、`/me/quotas`、`/capabilities`，确认实际授权，再测试业务接口。

```bash
export NM_API_BASE='https://mapping.example.com/open-api/v1'
# NM_API_KEY 从秘密管理系统注入；不要写进源码、URL、工单或日志。
curl --fail-with-body "$NM_API_BASE/me" \
  -H "Authorization: Bearer $NM_API_KEY"
curl --fail-with-body "$NM_API_BASE/assets/search" \
  -H "Authorization: Bearer $NM_API_KEY" -H 'Content-Type: application/json' \
  --data '{"query":"ip IN 192.0.2.0/24 AND port = 443","page_size":50,"fields":["ip","port","service"]}'
```

服务器只接受 `Authorization: Bearer nm_api_<uuid>.<secret>`，不接受网页登录 Cookie、扫描器密钥、URL 中的 token 或管理员会话替代外部凭据。外部调用无需 CSRF token；管理 API 仍使用现有会话与 CSRF。

## 授权和数据范围

有效权限是应用批准的 scopes 与当前凭据 scopes 的交集；同时应用和凭据的来源 IP 白名单均须通过。每次调用都检查平台开关、应用状态与有效期、密钥有效期及撤销状态，以及责任用户是否可登录。

`data_mode=owner` 读取责任用户拥有的资产与任务；`application` 仅读取该应用提交扫描产生的数据。合作方应用不会自动获得全局资产。当前不支持任意跨用户数据集共享，也不提供 OAuth 用户授权流程。

批准的 CIDR、排除 CIDR、域名、时间范围、字段和标签 ID 进一步限制数据。读数据时空 CIDR/域名列表表示不额外限制已选数据来源；提交扫描时必须显式批准目标 CIDR 或域名。排除范围优先，包含任何排除网段的扫描任务整体拒绝。域名按完整标签匹配批准域及其子域，国际化域名使用 punycode。

策略变更会提升 `policy_revision`：旧游标、旧授权生成的文件和待执行扫描失效；修改应用名称与用途只提升编辑版本 `revision`。撤销密钥后新的调用立即拒绝，后台扫描、生成任务和回调在调度/处理时重新检查授权。已在网络中执行的请求或扫描通过现有超时和取消协议收敛，撤销不能收回已经交付的数据。

不开放用户创建/修改/删除、密码/2FA、扫描器注册/密钥/命令、系统设置、数据库/ES 管理、备份、升级、内部全局报告和邮件配置。注释、保存查询、导出文件和 Webhook 是应用自己的资源。

## 请求和响应约定

JSON 请求体最多 128 KiB；接口只接受规定字段。除文件下载外，成功响应如下，创建扫描、导出、报告和任务重试返回 HTTP 202，其他成功返回 200。

```json
{"data":{"items":[],"next_cursor":null},"request_id":"68a3e0d6-37ae-4f38-b8d7-13aee33b22ef"}
```

```json
{"error":{"code":"scope_denied","message":"未授权此操作"},"request_id":"68a3e0d6-37ae-4f38-b8d7-13aee33b22ef"}
```

保留 `request_id` 供管理端排查。响应不缓存。文件下载直接返回 JSON/CSV/JSONL 字节、正确 Content-Type 及 `Content-Disposition: attachment`，没有 `data` 包装，`X-Content-SHA256` 是本次文件字节的 SHA-256。

| HTTP | 处理建议 |
| --- | --- |
| 401 | 检查凭据、应用、责任用户及平台开关；不无限重试 |
| 403 | 功能、字段、目标或来源未批准；请求授权调整 |
| 404 | 资源不存在或不可见；不能据此探测其他应用资源 |
| 409 | 幂等内容冲突、策略/配置变更、文件需重建 |
| 413 / 422 | 缩小请求，修正参数、范围或计算预算 |
| 429 | 共享配额或统计并发耗尽；遵循 Retry-After，并加随机退避 |
| 503 | 维护或依赖不可用；遵循 Retry-After；创建请求重用幂等键 |

创建扫描、刷新、任务重试、导出和报告必须提供 `Idempotency-Key`，1–128 个可见 ASCII 字符。同一应用、同一操作下保存 24 小时；相同 JSON 对象重放返回同一结果，内容变更返回 409。重放仍需要当前有效授权，并消耗通用请求额度。键不要用于不同业务请求。

输入时间推荐 RFC 3339，例如 `2026-10-01T00:00:00+08:00`，兼容 UTC 毫秒整数。时间窗口为 `[start_at,end_at)`；查询窗口与策略窗口取交集。扫描/执行的 `created_at/started_at/ended_at` 和资产投影时间沿用现有毫秒值，管理资源及事件时间为 RFC 3339；不要将所有数值时间当作秒。统计按服务业务时区分组，从 `/catalog/statistics` 获取时区。

## 分页

资产、观察、漏洞和任务列表使用 `page_size`（1–100，默认 50）和 `cursor`。`next_cursor` 非空时，用相同查询、相同字段、相同页大小及同一凭据继续请求；游标 10 分钟有效，绑定应用和授权版本，不传递内部 ES sort/PIT。

当前资产是实时投影分页，扫描数据变化时不保证多页快照一致性。筛选后的页面可以为空而仍有下一页，尤其是漏洞分类与范围化任务列表；只有 `next_cursor=null` 才表示结束。批量 IP 查询同样需要跟随游标。DNS 批量查询每个域名的子结果有独立游标，通过单域名接口继续读取。

事件使用 `after` 整数和 `page_size`；下一次请求传回 `next_after`。即使该页没有可见事件也推进 `next_after`，避免重复读取不再授权的事件。

执行、子任务、导出/报告、保存查询、Webhook 及投递列表目前最多返回 100 项，没有完整历史分页；管理应用/审批最多 200 项，管理日志和审计支持 `after` 翻页。这些上限不代表资源总数。

## 资产、观察、DNS、漏洞与标签

资产搜索 POST body 支持 `query,page_size,cursor,fields,start_at,end_at`。DSL 参见 `docs/SEARCH_SYNTAX.md`；只能查询批准字段，标签 ID 只能来自批准目录，域名解析条件还需 `dns:read`。先用 `/assets/search/validate` 校验语法。资产搜索时间筛选 `last_seen`。

批量 IP 查询：`{"ips":["192.0.2.1"],"fields":["ip","port"],"page_size":50}`，每次 1–100 个 IP。`services` 与 `tls` 接口仅返回相关的已授权字段；资产标签合并当前页端点上获批的标签，继续分页可取得其他端点的标签。字段未被批准时不会提供值，也不能通过搜索推断该字段。

资产是「观察到开放的端点」。没有返回一个端口不能断言它关闭。`first_seen/last_seen` 是保留数据中的时间，服务信息可晚于端口观察到达。

观察 GET 查询接受 `page_size,cursor,start_at,end_at,task_id,execution_id`。不接受当前资产 DSL 或 `fields`；输出始终由批准字段投影，并附 kind、观察时间及任务/执行 ID。观察只来自责任用户/当前应用的成功执行，不包含内部扫描器身份和原始响应正文。

DNS 批量 body 为 `{"domains":["api.example.com"]}`，每次最多 20 个域名。DNS 从批准范围内成功执行的原始观察读取，不使用共享的全局 DNS 当前记录库。记录/地址/关联域名由当前观察页导出，展示 resolver ID/显示名称及延时，不输出解析器 IP、节点和内部状态；IP 记录也经过 CIDR 与排除过滤。关联域名为当前页的直接记录引用，不做主动枚举或完整 CNAME 递归。查不到记录不等于失效。

漏洞 POST body 接受观察条件，另支持 `severity=info|low|medium|high|critical`、`template_id`。查询和摘要描述扫描器观察，不推断已验证或已修复。因为现有 ES 的原始 `data` 不建立索引，严重程度/模板在授权分页后筛选，可能返回空页与非空游标。摘要计算最多检查 10,000 条观察，超出预算返回错误，绝不把截断当完整结果。`finding_id` 是不透明定位符，每次详情查询重新核验归属。额外 `vulnerabilities:evidence` 才返回 matcher、匹配位置和提取结果。

标签目录只返回管理员批准的标签 ID。资产注释 PUT 为 `{"value":"生产环境"}`，key 仅允许字母/数字/下划线/短横线、最长 64，value 1–2048 字，每应用每 IP 最多 100 项；注释不修改全局标签。保存查询 POST/PATCH 为 `{"name":"HTTPS","query":"port = 443"}`，PATCH 另带 `expected_revision`；每应用最多 100 条，所有查询仍按调用时授权执行。

## 扫描任务

```bash
curl --fail-with-body "$NM_API_BASE/tasks" \
  -H "Authorization: Bearer $NM_API_KEY" -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: inventory-2026-10-14-001' \
  --data '{"targets":["192.0.2.1"],"ports":"80,443","scan_profile":"service_inventory","client_reference":"inventory-001"}'
```

输入包含 `targets` 或 `domains`（互斥），以及 `ports,scan_profile,remark,client_reference`。支持 port_only、service_inventory、vulnerability_scan、dns_records，必须在批准 profiles 中。IPv4/IPv6 不混用；CIDR 展开数量与端口总数计入限额。`dns_records` 只接受域名且不接受端口；其他域名扫描先执行 DNS，解析后仅在批准的 IP/CIDR 内创建后续任务。超过地址预算会阻止后续生成，不部分放行越界地址。DNS 后续任务同样计入应用任务分钟/每日与并发配额，无法容纳整批子任务时不生成该批任务。

`/tasks/validate` 和 `/estimate` 不下发扫描；估算输出地址数与端口探测数，不承诺时长或域名将解析出的地址数量。`/assets/{ip}/refresh` 由服务器固定目标为路径 IP，另需 `tasks:create`。

通过任务/执行接口区分执行状态和 `projection_status`。执行完成但投影 pending 时，当前资产查询可能尚未更新；使用 `asset.ready` 事件或继续轮询。取消和重试只能操作该应用提交的任务，不能操作责任用户通过其他入口创建的任务。重试还需要 `tasks:create`，并按当前策略重新验证目标。

## 统计与归档报告

统计目录给出 data_type、group_by 与 metrics 合法组合：discovery（day/week/month/scanner/task_source）、port（port）、service（service）、tasks（day/week/month/task_source）、scanners（scanner/day/week/month）。统计的 scanner 是应用内稳定化标识，不暴露节点身份。

```json
{"data_type":"discovery","group_by":"day","metrics":["count"],"start_at":"2026-10-01T00:00:00Z","end_at":"2026-10-08T00:00:00Z","comparison":"previous"}
```

范围默认近 30 天、最多 366 天，统计与内部平台共用两槽集群计算预算；接口不使用内部全局统计缓存。discovery 每组去重 IP，总数直接全局去重，不能累加分组；port/service 按执行、IP、端点计数；任务的 created 和终态 completed 按各自发生时间计算，scanners 按执行计算。结果基于实际保留的历史。超过 50,000 composite buckets、10,000 任务/授权执行集合或时间预算会失败，不给近似成功结果。

`/analytics/statistics/details` 接受 data_type/group_by、时间、游标、页大小；category 仅用于 port/service 明细。任务/执行明细不接受 category。周期对比支持前一等长周期。分布/发现趋势快捷接口使用相同范围与统计口径。

报告 POST body 只接受 `start_at,end_at,format`，时间区间必须已结束、最长 366 天，另需 `analytics:read`。后台捕获批准的成功执行集合，计算发现趋势、端口和服务分布，归档 policy_revision、业务时区、输入任务/执行 ID、captured_at、质量说明及 schema_version；不读取平台的全局报告。报告不能证明 ES 保留历史完整，也不推断关闭端口或漏洞修复。

`/reports/{id}/data` 返回 `{payload,artifact_checksum}`。checksum 是创建时所选格式文件的 SHA-256；切换下载格式时字节不同，不能用它校验新格式，使用下载响应的 X-Content-SHA256。文件格式支持 json/jsonl/csv，报告 CSV 为 section/data 行。报告授权版本变化后需要重建。

## 异步导出

导出 POST 支持 `query,fields,start_at,end_at,format`，另需 `assets:read`。轮询 `/exports/{id}`，succeeded 后 GET `/download`；失败仅给公开原因码。每应用最多两个排队/运行生成任务，默认每日 10 次（导出和报告共用），默认 10,000 行，配置上限 50,000 行，文件硬上限 8 MiB，超过预算明确失败，绝不静默截断。

导出读取实时资产投影，元数据包含 captured_at、consistency 和 row_count；不保证扫描变化期间跨页快照一致。生成文件保存 PostgreSQL，保留 7 天，下载时核验当前应用授权及版本。DELETE 删除生成物和归档结果，不删除资产/扫描数据；取消只能取消排队或运行的生成任务。CSV 对公式前缀进行转义。

## 事件和 Webhook

事件类型：task.succeeded/failed/partial/cancelled、asset.ready、export.succeeded/failed、report.succeeded/failed、webhook.test。事件仅属于当前应用，读取和投递时再次检查关联任务/生成任务是否仍可见。订阅除 `webhooks:manage` 外，还需 `events:read` 及各事件对应的 tasks/assets/exports/reports 读取权限。

创建/PATCH body：`{"url":"https://hooks.example.com/network-events","event_types":["task.succeeded"],"enabled":true}`。PATCH 提供完整 URL 与事件列表。签名密钥创建时一次显示，数据库加密保存。订阅绑定创建凭据，撤销该凭据会停止投递；通过新凭据创建替代订阅。

仅允许管理员批准的精确域名、HTTPS 443。每次投递重新解析 DNS，所有地址均须为允许的公网地址；禁止用户信息、URL 片段、重定向及内网/回环/链路本地/保留地址。代理环境的出口控制要求见管理文档。

接收 JSON 为 `{id,type,resource_id,payload,occurred_at,version}`。请求头 `NM-Event-ID`、`NM-Event-Timestamp`（Unix 秒）、`NM-Event-Signature: v1=<hex>`。签名为 `HMAC-SHA256(signing_secret, timestamp + "." + 原始请求体字节)`。

```python
import hashlib, hmac, time

def verify(raw_body: bytes, headers, signing_secret: str):
    stamp = headers['NM-Event-Timestamp']
    if abs(time.time() - int(stamp)) > 300:
        return False
    expected = 'v1=' + hmac.new(signing_secret.encode(),
        stamp.encode() + b'.' + raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, headers['NM-Event-Signature'])
```

验证原始字节后，用事件 ID 去重，持久入队后尽快返回 2xx。交付至少一次，可能重复，不保证顺序。单次接收请求超时 10 秒，整体尝试 20 秒，最多 5 次，指数退避；通过投递详情查看状态并对 failed 执行手动 retry。Webhook 测试也进入持久队列，不直接向任意目标发送请求。任务与投影事件通过后台状态对账持久化，生成任务的事件与结果在同一事务写入。

## 默认配额

| 项目 | 默认值 |
| --- | ---: |
| 应用通用请求 / 分钟、UTC 日 | 120、10,000 |
| 高级资产搜索 / 分钟 | 30 |
| 统计 / 分钟 | 12 |
| 新扫描 / 分钟、UTC 日 | 6、50 |
| 任务目标地址、端口、排队与运行任务 | 4,096、100、5 |
| 生成任务 / UTC 日、导出最大行数 | 10、10,000 |
| Webhook 数量 | 5 |

同一应用全部密钥共享 PostgreSQL 原子计数，额外匿名入口每进程每源 IP 每分钟最多 600 次。可通过 `/me/usage` 查看桶计数，通过申请修改配额；额度变更只能由管理员批准。沙箱是禁止真实扫描的逻辑环境，读取已获批的实际数据，不自动生成演示数据。

## 全部接口目录

基础权限如下。导出额外需要 assets:read，报告额外需要 analytics:read，刷新与任务重试额外需要 tasks:create；Webhook 事件还需对应读取权限，查询字段和数据范围均受策略限制。机器可读参数和示例类型以 `docs/open-api/openapi.json` 为准。

| 方法 | 路径（省略 /open-api/v1） | 基础 scope | 功能 |
| --- | --- | --- | --- |
| GET | `/capabilities` | `metadata:read` | 当前凭据可用的接口 |
| GET | `/me` | `metadata:read` | 当前应用身份 |
| GET | `/me/scopes` | `metadata:read` | 有效权限和字段 |
| GET | `/me/quotas` | `metadata:read` | 应用配额 |
| GET | `/me/usage` | `metadata:read` | 自身用量 |
| GET | `/service-status` | `metadata:read` | 服务可用状态 |
| GET | `/catalog/search-fields` | `metadata:read` | 搜索字段 |
| GET | `/catalog/scan-profiles` | `metadata:read` | 批准的扫描模式 |
| GET | `/catalog/dns-resolvers` | `metadata:read` | 批准的解析器目录 |
| GET | `/catalog/statistics` | `metadata:read` | 统计目录 |
| POST | `/assets/search` | `assets:read` | 高级资产搜索 |
| POST | `/assets/search/validate` | `assets:read` | 搜索语法校验 |
| GET | `/assets/{ip}` | `assets:read` | 资产摘要 |
| POST | `/assets/lookup` | `assets:read` | 批量资产查询 |
| GET | `/assets/{ip}/ports` | `assets:read` | 当前端口 |
| GET | `/assets/{ip}/ports/{port}/history` | `observations:read` | 端口观察历史 |
| GET | `/assets/{ip}/services` | `assets:read` | 服务信息 |
| GET | `/assets/{ip}/tls` | `assets:read` | TLS 信息 |
| GET | `/assets/{ip}/tags` | `tags:read` | 授权资产标签 |
| GET | `/assets/{ip}/observations` | `observations:read` | 资产观察 |
| POST | `/assets/{ip}/refresh` | `assets:refresh` | 提交刷新扫描 |
| GET | `/domains/{domain}` | `dns:read` | 域名摘要 |
| GET | `/domains/{domain}/records` | `dns:read` | 成功执行中的 DNS 记录 |
| GET | `/domains/{domain}/observations` | `dns:read` | DNS 观察 |
| GET | `/domains/{domain}/addresses` | `dns:read` | 域名关联地址 |
| GET | `/domains/{domain}/related-domains` | `dns:read` | 观察中的关联域名 |
| POST | `/domains/lookup` | `dns:read` | 批量域名查询 |
| POST | `/vulnerabilities/search` | `vulnerabilities:read` | 漏洞观察查询 |
| GET | `/vulnerabilities/{finding_id}` | `vulnerabilities:read` | 漏洞观察详情 |
| GET | `/assets/{ip}/vulnerabilities` | `vulnerabilities:read` | 资产漏洞观察 |
| GET | `/tasks/{task_id}/vulnerabilities` | `vulnerabilities:read` | 任务漏洞观察 |
| POST | `/vulnerabilities/summary` | `vulnerabilities:read` | 漏洞观察摘要 |
| GET | `/tags` | `tags:read` | 批准的标签目录 |
| GET | `/tag-categories` | `tags:read` | 批准的标签分类 |
| GET | `/assets/{ip}/annotations` | `annotations:read` | 应用私有注释 |
| PUT | `/assets/{ip}/annotations/{key}` | `annotations:write` | 保存应用注释 |
| DELETE | `/assets/{ip}/annotations/{key}` | `annotations:write` | 删除应用注释 |
| GET | `/tasks` | `tasks:read` | 授权任务列表 |
| GET | `/tasks/{task_id}` | `tasks:read` | 任务详情 |
| GET | `/tasks/{task_id}/executions` | `tasks:read` | 执行列表 |
| GET | `/tasks/{task_id}/executions/{execution_id}` | `tasks:read` | 执行详情 |
| GET | `/tasks/{task_id}/results` | `tasks:read` | 执行结果 |
| GET | `/tasks/{task_id}/dns-comparison` | `dns:read` | 任务 DNS 对比 |
| GET | `/tasks/{task_id}/children` | `tasks:read` | DNS 子任务 |
| POST | `/tasks/validate` | `tasks:create` | 校验目标和扫描模式 |
| POST | `/tasks/estimate` | `tasks:create` | 预估扫描工作量 |
| POST | `/tasks` | `tasks:create` | 创建受控扫描 |
| POST | `/tasks/{task_id}/cancel` | `tasks:cancel` | 取消应用任务 |
| POST | `/tasks/{task_id}/retry` | `tasks:retry` | 重试应用任务 |
| GET | `/analytics/overview` | `analytics:read` | 范围内概览 |
| POST | `/analytics/distribution` | `analytics:read` | 端口和服务分布 |
| POST | `/analytics/discovery-series` | `analytics:read` | 发现趋势 |
| POST | `/analytics/statistics/query` | `analytics:read` | 统计查询 |
| POST | `/analytics/statistics/details` | `analytics:read` | 统计明细 |
| GET | `/reports` | `reports:read` | 应用报告列表 |
| GET | `/reports/{report_id}` | `reports:read` | 报告详情 |
| GET | `/reports/{report_id}/data` | `reports:read` | 归档报告数据 |
| POST | `/reports` | `reports:create` | 生成范围化报告 |
| GET | `/reports/{report_id}/artifacts/{format}` | `reports:read` | 报告文件 |
| POST | `/exports` | `exports:create` | 创建异步导出 |
| GET | `/exports` | `exports:read` | 导出列表 |
| GET | `/exports/{export_id}` | `exports:read` | 导出状态 |
| POST | `/exports/{export_id}/cancel` | `exports:create` | 取消导出 |
| GET | `/exports/{export_id}/download` | `exports:read` | 读取生成文件 |
| DELETE | `/exports/{export_id}` | `exports:create` | 删除生成文件 |
| GET | `/events` | `events:read` | 游标拉取自身事件 |
| GET | `/webhooks` | `webhooks:manage` | 订阅列表 |
| POST | `/webhooks` | `webhooks:manage` | 创建签名订阅 |
| GET | `/webhooks/{webhook_id}` | `webhooks:manage` | 订阅详情 |
| PATCH | `/webhooks/{webhook_id}` | `webhooks:manage` | 修改订阅 |
| DELETE | `/webhooks/{webhook_id}` | `webhooks:manage` | 停用订阅 |
| POST | `/webhooks/{webhook_id}/test` | `webhooks:manage` | 测试订阅 |
| GET | `/webhooks/{webhook_id}/deliveries` | `webhooks:manage` | 投递列表 |
| GET | `/webhook-deliveries/{delivery_id}` | `webhooks:manage` | 投递详情 |
| POST | `/webhook-deliveries/{delivery_id}/retry` | `webhooks:manage` | 重试投递 |
| GET | `/saved-searches` | `saved_searches:manage` | 保存的查询列表 |
| POST | `/saved-searches` | `saved_searches:manage` | 保存查询 |
| GET | `/saved-searches/{search_id}` | `saved_searches:manage` | 读取保存的查询 |
| PATCH | `/saved-searches/{search_id}` | `saved_searches:manage` | 修改保存的查询 |
| DELETE | `/saved-searches/{search_id}` | `saved_searches:manage` | 删除保存的查询 |

## 操作系统摘要

应用字段白名单批准 `os` 后，资产查询和服务查询可以返回系统摘要，并允许 `os.family`、
`os.distribution`、`os.version`、`os.confidence`、`os.status`、`os.score` 条件。
返回对象不包含原始证据、观察索引引用和候选明细。没有批准 `os` 的既有应用保持原权限。
置信度、未知和过期语义见[操作系统识别](OS_DETECTION.md)。
