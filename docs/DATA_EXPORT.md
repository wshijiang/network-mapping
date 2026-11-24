# 数据管理 · 后台导出（搜索语句 → CSV）

[文档中心](README.md)

用户可通过 Web 管理端或服务器 CLI，把**搜索语句匹配的资产端点数据**交给后台导出：服务器 worker 执行查询、流式写入 CSV 文件并保存至服务器本地、S3 兼容对象存储或两个位置，Web 端可选下载来源。导出与资产搜索使用同一 DSL、同一数据范围规则，适合大批量结果离线分析。

- Web 入口：侧边栏「**数据管理 → 导出**」（`/data/export`）；搜索页结果区「**导出**」按钮（可选本页/全部、调整字段）。
- CLI 入口：`network_mapping_server export …`（与 `import` 同级）。**CLI 仅创建/查看/取消任务，文件下载仅 Web 提供。**

## 架构与口径

- **后台执行**：Web 与 CLI 都只在 PostgreSQL 创建任务（`data_export_task`），由服务器进程内的导出 worker 认领执行（租约模式，与数据导入一致）。服务器离线时任务保持待执行，启动后自动继续；租约过期的运行中任务从头重跑（导出只读、幂等）。
- **与搜索同口径**：同一搜索 DSL（`parse_and_compile_elasticsearch`）、同一排序定义。创建任务时**快照数据范围**（管理员 `global`，普通用户 `user` 级），后台执行期间角色变化不影响结果口径。
- **只读本地索引**：导出查询 `current_endpoint` 索引，**不触发联测**。联测完成的数据本就自动入库，会被后续导出自然覆盖；搜索页展示态中尚未入库的联测端点不在导出范围内。匹配条数以本地索引 count 为准（`POST /api/data-export/preview`），与搜索页 total（可能含联测合并新增）可能有差异。
- **突破 10k 浏览窗口**：搜索页分页受 `offset + limit ≤ 10000` 限制；「全部」导出使用 Elasticsearch **PIT + search_after** 分批遍历（排序含 `endpoint_key` tie-breaker，全序稳定），不受该窗口限制，行数上限由 `max_rows` 约束。PIT id 若被 ES 轮换，逐批跟随最新 id 并在结束时清理。
- **拒绝不完整结果**：「本页」与「全部」导出均校验 ES 响应的 `timed_out` 与失败分片（`allow_partial_search_results=false` + 响应校验），不完整响应直接使任务失败，不会写出半份 CSV 后标记完成。
- **流式写入**：逐批拉取、缓冲写入文件，内存占用与结果规模无关；边写边累计 SHA-256 与文件大小。

## 导出范围与字段

创建任务时选择：

| 范围 | 说明 |
|---|---|
| `page`（本页） | 导出当前分页窗口（`offset`/`limit`，`offset + limit ≤ 10000`），与搜索页所见一致 |
| `all`（全部） | 导出语句匹配的全部端点；创建时按预览 count 校验 `max_rows`，worker 首批兜底校验 |

字段目录由 `GET /api/data-export/schema` 下发（单一事实来源，Web modal 与 CLI 共用），列顺序与标签对齐搜索页原「导出当前页 CSV」表头：基础（IP/端口/协议/服务/Banner/网页标题/扫描时间/标签/数据来源）、系统（8 列 OS 推断）、技术栈（5 列 Web 推断）、TLS（11 列证书信息）、归属（ASN/AS 组织、位置）。默认全选；可任意勾选子集（至少 1 个），列顺序按目录固定。

CSV 格式：UTF-8 带 BOM、CRLF 行尾、RFC4180 引号；单元格公式注入防护（`= + - @` 或制表符/换行开头前置 `'`），与前端既有导出规则一致。时间列按系统时区设置（「设置 → 常规」）格式化为 `YYYY-MM-DD HH:mm:ss`。「数据来源」列恒为「本地」（见上文口径）。

## HTTP API

所有接口要求有效登录 Session 与 CSRF Token。任务按所有权隔离：普通用户仅可见/操作本人任务，管理员可见全部。写操作与下载记审计（category `data_export`）。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/data-export/schema` | 字段目录 + 默认字段 + 限制（`max_rows`、`retention_days`） |
| POST | `/api/data-export/preview` | `{query}` → `{matched_total}`（本地索引 count）；语法错误返回与搜索同构的 `422 {code, message, span}` |
| POST | `/api/data-export/tasks` | 创建任务，见下方请求体 |
| GET | `/api/data-export/tasks` | `?limit&offset&status`；普通用户仅本人，管理员全部 |
| GET | `/api/data-export/tasks/{id}` | 详情（含进度 `exported_rows`/`matched_total`） |
| GET | `/api/data-export/tasks/{id}/download` | 仅 `completed`；可选 `?source=local\|s3`，默认本地优先 |
| GET | `/api/data-export/tasks/{id}/download-link` | 验证指定副本并返回下载 URL；S3 直连链接有效期 60 秒 |
| GET / PUT | `/api/data-export/settings` | 管理员查看或更新全局导出设置；更新时提交 `expected_revision` 和 `document` |
| GET / PUT | `/api/data-export/settings/s3` | 管理员查看或保存 S3 连接；提交 `expected_revision` 和 `connection`，传 `null` 恢复部署默认连接 |
| POST | `/api/data-export/settings/test-s3` | 管理员验证测试对象的写入、读取和删除 |
| POST | `/api/data-export/tasks/{id}/cancel` | `pending`/`running` → `cancelled`（worker 批间检查生效） |
| DELETE | `/api/data-export/tasks/{id}` | 仅终态任务；删除任务后由后台清理副本 |

创建请求体：

```json
{
  "query": "country = CN AND port = 443",
  "scope": "all",
  "offset": 0,
  "limit": 50,
  "sort_field": "last_seen",
  "sort_order": "desc",
  "fields": ["ip", "port", "service", "title", "scan_time"]
}
```

`scope` 缺省 `all`；`fields` 缺省全部字段；`offset`/`limit` 仅 `scope=page` 有效。状态机：`pending → running → completed | error | cancelled`。响应不回显服务器文件路径（路径仅 CLI `status` 可见）。

## CLI

仅需 PostgreSQL；任务由运行中的服务器执行。

```bash
# 创建（管理员身份用于授权与审计）
network_mapping_server export create --admin admin \
  --query 'country = CN AND port = 443' --fields ip,port,service,title --wait

# 本页窗口导出
network_mapping_server export create --admin admin --query 'port = 80' \
  --scope page --offset 0 --limit 50

# 查看（CLI 不提供下载）
network_mapping_server export list [--status running] [--owner alice] [--json]
network_mapping_server export status <task-id> [--json]

# 取消
network_mapping_server export cancel <task-id> --admin admin
```

导出设置和 S3 连接也可以通过 CLI 管理，所有管理子命令都需要 `--admin`。

```bash
network_mapping_server export settings show --admin admin
network_mapping_server export settings set --admin admin --local true --s3 true --batch-size 2000 --workers 2 --upload-concurrency 4

network_mapping_server export s3 show --admin admin
network_mapping_server export s3 set --admin admin --region us-east-1 --bucket network-mapping-exports \
  --endpoint https://s3.example.invalid --prefix exports --path-style \
  --proxy-url http://proxy.example.invalid:8080
network_mapping_server export s3 test --admin admin
network_mapping_server export s3 reset --admin admin
```

`settings set` 只更新传入的字段。`s3 set` 保存整套连接，可选 `--download-endpoint` 或 `--proxy-download`。配置可以先保存并测试，再通过 `settings set --s3 true` 启用。没有部署默认连接时，先取消 S3 保存位置，再执行 `s3 reset`。

`--wait` 阻塞轮询直至终态并打印进度。CLI 创建的任务匹配条数由 worker 首批统计（创建时不做 ES 预览），超 `max_rows` 时任务失败并给出中文原因。

## 配置

```toml
[data_export]
enabled = true
directory = "./data-export"   # CSV 存放目录；相对路径相对配置文件目录解析
max_rows = 1000000            # 单任务「全部」导出行数上限
batch_size = 2000             # 首次初始化导出设置时使用的 ES 每批行数（1..=10000）
lease_seconds = 120           # worker 租约（≥10）
retention_days = 30           # 终态任务文件与记录保留天数
```

首次部署默认只保存到服务器本地。管理员可在「数据管理 → 导出 → 导出设置」勾选一个或两个位置，调整每批读取行数、每个服务进程同时执行的任务数（默认 1，范围 1–4）和每任务的 S3 分片上传并发数（默认 2，范围 1–8）。保存位置、批大小和上传并发会随新任务快照。历史任务按创建时的副本位置下载。

在 Web「导出设置 → 管理 S3 连接」或 CLI 中保存并测试连接，然后勾选 S3 保存位置。两处修改共用数据库配置，保存后无需重启。也可以通过 `[data_export.s3]` 提供部署默认连接，以下示例适用于使用路径式地址的兼容产品。

```toml
[data_export.s3]
region = "us-east-1"
bucket = "network-mapping-exports"
prefix = "exports"
endpoint = "https://s3.example.invalid"
path_style = true
# download_endpoint = "https://download.example.invalid"
# proxy_download = true
# proxy_url = "http://proxy.example.invalid:8080"
```

AWS S3 通常可省略 `endpoint`，并使用默认的虚拟主机式地址。凭据由 AWS 凭据链提供，例如工作负载角色或服务进程的 `AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY` 和可选的 `AWS_SESSION_TOKEN`。存储桶应保持私有，凭据仅授权导出前缀下的对象读写、删除和分片中止。对启用了对象版本控制的桶，可在导出前缀设置生命周期，清理非当前版本和未完成的分片上传。

可配置 HTTP(S) 出站代理，地址不含用户信息。代理用于服务端的连接测试、上传、下载探测、服务端转发下载及清理。浏览器直连使用客户端自己的网络。

默认由浏览器通过短时签名直连对象存储。若上传地址无法从浏览器访问，可指定供应商配置的 HTTPS `download_endpoint`，或设 `proxy_download = true` 从服务器流式转发。既有对象仍使用原始地址和桶；迁移时需保持旧位置、代理和凭据可用，直至旧副本到期。

仅选 S3 时也需要可写的本地目录作为生成和上传的暂存区。多实例部署应让各实例在同一绝对路径访问共享导出目录。超过保留期或手动删除的任务由后台清理副本。系统维护模式期间不认领新任务。

## 安全与限制

- 所有权隔离 + 创建时范围快照；下载路径只来自数据库记录，文件名服务端生成。
- 审计事件：`data_export.create/cancel/delete/download`（Web）与 `cli.create/cli.cancel`（CLI）。
- 使用 `max_rows`、批大小和并发上限约束资源；PIT 在任务结束或失败时关闭。
- 双位置任务上传失败时保留已生成的本地副本，并在列表显示 S3 上传失败。仅选 S3 的任务在上传失败时标为失败。
- 通过独立的执行尝试记录追踪暂存文件和对象，任务取消、过期或重领后可重试清理。
- 导出为只读操作，不修改资产数据；情报标注列暂未纳入字段目录（后续迭代）。