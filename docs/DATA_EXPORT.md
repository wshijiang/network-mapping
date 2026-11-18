# 数据管理 · 后台导出（搜索语句 → CSV）

[文档中心](README.md)

用户可通过 Web 管理端或服务器 CLI，把**搜索语句匹配的资产端点数据**交给后台导出：服务器 worker 执行查询、流式写入 CSV 文件并存放于服务器导出目录，Web 端下载文件。导出与资产搜索使用同一 DSL、同一数据范围规则，适合大批量结果离线分析。

- Web 入口：侧边栏「**数据管理 → 导出**」（`/data/export`）；搜索页结果区「**导出**」按钮（可选本页/全部、调整字段）。
- CLI 入口：`network_mapping_server export …`（与 `import` 同级）。**CLI 仅创建/查看/取消任务，文件下载仅 Web 提供。**
- 设计稿见工作区 `DATA_EXPORT_PLAN.md`。

## 架构与口径

- **单一执行者**：Web 与 CLI 都只在 PostgreSQL 创建任务（`data_export_task`），由服务器进程内的导出 worker 认领执行（租约模式，与数据导入一致）。服务器离线时任务保持待执行，启动后自动继续；租约过期的运行中任务从头重跑（导出只读、幂等）。
- **与搜索同口径**：同一搜索 DSL（`parse_and_compile_elasticsearch`）、同一排序定义。创建任务时**快照数据范围**（管理员 `global`，普通用户 `user` 级），后台执行期间角色变化不影响结果口径。
- **只读本地索引**：导出查询 `current_endpoint` 索引，**不触发联测**。联测完成的数据本就自动入库，会被后续导出自然覆盖；搜索页展示态中尚未入库的联测端点不在导出范围内。匹配条数以本地索引 count 为准（`POST /api/data-export/preview`），与搜索页 total（可能含联测合并新增）可能有差异。
- **突破 10k 浏览窗口**：搜索页分页受 `offset + limit ≤ 10000` 限制；「全部」导出使用 Elasticsearch **PIT + search_after** 分批遍历（排序含 `endpoint_key` tie-breaker，全序稳定），不受该窗口限制，行数上限由 `max_rows` 约束。PIT id 若被 ES 轮换，逐批跟随最新 id 并在结束时清理。
- **拒绝不完整结果**：「本页」与「全部」导出均校验 ES 响应的 `timed_out` 与失败分片（`allow_partial_search_results=false` + 响应校验），不完整响应直接使任务失败，不会写出半份 CSV 后标记完成。
- **流式写入**：逐批拉取、逐行追加写文件，内存占用与结果规模无关；边写边累计 SHA-256 与文件大小。

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
| GET | `/api/data-export/tasks/{id}/download` | 仅 `completed`；流式下载 CSV（`Content-Disposition` 附件） |
| POST | `/api/data-export/tasks/{id}/cancel` | `pending`/`running` → `cancelled`（worker 批间检查生效） |
| DELETE | `/api/data-export/tasks/{id}` | 仅终态任务；删除记录与文件 |

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

`--wait` 阻塞轮询直至终态并打印进度。CLI 创建的任务匹配条数由 worker 首批统计（创建时不做 ES 预览），超 `max_rows` 时任务失败并给出中文原因。

## 配置

```toml
[data_export]
enabled = true
directory = "./data-export"   # CSV 存放目录；相对路径相对配置文件目录解析
max_rows = 1000000            # 单任务「全部」导出行数上限
batch_size = 2000             # ES 每批拉取行数（1..=10000）
lease_seconds = 120           # worker 租约（≥10）
retention_days = 30           # 终态任务文件与记录保留天数
```

未配置时使用上述默认值，升级零行为变化。部署时导出目录需持久化（Docker 卷）；worker 定期清理超过保留期的终态任务文件与记录。系统维护模式期间不认领新任务。

## 安全与限制

- 所有权隔离 + 创建时范围快照；下载路径只来自数据库记录，文件名服务端生成。
- 审计事件：`data_export.create/cancel/delete/download`（Web）与 `cli.create/cli.cancel`（CLI）。
- 单 worker 顺序执行；`max_rows` 与批间租约续期约束资源占用；PIT 在任务结束/失败时关闭。
- 失败任务不留半成品文件；取消竞态由完成登记的条件更新兜底（登记失败即删除文件）。
- 导出为只读操作，不修改资产数据；情报标注列暂未纳入字段目录（后续迭代）。