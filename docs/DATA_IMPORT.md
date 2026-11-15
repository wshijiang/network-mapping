# 数据管理 · 外部导入（CSV 资产端点导入）

[文档中心](README.md)

管理员可通过 Web 管理端或服务器 CLI 上传/指定 CSV 文件，将**外部资产端点数据**（ip、port、protocol、service、banner、OS、Web 技术、网页标题、ASN/位置等）批量导入现有 Elasticsearch 资产库。导入观察复用扫描结果写入管道（`result_ingest`），导入完成后可在资产搜索/详情中直接查看，并自动参与投影、OS/Web 检测、分析与威胁情报标注。

- Web 入口：侧边栏「**数据管理 → 导入**」（`/data/import`，仅管理员）。
- CLI 入口：`network_mapping_server import …`（与 `intel import` 同级）。
- 设计稿见工作区 `DATA_IMPORT_PLAN.md`。

## 架构与复用

- **单一执行者**：Web 与 CLI 都只在 PostgreSQL 创建任务（`data_import_task`），由服务器进程内的导入 worker 唯一执行。CLI 创建任务后需服务器在线才会执行；服务器离线时任务保持待执行，启动后自动继续。
- **复用扫描管道**：每个导入任务物化为一条 `scan_task`（`task_source='import'`）+ `scan_task_execution`，以预留系统扫描器「数据导入」身份经 `save_scanner_results` 写入。PG 事实、各类 outbox、端点投影、分析快照、任务聚合全部由既有管道处理，**不另建资产表、不直写 current 索引**。
- 扫描任务列表默认排除 `task_source='import'`；扫描器管理列表排除预留扫描器。
- **幂等与续传**：ES 观察文档 `_id = sha256(execution_id + observation_key)` 且用 `create` 动作；批次台账（`data_import_batch`）记录行区间与状态，暂停/崩溃后从已连续提交水位续传，重放幂等。

## CSV 头部规范

必须头部：**`ip`、`port`、`protocol`、`observed_at`**。其余可选。后端经 `GET /api/data-import/schema` 暴露规范（含别名），Web 据此自动配对，CLI `import check` 共用同一份定义。

| 内部头部 | 必须 | 说明 |
|---|---|---|
| `ip` | ✅ | IPv4/IPv6；拒绝 CIDR/主机名与非单播地址（回环/组播/广播/未指定） |
| `port` | ✅ | 1–65535 |
| `protocol` | ✅ | `tcp` / `udp` |
| `observed_at` | ✅ | epoch 毫秒/秒（按量级判别）或 ISO8601（无时区按 UTC）；不得晚于当前时间+容差（默认 300s），且 >0 |
| `service` | ❌ | 服务名 ≤128 字符 |
| `banner` | ❌ | ≤64KB，剔除 NUL/控制字符 |
| `source` | ❌ | ≤64 字符，默认 `import` |
| `asn` | ❌ | `AS12345`/`12345`，归一化为纯数字；缺省由 MaxMind 补全 |
| `as_org` | ❌ | ≤256 字符；缺省由 MaxMind 补全 |
| `country_code` | ❌ | ISO 3166-1 alpha-2；缺省由 MaxMind 补全 |
| `country_name` / `region_name` / `city_name` | ❌ | ≤128 字符；缺省由 MaxMind 补全 |
| `latitude` / `longitude` | ❌ | ±90 / ±180；缺省由 MaxMind 补全 |
| `os` | ❌ | 操作系统家族（windows/linux/unix…）≤64；缺省由检测管道派生 |
| `os_confidence` | ❌ | `medium`/`high`，默认 `high`（须与 `os` 同时指定） |
| `tech` | ❌ | 分号分隔 `id[@version]`（如 `nginx@1.25.3;jquery@3.7.1`），≤64 项 |
| `title` | ❌ | 网页标题 ≤512 字符 |

格式：UTF-8（允许 BOM），逗号分隔，RFC4180 引号。未映射的多余列忽略；头部自动配对按归一化（trim+小写）精确或别名匹配，多列匹配同一内部头部判为冲突需手动指定。

### 富化与覆盖语义

- **ASN/位置**：CSV 指定值优先；未指定/未映射时按字段经 MaxMind（GeoLite2 ASN/City/Country）补全；MaxMind 未配置或无匹配则留空（不报错）。`isp` 不作 CSV 列，沿用从 `as_org` 派生。
- **OS/Web 技术/title**：CSV 指定值优先。`title` 经观察字段直通端点；`os`/`tech` 解析为预设推断对象（`inference_scope='csv_import'`），检测 worker 不覆盖 import 预设；未指定时由检测管道从证据派生。
- **覆盖策略**（任务级，Web 单选 / CLI `--overwrite`）：
  - `fill`（默认，不覆盖）：导入观察完整写入历史；对**扫描权威**端点（有服务证据且非 import 来源）仅补空字段，不替换服务证据、不推进时钟。**导入数据不直接作为最新结果。**
  - `overwrite`（覆盖本地）：参与现有「observed_at 新者胜」规则（仍受时间守卫，旧导入不覆盖新扫描）。
  - 两种策略均**保留既有标签**（tags 为用户元数据）。新端点（无扫描数据）由 import 创建当前态。
- **去重汇聚**：文件内完全重复行折叠（`duplicate_rows`）；同端点同时间不同内容判冲突，last-wins（`conflict_rows`）；同端点不同时间均保留为历史，当前态按端点身份 `ip|port|protocol` 汇聚，不产生重复资产。

## 任务状态与控制

状态：`pending`（未开始）→ `validating`（完整性校验）→ `type_checking`（类型检查）→ `importing`（导入中）→ `completed`（已完成）；`paused`（暂停）、`error`（错误）、`cancelled`（已取消）。

- **暂停/继续**：批次边界生效；继续时可调整 `batch_size`（1–50000）与 `concurrency`（1–8）。
- **取消**：批次边界停止，**已导入数据保留**（ES 跨批次无事务，不回滚）。
- **试运行**（`dry_run`）：只校验与去重统计，不写入。
- **快速模式**（`fast`）：校验合并进导入，单遍完成。
- **无效行策略**（`on_invalid`）：`skip`（默认，记录错误样本与计数）/ `abort`（首个无效行即终止）。
- 进度：`processed_rows/total_rows` + 导入/无效/重复/冲突计数；错误样本上限 1000，完整错误报告 CSV 可下载（含公式注入防护）。
- 崩溃恢复：租约过期后 worker 重新认领并从台账续传。

## 数据检查清单

- 结构级（致命）：UTF-8/BOM、空文件/仅头部、空列名/重复列名、必须头部映射缺失/冲突、列数≤128、行数/文件大小上限、引号转义。
- 字段级（行级）：必须字段非空、IP 单播、port 范围、protocol 枚举、时间未来容差、长度上限、经纬度范围、asn 数字、country_code 格式、os_confidence 枚举、tech 项数/字符集、文本卫生、跨字段一致性。
- 安全：错误报告 CSV 公式注入防护；ES strict mapping 仅允许已映射字段；上传文件名清理、UUID 存储防路径穿越。

## Web 上传

- 选择文件后前端仅 `File.slice(0, 64KB)` 只读头部（引号感知解析，不加载全文件），自动配对 + 手动映射必须头部，核对通过后点击「导入」才上传（multipart）。
- 上传流式写盘（不进内存），路由级限额 `data_import.max_upload_bytes`（默认 512MB），超限 413。
- 超大文件建议走 CLI（本地文件，无上传限制）。

## CLI

```bash
# 本地头部检查（无需数据库）；退出码 0=可直接导入，2=需要映射
network_mapping_server import check assets.csv [--json]

# 创建导入任务（由运行中的服务器执行）
network_mapping_server import run assets.csv --admin admin \
    [-m ip:主机地址 -m port:端口号 -m protocol:协议类型 -m observed_at:时间] \
    [--batch-size 1000] [--concurrency 2] [--on-invalid skip|abort] \
    [--overwrite] [--dry-run] [--fast] [--wait]

network_mapping_server import list [--status importing] [--json]
network_mapping_server import status <TASK_ID> [--json]
network_mapping_server import pause  <TASK_ID> --admin admin
network_mapping_server import resume <TASK_ID> --admin admin [--batch-size N] [--concurrency N]
network_mapping_server import cancel <TASK_ID> --admin admin
```

- `-m/--header-mapping internal:file`（可重复）：把文件头部映射为内部头部。clap 短选项为单字符，`-hm` 不可用，故用 `-m`（服务器 CLI 全局短选项仅 `-d`/`-v`，无冲突）。
- `--admin` 沿用 intel 先例：以有效管理员用户名做授权与审计归属。
- `run` 先执行与 `check` 相同的头部校验，必须头部齐全才创建任务。

## HTTP API（管理员，会话鉴权 + CSRF，写审计）

| 方法/路径 | 说明 |
|---|---|
| `GET /api/data-import/schema` | 头部规范 + 别名 + 限额 + 枚举 |
| `POST /api/data-import/tasks` | multipart：file + mapping(JSON) + batch_size/concurrency/on_invalid/overwrite_policy/fast/dry_run |
| `GET /api/data-import/tasks?status=&limit=&offset=` | 分页列表 |
| `GET /api/data-import/tasks/{id}` | 详情 + 进度 |
| `GET /api/data-import/tasks/{id}/errors` | 错误样本 |
| `GET /api/data-import/tasks/{id}/errors.csv` | 错误报告下载 |
| `POST /api/data-import/tasks/{id}/pause` \| `/cancel` | 暂停 / 取消 |
| `POST /api/data-import/tasks/{id}/resume` | 继续（body 可带 batch_size/concurrency） |
| `DELETE /api/data-import/tasks/{id}` | 删除记录与文件（仅终态；已导入数据保留） |

响应包装 `{success, data, message}`。multipart 布尔字段为字符串 `"true"/"false"`；mapping 值保留文件头部原文（后端按 trim+小写定位列）。

## 配置

```toml
[data_import]
enabled = true
directory = "./data-import"        # 受管文件目录（相对路径基于配置文件目录解析）
max_upload_bytes = 536870912       # 512MB，Web 上传限额
max_rows = 10_000_000
default_batch_size = 1000
max_batch_size = 50000
default_concurrency = 2
max_concurrency = 8
retention_days = 30                # 终态任务文件保留期
lease_seconds = 120
observed_at_future_tolerance_seconds = 300
dedup_window = 1_000_000           # 文件内去重窗口（内存）
```

## 并发说明

写任务为 IO 密集（PG 事务 + ES bulk），单解析器 → 有界 channel → 并发写任务（Semaphore）。受 ES typed 协议单批 ≤500 观察限制，`batch_size` 大于 500 时按 500 切分子批；吞吐主要由 `concurrency` 提升。有效并发建议不超过连接池的一半，给 API/投影留余量；ES 429 走既有重试退避。默认 2，上限 8。

## 部署注意

- 反向代理 `client_max_body_size` 需与 `max_upload_bytes` 同步放宽。
- 导入依赖 Elasticsearch 与运行中的服务器 worker；ES 未启用时导入任务会失败。
- 新增表：`data_import_task`、`data_import_batch`；预留扫描器行（`scanner_id=00000000-0000-7000-8000-00000000d1a0`）。升级自动迁移，零行为变化（默认启用但无任务）。

## 后续增强

分块/断点续传上传、非 UTF-8 编码探测、分隔符自动识别、与既有观察精确去重预检、按 execution 清除已导入数据、校验阶段并行分块。