# 数据管理 · 联测（多源网络空间测绘联合查询）

联测在用户搜索资产时，按策略同时向外部网络空间测绘平台（**奇安信 Hunter 鹰图、360 Quake、FOFA、Shodan**）发起查询，将结果与本地资产库**聚合去重**后返回，并按策略写入现有 Elasticsearch 资产库。Web 管理端与服务器 CLI 功能对等。

- 导航：**数据管理 → 联测**（`/data/federation`，管理员）
- CLI：`network_mapping_server federation …`
- 设计文档：工作区 `FEDERATION_PLAN.md`（含官方 API 核实记录，2026-11-16）

## 工作原理

```
用户搜索 ──► 触发评估（策略/字段/新鲜度/冷却）
              │ 不触发 → 原搜索路径
              ▼
        创建 federation_run ──► 执行器（服务器进程内唯一执行）
              │                  ├─ 本地 DSL AST → 各平台查询语法
本地 ES 搜索 ◄┘（并行）           ├─ 每源代理/限速/分页/会员降级
              │                  ├─ 归一化 + 残余精过滤
              │                  └─ 跨源聚合去重（新者胜）
              ▼
        async：立即返回本地结果（已完成的联测并入）
        blocking：等待联测（总超时兜底）后合并返回
              │
              ▼
        入库决策 → result_ingest 管道（task_source='federation'）
        → 投影 → current_endpoint（global scope）→ 搜索/详情/统计自动生效
```

关键语义：

- **冲突以最新为准**：展示合并与入库合并均按平台数据时间戳（`observed_at`）新者胜；入库走现有投影的服务时钟守卫，**旧平台数据不会覆盖新扫描**。时间戳平局（Hunter 仅日期粒度）本地扫描优先。
- **聚合去重**：端点身份 = `ip|port|protocol`；同键多源记录新者胜 + 空字段互补 + tech 并集 + 来源累加。
- **保守翻译**：平台不支持的查询构造（如 Shodan 跨字段 OR、`has_endpoint`、tag/os/tls 字段）→ 该源本次跳过（`unsupported`），绝不丢谓词放大查询。平台语义宽于本地时（如 Shodan `hostname:` 包含匹配）用本地残余谓词精过滤。
- **仅管理员触发**：联测数据入 global scope；非管理员搜索走原路径。

## 数据源配置

每个数据源独立配置（`federation_source` 表，凭据 AES-GCM 加密落库，API/CLI 永不回显明文）：

| 配置 | 说明 |
|---|---|
| 平台/名称/启用 | hunter / quake / fofa / shodan |
| 凭据 | Hunter `api_key`；Quake `token`；FOFA `key`（`email` 可选兼容）；Shodan `key` |
| 代理 | **跟随全局**（system，全局代理不可用时失败关闭）/ **直连**（direct）/ **自定义**（custom，http/https/socks5/socks5h） |
| 字段 | ip/domain/port/service/tech/title/banner（ip/port 恒选） |
| 分页 | 跟随本地搜索（follow_local）/ 固定（fixed：page_size × max_pages） |
| 时间窗 | 跟随策略（follow）/ 不指定（none）/ 单独设置（custom，1..60 天） |
| 超时/限速 | timeout_seconds 3..120；rate_limit_qps (0,10] |

**默认时间窗按"最划算"原则**：Hunter 跟随全局默认 30 天（官方近 30 天窗口优先扣免费积分，超窗扣权益积分）；Quake/FOFA/Shodan 默认不指定（避免会员门槛；Shodan 搜索本就固定近 30 天窗口）。

### 平台要点（官方文档核实 2026-11-16）

| 平台 | 端点 | 计费 | 关键限制 |
|---|---|---|---|
| Hunter | `GET /openApi/search`（search=base64url） | 积分制：每日免费积分 + 权益积分 | page_size ≤100；查询串 ≤2048；约 2s/请求；`updated_at` 仅日期粒度 |
| Quake | `POST /api/v3/search/quake_service`（X-QuakeToken） | 免费 API 5–20 次/月，之后 1 积分/条 | size ≤100；单次量按会员（基础 100/高级 5000/白金 10000）；**基础会员无 time/components/domain/banner**；时间参数仅高级+；需实名；限速 q3005（建议间隔 ≥15s） |
| FOFA | `GET /api/v1/search/all`（key-only，qbase64） | F 点 1 点=1 条；月度配额 Web+API 共享 | size ≤10000（含 body 查询 ≤500）；**lastupdatetime/product 需专业版+**；after/before 需个人版+；**403=IP 永久封禁**（不重试，联系 FofaBot 解禁）；建议 <2 req/s |
| Shodan | `GET /shodan/host/search` | 带 filter 每页 1 credit | 每页 100；1 req/s；**无时间过滤器**（固定近 30 天）；无跨字段 OR；**单 IP 查询走免费 `/shodan/host/{ip}`**（history=true ≤90 天） |

**账号建议**：Quake 高级及以上、FOFA 专业版及以上（否则缺时间戳/tech，时间戳按拉取时间标注 `timestamp_inferred`）。测试连接按钮探测会员等级与剩余额度（免费账号接口），额度常驻显示在源卡片并每 6 小时刷新。

## 策略（runtime_configuration namespace `federation`）

Web「策略」tab 与 CLI `federation policy set` 读写同一行，乐观并发，发布后数秒热生效。

| 字段 | 默认 | 说明 |
|---|---|---|
| enabled | true | 总开关 |
| mode | async | async=立即返回本地结果，联测后台入库；blocking=等待合并返回（超时兜底） |
| trigger | empty_or_stale | always=每次搜索；empty_or_stale=本地无结果或过期时 |
| stale_days | 60 | 本地过期阈值（匹配端点最新 last_seen 距今超过该天数） |
| query_window_days | 30 | 远端查询时间窗全局默认（1..60），供 follow 源使用 |
| trigger_fields | []（任意） | 查询涉及这些字段才触发（ip/domain/port/service/tech/title/banner） |
| blocking_timeout_seconds | 30 | 阻塞模式总等待上限（5..120） |
| persist | enabled/on_empty/on_stale=true，on_fresh=false | 入库开关与条件 |
| cooldown_seconds | 300 | 同查询冷却：窗口内复用最近 run 结果缓存，不重复请求平台 |
| max_records_per_run | 500 | 单 run 归一化记录上限 |
| max_concurrent_runs | 4 | 并发 run 上限 |

**入库条件**（`persist`）：本地无结果 → `on_empty`（"没有数据则入库"）；本地过期 → `on_stale`（"过期数据入库"，用联测新数据刷新）；本地新鲜（trigger=always）→ `on_fresh`（默认关，仅展示合并）。手动 run 可强制/跳过。入库经现有 `result_ingest` 管道：MaxMind 补缺、OS/Web 富化、投影、统计、情报标注全部自动生效；扫描任务以 `task_source='federation'` 标记（任务列表默认过滤）。

## Web 管理端

- **数据源**：卡片列表（启用状态、凭据状态、代理模式、时间窗、**剩余额度徽标**与低额度告警）；添加/编辑抽屉；测试连接（会员/配额/延迟）；删除。
- **策略**：上表全部字段；冲突时提示重新加载。
- **联测记录**：run 列表（状态徽标、拉取/合并/入库计数）；活动 run 2s 轮询；详情含每源明细（状态、错误码、时间窗、平台查询串、耗时）；取消/删除；**手动联测**入口。
- **搜索页**：联测状态条（进行中/完成新增 N 个端点/缓存/超时）+ 刷新按钮；结果行来源徽标（联测/本地+联测）；导出 CSV 含"数据来源"列。

## CLI

```bash
network_mapping_server federation source list [--json]
network_mapping_server federation source add --kind hunter --name 鹰图 --api-key - --enabled --admin admin
network_mapping_server federation source update <ID> [--window-days 45 | --window-follow | --window-none] --admin admin
network_mapping_server federation source remove <ID> --admin admin
network_mapping_server federation source test <ID> [--json]      # 本地出站 HTTP
network_mapping_server federation policy show [--json]
network_mapping_server federation policy set --mode blocking --stale-days 90 --admin admin
network_mapping_server federation run 'ip = "1.1.1.1"' --wait --admin admin
network_mapping_server federation runs [--status running] [--json]
network_mapping_server federation status <RUN_ID> [--json]
network_mapping_server federation cancel <RUN_ID> --admin admin
```

除 `source test` 外仅需 PostgreSQL；run 由运行中的服务器执行（CLI 创建 pending，worker 认领）。`--api-key -` 从 stdin 读取凭据。

## HTTP API（管理员，会话鉴权 + CSRF，写审计）

| 方法/路径 | 说明 |
|---|---|
| GET `/api/federation/schema` | 平台能力目录 |
| GET/POST `/api/federation/sources` | 源列表/创建 |
| PUT/DELETE `/api/federation/sources/{id}` | 更新（expected_revision）/软删除 |
| POST `/api/federation/sources/{id}/test` | 测试连接 |
| GET/POST `/api/config/runtime/federation` | 策略读写（复用运行时配置） |
| POST `/api/federation/runs` | 手动联测 |
| GET `/api/federation/runs` / `runs/{id}` | run 列表/详情 |
| POST `/api/federation/runs/{id}/cancel` | 取消 |
| DELETE `/api/federation/runs/{id}` | 删除终态 run |

搜索响应扩展（向后兼容）：`federation{run_id,status,mode,merged_new}`；结果项 `data_origin`（local/federation/merged）与 `federation_sources`。

## 配置（config.toml）

```toml
[federation]
enabled = true                 # 部署级总开关
worker_poll_seconds = 2        # pending/租约过期 run 认领间隔
run_retention_days = 30        # 终态 run 保留期
lease_seconds = 120            # run 租约（崩溃恢复）
observed_at_future_tolerance_seconds = 300
quota_refresh_hours = 6        # 额度周期刷新
```

数据库迁移：`source/database/migrate_federation.sql`（`federation_source`、`federation_run`、预留扫描器"联测"）。升级零行为变化：未配置数据源时搜索路径不受影响。

## 限制与排错

- **查询翻译**：`~` 包含、比较运算、`has_endpoint`、tag/os/tls/first_seen/last_seen 等构造多数平台不支持 → 该源跳过（run 详情可见 `unsupported` 与原因）。tech 版本（`tech = "x@1.2"`）平台侧丢弃版本匹配（标注 `version_ignored`）。
- **Shodan 时间窗 >30 天**：search 仍只覆盖近 30 天（`platform_window=30d`）；单 IP 查询经免费 host 端点 history 可覆盖 ≤90 天。
- **会员降级**：Quake 基础/FOFA 免费账号请求受限字段时自动降级重试一次；时间戳缺失按拉取时间标注 `timestamp_inferred`。
- **错误码**：`auth_failed`（凭据无效）、`quota_exhausted`（额度耗尽）、`rate_limited`（退避重试）、`ip_banned`（FOFA 403，永久，需解禁）、`field_permission`（降级）、`proxy_*`（代理）、`unsupported`（查询不支持）。
- **异步完成到可搜索**有秒级投影延迟；状态条提示刷新后重搜即可。
- 纯域名记录（无 ip:port）不入端点模型（丢弃计数）；域名资产联动见域名发现。