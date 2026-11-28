# 服务端更新日志

[文档中心](README.md) · [配套发布与升级](https://github.com/wshijiang/network-mapping/blob/main/docs/RELEASING.md)

## 未发布

- **服务产品规则 v7** 将 `products[]` 收窄为 C2 部署候选，端点投影复用旧 C2 字段的证书判定。搜索与详情在升级后立即过滤 nginx、Apache HTTP Server 和 OpenSSH 的旧产品项。重建可清理索引存量并保留原始证据时间。nginx 与 Apache 继续通过 Web 技术栈查询，OpenSSH 声明保存在 SSH 握手证据中。[服务产品识别](SERVICE_PROTOCOLS.md#服务产品识别)

- **服务产品规则 v6** 将 Sliver、Mythic 和 Empire / Starkiller 条件迁入外部可替换的 JSON 规则包，支持嵌套 `all`、`any`、`none`。新增离线导出、校验和样本回放，启动日志与产品 API 记录规则摘要，端点投影写入和重建续跑核对规则修订号与摘要。[规则包说明](SERVICE_PRODUCT_RULES.md)

- **服务产品规则 v5** 增加 Mythic Web UI 和 Empire / Starkiller 管理端候选。复用已保存的 HTTP/HTTPS 正文和可核对的同源落地页，以 `product IN (mythic, empire)` 查询。补充普通页面、跨站跳转、截断响应、来源隔离和旧数据回算回归。[规则与样本范围](SERVICE_PROTOCOLS.md#mythic-与-empire-管理端)

- **说明澄清**：说明既有协议、Web 技术栈和 C2 专项结果与通用产品字段的关系，补充证据路径、结果状态及 JARM 探测/计数的适用含义，区分本地规则分析与额外网络采集。

- **Review 修复**：规范 Windows OpenSSH 版本，移除 `for_Windows_` 平台前缀，保留完整声明证据并将产品规则提升至 v4，补充旧观察回算与版本查询说明。

- **JARM 配置管理**：新增服务器 CLI `scanner-config set-jarm`，支持开关、并发、单次握手超时和块级预算的局部修改；与 Web 共用配置校验、修订历史及事务审计，保留并发冲突保护和节点本地授权。补充根命令解析、局部更新、边界及 Web API 回归。

- **检测方式与 JARM**：产品规则 v3 增加四类方式的采集方式、是否需要额外连接及基本原理元数据，端口/历史/搜索携带完整或不完整 JARM 观察。扫描器运行配置新增默认关闭的 JARM 开关与边界校验；指纹不单独生成 C2 产品归属。补充 API、启用流程、旧数据兼容与本地回归。

- **服务产品规则 v2**：新增 Sliver 默认 Multiplayer 管理端证书候选和 QakBot 历史证书结构候选；复用已有 TLS/HTTPS 叶证书，独立于 IOC 库。QakBot 明确标记历史启发式，Sliver 不扩大为通用植入体监听器识别。新增缺失/矛盾字段、普通 mTLS、证书链、跳转与旧规则回算回归；匹配边界及来源见[使用说明](SERVICE_PROTOCOLS.md#sliver-与-qakbot-的候选边界)。

- 同步独立目标监控迁移与初始化 SQL 的端口默认值升级语句，修复旧初始化文件兼容测试；增加无数据库的迁移块同步检查及默认值升级幂等/存量规则保留回归。benchmark 结果文件改为仅本地保存，保留复现脚本和文档汇总。

- **扫描性能核查**：确认告警旧版搜索新鲜度 SQL 已在主分支改为主键驱动并移出上传事务；本次避免相同时间/计划的重复物理 UPDATE，保留等时计划变更与时间单调性。数据库任务和监控规则默认端口补齐至低 11000 端口及指定高端口，保留已有值。新增隔离 SQL 基准、幂等回归及 [调查报告](SCANNER_PERFORMANCE.md)，区分告警旧查询、分支基线与本次优化。


- **服务产品识别**：协议与产品分层输出，统一展示 nginx、Apache HTTP Server、OpenSSH 声明及 Cobalt Strike、AsyncRAT / DcRAT 证书候选。新增端口、历史和搜索 API 的产品与证据字段，支持 `product` / `ID@版本` 搜索；按观察时间保留证据，完全独立于 IOC 库。停止自动生成 IP 级恶意标签，保留既有标签和旧 API 兼容。存量搜索回填与使用边界见[服务产品识别](SERVICE_PROTOCOLS.md#服务产品识别)。

- **扫描分析 · 图表快照**：后台精确生成按日去重的发现 IP 热力图，以及预设窗口的服务／端口 Top 10 和总数，按同一版本发布。页面读取预计算结果，保留普通用户权限、扫描器和任务来源口径。新增 `analytics_snapshot.page_rollups`，支持先构建后切换及独立回滚，详见[扫描分析快照](ANALYTICS_SNAPSHOTS.md#扫描分析页图表快照)。本地 PostgreSQL 18 同量级合成数据下，12 周热力图、服务分布、端口分布的接口 P95 分别从 **211.69／39.20／78.60 ms** 降至 **1.70／1.02／1.20 ms**。

- 增加普通、只读和审计账号的显式授权，与管理员组成四类角色。用户管理 Web 和本地 CLI 支持版本化更新、授权到期、按类别审计及扫描范围和配额控制，详见[用户角色与权限管理](USER_ACCESS.md)。
- 新增扫描器需要管理员近期验证。Web 重试保留任务授权限制，开放平台任务经原应用重试。开放平台敏感操作按统一路径匹配要求二次验证。

- **平台报告 · 用户订阅与平台内投递**：新增 `report_subscription`（按用户 × 日报/周报/月报，幂等迁移）与自助接口 `GET/PUT /api/report-subscriptions`。报告生成事件的站内扇出改为「计划收件人 ∪ 该周期订阅者」（外部飞书/Telegram/邮件仍按管理员配置，不扩大外发范围）；订阅者可在报告中心查看所订阅周期的已归档报告，管理员与管理员在计划中选中的用户同样可查看。报告计划收件人不再限定管理员，可选择任意启用中且有有效邮箱的平台用户（计划页显示站内订阅人数）。修复日报事件未进入站内收件箱（`report.daily` 类别缺失）、日报邮件渲染器模板身份校验与 `mail_template` 种子缺失。

- **平台报告 · 日报周期**：报告新增 `daily` 周期（每日生成上一日报告），`PeriodType`、计划调度、手动生成、统计口径、邮件模板（`report_daily`）、`report.daily` 通知事件与前端全部接通；幂等迁移扩展 `report_schedule` 约束并补齐日报计划行，种子日报邮件模板，旧库升级不补发启用前历史。

- **目标监控 · 本地实测修复**：端到端触发各类通知时发现并修复问题——① diff 前显式刷新任务对应的 ES 执行端点索引 / DNS 数据流，避免最终批次上传后读到未刷新的空快照而误报离线；② DNS 观察文档为嵌套结构（载荷在 `_source.dns`），修正解析；③ 监控来源任务（`task_source='monitor'`）不再重复产生任务通知，信号由 monitor.* 事件承载（防噪声）。新增监控任务通知抑制回归断言。

- **通知中心 · 评审修复**：① 启动迁移补齐——`db::init_database_table` 内嵌迁移列表加入 `migrate_notification_inbox.sql` 与 `migrate_target_monitor.sql`，自定义/旧版 `init_database_file` 部署升级时收件箱与监控表不再缺失（新增旧 init 文件回归测试）；② 目标监控首跑即报告阈值窗口内的证书到期（抑制端口噪声但保留到期告警，长周期规则不会漏报到过期之后）；③ 运行收尾改为逐条 `FOR UPDATE OF run SKIP LOCKED` 认领并在同一事务内完成，多实例不再重复插入变化明细（二次收尾幂等回归测试）；④ IP 快照改读本任务执行端点投影（`task_id` 过滤 + `endpoint_key` collapse 取最新观测），并发扫描更新共享 CurrentEndpoints 不再混入本次运行结果；⑤ 运行派发时冻结规则配置（新增 `target_monitor_run.target_type/targets/baseline` 幂等迁移），运行期间编辑规则不影响在途任务的 diff 输入；⑥ 快照超过 1024 端点时改为部分比对（只比较已观测端点，不推断端口关闭/目标离线）并在基线标记 `truncated`，后续运行继续部分比对，避免位移端点被误报关闭或写坏基线。

- **目标监控（资产监控）**：新增 `/monitor` 目标监控与 `/api/target-monitor/*`：对 IP/CIDR 或域名规则周期复扫（1 小时–30 天），任务终态后与基线 diff 产生变化明细与通知。IP 规则检测端口开/关、服务/产品/版本、网页标题、证书指纹变化与证书到期（≤14 天 warning / ≤7 天 critical）、目标离线/恢复；域名规则走 `dns_records` 任务检测 A/AAAA 解析漂移。新增 `monitor.change` / `monitor.availability` / `monitor.cert_expiring` 事件与 `monitor_alert` 邮件模板（飞书/Telegram 默认模板自动派生），按 run 聚合防风暴（明细 ≤20、单 run 变化 ≤200、快照 ≤1024 端口），证书按规则+目标+到期日+阈值桶稳定去重。**用户自助 + 管理员管控**：全局 `monitorUserEnabled` 开启后普通用户可创建管理自己的规则（收件人固定本人、目标受自动扫描授权网段与 DNS 排除约束、每用户 ≤20 条），管理员管理全部规则（≤200 条）并指定收件人；规则 CRUD 乐观并发 + 审计（新审计分类 `target_monitor`，幂等迁移）。调度 worker 60s 周期：过期租约主动清扫（任务失败通知不再依赖页面访问）、`FOR UPDATE SKIP LOCKED` 领取到期规则、无可用扫描器跳过并站内提示、ES 不可用降级保留基线、180 天运行清理。监控任务 `task_source='monitor'` 默认归入系统任务隐藏。

- **通知 · 站内收件箱**：新增站内通知（`notification_inbox` + `notification_user_preference`，幂等迁移）。事件入队同事务按类别扇出到收件人：任务事件→任务所有者，健康告警 / Scanner 事件→全部有效管理员，登录→本人，报告→计划收件人；受全局 `inAppEnabled` 与个人类别偏好（task/monitor/alert/security/report，默认全开）双重过滤。收件箱行携带事件快照与深链，独立于事件表 30 天清理；保留天数（默认 90）与每用户容量（默认 2000，超限优先清理最旧已读）由管理员配置、通知 worker 周期清理。新增 `/api/inbox/*`：列表（类别/未读过滤 + UUIDv7 游标分页 + 未读数）、未读计数（按类别）、标记已读（指定 ID ≤200 或全部/按类别）、单条删除（软删）、个人偏好读写；全体登录用户可用，写操作过 CSRF。

- **通知 · 任务生命周期事件**：新增 `task.completed`（info，部分完成升 warning）、`task.failed`（warning）、`task.cancelled`（info，默认关闭）三种通知事件。任务聚合刷新（`refresh_task_aggregate`）检测到进入终态的跃迁时同事务原子入队，dedup_key `task:{任务ID}:{终态}` 防重，终态重复刷新静默。接线既有 `notifyOnComplete`/`notifyOnStuck` 全局开关（此前仅持久化无消费点），新增 `notifyOnCancel`（默认关，管理员可配置）。渠道最低严重级别扩展 `info`（info < warning < critical 按秩过滤，扇出/领取/重试三处一致；存量 warning 渠道行为零变化，需显式降到 info 才接收任务完成通知）。新增邮件模板 `task_completed`/`task_failed`（变量清单与示例齐全），飞书/Telegram 默认模板由邮件模板自动派生，任务完成卡片绿色、失败橙色。全局通知偏好另增 `inAppEnabled`、`monitorNotifyEnabled`、`monitorUserEnabled`、`inboxRetentionDays`（7–365，默认 90）、`inboxMaxPerUser`（100–10000，默认 2000），为站内通知与目标监控预留，旧前端缺字段按默认值反序列化。幂等迁移扩展 `notification_channel_minimum_severity_check` 约束。
- **搜索 · 网页资产（favicon / JS / 正文）**：新增 `icon_md5`（别名 `icon`、`web.icon`）、`js_name`（别名 `js.name`）、`js_md5`（别名 `js.md5`）三个端点级搜索字段，支持精确/包含/集合/否定/`EXISTS` 与 `has_endpoint(...)` 组合。数据来自扫描器新增的网页内容富化证据（`web_assets`，默认开启、并发异步抓取）：favicon 原始字节（默认上限 **64KB**）随证据入库，**MD5 在服务端投影时计算**（与 Hunter `web.icon` / 360 Quake `favicon.hash` 同算法，算法修复可重投影无需重扫）；同源外部 JS 默认每页最多 **10** 个，只存路径与 MD5（与 FOFA `js_md5` 一致），不存 JS 内容；原探测遇重定向/空正文时补抓的落地页正文自动接管 `http_body`/`title` 派生。历史数据无富化证据时 `js_name` 从已存正文被动提取路径兜底。ES 端点索引新增 `icon_md5`/`favicon_url`/`favicon`(不索引)/`js_name`(+text)/`js_md5` 字段（schema 9，启动时对存量索引 additive 升级，零 DDL）。
- **资产展示 · favicon 中继**：新增 `GET /api/assets/favicon?ip=&port=[&protocol=]`，按调用者数据范围读取 ES 存储的图标字节回传（`Content-Type` 白名单 image/*、`Cache-Control: private, max-age=86400`、`ETag=icon_md5`、支持 If-None-Match 304，无图标 404）；服务端零出站、浏览器不热链接目标。搜索响应新增 `icon_md5`/`favicon_url`/`favicon`(仅元数据)/`js_names`，base64 不进搜索响应（`_source` 排除）；资产详情端口列表同步返回 `icon_md5`/`favicon`/`js_names`/`js_md5s`。搜索页「网页 / TLS」列头部、资产详情、任务详情展示图标（没有则不占位）。
- **配置管理 · 网页内容富化**：扫描器运行时配置新增 `service_detection.web_content`（enabled 默认 true、concurrency 16、fetch_timeout_seconds 10、max_redirects 3、max_stage_seconds 120、max_favicon_bytes 65536、max_js_files 10、max_js_bytes 524288、max_body_bytes 262144、user_agent），**Web 端扫描器配置页与服务器 CLI 均可管理**：新增 `network_mapping_server scanner-config show <ID>` / `scanner-config set-web-content <ID> [--enabled …] [--concurrency …] [--max-favicon-bytes …] …`，与 Web 写入同一文档（新修订 + 历史 + 审计，扫描器下次拉取生效，有效开关为本地 AND 远端）。创建扫描任务新增 `web_content_enabled` 可选覆盖（经 `scan_plan.web_content` 下发，无 DDL）。旧配置文档缺省该段时按默认值升级，零行为变化。
- **联测 · 网页资产翻译**：`icon_md5` 翻译为 Hunter `web.icon==` / Quake `favicon.hash:`（同 MD5 算法）；`js_name`/`js_md5` 翻译为 FOFA `js_name`/`js_md5`（= 包含 / == 精确，2026-11-20 经官方语法资料核实）；不支持的字段×平台组合按既有保守策略跳过该源。
- **网页资产 · 评审修复**：域名任务（统一域名模式 / DNS 后续）支持 `web_content_enabled`，经父任务 `generation_metadata.dns_follow_up` 传递到每个地址后续任务的 `scan_plan`；无富化证据的被动兜底正文截断改为 UTF-8 字符边界（修复多字节字符跨界时投影 panic）。
- **数据导出 · 网页资产列**：字段目录新增「网页资产」组：Favicon MD5、Favicon 来源、JS 路径、JS MD5。详见[资产搜索语法与 API](SEARCH_SYNTAX.md#42-端点与服务字段)。

## v0.1.31（2026-11-18）

- **扫描上传 · 心跳续租锁超时修复**：修复任务最终批次结果上传期间扫描器心跳偶发 503（`renew_task_lease_failed`，SQLSTATE 55P03）并触发 critical 健康告警的问题。上传确认事务对 `scan_task_execution` 行加 `FOR UPDATE` 锁后，在同一事务内执行搜索目标新鲜度更新（谱系 CTE + GiST 网段连接，生产 pg_stat_statements 均值约 600ms，随 `search_target_state` 增长实测可达 1.3–2s），而心跳续租的 `lock_timeout` 仅 1500ms，等锁超时即返回 503。现将搜索新鲜度更新移入新增的 `search_freshness_outbox` 表，由后台 worker 异步执行：上传确认事务（含 DNS 最终批次）只原子入队，执行行锁持有时间从约 1.7s 降至毫秒级；路由反馈与自动目标历史（防重复生成的刷新门，均为亚毫秒）仍留在原事务内，原子性与防重复生成语义不变。worker 以 `FOR UPDATE SKIP LOCKED` 认领并在同一事务内完成与标记，崩溃自动回滚重领，失败按指数退避（2–256s）重排并记录 `last_error`，任务删除级联清理；新鲜度 UPDATE 单调幂等，同一任务再次成功可重入队推进 `last_success_at`。上传响应同时提速约 1s。新增 `search_freshness_outbox` 表（幂等迁移，升级零行为变化，历史已完成任务无需回填）；新增延迟生效、重入队、失败退避、级联删除 4 个集成测试。

- **搜索 · 情报标注性能**：修复多结果页搜索与资产详情端口列表的情报标注慢查询。原标注查询以 `kind||':'||value = ANY(keys)` 表达式谓词查 `intel_record_state` 视图，key 数稍多（≥13）时规划器对表达式索引选择率估算失真（110 key 估 8.6 万行，实际几十行），翻转为全视图 Hash Join + Sort + 双层 WindowAgg（cost ≈ 368 万）并每次执行触发 JIT，50 条页搜索服务端耗时 500+ms（limit=5 即出现 31→578ms 悬崖），资产详情端口列表（最多约 101 key）同样受累。现改为 `unnest` 拆分 key 后按裸列 `(kind,value)` join 视图，命中既有部分索引 `intel_record_published` 的参数化嵌套循环；视图来源过滤与过期计算语义不变，custom/generic plan 均稳定走索引、无 JIT，**零 DDL**。实测测试环境 `port = 443`：limit=1/5/50 总耗时 27–30/24–30/39–59ms，情报标注 3–6ms；EXPLAIN ANALYZE 110 key 2.5ms、500 key 37ms。搜索成功响应另增 `es_wall_ms`（ES 调用墙钟）与 `intel_took_ms`（情报标注累计）分阶段耗时，标注查询失败降级补 `IntelAnnotationUnavailable` 警告日志；新增多 key 批量标注回归测试（批量与逐 key 等价、rank 截断、三态、ASN 上下文不污染）。详见[资产搜索语法与 API](SEARCH_SYNTAX.md#82-成功响应)。

- **搜索 · 耗时展示**：`/api/search/v2` 成功响应新增 `took_ms`（服务端处理本次搜索的总耗时，毫秒，含 Elasticsearch 查询、情报标注与联测合流）与 `es_took_ms`（本次搜索触发的全部 Elasticsearch 查询自报 `took` 之和，含 `has_endpoint`/`domain` 扩展解析查询），搜索页结果摘要展示耗时，悬停可见 Elasticsearch 查询耗时，便于用户判断慢查询来自索引还是服务端附加处理。详见[资产搜索语法与 API](SEARCH_SYNTAX.md#82-成功响应)。

- **数据管理 · 后台导出**：新增「数据管理 → 导出」导航与服务器 CLI `network_mapping_server export`，把搜索语句匹配的资产端点数据交给后台 worker 导出为 CSV。与资产搜索同一 DSL、同一数据范围规则（创建时快照管理员全局/普通用户个人口径），只读本地索引、不触发联测；「全部」导出经 Elasticsearch PIT + search_after 分批遍历，突破搜索页 10k 浏览窗口，单任务行数上限默认 100 万。搜索页「导出当前页 CSV」升级为「导出」modal：可选本页/全部、展示语句匹配条数、按字段目录勾选导出列（本页同样可调），提交后后台执行。字段目录为单一事实来源（`GET /api/data-export/schema`），列顺序与标签对齐原当前页 CSV；UTF-8 BOM + CRLF、公式注入防护，时间列按系统时区格式化。任务全生命周期管理：5 态状态机、进度计数、取消、删除、租约认领与崩溃重跑、保留期清理（默认 30 天）；Web 流式下载（仅所有者/管理员），CLI 仅创建/查看/取消。写操作与下载记审计；新增 `data_export_task` 表与 `[data_export]` 配置段，未配置时升级零行为变化。详见[数据导出](DATA_EXPORT.md)。

- **自动目标生成 · 排除段跳跃与游标延续**：修复修改 `common_ports` 等策略字段后自动任务长时间停止生成目标的问题。原实现在策略哈希变化时把顺序游标重置为零，随后以每轮最多 256 个子网的速度爬行强制排除段 `0.0.0.0/8`（65536 个 `/24`，约 2 小时），期间不生成任务且无日志。现在游标命中排除网段时整段跳过（含跨授权池边界与 IPv6），并记录 `AutomaticTargetExcludedBlockSkipped` 日志；策略变更保留游标覆盖位置（按新子网空间取模归一），不再归零重扫已覆盖地址。详见[双栈与自动目标](DUAL_STACK_SCANNING.md#生成行为)。

- **自动目标生成 · 手动游标调整**：管理员可在「设置 → 运行时配置 → 自动扫描策略」的生成游标卡片，或调用 `POST /api/automatic-target/cursor`，把生成游标移动到授权范围内任意位置，支持直接输入位置序号或任务 CIDR（自动换算），用于从指定网段继续扫描、跳过已覆盖区域或故障恢复后对齐进度。状态接口新增游标指向的下一个任务 CIDR（`next_target`）。游标写入与生成器补充事务共用行锁，下一个生成周期即从新位置继续，不立即创建或删除任务；越界、超出授权范围、前缀不一致或未知地址族返回 400 及中文原因，成功调整写入审计事件（`automatic_target` / `cursor.manual_update`，含操作者与新旧位置）。详见[双栈与自动目标](DUAL_STACK_SCANNING.md#手动调整生成游标)。

- **技术栈识别 · 目录扩充**：「Web 技术栈」更名为「技术栈」（仅展示标签，响应字段 `web` 与搜索 DSL `tech` 保持不变）。内嵌规则由 88 条 / 53 种扩充至 **136 条 / 100 种**（规则版本 `2026-11-16.7`，修订 7），新增 Tomcat、Undertow、Kong、APISIX、Envoy、Varnish、F5 BIG-IP、Cloudflare、CloudFront、Django、Rails、CodeIgniter、Phusion Passenger、Magento、PrestaShop、OpenCart、TYPO3、Roundcube、Zimbra、Kibana、Prometheus、SonarQube、Portainer、Nacos、Zabbix、Gitea、CouchDB、InfluxDB、Neo4j、pgAdmin、RedisInsight、Svelte、Preact、Material UI、Chakra UI、Naive UI、Arco Design、Lodash、Day.js、Socket.IO、Matomo、Hugo、Jekyll、Hexo、MkDocs、Redoc、GraphiQL 等；首次启用页面标题与 HTML class 证据来源，并修正 Apache 对 «Apache Tomcat» / «Apache-Coyote» 的误判。提升修订后自动回填历史证据，无需重新扫描目标。详见[技术栈目录](WEB_TECHNOLOGY_CATALOG.md)。

- **操作系统识别 · 被动增强**：扩充被动发行版签名（Fedora、RHEL、Rocky Linux、AlmaLinux、Alpine、openSUSE/SLES、Amazon Linux、Arch、Gentoo、Oracle Linux、Deepin、统信 UOS、麒麟 Kylin、Linux Mint、Kali、OpenWrt），增强 `native_os` / `server_os` 版本提取（跳过引导产品词、识别 `v` 前缀，如 «Debian GNU/Linux 12»→12、«Alpine Linux v3.19»→3.19、«Rocky Linux 9.3»→9.3）。仍只读取已上传的握手字段，不额外探测、不改扫描器；规则版本 `2026-11-16.2`（修订 2）触发历史回填。为未来主动 TCP/IP 指纹预留 `OsEvidence.probe_method` 字段与开发契约（本期不实现探测）。详见[操作系统识别](OS_DETECTION.md)。

- **数据管理 · 联测**：新增「数据管理 → 联测」导航与服务器 CLI `network_mapping_server federation`，搜索时按策略联合 **Hunter 鹰图 / 360 Quake / FOFA / Shodan** 查询（端点/参数/计费经 2026-11-16 官方文档核实），结果与本地资产聚合去重后返回并按策略入库。本地搜索 DSL 直接翻译为各平台语法（不支持构造保守跳过、宽匹配语义本地残余精过滤）；冲突以平台数据时间戳新者胜（服务时钟守卫保证旧平台数据不覆盖新扫描）。支持异步/阻塞两种模式、字段触发与本地无结果/过期触发（默认 60 天）、远端查询时间窗（默认 30 天、最大 60 天、每源可单独设置，默认按平台最划算：Hunter 30 天免费窗口、其余不指定）、分页跟随本地或固定、每源代理跟随全局/直连/自定义（失败关闭）。入库可选（本地无结果/过期/新鲜三条件开关），经现有 `result_ingest` 管道写入（`task_source='federation'`），投影/富化/统计/情报自动生效。凭据加密落库脱敏回显；会员能力探测与字段降级；额度常驻显示与周期刷新；同查询冷却复用与在途去重保护平台额度（Shodan 单 IP 走免费端点）。Web 三 tab 管理（数据源/策略/联测记录）+ 手动联测 + 搜索页状态条与来源徽标；策略存运行时配置热生效；新增 `federation_source`、`federation_run` 表与 `[federation]` 配置段，未配置数据源时升级零行为变化。详见[联测](FEDERATION.md)。

- **数据管理 · 外部导入**：新增「数据管理 → 导入」导航与服务器 CLI `network_mapping_server import`，支持上传/指定 CSV 将外部资产端点数据批量导入现有 Elasticsearch 资产库。必须头部 `ip/port/protocol/observed_at`，可选 `service/banner/source/asn/as_org/位置/os/os_confidence/tech/title`；Web 端只读 CSV 头部（64KB 切片）自动配对 + 手动映射，核对必须头部后才上传。后台流式解析、完整性与类型校验、文件内去重汇聚，经现有 `result_ingest` 管道写入（复用投影/OS/Web 检测/分析/情报），不另建资产表。任务全生命周期管理：8 态状态机、进度计数、暂停/继续（可调整批次大小与并发）/取消、试运行、错误报告 CSV 下载、崩溃租约续传。ASN/位置 CSV 优先、缺省 MaxMind 补全；OS/Web/title CSV 优先、缺省检测派生；默认 `fill` 不覆盖扫描结果（仅新增/补缺、保留标签），可选 `overwrite` 按时间新者胜，导入数据不直接作为最新结果。管理员专属，写审计；新增 `data_import_task`、`data_import_batch` 表与 `[data_import]` 配置，升级零行为变化。详见[数据导入](DATA_IMPORT.md)。

- **Syslog 转发**：新增系统运行日志、审计事件、IP 访问日志与扫描器诊断事件的远程 syslog 转发，仅适配现代产品（RFC 5424，TCP/TLS 使用 RFC 6587 octet-counting 帧）。最多 10 个目标，各自独立选择 UDP/TCP/TLS 与自定义端口、订阅日志类型（默认全部）；配置存于运行时配置（namespace `syslog`），Web 发布与 CLI 变更均在数秒内热生效，无需重启。Web 管理入口位于「日志」导航，CLI `networkm syslog` 与 Web 功能对等（配置/状态/历史/测试/统计/通知策略/回填）。分钟级转发统计支撑 Web 图表与 CLI 终端图（malevich）；通知策略支持整体失败率、发送耗时 P95/P99 三条独立开关，经健康告警渠道通知。默认关闭，升级零行为变化；新增 `syslog_target_status`、`syslog_metric_minute` 表。
- **Syslog 历史日志回填**：管理员可手动下发回填任务，把数据库留存的审计事件、IP 访问日志与扫描器诊断重放到已启用目标，默认最近 7 天，支持「N 天前至今」或自定义时间段（最长 31 天）；保留原始事件时间戳，带进度计数、取消与重启恢复，不计入实时统计。新增 `syslog_backfill_job` 表与 `networkm syslog backfill create/list/cancel`。
- **Syslog SOCKS5 代理与自动回退**：转发跟随全局网络代理，但仅 SOCKS5（`socks5`/`socks5h`，支持用户名密码认证与代理侧 DNS）生效，作用于 TCP/TLS 目标；全局代理为 HTTP/HTTPS 等其他类型、直连或未配置时自动回退直连，UDP 目标始终直连。代理配置变更热生效，状态接口与 CLI 展示当前代理或回退结果。
- 修复扫描器本地启用引擎、但服务端扫描配置将其禁用时，漏扫等任务仍被派发给该扫描器并必然失败的问题：心跳能力只反映扫描器本地配置，而实际执行开关是本地与服务端配置的交集。现在任务创建、分配预览、规划预留、领取与恢复全链路都按服务端运行时配置校验任务必需阶段的引擎开关（Nuclei、服务识别、DNS），配置发布后立即生效，无需等待心跳；节点尚无配置记录时保持原有调度行为。调度条件见[扫描流水线](SCAN_PIPELINE.md#能力调度)。
- 修复单次扫描执行去重键超过 20 万导致统计回填永久停滞、报告等待超时的问题：使用 Elasticsearch PIT 分页及 PostgreSQL 临时表分批去重，保留领取校验与原子发布；新增暂存空间和执行时间限制。升级及定向恢复步骤见[扫描分析快照](ANALYTICS_SNAPSHOTS.md)。
- 补充扫描节点 Modbus TCP 改用固定版 zgrab2 后的识别边界和 blocklist 配置说明，提示镜像默认屏蔽 RFC 1918 地址。

- 修复飞书应用机器人发送较长消息后，成功响应因大小限制被误记为投递失败的问题。
- 修复数据库连接池仅有一个连接时，飞书绑定确认回复无法更新投递状态的问题。

- 飞书应用机器人通过长连接接收私聊绑定指令，使用一次性绑定码自动绑定个人接收者，支持重新绑定和解除绑定；补充指令格式和事件推送排障说明。

- 飞书应用机器人可选择群聊或个人聊天，支持向指定用户 Open ID 发送通知和报告趋势图；历史群聊渠道保持兼容。

- 补充飞书应用机器人与群聊自定义机器人的配置、报告图片权限及联调排障说明。

- 飞书通知区分群聊自定义机器人和应用机器人；应用机器人支持使用应用凭据向目标群发送通知及报告趋势图，历史 Webhook 渠道保持兼容。

- 统计查询分组默认上限提高到 20,000，管理员可在运行策略配置 1–65,536；实时、快照和任务历史共享该限制。旧配置自动使用默认值，并修正快照模式下的超限提示。

- 自动周报和月报计划支持直接选择已启用的飞书、Telegram 渠道，并同步报告事件订阅。

- Telegram 通知模板增加富消息格式，通过 `sendRichMessage` 发送；未自定义的报告模板默认使用该格式。
- 报告支持按订阅自动或手动选择飞书、Telegram 渠道投递；Telegram 富消息上传趋势图，飞书可配置加密应用凭据，先上传图片再使用 image_key 发送。
- **统计查询诊断**：为在线预算和繁忙拒绝补充分项原因、计数、限额与安全的查询上下文，支持按请求 ID 关联，便于排查端口分布失败。日志字段和使用说明见[统计分析](STATISTICS.md#计算保护)。

## v0.1.30（2026-10-27 重新发布）

**2026-10-26 的同版本发布已撤回，2026-10-27 修复后重新发布**。请以本次 tag 指向的提交、BUILD-INFO 和 SHA-256 校验文件为准，不复用已撤回制品或旧 Actions 构建附件。本节按最终实现汇总此前阶段记录。

| 核对项 | 固定范围 |
| --- | --- |
| 上次发布 | `v0.1.29` · `d5f2da809e9ebecbf80ea7b3debe849ec9a824c1` |
| 本次代码基线 | `5cb0bc82eecec854388cdca1189bb60e1536fc02`（`main`） |
| 变动范围 | 49 个提交（含合并提交）；[完整比较](https://github.com/wshijiang/network-mapping/compare/v0.1.29...5cb0bc82eecec854388cdca1189bb60e1536fc02) |

本次另含版本、发布说明及文档整理；服务端同时固定配套控制台发布提交。

### 撤回后补充的修复

- 重建必须显式指定 `--rebuild-transport-mode new-index` 或 `in-place`；原地重建先克隆并验证两个旧投影的备份，完成后才删除原名索引。中断可用原配置、原模式续跑。
- 按 ES 现存事实重建，不再使用 PG 上传回执、批次数量或事实校验和做数据对账；PG 提供执行归属、状态和标签，ES 数量只作进度参考。原始事实缺失可能使新投影少于旧投影，升级前须保留配套备份。
- 默认使用 32 个独立执行并发、每页 10000 条，支持 CLI 调整；单执行发布最多保留 4 页在途，等待下一页查询时持续驱动 Bulk，按页序保存断点并保持跨执行发布顺序。修复原先只入队而未持续轮询导致查询与写入串行的问题。
- 标签采用 PIT + `_shard_doc` 分页，每页使用最新返回的 PIT ID，成功或失效重启时关闭最新 ID，修复 PIT 轮换后继续使用旧 ID 的问题；支持中断续跑、PIT 过期重扫及无序标签比较。
- 使用 composite 聚合统计进度、按阶段批量读取断点、集合 SQL 切换计数及 outbox；全量刷新使用独立 300 秒预算，新增逐页搜索/写入耗时日志。
- 同步主分支发布版本和文档并解决冲突；补充 PIT 轮换/恢复/关闭、查询期间写入轮询及有序错误回归。操作步骤及恢复边界见[存储升级与回滚](SERVICE_PROTOCOLS.md#存储升级与回滚)。

### 新增与调整

- **服务自动识别**：TCP 默认识别全部已实现服务；加入 DNS TCP、DoH/DoT、VNC、Modbus TCP、EtherNet/IP、经典 S7comm、OPC UA，以及原生 MQTT/MQTTS。新增独立 UDP 主动和被动任务，预览、创建、调度、重领及恢复共同核对节点协议能力和探测预算。完整范围与限制见[服务协议矩阵](SERVICE_PROTOCOLS.md)。
- **传输端点与可恢复迁移**：端点身份包含 TCP/UDP/unknown，默认执行/当前投影升级至 v2/v3。重建须显式选择 `new-index` 或 `in-place`，按 ES 现存事实重建；PG 提供任务归属、状态和标签，不执行回执/数量/校验和对账。按页持久化游标，校验源/目标/备份身份，支持同模式恢复、进度/速度/ETA 和有界停止。全部阶段确认后才事务性切换运行标记、计数、outbox 和 OS/Web 补全队列；失败保留运行状态；`new-index` 保留旧索引，`in-place` 在备份完成后才删除旧投影。见[存储迁移与回滚](SERVICE_PROTOCOLS.md#存储升级与回滚)。
- **操作系统与 Web 识别**：复用已有握手及 HTTP 证据，不增加目标请求；支持证据、置信度、冲突、不完整/过期标记、搜索及经审批的外部 API 摘要。Web 目录包含 Elasticsearch REST 识别（规则修订 6，88 条规则、53 种技术）；不包含 Elasticsearch 原生 Transport。见[系统识别](OS_DETECTION.md)、[Web 技术目录](WEB_TECHNOLOGY_CATALOG.md)。
- **统一通知**：邮件、飞书、Telegram 独立订阅、持久化投递、有限重试与历史；按渠道模板支持草稿、发布、恢复、预览及测试。每渠道可独立配置系统/直连/自定义代理，敏感值加密，代理失败不回退直连。见[通知渠道](NOTIFICATIONS.md)、[通知模板](NOTIFICATION_TEMPLATES.md)。
- **登录与域名策略**：可选 Cloudflare Turnstile，默认关闭，管理员配置持久化；域名按标签边界匹配后代。DNS 排除策略覆盖手工、搜索生成及 OpenAPI 任务；证书透明度发现提供候选域名、SAN 和同证书关系，再显式选择 DNS 验证，不作为资产归属证明。见[登录保护](HUMAN_VERIFICATION.md)、[DNS 排除策略](SEARCH_TARGET_GENERATION.md)、[域名发现](DOMAIN_DISCOVERY.md)。
- **可信情报与固定人工审核**：结构化 IOC、MITRE、RSS 文章、离线文件及数据库来源接入，支持断点导入、过期证据、手工文章和批量 CLI；AI 提取生成原文定位的待审提议，不能自动绕过人工审核。见[威胁情报](THREAT_INTELLIGENCE.md)。
- **LLM 供应商与在线调试**：供应商/模型管理、Chat Completions 与 Responses、全局/局部代理及头/session/流式设置；支持思考展示、实际用量、缓存命中、多轮调试、可选加密历史与重放。默认不留存对话；未发送草稿在浏览器按用户保留七天。见[LLM 配置与迁移](LLM.md)。
- **部署与语言**：支持仅回环监听的可选 HTTP、host 数据库示例及状态码式 `/healthz` 存储就绪探针；固定配套前端提交。界面支持浏览器偏好和 cookie 中英切换；三个文档站默认严格构建同时生成中英文页面、资源与搜索索引，尚未翻译的专题明确回退。见[部署](DEPLOYMENT.md)、[多语言](LOCALIZATION.md)。

### 修复与维护

- 拒绝零成功分片或缺计数的刷新；纯漏洞观察不发送空端点 Bulk，重建完成后清除旧 outbox 游标/租约。ES 诊断保留耗时及连接/超时类别并去除 URL 凭据；修复 UDP profile 数据库约束及 Docker 默认索引契约。
- 修复旧通知队列接管、过期清理、共享冷却和维护暂停；保留历史投递回执，避免重复发送已成功收件人。修复旧 OS/Web 证据回填及歧义响应归属。
- 适配 actix-files 0.7 的阻塞文件打开，保留资源/日志下载鉴权、状态码与响应头；更新 actix-web、uuid、serde_json、ipnet、rustls 和构建 Actions。直接依赖及许可证以[第三方清单](OPEN_SOURCE_CATALOG.md)为准。
- 修复默认文档构建只生成中文导致英文资源 404、子路径语言跳转及 cookie 不可用时显式语言选择丢失；补齐中英文部署和维护入口。

### 升级与兼容

1. **先备份再迁移**：停止全部旧后端、扫描写入和事实清理，保留 PG/ES 配套备份、`server.encrypt_key`、扫描器 pepper 和身份状态。既有部署不能直接切到空索引；按[端点迁移](SERVICE_PROTOCOLS.md#存储升级与回滚)显式选择 `--rebuild-transport-mode new-index`（配置全新 execution/current 索引）或 `in-place`（克隆备份后原地重建），配合 `--rebuild-transport-endpoints` 执行；完成后按需运行 `--rebuild-analytics-snapshots`，成功后再启动服务。observation/DNS 索引位置保持不变。
2. 重建中断后以相同配置、原模式和命令恢复。旧式仅含 `last_execution_id` 的断点不能续用，可使用全新目标 `new-index` 或显式 `in-place` 从头重建；不执行 PG/ES 数据对账，ES 事实缺失可能使新投影少于旧投影。回滚使用旧索引或原地重建备份，并恢复配套程序、配置及迁移前 PG 运行标记。
3. 配套升级 Scanner **0.1.21**（Agent、Worker、完整 IPC **3** 模块包）和控制台 **0.1.24**；先排空旧 generation 的任务/检查点，不通过删除状态库绕过检查。TCP plan v1、结果上传协议 3 保持兼容；新 UDP 任务要求 plan v2。
4. 通知迁移后只运行新版 worker；旧域名白名单迁移会关闭域名搜索生成，管理员核对排除策略后再启用。开启 Turnstile 前部署新版登录页；新增外部 API `os`/`web` 权限仍需单独审批。
5. 旧 AI 配置与密钥按 [LLM 迁移说明](LLM.md#迁移并发与部署)核对；保留加密主密钥。历史丢失的握手正文或字段无法通过回填恢复，需要重新执行相应任务。

本日志描述已合入实现及升级影响，不表示真实设备、外部通知/AI 服务或生产 ES 迁移已经验收。具体本地检查结果见 release PR；默认忽略的集成测试单独列出。

此前发布见 [GitHub Releases](https://github.com/wshijiang/network-mapping/releases)；本节不重复计入 `v0.1.29` 已交付的功能。
