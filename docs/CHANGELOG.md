# 服务端更新日志

[文档中心](README.md) · [配套发布与升级](https://github.com/wshijiang/network-mapping/blob/main/docs/RELEASING.md)

## 未发布

- Telegram 通知模板增加富消息格式，通过 `sendRichMessage` 发送；未自定义的报告模板默认使用该格式。
- 报告支持按订阅自动或手动选择飞书、Telegram 渠道投递；Telegram 富消息上传趋势图，飞书可配置加密应用凭据，先上传图片再使用 image_key 发送。

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
