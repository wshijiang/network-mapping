# 服务端更新日志

[文档中心](README.md) · [部署与升级](DEPLOYMENT.md) · [扫描端更新日志](https://github.com/wshijiang/Network-Mapping-Scanner/blob/main/docs/CHANGELOG.md)

## 待发布开发变更

- 新增独立 LLM 管理 API、DeepSeek / OpenCode Go / CommandCode GOAT 预设及供应商、模型管理；IOC 提取使用唯一供应商与模型组合。
- 支持全局与供应商局部的代理、自定义头、session 头名称及流式传输；敏感配置加密保存，局部关闭与继承具有独立语义。
- 扩展 async-openai 的自定义有界传输，支持 Chat / Responses 流式输出、正常结束检查和可取消的在线对话调试。IOC 流完整结束后才执行原文证据校验与人工审核。
- 幂等迁移旧 AI 设置；保留运行配置投影及入库版本锁。迁移后旧 AI 设置写接口返回已迁移错误，发布所用 frontend-ref 已固定配套 LLM 控制台提交，需一同部署。
- 补充 [LLM 配置与升级文档](LLM.md)、模型发现和配置继承测试、真实 PostgreSQL 迁移与单选约束测试、SDK 流式与取消测试。

本节为当前工作区开发变更，未计入下方主分支历史截止快照。升级前备份数据库并停止旧服务实例，保留加密主密钥；回滚需同步恢复对应备份与前端。

## 未发布（自 v0.1.29 以来）

截至 **2026-10-21（北京时间）**，以最新已发布 tag [v0.1.29](https://github.com/wshijiang/network-mapping/releases/tag/v0.1.29) 为基线，汇总主分支已合入的服务端变动，不包含尚未合入的开发分支或前端独立变动。

| 比较项 | 固定版本 |
| --- | --- |
| 上次发布 | `v0.1.29`，2026-10-15 发布，提交 `d5f2da809e9ebecbf80ea7b3debe849ec9a824c1` |
| 本次截止 | `main` 的 `919cecb2151ee5612c4cbf2d03d2e20d4c87e6e6` |
| 变动范围 | 32 个提交（含合并提交）；[查看完整比较](https://github.com/wshijiang/network-mapping/compare/v0.1.29...919cecb2151ee5612c4cbf2d03d2e20d4c87e6e6) |

### 新增

- **统一通知渠道**：邮件、飞书和 Telegram 支持同级订阅与多渠道独立投递，覆盖健康告警、扫描器掉线/恢复、登录、周报和月报；支持启停、最低级别、连通性测试、投递历史及失败重试。通知使用持久化队列、租约和有限重试；停用通知不影响报告归档。见[通知渠道](NOTIFICATIONS.md)。
- **分渠道通知模板**：新增飞书、Telegram 按事件管理的模板 API，支持纯文本/受限 HTML、草稿、发布、历史恢复、变量目录和在线预览。测试发送可以使用未保存模板，返回投递 ID 并查询状态；入队不等于发送成功。补充邮件模板通知状态的预览和测试。见[通知模板](NOTIFICATION_TEMPLATES.md)，相关 [#113](https://github.com/wshijiang/network-mapping/pull/113)、[#115](https://github.com/wshijiang/network-mapping/pull/115)。
- **每渠道通知代理**：邮件、飞书和 Telegram 可独立选择系统默认、直连或自定义 HTTP/HTTPS/SOCKS5/SOCKS5H 代理，代理凭据加密存储；邮件支持代理隧道内的 SMTPS，连接失败不回退直连。见[通知代理](NOTIFICATIONS.md#每渠道投递代理)，相关 [#116](https://github.com/wshijiang/network-mapping/pull/116)。
- **可选登录人机验证**：密码登录前支持 Cloudflare Turnstile，默认关闭；提供公开配置接口和管理员配置 API，设置持久化、Secret 加密，支持版本冲突检查和多实例读取权威配置。启用后须校验单次证明的成功状态、hostname 和 `action=login`，外部验证失败或超时会停止本次登录。见[登录人机验证](HUMAN_VERIFICATION.md)。
- **操作系统识别**：复用扫描器已有服务握手证据，异步推断端点系统线索并生成资产摘要，提供证据、置信度、冲突和过期标识；支持 `os.*` / `service.os.*` 搜索及经审批的外部 API `os` 摘要，不增加目标请求。见[操作系统识别](OS_DETECTION.md)。
- **Web 技术识别**：基于已有 HTTP/HTTPS 响应识别 52 种技术（86 条内置规则），提供组件、版本、证据、冲突与完整性状态；支持 `tech`、`web.status`、端点关联搜索及经审批的外部 API `web` 摘要。识别由服务端执行，不下载额外资源、不运行网页脚本；结果代表 IP 端点视角。见[Web 识别](WEB_DETECTION.md)和[技术目录](WEB_TECHNOLOGY_CATALOG.md)，相关 [#112](https://github.com/wshijiang/network-mapping/pull/112)。
- **证书透明度域名发现**：通过 crt.sh 查询种子域和后代，可补充证书完整 DNS SAN 及同证书关系；后台作业支持配额、缓存、租约恢复和部分结果标记，证据按用户隔离。选中具体域名后复用现有 `dns_records` 任务进行 DNS 验证，证书关系不作为资产归属或存活证明。见[域名发现](DOMAIN_DISCOVERY.md)，相关 [#116](https://github.com/wshijiang/network-mapping/pull/116)。

### 行为变更与修复

- **DNS 改用共享域名排除策略**：`dns_follow_up.excluded_domains` 统一作用于手工、搜索生成及 OpenAPI DNS 任务，与解析后 IP 扫描开关独立。精确项只排除该域名，`*.example.com` 排除各级子域、不含根域；混合批次命中排除项会整批拒绝，已运行任务在后续心跳接收取消指令。旧域名白名单迁移会关闭域名搜索生成，需管理员检查后重新启用。见[域名排除与升级](SEARCH_TARGET_GENERATION.md#域名排除与升级)。
- **Turnstile 域名匹配**：允许配置域及其各级子域，按域名标签边界匹配，修复合法子域登录失败；旧允许域的适用范围随升级扩展至其后代，需要收窄时配置具体登录域。登录保护管理操作同时纳入监控。见[登录保护配置](HUMAN_VERIFICATION.md#部署与启用)。
- **通知可靠性与兼容**：修复过期通知清理、共享冷却、维护中途暂停领取、旧扫描器邮件与自动报告队列迁移、历史掉线回执保留。缺少可导入 SMTP 时保留旧队列，之后配置首个有效邮件渠道可接管，不重复发送已成功收件人。见[通知升级说明](NOTIFICATIONS.md)。
- **识别证据保留与回填**：系统识别保留各个冲突家族及旧证据，避免无必要的强制刷新；Web 识别支持旧端点证据回填，拒绝歧义 HTTP 响应，避免将不确定证据附到错误端点。历史回填不能恢复此前未采集或已丢失的内容。相关 [#114](https://github.com/wshijiang/network-mapping/pull/114)。
- **本机 HTTP 与 Docker 部署**：新增 `tls.enabled=false`，只允许回环 IP 监听，默认仍启用 TLS；提供 Linux host 网络和宿主机数据库部署示例，健康检查自动匹配 HTTP(S)、地址及端口，并保留证书校验。标准 bridge 端口映射不能用于访问容器内回环 HTTP 监听。见[Docker 部署](DOCKER.md)和[配置参考](DOCKER_CONFIGURATION.md)。
- **存储就绪探针**：新增无需登录的 `GET/HEAD /healthz`，根据后台缓存的 PostgreSQL 与 Elasticsearch 就绪状态返回 200 或 503，响应不暴露依赖详情；Docker 健康检查及可选覆盖配置改用该探针。
- **版本检查**：CSP 放行 GitHub 版本检查所需连接，修复控制台版本检查被服务端策略拦截。

### 部署、文档与依赖

- 完善原生安装、systemd、Docker 配置来源、环境变量与升级指南；新增 MkDocs 文档站、按任务分组的导航及仓库源码链接转换钩子。见[文档维护](DOCUMENTATION.md)。
- 更新锁文件中的 `rustls` 至 0.23.45，增加识别、证书解析和通知代理所需依赖；MkDocs Material 更新至 9.7.7。
- 更新发布工作流的 `actions/upload-artifact` 至 v7，新增系统识别工作流，Dependabot 目标分支切换为 `main`。

### 升级与兼容注意

1. **备份并安排服务端切换**：保留 PostgreSQL、Elasticsearch 数据及原有 `server.encrypt_key`。通知队列迁移前先停止所有旧后端实例，迁移后只运行新版，避免旧 worker 与新队列并行投递。
2. **启动自动执行幂等数据库迁移**：包括通知、模板、代理、OS/Web 派生队列、DNS 排除策略与域名发现。服务端还会补充 ES 识别字段映射并在后台回填历史成功执行；扫描完成不代表派生识别已完成。迁移入口见 [数据库初始化实现](../src/db/mod.rs)。
3. **核对运行策略**：旧 `authorized_domains` 不会转换为排除项；升级会关闭域名搜索生成。先配置排除范围，再决定是否重启该功能；OpenAPI 应用自身授权范围继续生效。
4. **部署配套控制台后启用登录保护**：已有登录请求在保护关闭时继续兼容；开启后，旧客户端缺少证明不能登录。已存数据库配置不会被启动文件或环境变量覆盖。新增 `os`、`web` 外部 API 字段须单独审批，已有应用不会自动取得权限。
5. **按需升级扫描器**：服务端识别可处理现有上传协议；新扫描器能改善超大握手系统字段的保留并传递 HTTP 正文截断标识。已丢失证据需重新执行服务识别任务，不能依靠回填补全。
6. **准备新功能出站访问**：启用 Turnstile、crt.sh 发现或通知渠道时，分别核对服务端对应 HTTPS/SMTPS 出站连通性；域名发现还需在线且支持 `dns_records` 的扫描器。保留 TLS 校验。
7. **回退前停用不兼容能力**：尤其是新增邮件/Telegram 渠道、自定义通知代理及域名自动生成，并按专题恢复配套配置和前端。保留新增表、列和加密主密钥；不能假设旧 worker 能理解新渠道或遵守代理配置。

本节记录代码变动与升级影响，不代表真实通知服务、Cloudflare、crt.sh 或扫描目标已经完成部署联调。
