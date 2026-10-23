# DNS、DoH、DoT 与 VNC 服务识别扩展计划

[文档中心](README.md) · [服务探测分批计划](SERVICE_DETECTION_ROADMAP.md) · [DNS 测绘](DNS_MAPPING.md)

规划日期：2026-10-23（北京时间）。A 批次的 DNS TCP/VNC 已接入并完成本地验证，操作与兼容说明见[扫描流水线](SCAN_PIPELINE.md)；B/C 及后续工业批次仍待实现，尚未部署或完成真实产品验收。

后续 Modbus TCP、EtherNet/IP、S7、OPC UA、MQTT/MQTTS 与 BACnet/IP 见[工业与物联网服务识别扩展计划](INDUSTRIAL_SERVICE_DETECTION_PLAN.md)，继续复用本文的统一编排、协议端点迁移和前端样式，追加 D/E/F 批次。

## 目标与规划时基线

目标是在扫描节点完成协议确认，并贯通任务、能力协商、结果上传、资产搜索、历史、统计、导出和控制台展示。DNS 同时覆盖 TCP 与 UDP；DoH 首批覆盖 HTTPS 上的 RFC 8484 二进制 DNS；DoT 覆盖 TLS 上的 DNS；VNC 覆盖 RFB 协议识别。

以下为实施前的基线，A 批次已增加 DNS/VNC 探测、显式任务选择和前端展示，其余限制按后续批次处理：

- 扫描端 `src/scan/detection.rs` 的 `ProbeKind` 没有 DNS、DoH、DoT、VNC；`unique_tcp_endpoints` 仅接受 TCP，853 默认映射为通用 TLS。
- `src/udp_probe.rs` 已有 DNS UDP 请求、解析和回环测试，但未接入任务、CLI、能力、全局限速与持久化。现有 `dns_lookup` / `dns_records` 是域名解析任务，不能据此宣称发现了目标 DNS 服务。
- `src/scan/engines/zgrab2.rs` 负责现有分块调度、恢复和证据聚合；`src/modules/worker.rs` 的服务阶段直接调用它。不能只在枚举中加名称就把新模块交给 zgrab2。
- 服务端 `src/elasticsearch.rs` 的执行端点 ID，以及 `src/elasticsearch/projection.rs` 的当前端点 ID，均未包含传输协议。开放 UDP 前必须迁移，否则同 IP 同端口的 TCP/UDP 会相互覆盖。
- VNC 已有 Nuclei 选择规则和 5900 端口回退，但这属于漏洞模板选择，不是 RFB 服务确认。
- 前端已有 Tailwind CSS 4、daisyUI 5、明暗主题及搜索、任务详情、资产详情共享的样式约定，无需新增 UI 框架。

## 协议范围与判定

下表中的端口只用于安排探测，不是确认依据。非标准端口通过明确目标配置或有预算的回退探测支持。

| 服务标识 | 传输与常用端口 | 确认条件 | 首批边界 |
| --- | --- | --- | --- |
| `dns` | TCP/53、UDP/53 | 有效 DNS 响应，事务 ID、QR、Opcode、原始问题匹配；TCP 还须通过两字节长度分帧校验 | 复用根 SOA、RD=0；不做 AXFR、ANY、递归开放测试或软件版本猜测 |
| `dot` | TCP/853 + TLS | TLS 建连后，收到分帧正确且与请求关联的 DNS 响应 | TLS 握手、证书名称、ALPN 或端口本身不足以确认 DoT；不包含 DoQ |
| `doh` | TCP/443 + HTTPS，默认路径 `/dns-query` | HTTP 成功响应、正确的 `application/dns-message` 媒体类型及有效关联 DNS 消息 | 默认 POST；GET 作为显式选项并计入预算；不包含供应商 JSON API、HTTP/3 或任意路径枚举 |
| `vnc` | TCP/5900，常见显示号端口由任务明确给出 | 完整合法的 12 字节 RFB 版本问候；可按支持的版本继续确认有界安全类型协商 | 不尝试认证、不提交口令、不进入桌面会话或采集屏幕；不将 RFB 版本当作软件版本 |

合法且关联的 DNS REFUSED/NXDOMAIN/SERVFAIL 响应可以证明协议存在，但不证明目标可递归解析。DoH 的普通网页、单独的媒体类型、401/403/404 和不匹配 DNS 正文均不足以确认服务。RFB 的合法服务端问候可作为协议证据，只有进一步收到安全类型信息时才展示该信息；不据此自动判定未授权访问漏洞。

DoH 的域名、路径和 SNI 来自任务明确携带且经过校验的目标上下文；IP-only 探测只能说明该 IP 默认虚拟主机的结果。连接固定到任务内目标 IP/端口，保留合法的 Host/SNI，不因域名重新解析或重定向扩大范围。关闭自动重定向、环境代理继承及无限重试；自定义路径数量、长度及报文体均受预算限制。

TLS 默认验证证书，支持明确配置的受信 CA。证书不可信、名称不匹配、mTLS 需求和握手失败分别保留原因；失败不能仅凭端口确认加密 DNS。若后续需要采集自签名服务，必须提供单独、显式的探测策略并标明证书未验证，不复用或放宽 Agent 到控制端的 TLS 策略。

## 扫描端架构与证据

1. 在现有 `service_detection` 阶段抽出统一编排，保留 zgrab2 适配器，为 DNS TCP、DoT、DoH、VNC 增加原生 Rust 适配器。DNS UDP 复用现有库。实施前核对项目实际依赖版本与固定 zgrab2 提交；通过 Context7 查询依赖 API 后再确定 TLS/HTTP 接入，不假定外部引擎支持未验证模块。
2. 抽出共享 DNS 查询构造与响应校验，复用 UDP 的随机事务、问题关联、长度/记录数量限制。TCP/TLS 必须正确处理分片读取、长度前缀、提前 EOF、超大响应与绝对截止时间；DoH 在相同校验器前增加 HTTP 状态、媒体类型及响应体大小校验。
3. `standard` 在 TCP/53、853、5900 选择对应探测；443 先保留 HTTPS 行为，仅在启用 DoH 策略或明确端点配置时尝试 DoH。`adaptive` 为新增协议分配有界回退预算；在 853 的应用探测完成前，通用 TLS 成功不能提前结束；HTTP 成功也不能跳过已安排的 DoH 验证。`exhaustive` 执行当前启用且适用的模块，仍受总时间、字节及取消约束。
4. 探测连接数、TLS/HTTP 重试、每 IP 和全局速率使用同一预算，不给原生适配器另开无限连接池。策略默认值和新增配置的上下限必须同时更新本地配置、服务端远程配置、Worker DTO 与节点能力；未启用 UDP 时不发送 UDP 报文。
5. DoH 确认后选 `service=doh`，传输仍为 `protocol=tcp`；DoT 选 `dot`。明确具体应用优于其 HTTPS/TLS 包装，避免现有同分候选冲突规则把 DoH+HTTPS 判成未知；无关协议的同等证据仍保留冲突，不靠端口强行裁决。
6. DoH 保留必要的 HTTP 响应元数据和 TLS 证据，DoT 保留 DNS 与 TLS 证据。同步服务端 HTTP/TLS 证据提取、OS/Web 推断及 Nuclei 选择：`doh` 不能变成非 Web，也不能落入不限协议的模板扫描。没有对应模板时明确未覆盖。
7. 新结果记录真实适配器来源，不统一伪装为 `zgrab2`。沿用结构化 service observation，并明确证据 schema 的兼容读写；保存协议、匹配结果、DNS RCODE/必要标志、DoH 方法/路径、RFB 协议版本及实际获取的安全类型。原始 DNS 回答、桌面名和大体积正文不作为默认摘要存储。
8. 未应答、取消、预算耗尽、证书失败与协议不匹配分别记录探测状态；不得用这些结果覆盖已有成功服务，也不得把未确认解释为端口关闭。截断数据不足以完成协议校验时保持未确认。

原生适配器必须贯通进程内与 Worker 路径、阶段期限、取消、租约丢失、分块 ACK、检查点和重启恢复。检查点绑定实际策略及模块 generation；不把新旧证据 schema 混合恢复。若现有上传/计划版本不能表达新增状态或传输，先完成版本协商，再开放对应任务。

## 服务端与兼容迁移

- 新增服务能力集合与协议版本声明，缺失字段按旧能力处理；要求新协议的任务在估算、自动/指定节点分配、重领和恢复中均排除不支持的节点。域名解析能力不等于 DNS 服务探测能力。
- TCP 扩展沿用现有端点身份可先交付；DNS UDP 复用分批计划第二批的结构化 `port_sets` 和能力协商，不通过 `U:` 字符串绕过现有校验，也不要求 UDP 候选先被 TCP masscan 命中。
- UDP 开放前将执行端点、当前资产、endpoint_key、证据引用、分页排序/游标、历史、去重及关联 ID 纳入传输协议；同步范围权限、统计、报告、CSV、开放 API 和自动刷新链路。
- 采用新版本投影和可回滚切换，从原始 observation 重建并核对计数及同端口隔离。缺失历史传输信息保持未知，不以默认值批量推断 TCP。原始证据丢失时明确需要重扫。
- 保持旧任务端口字段的 TCP 语义；旧 Agent 不接收其不能表达的新任务。关闭新协议策略不删除原始观察、待上传批次或已提交检查点。
- 加密 DNS/VNC 首批只新增服务识别，不自动宣布支持递归测试、未授权访问检测或新的 Nuclei 覆盖范围。

## 前端交互与样式

沿用 `src/style.css`、`docs/theme-guide.md` 和现有页面结构；统一使用 daisyUI 的 `card`、`input`、`select`、`toggle`、`badge`、`table`、`alert`、`modal` 和 `btn`，配色使用 `base-*` 与语义状态色，图标使用现有 Lucide、`currentColor`。不引入另一套样式或单独硬编码亮色外观。

| 页面 | 计划调整 | 验收重点 |
| --- | --- | --- |
| `src/views/createscan.vue` | 在已有服务识别模式内配置目标协议、DoH 路径与可选域名上下文；UDP 发布后再展示 TCP/UDP 端口集合 | 能力不足的节点不可选择；新 DNS 服务选项与现有 DNS 解析器设置分开；保留草稿、校验和错误反馈 |
| `src/Search.vue` | 服务列共享展示 DNS、DoH、DoT、VNC，补充当前可用的搜索示例 | UDP 上线后显示 53/TCP、53/UDP；确认服务与未完成探测状态不能混淆 |
| `src/views/taskdetail.vue` | 复用现有表格，提供有界协议证据摘要与展开详情 | DoH 展示 HTTPS 包装，DoT 展示 TLS；RFB 版本标为协议版本 |
| `src/views/AssetDetail.vue` | 复用历史 modal、服务过期提示与详情布局 | 新结果与历史分别标明时间和传输协议；失败不掩盖既有成功证据 |
| `src/views/ScannerDetail.vue`、`src/views/ScannerConfiguration.vue` | 显示实际服务能力、策略及生效配置 | 区分未安装、未启用、配置未生效和协议未确认；旧节点正常展示 |

服务徽标和证据摘要提取为共享组件/工具供三处结果页面复用，沿用现有 `WebTechnologies`、`OsFingerprint` 的字号与展开布局。所有目标返回文本由 Vue 转义；兼容明暗主题、移动端、键盘和焦点状态。DoH 的 HTTP/TLS 信息继续使用既有展示组件，不另造重复卡片。

## 分批交付与验收门槛

以下批次与原有 Elasticsearch/UDP 批次协调推进，不改变原有批次的完成状态。每批同步三仓库中实际受影响的文档和 CHANGELOG，明确库 API、任务端到端和真实服务验收的区别。

| 批次 | 交付内容 | 依赖与完成条件 |
| --- | --- | --- |
| A | 原生适配器编排、能力/证据契约；DNS TCP、VNC 端到端；前端共享服务展示 | Worker/恢复、正常与反例、旧节点调度隔离、搜索/历史/CSV 和文档通过；不开放 UDP |
| B | DoT、DoH 端到端、策略配置、HTTP/TLS 与应用证据共存 | 依赖 A；DNS/TLS/HTTP 联合校验、候选优先级、证书/虚拟主机边界及前端控制项通过 |
| C | DNS UDP 端到端、结构化端口集合、能力协商与协议端点迁移 | 依赖已有分批计划第二批；同 IP 同端口 TCP/UDP 不覆盖，游标/历史/导出/回滚完成后开放 UI |

每批至少包括：

- 协议正反例：错误事务/问题、回显、截断、超限、非法长度、慢速分片、错误媒体类型、普通 HTTPS、伪 RFB 文本及不支持版本；合法 DNS 错误响应不误报解析能力。
- 运行路径：IPv4/IPv6、本地可控 TCP/UDP/TLS/HTTPS/RFB 服务、取消/超时、限速、Worker 崩溃、未 ACK 块重试、部分结果、ACK 后重启和待上传重试。
- 兼容性：旧节点拒绝新任务、旧任务正常执行、已有 TLS/HTTPS 识别不退化、权限隔离、搜索分页稳定、DoH Web/TLS 提取以及 Nuclei 不越界选择。
- UDP 批次额外核对同一 IP/53 的 TCP 与 UDP 并存、历史协议缺失、新旧投影切换和回滚。
- 前端工具/组件测试与生产构建，明暗主题、手机视口、空/失败/受限状态及服务证据文本转义。
- 使用真实受控服务进行独立验收，并分别记录模拟协议、回环和真实服务结果。合成测试通过不等于已部署或线上验收。

Rust 使用 `.cloud` 指定的缓存、`cargo build --locked`、相关 `cargo test --locked`、`cargo fmt --check` 与 `cargo clippy --locked --all-targets`；前端运行受影响的工具/组件测试、`node --test src/utils/*.test.js` 和 `pnpm build`。服务端/扫描端文档执行各自 MkDocs 严格构建。未运行的检查和真实依赖未就绪的项目必须单独记录。

## 文档、工作方式与 Git

实施遵循 `/workspace/.cloud/start-skill.md`：使用现有三个仓库，不新建 worktree；先检查适用 AGENTS.md 和工作区；`source /workspace/.cloud/env.sh` 后复用工具与缓存；CodeGraph 的结论回到源码核对，依赖 API 使用 Context7 核实。环境初始化不得借机修改依赖声明或锁文件；功能确需新依赖时作为独立源码变更说明原因与锁文件变化。

| 仓库 | 实现时核对及更新的文档 |
| --- | --- |
| `Network-Mapping-Scanner` | `docs/USAGE.md`、`MAINTENANCE.md`、`UDP_DETECTION.md`、`MODULE_UPDATES.md`、`recovery.md`、配置示例、`docs/CHANGELOG.md` |
| `network-mapping` | 本计划、`SERVICE_DETECTION_ROADMAP.md`、`SCAN_PIPELINE.md`、`DNS_MAPPING.md`、`SEARCH_SYNTAX.md`、`ELASTICSEARCH.md`、开放 API/配置及迁移说明、`docs/CHANGELOG.md` |
| `network-mapping-vue` | `docs/FEATURES.md`、`WEB_DETECTION.md`、`theme-guide.md`、相关配置/搜索说明、`docs/CHANGELOG.md` |

各仓库现有更新日志位于 `docs/CHANGELOG.md`，不额外创建根目录同名日志。新增专题同步文档首页和已有 MkDocs 导航。规划条目只记录文档补充；实现、验证与发布状态按实际完成情况更新，不提前列为已支持功能。

Git 写操作以命令级配置或仓库局部配置设置 author/committer 为 `wshijiang <111570850+wshijiang@users.noreply.github.com>`，不修改全局身份。按批次组织可独立审查的变更；远程提交、PR 和部署按用户授权执行。本次规划不执行发布。
