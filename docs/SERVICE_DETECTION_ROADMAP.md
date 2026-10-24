# 服务探测分批交付计划

[文档中心](README.md) · [Web 识别](WEB_DETECTION.md)

本计划覆盖 Elasticsearch HTTP/HTTPS/原生 TCP Transport 和 UDP 服务识别。每批独立提交和评审，状态以对应实现与验证记录为准。

DNS TCP/UDP、DoH、DoT 与 VNC 的新增范围、原生探测编排、证据契约、前端 daisyUI 适配和分批验收见 [DNS 与 VNC 服务识别扩展计划](DNS_DOH_DOT_VNC_PLAN.md)。该专题 A/B/C 基础范围已接入，详见[当前支持与部署](SERVICE_PROTOCOLS.md)；UDP 采用独立 profile 而非混合 port_sets。

后续新增 Modbus TCP、EtherNet/IP、S7、OPC UA、BACnet/IP 及已有 MQTT/MQTTS 补强见[工业与物联网服务识别扩展计划](INDUSTRIAL_SERVICE_DETECTION_PLAN.md)。区分 TCP 握手、UDP 单播发现与 PubSub/I/O 被动观察；D/E 基础握手与单播发现已接入，F 为有限的 IPv4 被动接收；完整抓包及产品验收仍需后续扩展。

| 批次 | 交付范围 | 完成条件 | 当前状态 |
| --- | --- | --- | --- |
| 1 | Elasticsearch REST 被动指纹；DNS/NTP/STUN UDP 库内核；前端数据库标签 | 协议反例、HTTP/HTTPS 证据与 UI 测试通过，文档和 CHANGELOG 同步 | 首批已完成；NTP/STUN 保持库 API |
| 2 | UDP 端到端任务、能力协商、端点迁移、查询与 UI | 同一 IP 的 TCP/UDP 同端口互不覆盖；旧节点不领取 UDP；可恢复与回滚 | 基础范围已实现；混合任务/域名继承仍待扩展 |
| 3 | Elasticsearch 原生 Transport 明文/TLS | 有界协议确认；兼容实现区分；mTLS 受限状态；Worker 与恢复验证 | 待实现 |
| 4 | 其余 UDP 协议 | 逐协议解析器、事务关联、速率和真实服务验收 | 待实现 |

## 第一批的实际行为

服务端复用已有 zgrab2 HTTP/HTTPS 响应。`X-Elastic-Product: Elasticsearch` 可证明产品响应特征，但不提供版本，也不等于无需认证。完整 JSON、JSON 媒体类型、固定 tagline、明确版本、Lucene 版本及构建哈希共同支持根响应识别。明确 OpenSearch 分发标识或 tagline 不归为 Elasticsearch；正文提及产品、通用 401 和端口号均不足以识别。

`service` 保持 http/https，新增 `web.technologies[].id=elasticsearch`，查询使用 `tech = elasticsearch` 或 `tech = "elasticsearch@8.19.0"`。规则修订 6 通过现有队列触发历史证据回填，不修改原始观察、checksum 或权限。原始响应缺失或被截断时不能补出版本。前端使用现有共享技术标签、daisyUI 徽标和 Lucide 通用数据库符号。

扫描端的 `udp_probe` 是独立库 API，仅含定向 DNS/NTP/STUN 请求与解析。该独立 API 保留；另有原生 UDP 引擎将 DNS、EtherNet/IP、BACnet 接入任务，NTP/STUN 仍仅为库 API。协议测试和本地回环测试不能代替端到端 UDP 验收。

## 第二批：先修正协议身份，再开放 UDP

1. 新任务增加结构化 `port_sets`（protocol + ports）；旧 port 保持 TCP 语义。校验范围、去重和混合任务，不直接拼接用户提供的引擎参数。
2. 节点上报 UDP 引擎、协议集合和任务版本，调度、指定节点、重领及恢复均拒绝不兼容节点。域名子任务继承协议和策略。
3. 当前执行端点 ID、当前资产端点 ID 和 endpoint_key 只含 IP/端口，必须加入 tcp/udp。权限作用域、分页游标、服务证据引用、OS/Web 派生回填、统计、报告和 CSV 同步调整。
4. 采用新版本投影、从原始 observation 重建、校验和切换；保留旧投影回滚。历史协议缺失时标未知，不将全部旧记录推成 TCP。重建不能恢复已丢失的原始证据。
5. UDP 引擎直接处理任务指定候选，不以 masscan 命中为唯一入口。只有匹配的响应证明 open；超时为未确认/open_or_filtered，可关联 ICMP 才用于 closed/filtered。
6. 全局/每 IP 报文速率、并发、重试和字节预算统一执行；局域网组播、凭据型探测分开配置。未知尝试不覆盖此前成功服务。
7. 创建页采用现有 daisyUI 控件；端点显示 53/TCP、53/UDP，区别端口状态与服务判定。Nuclei 未覆盖 UDP 不表示已检测无漏洞。

## 第三批：Elasticsearch 原生 Transport

用独立 Rust 探测器支持明文及 TLS 包装，不把未接入的模块交给 zgrab2。验证 Transport Ping 与必要协议确认，排除回显等反例；端口开放、TLS 握手或证书名字都不足以确认 Elasticsearch。仅有兼容协议证据时显示 Elasticsearch 兼容 Transport，不推断产品版本；客户端证书要求导致的中止保持受限状态。不得加入集群或读取索引。新调度必须覆盖进程内、Worker、任务期限、取消及检查点路径。

## 第四批：UDP 协议顺序

- 常用请求/响应：SNMP、NBNS、RPCbind、TFTP、SQL Browser、Memcached、SIP、CoAP。
- 扩展：QUIC/HTTP3、IKE、DTLS、SSDP、mDNS、LLMNR、CLDAP、RMCP/IPMI、NFS。
- 专项：BACnet、RADIUS、有配置的 VPN、局域网 DHCP/被动 Syslog；无应答协议不能靠端口或超时认定产品。

## 每批验收与提交

使用 /workspace/.cloud/start-skill.md 的现有仓库、工具和缓存，不新建 worktree。Rust 使用锁文件构建、相关测试、fmt 和 clippy；前端运行工具/组件测试与生产构建。真实 Elasticsearch/PostgreSQL 联调、合成协议测试及回环测试分别记录。新增专题同步文档索引和 MkDocs，更新各仓库 CHANGELOG。Git author/committer 使用 wshijiang <111570850+wshijiang@users.noreply.github.com>；按批次开 PR，不自动合并或部署。
