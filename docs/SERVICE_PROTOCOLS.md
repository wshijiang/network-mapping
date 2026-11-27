# 服务协议识别与部署

本次扩展覆盖 DNS（TCP/UDP）、DoH、DoT、VNC，以及 Modbus TCP、EtherNet/IP、经典 S7comm、OPC UA、MQTT/MQTTS 和 BACnet/IP。端口用于选择探测目标，确认依赖协议响应或明确标记的被动证据；不会仅凭端口推断厂商、产品或漏洞。

## 支持矩阵

| 服务标识 | 传输 / 常用端口 | 本次实现与边界 |
| --- | --- | --- |
| `dns` | TCP/53 | 根 SOA、RD=0；长度分帧、随机事务与原始问题匹配，合法拒绝也可确认协议 |
| `dns_udp` → `service=dns` | UDP/53 | 独立 UDP 任务；连接式来源过滤及相同 DNS 校验 |
| `dot` | TCP/853 + TLS | 验证证书后进行 DNS 分帧和请求关联 |
| `doh` | TCP/443 + HTTPS | 默认 POST `/dns-query`，校验 200、媒体类型及 DNS 正文；关闭重定向、代理继承和自动重试 |
| `vnc` | TCP/5900 等 | 只接收合法 RFB 003.003 / 003.007 / 003.008 问候，不认证或进入桌面 |
| `modbus` | TCP/502 | 由固定版 zgrab2 执行 Read Device Identification 0x2B/0x0E；适配器匹配事务、Unit ID、功能及标识对象。每个引擎进程使用随机请求 ID；关联异常仅确认协议，不保证可采集设备标识。遵守 zgrab2 blocklist，镜像默认列表包含 RFC 1918 地址，内网探测需部署方按授权配置 |
| `enip` | TCP/44818 | 有界 ListIdentity；校验 SenderContext、封装长度及身份条目 |
| `enip_udp` → `service=enip` | UDP/44818 | 单播 ListIdentity，校验来源及 SenderContext；不广播或建立 I/O 连接 |
| `s7` | TCP/102 | TPKT/COTP + 经典 S7 Setup Communication；匹配 PDU 引用，不读取过程数据。S7comm Plus 不在范围内 |
| `opcua` | TCP/4840 等 | HEL/ACK 或结构合法的 ERR；不建立 SecureChannel 或应用会话 |
| `mqtt` / `mqtts` | TCP/1883 / TLS 8883 | 原生有界 CONNECT/CONNACK，支持显式 MQTT 3.1.1 / 5.0；保存合法认证拒绝，成功后断开。不订阅、发布或设置 Will |
| `bacnet` | IPv4 UDP/47808 等 | 单播 Who-Is / I-Am，严格校验 BVLC、NPDU、对象及字段；无事务 ID，按来源与窗口关联，不保证因果关系。不支持 BBMD、广播、BACnet/IPv6 或 BACnet/SC |
| `enip_io` | IPv4 UDP/2222 等 | 被动接收 CPF Sequenced Address + Connected Data，校验连接标识与长度；只识别帧格式，不证明会话有效或端口开放 |
| `opcua_pubsub` | IPv4 UDP/4840 等 | 被动接收 UADP v1 DataSet NetworkMessage，要求 Publisher/WriterGroup/Payload 标头及结构完整的 Variant keyframe。支持有界标量；加密/签名、分块、RawData、DataValue、数组、增量帧和复杂 Variant 暂不确认 |

所有已实现 TCP 服务均纳入自动识别候选，包括工业协议；用户无需预先选择服务名称。端口只决定探测顺序，确认仍依赖合法响应。MQTT 原已有协议名称，本次替换为可验证版本、认证拒绝及 TLS 的原生握手。EtherNet/IP 不等同于罗克韦尔产品；OPC UA UDP 是 UADP PubSub，与 TCP HEL 识别独立。

## TCP 任务

`POST /api/task/create` 和 `/api/task/placement-preview` 支持 `service_probe_options`。TCP 使用既有 `service_inventory` / `vulnerability_scan`，plan v1；默认省略或留空 `required_services`，自动识别全部已实现协议。旧 API 非空 `required_services` 仍可限制探测范围，创建页不再要求选择协议。必需阶段执行完整即可完成任务，不要求所有目标识别成功。

节点默认采用 adaptive：按端口线索执行应用握手及 Banner/TLS/HTTP(S)，再用剩余预算回退；工业 TCP 502/44818/102/4840、DNS/DoT、VNC、MQTT/MQTTS 均有端口映射。HTTPS 常用端口会尝试 DoH；非标准端口发现 HTTPS 后，预算允许时细分 DoH，合法完整 RFB 问候可直接确认 VNC。standard 保留端口优先探测（HTTPS 同时确认 DoH），exhaustive 尝试所有支持的 TCP 模块，包括工业协议。非标准端口覆盖受策略、预算和期限限制，不保证每个端点都执行全部握手。

```json
{
  "ip": "192.0.2.53", "port": "443", "level": 1,
  "scan_profile": "service_inventory",
  "service_probe_options": {"server_name": "dns.internal", "doh_path": "/dns-query"}
}
```

TLS 的 `server_name` 仅控制 Host/SNI 与证书名校验，实际连接固定到任务 IP/端口，不重新解析或跟随跳转。默认信任系统 CA，可用 `tls_ca_pem` 增加公开 CA（最多 64 KiB，拒绝私钥）；不提供跳过校验模式。TLS 失败保留诊断类别，不能据此确认应用；当前不细分所有 mTLS 与证书错误。

其他选项：`modbus_unit_id` 为 0–255（默认 1）；`s7_tsap` 为 0–65535（默认 258 / 0x0102，仅一组 TSAP）；`mqtt_version` 为 4（默认，MQTT 3.1.1）或 5。自动识别可直接配置上述参数，不限制候选协议；旧 API 使用非空协议列表时，参数仍需匹配该列表。DoH 路径最多 256 字节，只支持单一路径 POST，不含 GET、JSON DNS API、HTTP/3、DoQ 或路径枚举。

## UDP 主动任务

UDP 使用 plan v2，结果仍为上传协议 3；与 TCP 分开创建任务，当前不支持同一任务混合 TCP/UDP 或自动域名后续任务。服务端启动初始化更新任务 profile 约束；升级部署须同步程序随附的数据库初始化 SQL。`udp_inventory` 自动识别其支持的全部协议，无需手动勾选；服务端将规范化的默认集合写入 plan，预览、创建、调度与恢复共用此集合。默认 DNS、EtherNet/IP、BACnet/IP；经典 BACnet/IP 仅适用于 IPv4。旧 API 非空列表仍可限制范围。最多 256 个单播目标地址、最多 32 个明确端口，不使用隐式全端口扫描。

```json
{
  "ip": "192.0.2.53", "port": "53", "level": 1,
  "scan_profile": "udp_inventory"
}
```

主动任务串行执行，受阶段累计期限、每目标超时、取消及速率限制；上限为节点配置与 5 次/秒中较小值，每请求最多接收 32 个不匹配报文，每报文最多 8192 字节。一个目标/端口完成后保存 ACK 检查点；恢复从下一端点继续。无有效响应不生成开放/关闭观察，也不产生伪造的成功服务。

早期的 `udp_passive` 被动接收模式（EtherNet/IP I/O、OPC UA UADP）已随扫描模式收敛下线：创建接口拒绝该 profile，`service_probe_options` 不再接受 `passive_*` 字段，节点不再声明 `opcua_pubsub` / `enip_io` 协议能力。数据库 profile 约束与心跳能力校验仍容忍这些历史取值，保证存量任务行与滚动升级期间的旧节点心跳不受影响；历史被动结果（`source=passive_udp`）只读展示，不参与新任务。

## 能力、显示与兼容

节点上报 `service_protocols`、`max_service_probes`、`plan_versions=[1,2]` 和所启用的 profiles。创建、预览、路由偏好、领取、重领和恢复均校验所选协议及单端点探测预算；旧节点缺失字段时不能领取新协议任务。UDP 任务仍走现有 `service_detection` Worker、阶段错误策略和持久化链路。

Worker IPC 升为 **3**。升级时先暂停分配并排空旧 generation 的任务和检查点，再配套升级 Agent、Worker 与完整 IPC 3 模块包。不得混用旧 Worker 或通过删除状态库绕过预检。plan v1 与上传协议 3 保持兼容，新增 UDP 任务要求 plan v2；SQLite schema 不变。

前端沿用现有 daisyUI 的表单、badge 和 details；任务创建默认自动识别，移除协议勾选，TLS/SNI、DoH 路径、Unit ID、TSAP 与 MQTT 版本集中在可折叠的高级参数内。显示协议证据、MQTT 认证拒绝及被动来源，动态字符串按文本转义。资产历史按 IP/端口/传输协议过滤，表格键区分 TCP/UDP。

## 存储升级与回滚

端点身份改为 IP + 端口 + `tcp`/`udp`/`unknown`，执行和用户/global/API client 范围均包含传输协议；分页、OS/Web 补全及历史查询同步处理。历史缺失或无法确定的传输保持 `unknown`，不补猜 TCP。不可变扫描事实和上传校验和不重写。

默认执行投影为 `network-mapping-execution-endpoints-v2`，当前投影为 `network-mapping-endpoints-current-v3`。执行重建前停服，保持 observation/DNS 索引名不变。**必须显式指定 `--rebuild-transport-mode`，没有默认模式**；遗漏、无效或重复指定模式会在连接数据库之前由 CLI 拒绝。

迁移到新索引：在配置中填写全新的 execution/current 索引名，保留旧索引供回滚。

```sh
network_mapping_server --config config.toml --rebuild-transport-endpoints --rebuild-transport-mode new-index
```

原地重建：使用配置中的 execution/current 索引名称。对已存在的两个旧投影先添加写入块并分别克隆到 `transport-rebuild-backup-<运行 ID>-execution`、`transport-rebuild-backup-<运行 ID>-current`，等待备份主分片可用、冻结备份写入并持久化备份 UUID，**两个备份均完成后才删除旧投影**，再以相同名称创建并重建。备份失败时旧投影不会删除；只读备份索引不会自动删除，保留供人工检查或恢复。克隆要求源索引为 green 且有足够磁盘空间，不满足时命令会失败。原始 observation/DNS 索引不删除。中断期间需要继续停服，用同一模式续跑。存在未完成的原地重建时，普通服务启动会提示续跑并退出，避免使用半成品投影。

```sh
network_mapping_server --config config.toml --rebuild-transport-endpoints --rebuild-transport-mode in-place
```

两种模式重建的内容相同。能修改配置并接受新索引名时优先用 `new-index`：旧索引原样保留，也无需克隆备份。`in-place` 只用于必须维持原配置名称的情况；它需要额外克隆和磁盘空间，随后会删除原名索引，旧数据保存在备份索引中。

完成后按需重建分析快照：

```sh
network_mapping_server --config config.toml --rebuild-analytics-snapshots
```

重建持有与服务互斥的存储锁，按 PG 中的 IP 执行读取 ES 现存事实并重建 execution/current 投影，PG 提供任务归属、执行状态和当前标签。**不做 PG/ES 数据对账**：不读取上传回执，不比较 PG/ES 总数、批次数量、事实校验和或数据指纹。历史回执、附带 DNS 批次、过期回执引用和校验和差异不会阻断重建。ES 数量仅用于进度显示，实际重放持续到分页结束，不以预计数量作为停止或失败条件。若原始事实缺失，新投影可能少于旧投影；`in-place` 的旧投影仍保存在备份索引中，可用于人工检查或回退。

断点记录重建模式、运行 ID、原地重建前的目标 UUID、备份 UUID、源集群/索引 UUID、进度参考数量、目标 UUID，以及各执行重放/发布页和标签页游标。**中断后重新运行相同配置和命令即可自动恢复**，无需手动指定游标。Bulk 全部动作确认后才保存页断点；确认前中断的页会幂等重放。恢复时先等待同一运行遗留的 ES 写请求结束；源索引、备份或目标身份改变会拒绝续跑。未完成运行必须使用原模式续跑，不能在迁移和原地重建之间切换。原地模式先持久化旧目标身份和备份身份再删除，删除/创建之间中断仍可恢复，已创建的新目标不会在续跑时再次清空。旧版仅含 `last_execution_id` 的断点不能续用：可以选择 `new-index` 使用全新目标，或显式选择 `in-place` 从头重建配置中的目标。`new-index` 已完成运行重复执行不再切换或重排 outbox；`in-place` 已完成后再次显式执行会启动一次新的原地重建。

重建命令默认使用 32 个独立执行并发、每页 10000 条；可用 `--rebuild-transport-concurrency 50` 调整并发（1–50），用 `--rebuild-transport-page-size 10000` 调整分页（1–10000）。启动时显示实际模式、并发和分页。每批最多 2000 个动作或 16 MiB；不修改正常服务的配置文件或默认参数。进度计数使用 composite 聚合成批统计各执行事实数，执行汇总也并发执行。

当前投影在同一页内对不同端点并发提交 Bulk，单执行内最多保留 4 页待确认（包含已写完但尚未保存断点的页）。等待下一页查询时会持续轮询在途 Bulk，使查询、写入和重试能够重叠；整页成功后按页序推进断点，后页先写完也不能越过前页失败的断点。跨执行仍按执行 ID 顺序发布，保持历史覆盖顺序。

标签扫描使用 PIT 和 `_shard_doc` 顺序读取当前投影，每页一次 PG 查询，仅对变化文档发 Bulk，不逐 IP 执行带刷新的 update-by-query。ES 返回新的 PIT ID 后，后续查询及最终关闭都使用最新 ID；页断点同时保存该 ID，重启后沿用它。PIT 失效或旧版标签游标无法续用时会自动从头重扫（标签补丁幂等），完成标记持久化以避免重复扫描。新目标索引创建时关闭自动刷新（`refresh_interval=-1`），阶段结束显式刷新，切换前恢复 `1s`；全量刷新使用独立的 300 秒请求预算，恢复自动刷新失败可原命令续跑。

终端每 5 秒显示阶段、已确认量/总量、执行信息、速度和有足够采样时的阶段 ETA（参考数量）；续跑前的历史数量不计入本次速度。Ctrl-C/SIGTERM 会等待当前页确认（最多 60 秒），存储锁连接丢失则停止。完成全部重放、发布、标签同步和刷新后，在同一 PG 事务中更新计数、处理投影 outbox、排队 OS/Web 补全并切换运行标记。失败期间保留原运行配置和计数；`new-index` 保留旧索引，`in-place` 保留旧端点投影的独立备份，纯漏洞观察不生成端点 Bulk。重建期间须停止扫描写入、事实保留期清理及 DNS/observation 位置变更。

### 刷新失败与超时排查

`error sending request ... /_refresh` 只是客户端发送请求失败，不能单凭这一行判断超时。新的错误详情包含 `timeout`、`connect`、耗时和底层错误链；重建日志包含执行 ID、已重放观察数和断点进度。`timeout=true` 表示请求期限已到，`connect=true` 表示建立连接失败（连接超时时两者可以同时为 true）。

即使 HTTP 200、`_shards.failed=0`，`{"_shards":{"total":1,"successful":0,"failed":0}}` 也没有成功刷新分片。ES 9.5 的广播复制操作遇到分片不可用时，可以不将其计入 `failed`；迁移现在拒绝把这种响应确认为完成。先在已认证且验证 TLS 的 ES 控制台查询实际目标索引，例如：

```text
GET /_cluster/health/network-mapping-execution-endpoints-v2?level=shards
GET /_cat/shards/network-mapping-execution-endpoints-v2?v=true
POST /_cluster/allocation/explain
{"index":"network-mapping-execution-endpoints-v2","shard":0,"primary":true}
```

将示例索引名替换为错误日志中的目标；只有存在未分配主分片时才对该主分片执行 allocation explain。先解决实际返回的磁盘、分配、恢复或节点问题，再重跑原命令，不删除事实或迁移状态。如果日志仍指向 `execution-endpoints-v1`，核对实际生效配置；旧部署的传输端点重建需要全新 execution/current 目标名，配置中的显式旧值不会自动随默认值升级。

`elasticsearch.request_timeout_seconds` 默认 **30 秒，限制单次 HTTP 请求**，并非整个迁移的总时限。分片健康且确实出现 `timeout=true` 时，可在停服迁移使用的配置中按负载调整，例如：

```toml
[elasticsearch]
request_timeout_seconds = 180
```

对应环境变量为 `NM__ELASTICSEARCH__REQUEST_TIMEOUT_SECONDS`，仅在 `--config-source env` 时使用；`--config-source file` 不会将环境变量合并覆盖文件。Bulk 另受 `bulk_total_timeout_seconds`（默认 25 秒）约束；只增加 HTTP 超时不会增加 Bulk 总预算，也不会修复未分配主分片。失败页不推进断点，重跑会幂等重放该页；已确认的页从持久化游标继续。

若手动 GET 刷新约 1 分钟后返回零成功分片，而程序使用默认 30 秒请求期限，程序可能在 ES 等待分片期间提前超时。GET 与 POST 都受刷新语义约束；应先确认分片状态，不能仅改用 GET 或延长等待便认定迁移成功。

`new-index` 模式回滚需停服并恢复配套旧程序、旧 execution/current 配置和迁移前 PG 运行标记；重建保存的 `transport_endpoints_previous_runtime` 可供核对，但生产回滚以备份及部署变更记录为准。启用 UDP 后产生的新结果须保留，旧程序不能完整展示这些结果，不应回滚后删除新事实。

## 验证范围

测试使用合成响应、本机回环服务和隔离的 PostgreSQL/Elasticsearch 资源；覆盖错误事务/来源/长度、TLS 信任与服务名、错误 DoH 正文/状态/重定向、工业拒绝响应及被动帧格式。真实产品、设备网络、组播环境和线上发布仍需部署方在授权范围验收，不能把局部协议实现称为全版本产品认证。

历史执行记录（2026-10-23）：扫描端全目标测试 217 项常规与 6 项 Worker 进程测试通过；另有 4 项被动接收定向回归通过。前端 152 项工具/组件测试通过，服务端常规测试、PostgreSQL 调度和投影测试的结果随 PR 记录。默认忽略的集成测试不计入常规通过数量。

2026-10-27，修复基线 `5cb0bc82eecec854388cdca1189bb60e1536fc02` 的 [Service evidence inference CI](https://github.com/wshijiang/network-mapping/actions/runs/40498195862) 已通过：使用 PostgreSQL 和真实 Elasticsearch **9.5.4** 验证基础端点重建、投影、服务证据及不可变事实；[重新发布 PR](https://github.com/wshijiang/network-mapping/pull/136) 将 `transport_rebuild::tests` 与 `transport_rebuild::recovery_tests` 都纳入该工作流，覆盖模式选择、原地备份、PIT 恢复及真实 ES 重建。测试创建独立合成资源，不操作生产索引。生产迁移仍须事先备份并按实际配置验收；真实设备网络、浏览器视觉与线上部署不在该 CI 验证范围内。

## 服务产品识别

仓库已有 `service` 协议识别结果、Web 技术栈，以及旧 `c2_fingerprint` 证书线索。产品名称和版本等线索原先保存在协议原始数据、Web 技术栈或专项 C2 结果中；本次增加通用的服务产品结果结构，便于用同一组字段查看和查询本节列出的普通软件声明与 C2 部署候选。

| 字段 | 表达内容 | 示例 |
| --- | --- | --- |
| `service` | 既有应用协议识别结果 | `https`、`tls`、`ssh` |
| `products[]` | 匹配到的产品声明或部署候选，可为空或有多项 | nginx 及其声明版本、疑似 Sliver Multiplayer |
| `product_identification` | 本次产品规则分析的状态、证据完整程度、规则版本和观察来源；另附检测方式及 JARM 记录 | `identified`、`coverage=partial`、原始观察时间 |

已有 Web 技术栈及其 `tech` 查询继续使用原有识别流程，旧 `c2_fingerprint` 保留兼容；本次没有把全部既有技术目录迁入 `products[]`。`products[]` 的具体范围以本节产品表为准。

服务端产品规则只分析已保存的协议观察，不查询 IOC 库、不依赖威胁情报开关，也不自行连接目标。扫描器保留基础补充证据不会增加原有探测请求；后文可选的 JARM 采集会额外发起最多 10 次连接与 ClientHello 探测，默认关闭。

### 当前支持与判断范围

| 产品 ID | 展示名称 | 依据与结果 |
| --- | --- | --- |
| `nginx` | nginx | 首个 HTTP 响应 Server 头声明；`identified`，可提取版本 |
| `apache_http_server` | Apache HTTP Server | 首个 HTTP 响应 Server 头声明；`identified`，可提取版本 |
| `openssh` | OpenSSH | SSH 握手的 `server_id.software`；`identified`，可提取版本 |
| `cobalt_strike` | Cobalt Strike / Team Server | 叶证书 SHA-256 符合公开记录的默认证书；`suspected` |
| `asyncrat_family` | AsyncRAT / DcRAT | 主体、颁发者、自签名、9999 年到期与 SHA512-RSA 组合；`suspected`，不细分共享模板的具体家族 |
| `sliver` | Sliver / Multiplayer | 默认多人管理端的主体、颁发者、非自签名与 ECDSA 签名组合；`suspected`，不表示已发现植入体通信监听器 |
| `qakbot` | QakBot | 历史证书主体与颁发者的完整结构组合；`suspected`，`basis=historical_certificate_heuristic`，家族归属需复核 |
| `mythic` | Mythic / Web UI | 管理页标题、挂载节点、manifest 与构建脚本路径组合。`suspected`，`basis=http_management_fingerprint` |
| `empire` | Empire / Starkiller | 管理页标题、挂载节点、模块脚本与 Starkiller 专属 `noscript` 提示组合。`suspected`，`basis=http_management_fingerprint` |

`identified` 表示服务声明了产品名称，不证明声明可信或存在漏洞。`suspected` 表示证书或管理页特征符合已收录规则，不确认服务角色、恶意用途或主机感染。通用 404、自签名、正文中的软件名称以及网页文件 IOC 不独立产生产品身份。Sliver 目前仅覆盖默认 Multiplayer 管理端证书，不覆盖通用 mTLS、HTTP(S)、DNS 或 WireGuard 植入体监听器。QakBot 仅提供历史证书启发式，不保证适用于当前基础设施或全部变种。

HTTP/HTTPS 产品声明及 HTTPS 证书使用首次响应，跳转目的站不能覆盖原端口身份。管理页规则支持符合下文条件的同源落地页。TLS 握手失败前取得的证书可以产生候选，采集仍标记不完整。扫描器在既有大小预算内保留选中服务之外的 HTTP/HTTPS/TLS 补充证据，这一步只保留已执行探测的结果，不改变原始协议选择，也不另发请求。可选 JARM 的额外连接另见后文。

### Sliver 与 QakBot 的候选边界

Sliver 规则依据上游 v1.5.42 的多人管理端证书生成逻辑：叶证书主体为 `CN=multiplayer`、颁发者为 `CN=operators`，并要求明确的非自签名状态和 ECDSA 签名。只命中名称片段、通用 mTLS 或普通 CA 不产生候选。TLS 握手失败但已保存完整必要证书字段时仍可输出候选，并保留失败状态与 `coverage=partial`。

QakBot 规则参考 2023 年公开研究的历史证书结构，要求同一叶证书上主体包含国家、组织单位和域名 CN，颁发者包含国家、省州、城市、组织和域名 CN；完整字段形状匹配，并额外要求两者的国家与 CN 相同。拒绝常见 `Domain Control Validated` 组织单位、额外 DN 字段、缺失和超长值。该研究提示候选可能误报，因此详情明确标为「历史证书启发式」，不输出已确认家族、服务角色、软件版本或当前恶意活动。

新增规则复用已有原始握手，不需要导入 IOC 或新增扫描器配置，不发送 C2 专属通信或控制消息。只使用叶证书；HTTPS 只使用首次响应的证书，不把链证书、跳转目的站或正文中的产品名字归给源端口。回归使用合成字段及普通/矛盾/不完整证书反例，不代表已完成真实部署或全版本认证。

研究与实现依据：[Sliver 管理端 TLS 配置](https://github.com/BishopFox/sliver/blob/v1.5.42/server/transport/mtls.go)、[Sliver CA 生成](https://github.com/BishopFox/sliver/blob/v1.5.42/server/certs/ca.go)、[Sliver 证书生成](https://github.com/BishopFox/sliver/blob/v1.5.42/server/certs/certs.go)、[QakBot 历史证书研究](https://www.embeeresearch.io/advanced-threat-intel-queries-catching-83-qakbot-servers-with-regex-censys-and-tls-certificates/)。

### Mythic 与 Empire 管理端

规则 v5 在同一个 HTML 响应中匹配上表所列结构。直接响应须为 HTTP 200 `text/html`。首次根路径响应若发生重定向，可复用扫描器已保存的 `web_assets` 落地页。首次 `Location` 须与落地页记录的首个跳转一致，全部跳转须保持协议、主机和端口一致，最终落地页须为 HTTP 200。来源字段须能核对，出现不同 Host/SNI 上下文时跳过落地页。规则检查未标记截断且不超过 64 KiB 的正文。

候选只描述观察到的管理界面组件，软件版本留空。规则参考 Mythic **v3.4.0.61** 和 **v4.0.0rc5** 的上游构建页面，以及 Starkiller **v3.6.0** 和 **v4.0.3** 的上游页面模板。回归用这些结构构造本地样本，真实部署上的误报率和未覆盖版本尚待验证。[Mythic v3.4.0.61](https://github.com/its-a-feature/Mythic/blob/v3.4.0.61/mythic-react-docker/mythic/public/index.html) · [Mythic v4.0.0rc5](https://github.com/its-a-feature/Mythic/blob/v4.0.0rc5/mythic-react-docker/mythic/public/index.html) · [Starkiller v3.6.0](https://github.com/BC-SECURITY/Starkiller/blob/v3.6.0/index.html) · [Starkiller v4.0.3](https://github.com/BC-SECURITY/Starkiller/blob/v4.0.3/index.html)

### 查看与搜索

搜索和资产端口表的「服务」列同时显示协议与产品，候选带黄色「疑似」徽标。展开端口，在「服务识别 → 产品识别」查看规则、证据路径、Host/SNI、观察时间与来源。历史弹窗显示对应原始观察的产品结果。

高级搜索支持产品 ID，以及同一产品上的 ID 与版本组合：

```text
service = https AND product = cobalt_strike
product = "nginx@1.26.2"
product IN (cobalt_strike, asyncrat_family, sliver, qakbot)
product IN (mythic, empire)
EXISTS(product)
```

`product != cobalt_strike` 只表示当前结果没有该产品匹配，不能解释为目标正常。产品字段只匹配本地观察；联测结果不会借展示合流获得本地产品身份。

### API 与旧数据

搜索及资产端口、端口历史响应新增：

- `products[]`：`id`、`name`、`component`、`version`、`assessment`、`basis`、`evidence[]`。
- `product_identification`：`status`（`identified` / `suspected` / `not_matched` / `insufficient_evidence`）、`coverage`（`complete` / `partial`）、`ruleset_revision`、`observed_at`、`stale`、`observation_ref`。

`products[]` 是匹配结果，`product_identification` 用于解释匹配和证据状态；它们不会因为有一项为空而互相替代：

- `status=identified` 表示存在产品声明匹配且无疑似候选。`suspected` 表示至少有证书或管理页候选。`products[]` 为空时，`not_matched` 表示本次可检查的协议证据未匹配已收录产品规则，`insufficient_evidence` 表示当前证据不足以得出产品匹配结果。
- `coverage=partial` 表示相关协议观察缺失、失败或被截断等情况；`complete` 仅表示当前汇总未发现这些不完整标记，不保证扫描了所有协议、支持所有产品或发现了端点上的全部软件。已看到明确 nginx 声明但 TLS 证据不全时，可以同时得到 `status=identified` 和 `coverage=partial`。
- `ruleset_revision` 是规则修订号，不是软件版本。`observed_at` 属于原服务观察，重算时不改为重算时间。`stale` 表示该结果落后于较新端点观察或当前规则版本，不表示证书已经到期。
- JARM 状态单独保存在 `jarm` 中。得到 JARM 指纹也可能没有任何产品匹配，不能用 `jarm.status=success` 推断产品 `status=identified`。

#### 如何核对识别证据

`products[].evidence[]` 保存规则采用的关键值及其来源位置，不是完整原始报文或抓包文件，也不表示已经确认软件真实身份或恶意用途：

| 字段 | 核对方法 |
| --- | --- |
| `rule_id` / `detection_method` | 查看命中的规则及使用的检测方式；旧记录可能缺少检测方式字段 |
| `probe` | 保存该条依据的采集模块，例如 `https`、`ssh` 或 `web_assets` |
| `field_path` | 相对于该次服务观察 `data` 对象的 JSON Pointer，不是相对于搜索响应根对象的路径 |
| `details` | 规则采用的关键字段和值，展示长度受限；完整数据以仍被保留的原始观察为准 |
| `sni` / `http_host` | 采集时的虚拟主机上下文，不用于重新解析或扩大扫描目标 |
| `source_url` | 可选的规则实现或研究参考，不是目标响应的下载地址 |
| `product_identification.observation_ref` | 与上述路径配合，定位证据所属的服务观察 |

例如 HTTPS 观察中的 `Server: nginx/1.26.2` 可生成产品 `nginx`、版本 `1.26.2`、`basis=service_declaration`，证据路径通常为 `/evidence/0/result/response/headers/server`（实际索引随观察排列变化）。这说明服务端自报了 nginx；证书模板匹配则输出 `suspected`。原始数据已清理时，仍可展示已保存的规则依据，但不能仅凭 `field_path` 取回缺失原文。

内置产品规则版本为 **6**。v2 增加 Sliver 和 QakBot，v3 增加检测方式及 JARM 元数据，v4 规范 Windows OpenSSH 版本，v5 增加 Mythic 和 Empire 管理端。v6 将 Sliver、Mythic 和 Empire 条件移入可独立加载的 JSON 规则包，`product_identification.ruleset_sha256` 记录实际使用的文件摘要。结果按自身服务观察时间更新，较早或旧规则的结果标记 `stale`。相同产品存在不同版本声明时并列保留。[规则格式、校验与回放](SERVICE_PRODUCT_RULES.md)

启动会增加 ES 映射。新扫描与执行投影重放生成可搜索产品；旧端口/历史详情只在原始数据确属该次服务观察时即时推断。若需要让全部存量产品进入 `product` 搜索，可在备份后按本文「存储升级与回滚」重建端点投影；不会自动重扫网络或改写原始观察。新前端兼容缺少新字段的服务端，保留旧版证书线索展示；旧 `c2_fingerprint` 字段和指纹过滤暂保留兼容。

产品候选不再自动添加 IP 级「威胁」「恶意软件」或家族标签。既有标签和人工标签保留，可由管理员复核移除；产品识别与 IOC 风险、标签各自独立。

研究来源：[Cobalt Strike 默认证书研究](https://www.recordedfuture.com/research/cobalt-strike-servers)、[AsyncRAT / DcRAT 证书模板研究](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/21/i/ssl-tls-technical-brief/ssl-tls-technical-brief.pdf)。


### 检测方式与 JARM 主动采集

| 检测方式 | 是否主动探测 | 基本原理 | 当前用途 |
| --- | --- | --- | --- |
| JARM | 是，显式启用后额外最多 10 次 TCP 连接与 ClientHello 探测 | 对 10 组不同 ClientHello 的服务端密码套件、TLS 版本、ALPN 与扩展响应生成 62 个十六进制字符的指纹 | 保存 TLS 配置指纹；当前没有以 JARM 单独归属 C2 家族的规则 |
| TLS Certificate | 证书采集是；分析复用已有观察，无额外连接 | 分析叶证书主题、颁发者、有效期、公钥等元数据 | Cobalt Strike、AsyncRAT / DcRAT、Sliver、QakBot 候选，适用前述规则边界 |
| HTTP Fingerprint | HTTP 采集是；产品规则复用已有响应 | 分析 HTTP 状态、响应头和内容特征 | nginx / Apache 的 Server 声明，以及 Mythic / Empire 管理页候选 |
| Protocol Fingerprint | 通常是；已有工业被动接收方式除外，识别复用已有握手 | 根据应用层握手和协议响应识别服务 | 既有协议识别及 OpenSSH 软件声明；不表示已实现各 C2 的私有协议规则 |

JARM 以 TLS 握手响应为依据。证书轮换后，握手响应特征保持一致时，JARM 可以保持稳定。共享反向代理也可能为不同应用返回相同的握手特征。规则 v5 保持 JARM 为独立观察，家族候选由已收录的证书或 HTTP 管理页规则产生。[JARM 原理与样本重合情况](https://github.com/salesforce/jarm#how-jarm-works)

在扫描器本地 `config.toml` 中明确允许 JARM：

```toml
[service_detection.jarm]
enabled = true
concurrency = 4
probe_timeout_seconds = 3
max_stage_seconds = 60
```

再在控制台「扫描器 → 配置 → JARM 主动采集」启用该扫描器的远程开关。服务识别本身也需启用。JARM 本地和服务端默认均为关闭，远程开启不能覆盖本地禁用；旧服务端未下发该段时保留本地配置。配置在下一任务快照生效。模块模式需要同步更新 service-detection worker，旧 worker 不具备 JARM 采集能力。

参数范围：`concurrency` 1–32、`probe_timeout_seconds` 1–30 秒、`max_stage_seconds` 1–3600 秒。并发以端点计，完整指纹需要 10 个按原始顺序的探测槽；每槽新建 TCP 连接并发送一组 ClientHello，最多尝试一次，不完成应用会话，无重试。预算或取消可使实际执行少于 10 槽；沿用 `server_rate_limit` 的每 IP 连接间隔。每连接最多读取 64 KiB，仅解析 ServerHello/拒绝响应，不发送应用层请求；同时受块级总预算、任务剩余预算、取消信号及 64 MiB 结果上限约束。

只对本次已有 TLS ServerHello 或证书证据的 TCP 端点采集（包括保留服务端证书的失败 mTLS 握手），不按端口号猜测，不跟随 HTTPS 跳转目的站。连接固定到扫描 IP 与端口；任务 `probe_options.server_name` 仅作为经过校验的 SNI，无此项时使用扫描 IP 文本，不执行额外 DNS 解析。

成功指纹要求 10 个槽都取得可判定结果，且至少一个槽取得 ServerHello；这不要求 10 次成功或完整的 TLS 握手。显式 TLS 拒绝或尚未收到任何字节时的正常关闭记为空槽；超时、连接异常、截断、畸形或超限响应标为不完整，不生成有效哈希。全部拒绝显示 `no_response`，不发布全零指纹。块级超时或取消会丢弃尚在执行的端点采集，保留基础服务证据和已完成端点；采集失败不会使基础扫描失败。JARM 与单次 ServerHello 的 JA3S 不同，共享指纹只说明 TLS 配置相似，不能单独确认家族或恶意用途。

API 字段位置如下：

- `product_identification.detection_methods[]`：`id`（`jarm` / `tls_certificate` / `http_fingerprint` / `protocol_fingerprint`）、`name`、`active_probe`（采集是否需要主动网络交互）、`additional_probe`（该方式是否需要额外连接）、`observed`（该次观察是否有此类记录；仅被动协议证据时 `active_probe=false`）、`principle`（稳定原理键）。`active_probe` / `additional_probe` 描述采集方式，不代表本次已实际执行。`observed=true` 表示有相应记录，JARM 记录可能只有部分结果；是否得到指纹仍需看 `jarm.status` 与 `fingerprint`。方式清单不代表四类方式均有 C2 产品规则或均已采集成功。
- `product_identification.jarm`：没有可展示记录时为 `null`，可能是未启用、没有符合条件的端点、取消/预算不足导致记录未保留，或记录未通过格式校验；不能仅凭 `null` 判断从未尝试过连接。存在记录时包含 `status`（`success` / `partial` / `no_response`）、`fingerprint`（不完整或全部拒绝为 `null`）、`expected_probes`、`attempted_probes`、`completed_probes`、`sni`、`field_path`。`attempted_probes` 是已尝试槽数，`completed_probes` 是可判定槽数，包括 ServerHello、明确 TLS 拒绝及未收到任何字节时的正常关闭，不等同于成功 ServerHello 数或完成 TLS 会话数。
- `products[].evidence[].detection_method` 标明产品规则使用的方式。新字段缺省兼容旧数据，不把历史观察标成已完成 JARM。

搜索、端口当前与历史 API 沿用产品观察时钟携带这些元数据；JARM 不创建虚构产品或自动恶意标签，也未增加 JARM DSL 过滤字段。只有新扫描能获取新 JARM；重放旧数据不会主动连接网络。

实现使用固定版本 [netfp 0.2.1](https://docs.rs/netfp/0.2.1/netfp/) 的纯编解码与哈希组件，网络、速率及预算由扫描器控制。算法说明见 [Salesforce JARM](https://github.com/salesforce/jarm)。回归仅使用本地合成 TLS 响应，未探测外部 C2，也不代表已完成各类真实部署验证。


### 通过 Web 或服务器 CLI 管理 JARM

Web 入口为「扫描器 → 配置 → JARM 主动采集」，可修改 `enabled`、`concurrency`、`probe_timeout_seconds`、`max_stage_seconds`。管理员通过已有 `GET/PUT /api/scanner/{scanner_id}/configuration` 读写完整运行配置，发布请求需携带 `expectedRevision`；旧版本或并发更新发生冲突时重新加载后再发布。节点本地授权和下一任务边界生效规则不变。

服务器 CLI 读写同一份配置，无需运行 HTTP 或 Elasticsearch，仅需正确的 PostgreSQL 连接配置：

```bash
# 使用实际扫描器 UUID 替换 <ID>；可在命令前指定 --config /path/to/config.toml。
network_mapping_server scanner-config show <ID>
network_mapping_server scanner-config set-jarm <ID> --enabled true --concurrency 4 --probe-timeout-seconds 3 --max-stage-seconds 60 --change-reason "授权资产盘点"
network_mapping_server scanner-config set-jarm <ID> --enabled false --change-reason "暂停额外 TLS 握手"
```

`set-jarm` 仅修改给出的字段，保留其他 JARM 参数和网页抓取、端口扫描等配置；不传任何修改字段会报错。参数范围与 Web 相同，`--enabled` 必须显式传 `true` 或 `false`，变更原因最多 500 个字符。每次成功更新都在同一事务中写入新修订、历史与审计；如果 Web 或另一个 CLI 已先修改配置，则报修订冲突并退出，不覆盖并发更新。`show` 可核对当前文档和修订；现有 `set-web-content` 命令继续可用。

两种入口均只能管理服务端运行配置，不能越过扫描节点本地 `service_detection.enabled` / `service_detection.jarm.enabled` 授权。旧 worker 需同步升级后才能实际采集 JARM。

Windows OpenSSH 的 `OpenSSH_for_Windows_9.5` 声明输出产品 `openssh`、版本 `9.5`，平台前缀保留在原始声明证据中，`product = "openssh@9.5"` 可与其他平台的同版本一并查询。旧规则详情仅在原始数据属于对应服务观察时回算；存量搜索投影需按前述步骤重放，新规则不会刷新旧观察时间。
