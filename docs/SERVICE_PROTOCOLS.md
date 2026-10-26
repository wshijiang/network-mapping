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
| `modbus` | TCP/502 | Read Device Identification 0x2B/0x0E；匹配事务、Unit ID、功能及标识对象。关联异常仅确认协议，不保证可采集设备标识 |
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

## UDP 主动与被动任务

UDP 使用 plan v2，结果仍为上传协议 3；与 TCP 分开创建任务，当前不支持同一任务混合 TCP/UDP 或自动域名后续任务。服务端启动初始化更新任务 profile 约束，允许 `udp_inventory` / `udp_passive`；升级部署须同步程序随附的数据库初始化 SQL。两类 UDP 任务均自动识别其支持的全部协议，无需手动勾选；服务端将规范化的默认集合写入 plan，预览、创建、调度与恢复共用此集合。主动默认 DNS、EtherNet/IP、BACnet/IP；经典 BACnet/IP 仅适用于 IPv4。被动默认 EtherNet/IP I/O 与 OPC UA UADP。旧 API 非空列表仍可限制范围。最多 256 个单播来源/目标地址；`udp_inventory` 最多 32 个明确端口，不使用隐式全端口扫描。

```json
{
  "ip": "192.0.2.53", "port": "53", "level": 1,
  "scan_profile": "udp_inventory"
}
```

主动任务串行执行，受阶段累计期限、每目标超时、取消及速率限制；上限为节点配置与 5 次/秒中较小值，每请求最多接收 32 个不匹配报文，每报文最多 8192 字节。一个目标/端口完成后保存 ACK 检查点；恢复从下一端点继续。无有效响应不生成开放/关闭观察，也不产生伪造的成功服务。

```json
{
  "ip": "192.0.2.20", "port": "4840", "level": 1,
  "scan_profile": "udp_passive",
  "dispatch_mode": "selected", "scanner_ids": ["019c0000-0000-7000-8000-000000000001"],
  "service_probe_options": {
    "passive_bind": "192.0.2.10", "passive_window_seconds": 10,
    "passive_group": "239.0.0.1", "passive_interface": "192.0.2.10"
  }
}
```

被动任务的 `ip` 是获授权的发送源，`port` 是扫描节点唯一的本机接收端口；`passive_bind` 必须是节点实际 IPv4 接口。组播可选，配置时接口必须与 bind 相同。不支持混杂抓包、镜像口捕获或离线 PCAP 导入；只接收已送达本机/加入组播组的流量。窗口默认 10 秒，范围 1–60 秒；最多处理 1024 个报文、记录 256 个源端点。被动任务必须以 selected 模式明确指定一台接收节点，不能自动分配或多节点广播。

被动结果归属实际 UDP 发送源 IP/源端口，不把接收端口或组播地址登记成目标资产；`source=passive_udp`、confidence 80，证据标记 `reachability_asserted=false`。没有合格报文表示未观察到，不能判为关闭。仅保留结构摘要，不保存 I/O / DataSet 载荷。检查点保留已确认结果和累计窗口；恢复不延长总观察预算。

## 能力、显示与兼容

节点上报 `service_protocols`、`max_service_probes`、`plan_versions=[1,2]` 和所启用的 profiles。创建、预览、路由偏好、领取、重领和恢复均校验所选协议及单端点探测预算；旧节点缺失字段时不能领取新协议任务。UDP 任务仍走现有 `service_detection` Worker、阶段错误策略和持久化链路。

Worker IPC 升为 **3**。升级时先暂停分配并排空旧 generation 的任务和检查点，再配套升级 Agent、Worker 与完整 IPC 3 模块包。不得混用旧 Worker 或通过删除状态库绕过预检。plan v1 与上传协议 3 保持兼容，新增 UDP 任务要求 plan v2；SQLite schema 不变。

前端沿用现有 daisyUI 的表单、badge 和 details；任务创建默认自动识别，移除协议勾选，TLS/SNI、DoH 路径、Unit ID、TSAP 与 MQTT 版本集中在可折叠的高级参数内。显示协议证据、MQTT 认证拒绝及被动来源，动态字符串按文本转义。资产历史按 IP/端口/传输协议过滤，表格键区分 TCP/UDP。

## 存储升级与回滚

端点身份改为 IP + 端口 + `tcp`/`udp`/`unknown`，执行和用户/global/API client 范围均包含传输协议；分页、OS/Web 补全及历史查询同步处理。历史缺失或无法确定的传输保持 `unknown`，不补猜 TCP。不可变扫描事实和上传校验和不重写。

默认执行投影改为 `network-mapping-execution-endpoints-v2`，当前投影改为 `network-mapping-endpoints-current-v3`。既有部署必须停服、完成待上传对账并备份 PG 状态与 ES 事实，保持 observation/DNS 索引名不变，配置全新的 execution/current 索引名后运行：

```sh
network_mapping_server --config config.toml --rebuild-transport-endpoints
network_mapping_server --config config.toml --rebuild-analytics-snapshots
```

重建持有与服务互斥的存储锁，按 PG 中的 IP 执行读取 ES 现存事实并重建 execution/current 投影，PG 提供任务归属、执行状态和当前标签。**不做数据对账**：不读取上传回执，不比较 PG/ES 总数、批次数量、事实校验和或数据指纹。历史回执、附带 DNS 批次、过期回执引用和校验和差异不会阻断重建，也不会要求恢复备份。ES 数量仅用于进度显示，实际重放持续到分页结束，不以预计数量作为停止或失败条件。

断点记录运行 ID、源集群/索引 UUID、进度参考数量、目标 UUID，以及各执行重放/发布页和标签页游标。**中断后重新运行相同配置和命令即可自动恢复**，无需手动指定游标。Bulk 全部动作确认后才保存页断点；确认前中断的页会幂等重放。恢复时先等待同一运行遗留的 ES 写请求结束；源索引被替换或目标身份改变会拒绝续跑。旧版仅含 `last_execution_id` 的断点无法验证，必须重新选择全新目标索引，不得直接沿用旧索引。已完成运行重复执行不再切换或重排 outbox。

重建命令自动使用离线高吞吐配置：32 个独立执行并发、每页 2000 条、每批最多 2000 个动作或 16 MiB；不修改正常服务的配置文件或默认参数。进度计数及执行汇总也并发执行。当前投影在同一页内对不同端点并发提交 Bulk，整页成功后再推进断点；跨执行仍按执行 ID 顺序发布，保持历史覆盖顺序。标签每页一次 PG 查询，仅对变化文档发 Bulk，不逐 IP 执行带刷新的 update-by-query。新目标索引创建时关闭自动刷新（`refresh_interval=-1`），阶段结束显式刷新，切换前恢复 `1s`；恢复自动刷新失败可原命令续跑。

终端每 5 秒显示阶段、已确认量/总量、执行信息、速度和有足够采样时的阶段 ETA（参考数量）；续跑前的历史数量不计入本次速度。Ctrl-C/SIGTERM 会等待当前页确认（最多 60 秒），存储锁连接丢失则停止。完成全部重放、发布、标签同步和刷新后，在同一 PG 事务中更新计数、处理投影 outbox、排队 OS/Web 补全并切换运行标记。失败期间保留旧运行配置和计数；旧索引不删除，纯漏洞观察不生成端点 Bulk。重建期间须停止扫描写入、事实保留期清理及 DNS/observation 位置变更。

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

回滚需停服并恢复配套旧程序、旧 execution/current 配置和迁移前 PG 运行标记；重建保存的 `transport_endpoints_previous_runtime` 可供核对，但生产回滚以备份及部署变更记录为准。启用 UDP 后产生的新结果须保留，旧程序不能完整展示这些结果，不应回滚后删除新事实。

## 验证范围

测试使用合成响应、本机回环服务和隔离的 PostgreSQL/Elasticsearch 资源；覆盖错误事务/来源/长度、TLS 信任与服务名、错误 DoH 正文/状态/重定向、工业拒绝响应及被动帧格式。真实产品、设备网络、组播环境和线上发布仍需部署方在授权范围验收，不能把局部协议实现称为全版本产品认证。

本次执行记录（2026-10-23）：扫描端全目标测试 217 项常规与 6 项 Worker 进程测试通过；另有 4 项被动接收定向回归通过。前端 152 项工具/组件测试通过，服务端常规测试、PostgreSQL 调度和投影测试的结果随 PR 记录。默认忽略的集成测试不计入常规通过数量。

真实 Elasticsearch 9.5.0 官方发行包已下载并通过 SHA-512 校验；本实例缺少 `/proc/self/coredump_filter`，官方进程在启动时失败，容器和提升权限执行亦然。因而此环境未完成真实 ES 端到端迁移验收；PostgreSQL + HTTP 投影协议测试不能替代该验证。未做真实设备网络、浏览器视觉验收或线上部署。
