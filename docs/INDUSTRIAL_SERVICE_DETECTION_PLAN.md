# 工业与物联网服务识别扩展计划

[文档中心](README.md) · [服务探测分批计划](SERVICE_DETECTION_ROADMAP.md) · [DNS 与 VNC 扩展计划](DNS_DOH_DOT_VNC_PLAN.md)

当前交付（2026-10-23）：A/B/C、D/E 基础范围已实现，F 提供明确配置的 IPv4 被动接收和保守的帧格式识别。当前操作方式和准确限制以[服务协议识别与部署](SERVICE_PROTOCOLS.md)为准；下文保留原设计与后续验收计划，其中混合 port_sets、自动域名 UDP 子任务、完整 UADP 类型、镜像抓包与真实设备认证仍非当前交付。尚未线上部署。

## 当前基线与协议范围

扫描端 `src/scan/detection.rs` 已包含 `mqtt`、`mqtts`，分别映射 TCP/1883、8883，并支持非标准端口策略；本次不将其重复计为新增协议。其余五类已增加有限的协议确认/接收路径；实际支持范围见当前协议表，原设计不代表所有扩展能力均已交付。

| 协议 | 建议服务标识 | 传输与常用端口 | 应用场景与本次范围 |
| --- | --- | --- | --- |
| Modbus TCP | `modbus` | TCP/502 | 数据采集、设备互联；采用有界只读设备标识请求确认协议 |
| EtherNet/IP | `enip` | TCP/44818、UDP/44818；实时 I/O 常用 UDP/2222 | 多厂商 CIP 生态；先交付单播身份发现，实时 I/O 另作被动识别，不按协议名推断罗克韦尔产品 |
| S7 通信 | `s7` | TCP/102 | PLC 与 SCADA/工程站通信；首批确认经典 S7comm，不把 ISO-on-TCP 或 S7comm Plus 等同于已支持 |
| OPC UA | `opcua`、`opcua_pubsub` | TCP 常用 4840；UDP UADP 常用 4840，可配置 | 跨平台 IT/OT 数据互联；TCP 客户端/服务端握手与 UDP PubSub 分开实现、声明能力和验收 |
| MQTT / MQTTS | `mqtt`、`mqtts` | TCP/1883、8883（TLS） | IIoT 上云、远程监测；复用现有模块，核验协议版本、认证拒绝、TLS 与非标准端口证据 |
| BACnet/IP | `bacnet` | UDP/47808（0xBAC0），可配置 | 楼宇暖通、照明和门禁集成；首批为经典 IPv4 BACnet/IP 单播识别，BACnet/IPv6、BACnet/SC 分别扩展 |

端口只安排候选探测，不足以确认服务或设备厂商。EtherNet/IP 的 UDP/44818 需要补进发现范围，不能用 UDP/2222 代替；参见 [Rockwell EtherNet/IP 端口说明](https://www.rockwellautomation.com/en-in/docs/factorytalk-edge-gateway/distributed-1-00/ft-edge-gateway-help-ditamap/data-sources/data-source-configuration/add-auto-discovery-and-model/ftlinx-and-ft-logix-echo-binding.html)。OPC UA UDP 使用 UADP PubSub，包括单播和组播，并非 TCP 握手的 UDP 版本；参见 [OPC Foundation UDP 映射](https://reference.opcfoundation.org/specs/OPC-10000-14/7.3.2)。

## 各协议的确认与采集边界

| 协议 | 探测与确认方式 | 证据及边界 |
| --- | --- | --- |
| Modbus TCP | 首选 Read Device Identification（0x2B/0x0E）；校验 MBAP、事务 ID、Protocol ID、长度、Unit ID 与功能码；严格解析标识对象或对应异常响应 | 关联且合法的异常可证明 Modbus 响应，但不能证明支持设备标识；厂商/产品/修订仅取明确对象。不默认读取过程寄存器；不写线圈、寄存器或执行诊断动作 |
| EtherNet/IP TCP | 使用有界 ListIdentity（必要时 ListServices）；校验封装命令、长度、状态、上下文及条目结构 | 明确返回时保存 vendor ID、device type、product code、revision 和有界产品名。不建立 I/O 连接，不调用 Forward Open 或发送控制指令 |
| EtherNet/IP UDP/44818 | 向明确目标单播 ListIdentity；校验来源端点、响应结构、条目数量及实现适用的 SenderContext 回显规则 | 不默认广播；不得假定所有实现都提供强事务关联。只有已验证的关联规则才用于确认，无法关联时保持未确认 |
| EtherNet/IP UDP/2222 | 在配置明确的被动流量或导入报文中校验 CPF、连接标识、序列及 I/O 格式，结合会话上下文 | 不向实时 I/O 端口发送试探数据，不靠超时或端口认定协议；没有合格流量时标记未观察到，不标记关闭 |
| S7 | TPKT/COTP 建连后，校验经典 S7 Setup Communication 应答及关联 PDU 引用；仅 COTP 成功保留 ISO-on-TCP 线索 | TSAP/rack/slot 来自明确配置，默认仅尝试受支持的一组，不枚举机架插槽；不读写 PLC 数据块、不上传下载程序、不切换 RUN/STOP。未获取明确设备身份时不推断型号/固件 |
| OPC UA TCP | 发送有界 HEL，解析 ACK 或合法关联 ERR，核对消息类型、分帧长度、协议版本和限制字段 | 确认 OPC UA TCP 传输，并单独展示受限错误；不据此宣称会话认证、加密策略或节点数据可访问。首批不创建应用会话、不 Browse/Read/Write/Call |
| OPC UA UDP PubSub | 首先实现 UADP 解析器与离线样本；再支持指定网卡/来源/单播接收或显式组播组的有限观察窗口 | 校验版本、标志、长度、PublisherId/WriterGroup 等实际存在字段；不采集业务 DataSet 值，不发送控制/发布数据。加密或证据不完整时只保留可验证层级，不猜测载荷 |
| MQTT / MQTTS | 复用现有适配器，核对 CONNECT/CONNACK、认证拒绝、协议版本与 TLS 证据；协议版本补强按固定引擎实际能力实现 | 不把合法认证拒绝变成“不是 MQTT”；使用随机唯一 Client ID、无 Will、无持久会话和有界连接生命周期；不发布、订阅主题，不读取业务消息或测试口令 |
| BACnet/IP | 向指定端点发送有界单播 Who-Is，校验来源、BVLC 类型/功能/长度、NPDU、APDU 与 I-Am 结构 | 可保存 device instance、vendor ID、max APDU、分段能力；Who-Is/I-Am 没有通用事务 ID，必须按来源及观察窗口关联且注明限制。不注册 Foreign Device/BBMD，不修改属性或发送 ReinitializeDevice |

Modbus Unit ID 由任务显式配置或采用已文档化的单一默认值，不遍历下挂设备；异常、不支持和无响应分别保留。串口 RTU、RTU-over-TCP 及 Modbus Security 不自动包含在 TCP/502 的交付声明中。

OPC UA HEL/ACK 是 UA TCP 协议握手；其 SecureChannel 属于 OPC UA 自身的安全机制，不能照搬 DoT 的通用 TLS 探测。GetEndpoints、FindServers 和设备身份采集作为后续独立只读选项，先实现有界解析与明确访问状态，不自动跟随返回 URL 扩大目标范围。

MQTT Broker 的存在不能证明运行了 OPC UA PubSub；仅因 1883/8883、产品名或主题字符串命中不能生成 `opcua_pubsub`。已有 MQTT/MQTTS 模块的 3.1.1/5.0 覆盖及认证拒绝处理必须用固定版本引擎和真实 Broker 核验，不能从模块名称推断。

## 编排、能力与数据契约

沿用 DNS/VNC 计划中的统一服务编排、分块 ACK、Worker、取消、期限、重试、租约丢失和检查点约束。实施前核对 Dockerfile 固定 zgrab2 提交的实际模块、请求行为和输出；可复用的引擎经适配与验证后接入，未支持或无法满足边界的协议使用独立 Rust 适配器，不把虚构模块名交给 zgrab2。

- 工业主动探测提供单独启用项、协议白名单与探测预算；`exhaustive` 不隐式打开未启用的工业模块、广播、组播或被动采集。每目标并发、报文速率、超时和重试与全局预算共同生效。默认不枚举 Unit ID、TSAP、对象、设备或过程地址。
- 能力按协议、传输与模式声明，区分 `enip` 的 TCP、UDP 发现、I/O 被动观察及 `opcua` TCP、PubSub；MQTT 继续使用既有服务语义。调度、指定节点、估算、重领和恢复均检查实际能力。
- 标识为建议契约，实施时固定映射并补充搜索/API 文档；`protocol` 仍表达 tcp/udp，`service` 表达应用服务。协议版本、设备固件修订和产品版本分别存储，不从 RFB/S7/CIP/UA/MQTT 协议版本推出设备版本。
- 单播 UDP 依赖现有分批计划的协议端点迁移：同一 IP/44818 或 IP/4840 的 TCP/UDP 必须可并存；同步 ID、证据、游标、历史、统计、报告、导出、权限和开放 API。
- 被动 PubSub/I/O 是新的采集模式，不能直接塞进“开放端口”结果。先定义观察记录、节点能力、来源追踪、存储/上传契约及恢复，再开放入口；从源 IP/源端口与流上下文关联生产者，不能把接收端口或组播组地址当成设备资产。
- 组播必须明确网卡、组地址、来源过滤及观察时长；不自动加入发现组或泛化监听全部接口。被动观察不进行应用写入，但加入组本身仍是可见网络行为，应在配置中明示。无流量仅表示未观察到。
- 证据保存真实来源、解析器版本、探测模式、限制、时间和确认层级。未知、受限、未观察到、取消和过期分别表达，失败或不支持不覆盖已有成功证据。
- 新服务不自动扩大 Nuclei 模板范围；逐服务核对受限选择规则，无对应规则/模板时标记未覆盖，不能回退成不受限扫描。

## 前端适配

创建页在已有服务识别配置中增加工业协议选择及最少必要参数，复用 daisyUI 的 `card`、`select`、`input`、`toggle`、`alert` 与现有校验；不另起一套工控页面样式。未发布的 UDP/被动模式不提前展示可用入口，能力不足的节点不可选，原有 DNS 解析设置不受影响。

搜索、任务详情、资产详情共用服务徽标与证据摘要，沿用 DNS/VNC 计划的共享组件、既有表格和历史 modal。展示 Modbus、EtherNet/IP、S7、OPC UA、MQTT/MQTTS、BACnet/IP，区分主动确认、被动观察、认证受限和过期；不把协议存在显示为可控制设备。使用 Lucide 通用图标、`currentColor`、daisyUI 语义色，兼容明暗主题、移动端与键盘操作。

为 BACnet/IP、OPC UA PubSub 与 EtherNet/IP 显示实际传输和端口；被动证据独立标注来源与采集模式。设备名称和返回文本由 Vue 转义；CSV、统计和报告沿用后端已经明确的版本/状态语义，不由前端根据端口推断厂商或协议。

## 追加交付批次

保留原 DNS/VNC 的 A、B、C 批次，追加 D、E、F。D 依赖 A 的编排与契约，可独立于 UDP 迁移推进；E、F 需要分别满足表中的前置条件，不能因为前一批解析器通过测试就声明全部工业协议已上线。

| 批次 | 范围 | 完成条件 |
| --- | --- | --- |
| D | Modbus TCP、EtherNet/IP TCP、S7、OPC UA TCP；MQTT/MQTTS 兼容核验与证据补强 | 逐协议单播握手、反例、受限状态、引擎行为、Worker/恢复、能力、搜索/历史/导出与 daisyUI 展示通过；MQTT 已有能力不重复记为新增 |
| E | EtherNet/IP UDP/44818、BACnet/IP UDP/47808 | 依赖 C/既有 UDP 端到端批次及相应适配器；协议端点隔离、响应关联限制、限速、重启恢复与真实设备/参考实现验收完成 |
| F | OPC UA UDP PubSub、EtherNet/IP UDP/2222 I/O 的被动识别 | 先完成报文解析与离线验收，再交付被动采集能力、明确的网卡/来源/组配置、观察记录及资产归属；逐模式验收，不主动建立控制或 I/O 会话 |

每个协议至少验证：合法/异常/拒绝响应、回显、错事务或上下文、畸形/超大长度、截断、慢速分片、随机数据、跨目标响应、预算及取消；COTP 成功不能误报 S7、通用二进制不能误报 UA/UADP、MQTT 不能误报 OPC UA PubSub。Who-Is/I-Am 无事务 ID、被动数据无请求上下文的限制要在测试与文档中体现。

运行与回归覆盖真实固定版本引擎、受控协议服务、进程内/Worker、阶段超时、分块 ACK 前后重启、旧节点、既有协议、同 IP 同端口 TCP/UDP、查询分页、权限及导出。被动模式还覆盖接收目标与真实来源分离、组播组非资产、无流量、加密/未知载荷及异常流量上限。

模拟器、合成报文、离线报文、回环服务和实际设备验收分别记录；不把协议库测试当作设备兼容证明，也不在规划阶段声称覆盖所有 PLC/固件。每批执行 `.cloud/start-skill.md` 的相关 Rust 检查、前端工具/组件测试及构建、文档严格构建，并记录未执行项。

## 文档与实施约定

继续遵循 `/workspace/.cloud/start-skill.md` 及前一计划的工作方式：现有仓库、不新建 worktree、复用工具/缓存、CodeGraph 结论回查源码、依赖 API 用 Context7 核对；Git author/committer 使用 `wshijiang <111570850+wshijiang@users.noreply.github.com>`，不修改全局身份。

各实现批次同步三个仓库实际受影响的 `docs/CHANGELOG.md` 和文档。扫描端更新协议范围、配置、UDP/被动能力、Worker、恢复及引擎版本；服务端更新任务/能力、证据/观察 schema、迁移、查询、API、权限和统计口径；前端更新功能、配置、主题及结果说明。新增专题同步文档首页与已有 MkDocs 导航；规划只记录为文档变更。

## 协议参考

- [Modbus Organization 应用协议 V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)：功能码 43/14、设备标识与异常响应。
- [Rockwell TCP/UDP 端口参考](https://literature.rockwellautomation.com/idc/groups/literature/documents/qr/comm-qr001_-en-e.pdf)：区分 EtherNet/IP 消息发现与 I/O 传输。
- [Siemens 通信协议与端口](https://docs.tia.siemens.cloud/r/simatic_et_200al_manual_collection_enus_21/function-manuals/communication/communication/communications-services/communications-protocols-and-port-numbers-used-for-ethernet-communication?contentId=~9azSVGvzaaGkjR0NYHEdw)：S7、ISO-on-TCP 与 TCP/102。
- [OPC Foundation UA TCP Hello](https://reference.opcfoundation.org/specs/OPC-10000-6/7.1.2.3)与 [UDP PubSub](https://reference.opcfoundation.org/specs/OPC-10000-14/7.3.2)：两类传输及其不同的验证边界。
- [OASIS MQTT 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html)：CONNECT、CONNACK 与认证拒绝。
- [BACnet/IP 网络说明](https://bacnet.org/wp-content/uploads/sites/4/2022/06/Building-Wide-Area-Networks-With-BACnet-Part-2.pdf)：UDP/47808 与发现报文。
