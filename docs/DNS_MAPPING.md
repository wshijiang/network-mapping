# DNS 测绘

DNS 数据分为不可变查询证据和可更新的当前 RR。PostgreSQL 继续负责任务、扫描器身份、执行租约和上传回执；DNS 原始响应与当前解析状态由 Elasticsearch 管理。

## 数据模型

- `network-mapping-dns-observations`：Data Stream。每次查询产生一条追加事件，包含问题、rcode、answer/authority/additional、解析器、延迟、扫描器、任务和 DNS view。
- `network-mapping-dns-records-v1`：当前 RR 索引。每个文档是一条 DNS resource record，而非一整个 domain 或 IP 文档。

当前 RR 的 `_id` 是规范化 `tenant_id`、`dns_view_id`、owner、class、type 和完整 `canonical_rdata` 的 SHA-256。域名统一为小写、去末尾点；A/AAAA 统一为规范 IP；MX 包含 priority；SRV 包含 priority、weight、port 和 target。TTL 不属于身份，变化只更新当前文档。

`tenant_id` 和 `dns_view_id` 目前固定为 `default`，以保持上传协议兼容。生产多租户或 split-horizon 部署接入前必须将二者变成服务端授权的任务属性，不能让扫描器任意声明。

## 状态语义

成功 `NOERROR` answer 会 upsert 为 `active` 并刷新 `last_seen_at`。`NXDOMAIN`、NODATA、`SERVFAIL`、拒绝和超时始终写入 observations，但不会将已有 RR 标为失活，避免短暂解析器故障误删资产。

“失活”需要后续完整覆盖确认：按 `(domain, record_type, dns_view)` 记录成功扫描代次，仅当该代次确认 RR 缺失时增加 `missing_completed_scans`。该状态机尚未启用，因此当前不会自动失活记录。

## 扫描器和任务

```toml
[dns]
enabled = true
record_types = ["A", "AAAA", "CNAME", "NS", "MX", "PTR", "SRV", "TXT", "CAA", "SOA", "SVCB", "HTTPS"]
query_timeout_seconds = 5
```

DNS engine 默认逐类查询 A、AAAA、CNAME、NS、MX、PTR、SRV、TXT、CAA、SOA、SVCB 和 HTTPS。A/AAAA 用于生成后续地址任务；MX 和 SRV 会额外保留 priority、weight 与 port 等结构化字段。

创建扫描页对 IP/CIDR 和域名使用同一组模式：`vulnerability_scan`（全部）、`port_only`
（仅端口）、`service_inventory`（服务识别）和 `dns_records`（仅 DNS）。前三种域名任务先执行
DNS 查询，再由服务端把授权的 A/AAAA 地址按地址族拆为对应 IP 子任务；`dns_records` 只归档
记录，不创建子任务。旧协议的 `dns_ports`、`dns_full` 仍可被已有客户端和扫描器接受，但
新前端不再创建这两种任务。

DNS 任务由管理员 API 创建，可自动分配、指定扫描器或分配给全部扫描器。候选节点必须在
heartbeat 中声明对应 DNS profile 与 `dns_lookup` 能力：

```http
POST /api/task/create-dns
Content-Type: application/json

{"domains":["api.example.com","www.example.com"],"port":"80,443","level":2,"scan_profile":"service_inventory","dispatch_mode":"automatic","remark":"authorized inventory"}
```

该 API 只接受显式域名列表（1–500）。使用前三种模式前必须配置并启用
`dns_follow_up`：`authorized_cidrs` 是可扫描地址 allowlist，`excluded_cidrs` 优先排除地址，
`max_targets_per_task` 控制每个地址族子任务的目标上限。解析结果会去重；不在授权范围内的
地址不会进入扫描队列。策略关闭时服务端拒绝创建域名后续扫描。`dns_records` 不依赖该策略，
不允许携带非空 `port`。

```toml
[dns_follow_up]
enabled = true
authorized_cidrs = ["192.0.2.0/24", "2001:db8::/32"]
excluded_cidrs = ["192.0.2.128/25"]
max_targets_per_task = 100
```

示例网段仅用于说明，部署时必须替换为组织已书面授权的实际范围。

前端“创建扫描”页使用单一目标输入框，完整校验后把整批目标识别为 IPv4/CIDR、IPv6/CIDR
或域名，并自动选择对应创建接口。多个目标可用逗号或换行分隔，但同一次输入只能使用一种
分隔符，且不能混合目标类型。“仅 DNS”只有在整批目标均识别为域名时才可选；提交前仍会
再次校验。扫描域名必须至少包含两个由 `.` 分隔的标签，仅允许 ASCII 字母、数字及非首尾
连字符；单标签最多 63 octets，完整 wire name 最多 255 octets（不含末尾根点的点分形式最多
253 octets）。长度限制依据 [RFC 1035 §2.3.4](https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.4)，
字符规则采用其 [§2.3.1 preferred name syntax](https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.1)。
首字符允许数字遵循 [RFC 1123 §2.1](https://www.rfc-editor.org/rfc/rfc1123.html#section-2.1) 的放宽。
DNS 父任务支持自动分配、指定扫描器和全部扫描器；生成的 IP 子任务按系统任务保存，可通过任务列表的系统
任务开关查看。

## Elasticsearch 配置与保留

```toml
[elasticsearch]
enabled = true
dns_observation_data_stream = "network-mapping-dns-observations"
dns_record_index = "network-mapping-dns-records-v1"
dns_observation_retention_days = 180
```

首次 DNS 上传会创建 Data Stream template、Data Stream 与 current-record index。观测使用确定性 `create`，重传 409 视为幂等成功；当前 RR 使用带 `retry_on_conflict` 的脚本化 upsert。部署账户需拥有管理该 template/Data Stream、向 Data Stream `create` 和向 RR index `update` 的最小权限。

不要把 `dns-records` 嵌入 IP、服务或 HTTP 文档。查询 Domain→IP 或 IP→Domain 时以 `ip` 字段关联，由后端组合查询。`domain-assets` 是可重建详情页投影，尚未创建；大规模 CDN 域名必须设置每种 RR 的数量上限和截断标记后才可启用。

## 域名任务排除

运行策略“DNS 排除与解析后扫描”中的 `excluded_domains` 对所有 DNS 任务生效，支持精确项和左侧 `*.` 各级子域项。该策略独立于 DNS 后续端口扫描开关；OpenAPI 仍需满足应用自己的允许范围。详细语义与旧域名白名单迁移见[搜索触发目标更新](SEARCH_TARGET_GENERATION.md#域名排除与升级)。
