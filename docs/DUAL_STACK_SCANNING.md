# 双栈扫描、协议能力与自动目标

本文说明服务端如何区分 IPv4/IPv6 任务、接收扫描器公网协议探测结果、选择兼容扫描器，
以及分别维护 IPv4/IPv6 自动目标队列。

## 设计原则

- 一个任务只包含一种地址族：`ipv4` 或 `ipv6`。
- 地址族由服务端解析目标后得出，不信任客户端提交的地址族字段。
- 扫描器连接服务端时使用的来源 IP 不代表扫描能力；能力必须通过心跳显式上报。
- `supported` 表示该协议没有被扫描端配置禁用，`ready` 表示内核能为该地址族选择源地址和路由。
- 服务端不会把 IPv6 任务分配给 IPv4-only 或 IPv6 路由不可用的扫描器。
- 自动目标永远限定在配置的授权 CIDR 内，不发现或扩展未经授权的地址范围。
- 排除 CIDR 的优先级高于授权 CIDR，候选任务与排除范围相交时不会生成。

当前可用性探测验证的是扫描器操作系统能否为对应地址族选择源地址和路由，但不能证明
扫描器可以访问任意私有网段，也不能替代路由、ACL 和扫描引擎的实际运行验证。公网 IP
查询只补充出口地址；查询失败不会把对应地址族标记为不可用。

## 数据流

```text
扫描器 IPv4/IPv6 路由检查
          │
          ├── GET /api/scanner/network/public-ip
          │        返回服务端观察到的来源 IP
          │
          ▼
POST /api/scanner/heartbeat
          │
          ├── 保存 supported/ready、公网地址、失败原因
          └── 刷新 network_capabilities_updated_at
                              │
创建或自动生成单地址族任务 ───┤
                              ▼
                    GET /api/task/apply
                              │
                    地址族与扫描器能力匹配
                              │
                              ▼
                         扫描器执行
```

## 心跳协议

扫描器在原心跳字段之外提交 `network_capabilities`：

```json
{
  "scanner_id": "019c0000-0000-7000-8000-000000000001",
  "state": "idle",
  "active_task_id": null,
  "scanner_version": "0.1.0",
  "system": {
    "os_name": "Linux",
    "os_version": "6.x",
    "cpu_model": "Example CPU",
    "cpu_cores": 8,
    "ram_total_mb": 16384,
    "uptime_seconds": 3600
  },
  "network_capabilities": {
    "ipv4": {
      "supported": true,
      "ready": true,
      "public_ip": "203.0.113.10",
      "reason": null
    },
    "ipv6": {
      "supported": true,
      "ready": false,
      "public_ip": null,
      "reason": "probe_request_failed: ..."
    }
  }
}
```

服务端会验证 `public_ip` 的格式和地址族。IPv4 字段携带 IPv6 地址或反之时返回 400。
失败原因以 JSON 保存并在扫描器详情接口返回；扫描端会将原因截断，避免错误响应无限增长。

### 鉴权公网 IP 接口

扫描器优先通过服务端查询自己的公网出口地址：

```http
GET /api/scanner/network/public-ip?scannerid=<UUID>
Authorization: Bearer <runtime_token>
```

成功响应使用当前连接的实际地址族：

```json
{"ip":"203.0.113.10"}
```

接口复用扫描器运行令牌校验，只允许已注册、已启用且令牌匹配的扫描器访问，并返回
`Cache-Control: no-store`。服务端直接终止 TLS 时以 TCP 对端地址为准，不信任客户端自行
提交的转发头。

如果服务端位于反向代理后，管理员可以在 Web“系统设置 → 来源 IP 可信代理”中配置代理的
IPv4/IPv6 CIDR，并选择由代理维护的 `X-Forwarded-For`、`Forwarded` 或自定义请求头。
自定义请求头适用于 `X-Real-IP`、`CF-Connecting-IP` 等传递裸 IP 或逗号分隔 IP 链的字段；
只有 `Forwarded` 会按 RFC 7239 的 `for` 参数解析。配置写入数据库并立即生效，无需重启
服务。留空表示禁用转发头解析；服务端拒绝 `0.0.0.0/0` 和 `::/0`，最多允许 32 条 CIDR，
请求头名称最长 64 个字符。

解析遵循以下规则：

1. TCP 直连地址必须命中可信代理 CIDR，否则完全忽略转发头。
2. 只读取 Web 界面选中的一种请求头；请求头名称会被校验并规范化为小写。
3. 从右向左剥离可信代理，取第一个非可信地址作为请求来源地址。
4. 请求头缺失、无法解析或整条代理链均为可信地址时，安全回退到 TCP 对端地址。

服务端在请求入口只解析一次来源 IP，并将同一结果用于请求日志、安全审计、登录记录、限流、
健康告警和扫描器接口，避免同一个请求在不同模块中显示不同地址。

例如 Nginx 与服务端同机部署时，可将 `127.0.0.1/32`（按实际监听方式也可能需要
`::1/128`）加入可信代理，并使用：

```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

服务端会把 `::ffff:127.0.0.1`、`::ffff:64.81.116.137` 等 IPv4-mapped IPv6 地址规范化为
普通 IPv4 地址。因此代理对端显示为 `::ffff:127.0.0.1` 时，应将 `127.0.0.1/32` 加入可信
代理；连接方式可能在原生 IPv6 loopback 与 IPv4-mapped loopback 间变化时，可同时配置
`127.0.0.1/32` 和 `::1/128`。扫描器心跳连接地址、请求/审计来源地址和接口响应均以不带
`/32`、`/128` 前缀长度的规范地址显示。

如果还有上游负载均衡器，应逐跳加入实际代理网段，并确保每一层都追加或重写同一个请求头。
使用 `X-Real-IP`、`CF-Connecting-IP` 等单值自定义头时，最后一层可信代理必须覆盖客户端提交
的同名字段，不能直接透传。不要把普通客户端可以直接连接的地址范围设为可信代理。

管理员配置接口为：

```http
GET  /api/config/security/trusted-proxies
POST /api/config/security/trusted-proxies
```

POST 请求示例：

```json
{
  "trustedProxyCidrs": ["127.0.0.1/32", "10.20.0.0/16"],
  "clientIpHeader": "x-forwarded-for"
}
```

自定义请求头示例：

```json
{
  "trustedProxyCidrs": ["127.0.0.1/32"],
  "clientIpHeader": "cf-connecting-ip"
}
```

旧版扫描器省略 `network_capabilities` 时，服务端按以下值兼容：

```text
IPv4: supported=true, ready=true
IPv6: supported=false, ready=false
```

## 数据库字段

`scan_task`：

| 字段 | 类型 | 说明 |
|---|---|---|
| `address_family` | TEXT | `ipv4` 或 `ipv6` |

`scanner_info`：

| 字段 | 类型 | 说明 |
|---|---|---|
| `supports_ipv4` / `supports_ipv6` | BOOLEAN | 扫描端是否启用对应协议 |
| `ipv4_ready` / `ipv6_ready` | BOOLEAN | 最近一次探测是否成功 |
| `public_ipv4` / `public_ipv6` | INET | 探测得到的公网地址 |
| `network_status_reason` | JSONB | 两种协议的失败原因 |
| `network_capabilities_updated_at` | TIMESTAMPTZ | 最近一次能力心跳时间 |

启动时执行的 `source/database/init.sql` 会为已有数据库补列。已有纯 IPv6 任务会根据
`task_target` 回填为 `ipv6`，其余旧任务保留为 `ipv4`。

## 创建任务

请求格式保持不变：

```json
{
  "ip": "2001:db8:100::10/128,2001:db8:100::20/128",
  "port": "22,80,443",
  "level": 1,
  "remark": "IPv6 check",
  "dispatch_mode": "automatic",
  "scanner_ids": []
}
```

规则：

- 所有目标都是 IPv4 时写入 `address_family=ipv4`。
- 所有目标都是 IPv6 时写入 `address_family=ipv6`。
- 混合目标返回 400，调用方应拆成两个任务。
- `selected` 模式下任一指定扫描器不兼容时返回 400。
- `all` 模式仅为当前兼容的扫描器创建执行实例；没有兼容扫描器时返回 409。
- `automatic` 模式允许任务先进入等待队列，之后由兼容扫描器领取。

任务领取响应增加：

```json
{
  "task_id": "019c0000-0000-7000-8000-000000000002",
  "task_target": ["2001:db8:100::10/128"],
  "task_port": "22,80,443",
  "address_family": "ipv6"
}
```

扫描器在执行前仍会检查本地最新能力。如果领取后协议状态发生变化，它会先刷新心跳，
再将任务作为可重试失败上报，避免继续执行不兼容任务。

## 调度条件

| 任务地址族 | 必须满足的扫描器字段 |
|---|---|
| IPv4 | `supports_ipv4 AND ipv4_ready` |
| IPv6 | `supports_ipv6 AND ipv6_ready` |

自动目标生成还要求扫描器：

- `is_enable=true`；
- 未软删除；
- 最近 90 秒收到过心跳。

## 自动目标配置

```toml
[automatic_target]
# IPv4 开关，为兼容旧配置继续使用 enabled
enabled = true
strategy = "sequential_subnet"
interval_seconds = 30
pending_low_watermark = 2
pending_high_watermark = 5
priority = 0
authorized_cidrs = ["198.51.100.0/24"]
excluded_cidrs = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "127.0.0.0/8",
  "169.254.0.0/16"
]
ipv4_task_prefix = 24

# IPv6 独立开关、授权范围和队列水位
ipv6_enabled = false
ipv6_authorized_cidrs = ["2001:db8:100::/64"]
ipv6_excluded_cidrs = ["fc00::/7", "fe80::/10", "::1/128"]
ipv6_task_prefix = 120
ipv6_pending_low_watermark = 1
ipv6_pending_high_watermark = 2

common_ports = "22,80,443"
repeat_after_seconds = 604800
```

### 生成行为

- 每个地址族的待领取任务低于低水位时，补充到对应高水位。
- IPv4 和 IPv6 使用独立游标，互不占用队列配额。
- 没有对应地址族的在线就绪扫描器时暂停生成，不删除已有等待任务。
- `repeat_after_seconds` 内不会为同一地址族和 CIDR 重复生成任务。
- 候选任务只要与对应排除 CIDR 有任何交集，就跳过整个候选任务。
- 顺序游标命中排除网段时直接跳到整段之后（含跨授权池边界），不会逐个子网爬行；
  例如强制排除的 `0.0.0.0/8` 含 65536 个 `/24`，一次生成即可越过。整段跳跃记录
  `AutomaticTargetExcludedBlockSkipped` 日志（含起止 CIDR 与跳过的子网数）。
- IPv4 延续原有状态键和 generation key，升级不会主动重置现有 IPv4 游标。
- 策略变更（如修改 `common_ports`、授权范围、排除范围或任务前缀）保留游标的覆盖
  位置，仅按新的子网空间取模归一，不会归零重扫已覆盖的地址空间。
- IPv6 子网数量和游标使用 128 位整数；数据库和状态接口以十进制字符串保存和返回，
  避免 JSON 大整数精度损失，并兼容读取旧版数字游标。
- 允许使用 `::/0` 作为 IPv6 授权范围。默认按 `/120` 生成时，每个任务仍只包含 256 个
  地址；授权整个地址空间不会生成一个巨大的 `/0` 扫描任务。

IPv6 地址空间非常大。默认 `/120` 使单任务最多覆盖 256 个地址；即使配置允许，也不应
直接生成 `/64` 扫描任务。网络测绘场景可将 `ipv6_authorized_cidrs` 配置为 `["::/0"]`，
并通过 `ipv6_excluded_cidrs` 排除不应扫描的范围。顺序遍历完整 IPv6 空间在现实时间内无法
穷尽；对于发现效率要求较高的场景，仍建议优先加入已知活跃网段，后续也可替换为资产清单
或命中率驱动的生成策略。

### 状态接口

管理员调用 `GET /api/automatic-target/status`，响应按地址族返回：

- 是否启用；
- 授权 CIDR、排除 CIDR 和任务前缀；
- 低/高水位；
- pending/running 数量；
- 当前就绪扫描器数量；
- 游标位置、总子网数（IPv6 均为十进制字符串，IPv4 保持数字格式）；
- 游标指向的下一个任务 CIDR（`next_target`，授权范围为空时为 `null`）；
- 最近生成时间和错误。

### 手动调整生成游标

管理员可以把生成游标移动到授权范围内的任意位置，用于从指定网段继续扫描、
跳过已覆盖区域或在故障恢复后对齐进度。两个入口等价：

- Web：「设置 → 运行时配置 → 自动扫描策略」中的生成游标卡片，按地址族显示
  当前位置、对应 CIDR、子网总数、最近生成时间和错误，输入新位置后保存；
- API：`POST /api/automatic-target/cursor`（仅管理员），请求体：

```json
{ "address_family": "ipv4", "target": "1.250.4.0/24" }
```

`position` 与 `target` 必须且只能提供其一：

| 字段 | 说明 |
|---|---|
| `address_family` | `ipv4` 或 `ipv6` |
| `position` | 十进制位置序号，数字或字符串（IPv6 大整数请用字符串），范围 `0 ≤ position < total_subnets` |
| `target` | 任务 CIDR，前缀必须等于该地址族的任务前缀（如 `/24`），且完整落在某个授权池内；服务端自动换算为位置序号 |

成功响应返回新位置、原位置、对应 CIDR 与子网总数：

```json
{
  "success": true,
  "data": {
    "address_family": "ipv4",
    "position": 129540,
    "previous_position": 24832,
    "target": "1.250.4.0/24",
    "total_subnets": 16777216
  }
}
```

行为边界：

- 游标写入与生成器补充事务共用同一行锁，手动调整后的下一个生成周期即从新位置
  继续；手动调整不会立即创建任务，也不会删除已排队任务。
- 位置越界、CIDR 不在授权范围、前缀不一致、未知地址族或授权范围为空时返回
  400 及中文原因；数据库错误返回 500。
- 每次成功调整写入审计事件（类别 `automatic_target`，动作 `cursor.manual_update`），
  记录操作者、新旧位置、对应 CIDR 与策略哈希。
- 手动调整只移动覆盖指针，不改变冷却期去重：`repeat_after_seconds` 内已生成过
  任务的网段仍会被跳过。

## 扫描器查询接口

`GET /api/scanner/list` 和 `GET /api/scanner/{id}` 会返回网络能力字段。公网出口地址属于
部署信息，只有已有扫描器管理权限的用户才能通过这些接口查看，不应写入公开日志或截图。

## 升级与回滚注意事项

1. 先升级服务端，使数据库字段和兼容逻辑生效。
2. 再逐台升级扫描器。未升级设备在过渡期间继续承担 IPv4 任务。
3. 确认扫描器详情页出现能力检测时间和公网地址。
4. 最后按需配置并启用 IPv6 自动目标。

旧版服务端无法识别新版心跳中的额外字段时通常会由 Serde 忽略，但不具备地址族调度；
因此不建议先大规模升级扫描端并创建 IPv6 任务后再回滚服务端。

## 故障排查

### IPv6 始终不可用

1. 查看扫描器详情中的 `network_status_reason.ipv6`。
2. 确认主机存在 IPv6 地址、默认路由并允许 HTTPS 出站。
3. 确认服务端域名具有 AAAA 记录，且服务端监听地址和防火墙允许 IPv6 连接。
4. 服务端 IPv6 不可达时，确认备用 IPv6 IP 回显接口可用。
5. 等待下一次探测周期，或重启扫描器触发启动探测。

### IPv6 任务一直 pending

检查是否至少有一台启用、最近 90 秒在线且 `supports_ipv6=true`、`ipv6_ready=true` 的扫描器。
任务不会回退到 IPv4 扫描器。

### 自动目标没有生成

检查对应地址族开关、授权 CIDR、队列水位、在线扫描器数量和
`GET /api/automatic-target/status` 中的 `last_error`。配置校验失败会阻止服务端启动，
而没有就绪扫描器只会暂停该地址族生成。

若各项正常但长时间没有新任务，查看状态接口的 `cursor_position` 与 `next_target`：

- 游标停在某个排除网段内：当前版本会整段跳过并记录
  `AutomaticTargetExcludedBlockSkipped` 日志；旧版本曾以每轮最多 256 个子网的速度
  爬行排除段（如 `0.0.0.0/8` 需约 2 小时），期间无任何日志。
- 游标指向的网段近期已扫描过：冷却期（`repeat_after_seconds`）内会跳过，
  日志计入 `skipped_recent`。
- 需要立即对齐进度时，使用[手动调整生成游标](#手动调整生成游标)把游标移到
  期望的网段，而不是等待顺序遍历。

## 排除范围

`excluded_cidrs` 和 `ipv6_excluded_cidrs` 用于在授权范围内进一步划出禁止自动扫描的地址。
它们只影响自动目标生成，不限制用户通过 `POST /api/task/create` 手工创建任务。

排除采用“任务级安全跳过”，不是从候选任务中切掉部分地址。例如：

```toml
authorized_cidrs = ["198.51.100.0/24"]
ipv4_task_prefix = 24
excluded_cidrs = ["198.51.100.128/25"]
```

虽然只排除了后半个 `/25`，候选任务是完整 `/24`，二者存在交集，因此
`198.51.100.0/24` 整个任务都不会生成。若仍需扫描前半段，应把任务前缀调整为 `/25`
或把授权范围改成明确的 `198.51.100.0/25`。

配置校验规则：

- IPv4、IPv6 排除项必须分别放入对应字段；
- 每项必须是合法 CIDR；
- 同一排除列表内不允许重复或相互重叠；
- 排除项可以位于授权范围之外，此时不会产生影响；
- 旧配置未提供排除字段时按空列表处理，保持原生成行为。

以下列表适合希望避免自动生成常见非公网地址的部署：

```toml
excluded_cidrs = [
  "10.0.0.0/8",       # RFC1918
  "172.16.0.0/12",    # RFC1918
  "192.168.0.0/16",   # RFC1918
  "127.0.0.0/8",      # loopback
  "169.254.0.0/16"    # link-local
]
ipv6_excluded_cidrs = [
  "fc00::/7",          # ULA
  "fe80::/10",         # link-local
  "::1/128"            # loopback
]
```

如果系统用途就是扫描已授权的内网资产，应删除相应排除项，而不是扩大授权范围绕过它。
