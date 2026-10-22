# 资产搜索语法与 API

本文档描述 Network-Mapping 高级搜索的结果语义、查询语法、字段、标签行为、API、限制和
兼容策略。前端搜索页使用 `POST /api/search/v2`，旧版单条件搜索接口暂时保留。

## 1. 搜索结果语义

### 1.1 默认结果单位

每条结果表示一个当前可见的服务端点：

```text
(IP 地址, 端口)
```

因此下面的条件要求同一个端点同时满足端口和服务条件：

```text
port = 443 AND service = "https"
```

返回结果仍包含资产级信息，包括 ASN、ISP、AS 组织、国家、城市和该 IP 的全部有效标签。

每条已授权结果另含 `intel` 自动情报：`available` 表示情报查询是否成功，`risk` 为
`malicious`、`suspicious` 或空，`matches` 保存来源与证据。IP:端口只匹配该端点，IP
证据可匹配同 IP 端点；未命中不表示正常。自动情报与人工 `tags` 独立，现有 `tag`
语法仍查询人工标签，当前没有 `intel.*` 搜索字段。精确 IOC 查询、有效期及审核规则见
[威胁情报说明](THREAT_INTELLIGENCE.md)。

### 1.2 当前状态来源

高级搜索只读取当前用户有权访问且 execution 状态为 `succeeded` 的 observation：

- 普通用户只能搜索自己任务产生的数据；
- 管理员可以搜索全部用户的数据；
- 端口、协议和扫描器取该端点最新 observation；
- 服务和 Banner 取该端点最新的 `service` observation；`source` 在存在服务 observation
  时取该服务来源，否则取端点最新 observation 来源；
- `first_seen`、`last_seen` 是可访问成功 execution 中该端点的首次和末次观察时间；
- IP 情报取当前用户可访问的最新记录；
- 标签按 IP 全局绑定，不属于某一次扫描任务。

扫描器当前只报告发现的开放端口，因此搜索结果表示“曾被成功执行观察到的当前端点视图”，
不会因后续扫描没有发现某端口就自动推断该端口已经关闭。

## 2. 快速开始

搜索单个 IP：

```text
192.0.2.10
```

搜索 CIDR 内的资产：

```text
192.0.2.0/24
```

搜索指定端口：

```text
port = 443
```

组合资产、服务和标签：

```text
ip IN 192.0.2.0/24
AND port IN (80, 443)
AND service ~ "http"
AND tag = "生产环境"
```

搜索最近七天观察到的中国 HTTPS 端点：

```text
country = CN
AND service = "https"
AND last_seen >= now-7d
```

## 3. 语法规则

### 3.1 表达式结构

简化语法如下：

```text
expression     := or_expression
or_expression := and_expression (OR and_expression)*
and_expression:= unary_expression (AND unary_expression)*
unary_expression := NOT unary_expression
                  | ( expression )
                  | predicate
                  | EXISTS(field)
                  | has_endpoint(expression)

predicate      := field operator value
                | field IN value
                | field IN (value, value, ...)
                | field NOT IN (value, value, ...)
                | field:value
```

字段名和关键字不区分大小写。字符串值可以使用单引号或双引号；包含空格、逗号、括号或
关键字的值必须加引号：

```text
tag = "核心生产资产"
banner ~ 'Welcome to nginx'
```

字符串内使用反斜杠转义引号或反斜杠：

```text
tag = "业务方标记：\"重点\""
```

条件之间必须显式写出 `AND` 或 `OR`，当前不支持以空格表示隐式 AND：

```text
# 正确
port = 443 AND service = "https"

# 错误
port = 443 service = "https"
```

### 3.2 逻辑优先级

优先级从高到低为：

1. 括号；
2. `NOT`；
3. `AND`；
4. `OR`。

以下两个查询等价：

```text
country = CN OR port = 443 AND service = "https"
country = CN OR (port = 443 AND service = "https")
```

需要先执行 OR 时必须使用括号：

```text
(country = CN OR country = SG) AND port = 443
```

### 3.3 运算符

| 运算符 | 含义 | 示例 |
|---|---|---|
| `=` | 不区分大小写精确匹配 | `service = "https"` |
| `!=` | 不等于或不存在指定标签 | `tag != "已下线"` |
| `~` | 不区分大小写的文字包含 | `banner ~ "nginx"` |
| `!~` | 不包含指定文字 | `service !~ "unknown"` |
| `>` | 大于 | `port > 1024` |
| `>=` | 大于等于 | `last_seen >= now-7d` |
| `<` | 小于 | `port < 1024` |
| `<=` | 小于等于 | `first_seen <= "2026-08-01T00:00:00Z"` |
| `IN` | 属于集合；对 IP 也表示属于 CIDR | `port IN (80, 443)` |
| `NOT IN` | 不属于集合 | `country NOT IN (US, RU)` |
| `EXISTS(field)` | 字段存在且非空 | `EXISTS(banner)` |

`~` 和 `!~` 是字面包含操作。搜索值中的 `%`、`_` 不会被当作 SQL 通配符，系统会转义后
作为普通字符搜索。当前不支持用户提供正则表达式。

### 3.4 冒号简写

为兼容旧版和方便输入，可以使用 `field:value`：

```text
port:443
service:https
banner:nginx
tag:生产环境
```

冒号会根据字段转换为不同操作：

- `service`、`banner`、`title`、`http_body`、`tls_subject`、`tls.issuer`、`tls.san`、`isp`、`org`、`city`、
  `scanner`：转换为包含匹配 `~`；
- 其他字段：转换为精确匹配 `=`；
- `ip` 的值为 CIDR 时，按网段包含关系处理。

### 3.5 域名关联搜索

`domain`（别名 `dns.domain`）是资产级字段。搜索会在当前 DNS RR 索引中查找匹配的
域名，收集其 `A`/`AAAA` 地址，并最多跟随 8 层 `CNAME` 后，以得到的 IP 筛选当前可见的
服务端点。结果单位仍是 `(IP 地址, 端口)`，不会把 DNS 记录复制进资产搜索索引：

```text
domain = "www.example.com"
domain ~ "example.com" AND port = 443
domain IN ("api.example.com", "www.example.com") AND service = "https"
```

`domain:` 等同于包含匹配。支持 `=`、`!=`、`~`、`!~`、`IN` 和 `NOT IN`；不支持
`EXISTS(domain)` 或范围比较。域名不允许写在 `has_endpoint(...)` 内。

域名搜索依赖 Elasticsearch DNS RR 索引。DNS 记录超过 10000 条、CNAME 链的唯一域名超过
1000 个时，接口返回 HTTP `422` 和 `DOMAIN_RESULT_TOO_BROAD`，请改用精确域名或增加其他
条件；索引不可用时返回 HTTP `503`，不会回退到 PostgreSQL 并返回不完整结果。

对于复杂查询建议使用完整运算符，语义更明确。

## 4. 字段参考

### 4.1 资产级字段

资产级字段属于 IP，不随结果端口变化。

| 字段 | 类型 | 支持操作 | 说明 |
|---|---|---|---|
| `ip`、`network` | IP/CIDR | `=`、`!=`、`IN`、`NOT IN` | `network` 是 `ip` 的别名 |
| `domain`、`dns.domain` | 域名 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | 经当前 A/AAAA 与 CNAME 链关联到 IP；仅 Elasticsearch |
| `asn` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | `AS4134` 与 `4134` 精确匹配等价 |
| `isp` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | ISP 名称 |
| `org`、`as_org` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | AS 组织；`as_org` 是别名 |
| `country`、`country_code` | 两位代码 | `=`、`!=`、`IN`、`NOT IN` | 例如 `CN`、`US` |
| `city`、`city_name` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | 城市名称 |
| `tag` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | 标签名称 |
| `tag.id` | 正整数 | `=`、`!=`、`IN`、`NOT IN` | 稳定标签 ID |
| `tag.kind` | 枚举 | `=`、`!=`、`IN`、`NOT IN` | `info`、`malicious`、`benign` |

示例：

```text
ip IN 2001:db8::/32 AND country = CN
asn IN (4134, AS4837)
org ~ "Cloud"
tag.kind = malicious
```

IPv6 可以直接使用；在复杂表达式中也可以加引号：

```text
ip = 2001:db8::10
ip IN "2001:db8::/32"
```

### 4.2 端点与服务字段

以下字段默认作用于当前 `(IP, port)` 结果行：

| 字段 | 类型 | 支持操作 | 说明 |
|---|---|---|---|
| `port` | 1–65535 | 比较、`IN`、`NOT IN` | 开放端口 |
| `protocol` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | 例如 `tcp` |
| `service` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | 最新服务识别结果 |
| `banner` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | 最新服务 Banner |
| `title`、`http.title` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | 最新 HTTP 页面标题 |
| `http_body`、`http.body` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | 截断后的最新 HTTP 正文，仅用于搜索 |
| `tls_subject`、`tls.subject` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | 最新 TLS 证书 Subject |
| `tls.issuer` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | 最新 TLS 证书签发者 |
| `tls.names`、`tls.san` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | 证书名称及 DNS/IP SAN |
| `tls.mode` | 枚举 | `=`、`!=`、`IN`、`NOT IN` | `direct`、`implicit` 或 `starttls` |
| `tls.version` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | 协商出的 TLS 版本 |
| `tls.cipher`、`tls.cipher_suite` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | 协商出的密码套件 |
| `tls.serial`、`tls.serial_number` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | 叶子证书序列号 |
| `tls.fingerprint`、`tls.fingerprint_sha256` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | 叶子证书 SHA-256 指纹 |
| `tls.self_signed` | 布尔 | `=`、`!=` | 是否为自签名证书 |
| `tls.not_before`、`tls.not_after` | 时间 | `=`、`!=`、`>`、`>=`、`<`、`<=` | 叶子证书有效期 |
| `source` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | observation 来源 |

示例：

```text
port >= 8000 AND port <= 8999
protocol = tcp AND port IN (22, 80, 443)
service = "https" AND banner ~ "nginx"
title ~ "camera" AND http.body ~ "hikvision"
tls.subject ~ "example.com"
service = "smtps" AND tls.self_signed = true
service = "smtp" AND tls.mode = starttls
tls.not_after < "2026-10-01T00:00:00Z"
tls.san = "mail.example.com"
EXISTS(service) AND NOT EXISTS(banner)
```

Banner、标题、HTTP Body 和 TLS Subject 查询值最少需要两个字符；其他文本值长度必须在
1–128 个字符之间。搜索结果列表不会返回完整 HTTP Body。

### 4.3 扫描器字段

| 字段 | 类型 | 支持操作 | 说明 |
|---|---|---|---|
| `scanner`、`scanner_name` | 文本 | `=`、`!=`、`~`、`!~`、`IN`、`NOT IN` | 最新端点 observation 对应的扫描器名称或 ID |

```text
scanner ~ "上海" AND port = 443
```

### 4.4 时间字段

| 字段 | 类型 | 支持操作 | 说明 |
|---|---|---|---|
| `first_seen` | 时间 | `=`、`!=`、`>`、`>=`、`<`、`<=` | 首次观察时间 |
| `last_seen` | 时间 | `=`、`!=`、`>`、`>=`、`<`、`<=` | 最近观察时间 |
| `tls.not_before` | 时间 | `=`、`!=`、`>`、`>=`、`<`、`<=` | 证书生效时间 |
| `tls.not_after` | 时间 | `=`、`!=`、`>`、`>=`、`<`、`<=` | 证书失效时间 |

支持 RFC 3339：

```text
last_seen >= "2026-08-01T00:00:00+08:00"
```

支持相对当前时间：

```text
last_seen >= now-30m
last_seen >= now-24h
last_seen >= now-7d
last_seen >= now-4w
```

相对时间单位：`m` 分钟、`h` 小时、`d` 天、`w` 周。数值必须为正整数。

## 5. 标签查询语义

标签通过 `asset_tag` 目录定义，通过 `asset_ip_tag` 绑定到 IP。同一个标签会应用到该 IP 的
所有端口和历史任务。

### 5.1 同时拥有多个标签

```text
tag = "公网" AND tag = "核心资产"
```

含义是同一个 IP 同时拥有两个标签。服务端为每个条件生成独立的存在性判断，不会要求一条
标签记录同时拥有两个名称。

### 5.2 排除标签

```text
tag != "已下线"
```

含义是该 IP 不存在名为“已下线”的有效标签。没有任何标签的资产也可以满足该条件。

以下写法等价：

```text
tag != "已下线"
NOT tag = "已下线"
```

### 5.3 标签集合和分类

```text
tag IN ("生产环境", "预发布环境")
tag.kind = malicious
tag.kind IN (malicious, info)
```

`tag.kind` 的值必须使用小写 `info`、`malicious` 或 `benign`。

## 6. 跨端点资产条件

普通端点条件必须由同一结果行满足：

```text
port = 443 AND service = "https"
```

搜索“同一个 IP 同时存在 80 和 443 两个端点”时，必须使用 `has_endpoint`：

```text
has_endpoint(port = 80) AND has_endpoint(port = 443)
```

搜索 80 端口，并要求同一 IP 还存在 HTTPS 443 端点：

```text
port = 80 AND has_endpoint(port = 443 AND service = "https")
```

`has_endpoint(...)` 内只允许使用端点字段：

```text
port, protocol, service, banner, title, http_body, tls.*, source
```

资产字段应写在函数外部：

```text
# 正确
tag = "生产环境" AND has_endpoint(port = 443)

# 错误
has_endpoint(tag = "生产环境" AND port = 443)
```

`has_endpoint` 不能嵌套。只使用 `has_endpoint` 而不指定外层端口时，会返回满足资产条件的
全部端点；如果只希望展示某个端点，应同时增加外层 `port` 或 `service` 条件。

## 7. 常用查询示例

### 7.1 Web 服务

```text
port IN (80, 443, 8080, 8443)
AND (service ~ "http" OR banner ~ "nginx" OR banner ~ "apache")
```

### 7.2 暴露的数据库服务

```text
service IN (mysql, postgresql, mongodb, redis)
OR port IN (3306, 5432, 27017, 6379)
```

### 7.3 最近出现的高位端口

```text
port > 1024 AND first_seen >= now-24h
```

### 7.4 指定网段内的恶意资产

```text
ip IN 10.20.0.0/16 AND tag.kind = malicious
```

### 7.5 有服务名但没有 Banner

```text
EXISTS(service) AND NOT EXISTS(banner)
```

### 7.6 同时提供 SSH 和 HTTPS

```text
has_endpoint(port = 22 AND service ~ "ssh")
AND has_endpoint(port = 443 AND service ~ "https")
```

## 8. HTTP API

### 8.1 请求

```text
POST /api/search/v2
Content-Type: application/json
```

接口要求有效登录 Session 和 CSRF Token。前端统一 HTTP 客户端会自动附加
`X-CSRF-Token`。

请求体：

```json
{
  "query": "country = CN AND port = 443 AND tag = \"生产环境\"",
  "limit": 50,
  "offset": 0,
  "sort_field": "last_seen",
  "sort_order": "desc"
}
```

| 参数 | 必填 | 默认值 | 范围 | 说明 |
|---|---|---|---|---|
| `query` | 是 | 无 | 最多 2048 字符 | 搜索表达式 |
| `limit` | 否 | 50 | 1–100 | 每页条数 |
| `offset` | 否 | 0 | `offset + limit ≤ 10000` | 分页偏移；最多浏览前 10000 条 |
| `sort_field` | 否 | `last_seen` | `last_seen`、`first_seen`、`ip`、`port` | 排序字段 |
| `sort_order` | 否 | 时间字段为 `desc`，IP/端口为 `asc` | `asc`、`desc` | 排序方向 |

排序在 Elasticsearch 中针对全部匹配结果执行，然后分页；页面仅导出当前页，CSV 保持响应顺序。默认结果按最近扫描时间降序、IP 升序、端口升序排列。同值时使用固定的端点键维持确定顺序；首次发现时间缺失的结果排在末尾。排序字段和方向只接受上述枚举值，非法值或超出分页窗口返回 HTTP `400`。索引在两次翻页之间若有更新，偏移分页仍可能出现重复或遗漏；需要遍历全部结果的客户端应等待后续游标分页接口。

### 8.2 成功响应

```json
{
  "query_type": "advanced",
  "query": "country = CN AND port = 443",
  "items": [
    {
      "ip_address": "192.0.2.10",
      "port": 443,
      "protocol": "tcp",
      "service": "https",
      "banner": "nginx",
      "scanner_name": "scanner-east-1",
      "scan_time": 1787270400000,
      "asn": "4134",
      "isp": "Example ISP",
      "as_org": "Example Network",
      "country_code": "CN",
      "country_name": "China",
      "region_name": "Shanghai",
      "city_name": "Shanghai",
      "tags": [
        {
          "id": 1,
          "name": "生产环境",
          "kind": "info",
          "description": null
        }
      ]
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0,
  "sort_field": "last_seen",
  "sort_order": "desc"
}
```

`scan_time` 是 `last_seen` 的 Unix 毫秒时间戳。`sort_field` 和 `sort_order` 回显实际使用的排序设置。

### 8.3 语法错误

语法、字段、类型或操作符校验失败时返回 HTTP `422`：

```json
{
  "code": "SEARCH_SYNTAX_ERROR",
  "message": "条件之间需要使用 AND 或 OR",
  "span": {
    "start": 11,
    "end": 18
  }
}
```

`span` 是前端 JavaScript 字符串使用的 UTF-16 起止位置，可直接传给输入框的
`setSelectionRange(start, end)`。

分页参数错误返回 HTTP `400`；数据库或连接池异常返回 HTTP `500`。关闭 PostgreSQL
回退且 Elasticsearch 不可用时返回 HTTP `503`。响应不会暴露内部 SQL、认证信息和底层错误。

## 9. 查询限制与安全

服务端执行以下限制：

| 限制 | 数值 |
|---|---:|
| 查询长度 | 2048 字符 |
| 逻辑/函数嵌套 | 12 层 |
| 条件数量 | 50 个 |
| 单个 `IN` 列表 | 100 个值 |
| 文本值长度 | 1–128 字符 |
| Banner/标题/HTTP Body/TLS Subject 值长度 | 2–128 字符 |
| 每页结果 | 1–100 条 |
| 最大 offset | 10000 |

查询字符串不会作为 SQL 或 Elasticsearch JSON 片段执行：

- 字段和操作符必须来自服务端白名单；
- PostgreSQL 搜索值使用绑定参数，Elasticsearch 查询由受控 AST 生成；
- `%`、`_` 在包含搜索中作为普通字符；
- 用户权限过滤由服务端固定注入，搜索语法不能覆盖；
- 当前不开放任意 `scan_observation.data` JSON 路径和正则搜索。

## 10. 兼容旧版搜索

`POST /api/search/v2` 接受旧版单条件输入：

| 旧输入 | 等价高级语法 |
|---|---|
| `192.0.2.10` | `ip = 192.0.2.10` |
| `192.0.2.0/24` | `ip IN 192.0.2.0/24` |
| `port:443` | `port = 443` |
| `service:https` | `service ~ "https"` |
| `banner:nginx` | `banner ~ "nginx"` |

以下旧接口暂时保留，供尚未迁移的客户端使用：

```text
GET /api/search/ip
GET /api/search/network
GET /api/search/port
GET /api/search/service
GET /api/search/banner
```

这些 GET 接口也接受相同的可选 `sort_field`、`sort_order` 查询参数，并遵守相同的分页窗口限制；未传参数时保持原有默认顺序。

新客户端应只使用 `/api/search/v2`，避免把查询拆分为互斥的搜索类型。

## 11. 当前边界与后续方向

当前版本尚未提供：

- 正则表达式；
- 任意 JSON 路径查询；
- 标签命名空间和端口级标签；
- facets 聚合；
- 保存查询和变化订阅；
- 游标分页。

如果新增 TLS、HTTP、证书等扫描字段，应先将稳定字段加入后端字段注册表并建立对应索引，
不应直接开放用户控制的 JSON 路径或 SQL 表达式。

## 操作系统线索字段

`os.family`、`os.distribution`、`os.version`、`os.confidence`、`os.status`、`os.score`
属于端点字段，均支持 `service.os.*` 同义写法。`os.score` 为 0–100 的整数规则得分，
不表示概率；`os.version` 仅来自明确的服务系统字段，可能为空。

```text
os.family = linux AND os.distribution = ubuntu
os.status = conflict
has_endpoint(os.family = windows) AND has_endpoint(port = 445)
```

字段含义及过期行为见[操作系统识别](OS_DETECTION.md)。资产级宿主机摘要不作为这些
端点条件的匹配对象；新数据在后台处理期间可显示 `pending`。

## Web 技术栈字段

`tech`（别名 `web.tech`）属于端点字段，支持 `=`、`!=`、`IN`、`NOT IN` 和 `EXISTS`。
使用组件 ID，或 `ID@版本` 精确限定同一组件。版本大小写保持原样，组件 ID 大小写不敏感。
`web.status` 查询 `pending/identified/unknown/partial/unsupported/not_web`。

```text
tech = elasticsearch
tech = "elasticsearch@8.19.0"
tech = nginx
tech = "jquery@3.7.1"
tech IN (wordpress, drupal)
has_endpoint(port = 8443 AND tech = nextjs)
web.status = partial
```

名称与版本由同一 ES nested 查询关联。否定条件包含尚未识别的端点；需要时附加
`web.status = identified`。不支持 `tech ~` 或独立的非关联版本字段。
证据范围与过期语义见 [Web 框架与组件识别](WEB_DETECTION.md)。

Web 技术目录现支持 `tech = minio`、`tech = s3`、`tech = gitlab` 和 `tech = git`；
产品身份与协议能力分别判断，证据要求见 [技术目录](WEB_TECHNOLOGY_CATALOG.md)。
