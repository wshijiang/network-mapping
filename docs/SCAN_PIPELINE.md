# 扫描计划与结果协议

## 任务计划

创建扫描页与域名任务 API 使用以下四种用户模式：

- “全部”/`vulnerability_scan`：端口发现、可选服务识别和必需漏洞检测；
- “仅端口”/`port_only`：只执行端口发现；
- “服务识别”/`service_inventory`：端口发现后执行必需的服务识别；
- “仅 DNS”/`dns_records`：只查询并归档 DNS 记录，只允许域名目标。

IP/CIDR 使用 `POST /api/task/create`；域名使用 `POST /api/task/create-dns`。域名选择前三种
模式时，服务端先保存一个 `dns_records` 父任务，再从其 A/AAAA 结果中筛选授权地址，按
IPv4/IPv6 和任务上限拆分为对应 profile 的子任务。“仅 DNS”不会创建子任务，也不接受
`port`。两条创建接口都会执行最终目标/profile 校验，不能依靠绕过前端提交非法组合。

两个创建接口都接受 `dispatch_mode=automatic|selected|all`。`selected` 必须同时提供非空
`scanner_ids`，另外两种模式不能附带 `scanner_ids`。域名接口按 DNS 父任务能力及显式解析器
能力校验所选节点，并为每台指定或符合“全部扫描器”的节点创建独立执行记录。

协议层还保留以下兼容 profile：

- `legacy`：兼容旧扫描器，由节点本地配置决定是否识别服务；
- `dns_ports`：对显式 domain 查询 A/AAAA 后扫描解析地址的端口；
- `dns_full`：归档 DNS 记录，并扫描解析地址的端口。

未传入时默认 `legacy`。服务端将 profile 展开为版本 1 `scan_plan` 并保存，客户端不能传入
任意命令、二进制路径或 CLI 参数。任务领取响应包含完整计划。

漏洞扫描计划固定为：

```json
{
  "version": 1,
  "profile": "vulnerability_scan",
  "stages": [
    { "type": "port_discovery", "required": true },
    { "type": "service_detection", "required": false },
    { "type": "vulnerability_detection", "required": true }
  ]
}
```

服务识别是可选阶段：节点没有启用 zgrab2 或识别失败时仍可继续 Nuclei；漏洞检测是必需阶段，
Nuclei 启动失败、非零退出、输出无效、超时或超过本地安全上限都会使执行失败。

创建 IP 漏洞扫描任务的请求示例：

```json
{
  "ip": "192.0.2.10",
  "port": "80,443,8080,8443",
  "level": 1,
  "scan_profile": "vulnerability_scan",
  "dispatch_mode": "automatic"
}
```

创建域名“全部”任务的请求示例：

```json
{
  "domains": ["api.example.com", "www.example.com"],
  "port": "80,443,8080,8443",
  "level": 1,
  "scan_profile": "vulnerability_scan",
  "dispatch_mode": "selected",
  "scanner_ids": ["019c0000-0000-7000-8000-000000000001"]
}
```

创建“仅 DNS”任务时必须使用域名接口，且省略 `port`：

```json
{
  "domains": ["example.com"],
  "level": 1,
  "scan_profile": "dns_records",
  "dispatch_mode": "automatic"
}
```

域名解析后扫描受运行时 `dns_follow_up` 策略控制。只有 `enabled=true` 且解析地址落入
`authorized_cidrs`、同时未命中 `excluded_cidrs` 时才会生成子任务。策略未启用时创建请求
返回冲突响应，不会退化为不受限扫描。

任务目标必须属于调用方已获授权的范围。服务端只负责调度和结果校验，不会代替组织完成扫描
授权审批。

## 能力调度

扫描器心跳的 `scan_capabilities` 包含 `plan_versions`、`profiles` 和 `stages`。服务端保存该
结构，并仅把非 legacy 任务分配给声明支持相应 profile 的扫描器。旧扫描器按仅支持
`legacy` 处理。

可领取漏洞任务的节点必须同时满足：

- 心跳 `scan_capabilities.plan_versions` 包含 `1`；
- `scan_capabilities.profiles` 包含 `vulnerability_scan`；
- `scan_capabilities.stages` 包含 `vulnerability_detection`；
- 目标地址族当前就绪；
- 节点在线、启用且没有被其他执行占用。

扫描器只有在本地启用 Nuclei，并通过二进制和模板目录启动检查后才声明这些能力。指定扫描器
和全部扫描器模式仍逐个应用相同的能力条件。

## 类型化结果协议

结果协议版本 3 在版本 2 的 `port` 和 `service` observations 基础上增加
`vulnerability` observation。漏洞记录保存模板 ID、名称、严重级别、匹配位置、修复建议和
引用，不接收 Nuclei 的原始请求/响应，避免将凭据、Cookie 或响应正文写入结果库。每个请求
最多 500 条，并携带：

- `upload_id`：一个任务缓存周期内保持稳定；
- `batch_index`：从 0 开始的批次序号；
- `is_final`：是否为最后一批。
- `observed_at`：观察产生时的 Unix epoch 毫秒时间，重试时保持不变。

### 漏洞 observation

```json
{
  "kind": "vulnerability",
  "ip": "192.0.2.10",
  "port": 443,
  "protocol": "https",
  "template_id": "cve-example",
  "name": "Example vulnerability",
  "severity": "high",
  "matcher_name": "body",
  "matched_at": "https://192.0.2.10:443/",
  "description": "Structured template description",
  "remediation": "Apply the vendor update.",
  "tags": ["cve"],
  "references": ["https://example.invalid/advisory"],
  "classification": {},
  "extracted_results": [],
  "source": "nuclei",
  "observed_at": 1788393600000
}
```

| 字段 | 约束 |
|---|---|
| `template_id` | 必填，最多 256 字节 |
| `name` | 必填，最多 512 字节 |
| `severity` | info、low、medium、high、critical 之一 |
| `matcher_name` | 可选，最多 256 字节 |
| `matched_at` | 必填，最多 4096 字节 |
| `description` / `remediation` | 可选，各最多 8192 字节 |
| `tags` | 最多 128 项，每项最多 128 字节 |
| `references` | 最多 64 项，每项最多 2048 字节，且仅允许 HTTP(S) URL |
| `extracted_results` | 最多 64 项，每项最多 2048 字节 |

单条 observation 的 `data` 序列化后不得超过 1 MiB。字符串中的 NUL 会被清理或拒绝。服务端
不接收 Nuclei 原始 request/response；这些字段也不会出现在扫描器缓存、PostgreSQL 或
Elasticsearch observation 中。

扫描器将任务、稳定上传身份、观察和已确认批次序号持久化到本地状态文件，重启后先恢复
未完成上传。服务端通过 `(execution_id, upload_id, batch_index)` 回执和 payload SHA-256
实现批次幂等，并要求最终批形成从 0 开始的连续序列。

扫描结果仅支持 `elasticsearch.scan_storage=elasticsearch`，PostgreSQL 保存控制面、上传回执
和派生分析快照；原始扫描结果及端点投影存储在 ES。PG 历史结果只通过独立 PG → ES 迁移命令
导入，不支持正常运行时的 PG 写入、查询或双写。参见 [ES 存储说明](ELASTICSEARCH.md)。

漏洞 observation 使用端点、模板 ID、matcher 和匹配位置生成稳定键。同一执行内的上传重试
不会重复入库；不同执行仍分别保留，用于追踪扫描历史。

DNS task 使用同一批次/回执机制，但一个批次只能包含 `dns` observations，不能与端口、服务或漏洞 observation 混合。DNS query 的 `observed_at`、question、rcode、answer sections 和解析器元数据写入 Elasticsearch Data Stream；详情见 [`DNS_MAPPING.md`](DNS_MAPPING.md)。

PostgreSQL 模式下 `scan_observation` 是事实来源，`ips`、`ports` 是资产与端口索引；ES
权威模式下对应角色分别由月度 observation 索引和 execution/current endpoint 索引承担。
读取接口按
`scan_execution_endpoint_latest` 定义的顺序选择一次执行内的端点展示结果：服务观察优先于端口观察，
再按观察时间和记录 ID 排序。端点列表使用参数化查询，仅检查当前端点的观察记录，避免为分页
结果计算全表窗口；漏洞 observation 单独展示，不参与端点当前状态投影。任务详情、搜索、导出和分析查询均不依赖 `scaninfo`。协议版本
1 的结果会直接转换为 observation，并绑定到 execution 对应的合成批次。

## 任务详情响应

`GET /api/task/{task_id}` 返回所选执行的漏洞摘要和明细：

```json
{
  "success": true,
  "data": {
    "summary": {
      "ip_count": 1,
      "port_count": 2,
      "result_count": 5,
      "vulnerability_count": 1
    },
    "vulnerabilities": [
      {
        "template_id": "cve-example",
        "name": "Example vulnerability",
        "severity": "high",
        "ip": "192.0.2.10",
        "port": 443,
        "protocol": "https",
        "matched_at": "https://192.0.2.10:443/",
        "observed_at": 1788393600000
      }
    ]
  }
}
```

`vulnerability_count` 是该执行的总数；`vulnerabilities` 最多返回最近 500 条。普通端点结果仍
通过既有分页参数读取，漏洞列表目前没有独立分页接口，也不会出现在任务导出文件中。

## 上线、兼容与回滚

跨仓库部署顺序必须为：

1. 部署服务端并执行 `source/database/init.sql` 中的幂等初始化，使约束接受新 profile、协议 3
   和 vulnerability kind；
2. 部署前端，使任务创建和详情页识别新字段；
3. 在少量扫描节点安装 Nuclei 和审核模板，启用 `[nuclei]` 并重启；
4. 完成隔离测试目标验收后再逐步扩大节点范围。

服务端必须先于扫描器升级，因为旧服务端会拒绝协议版本 3。协议 1、2 客户端可以继续与新
服务端工作，因此服务端先升级不会中断旧扫描器。

新版扫描器对所有类型化结果都使用协议 3，而不只对漏洞结果使用。回滚服务端前，必须先停止
新版扫描器领取任务，在新服务端上排空协议 3 待上传批次，再回滚扫描器二进制并确认其恢复
协议 2，最后才能回滚服务端。扫描器会把任务和批次持久化到本地 SQLite；直接降级服务端或
删除节点状态可能造成持续上传失败或结果丢失。

## 操作系统派生识别

服务端在执行成功、当前资产发布后异步解析已有 service 证据，结果不进入上传 observation
或 checksum。扫描计划和上传协议不增加 OS 阶段；本地关闭服务识别的节点仍可上传端口。
服务证据截断时可带 `evidence[].truncated`，缺失系统字段应保持未知。
字段、重算和存储约束见[识别维护说明](OS_DETECTION_DEVELOPMENT.md)。

## Web 技术栈派生识别

服务端在执行成功、端点发布后异步处理已有 HTTP/HTTPS 服务证据，独立保存技术栈派生结果。
本版本不增加扫描阶段或改变结果协议；仅端口任务不会生成新的 Web 证据。
原始事实和上传 checksum 不含识别结果。见 [使用说明](WEB_DETECTION.md)与[维护说明](WEB_DETECTION_DEVELOPMENT.md)。
