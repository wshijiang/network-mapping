# Web 技术栈识别开发与维护

[使用说明](WEB_DETECTION.md) · [扫描协议](SCAN_PIPELINE.md) · [Elasticsearch 存储](ELASTICSEARCH.md)

## 当前实现

`src/web_detection.rs` 解析有界 HTTP 证据，`src/web_detection/rules.json` 定义内置规则。
HTML 使用 scraper 解析 DOM，不把页面正文当作产品名称词典。
支持 schema 2 的 `data.evidence[].module/result`、无版本的旧 evidence 和明确 HTTP 服务的
`data.result` envelope；未知 schema 返回 `unsupported`，不会递归搜索 JSON 字符串。

每份正文最多 256 KiB，单值最多 4096 字节，每份 evidence 数组最多 32 项；
每份响应最多处理 512 个头值，每条选择器最多处理 512 个元素，最多返回 64 个组件、
每组件 8 条去重证据。资源只匹配 HTTP(S) URL path，Cookie 只匹配名称。
超长标量不根据被截断的前缀作精确判断；派生证据不保留 ID 值、资源查询参数、桶名或 Git refs。
规则首次使用时校验、编译，不从远程下载或执行。非法规则会使验证失败。

### 原子条件与组合条件

既有扁平规则继续兼容。原子条件支持：

| source | 检查范围 |
| --- | --- |
| `header` | 指定名称的响应头值；禁止直接读取 Set-Cookie 值 |
| `header_name` | 指定响应头是否出现，只记录头名称 |
| `cookie_name` | Cookie 名称 |
| `selector` | 指定 DOM 元素存在性或属性 |
| `resource` | src/href 中 HTTP(S) 资源的 path |
| `title` | title 的有界文本，不能选择任意页面正文 |
| `s3_xml` | XML 媒体类型下已验证的 S3 结构标记 |
| `git_advertisement` | 媒体类型与 pkt-line 一致的 Git 广告标记 |

`source=composite` 使用 `all`、`any`、`not` 数组。all 全部满足，非空 any 至少一项满足，
not 必须全部不匹配。每条规则含主条件在内最多 8 个原子条件，不允许递归组合或仅有 not。
有主条件的扁平规则也可增加条件组。条件在同一 HTTP 响应视图中匹配；通过全部条件后才提交正向证据。
不完整输入无法通过 not；协议解析失败不能作为否定证明，所以协议来源不允许出现在 not。

```json
{
  "id": "minio-console",
  "technology": "minio",
  "name": "MinIO",
  "category": "object_storage",
  "source": "composite",
  "all": [
    { "source": "title", "pattern": "(?i)^MinIO Console$" },
    { "source": "selector", "selector": "meta[name=description]", "attribute": "content", "pattern": "(?i)^MinIO Console$" }
  ],
  "confidence": "high",
  "usage": "response_marker"
}
```

`version_group` 指向正则捕获组；协议和头名称条件不能提取软件版本。同一组件合并去重，
不因重复命中累计置信度；多个明确版本返回冲突标记。资源和 DOM 同时参与时显示为多种证据。

### 协议解析

`src/web_detection/protocol.rs` 仅解析内存中的响应，既不访问目标也不解析外部实体。
S3 使用 quick-xml 解析有效的列表/错误 envelope，核对命名空间、必要字段与响应头；
拒绝 DTD、未知实体、嵌套 Code/RequestId、多个根和未闭合 XML，深度上限 32、事件上限 16384。
仅输出固定结构名和允许的错误码，不复制桶名、对象名、RequestId 或 HostId。

Git 校验广告媒体类型、十六进制 pkt-line 长度、操作名和 flush；v2 还要求 ls-refs 与 fetch
能力，最多检查 128 条能力行。仅输出 upload-pack/receive-pack 标记，不保留 refs 或 agent。
普通 GitLab 页面、`.git` 路径和通用 SSH 服务不能证明 Git smart HTTP 能力。

目录与分批状态见 [Web 技术目录](WEB_TECHNOLOGY_CATALOG.md)。
`fixtures.json` 为合成正例，测试核对每个扩展组件的技术集合、版本与敏感值不泄漏；
另测缺少条件、跨响应拼接、截断、否定、DTD、命名空间及非法 pkt-line。

## 队列、存储与更新

`src/elasticsearch/web_detection.rs` 复用 OS 识别的队列机制，独立维护
`web_detection_outbox` 和 `web_detection_backfill`。
队列主键为 `(execution_id, ruleset_revision)`，执行成功事务中入队；历史成功执行每轮
最多 100 条入队，领取还要求端点发布完成。使用 `SKIP LOCKED`、claim token、租约续期、
失败退避和每页最多 64 条 observation 的游标处理；PG 连接不跨 ES 请求持有。

派生结果仅写 execution/current endpoint 的 `web` 对象，不修改原始 observation、
`observation_rows`、文档 checksum 或上传 checksum。现有 `(IP, port)` 模型保留，
`inference_scope=ip_endpoint` 明确当前精度；此版本没有完整的独立域名 Web 资产索引。

更新同时检查 service observation 引用和时间，旧投影回填还需匹配用户、服务时间、服务及 Banner。
端点的最新执行 ID 可能来自后续端口扫描，不能用于限制旧服务证据的回填；已有有效引用但指向
其他服务证据时，不使用旧投影匹配回退。修订版 4 创建独立回填水位，重新处理旧版本已完成但
漏写当前端点的任务，不修改扫描事实或要求重新扫描。
旧证据不能覆盖新服务，低规则版本不能覆盖高版本；重复发布同份证据保留已经完成的派生结果。
新服务观察重置为 pending，端口观察保留原服务结论和服务时钟。不同权限范围独立更新。
没有 upsert，已删除的端点不会通过重算复活。

`web.technologies` 使用 ES `nested` 类型。`tech = "ID@版本"` 将两个条件放在同一个 nested
查询中，否定放在 nested 查询外层；不提供可能跨组件组合的独立版本字段。
外部 API 同时检查返回字段及 DSL 访问权限，再移除各组件证据。

## 修改规则与排障

规则、解析行为或需要重新回填的派生写入逻辑变更时，同时递增 `RULESET_REVISION` 和更新 `RULESET_VERSION`。
新版本自动创建独立回填水位，历史数据只能根据仍保留的证据重算，截断部分无法恢复。
检查 `WebDetectionWorkerError`、`WebDetectionPageCompleted` 和队列中的 `last_error`、
`available_at`、租约及游标。ES 结果遵循正常刷新周期，完成写入不代表搜索立即可见。
人工重放同版本应在维护窗口重置队列任务状态，不删除原始证据或上传回执。

## 验证

从服务端仓库执行：

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets
cargo test --locked --workspace --lib
cargo run --locked --example export_openapi > docs/open-api/openapi.json
python -m mkdocs build --strict -f mkdocs/mkdocs.yml
```

使用可创建隔离 schema 的 PostgreSQL，及真实 Elasticsearch 9.5.x：

```sh
STORAGE_TEST_DATABASE_URL='host=127.0.0.1 dbname=storage_test user=test' \
  cargo test --locked --lib web_jobs_wait_for_publication_and_recover_expired_leases -- --ignored --test-threads=1

STORAGE_TEST_DATABASE_URL='host=127.0.0.1 dbname=storage_test user=test' \
OS_TEST_ELASTICSEARCH_URL='http://127.0.0.1:9200' \
  cargo test --locked --lib live_web_enrichment_preserves_raw_checksums_and_newer_service_evidence -- --ignored --test-threads=1
```

`OS_TEST_ELASTICSEARCH_URL` 是当前共享真实 ES 测试配置读取器沿用的环境变量名。
有认证或自定义 CA 时使用既有 `STORAGE_TEST_CONFIG_PATH`。
集成测试使用随机 `nm-web-test-` 前缀，结束后清理测试数据；不能用 HTTP fixture
替代真实 mapping、nested 查询、Painless 条件更新和重放验证。

## 后续阶段（尚未实现）

1. 补齐域名任务的 hostname、Host/SNI 与 connect IP；在权限范围内按 scheme、host、port、
   应用路径及连接地址保存站点观察。以独立 Web 执行/当前索引承载多站点，端点仅保存摘要。
2. 通过新能力和协议版本承载多份 Web 证据，增加有界重定向、静态资源和 favicon 采集；
   对每次跳转和资源访问应用目标授权范围，保存完整采集状态。
3. 将审核过的 Nuclei 技术模板结果与漏洞结果分开，保留模板版本和证据；
   按需引入浏览器隔离执行、运行时技术与版本探测。

新协议上线必须先升级服务端，再灰度扫描器。回滚前停止新任务领取并排空本地待上传批次，
不删除 SQLite 状态或上传回执来绕过版本问题。
