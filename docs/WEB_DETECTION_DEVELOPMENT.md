# Web 技术栈识别开发与维护

[使用说明](WEB_DETECTION.md) · [扫描协议](SCAN_PIPELINE.md) · [Elasticsearch 存储](ELASTICSEARCH.md)

## 当前实现

`src/web_detection.rs` 解析有界 HTTP 证据，`src/web_detection/rules.json` 定义内置规则。
HTML 使用 scraper 解析 DOM，不把页面正文当作产品名称词典。
支持 schema 2 的 `data.evidence[].module/result`、无版本的旧 evidence 和明确 HTTP 服务的
`data.result` envelope；未知 schema 返回 `unsupported`，不会递归搜索 JSON 字符串。

每份正文最多 256 KiB，单值最多 4096 字节，每份 evidence 数组最多 32 项；
每条选择器规则最多处理 512 个元素，最多返回 64 个组件、每组件 8 条去重证据。
资源规则只匹配 URL path；Cookie 只匹配名称。派生证据只保留命中特征或选择器，
不复制完整响应头、Cookie 值、资源查询参数或原始正文。
规则在进程首次使用时校验、编译，验证失败使测试/启动识别失败，不从远程下载或执行规则。

规则包含 `id`、`technology`、`name`、`category`、`source`、`pattern`、`confidence` 和 `usage`。
`header` 规则指定 `field`；`selector` 规则指定 CSS `selector` 和可选 `attribute`；
`cookie_name` 仅接收 Cookie 名称。`version_group` 指向正则捕获组。
同一组件多条规则合并，不因重复命中累计置信度；多版本返回冲突标记。

## 队列、存储与更新

`src/elasticsearch/web_detection.rs` 复用 OS 识别的队列机制，独立维护
`web_detection_outbox` 和 `web_detection_backfill`。
队列主键为 `(execution_id, ruleset_revision)`，执行成功事务中入队；历史成功执行每轮
最多 100 条入队，领取还要求端点发布完成。使用 `SKIP LOCKED`、claim token、租约续期、
失败退避和每页最多 64 条 observation 的游标处理；PG 连接不跨 ES 请求持有。

派生结果仅写 execution/current endpoint 的 `web` 对象，不修改原始 observation、
`observation_rows`、文档 checksum 或上传 checksum。现有 `(IP, port)` 模型保留，
`inference_scope=ip_endpoint` 明确当前精度；此版本没有完整的独立域名 Web 资产索引。

更新同时检查 service observation 引用和时间，旧投影回填还需匹配执行、用户、服务及 Banner。
旧证据不能覆盖新服务，低规则版本不能覆盖高版本；重复发布同份证据保留已经完成的派生结果。
新服务观察重置为 pending，端口观察保留原服务结论和服务时钟。不同权限范围独立更新。
没有 upsert，已删除的端点不会通过重算复活。

`web.technologies` 使用 ES `nested` 类型。`tech = "ID@版本"` 将两个条件放在同一个 nested
查询中，否定放在 nested 查询外层；不提供可能跨组件组合的独立版本字段。
外部 API 同时检查返回字段及 DSL 访问权限，再移除各组件证据。

## 修改规则与排障

规则或解析行为变更时，同时递增 `RULESET_REVISION` 和更新 `RULESET_VERSION`。
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
