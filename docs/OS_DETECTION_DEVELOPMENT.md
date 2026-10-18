# 操作系统识别开发与维护

[使用说明](OS_DETECTION.md) · [结果协议](SCAN_PIPELINE.md) · [存储说明](ELASTICSEARCH.md)

本文描述已实现的模块、数据约束与验证方式。

## 模块与数据流

`src/os_detection.rs` 提供有界特征解析、规则判断、资产摘要融合及结果模型。
`src/elasticsearch/os_detection.rs` 负责 PostgreSQL 队列、租约、分页和 ES 条件更新。
识别工作由现有 ES 后台循环调度，每轮处理一个有界页面，与资产发布和标签任务轮流执行。

扫描器上传协议保持兼容。当前 `ServiceObservation.data.schema_version = 2` 使用
`evidence[].module` / `evidence[].result`；解析器也兼容无 schema 版本的旧 `evidence` 数组
及直接 `result` 模块 envelope。
未知 schema 版本不进行递归字符串匹配，仍可使用独立的协议 Banner。

只读取协议所属的白名单字段：SSH `server_id.raw/software`、HTTP `response.headers` 中的
`Server`、SMB `native_os`（含已支持的嵌套路径）、RDP `native_os/server_os`，以及已明确
协议的 FTP/SMTP Banner。不从网页正文、证书主题、主机名或任意 JSON 字符串猜测系统。
探测类型存在不意味着引擎一定返回这些字段，SMB/RDP 缺少明确系统字段时保持未知。

每段文本最多处理 4096 字符，单个端点最多保留 32 条规则证据；响应头和 evidence 数量
也有固定上限。相同家族、协议与端口按证据组计分，60 分为一个支持组，累计封顶 100。
高置信度还要求不同协议。宽泛 Unix 与更具体 Unix 类线索可合并，其他家族冲突不会强选。

## 队列与幂等边界

`migrate_os_detection.sql` 同时用于新建库和启动时的幂等升级：

| 表 | 内容 |
| --- | --- |
| `os_detection_outbox` | `(execution_id, ruleset_revision)` 唯一任务、游标、租约、退避和完成状态 |
| `os_detection_backfill` | 每个规则版本的历史执行回填水位 |

新执行在成功确认的 PG 事务中入队。历史任务按执行 ID 每轮最多 100 条入队，回填水位与
入队在同一事务提交，避免每轮重新扫描全部已完成历史。领取还要求执行成功且资产投影
已发布。`SKIP LOCKED`、claim token 和租约防止并发领取；过期任务可恢复。

每个 ES 页面最多 64 条 service observation，游标由 IP、端口、观察时间与 observation key
组成。PG 连接不会跨越 ES 请求；ES 请求期间单独续租。每项 Bulk 结果通过验证后才推进
游标，失败保留游标并退避重试。后续页面仅读取原始观察，不依赖端点投影立即可搜索；
识别阶段不主动刷新索引，结果遵循 ES 配置的正常刷新周期。任务完成表示写入已确认，
查询可见性可能稍晚；若运维禁用自动刷新，需要按维护策略自行恢复或刷新。

## 原始事实与投影

原始 observation、`data`、批次 checksum、文档 checksum 及原始 `_id` 不包含 OS 派生结果。
不要把新规则输出加到 `observation_rows`：现有 checksum 计算会包含除指定可变情报外的字段，
这种修改会使跨版本重试发生内容冲突。

执行端点和当前端点增加显式 `os` mapping 及 `service_observation_ref`。后者记录原始观察
的确定性 ID，识别后补充索引引用。原始引用、规则、字段路径及证据时间可以追溯每个判断。

OS 更新只匹配当前服务证据 ID 和时间；旧投影回填还要求匹配执行、用户、服务和 Banner。
没有匹配时执行 noop，不通过 upsert 重建已经删除的端点。新服务观察使 OS 重新进入 pending；
端口观察保留先前 OS 和服务时钟。重复发布同一证据保留已经完成或更新版本的 OS 结果。

`global`、`user`、`api_client` 各自保存当前端点摘要。资产接口先按调用者权限过滤，再按
状态和家族分桶采集有界证据样本，防止分页隐藏少数家族的冲突。所有家族都参与判断；
详情片段最多返回 32 条。按证据原始执行记录扫描器来源，端口后来被其他节点发现不会改写证据来源。跨扫描器汇总置信度封顶为中，宿主机精确版本为空。
私有地址重复仍受现有 `(IP, port)` 资产模型限制，不能把该模型当作网络域隔离标识。

Web 的 `os` 对象包含状态、判断对象、系统字段、候选、证据、规则版本、证据时间和过期标识。
外部 API 的 `os` 必须单独批准，投影时移除证据和候选，仅提供摘要；`os.*` 查询也受该权限控制。

## 修改规则与回填

行为变化时同时递增 `RULESET_REVISION` 和更新 `RULESET_VERSION`。后台会为新版本创建独立
回填水位和任务，不修改原始观察。低版本任务不得覆盖高版本结果。
同版本失败任务自动恢复；需要人工重放同版本时，在维护窗口重置相应任务的游标、完成
标识、租约和退避状态。不要删除扫描回执或原始证据来触发重算。

## 验证

从服务端仓库执行：

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets
cargo test --locked --workspace --lib
```

队列测试需要可创建、删除隔离 schema 的 PostgreSQL：

```sh
STORAGE_TEST_DATABASE_URL='host=127.0.0.1 dbname=storage_test user=test' \
  cargo test --locked os_jobs_wait_for_publication_and_recover_expired_leases -- --ignored --test-threads=1
```

真实 ES 检查要求受支持的 9.5.x，只创建带随机 `nm-os-test-` 前缀的测试资源：

```sh
STORAGE_TEST_DATABASE_URL='host=127.0.0.1 dbname=storage_test user=test' \
OS_TEST_ELASTICSEARCH_URL='http://127.0.0.1:9200' \
  cargo test --locked live_os_enrichment_preserves_raw_checksums_and_newer_service_evidence -- --ignored --test-threads=1
```

有认证或自定义 CA 的测试集群可改用 `STORAGE_TEST_CONFIG_PATH` 指向本地服务端配置，勿提交
该文件。HTTP fixture 不能替代真实 ES 的 mapping、Painless 和分片刷新验证。
`.github/workflows/os-detection.yml` 在 PR 中启动隔离 PG 与 ES 9.5.4，运行上述专项检查。

接口字段更新后运行 `cargo run --locked --example export_openapi > docs/open-api/openapi.json`，
并执行 OpenAPI 一致性测试。新增规则需覆盖通用软件、非标准端口、伪造正文、未知 schema、
不同系统冲突、软件包版本与系统版本混淆、重复证据及过期证据。
