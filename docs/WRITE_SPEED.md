# 扫描写入与后台资产发布

## 提交边界

上传先用短事务保存 pending 回执，释放 PostgreSQL 连接后写 Elasticsearch 原始事实和执行
端点投影。成功后再次用短事务确认回执。final 的计数、执行成功、任务聚合、分析队列和
资产发布队列在同一事务提交。事务提交并归还连接后返回原来的 `{success, saved}` 响应。

资产当前投影只由后台发布，上传及重复 final 不再同步发布整个执行。已确认批次重试仍检查
身份与 checksum，返回 saved=0，不重置发布进度。ES 成功而 PG 确认失败时仍保留 pending，
由扫描器以相同身份重试。连接池超时返回 503 和 Retry-After: 2，其他数据库错误保留原分类。

任务详情和 executions 增加 projection_status：pending、running、retrying、ready、
not_started、not_applicable。仅 DNS 查询没有端点发布。任务结果读取执行投影，资产与搜索
读取当前投影；执行 succeeded 后资产可能暂时未更新。前端在等待资产发布时继续刷新。

## 队列与恢复

scan_projection_outbox 增加 claim_token、lease_expires_at、cursor、phase、processed_endpoints
和 updated_at。领取通过短事务 FOR UPDATE SKIP LOCKED + UPDATE RETURNING 原子完成，
仅处理 succeeded 执行。领取、上下文读取、续租和检查点之后均归还连接，不跨 ES I/O 持有连接。

每个发布片段最多处理配置指定页数，然后释放领取并把 available_at 更新为当前时间，给其他
执行和标签队列让出机会。单进程后台串行发布；多实例通过数据库租约避免正常情况下重复领取。
运行期间独立续租，续租、检查点、重试和完成都要求令牌匹配且租约有效。失去归属立即取消
本地等待并停止发送后续页，旧领取者不能覆盖新领取者的队列状态。

每页包含 global/user 两份确定性 ID 的更新，按操作数和实际 NDJSON 字节数分片。所有 bulk
逐项核对状态、ID、索引和条目数后才保存游标。ES 已成功而检查点失败可以重放该页；仍使用
原有幂等脚本，保持 first_seen 与服务观察的先后关系。协议允许恢复时重复写，不保证 ES
请求严格只执行一次；已经发出的请求可能在客户端取消后完成。

phase=refreshing 表示所有页已完成。只执行一次最终当前索引刷新，成功后才填写 processed_at。
刷新失败仅重试刷新，不重放已经确认的页。队列保留错误、指数退避和进度；进程崩溃后由
租约到期恢复。一个端点操作超过字节上限会保留错误并重试，不静默截断数据。

## 配置

以下是新增的启动配置默认值，不属于动态运行时配置：

```toml
[elasticsearch]
projection_page_size = 1000
projection_bulk_max_bytes = 5242880
projection_pages_per_tick = 4
projection_lease_seconds = 120
projection_heartbeat_seconds = 20
```

每个投影 bulk 操作数还受现有 bulk_batch_size 限制；ES 总并发仍受 bulk_max_concurrency 限制。
续租周期必须小于等于租约的三分之一。字节上限范围 64 KiB–16 MiB，页大小 1–2000，
每段页数 1–32，租约 10–3600 秒。先测量再调参，不能用扩大数据库连接池替代连接释放。

## 升级与回滚

新增字段由 init.sql 和内嵌 migrate_scan_projection.sql 幂等添加，原队列和历史回执保留。
升级前停止所有旧版服务实例，再启动新版；新旧队列协议不能混跑，旧版不识别领取令牌和
检查点。该变更不修改版本号或发布标签。

回滚时先停止新版 worker。新增字段可保留，但旧版会忽略它们，并恢复同步发布行为；
旧版再次存在慢 ES 占用连接的风险，因此应用回滚应使用包含连接释放修复的版本。

## 观测与验证

- ElasticsearchBulkCompleted：duration_ms、queue_wait_ms、request_ms、backoff_ms、attempts、
  request_bytes、operations、es_took_ms 和 success；trace_id 可关联原有 ES 慢操作日志。
- ScanWriteConnectionAcquired/Released：获取连接等待时间、持有时间和写入阶段。
- ScanProjectionClaimed/PageCompleted/Completed/OutboxError：执行 ID、阶段、页端点数、
  片段耗时和错误；实际累计进度与积压年龄通过队列表查询。
- 慢 SQL 监控仅将扩展缺失、权限不足和未加载识别为不可用；连接池故障单独报告采样失败。

```sql
SELECT execution_id, phase, processed_endpoints, attempts, claim_token,
       lease_expires_at, last_error, NOW() - created_at AS age
FROM scan_projection_outbox
WHERE processed_at IS NULL
ORDER BY available_at, execution_id;
```

在服务端目录执行 cargo fmt --check、cargo clippy --all-targets 和 cargo test。新增集成测试
使用临时 PostgreSQL 和本地 HTTP ES 协议模拟器：

```sh
STORAGE_TEST_DATABASE_URL=postgresql://test@127.0.0.1:5432/disposable \
  cargo test projection:: -- --include-ignored
```

覆盖单连接池释放、慢 ES 期间续租、并发领取、过期令牌拒绝、重启续传、错误 bulk 不推进
游标、刷新失败单独重试、最终上传和重复上传不等待资产发布。真实 ES 压测需要独立测试
集群，分别测 1 万、10 万、100 万端点的上传延迟、后台吞吐、心跳和连接池等待。

## 上传分段耗时

`ScanResultUpload` span 关联 scanner_id、task_id、upload_id、batch_index、is_final、
protocol_version 和 observation_count。所有同步写入阶段的 `ScanWriteStageCompleted`
继承同一 span，记录 stage、duration_us 和 success；提前错误或取消的未完成阶段记录
success=false。日志不记录 Token、checksum 或 observation 内容。

普通批、final、已确认批重试和 DNS/混合上传应分别比较 p50/p95/p99。阶段覆盖认证与执行
锁、上传身份、final 连续性、观察 enrichment、标签、回执预约/确认/提交、ES 事实与执行
端点 bulk、refresh、执行统计、任务聚合与目标新鲜度；DNS 路径另记录子任务生成。
连接等待与持有时间沿用 ScanWriteConnectionAcquired/Released，bulk 排队/请求/退避时间
沿用 ElasticsearchBulkCompleted。不要把 bulk 排队时间误判为扫描耗时。

## Final 索引范围

新上传在预约 final 的短事务中收集同一 execution/upload 已确认回执的索引清单，并加入
当前批次按 observed_at 推导的索引。ES refresh 与 observation count 只访问该清单，
跨月、空 final 和 pending 重试仍覆盖整个执行。空执行不发送 observation count。
执行端点索引仍是共享索引，refresh 作用于该索引。精确端点总数只在 IP composite 的
第一页计算，后续页关闭 track_total_hits；IP 数仍保持精确分页统计。

索引清单排序去重后，refresh 和 count 各自按 HTTP 请求行 3 KiB 预算分块，包含实际 URL
编码后的路径前缀、查询参数和 HTTP 方法/版本。各块顺序执行，执行端点索引仅刷新一次；
少月份时仍合并为一次刷新。count 使用相同 execution_id 条件并检查非负计数及累加溢出，
任一块失败均保留 pending，重试重新刷新和计数全部块，只有完整成功才确认 final。
超长的单个目标在批次事实写入前报错；不通过扩大 ES 请求行限制处理。

ScanFinalRequestPlan 记录 refresh_requests、count_requests 和 max_request_line_bytes。
refresh_execution_index_chunk、count_execution_observation_chunk 阶段记录单块耗时。

旧回执有观察却没有 storage_references，以及历史 PG → ES 迁移，显式走全历史索引
兼容范围，记录 ScanSummaryLegacyIndexScope。新上传不依赖该兼容路径。
