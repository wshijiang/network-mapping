# 扫描性能与慢 SQL 调查（2026-11-26）

[文档中心](README.md) · [健康告警](HEALTH_ALERT.md) · [扫描流水线](SCAN_PIPELINE.md)

## 告警与现有修复的关系

2026-11-19 的 `slow_sql` 告警报告窗口均值 3513.0ms、历史峰值 6443.2ms，共享块命中 8799、读取 5135。这些是用户提供的生产数据，本次没有连接生产数据库。SQL 文本以 `WITH completed AS MATERIALIZED` 开始，使用 `t.id=$1 OR t.id IN (...)`，每个执行还分别做子任务 MAX 和 NOT EXISTS。

分支基线 `e722aae` 已经做了两项修复：

- 先由 task_id 与谱系得到很小的 `requested` 集合，再按主键访问任务和执行；子任务完成状态和结束时间合并为一个 LATERAL 聚合。旧 OR/IN 形态可能扫描整个任务表并触发高成本 JIT；本地旧形态计划确实出现任务全表扫描和 JIT。单 IP 主键查找与网段 inet GiST 保持分开。
- 上传成功确认事务只写入 `search_freshness_outbox`；后台 worker 再更新搜索新鲜度，避免长 SQL 持有执行行锁阻塞心跳续租。DNS 父任务仍等待子任务成功。

因此不能把上述已有改写计作本次新增。告警发生时具体部署版本、缓存命中率、并发与磁盘状态未取得，无法据本地计划精确还原生产 3513ms 的构成。

## 本次改动

相同任务/谱系重新完成会再次写入同一新鲜度。原 `last_success_at <= ended_at` 即使时间和计划完全相同也更新整行，造成 WAL、死元组和索引维护。本次在时间变新时更新；时间相等时仅在 JSON 计划 `IS DISTINCT FROM` 时更新，保留空计划修复及等时计划变更。较旧时间不覆盖较新状态。

数据库 `scan_task.task_port`、`target_monitor_rule.ports` 的创建及升级默认值与创建任务 API 对齐；修改列 DEFAULT，不重写已有任务或规则。前端新建监控表单也使用同一默认端口集合。服务端 `masscan.rate` 默认已经是 10000，扫描器本地配置和示例同步为 10000；既有运行时自定义配置保留。

## SQL 基准

PostgreSQL 18.7，shared_buffers=128MB，JIT 使用默认配置；完整当前 init.sql 建立 UUID 隔离 schema，10 万任务、10 万成功执行、10 万 IP 搜索目标。请求执行为 id=1；谱系为空，DNS/子任务语义另由集成测试覆盖。每种场景/版本先一次，再 9 次，表中取后 9 次中位数；EXPLAIN ANALYZE 的写入都回滚，样本间 VACUUM 清理回滚死元组。使用强制 custom plan；未测试 generic plan、并发、生产磁盘或 OS 冷缓存。各变体顺序固定，仍存在缓存和系统负载噪声。

| 场景 | 告警旧形态 | 分支基线 | 本次优化 |
| --- | ---: | ---: | ---: |
| 无匹配目标 | 514.145ms | 0.187ms | 0.140ms |
| 首次更新 /24 | 555.151ms | 5.971ms | 6.478ms |
| /16 相同新鲜度回放 | 1493.955ms | 986.747ms | 174.085ms |

主要新增收益在重复完成的网段任务：/16 回放约 **5.7 倍**提速。最后一次样本 WAL 从 **42446536 字节降至 0**；共享块访问从 1127934 降至 265313。无匹配和首次 /24 更新没有稳定的额外提速，不能将亚毫秒噪声解释为收益。大网段即使不写入仍需匹配目标与排序，开销仍随覆盖目标数量增长。

原始计划与测量 JSON 仅在本地保存，不跟踪或上传。脚本输出首次耗时、热样本范围、块访问、WAL 和最后一份完整计划；可保存至已忽略的 `docs/benchmarks/` 或 `/tmp/`。本文保留汇总结果。复现只使用专用可丢弃数据库：

```bash
python3 scripts/benchmark_search_freshness.py \
  --database-url "$DISPOSABLE_DATABASE_URL" \
  --baseline-ref e722aae --rows 100000 --samples 9 \
  --output /tmp/search-freshness.json
STORAGE_TEST_DATABASE_URL="$DISPOSABLE_DATABASE_URL" \
  cargo test target_generated::search::tests -- --include-ignored
```

脚本仅创建和删除自己的 UUID schema；需 psql、UTF-8 数据库和创建 schema 权限。初始化包含事务内迁移，不要对生产连接运行基准。基准方法依据 [PostgreSQL EXPLAIN 文档](https://www.postgresql.org/docs/18/using-explain.html)：ANALYZE 会实际执行 UPDATE，必须用事务回滚隔离副作用，且回滚仍会产生 WAL。

## 服务识别和慢上传

扫描器回退规划改为一次按端点建立证据摘要，默认 512 端点的本地 CPU 基准 22.823→4.129ms；4096 端点压力输入 1271.223→32.511ms。上传改为借用缓存切片，读取有界成功确认体以支持连接复用，并添加客户端总耗时及规划耗时。细节与限制见配套扫描器 `docs/SCAN_PERFORMANCE.md`。

普通批次依次执行观察 Bulk 和执行端点投影 Bulk；最后批次还要刷新索引并计算精确统计。服务端已具备 `ScanWriteStageCompleted` 分阶段日志。排查时按执行/上传/批次关联客户端 `ResultBatchUploaded.elapsed_ms` 与服务端 `write_observation_bulk`、`write_execution_endpoints`、`refresh_execution_indices`、`execution_summary`。客户端时间包含编码、网络和服务端处理，不能直接称为网络传输耗时。本次没有生产分阶段日志，也没有 Elasticsearch 端到端吞吐基准，不能确认线上慢上传的主因已完全消除。

上线验证应检查新进程实际使用 `WITH requested AS MATERIALIZED`，观察新查询窗口均值/块读取和 outbox 重试/滞后；不提高慢 SQL 告警阈值。历史峰值不会因升级自动清零，也不应为比较而重置生产统计。

## 验证记录

- 服务端全量常规测试 829 通过，222 个外部依赖测试按原配置忽略；另在临时 PostgreSQL 执行搜索新鲜度 17 项测试全部通过，包含 GiST 计划、所有者隔离、DNS 后代、队列、并发和新增幂等回归。
- 扫描器全量及 HTTP 确认体专项测试通过；覆盖报文逐字节一致、续传边界、零结果、分片确认连接复用、中途断线、确认体大小上限。
- 两个 Rust 组件 fmt/clippy 检查完成；服务端 clippy 有既有警告，未将无关清理混入本次变更。
- 前端目标监控测试与 pnpm build（Node 24.16.0）通过。浏览器因缺少显示服务启动失败，人工页面交互未完成；未计为通过。

Review 复核：同步独立监控迁移中的端口 DEFAULT 升级，补充无需数据库的完整迁移块一致性检查；监控集成测试夹具同时执行启动所需的 Open API 迁移，避免缺少 `user_access_version` 列。新增重复升级不覆盖旧规则/自定义端口的回归。复测：常规单元测试 830 通过、223 按原策略忽略，另执行完整目标监控数据库测试组 5 项全部通过。
