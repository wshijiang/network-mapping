# 扫描写入压力测试

`elasticsearch::stress_tests::scan_write_large_data_stress` 是显式启用的代码压力测试，
调用实际 save_scanner_results 写入路径，使用真实 PostgreSQL 和 Elasticsearch，
不调用扫描引擎。测试在独立 schema 和随机 nm-stress-* 索引中写入，成功后清理自己的
数据。勿将变量指向生产系统。

默认写入 1 万、10 万、100 万条端口观察，每批 500 条、四路并发执行。每端点只有一条
观察，覆盖三个月索引；预置 12 个空的无关历史索引、10 万个无关搜索目标。每路结束后重复
final，验证 saved=0，并核对执行状态及精确 IP、端点、观察计数。

```sh
STORAGE_TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:55439/postgres \
SCAN_STRESS_ES_URL=http://127.0.0.1:59200 \
SCAN_STRESS_COUNTS=10000,100000,1000000 \
SCAN_STRESS_CONCURRENCY=4 \
SCAN_STRESS_OUTPUT=/tmp/scan-write-stress.json \
cargo test --locked --lib scan_write_large_data_stress -- --ignored --nocapture
```

测试输出 SCAN_STRESS_RESULT JSON，包含批次 p50/p95/p99/max、总耗时、观察吞吐、
final/重复 final、错误列表、写入阶段与连接/bulk 等待分布，以及 ES indexing/refresh/
merge/heap/GC/CPU 的前后快照。原始 JSON 可由 SCAN_STRESS_OUTPUT 保存。

普通批次延迟不含输入数据构造；总耗时包含数据构造、重复 final 和结果核对。没有运行
后台资产发布和分析 worker，因此结果代表同步写入链路。每个规模每路只有一次 final，
默认四个样本，final p95/p99 接近最大值；不能据此推断生产尾延迟。

跨大量月份的回归压力场景可设置 `SCAN_STRESS_MONTHS=50`、
`SCAN_STRESS_PREFIX_PADDING=120`、`SCAN_STRESS_COUNTS=10000`；
`SCAN_STRESS_EMPTY_FINAL=true` 会在所有数据批次确认后发送独立空 final。
MONTHS 默认 3，其他取值使用从 1970 年 1 月开始的真实月历，最多 500 个月。
索引前缀填充默认 0，最多 150 字节，保留合法的索引名称长度。

长请求场景先证明原始单次 count 请求会被 ES 默认 4 KiB 限制拒绝，再运行实际上传流程。
这个预期拒绝独立记录为 unchunked_request_rejected，不计入上传 errors。
输出新增 final_request_plans（刷新/计数请求数量与最大请求行字节数）、
refresh_execution_index_chunk 和 count_execution_observation_chunk 单块耗时。
每路均断言精确 IP/端点/观察统计、重复 final，以及计划中的请求行不超过 3 KiB。
少月份场景另断言一次刷新和一次 observation count。


## 2026-10-14 实测（上海时区）

PostgreSQL 17.11、Elasticsearch 9.5.3，2 vCPU、8 GiB、ES heap 1 GiB；Rust 1.99.0 的未优化测试构建。两版本分别运行一次相同工作负载。

云端 gVisor 缺少 `/proc/self/coredump_filter`。官方 ES 安装包通过 SHA-512 校验后，仅将 bootstrap 中该诊断写入路径重定向至临时文件，查询/索引执行代码未改；此适配不属于仓库变更。

| 版本 | 观察数 | 总耗时（秒） | 吞吐（条/秒） | 普通批 p50/p95/p99（ms） | Final 最大值（ms） | 写入错误 |
| --- | ---: | ---: | ---: | --- | ---: | ---: |
| 原始 main | 10,000 | 9.98 | 1002 | 1796.0 / 2871.0 / 2871.0 | 2769.0 | 0 |
| 原始 main | 100,000 | 49.68 | 2013 | 939.0 / 1438.2 / 1690.7 | 1805.8 | 0 |
| 原始 main | 1,000,000 | 416.09 | 2403 | 791.8 / 1164.6 / 1488.8 | 4133.1 | 0 |
| 分块修复前 | 10,000 | 5.16 | 1937 | 990.5 / 1320.3 / 1320.3 | 1286.8 | 0 |
| 分块修复前 | 100,000 | 41.50 | 2409 | 806.7 / 1071.1 / 1183.4 | 1484.1 | 0 |
| 分块修复前 | 1,000,000 | 403.92 | 2476 | 781.4 / 1097.3 / 1248.1 | 3856.9 | 0 |

三种规模均核对 IP/端点/观察精确计数，重复 final 返回 saved=0。原始版本写入和计数断言全部通过，初次结束时 ES 拒绝通配符清理；已显式清理其具体索引并修复测试清理逻辑。分块修复前的优化版本压测完整执行通过。

百万条普通批 p95 差异约 -5.8%、p99 约 -16.2%，吞吐差异约 +3.0%。原始版本先运行，含 JVM 热身，且百万阶段初期有构建缓存复制 I/O；这些结果属于单轮观测，特别是小幅吞吐差异不能可靠归因于代码。第一组冷启动差异也不能作为优化幅度。

### 百万条阶段观测

阶段时间含调度等待，不等同于数据库执行时间；final 相关阶段各仅四个样本。

| 阶段 | p95（ms） | 样本数 |
| --- | ---: | ---: |
| upload_identity | 97.71 | 2004 |
| load_execution_index_manifest | 8.35 | 4 |
| write_observation_bulk | 172.88 | 2000 |
| write_execution_endpoints | 472.96 | 2000 |
| refresh_execution_indices | 1144.32 | 4 |
| execution_summary | 1721.01 | 4 |
| update_target_freshness | 3.75 | 4 |

百万条上传的 final 最大值仍为约 3.86 秒，当前实现仍保留精确 IP 聚合和共享执行索引 refresh。后续若要继续缩短 final，需再评估计数物化或独立后台完成流程；本 PR 未改变完成语义。

### 资源与执行计划

Java 进程合计 RSS 采样峰值：原始版本 1917.6 MiB，本 PR 1871.9 MiB。cgroup 包含进程及文件缓存，原始版本达到 8 GiB 上限，本 PR 峰值 7333.8 MiB；采样覆盖及准备工作存在差异，不能视为内存优化比例。

10 万个目标的 CIDR 查询使用 GiST，命中 256 条，14 个共享缓冲命中，单次执行约 0.154 ms；完整目标状态 UPDATE 也使用 GiST/主键，无目标表 Seq Scan，单次约 5.717 ms。这是小范围、缓存热的执行计划验证。

[原始统计 JSON](benchmarks/scan-write-2026-10-14.json) 包含各阶段分布、重试延迟和 ES indexing/refresh/merge/heap/GC/CPU 前后快照。

## 2026-10-14 Codex review 分块修复后复测

同一真实 PG/ES 环境，四路并发、每批 500 条；50 个月场景额外填充 120 字节索引前缀。
原始未分块 count 请求行为 9,267 字节，被默认 4 KiB 限制以 too_long_http_line_exception 拒绝。
分块后所有 final 的最大请求行为 3,013 字节，刷新与 count 各四块；500 个月协议回归
另覆盖数据/空 final 与后续 refresh/count 块失败的四种组合，确认 pending、无提前发布及完整重试。

| 场景 | 观察数 | 总耗时（秒） | 吞吐（条/秒） | 普通批 p50/p95/p99（ms） | Final 最大值（ms） | 每次 Final 刷新/计数请求 | 最大请求行（字节） | 写入错误 |
| --- | ---: | ---: | ---: | --- | ---: | --- | ---: | ---: |
| 3 个月，数据 final | 10,000 | 4.44 | 2251 | 824.3 / 1094.4 / 1094.4 | 1011.7 | 1 / 1 | 314 | 0 |
| 3 个月，数据 final | 100,000 | 41.00 | 2439 | 807.2 / 1099.0 / 1340.0 | 1105.5 | 1 / 1 | 314 | 0 |
| 3 个月，数据 final | 1,000,000 | 398.08 | 2512 | 765.7 / 1073.8 / 1245.3 | 4430.0 | 1 / 1 | 314 | 0 |
| 50 个月，数据 final | 10,000 | 7.21 | 1387 | 1121.7 / 2412.2 / 2412.2 | 1593.6 | 4 / 4 | 3013 | 0 |
| 50 个月，空 final | 10,000 | 11.85 | 844 | 1714.1 / 4596.8 / 4620.1 | 1776.2 | 4 / 4 | 3013 | 0 |

所有规模均断言精确 IP/端点/观察统计和重复 final saved=0。少月份时仍只有一次刷新与
一次 observation count，无新增 ES 请求。压力测试完整通过并清理专用 schema、索引和模板。

本轮复用已热身的 ES 实例，每种负载仅运行一次，final 每规模四个样本；50 个月空 final
早期与 Clippy 检查重叠。本轮数据用于修复正确性与大量写入回归，不据此计算前后性能收益。
压力测试继续使用未优化测试构建，未包含 HTTP 解析或后台 worker。常规测试 393 项、
Elasticsearch 相关检查 62 项、格式与严格 Clippy 全部通过。

[分块修复原始统计 JSON](benchmarks/scan-write-chunking-2026-10-14.json) 包含完整分布、
每次 final 请求规划、单块刷新/count 耗时，以及 ES heap/GC/CPU/indexing/refresh/merge 快照。
