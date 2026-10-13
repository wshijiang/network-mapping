# 服务端模块化实现与报表渲染热更新

[整体设计](MODULAR_ARCHITECTURE.md) · [模块运行时](../crates/nm-module-runtime/src/lib.rs) · [生产报表工作流](../src/reports/worker.rs)

本文描述当前实际接入的代码。服务端原有业务已经迁移到领域模块；运行时与纯报表邮件渲染成为两个可独立构建的 Cargo workspace 包；生产报表使用同一个模块接口调用内置实现或独立 worker。管理员可以在服务端不重启的情况下切换报表邮件渲染制品。

## 1. 当前代码结构

```text
Cargo.toml                         Cargo workspace
crates/
  nm-module-runtime/               契约、路由、代际句柄、排空、进程 IPC
  nm-report-renderer/              纯邮件渲染、报表 DTO、独立 worker
src/
  main.rs                          解析 CLI，调用 application::run
  application/
    mod.rs                         基础设施和业务服务装配、HTTP 启动
    background.rs                  后台服务所有权和关闭管理
  http/mod.rs                      按领域组合 HTTP 路由
  identity.rs                      密码、凭据、退出、加解密
  scan_control/
    creation.rs                    任务创建和计划
    dispatch.rs                    领取、租约、恢复、聚合
    query.rs                       任务查询和分页
    target.rs                      地址和端口解析
  result_ingest/
    model.rs                       上传 DTO 和错误
    validation.rs                  observation 校验和清理
    storage.rs                     结果接入、幂等和回执
    dns.rs                         DNS 入库与后续任务
  system_resources.rs              系统资源采集和查询
  web_support.rs                   响应与请求辅助类型
  clock.rs                         时间戳
  reports/
    worker.rs                      生产捕获、计算、归档、投递流程
    service.rs                     渲染器选择、持久化发布和刷新
    render_module.rs               独立渲染包的兼容导出
  handlers/modules.rs              管理员模块状态与发布接口
```

`lib.rs` 保留兼容导出，原来的公开调用路径仍可编译；内部调用已经改为明确的领域路径。扫描器 URL、scan_plan、结果协议、上传幂等键以及任务租约保持原语义。跨领域的结果最终确认仍在原 PG 事务中完成，不拆成远程事务。

## 2. Workspace 构建与验证

```sh
cargo check --locked --workspace --all-targets
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets
cargo build --locked -p nm-report-renderer --bin nm-report-render-worker
cargo run --locked --example report_module
```

渲染 worker 只链接运行时、serde、Tokio、Tera、CSS 和 HTML 清理依赖，不依赖 Actix、PostgreSQL、Elasticsearch、扫描器凭据或 SMTP。可以单独编译它并发布，不需要重建服务端主程序。

`crates/nm-report-renderer/tests/process.rs` 使用真实 worker 验证握手、版本切换、旧句柄继续执行、排空、进程回收、故障后相同修订恢复和新修订回滚，以及业务校验或请求帧大小错误后仍能处理下一次请求。这些测试使用同一 worker 构建产物启动不同发布身份，验证运行时切换与恢复；不等同于数据库、管理 API 和 SMTP 全链路验收。

部分既有测试需要本地 TCP 监听或可丢弃的 PG/ES 环境。受限沙箱中的监听失败不作为业务测试通过；验证报告会单独说明这些限制。

## 3. 模块契约与调用

`Module` 定义 contract/self_test/invoke/shutdown 和可用性检查。宿主的 `ModuleSlot` 固定允许的方法、输入/输出 schema、并发、数据大小与超时。报表允许的方法只有 `render`。

生产调用取得一次代际句柄：

```rust
let lease = service.registry().acquire("report-render").await?;
let result = lease.invoke("render", serde_json::to_value(input)?).await?;
```

发布先在锁外准备候选并自检，再以短锁替换路由。已有请求保留旧句柄；旧版本只有在请求句柄与实际执行都结束后才关闭。请求超时后，仍在执行的工作继续占用容量并被计入排空，避免后台工作无限堆积或旧进程提前终止。

模块选择使用既有 `runtime_configuration` 和修订表中的 `report_renderer` namespace。启动默认插入 `{"release_id":"builtin"}`，已有选择不覆盖。启动和每五秒刷新读取数据库 revision；内存支持直接应用更高 revision，允许实例在重启或通知间隔中跳过多个修订。

工作进程故障时保持错误可见，并在刷新循环中重启相同选择；故障重启保持配置 revision，表示同一发布代际的进程恢复。无效制品不能通过发布前校验，不会替换活跃实现。配置只接受 schema_version=1 和正数 revision，拒绝把未来版本的配置当成当前协议解释。

数据库初始化成功后，如果保存的渲染制品缺失或不能启动，宿主继续启动，渲染能力暂不可用，刷新循环持续重试。不会偷偷改用内置实现或覆盖数据库选择。统计归档仍沿用邮件错误降级逻辑；管理员可以安装缺失制品，或发布新修订切回 `builtin`。数据库连接及初始化失败仍属于宿主启动错误。

## 4. 发布一个渲染 worker

服务端配置新增可选段；仅用内置渲染器时无需配置：

```toml
[report_renderer]
releases_directory = "/opt/network-mapping/modules/report-render"
```

相对路径以配置文件所在目录为基准。部署目录按不可变 release ID 保存：

```text
/opt/network-mapping/modules/report-render/
  renderer-1.0.0/
    manifest.json
    nm-report-render-worker
```

manifest 使用当前实现的 JSON 格式：

```json
{
  "release_id": "renderer-1.0.0",
  "artifact_sha256": "64 位小写十六进制 SHA-256"
}
```

制品由受信任的部署人员安装，服务账号只读。加载器校验 release 名称、目录范围、固定二进制名称、manifest 大小、SHA-256 和运行时协议。HTTP 请求只提供 release ID，不接收路径、命令或二进制上传。当前真实性依赖受控的本地制品目录；尚未接入签名制品仓库。

从服务端仓库目录构建并取得摘要：

```sh
cargo build --locked --release -p nm-report-renderer --bin nm-report-render-worker
sha256sum target/release/nm-report-render-worker
```

将该二进制和对应 manifest 安装到同一 release 目录。多实例部署必须在每台涉及的主机上先安装制品。

## 5. 管理接口与回滚

两个接口沿用登录、CSRF、限流，并额外要求管理员：

- `GET /api/modules/report-render`：数据库期望选择、revision、本实例已应用版本、可用性、同步状态和 `lastRefreshError`。已应用身份与 revision 取自同一代际句柄；只有修订一致且模块可用时 `converged` 才为 true。
- `POST /api/modules/report-render`：预热指定制品、乐观并发发布选择、切换本实例并排空旧实现。

请求示例：

```json
{
  "expectedRevision": 1,
  "releaseId": "renderer-1.0.0",
  "changeReason": "发布新的报表邮件渲染逻辑"
}
```

先通过 GET 读取 expectedRevision。成功后 revision 递增；其他实例在五秒刷新循环中应用相同选择。发布冲突返回 409，候选身份/摘要/握手/自检失败返回 400 且不写入新的配置。数据库故障返回 503；如果选择已经持久化而本实例激活失败，503 响应包含 `persistedRevision` 和 `pendingActivation=true`，需通过 GET 查询并等待刷新恢复，不应继续使用旧 expectedRevision 重发。

回滚使用同一个 POST，把 releaseId 改为已安装的旧制品，或 `builtin`，并携带当前 revision。回滚创建新修订，不倒退 revision。已归档报告与已发送邮件不改写。

配置文档和历史在同一事务中保存；发布成功后按既有审计接口另行记录管理员操作。当前使用配置修订表管理这个单一能力，未启用整体设计中的 module_deployment 等完整发布控制表。

## 6. 生产报表三阶段流程

现有 `reports/worker.rs` 已实际改造为：

1. **capture**：RepeatableRead 事务验证 claim token 和有效租约，读取任务快照、统计、周期、邮件配置及已发布模板源/版本；保留原等待完整数据和失败判断；提交并释放连接。
2. **generate**：在事务外生成图表、准备图片 token/URL、构造固定上下文，并调用模块。模块只负责纯邮件渲染，不能读数据库、创建任务或发送邮件。宿主再次验证输出主题、HTML、大小和模板版本。
3. **commit**：新短事务按 job → report 顺序加锁，再检查 token、租约、report revision 与输入完成度；归档统计、渲染邮件和图片，更新任务，并同事务创建投递记录。

图片在计算阶段只是准备好的内存资源，直到归档事务提交才建立可访问记录。模板不引用图片时不会保存图片资产，保留旧模板兼容行为。模板禁用或渲染失败继续保留统计报告，并把问题写入 quality.mail_error，避免把邮件问题扩大为统计数据丢失。

归档 `quality.renderer` 记录 release_id、generation 和本次渲染输入 checksum。旧 generation 任务仍可在有效 claim 下提交，不能仅因版本切换拒绝旧任务。

本次固定输入保存在一次任务的内存中；完成后归档结果及输入身份。失败重试会重新捕获尚未归档的输入，尚未启用 `report_render_input` 持久化中间输入表。[数据库扩展草案](MODULE_RUNTIME_MIGRATION.sql)仍是后续设计，不参与本次启动迁移。

## 7. IPC 与故障处理

父子进程通过私有管道通信：四字节大端长度 + JSON；读取长度后先限制到 1 MiB，再分配缓冲。stdout 专用于协议，日志写 stderr。worker 使用清理后的环境，只收到制品身份，不继承服务端环境中的凭据。

协议包含 requestId、rpcVersion、releaseId 和业务数据。当前适配器串行化一条进程管道的请求/响应；宿主总在途容量为八。响应必须匹配请求和制品身份。

业务校验失败返回错误，但继续使用同一进程。宿主在写入管道前校验完整请求帧；即使业务 payload 未超限，RPC 包装后超限也会拒绝请求并保留健康进程。帧损坏、身份不匹配、管道关闭或十秒 IPC 超时会停止并回收进程，刷新循环随后恢复。调用方五秒等待超时不会假装实际计算已结束。更高吞吐可通过多进程池或后续 requestId 多路复用实现，当前不无限排队。

## 8. 启动与关闭

`main.rs` 仅解析命令并调用 `application::run`。组合层初始化配置、连接、领域服务和 HTTP。HTTP 注册已迁移到 `http::configure` 的领域分组，`config::init_routes` 保留兼容委托。

后台服务由 `BackgroundServices` 持有 JoinSet 和停止信号；监控通知/慢 SQL 也由生产组合层注册。HTTP 停止后，普通后台循环取消，报表循环停止新领取并完成当前任务；超时后取消剩余任务，其持久化租约负责恢复。最后排空并关闭模块进程。

## 9. 当前边界

已经接入：领域实现拆分、内部调用迁移、两个独立 workspace 包、生产报表模块调用、真实渲染进程、管理员版本切换、配置轮询、启动/后台生命周期管理。

仍保留：主进程中的扫描控制、结果接入、图表计算、分析、备份与诊断；其独立部署需进一步明确 DB 和文件所有权。现有备份恢复和诊断目录独占的多实例限制未被此改造解除。所有业务模块的独立进程、签名仓库、全域配置同步、完整发布状态机和持久化中间输入属于后续工作，不能从报表渲染热更新推断它们已经实现。

## 10. 本地核验记录（2026-10-13）

本次按“实际业务模块拆分，并让部分功能可以独立构建和热更新”核验代码，结果如下：

| 目标 | 实现证据 | 当前结论 |
| --- | --- | --- |
| 业务实现拆分 | `scan_control`、`result_ingest`、`identity` 等；`lib.rs` 85 行，`main.rs` 7 行 | 已落实到代码 |
| 部分能力独立构建 | 两个 workspace 包；独立 `nm-report-render-worker` | 已落实到代码 |
| 生产调用与热更新 | `reports/worker.rs` 调用代际句柄；管理接口发布，配置刷新应用 | 已接入，PG/API/邮件全链路仍待有依赖环境验收 |
| 切换、排空、故障恢复和回滚 | 真实子进程测试及运行时测试 | 本地测试通过 |
| 模块故障隔离 | 制品加载失败不终止宿主；健康状态检查；邮件错误降级 | 已落实到代码，恢复逻辑单测通过 |
| 全领域独立部署 | 其他领域仍使用宿主基础设施和事务 | 未实现，不作为本次部分热更新的成果 |

workspace 回归共 **361 项通过，0 项失败**。其中真实 worker 集成测试 4 项、运行时测试 6 项。54 项既有测试按代码中的 `ignore` 跳过，数据库集成未验收；另外显式过滤 4 项需要本地 TCP 监听的 ES 模拟测试，当前沙箱拒绝监听。这些跳过项不计为验证通过。

对应回归命令（本地依赖缓存齐全，因此使用 offline）：

```sh
cargo test --offline --locked --workspace --all-targets -- \
  --skip elasticsearch::storage_tests::dns_retry_only_writes_missing_documents_after_rollover \
  --skip elasticsearch::storage_tests::dns_reconciliation_rejects_duplicate_id_across_backing_indices \
  --skip elasticsearch::storage_tests::dns_retry_reconciles_through_data_stream_across_rollover \
  --skip elasticsearch::storage_tests::startup_checks_version_before_index_writes_and_reports_actual_version
cargo fmt --all --check
cargo clippy --offline --locked --workspace --all-targets
```

格式检查和 Clippy 均完成；Clippy 保留既有 ES 测试中一项 `chunks_exact` 风格警告。本次没有声称完整数据库、SMTP、扫描器联调或生产多实例发布已验证。
