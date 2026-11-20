# 配套发布与升级

[文档中心](README.md) · [服务端更新日志](CHANGELOG.md) · [部署指南](DEPLOYMENT.md)

## 本次版本与状态

| 组件 | 上次版本 | 本次版本 | 更新说明 |
| --- | --- | --- | --- |
| API / 服务端 | 0.1.30 | **0.1.31** | [服务端 CHANGELOG](CHANGELOG.md) |
| 扫描器 | 0.1.21 | **0.1.22** | [扫描端 CHANGELOG](https://github.com/wshijiang/Network-Mapping-Scanner/blob/main/docs/CHANGELOG.md) |
| Web 控制台 | 0.1.24 | **0.1.25** | [前端 CHANGELOG](https://github.com/wshijiang/network-mapping-vue/blob/main/docs/CHANGELOG.md) |


本次包含搜索新鲜度异步化（心跳续租锁超时修复）、情报标注与搜索耗时优化、数据导出/导入、联测、Syslog 转发、技术栈与操作系统识别扩充、飞书/Telegram 通知增强及相应控制台页面。自 0.1.30 升级为幂等增量迁移，未引入 ES 投影结构变更。版本继续各自递增，不要求三个组件的数字相同。

## 审阅与合并顺序

1. 核对版本声明及锁文件：服务端 `Cargo.toml` / `Cargo.lock` 为 0.1.31，扫描器为 0.1.22，前端 `package.json` 为 0.1.25。只更新本地包版本，不为发布重新解析无关依赖。
2. 先审阅控制台 PR。服务端 `.github/frontend-ref` 固定控制台发布提交的完整 SHA，归档与 Docker 构建读取相同引用。若控制台采用 squash/rebase 合并，合并后将服务端引用更新到最终 `main` 上的 0.1.25 提交，再核对前端版本和构建。
3. 审阅扫描器及服务端的 CHANGELOG、迁移/回滚步骤和验证结果。必须单独列出默认忽略、未运行或受环境限制的检查；局部协议测试不代表真实设备/生产验收。
4. 合并 release PR 并核对修复提交后再推送对应 tag。服务端与扫描器 Docker 流程要求 tag 提交已属于 `origin/main`，tag 名与包版本一致；不要在未合并分支上触发正式发布。


## 部署顺序与兼容核对

1. 停止全部旧后端实例和扫描写入，确认待上传结果状态；备份配套 PG/ES、配置、加密主密钥和扫描器身份状态，停止事实保留期清理。
2. 既有 0.1.30 部署按增量迁移升级：新增表与配置段（搜索新鲜度 outbox、数据导出/导入、联测、Syslog）均为幂等迁移，未配置时零行为变化，无需重建 ES 投影。来自 0.1.30 之前版本的部署仍须先按[存储升级与回滚](SERVICE_PROTOCOLS.md#存储升级与回滚)明确选择重建模式完成传输端点重建（`--rebuild-transport-endpoints --rebuild-transport-mode new-index` 或 `in-place`），保持 observation/DNS 位置不变，完成后按需运行 `--rebuild-analytics-snapshots`。
3. 部署服务端 0.1.31 与控制台 0.1.25，核对 `/healthz`、四个前端入口及实际 API；核对 DNS 排除策略、Turnstile，以及新增配置段（数据导出/导入、联测、Syslog 转发）默认关闭的升级行为。
4. 暂停节点分配，排空旧 generation 的任务与检查点，配套部署 Scanner 0.1.22 的 Agent、Worker 及完整 IPC 3 模块包。保留 SQLite、令牌、检查点与待上传结果；随后核对节点能力再开启新协议任务。
5. 回滚前停服，使用保留的旧索引或原地重建的备份，恢复配套旧程序、旧 execution/current 配置和迁移前 PG 运行标记；保留新增事实。旧版本无法完整展示新增 UDP 结果，不通过删除事实恢复旧界面。

本次不代替部署方执行生产迁移或真实网络扫描。具体协议边界、TLS/CA、UDP 被动接收及设备验收见[服务协议说明](SERVICE_PROTOCOLS.md)。
