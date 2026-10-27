# 配套发布与升级

[文档中心](README.md) · [服务端更新日志](CHANGELOG.md) · [部署指南](DEPLOYMENT.md)

## 本次版本与状态

| 组件 | 上次版本 | 本次版本 | 更新说明 |
| --- | --- | --- | --- |
| API / 服务端 | 0.1.29 | **0.1.30** | [服务端 CHANGELOG](CHANGELOG.md) |
| 扫描器 | 0.1.20 | **0.1.21** | [扫描端 CHANGELOG](https://github.com/wshijiang/Network-Mapping-Scanner/blob/main/docs/CHANGELOG.md) |
| Web 控制台 | 0.1.23 | **0.1.24** | [前端 CHANGELOG](https://github.com/wshijiang/network-mapping-vue/blob/main/docs/CHANGELOG.md) |

2026-10-26 的同版本发布因设计问题已撤回；2026-10-27 纳入服务端端点重建、扫描器引擎兼容、网络重试、退出码和文件锁修复后重新发布。版本号保持上表不变。请核对本次 tag 提交、BUILD-INFO、镜像 revision 和归档校验和，不复用撤回前的下载、镜像 digest 或历史 Actions 附件。实际可用制品以本次发布流程完成后的 GitHub Release 和 GHCR 为准。

本次包含端点身份及投影迁移、Worker IPC 3、自动 TCP/UDP 服务识别、通知/情报/LLM，以及中英文界面与文档。版本继续各自递增，不要求三个组件的数字相同。

## 审阅与合并顺序

1. 核对版本声明及锁文件：服务端 `Cargo.toml` / `Cargo.lock` 为 0.1.30，扫描器为 0.1.21，前端 `package.json` 为 0.1.24。只更新本地包版本，不为发布重新解析无关依赖。
2. 先审阅控制台 PR。服务端 `.github/frontend-ref` 固定控制台发布提交的完整 SHA，归档与 Docker 构建读取相同引用。若控制台采用 squash/rebase 合并，合并后将服务端引用更新到最终 `main` 上的 0.1.24 提交，再核对前端版本和构建。
3. 审阅扫描器及服务端的 CHANGELOG、迁移/回滚步骤和验证结果。必须单独列出默认忽略、未运行或受环境限制的检查；局部协议测试不代表真实设备/生产验收。
4. 合并 release PR 并核对修复提交后再推送对应 tag。服务端与扫描器 Docker 流程要求 tag 提交已属于 `origin/main`，tag 名与包版本一致；不要在未合并分支上触发正式发布。

## 合并后的 tag 操作

下例从相应仓库根目录执行；`release_version` 按上表选择。Git 身份使用 `wshijiang <111570850+wshijiang@users.noreply.github.com>`。

```sh
git config user.name wshijiang
git config user.email 111570850+wshijiang@users.noreply.github.com
git fetch origin --tags
release_version=0.1.30
release_commit='<已核对版本与文档的最终 main 提交 SHA>'
git merge-base --is-ancestor "$release_commit" origin/main
git show "$release_commit:Cargo.toml"   # 前端改查 package.json
```

先检查远端是否已有 `v$release_version`，以及本地待发布 tag 的实际指向。若本地 tag 指向的 release 提交由普通 merge 保留，且祖先检查通过，可以保留；若 squash/rebase 改写了提交，先核对最终版本与完整 diff，再仅重建**尚未推送的本地 tag**：

```sh
git show --no-patch "v$release_version"
# 只有本地未推送 tag 不再对应最终发布提交时，才删除并重新创建。
git tag -d "v$release_version"
git tag -a "v$release_version" "$release_commit" -m "Release v$release_version"
# 已获正式发布授权且核对完毕后执行：
git push origin "refs/tags/v$release_version"
```

远端版本 tag 一旦存在，不覆盖或强推；本次同版本重新发布已获明确授权，且原 tag、Release 和容器镜像引用已撤回，应先验证这些引用不存在，再在修复后的 main 提交上重新创建 tag。推送 tag 后检查归档发布工作流、校验和及对应版本的 Actions；容器发布还受仓库 `DOCKER_PUBLISH_ENABLED` 与 `container-release` 环境规则控制。tag 存在或构建已触发不等于全部制品已发布成功。前端以源码 tag 和服务端固定提交集成，不具有独立二进制归档发布流程。

## 部署顺序与兼容核对

1. 停止全部旧后端实例和扫描写入，确认待上传结果状态；备份配套 PG/ES、配置、加密主密钥和扫描器身份状态，停止事实保留期清理。
2. 既有部署按[存储升级与回滚](SERVICE_PROTOCOLS.md#存储升级与回滚)明确选择重建模式，保持 observation/DNS 位置不变。`new-index` 使用全新 execution/current 索引并保留旧索引；`in-place` 必须先克隆并验证两个旧投影备份，再删除原名投影。命令必须同时携带 `--rebuild-transport-endpoints --rebuild-transport-mode new-index` 或 `--rebuild-transport-endpoints --rebuild-transport-mode in-place`；完成后按需运行 `--rebuild-analytics-snapshots`。中断用相同配置及原模式续跑；重建按 ES 现存事实执行，不用 PG 回执、批次数或校验和对账，事实缺失可能使投影减少。
3. 部署服务端 0.1.30 与控制台 0.1.24，核对 `/healthz`、四个前端入口及实际 API。旧通知 worker 不与新队列并行；核对 DNS 排除策略、Turnstile 和 [LLM 迁移](LLM.md#迁移并发与部署)。
4. 暂停节点分配，排空旧 generation 的任务与检查点，配套部署 Scanner 0.1.21 的 Agent、Worker 及完整 IPC 3 模块包。保留 SQLite、令牌、检查点与待上传结果；随后核对节点能力再开启新协议任务。
5. 回滚前停服，使用保留的旧索引或原地重建的备份，恢复配套旧程序、旧 execution/current 配置和迁移前 PG 运行标记；保留新增事实。旧版本无法完整展示新增 UDP 结果，不通过删除事实恢复旧界面。

本次不代替部署方执行生产迁移或真实网络扫描。具体协议边界、TLS/CA、UDP 被动接收及设备验收见[服务协议说明](SERVICE_PROTOCOLS.md)。
