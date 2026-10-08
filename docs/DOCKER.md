# Docker 服务端部署

[项目首页](../README.md) · [文档中心](README.md) · [常规部署](DEPLOYMENT.md)

服务端镜像包含 Rust 后端、固定提交的 Vue 前端 dist、SQL 和模板；PostgreSQL、Elasticsearch 独立运行。
镜像地址为 `ghcr.io/wshijiang/network-mapping-server`，支持 Linux AMD64/ARM64。
Rust 使用 1.98.0、Node 24.16.0、pnpm 11.9.0；构建与运行环境采用 Debian 12，基础镜像固定多架构 digest。
真实配置、TLS、日志、数据库、本机二进制和 Git 目录通过构建上下文允许清单排除，最终镜像没有编译器或源代码。

## 固定前端与本地构建

`.github/frontend-ref` 必须是前端完整 40 位提交。前端与后端独立版本，修改前端后先提交并推送前端，
再通过后端 PR 更新 frontend-ref；不会因前端分支移动自动更换服务端镜像中的代码。
GitHub 服务端构建使用 `FRONTEND_REPO_TOKEN` 只读检出私有前端；前端公开时可不配置这个 Secret。
源码 artifact 由 git archive 的明确文件清单导出，不含 .git、凭据、开发 TLS 或环境文件。

PR 构建不提供私有前端 Token，仅验证后端 Rust 构建阶段；可信分支提交和正式 tag 构建完整镜像、
执行全部前端工具测试、目标校验与构建。前端仓库自己的 CI 同时覆盖 main/dev 的前端变更。

从 `network-mapping/` 运行，确保相邻前端目录已检出 frontend-ref 所记录的提交且工作区干净：

```sh
test "$(git -C ../network-mapping-vue rev-parse HEAD)" = "$(cat .github/frontend-ref)"
test -z "$(git -C ../network-mapping-vue status --porcelain)"
docker buildx build --build-context frontend=../network-mapping-vue \
  --build-arg REVISION="$(git rev-parse HEAD)" \
  --build-arg FRONTEND_REVISION="$(cat .github/frontend-ref)" \
  --tag network-mapping-server:local --load .
```

本地默认 VERSION 为 development，不作正式版本发布。镜像 `/opt/network-mapping/BUILD-INFO`
和 OCI labels 记录后端/前端版本、提交和架构。前端构建使用明确 COPY 清单，不复制开发证书或环境文件。

## 准备运行配置

从 `network-mapping/` 运行：

```sh
mkdir -p docker/runtime/tls
cp docker/config.example.toml docker/runtime/config.toml
cp docker/.env.example docker/.env
openssl rand -base64 32
openssl rand -hex 32
openssl rand -hex 24
```

将上述三个随机值分别填写到运行配置的 `server.encrypt_key`、`security.scanner_token_pepper`、
`database.password`。将同一数据库密码写入 `docker/runtime/postgres_password`，不得提交这些文件。
首次初始化后修改该文件不会自动修改 PG 中已存在的角色密码。

准备可信 TLS 文件 `docker/runtime/tls/cert.pem`、`key.pem` 和 `ca.pem`；
ca.pem 用于容器健康探针，必须能验证 cert.pem。`.env` 的 `SERVER_TLS_NAME` 填证书中的真实 DNS 名，
`SERVER_IMAGE` 填已批准的版本或完整 digest。服务仍使用 HTTPS，不支持直接改为明文 HTTP。
通过宿主机代理发布时上游也使用 HTTPS，并按项目说明配置可信代理。

服务进程 UID/GID 为 10001:10001。配置和私钥要能被该 UID 读取，例如由管理员调整为
属主 10001、模式 0400；TLS 目录允许该用户遍历。不要通过公开可读权限解决私钥读取问题。
命名卷首次创建会沿用镜像目录的属主，已有卷或宿主机绑定目录需手动检查 UID/GID。

## Compose 示例

```sh
docker compose --env-file docker/.env -f docker/compose.example.yml config --quiet
docker compose --env-file docker/.env -f docker/compose.example.yml up -d
docker compose --env-file docker/.env -f docker/compose.example.yml ps
```

示例部署一个服务端、一套 PG 18 和 ES 9.5.0，数据库没有宿主机端口映射；PG 18 卷挂载到
`/var/lib/postgresql`。服务端默认只发布宿主机 127.0.0.1:9999；需要直接访问时在 .env 明确设置
`SERVER_BIND_ADDRESS=0.0.0.0` 并配置防火墙、可信 DNS 和证书。

ES 示例关闭认证，只适用于隔离的单宿主机网络。生产应按 [ES 指南](ELASTICSEARCH.md)
配置认证与 TLS，并调整 TOML、CA 挂载及 ES healthcheck。PG 当前使用 NoTls，跨主机连接不能靠
`database.tls=true` 获得加密。宿主机需满足 ES 内存、文件描述符及 vm.max_map_count 要求，
例如由管理员设置 `vm.max_map_count=1048576`；不要从 Web 容器修改宿主机内核参数。

server-data 保存诊断与可选 MaxMind 数据，server-logs 保存滚动 JSON 日志；数据库分别有独立数据卷。
docker stdout 日志限制为 3×10MiB，应用文件日志仍需外部保留/轮转管理。
不要执行 `down -v` 清空生产数据。启动依赖健康检查仅控制启动顺序；服务端健康探针只验证
TLS 和登录页存活，不代表运行期间 PG/ES 持续就绪。pgBackRest Web 桥接默认关闭，备份由独立服务或宿主机负责。

## 容器验收范围

CI 从已验证 OCI 产物加载镜像，检查镜像配置 digest 一致后，在临时 PG/ES 下验证初始化、可信 HTTPS、
登录页静态资源、缺失路径/文件 404、正常停止及保留数据库的重启。临时网络与容器始终清理。
生产仍需人工验证管理员登录、历史页面刷新、API 鉴权、扫描器联调、备份恢复和实际证书链。

## GitHub 自动构建与发布

`.github/workflows/docker.yml` 在 `main`、`dev`、`dev/**`、`feature/**`、`fix/**`、
`release/**` 提交以及面向 `main`/`dev` 的 PR 上运行；扫描仓库另外兼容现有 `rust` 分支。
`workflow_dispatch` 只构建，不发布。工作流文件需先进入远端相应分支，手动入口需在默认 `main` 中存在。

两个原生 runner 分别构建 `linux/amd64` 与 `linux/arm64`，Dockerfile 内执行
`cargo fmt --check`、`cargo clippy --locked --all-targets`、`cargo test --locked` 和 release 构建。
GHA 缓存按组件/架构分开，Cargo.lock 和基础镜像 digest 固定；APT 软件仓库仍会变化，
因此不承诺不同日期重新构建有相同字节。缓存失效不会影响正确性。

镜像以包含 SBOM/最小构建来源证明的 OCI archive 保存为 Actions artifact，保留 14 天。
CI 校验所有 blob 摘要、镜像版本/提交/架构、前端提交（服务端）和归档 SHA-256，
再将同一产物导入 Docker 执行冒烟测试。发布复制这些产物，不重新编译。
SBOM/来源证明只说明构建组成与来源，不等同于镜像签名。

首次启用前，在对应仓库完成：

1. 确认 Actions 可使用 `ubuntu-24.04-arm`；私有仓库额度/runner 可用性不足时需提供相同架构的 runner。
2. 创建 `container-release` Environment，允许正式版本 tag，按套餐能力配置 Required reviewers。
   私有仓库并非所有套餐都支持 reviewer 门禁；无此能力时保留逐版本人工授权和受限 tag 创建权限。
3. 将仓库变量 `DOCKER_PUBLISH_ENABLED` 设置为 `true` 才启用镜像发布。
   该变量是功能开关，不代表对任何组件或版本的发布授权。
4. GHCR 使用 `GITHUB_TOKEN`，只在发布 job 授予 `packages: write`；确认包关联仓库与 Actions 写权限。
   首次发布后人工确认包可见性，私有镜像拉取需要相应读权限。

**只有用户批准明确组件、版本、提交及远端写操作后才可推送 `vX.Y.Z` tag。**
tag 必须与 Cargo.toml/Cargo.lock 版本一致，且提交已包含于远端 `main`。
分支、PR 和手动构建不写 GHCR。正式发布前执行仓库 AGENTS.md 的完整预检，
包括依赖提交在远端可达、二进制版本、测试、归档检查和具体推送顺序。

首次引入 Docker 发布也应使用新的、明确批准的版本，不能为触发新工作流重推或复用已发布 tag。

发布生成 `vX.Y.Z` 和 `sha-<完整提交>`；不自动维护 `latest`，避免并发旧版本覆盖新版本。
若任一正式标签已经存在，立即拒绝覆盖。网络/认证失败也会停止，不能视为标签不存在。
发布后读回 manifest，确认两种架构、证明文件和标签 digest 一致，并在运行摘要记录 digest。
`build-<run-id>-<attempt>-<arch>` 是发布阶段上传 OCI 的暂存标签，不是稳定版本；暂不自动删除。

归档发布工作流 `release.yml` 与镜像工作流分别由同一次已授权 tag push 触发，
避免依赖 `GITHUB_TOKEN` 创建 Release 后不会自动触发的 `release: published` 事件。
两条工作流没有跨工作流原子性：需监控两条运行。任一步失败时保留状态并报告，
未经新的明确授权不能重跑发布、删除/覆盖标签或静默重新发布。

生产部署固定完整 digest；升级前备份数据库和配置，检查 schema/结果协议兼容性，
回滚不清空状态、不重新注册。已有数据库的自动升级不能靠旧镜像降级自动撤销。

## 开发验证

从对应 Rust 仓库运行：

```sh
python3 -m unittest discover -s docker -p 'test_*.py'
python3 docker/ci.py metadata --component server
shellcheck docker/publish.sh
actionlint .github/workflows/docker.yml
```

新代码的 OCI 合约测试会拒绝损坏 blob、错误版本/提交/架构、缺少证明、归档路径穿越和错误校验和。
容器冒烟必须有 Docker Engine、Buildx、Skopeo 和 OpenSSL；无 Docker 权限时不能把容器验收记为通过。
后端 cargo test 默认跳过需要真实数据库的 ignore 测试，CI 容器冒烟不代表全部数据库集成测试已通过。

官方参考：[多架构构建](https://docs.docker.com/build/ci/github-actions/multi-platform/)、
[构建来源证明](https://docs.docker.com/build/ci/github-actions/attestations/)、
[GHA 缓存](https://docs.docker.com/build/cache/backends/gha/)、
[GHCR 发布](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images)、
[Environment 门禁](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)。
