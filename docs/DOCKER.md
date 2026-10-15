# Docker 服务端部署

[项目首页](../README.md) · [文档中心](README.md) · [常规部署](DEPLOYMENT.md)

服务端镜像包含 Rust 后端、固定提交的 Vue 前端 dist、SQL 和模板；PostgreSQL、Elasticsearch 独立运行。
镜像地址为 `ghcr.io/wshijiang/network-mapping-server`，支持 Linux AMD64/ARM64。
Rust 使用 1.99.0、Node 26.11.1、pnpm 11.9.0；构建与运行环境采用 Debian 12，基础镜像固定多架构 digest。
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

启动配置检查同时适用于文件和 Docker 部署，不修改只读挂载文件；Web 提示和升级后的处理方式见 [启动配置检查](CONFIG_CHECK.md)。

## 内置 SQL 与可选自定义 SQL

镜像默认包含仓库全部 SQL：`source/database/` 下的初始化、查询和迁移脚本，以及
`docs/` 下的 SQL，目录保留在 `/opt/network-mapping/` 中。`SQL-SHA256SUMS` 记录内置文件的摘要；
两个架构的 CI 都逐文件核对镜像内容与发布源码。默认配置直接使用内置 `init.sql` 与 SQL 目录，
首次启动无需挂载 SQL；初始化和自动迁移仍按服务端原有顺序执行。
随镜像提供的手工迁移、验证、查询及设计草案 SQL 不会因为打包而额外自动执行。

需要自定义 SQL 时，将审核后的文件放入宿主机独立目录，在 `docker/.env` 设置
`SERVER_SQL_DIRECTORY=/srv/network-mapping/sql`，按需配置 SQL 路径：

```dotenv
NM__DATABASE__INIT_DATABASE_FILE=/etc/network-mapping/sql/init.sql
NM__DATABASE__SQL_FILE_PATH=/etc/network-mapping/sql/
```

只需覆盖其中一项时保留另一项的内置路径。自定义目录需包含所选路径使用的 SQL 文件，
例如查询目录中的 `get_table_size.sql`；文件须允许 UID 10001 读取。使用可选 Compose 覆盖文件：

```sh
docker compose --env-file docker/.env -f docker/compose.example.yml \
  -f docker/compose.sql.example.yml config --quiet
docker compose --env-file docker/.env -f docker/compose.example.yml \
  -f docker/compose.sql.example.yml up -d
```

此挂载位于独立的只读目录，镜像自带 SQL 仍可使用。配置路径不改变程序内嵌自动迁移的执行逻辑；
额外维护脚本由管理员按对应迁移文档执行。

## 准备运行配置

从 `network-mapping/` 运行：

```sh
mkdir -p docker/runtime/tls
cp docker/.env.example docker/.env
openssl rand -base64 32
openssl rand -hex 32
openssl rand -hex 24
```

将上述三个随机值分别填写到 `docker/.env` 的 `NM__SERVER__ENCRYPT_KEY`、
`NM__SECURITY__SCANNER_TOKEN_PEPPER`、`NM__DATABASE__PASSWORD`。Compose 将数据库密码同时
传给服务端和 PostgreSQL；已有 PG 数据卷的角色密码不会随 env 修改自动改变。
`.env` 不提交到仓库，建议权限 0600。

Docker 的默认入口为 `--config-source env`，Compose 使用 `env_file: ./.env` 注入参数，
无需挂载 TOML。`--env-file` 负责 Compose 插值，不能单独代替服务级 `env_file`。
变量规则为 `NM__SECTION__FIELD`，映射到 `section.field`；数字和布尔值按类型校验，数组/对象用 JSON。
未知变量报错；字符串密码不会因为只含数字而被转换为数字。支持字段对应的 `_FILE` 输入，
例如 `NM__SERVER__ENCRYPT_KEY_FILE=/run/secrets/encrypt_key`，与直接值不能同时配置。
示例 Compose 的 PG 使用直接密码；使用外部 Secret 时需同步配置 PG 的密码来源。

连接需要认证的 Elasticsearch 时，使用 `NM__ELASTICSEARCH__API_KEY`，或同时设置
`NM__ELASTICSEARCH__USERNAME` 与 `NM__ELASTICSEARCH__PASSWORD`，两种方式互斥；
认证字段也支持对应的 `_FILE` 输入。请勿将用户名和密码写入 Elasticsearch URL。
私有 CA 可放在 `docker/runtime/tls/elasticsearch-ca.pem`，设置
`NM__ELASTICSEARCH__CA_CERTIFICATE_FILE=/etc/network-mapping/tls/elasticsearch-ca.pem`。
TLS 目录已只读挂载；该变量直接表示容器内的证书路径，不会被当作 `_FILE` 密钥输入读取。
未配置这些可选字段时，保持无认证和系统 CA 的原有行为。

SQL、模板、前端和日志路径等容器默认值内置在程序中，不依赖宿主机配置文件。
文件部署继续使用 `--config config.toml`（默认 file 模式）。需要兼容旧容器挂载时，显式使用
`--config-source file --config /etc/network-mapping/config.toml`。
env 模式的相对路径以进程工作目录为基准。日志和 Web 检查不展示密钥值。
Web 管理的运行设置继续以数据库为准，env 只提供缺失记录的初始值。
修改 `.env` 后执行 `docker compose ... up -d --force-recreate` 重新注入环境，单纯 restart 不更新环境。

准备可信 TLS 文件 `docker/runtime/tls/cert.pem`、`key.pem` 和 `ca.pem`；
ca.pem 用于容器健康探针，必须能验证 cert.pem。`.env` 的 `SERVER_TLS_NAME` 填证书中的真实 DNS 名，
`SERVER_IMAGE` 填已批准的版本或完整 digest。服务仍使用 HTTPS，不支持直接改为明文 HTTP。
通过宿主机代理发布时上游也使用 HTTPS，并按项目说明配置可信代理。

服务进程 UID/GID 为 10001:10001。配置和私钥要能被该 UID 读取，例如由管理员调整为
属主 10001、模式 0400；TLS 目录允许该用户遍历。不要通过公开可读权限解决私钥读取问题。
命名卷首次创建会沿用镜像目录的属主，已有卷或宿主机绑定目录需手动检查 UID/GID。

## Compose 示例

需要 Docker Compose 2.20.0 或更新版本（支持可选启动依赖）。

```sh
docker compose --env-file docker/.env -f docker/compose.example.yml config --quiet
docker compose --env-file docker/.env -f docker/compose.example.yml up -d
docker compose --env-file docker/.env -f docker/compose.example.yml ps
```

`.env.example` 默认启用 `local-postgres,local-elasticsearch` 两个 profile，
部署一个服务端、一套 PG 18 和 ES 9.5.0，数据库没有宿主机端口映射；PG 18 卷挂载到
`/var/lib/postgresql`。服务端默认只发布宿主机 127.0.0.1:9999；需要直接访问时在 .env 明确设置
`SERVER_BIND_ADDRESS=0.0.0.0` 并配置防火墙、可信 DNS 和证书。

已有 PostgreSQL 和 Elasticsearch 时，在 `docker/.env` 清空 profile 并指定地址和认证：

```dotenv
COMPOSE_PROFILES=
NM__DATABASE__HOST=pg.example.internal
NM__DATABASE__PORT=5432
NM__DATABASE__USERNAME=network_mapping
NM__DATABASE__PASSWORD=replace-with-database-password
NM__DATABASE__DB_NAME=network_mapping
NM__ELASTICSEARCH__URL=https://es.example.internal:9200
NM__ELASTICSEARCH__API_KEY=replace-with-api-key
```

使用上面相同的 Compose 命令即可只启动服务端，PG/ES 容器不会创建，也不会等待它们的健康检查。
只使用一项外部服务时，保留另一项的 profile，例如外部 ES 配本地 PG：
`COMPOSE_PROFILES=local-postgres`。外部服务必须能从容器网络访问，地址不能用容器内的 `127.0.0.1`；
数据库需预先创建并授予应用角色建表和升级权限，ES 版本须符合 [ES 指南](ELASTICSEARCH.md)。
已运行的本地 PG/ES 容器不会因禁用 profile 自动删除；切换前备份数据，迁移并验证外部服务后再停用旧容器。

ES 示例关闭认证，只适用于隔离的单宿主机网络。生产应按 [ES 指南](ELASTICSEARCH.md)
配置认证与 TLS，并调整对应 env 参数、CA 挂载及 ES healthcheck。PG 当前使用 NoTls，跨主机连接不能靠
`NM__DATABASE__TLS=true` 获得加密。宿主机需满足 ES 内存、文件描述符及 vm.max_map_count 要求，
例如由管理员设置 `vm.max_map_count=1048576`；不要从 Web 容器修改宿主机内核参数。

server-data 保存诊断与可选 MaxMind 数据，server-logs 保存滚动 JSON 日志；数据库分别有独立数据卷。
docker stdout 日志限制为 3×10MiB，应用文件日志仍需外部保留/轮转管理。
不要执行 `down -v` 清空生产数据。启动依赖健康检查仅控制启动顺序；服务端健康探针只验证
TLS 和登录页存活，不代表运行期间 PG/ES 持续就绪。pgBackRest Web 桥接默认关闭，备份由独立服务或宿主机负责。

## 容器验收范围

CI 从已验证 OCI 产物加载镜像，检查镜像配置 digest 一致后，在临时 PG/ES 下验证初始化、可信 HTTPS、
登录页静态资源、缺失路径/文件 404、正常停止及保留数据库的重启。临时网络与容器始终清理。
冒烟测试的 ES 数据目录使用容量上限为 1 GiB 的 tmpfs，避免 runner 上的构建缓存和 OCI 归档
使宿主磁盘占用过高而触发 ES 磁盘水位限制；只有集群健康为 green/yellow 且等待未超时才继续启动服务端。
PG 就绪探测通过 TCP，避开初始化临时实例的 Unix socket；就绪等待按实际耗时限制为 180 秒，
容器提前退出或被 OOM 杀死会立即报错。诊断和清理各命令限制为 10 秒，失败后仍继续清理并保留原始错误。
生产仍需人工验证管理员登录、历史页面刷新、API 鉴权、扫描器联调、备份恢复和实际证书链。

## GitHub 自动构建与发布

`.github/workflows/docker.yml` 在 `main`、`dev`、`dev/**`、`feature/**`、`fix/**`、
`release/**` 提交以及面向 `main`/`dev` 的 PR 上运行；扫描仓库另外兼容现有 `rust` 分支。
`workflow_dispatch` 留空版本时只构建；填写 `promote_version` 时只提升已发布镜像的 latest。工作流文件需先进入远端相应分支，手动入口需在默认 `main` 中存在。

两个原生 runner 分别构建 `linux/amd64` 与 `linux/arm64`，Dockerfile 内执行
`cargo fmt --check`、`cargo clippy --locked --all-targets`、`cargo test --locked` 和 release 构建。
GHA 缓存按组件/架构分开，Cargo.lock 和基础镜像 digest 固定；APT 软件仓库仍会变化，
因此不承诺不同日期重新构建有相同字节。缓存失效不会影响正确性。

Docker 使用固定版本 `cargo-chef 0.1.78`：先从真实 manifests 和目标列表生成依赖配方，
再分别预编译 Clippy、开发/测试和 release 依赖。编译产物保存在普通 Docker 层中，
由现有 `type=gha,mode=max` 跨运行保存；没有需要额外导出的 BuildKit cache mount。
只修改业务源码时配方保持不变，依赖编译层可复用；依赖、features、工具链或基础镜像变化时重新构建。
真实 Cargo.toml、Cargo.lock、build.rs、源码和编译期资源在预编译后恢复，随后执行完整检查和测试。
Cargo 构建和测试使用默认并发，不设置 jobs 或 test-threads。

独立归档构建通过固定提交的 `Swatinem/rust-cache` 缓存 Cargo 下载和依赖编译产物，
按组件/目标三元组、Rust 编译器及构建环境区分；musl 的链接器和 features 在恢复缓存前配置。
`release.yml` 在 main 的 Cargo.toml、Cargo.lock、build.rs 或该工作流变化时预热四个目标的缓存，
此路径不检出前端、不打包、不上传归档、不发布。普通业务源码提交不额外触发预热。
只有 main 和 tag 运行写 Cargo 缓存；手动运行其他分支只读取可访问的缓存。
tag/手动归档构建保留原有行为，GitHub Release 发布仍要求 tag push。
Cargo 缓存和 Docker GHA 缓存共同占用仓库缓存容量；比较冷缓存、重复构建、源码修改和依赖更新的
总耗时及缓存传输耗时，容量不足或缓存过期时允许回退到完整编译。

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

发布生成 `vX.Y.Z` 和 `sha-<完整提交>`；稳定版本发布成功后自动维护以下可移动标签：

| 标签 | 运行架构 |
| --- | --- |
| `ghcr.io/wshijiang/network-mapping-server-amd64:latest` | 仅 Linux AMD64，保留该架构的构建证明 |
| `ghcr.io/wshijiang/network-mapping-server-arm64:latest` | 仅 Linux ARM64，保留该架构的构建证明 |

`docker/latest.py` 先读回正式版本，核对组件、Git tag 对应提交、两种架构的配置和各自证明的关联。
按数值比较稳定版本，旧版本不能覆盖更新的 latest；预发布版本不移动 latest。
所有标签更新与正式发布共享仓库级并发锁。两个架构使用独立的镜像名称，各自维护 `:latest`。
Skopeo 跨镜像仓库复制对应架构的全部 layers 和构建证明，逐个读回核对 digest；
注册表不支持两个镜像仓库的原子事务，失败后可重试修复部分更新。
版本与 SHA 标签保持不可变，latest 不替代生产部署的 digest 固定。

已有正式镜像可在 **Docker images → Run workflow** 填写 `promote_version`（如 `0.1.28`），
复用相同校验与 `container-release` 环境，仅补齐 latest，不构建、不重推版本或 SHA 标签。
此入口不依赖 `DOCKER_PUBLISH_ENABLED`：它只提升已存在的正式镜像；留空仍只构建。
首次创建这两个 GHCR 包后，检查它们各自的可见性和 Actions 访问权限。

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
actionlint .github/workflows/docker.yml .github/workflows/release.yml
```

新代码的 OCI 合约测试会拒绝损坏 blob、错误版本/提交/架构、缺少证明、归档路径穿越和错误校验和。
容器冒烟必须有 Docker Engine、Buildx、Skopeo 和 OpenSSL；无 Docker 权限时不能把容器验收记为通过。
后端 cargo test 默认跳过需要真实数据库的 ignore 测试，CI 容器冒烟不代表全部数据库集成测试已通过。

官方参考：[多架构构建](https://docs.docker.com/build/ci/github-actions/multi-platform/)、
[构建来源证明](https://docs.docker.com/build/ci/github-actions/attestations/)、
[GHA 缓存](https://docs.docker.com/build/cache/backends/gha/)、
[GHCR 发布](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images)、
[Environment 门禁](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)。


### CI 构建磁盘占用

服务端 workspace 会构建检查、测试和 release 三类 Rust 产物。Docker CI
关闭 dev/test 调试符号与增量编译，保留所有测试及原有 release 优化配置，
减少依赖层和真实源码构建层的占用。

两个一次性 GitHub 托管 runner 在构建前清理未使用的预装 SDK 和本地
Docker 缓存，并输出磁盘容量。完整镜像的 OCI 产物与 GHA 远程缓存导出
完成后，在镜像导入和数据库 smoke test 前清理 Buildx 快照，再输出容量。
PR 继续执行后端构建；可信分支继续执行前后端完整镜像验收。

清理只影响本次临时 runner，不删除 GHA 远程缓存或其他 CI 的缓存。
这些全局本地清理命令不应直接用于共享的自托管 runner；共享环境应使用
专用 builder 并只清理该 builder。
