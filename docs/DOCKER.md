# Docker 服务端部署

[项目首页](../README.md) · [文档中心](README.md) · [常规部署](DEPLOYMENT.md)

服务端镜像包含 Rust 后端、固定提交的 Vue 前端 dist、SQL 和模板；PostgreSQL、Elasticsearch 独立运行。
全部环境变量、类型、容器默认值、生效规则和 Compose 设置见 [Docker 完整配置参考](DOCKER_CONFIGURATION.md)。
镜像地址为 `ghcr.io/wshijiang/network-mapping-server`，支持 Linux AMD64/ARM64。
Rust 使用 1.99.0、Node 26.11.1、pnpm 11.9.0；构建与运行环境采用 Debian 12，基础镜像固定多架构 digest。
真实配置、TLS、日志、数据库、本机二进制和 Git 目录通过构建上下文允许清单排除，最终镜像没有编译器或源代码。

部署已有镜像无需本地编译或单独构建前端，从[准备运行配置](#准备运行配置)开始。所有命令默认在 `network-mapping/` 执行，使用同一份 `docker/.env`、Compose 文件及项目名；`docker/runtime/` 路径相对于 Compose 文件所在目录。

[准备配置](#准备运行配置) · [启动](#compose-示例) · [首次登录与联调](#首次登录与联调) · [升级与恢复](#升级与恢复) · [常见问题](#常见问题) · [本地构建](#固定前端与本地构建) · [CI 发布](#github-自动构建与发布)

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
chmod 0600 docker/.env
openssl rand -base64 32
openssl rand -hex 32
openssl rand -hex 24
```

将上述三个随机值分别填写到 `docker/.env` 的 `NM__SERVER__ENCRYPT_KEY`、
`NM__SECURITY__SCANNER_TOKEN_PEPPER`、`NM__DATABASE__PASSWORD`。Compose 将数据库密码同时
传给服务端和 PostgreSQL；已有 PG 数据卷的角色密码不会随 env 修改自动改变。
`.env` 不提交到仓库，建议权限 0600。

`.env.example` 已列出全部支持的基础环境变量；可选项、互斥认证及废弃字段默认注释，
按需启用。仅支持文件模式的字段另列在 `docker/config.example.toml` 的注释示例中。

`cp` 仅用于首次安装，已有部署应编辑原文件，避免覆盖长期密钥与连接参数。先确认以下项目，再启动：

| 配置 | 需要填写/确认 |
| --- | --- |
| `SERVER_IMAGE` | 实际存在且可拉取的版本或完整 `@sha256:…`；模板中的占位版本不能使用 |
| 三个随机值 | Base64 加密密钥、独立 Pepper、PG 密码，填到对应变量 |
| HTTPS | `cert.pem` 为完整服务证书链，`key.pem` 为匹配私钥，`ca.pem` 为健康探针信任的 CA 链 |
| 域名/端口 | HTTPS 的 `SERVER_TLS_NAME` 匹配证书 DNS 名（未填默认 `localhost`）；`SERVER_PUBLISH_PORT` 是宿主机入口，`NM__SERVER__PORT` 是容器监听端口 |
| 外部访问 | 默认仅 `127.0.0.1`；远程扫描节点需要可达的 HTTPS 代理或对外发布地址 |
| 依赖与资源 | 本地 PG/ES profiles 或已就绪的外部存储；ES 所需内存、磁盘与宿主机内核参数 |

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
`SERVER_IMAGE` 填已批准的版本或完整 digest。标准 Compose 默认启用 TLS，宿主机代理的上游使用 HTTPS，并按项目说明配置可信代理。

服务端也支持 `NM__TLS__ENABLED=false`，但必须同时设置 `NM__SERVER__HOST=127.0.0.1` 或 `::1`；此时无需服务端证书和私钥，其他密钥和数据库配置仍必需。文件模式使用 `[tls] enabled = false`。旧配置省略开关仍启用 TLS。

回环绑定限制作用于**容器内部**。普通 bridge 网络中的宿主机端口映射和独立代理容器无法访问该 HTTP 监听，不能通过修改 `SERVER_BIND_ADDRESS` 绕过限制；标准 Compose 应保留 TLS。需要 HTTP 上游时，代理应与服务端共享网络命名空间，或在 Linux 上使用经过配置的 host 网络并由同机代理访问。外部入口继续使用 HTTPS，协议转发头设置见[部署指南](DEPLOYMENT.md#本地-http)。

镜像健康探针自动读取 `NM__TLS__ENABLED`、`NM__SERVER__HOST` 和 `NM__SERVER__PORT`（支持对应 `_FILE`），关闭 TLS 时使用 HTTP 且不读取 CA；开启 TLS 时验证 `SERVER_TLS_NAME` 和 CA 链。`0.0.0.0`、`::` 分别探测对应地址族的回环地址，支持 IPv6 和自定义端口。本地探针不经过容器的出站代理，不会尝试另一协议作为失败回退。`SERVER_TLS_CA_FILE` 可覆盖探针 CA 路径，默认 `/etc/network-mapping/tls/ca.pem`。

使用 `--config-source file` 时，探针不解析 TOML。监听协议、地址和端口与 env 默认值不同时，在 Compose 中显式覆盖探针参数，与 TOML 保持一致，例如 IPv6 HTTP：

```yaml
healthcheck:
  test: [CMD, /opt/network-mapping/bin/healthcheck, http, "::1", "9999"]
```

`http` 模式无需 `SERVER_TLS_NAME`、CA 或服务端证书；`https` 模式继续使用证书校验。探针访问无需登录的 `/healthz`：PG/ES 就绪返回 `200`，未就绪或状态过期返回 `503`，响应正文为空。检查每 5 秒刷新、单项超时 2 秒、15 秒过期；具体错误只记录在服务端日志。ES 角色需具备读取集群健康的权限。详情见[健康检查 API](DEPLOYMENT.md#健康检查-api)。

服务进程 UID/GID 为 10001:10001。配置和私钥要能被该 UID 读取，例如由管理员调整为
属主 10001、模式 0400；TLS 目录允许该用户遍历。不要通过公开可读权限解决私钥读取问题。
命名卷首次创建会沿用镜像目录的属主，已有卷或宿主机绑定目录需手动检查 UID/GID。

专用 TLS 目录可在放入证书后按如下方式授权；原证书由其他服务共用时，复制到此目录再调整权限：

```sh
sudo chown 10001:10001 docker/runtime/tls docker/runtime/tls/cert.pem docker/runtime/tls/key.pem docker/runtime/tls/ca.pem
sudo chmod 0500 docker/runtime/tls
sudo chmod 0400 docker/runtime/tls/cert.pem docker/runtime/tls/key.pem docker/runtime/tls/ca.pem
```

如果还有 `elasticsearch-ca.pem`，也需给 UID 10001 读取权限。不要把客户端所需 CA 与服务端私钥一起复制到扫描节点。

## Compose 示例

需要 Docker Compose 2.20.0 或更新版本（支持可选启动依赖）。

```sh
docker compose --env-file docker/.env -f docker/compose.example.yml config --quiet
docker compose --env-file docker/.env -f docker/compose.example.yml pull
docker compose --env-file docker/.env -f docker/compose.example.yml up -d
docker compose --env-file docker/.env -f docker/compose.example.yml ps
docker compose --env-file docker/.env -f docker/compose.example.yml logs --tail=100 server
```

`config --quiet` 只验证 Compose 结构与插值，不验证应用密钥、证书、存储权限或服务就绪。不要把无 `--quiet` 的配置展开结果、`docker inspect` 环境信息发到工单，它们可能包含凭据。私有 GHCR 包需先使用有读取该包权限的身份登录注册表；拉取失败应先确认包可见性、版本和架构。

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

### NAT/bridge 容器连接宿主机 PostgreSQL

标准 Compose 已为服务端添加 `host.docker.internal:host-gateway` 映射，适用于支持 `host-gateway` 的 Linux Docker Engine（20.10+）。不要把宿主机 Docker 网桥地址写死为 `172.17.0.1`。容器的 `127.0.0.1` 指容器自身，`postgres` 指配套 PG 容器；它们都不表示宿主机数据库。Docker Desktop 使用其支持的宿主机访问机制；rootless 或远程 Docker daemon 应核实实际宿主机地址，远程 daemon 的 host 指 daemon 所在机器。

编辑 `docker/.env`，保留原来的密钥和数据库凭据。例如 PG 在宿主机、ES 仍使用配套容器：

首次安装也可复制 `docker/.env.host-db.example` 到 `docker/.env` 作为此拓扑的完整参数模板，再填写镜像、密钥、PG 凭据及 TLS 证书；已有部署直接编辑原 `.env`，不要覆盖密钥。

```dotenv
COMPOSE_PROFILES=local-elasticsearch
NM__DATABASE__HOST=host.docker.internal
NM__DATABASE__PORT=5432
```

如果 ES 也在宿主机，清空 `COMPOSE_PROFILES`，同时设置 `NM__ELASTICSEARCH__URL=http://host.docker.internal:9200`，按实际部署改用 HTTPS、认证和可信 CA。`SERVER_BIND_ADDRESS` 和 `ports` 只控制服务端入站连接，不影响访问数据库。

宿主机 PostgreSQL 必须监听容器可达的接口。只监听 `127.0.0.1` 时，添加名称映射仍无法访问。由数据库管理员确认 Docker 网桥接口地址及容器实际来源网段后配置，例如下面的地址仅作演示，必须替换为本机实际值：

```conf
# postgresql.conf：保留本机回环，同时增加实际宿主机网桥接口；修改后重启 PG
listen_addresses = '127.0.0.1,172.17.0.1'

# pg_hba.conf：仅授权应用库、角色及实际容器来源网段；修改后 reload
host network_mapping network_mapping 172.18.0.0/16 scram-sha-256
```

防火墙同样仅放行需要的容器来源访问实际 PG 端口，无需向公网开放数据库。核对 `ss -lntp 'sport = :5432'`、PG 日志中的来源地址，以及 `pg_hba.conf` 规则顺序。PG 当前使用 NoTls，因此仅允许 `hostssl` 的规则无法匹配，设置 `NM__DATABASE__TLS=true` 不会改变这一点。

应用配置确认后执行 `up -d --force-recreate server`，然后查看服务日志中的 `database_host`、`database_port` 和首个连接错误。名称解析失败通常是目标地址/映射问题，拒绝连接通常是监听/端口问题，超时需检查路由和防火墙，`no pg_hba.conf entry` 或密码失败需检查数据库授权与认证。容器默认使用 env 配置，修改宿主机根目录的 `config.toml` 不会覆盖它。

### Linux host 网络：本地 HTTP、宿主机数据库与代理

新增的 `docker/compose.host.example.yml` 是**独立部署文件**，不要与标准 bridge Compose 合并。它不发布端口、不创建配套 PG/ES、不挂载服务端证书，使用宿主机已就绪的 PG/ES。适用于原生 Linux Docker Engine；Docker Desktop 的 host 网络需要相应版本与显式启用，其他平台请使用受支持的部署方式。

```sh
cp docker/.env.host.example docker/.env.host
chmod 0600 docker/.env.host
# 填写实际 SERVER_IMAGE、长期密钥、PG 凭据和 PG/ES 连接地址，再执行：
docker compose --env-file docker/.env.host -f docker/compose.host.example.yml config --quiet
docker compose --env-file docker/.env.host -f docker/compose.host.example.yml up -d
docker compose --env-file docker/.env.host -f docker/compose.host.example.yml ps
docker compose --env-file docker/.env.host -f docker/compose.host.example.yml logs --tail=100 server
```

此模式下 `127.0.0.1` 与宿主机共享：模板默认 `NM__TLS__ENABLED=false`、`NM__SERVER__HOST=127.0.0.1`，数据库和 ES 也使用各自的宿主机回环端口。数据库可以继续只监听本机回环，无需添加容器网段授权。HTTP 探针自动适配，无需证书域名或 CA。宿主机反向代理使用 `http://127.0.0.1:9999`，公网仍由代理提供 HTTPS；代理头设置见[部署指南](DEPLOYMENT.md#本地-http)。

关闭 TLS 仍严格限制回环监听。host 模式下 `SERVER_BIND_ADDRESS`、`SERVER_PUBLISH_PORT` 和 Docker `ports` 不适用；用 `NM__SERVER__PORT` 修改实际宿主机监听端口并避免与其他进程冲突。`postgres`、`elasticsearch` 等 bridge 服务名不能继续作为此模式的默认地址，需改为宿主机或外部可达地址。

从已有部署切换时，先备份、停止旧服务端并保留数据卷，再启动新配置。两个示例沿用同一项目名与服务端数据卷名；需要同时运行多个部署时显式设置不同项目名及端口。复制 `.env.host.example` 只用于首次准备，已有部署必须保留原 `encrypt_key`、Pepper 和数据库凭据。切换到 host 网络不会迁移数据库或自动停止旧 PG/ES 容器；不要执行 `down -v`。

ES 示例关闭认证，只适用于隔离的单宿主机网络。生产应按 [ES 指南](ELASTICSEARCH.md)
配置认证与 TLS，并调整对应 env 参数、CA 挂载及 ES healthcheck。PG 当前使用 NoTls，跨主机连接不能靠
`NM__DATABASE__TLS=true` 获得加密。宿主机需满足 ES 内存、文件描述符及 vm.max_map_count 要求，
例如由管理员设置 `vm.max_map_count=1048576`；不要从 Web 容器修改宿主机内核参数。

server-data 保存诊断与可选 MaxMind 数据，server-logs 保存滚动 JSON 日志；数据库分别有独立数据卷。
docker stdout 日志限制为 3×10MiB，应用文件日志仍需外部保留/轮转管理。
不要执行 `down -v` 清空生产数据。启动依赖健康检查仅控制启动顺序；服务端健康探针报告
`/healthz` 的近期 PG/ES 就绪状态，不检查前端资源或完整业务流程。pgBackRest Web 桥接默认关闭，备份由独立服务或宿主机负责。

## 首次登录与联调

首次空库启动在不存在管理员时自动创建默认管理员。随机密码一次性输出到容器标准输出，可从上面的 `logs` 命令获取；用户名通常为 `admin`，以输出为准。限制这些日志的访问，登录后立即改密。首次启动失败前已写入的管理员不会在重试时重新显示密码。

已初始化数据库但没有保存密码时，使用交互式 CLI 设置密码（替换实际用户名）：

```sh
docker compose --env-file docker/.env -f docker/compose.example.yml exec server \
  /opt/network-mapping/bin/network_mapping_server --config-source env user password set admin
```

该命令复用容器环境与数据库，不会另起 HTTPS 监听。完整账号操作见[用户管理 CLI](USER_MANAGEMENT_CLI.md)。

以下检查示例使用 `server.example.com` 和宿主机 9999 端口，按实际入口替换：

```sh
sudo curl --fail --show-error --silent --cacert docker/runtime/tls/ca.pem \
  --resolve server.example.com:9999:127.0.0.1 https://server.example.com:9999/login -o /dev/null
```

随后从浏览器和**实际扫描节点**访问正式域名，检查静态资源、管理员登录和 API 鉴权。`SERVER_TLS_NAME` 只用于容器探针，不会创建 DNS 记录，也不会让客户端自动信任证书。使用 443 代理入口时，节点配置的是代理域名及 443，而非 Compose 内部服务名 `server` 或容器监听端口。

在控制台创建扫描器，按[扫描端部署指南](https://github.com/wshijiang/Network-Mapping-Scanner/blob/main/docs/DEPLOYMENT.md)完成注册。确认心跳、`accepting_tasks`、地址族/profile、首个授权任务、结果上传及搜索。`healthy` 表示近期 PG/ES 检查通过，不替代这组验收。

## 升级与恢复

1. 保存当前镜像 digest、`.env`、TLS、配置与数据卷清单；核对 schema、ES 和扫描协议变化。暂停自动任务及新任务分配，等待活动任务与上传完成。
2. 在 `.env` 中仅将 `SERVER_IMAGE` 改为待部署的固定版本/digest，先验证与拉取。升级应用时保持 PG/ES 版本、项目名和卷不变：

   ```sh
   docker compose --env-file docker/.env -f docker/compose.example.yml config --quiet
   docker compose --env-file docker/.env -f docker/compose.example.yml pull server
   docker compose --env-file docker/.env -f docker/compose.example.yml stop server
   ```

3. 确认其他实例也停止写入，在同一维护窗口取得 PG 备份与 ES 快照，并保存 server-data 中的诊断/可选数据。PG 数据卷的文件复制不能代替一致性备份。备份策略见[部署恢复](DEPLOYMENT.md#升级与恢复)。
4. 只重建服务端，不连带升级数据库：

   ```sh
   docker compose --env-file docker/.env -f docker/compose.example.yml up -d --no-deps --force-recreate server
   docker compose --env-file docker/.env -f docker/compose.example.yml ps
   docker compose --env-file docker/.env -f docker/compose.example.yml logs --tail=100 server
   ```

5. 重新执行首次登录与联调检查，再逐批恢复节点和自动任务。使用自定义 SQL 覆盖文件的部署，所有命令仍须带上原来的第二个 `-f` 参数。

回滚镜像不会撤销自动 DDL；只有确认 schema/协议向后兼容时才能改回原 digest 并重建。需要恢复数据时，停止全部写入，配对恢复 PG、ES、配置和长期密钥。保持 Compose 的 `name: network-mapping`（或原 `-p` 参数）及卷名，避免误启动空库；不要使用 `down -v`、删索引或清空数据卷排障。已有 PG 卷修改密码须在数据库内同步更新，改 env 不会重设已有角色密码。

## 常见问题

| 现象 | 优先检查 |
| --- | --- |
| 镜像不存在/拉取被拒绝 | 是否替换占位版本、GHCR 读权限、包可见性、节点架构 |
| 启动提示必填配置为空 | 三个密钥/密码是否填入 `.env`，是否同时配置直接值与 `_FILE`，是否重建容器 |
| `unhealthy` 或 TLS 读取失败 | UID 10001 的目录遍历/文件权限、证书链与私钥、`ca.pem`、`SERVER_TLS_NAME` 及监听端口 |
| 本机能访问、远程节点失败 | 默认仅绑定 127.0.0.1，检查入口代理、发布地址、防火墙、DNS 和客户端 CA |
| 本地 PG/ES 不启动 | `.env` 的 `COMPOSE_PROFILES`；若已改为外部服务，确认网络地址不是容器自身的 127.0.0.1 |
| ES 等待失败/内存不足 | 查看 `logs --tail=100 elasticsearch`，检查内存、磁盘水位、`vm.max_map_count` 与 healthcheck |
| PG 认证失败 | env 角色/库名与现有卷是否一致，旧角色密码是否已在 PG 中更改 |
| 修改 env 没有效果 | 使用同一 `.env` 和 Compose 文件执行 `up -d --force-recreate`；策略配置另按 Web 发布 |
| 重启后历史数据消失 | 检查项目名、卷名和连接目标；先找回原卷/原存储，不继续初始化新空库 |

先保存首个错误的脱敏日志，再调整配置。服务端文件日志在 server-logs，容器启动失败信息在 stdout；持续运行也应监控 PG、ES、磁盘、投影积压及扫描器心跳。

## 容器验收范围

CI 从已验证 OCI 产物加载镜像，检查镜像配置 digest 一致后，在临时 PG/ES 下验证初始化、可信 HTTPS、无证书回环 HTTP、镜像健康探针、
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
sh -n docker/healthcheck.sh
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
