# Docker 服务端完整配置参考

[Docker 部署指南](DOCKER.md) · [文档中心](README.md) · [运行时配置](RUNTIME_CONFIGURATION.md)

本文逐项列出本仓库服务端 Docker 部署的环境变量、Compose 设置、默认值和生效条件。
适用于 `docker/compose.example.yml`、`docker/compose.sql.example.yml` 和镜像默认的
`--config-source env` 模式。默认值来自容器内置配置及代码中的 `Default`，不是开发环境的 `config.toml`。
扫描器使用独立仓库和配置；Web 运行策略的完整文档见本文末尾的管理入口。

完整可复制示例分别位于 [`docker/.env.example`](../docker/.env.example)、
[`docker/config.example.toml`](../docker/config.example.toml) 和
[`docker/compose.example.yml`](../docker/compose.example.yml)。env 示例逐项列出所有基础变量，
TOML 示例同时列出仅文件配置可用的字段；可选项、互斥认证和废弃项以注释提供，按需启用。
TOML 示例仍是程序内置默认配置的来源，新增示例保持注释，不改变容器默认行为。

## 配置来源与生效

| 来源 | 用途 | 生效方式 |
| --- | --- | --- |
| `docker/.env` 中的 Compose 变量 | 镜像、端口、profile、可选 SQL 挂载 | Compose 解析并创建或重建容器 |
| `docker/.env` 中的 `NM__…` | 服务端启动参数 | `server.env_file` 注入环境，服务端启动时加载 |
| `compose.example.yml` | 服务定义、运行权限、卷、健康检查、PG/ES 容器参数 | 修改后重新执行 Compose `up` |
| 容器内置默认配置 | 未显式覆盖的已支持字段 | 先加载 `docker/config.example.toml` 的内嵌副本，其余使用类型默认值 |
| PostgreSQL 中的运行策略 | 请求日志、监控、自动目标等 | 已保存值优先；启动参数只为缺失记录提供初始值 |

`--env-file docker/.env` 用于 Compose `${…}` 插值；`server.env_file: ./.env` 用于容器环境注入，
两者用途不同。Compose 的 `environment` 会覆盖 `env_file` 中同名项；执行 Compose 时 shell 中的
同名变量也可能覆盖插值结果，部署时应保持这些值一致。单纯执行 `restart` 不会更新容器环境。

以下命令均从 `network-mapping/` 运行，要求 Docker Compose 2.20.0 或更新版本：

```sh
docker compose --env-file docker/.env -f docker/compose.example.yml config --quiet
docker compose --env-file docker/.env -f docker/compose.example.yml up -d --force-recreate
```

使用 `config --quiet` 校验配置，避免将含密码的完整展开结果输出到共享终端或日志。

## Compose 与镜像环境变量

这些变量不使用 `NM__SECTION__FIELD` 规则。

| 变量 | 类型 | 默认值 / 示例值 | 作用与约束 |
| --- | --- | --- | --- |
| `SERVER_IMAGE` | 字符串 | 无默认值，必填 | 服务端镜像；模板要求显式指定版本或 digest，`.env.example` 的版本占位符必须替换 |
| `SERVER_TLS_NAME` | 字符串 | Compose 必填；镜像单独运行默认为 `localhost` | 健康检查使用的证书 DNS 名；不是明文 HTTP 开关，也不会生成证书 |
| `SERVER_TLS_CA_FILE` | 字符串 | `/etc/network-mapping/tls/ca.pem` | HTTPS 健康探针 CA 路径；HTTP 模式不读取。 |
| `SERVER_BIND_ADDRESS` | 字符串 | `127.0.0.1` | 宿主机端口绑定地址；直接对外提供服务可显式改为 `0.0.0.0` |
| `SERVER_PUBLISH_PORT` | 整数 | `9999` | 宿主机发布端口，与容器监听端口可不同 |
| `COMPOSE_PROFILES` | 逗号分隔字符串 | `.env.example` 为 `local-postgres,local-elasticsearch`；未设置则不启用可选服务 | 选择本地依赖服务，具体组合见下表 |
| `SERVER_SQL_DIRECTORY` | 宿主机路径 | 未设置 | 仅使用 SQL 覆盖文件时必填；目录必须已存在且允许 UID 10001 读取 |
| `NM_DEFAULT_ADMIN_USERNAME` | 字符串 | `admin` | 数据库中没有管理员时创建初始管理员的用户名；密码随机生成，不通过环境变量指定；已有管理员不受影响 |
| `RUST_LOG` | 日志过滤表达式 | 未设置时为 `info`；使用 `--debug-model` 时为 `debug` | 例如 `info,network_mapping_server=debug`；控制文件日志，完整终端日志还需 `--verbose`；默认终端仍只显示启动摘要、警告和错误 |

| `COMPOSE_PROFILES` 值 | 本地启动的依赖 | 需要配置的外部连接 |
| --- | --- | --- |
| `local-postgres,local-elasticsearch` | PG、ES | 无 |
| `local-postgres` | PG | `NM__ELASTICSEARCH__URL` 及认证 |
| `local-elasticsearch` | ES | `NM__DATABASE__HOST`、端口和凭据 |
| 空字符串 | 无 | PG、ES 全部连接参数 |

关闭 profile 不会自动删除已存在的数据库容器或数据卷。外部连接地址必须能从容器内访问，
不能用容器内的 `127.0.0.1` 代表宿主机或远端数据库。

## 服务端环境变量规则

- `NM__SECTION__FIELD` 映射到 `section.field`，例如 `NM__DATABASE__HOST` 对应 `database.host`。
- 下表列出当前环境变量加载器接受的全部基础字段；未列出的 `NM__…` 会报未知字段错误。
  已接受但废弃的字段单独标明，不能据变量名称推断仍有效。
- 数字使用十进制值，布尔值使用 `true` / `false`；数组、对象使用 JSON，例如
  `NM__AUTOMATIC_TARGET__AUTHORIZED_CIDRS='["192.0.2.0/24"]'`。空值不能代替数字或布尔值。
- 每个基础字段均支持追加 `_FILE` 从**容器内文件**读取，文件末尾的 CR/LF 会去除。
  例如 `NM__SERVER__ENCRYPT_KEY_FILE=/run/secrets/encrypt_key`。
  必须通过 Compose `secrets` 或只读挂载提供文件；模板中的 Secret 示例默认注释，不会自动创建或挂载。
- 直接值与其 `_FILE` 输入不能同时存在；使用文件输入时要删除 `.env` 中原来的直接值行，即使该行值为空。
- 字段本身以 `_FILE` 结尾时优先解释为普通路径字段：
  `NM__TLS__PRIVATE_KEY_FILE`、`NM__DATABASE__INIT_DATABASE_FILE`、
  `NM__BACKUP__CONFIG_FILE`、`NM__ELASTICSEARCH__CA_CERTIFICATE_FILE` 都是路径，
  不是读取文件内容作为密钥的指令。
- 路径均指容器内路径；env 模式下相对路径基于进程工作目录，官方镜像为 `/opt/network-mapping`。
  修改路径时需同步挂载和权限，并满足只读根文件系统约束。

### 监听、安全与 HTTPS

| 环境变量 | 类型 | 容器默认值 | 作用与约束 |
| --- | --- | --- | --- |
| `NM__SERVER__HOST` | 字符串 | `0.0.0.0` | 容器内监听地址，不能为空；宿主机绑定地址由 `SERVER_BIND_ADDRESS` 控制 |
| `NM__SERVER__PORT` | 整数 | `9999` | 容器监听端口，正常部署使用 1–65535；Compose 映射与镜像健康检查均使用此变量 |
| `NM__SERVER__ENCRYPT_KEY` | 字符串 | 无可用默认值，必填 | 32 字节 Base64 密钥，通常为 44 字符；用 `openssl rand -base64 32` 生成并长期保存 |
| `NM__SERVER__MAX_BODY_SIZE` | 整数，字节 | `67108864` | 全局请求体上限，必须大于 0；部分接口有独立上限，见[扫描器诊断](SCANNER_DIAGNOSTICS.md) |
| `NM__SECURITY__SCANNER_TOKEN_PEPPER` | 字符串 | 无可用默认值，必填 | 去除首尾空白后至少 32 字符，建议 `openssl rand -hex 32`；变更会使已有扫描器令牌失效 |
| `NM__TLS__ENABLED` | 布尔 | `true` | 服务端 TLS 开关；关闭后只允许回环 IP 监听，证书可省略。 |
| `NM__TLS__CERTIFICATE_CHAIN_FILE` | 路径字符串 | `/etc/network-mapping/tls/cert.pem` | PEM 证书链，需与私钥匹配 |
| `NM__TLS__PRIVATE_KEY_FILE` | 路径字符串 | `/etc/network-mapping/tls/key.pem` | PEM 私钥，需允许 UID 10001 读取 |

服务端始终提供 HTTPS，没有关闭 TLS 或切换到明文 HTTP 的配置项。
默认将 `docker/runtime/tls` 挂载到 `/etc/network-mapping/tls`；还需提供 `ca.pem`，
镜像健康检查固定用 `/etc/network-mapping/tls/ca.pem` 验证服务器证书。
如果改变证书路径、目录或检查方式，需同时修改 Compose 挂载及 `server.healthcheck`。

端口映射为 `${SERVER_BIND_ADDRESS}:${SERVER_PUBLISH_PORT}:${NM__SERVER__PORT}`。
例如宿主机 443 转发至容器 9999，只需设置 `SERVER_PUBLISH_PORT=443`，容器仍使用 HTTPS。

### PostgreSQL

| 环境变量 | 类型 | 容器默认值 | 作用与约束 |
| --- | --- | --- | --- |
| `NM__DATABASE__HOST` | 字符串 | `postgres` | PG 主机名或 IP，不能为空 |
| `NM__DATABASE__PORT` | 整数 | `5432` | PG 服务端口 |
| `NM__DATABASE__USERNAME` | 字符串 | `network_mapping` | 应用数据库角色，不能为空 |
| `NM__DATABASE__PASSWORD` | 字符串 | 无可用默认值，必填 | 示例同时用于本地 PG 初始化；修改 env 不会自动修改已有数据卷中的角色密码 |
| `NM__DATABASE__DB_NAME` | 字符串 | `network_mapping` | 数据库名，不能为空；外部 PG 需提前创建数据库和角色 |
| `NM__DATABASE__POOL_MAX_SIZE` | 整数 | `10` | 最大连接数，必须大于 0 |
| `NM__DATABASE__POOL_WAIT_TIMEOUT_MS` | 整数，毫秒 | `2000` | 等待空闲连接的超时，必须大于 0 |
| `NM__DATABASE__POOL_CREATE_TIMEOUT_MS` | 整数，毫秒 | `5000` | 新建连接超时，必须大于 0 |
| `NM__DATABASE__POOL_RECYCLE_TIMEOUT_MS` | 整数，毫秒 | `3000` | 回收检查超时，必须大于 0 |
| `NM__DATABASE__TLS` | 布尔值 | `false` | 兼容字段；当前使用 `tokio_postgres::NoTls`，设为 `true` 也不会启用 PG TLS |
| `NM__DATABASE__INIT_DATABASE_FILE` | 路径字符串 | `/opt/network-mapping/source/database/init.sql` | 启动初始化 SQL，不能为空；默认使用镜像内置文件 |
| `NM__DATABASE__SQL_FILE_PATH` | 路径字符串 | `/opt/network-mapping/source/database/` | 查询 SQL 目录，保留结尾 `/` |

使用密码文件时，服务端可设置 `NM__DATABASE__PASSWORD_FILE`，但本地 PG 模板仍要求
直接密码插值。需同时调整 `postgres.environment`，例如改用官方 PG 的 `POSTGRES_PASSWORD_FILE`
并向该容器挂载同一 Secret；只增加服务端变量不足以完成切换。
自定义 SQL 的完整挂载步骤见[部署指南](DOCKER.md#内置-sql-与可选自定义-sql)。

### Elasticsearch 连接与存储

| 环境变量 | 类型 | 容器默认值 | 作用与约束 |
| --- | --- | --- | --- |
| `NM__ELASTICSEARCH__ENABLED` | 布尔值 | `true` | 当前必须为 `true`，不支持禁用 ES |
| `NM__ELASTICSEARCH__READ_ENABLED` | 布尔值 | `true` | 当前必须为 `true` |
| `NM__ELASTICSEARCH__SCAN_STORAGE` | 字符串 | `elasticsearch` | 仅接受此值；不支持 `postgres` 或 `dual` |
| `NM__ELASTICSEARCH__FALLBACK_TO_POSTGRES` | 布尔值 | `false` | 当前必须为 `false`，不支持 PG 扫描事实回退 |
| `NM__ELASTICSEARCH__URL` | 字符串 | `http://elasticsearch:9200` | HTTP(S) 地址，不得内嵌用户名或密码 |
| `NM__ELASTICSEARCH__EXPECTED_VERSION` | 字符串 | `9.5.x` | 仅支持正式 9.5.N；旧 `9.5.N` 配置也表示允许整个 9.5 系列 |
| `NM__ELASTICSEARCH__API_KEY` | 可选字符串 | 未设置 | 与用户名/密码认证互斥；也支持 `NM__ELASTICSEARCH__API_KEY_FILE` |
| `NM__ELASTICSEARCH__USERNAME` | 可选字符串 | 未设置 | 必须与 PASSWORD 同时提供；也支持 `NM__ELASTICSEARCH__USERNAME_FILE` |
| `NM__ELASTICSEARCH__PASSWORD` | 可选字符串 | 未设置 | 必须与 USERNAME 同时提供；也支持 `NM__ELASTICSEARCH__PASSWORD_FILE` |
| `NM__ELASTICSEARCH__CA_CERTIFICATE_FILE` | 可选路径字符串 | 未设置，使用系统 CA | 私有 CA 的容器内文件路径；可放入已挂载的 TLS 目录 |
| `NM__ELASTICSEARCH__OBSERVATION_INDEX_PREFIX` | 字符串 | `network-mapping-scan-observations-v1` | 原始扫描观察月索引前缀 |
| `NM__ELASTICSEARCH__EXECUTION_ENDPOINT_INDEX` | 字符串 | `network-mapping-execution-endpoints-v1` | 执行端点索引 |
| `NM__ELASTICSEARCH__CURRENT_ENDPOINT_INDEX` | 字符串 | `network-mapping-endpoints-current-v2` | 当前端点投影索引 |
| `NM__ELASTICSEARCH__DNS_OBSERVATION_DATA_STREAM` | 字符串 | `network-mapping-dns-observations` | DNS 观察 Data Stream 名称 |
| `NM__ELASTICSEARCH__DNS_RECORD_INDEX` | 字符串 | `network-mapping-dns-records-v1` | 当前 DNS 记录投影索引 |
| `NM__ELASTICSEARCH__DNS_OBSERVATION_RETENTION_DAYS` | 整数，天 | `180` | DNS 观察保留期，30–365 |
| `NM__ELASTICSEARCH__SCAN_NUMBER_OF_REPLICAS` | 整数 | `0` | 扫描索引副本数，0–5；单节点示例为 0 |
| `NM__ELASTICSEARCH__WRITE_WAIT_FOR_ACTIVE_SHARDS` | 字符串 | `1` | Bulk 写入分片等待数，接受 `1`、`all` 或正整数；单节点使用 `1` |
| `NM__ELASTICSEARCH__INDEX` | 旧字段 | 未使用 | 仅兼容名称，当前配置类型不再使用该字段；应删除，设置不会改变索引 |

索引/前缀名称不能为空、不得超过 240 字符，不能包含大写、空白及代码拒绝的特殊字符。
已有实例的事实索引与回执有关联，不能把修改名称当作自动迁移；迁移、备份和版本策略见
[Elasticsearch 指南](ELASTICSEARCH.md)。未使用的可选认证字段应省略，不要通过空字符串代替“未设置”。

### Elasticsearch 吞吐、超时与历史迁移

| 环境变量 | 类型 | 容器默认值 | 作用与约束 |
| --- | --- | --- | --- |
| `NM__ELASTICSEARCH__REQUEST_TIMEOUT_SECONDS` | 整数，秒 | `30` | 单次请求超时，必须大于 0 |
| `NM__ELASTICSEARCH__POLL_INTERVAL_MS` | 整数，毫秒 | `500` | 后台队列轮询间隔，100–60000 |
| `NM__ELASTICSEARCH__BULK_BATCH_SIZE` | 整数 | `500` | Bulk 批量操作数上限，1–2000 |
| `NM__ELASTICSEARCH__BULK_MAX_CONCURRENCY` | 整数 | `2` | 进程内 Bulk 并发上限，1–32 |
| `NM__ELASTICSEARCH__BULK_MAX_RETRIES` | 整数 | `4` | 暂时失败最大重试次数，0–10 |
| `NM__ELASTICSEARCH__BULK_RETRY_INITIAL_MS` | 整数，毫秒 | `200` | 指数退避初始间隔，10–60000 |
| `NM__ELASTICSEARCH__BULK_TOTAL_TIMEOUT_SECONDS` | 整数，秒 | `25` | 包含排队、请求、退避和重试的总预算，1–300 |
| `NM__ELASTICSEARCH__SCAN_MIGRATION_CONCURRENCY` | 整数 | `4` | PG→ES 历史迁移并发执行数，1–32 |
| `NM__ELASTICSEARCH__SCAN_MIGRATION_PAGE_SIZE` | 整数 | `100` | 迁移调度分页大小，1–10000，不能小于迁移并发数 |
| `NM__ELASTICSEARCH__SCAN_MIGRATION_CHECKPOINT_BATCHES` | 整数 | `100` | 每累计至少该数量的新迁移批次保存进度，必须大于 0 |

这些是启动参数，变更需重建服务端容器。设置迁移参数不会自动触发迁移；需显式运行迁移命令，
见 [Elasticsearch 迁移步骤](ELASTICSEARCH.md#历史-pg--es-迁移)。

### 日志、资源路径与密码哈希

| 环境变量 | 类型 | 容器默认值 | 作用与约束 |
| --- | --- | --- | --- |
| `NM__LOG__DIRECTORY` | 路径字符串 | `/var/log/network-mapping` | 文件日志目录，必须可写，模板已挂载日志卷 |
| `NM__LOG__FILE_NAME` | 字符串 | `server.json` | 日志文件名 |
| `NM__LOG__FILE_ROLLING` | 整数 | `0` | `0` 按天、`1` 按小时、`2` 按分钟，其他 u8 值不滚动；不自动清理旧文件 |
| `NM__LOG__STATUS_DURATION` | 整数，秒 | `5` | 系统资源采样间隔，必须大于 0 |
| `NM__TEMPLATES__TEMPLATES_DIRECTORY` | 路径/Glob 字符串 | `/opt/network-mapping/templates/**/*.html` | HTML 模板匹配路径 |
| `NM__TEMPLATES__TEMPLATES_NAME` | 字符串 | `error.html` | 错误页模板名称 |
| `NM__FRONTEND__DIRECTORY` | 路径字符串 | `/opt/network-mapping/frontend/dist` | 已构建的前端目录，缺失页面或资源返回 404 |
| `NM__MAXMIND__DIRECTORY` | 路径字符串 | `/var/lib/network-mapping/maxmind` | 可选 MMDB 数据目录；缺失时相关 IP 情报字段为空 |
| `NM__SCANNER_DIAGNOSTICS__DIRECTORY` | 路径字符串 | `/var/lib/network-mapping/scanner-diagnostics` | 可写诊断存储；持有独占目录锁，部署限制见[诊断指南](SCANNER_DIAGNOSTICS.md) |
| `NM__PWD_HASH__M` | 整数，MiB | `64` | Argon2id 内存参数，代码换算为 KiB；需满足 Argon2 参数约束 |
| `NM__PWD_HASH__T` | 整数 | `2` | Argon2id 迭代次数，需满足 Argon2 参数约束 |
| `NM__PWD_HASH__P` | 整数 | `2` | Argon2id 并行度，需满足 Argon2 参数约束 |

### pgBackRest 桥接

| 环境变量 | 类型 | 容器默认值 | 作用与约束 |
| --- | --- | --- | --- |
| `NM__BACKUP__ENABLED` | 布尔值 | `false` | 是否启用 Web 备份桥接 |
| `NM__BACKUP__BINARY` | 路径字符串 | `/usr/bin/pgbackrest` | 启用后必须为绝对路径 |
| `NM__BACKUP__STANZA` | 字符串 | `network_mapping` | 非空，仅字母、数字、下划线、连字符 |
| `NM__BACKUP__CONFIG_FILE` | 可选路径字符串 | 未设置 | 使用 pgBackRest 默认查找规则；设置后使用指定配置文件 |
| `NM__BACKUP__RUN_AS_USER` | 可选字符串 | 未设置 | 默认以服务进程用户执行；指定后通过 sudo 切换到有效的非 root 本机账户 |
| `NM__BACKUP__SUDO_BINARY` | 路径字符串 | `/usr/bin/sudo` | 指定 RUN_AS_USER 时使用，必须为绝对路径 |
| `NM__BACKUP__COMMAND_TIMEOUT_SECONDS` | 整数，秒 | `21600` | 命令超时，必须大于 0 |
| `NM__BACKUP__MAX_OUTPUT_BYTES` | 整数，字节 | `1048576` | 命令输出上限，至少 4096 |

默认服务端镜像未安装 pgBackRest 或 sudo，也未挂载 PG 数据与备份仓库。
仅设 `ENABLED=true` 不足以提供可用备份；默认由独立服务或宿主机负责。
如需桥接，先按[备份指南](PGBACKREST_BACKUP.md)准备二进制、配置、账户和访问路径。

## 仅作为数据库初始值的 env 参数

下列参数只在对应数据库运行策略记录缺失时作为种子使用。数据库已有值时，修改 env 并重建容器
也不会覆盖已发布策略；应通过 Web 管理页面修改。启动时仍要求这些值合法。

### 请求日志与监控

| 环境变量 | 类型 | 默认值 | 作用与约束 |
| --- | --- | --- | --- |
| `NM__REQUESTS__ENABLED` | 布尔值 | `true` | 请求日志采集开关 |
| `NM__REQUESTS__RETENTION_DAYS` | 整数，天 | `30` | 保留期，至少 1 |
| `NM__MONITOR__ENABLED` | 布尔值 | `true` | 健康监控总开关 |
| `NM__MONITOR__SLOW_REQUEST_THRESHOLD_MS` | 整数，毫秒 | `3000` | Web 慢请求阈值，必须大于 0 |
| `NM__MONITOR__SERVER_ERROR_ENABLED` | 布尔值 | `true` | 5xx 告警开关 |
| `NM__MONITOR__SLOW_SQL_THRESHOLD_MS` | 整数，毫秒 | `3000` | 慢 SQL 阈值，必须大于 0，依赖 `pg_stat_statements` |
| `NM__MONITOR__SLOW_SQL_CHECK_INTERVAL_SECONDS` | 整数，秒 | `60` | 慢 SQL 检查间隔，1–86400 |
| `NM__MONITOR__ELASTICSEARCH_QUERY_WARNING_THRESHOLD_MS` | 整数，毫秒 | `1000` | ES 查询警告阈值，必须大于 0 |
| `NM__MONITOR__ELASTICSEARCH_QUERY_CRITICAL_THRESHOLD_MS` | 整数，毫秒 | `3000` | ES 查询严重阈值，不小于查询警告阈值 |
| `NM__MONITOR__ELASTICSEARCH_WRITE_WARNING_THRESHOLD_MS` | 整数，毫秒 | `5000` | ES 写入警告阈值，必须大于 0 |
| `NM__MONITOR__ELASTICSEARCH_WRITE_CRITICAL_THRESHOLD_MS` | 整数，毫秒 | `15000` | ES 写入严重阈值，不小于写入警告阈值 |
| `NM__MONITOR__ALERT_COOLDOWN_SECONDS` | 整数，秒 | `300` | 同一告警冷却窗口，必须大于 0 |

监控策略的服务默认规则、操作级规则通过 Web 配置；数据格式与同步规则见
[监控策略](monitoring-policies.md)、[健康告警](HEALTH_ALERT.md)。

### 自动目标生成

| 环境变量 | 类型 | 默认值 | 作用与约束 |
| --- | --- | --- | --- |
| `NM__AUTOMATIC_TARGET__ENABLED` | 布尔值 | `false` | IPv4 周期生成开关；启用需提供 IPv4 授权范围 |
| `NM__AUTOMATIC_TARGET__STRATEGY` | 字符串 | `sequential_subnet` | 接受 `sequential_subnet` 或 `smart_refresh` |
| `NM__AUTOMATIC_TARGET__INTERVAL_SECONDS` | 整数，秒 | `30` | 调度间隔，至少 5 |
| `NM__AUTOMATIC_TARGET__PENDING_LOW_WATERMARK` | 整数 | `2` | IPv4 队列低水位，满足 0 ≤ low ≤ high |
| `NM__AUTOMATIC_TARGET__PENDING_HIGH_WATERMARK` | 整数 | `5` | IPv4 队列高水位，1–100 |
| `NM__AUTOMATIC_TARGET__PRIORITY` | 整数 | `0` | 自动任务优先级，0–4 |
| `NM__AUTOMATIC_TARGET__AUTHORIZED_CIDRS` | JSON 字符串数组 | `[]` | IPv4 授权网段，不允许重叠，不能小于任务网段 |
| `NM__AUTOMATIC_TARGET__EXCLUDED_CIDRS` | JSON 字符串数组 | `[]` | IPv4 排除网段，排除优先 |
| `NM__AUTOMATIC_TARGET__IPV4_TASK_PREFIX` | 整数 | `24` | IPv4 任务网段前缀，0–32 |
| `NM__AUTOMATIC_TARGET__IPV6_ENABLED` | 布尔值 | `false` | IPv6 周期生成开关；启用需提供 IPv6 授权范围 |
| `NM__AUTOMATIC_TARGET__IPV6_AUTHORIZED_CIDRS` | JSON 字符串数组 | `[]` | IPv6 授权网段，不允许重叠，不能小于任务网段；划分后的任务数须能以 128 位游标表示 |
| `NM__AUTOMATIC_TARGET__IPV6_EXCLUDED_CIDRS` | JSON 字符串数组 | `[]` | IPv6 排除网段，排除优先 |
| `NM__AUTOMATIC_TARGET__IPV6_TASK_PREFIX` | 整数 | `120` | IPv6 任务网段前缀，0–128；默认每任务最多 256 个地址 |
| `NM__AUTOMATIC_TARGET__IPV6_PENDING_LOW_WATERMARK` | 整数 | `1` | IPv6 队列低水位，满足 0 ≤ low ≤ high |
| `NM__AUTOMATIC_TARGET__IPV6_PENDING_HIGH_WATERMARK` | 整数 | `2` | IPv6 队列高水位，1–100 |
| `NM__AUTOMATIC_TARGET__COMMON_PORTS` | 字符串 | 见下方端口清单 | 非空端口/范围清单，1–65535，例如 `22,80,443,8000-8100` |
| `NM__AUTOMATIC_TARGET__REPEAT_AFTER_SECONDS` | 整数，秒 | `604800` | 重复刷新间隔，1–315360000 |
| `NM__AUTOMATIC_TARGET__FAILURE_BACKOFF_SECONDS` | 整数，秒 | `300` | 失败退避，30–86400 |
| `NM__AUTOMATIC_TARGET__CHANGE_REFRESH_SECONDS` | 整数，秒 | `3600` | 变化复核间隔，30–86400 |

默认常用端口：

```text
21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,1433,1521,2049,2375,2376,3000,3306,3389,5432,5900,6379,8080,8443,9200,11211,27017
```

首次启动不会额外强制关闭 env 中已启用的自动扫描；启用前核对授权范围。
搜索触发生成的 `automatic_target.search_generation` 暂不支持 env，配置入口见下文。

### DNS 后续任务与分析快照

| 环境变量 | 类型 | 默认值 | 作用与约束 |
| --- | --- | --- | --- |
| `NM__DNS_FOLLOW_UP__ENABLED` | 布尔值 | `false` | 根据 DNS A/AAAA 生成端口任务；启用需提供授权范围 |
| `NM__DNS_FOLLOW_UP__AUTHORIZED_CIDRS` | JSON 字符串数组 | `[]` | IPv4/IPv6 授权范围，同类网段不得重复或重叠 |
| `NM__DNS_FOLLOW_UP__EXCLUDED_CIDRS` | JSON 字符串数组 | `[]` | IPv4/IPv6 排除范围，排除优先，同类网段不得重复或重叠 |
| `NM__DNS_FOLLOW_UP__MAX_TARGETS_PER_TASK` | 整数 | `100` | 每任务最多派生目标数，1–500 |
| `NM__ANALYTICS_SNAPSHOT__MODE` | 字符串 | `realtime` | `realtime` 不运行快照 worker；`shadow` 生成快照；`snapshot` 使用快照读取 |
| `NM__ANALYTICS_SNAPSHOT__INTERVAL_MINUTES` | 整数，分钟 | `30` | 快照间隔，1–1440 |

## Compose 文件设置

下面列出仓库模板中实际使用的设置，路径以 YAML 为准。没有对应 `${…}` 插值的值需直接编辑
Compose 文件或使用覆盖文件；仅在 `.env` 增加 `ES_JAVA_OPTS` 等变量不会自动传入 ES 容器。
Docker Compose 自身的全部通用选项见[官方参考](https://docs.docker.com/reference/compose-file/)。

### 项目与服务端

| YAML 路径 | 当前值 | 用途与修改条件 |
| --- | --- | --- |
| `name` | `network-mapping` | Compose 项目名，也影响默认网络和卷的命名 |
| `services.server.image` | `${SERVER_IMAGE:?…}` | 必填镜像版本或 digest |
| `services.server.env_file` | `./.env` | 相对 Compose 文件目录，向服务端注入环境 |
| `services.server.init` | `true` | 使用容器 init 处理信号与子进程 |
| `services.server.restart` | `unless-stopped` | 自动重启策略 |
| `services.server.user` | `10001:10001` | 非 root 运行；挂载资源需匹配可读/可写权限 |
| `services.server.environment.SERVER_TLS_NAME` | `${SERVER_TLS_NAME:?…}` | 显式提供健康探针的证书域名 |
| `services.server.read_only` | `true` | 根文件系统只读，写入位置需使用卷或 tmpfs |
| `services.server.cap_drop` | `[ALL]` | 丢弃 Linux capabilities |
| `services.server.security_opt` | `[no-new-privileges:true]` | 禁止提升权限 |
| `services.server.ports` | `${SERVER_BIND_ADDRESS:-127.0.0.1}:${SERVER_PUBLISH_PORT:-9999}:${NM__SERVER__PORT:-9999}` | 宿主机地址、发布端口、容器端口 |
| `services.server.volumes` | TLS 只读挂载、`server-data`、`server-logs` | 路径和内容见下方挂载表 |
| `services.server.tmpfs` | `/tmp:rw,noexec,nosuid,size=64m` | 临时目录，容量 64 MiB |
| `services.server.stop_grace_period` | `60s` | 正常停止等待时间 |
| `services.server.depends_on.postgres.condition` | `service_healthy` | 启用本地 PG 时等待健康检查 |
| `services.server.depends_on.postgres.required` | `false` | 允许关闭本地 PG profile |
| `services.server.depends_on.elasticsearch.condition` | `service_healthy` | 启用本地 ES 时等待健康检查 |
| `services.server.depends_on.elasticsearch.required` | `false` | 允许关闭本地 ES profile |
| `services.server.logging.driver` | `json-file` | Docker stdout/stderr 日志驱动 |
| `services.server.logging.options.max-size` | `10m` | 每个 Docker 日志文件上限 |
| `services.server.logging.options.max-file` | `3` | Docker 日志文件保留数量；不控制应用文件日志 |

服务端健康检查来自 Dockerfile：每 30 秒、超时 5 秒、启动宽限 120 秒、连续失败 3 次标记不健康。
使用 `curl`、固定 CA 路径、`SERVER_TLS_NAME` 与 `NM__SERVER__PORT` 检查 HTTPS `/login`。
它验证 TLS 和前端存活，不代表 PG/ES 在运行期间持续就绪。

模板以注释形式提供以下可选覆盖项，使用时按需启用：

| YAML 路径 | 镜像 / Compose 默认行为 | 用途 |
| --- | --- | --- |
| `services.server.command` | 镜像 CMD 为 `["--config-source", "env"]` | 覆盖启动参数；自定义时保留 `--config-source env`，否则程序会回到 file 模式 |
| `services.server.healthcheck` | 使用上述镜像 HEALTHCHECK | 覆盖探针命令、间隔、超时等 |
| `services.server.secrets` / 顶层 `secrets` | 无 | 为 `_FILE` 输入提供文件；服务端、PG 分别声明需要的 Secret |
| `services.server.cpus` / `mem_limit` | 未显式限制 | 按部署容量增加 CPU/内存限制 |

例如只需要详细终端日志时，可在自己的覆盖文件中添加：

```yaml
services:
  server:
    command: ["--config-source", "env", "--verbose"]
```

### PostgreSQL 容器

| YAML 路径 | 当前值 | 用途与修改条件 |
| --- | --- | --- |
| `services.postgres.profiles` | `[local-postgres]` | 本地 PG 开关 |
| `services.postgres.image` | `postgres:18.6-bookworm`，完整 digest 见模板 | 固定 PG 镜像；更换主版本需要匹配数据库升级流程 |
| `services.postgres.restart` | `unless-stopped` | 自动重启策略 |
| `services.postgres.environment.POSTGRES_USER` | `${NM__DATABASE__USERNAME:-network_mapping}` | 初始化角色 |
| `services.postgres.environment.POSTGRES_DB` | `${NM__DATABASE__DB_NAME:-network_mapping}` | 初始化数据库 |
| `services.postgres.environment.POSTGRES_PASSWORD` | `${NM__DATABASE__PASSWORD:?…}` | 初始化角色密码，必填；已有 PG 数据不重新初始化 |
| `services.postgres.volumes` | `postgres-data:/var/lib/postgresql` | PG 18 数据卷挂载点 |
| `services.postgres.healthcheck.test` | `pg_isready -h 127.0.0.1 -t 3 -U "$POSTGRES_USER" -d "$POSTGRES_DB"` | TCP 就绪检查，避开初始化的临时 Unix socket 实例；YAML 用 `$$` 延后到容器解析 |
| `services.postgres.healthcheck.interval` | `10s` | 探测间隔 |
| `services.postgres.healthcheck.timeout` | `5s` | 探测超时 |
| `services.postgres.healthcheck.retries` | `20` | 连续失败次数 |

模板没有为 PG 发布宿主机端口。

### Elasticsearch 容器

| YAML 路径 | 当前值 | 用途与修改条件 |
| --- | --- | --- |
| `services.elasticsearch.profiles` | `[local-elasticsearch]` | 本地 ES 开关 |
| `services.elasticsearch.image` | `docker.elastic.co/elasticsearch/elasticsearch:9.5.0`，完整 digest 见模板 | 固定 ES 镜像，服务端仅支持正式 9.5.x |
| `services.elasticsearch.restart` | `unless-stopped` | 自动重启策略 |
| `services.elasticsearch.environment.discovery.type` | `single-node` | 单节点模式 |
| `services.elasticsearch.environment.xpack.security.enabled` | 字符串 `false` | 隔离单机示例关闭认证；启用认证/TLS 时同步修改服务端连接参数和健康检查 |
| `services.elasticsearch.environment.ES_JAVA_OPTS` | `-Xms1g -Xmx1g` | JVM 初始/最大堆内存，直接在 YAML 调整 |
| `services.elasticsearch.volumes` | `elasticsearch-data:/usr/share/elasticsearch/data` | ES 持久化目录 |
| `services.elasticsearch.healthcheck.test` | HTTP 集群健康检查，完整命令见模板 | 等待 yellow/green、无初始化分片且 `timed_out=false`；curl 上限 7 秒，ES 等待上限 5 秒 |
| `services.elasticsearch.healthcheck.interval` | `10s` | 探测间隔 |
| `services.elasticsearch.healthcheck.timeout` | `10s` | 探测超时 |
| `services.elasticsearch.healthcheck.retries` | `30` | 连续失败次数 |
| `services.elasticsearch.ulimits.nofile.soft` | `65536` | 软文件描述符上限 |
| `services.elasticsearch.ulimits.nofile.hard` | `65536` | 硬文件描述符上限 |

模板没有为 ES 发布宿主机端口。宿主机 `vm.max_map_count` 等系统前提由宿主机管理员配置，
不属于 `NM__…` 参数；部署示例见 [Docker 指南](DOCKER.md#compose-示例)。

### 卷、TLS 与可选 SQL 挂载

| 来源 / 顶层声明 | 容器目标路径 | 用途 |
| --- | --- | --- |
| `./runtime/tls`（相对 `docker/`） | `/etc/network-mapping/tls`，只读 | `cert.pem`、`key.pem`、`ca.pem` 及可选 ES CA |
| `volumes.server-data` | `/var/lib/network-mapping` | 可选 MaxMind 与扫描器诊断数据 |
| `volumes.server-logs` | `/var/log/network-mapping` | 应用 JSON 文件日志 |
| `volumes.postgres-data` | `/var/lib/postgresql` | PostgreSQL 数据 |
| `volumes.elasticsearch-data` | `/usr/share/elasticsearch/data` | ES 数据 |

命名卷首次创建沿用镜像目录属主；已有卷或替换成宿主机绑定目录后需检查 UID/GID。
不要通过 `down -v` 清空生产数据。TLS 私钥和 `_FILE` 文件需可被读取，应用日志、诊断目录需可写。

`compose.sql.example.yml` 仅覆盖 `services.server.volumes` 中的自定义 SQL 挂载条目：

| SQL 覆盖项 | 当前值 | 作用 |
| --- | --- | --- |
| `services.server.volumes[].type` | `bind` | 绑定已有宿主机目录 |
| `services.server.volumes[].source` | `${SERVER_SQL_DIRECTORY:?…}` | 自定义 SQL 目录，必填 |
| `services.server.volumes[].target` | `/etc/network-mapping/sql` | 容器 SQL 挂载目录 |
| `services.server.volumes[].read_only` | `true` | 只读 |
| `services.server.volumes[].bind.create_host_path` | `false` | 源目录不存在时失败，不自动创建空目录 |

启用覆盖文件后，还需按需要设置 `NM__DATABASE__INIT_DATABASE_FILE` 和/或
`NM__DATABASE__SQL_FILE_PATH`；挂载本身不会改用自定义 SQL，也不会额外执行所有迁移脚本。

```sh
docker compose --env-file docker/.env -f docker/compose.example.yml \
  -f docker/compose.sql.example.yml config --quiet
docker compose --env-file docker/.env -f docker/compose.example.yml \
  -f docker/compose.sql.example.yml up -d --force-recreate
```

## 有文件配置或 Web 入口、暂不支持 env 的字段

以下字段存在于配置类型中，但未纳入当前 env 白名单或内置配置叶字段。
将名称直接转成 `NM__…` 会报未知字段，不能依据 TOML 支持情况推断 env 支持。
需要文件配置时可通过只读挂载 TOML，并显式设置
`command: ["--config-source", "file", "--config", "/etc/network-mapping/config.toml"]`。
file 模式不再用 `NM__…` 覆盖 TOML；Compose 端口映射和探针环境仍需与 TOML 的监听端口保持一致。

| TOML 字段 | 类型 / 默认值 | 作用与配置入口 |
| --- | --- | --- |
| `elasticsearch.projection_page_size` | 整数，`1000` | 投影页大小，1–2000 |
| `elasticsearch.projection_bulk_max_bytes` | 整数，`5242880` 字节 | 投影 Bulk 字节上限，65536–16777216 |
| `elasticsearch.projection_pages_per_tick` | 整数，`4` | 每调度片段最多页数，1–32 |
| `elasticsearch.projection_lease_seconds` | 整数，`120` 秒 | 发布租约，10–3600 秒 |
| `elasticsearch.projection_heartbeat_seconds` | 整数，`20` 秒 | 续租周期，必须大于 0 且不超过租约三分之一；见[写入指南](WRITE_SPEED.md) |
| `scanner_diagnostics.enabled` | 布尔值，`true` | 诊断功能开关 |
| `scanner_diagnostics.log_retention_days` | 整数，`30` 天 | 诊断日志保留，1–3650 |
| `scanner_diagnostics.error_retention_days` | 整数，`90` 天 | 错误保留，1–3650 |
| `scanner_diagnostics.max_storage_bytes` | 整数，`10737418240` 字节 | 诊断存储上限，至少 1073741824 字节 |
| `scanner_diagnostics.auto_collect` | 布尔值，`false` | 自动采集开关；见[诊断指南](SCANNER_DIAGNOSTICS.md) |
| `report_renderer.releases_directory` | 可选路径，未设置 | 外部报表渲染制品目录；见[模块实现](MODULE_RUNTIME_IMPLEMENTATION.md) |
| `report_mail.public_base_url` | 字符串，空 | 报告外部 HTTPS 地址；文件种子或 Web「报告邮件」 |
| `report_mail.remote_images_enabled` | 布尔值，`false` | 报告远程图片开关，开启前需提供外部地址 |
| `report_mail.image_lifetime_days` | 整数，`365` 天 | 1–3650；文件种子或 Web「报告邮件」 |
| `report_mail.scanner_row_limit` | 整数，`20` | 1–100；见[报告邮件](reports.md) |
| `automatic_target.search_generation.enabled` | 布尔值，`false` | 搜索触发目标生成；文件种子或 Web「搜索触发更新」 |
| `automatic_target.search_generation.stale_after_days` | 整数，`7` 天 | 数据有效期，1–3650 |
| `automatic_target.search_generation.cooldown_minutes` | 整数，`1440` 分钟 | 生成冷却期，1–525600 |
| `automatic_target.search_generation.max_pending_tasks` | 整数，`100` | 待执行任务上限，1–10000 |
| `automatic_target.search_generation.per_user_hourly_limit` | 整数，`20` | 每用户小时额度，1–10000 |
| `automatic_target.search_generation.domain_enabled` | 布尔值，`false` | 域名搜索生成开关 |
| `automatic_target.search_generation.authorized_domains` | 字符串数组，`[]` | 精确授权域及其子域；开启域名生成需提供，见[搜索触发更新](SEARCH_TARGET_GENERATION.md) |
| `monitor.service_defaults` | 对象，`{}` | 按服务设置规则；文件种子或 Web「健康监控」 |
| `monitor.operation_rules` | 对象数组，`[]` | 按操作覆盖规则；结构和校验见[监控策略](monitoring-policies.md) |
| `email_config.host` | 字符串，整个段默认未设置 | SMTP 主机；文件部署的邮件初始值，也可通过 Web 邮件设置管理 |
| `email_config.account_username` | 字符串，整个段默认未设置 | SMTP 账户，使用文件段时需提供 |
| `email_config.account_password` | 字符串，整个段默认未设置 | SMTP 密钥，使用文件段时需提供；见[部署指南](DEPLOYMENT.md) |

`monitor.service_defaults` 以 `web_api`、`postgresql`、`elasticsearch_query`、
`elasticsearch_write` 为可选键。未配置时沿用前述基础阈值；每条显式规则包含以下字段，
`monitor.operation_rules[].rule` 使用相同结构：

| 规则字段 | 类型 | 作用与约束 |
| --- | --- | --- |
| `enabled` | 布尔值，必填 | 是否启用该服务/操作的慢检测 |
| `warning_threshold_ms` | 整数，必填 | 警告阈值，1–86400000 毫秒 |
| `critical_threshold_ms` | 可选整数，默认未设置 | 严重阈值，不小于警告阈值且不超过 86400000 毫秒；省略表示仅警告 |
| `cooldown_seconds` | 整数，必填 | 冷却时间，1–604800 秒 |

`monitor.operation_rules` 每项还需提供 `service`（上述服务名之一）和 `operation`
（操作目录中的稳定标识），以及 `rule` 对象；默认为空数组。通过 Web 操作目录选择标识，
无需猜测 HTTP 路由或 SQL 标识。规则不支持转换成 `NM__…` 输入。

Web 独立管理的系统业务时区、DNS 服务器、扫描器健康策略、统计缓存、智能扫描分配、
开放平台和扫描器运行参数，不是容器启动 env 项。分别见
[运行时配置](RUNTIME_CONFIGURATION.md)、[系统时间](SYSTEM_TIME.md)、[DNS 测绘](DNS_MAPPING.md)、
[监控策略](monitoring-policies.md)、[统计分析](STATISTICS.md)、[智能扫描](SMART_SCANNING.md)、
[开放平台管理](OPEN_API_MANAGEMENT.md) 和扫描器配置页面。

## 配置文档维护与覆盖检查

新增、删除或修改配置时，同步修改本文的类型、默认值、限制和生效方式，并将全部字段同步到
`docker/.env.example` 或 `docker/config.example.toml`；可选项使用注释，部署步骤变化同步更新 `DOCKER.md`。
环境变量名称的覆盖检查以 `src/public_config_fields.txt`、`docker/config.example.toml`
叶字段及 `src/config_env.rs` 的可选部署字段为来源，也核对 Compose 插值变量和 env 示例变量是否有文档，
并校验内置非密钥默认值与参数表一致。
检查还要求 env 示例覆盖全部基础变量、默认示例值与文档一致，TOML 示例覆盖 env、仅文件和兼容字段，
且所有可选 TOML 示例在展开后语法有效。
该检查不读取实际部署 `.env` 或根目录 `config.toml`，不导出用户配置。

在仓库根目录执行：

```sh
python3 -m unittest discover -s docker -p 'test_configuration_docs.py'
python3 -m unittest discover -s docker -p 'test_*.py'
```

覆盖检查用于防止新增字段漏写或旧名称残留；参数语义、默认值和兼容限制仍需在代码审查时核对。
