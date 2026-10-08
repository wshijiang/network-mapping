# 服务端部署指南

[项目首页](../README.md) · [文档中心](README.md)

容器镜像、Compose 与 GitHub 自动构建见 [Docker 部署指南](DOCKER.md)。

本文面向 Linux 部署，覆盖首次安装、启动验收和服务托管。已有 PG 扫描结果的升级必须先阅读[Elasticsearch 存储与迁移](ELASTICSEARCH.md)，不能按空库流程直接切换。

[准备环境](#准备环境) · [文件布局](#文件布局) · [数据库](#数据库) · [配置](#配置) · [首次启动](#首次启动) · [服务托管](#服务托管) · [验收与排障](#验收与排障)

## 准备环境

| 依赖 | 要求 |
| --- | --- |
| 服务端二进制 | 与目标系统架构、运行库兼容；源码构建使用 Rust stable，edition 2024 |
| 编译工具 | 源码构建需要 C 编译工具、OpenSSL 开发库和 pkg-config；CI 使用 Ubuntu 24.04 |
| PostgreSQL | 预先创建数据库和登录角色；角色需要执行初始化 SQL 中的建表、索引及升级 DDL |
| Elasticsearch | 支持正式版 9.5.x，服务端必须可访问并有创建/管理所需索引及读写权限 |
| 前端 | 已构建的 `dist/`，包含 `index.html`、`login.html`、`search.html`、`asset.html` 和 `assets/` |
| HTTPS | PEM 证书链与匹配私钥，域名与客户端访问地址一致 |

源码构建命令在对应仓库目录执行：

```sh
# network-mapping/
cargo build --locked --release

# network-mapping-vue/
pnpm install --frozen-lockfile
pnpm build
```

前端要求 Node `^20.19.0 || >=22.12.0`。仅安装服务端发布包时无需 Rust 或 Node；仍需准备数据库、ES、TLS 和与二进制匹配的运行库。发布包中的 `BUILD-INFO` 用于核对服务端与前端提交；校验随包提供的 SHA-256 文件后再解压。

## 文件布局

以下路径是部署示例，按实际环境调整。服务用户示例为 `network-mapping`，需要预先创建。

```text
/opt/network-mapping/
├── network-mapping/
│   ├── network_mapping_server
│   ├── source/database/       init.sql、查询 SQL 和迁移文件
│   ├── source/maxmind/        可选 MMDB 文件
│   └── templates/            服务端模板及邮件模板
└── network-mapping-vue/
    └── dist/                 前端构建产物
/etc/network-mapping/
├── config.toml
└── ssl/
    ├── cert.pem
    └── key.pem
/var/log/network-mapping/      服务端日志
/var/lib/network-mapping/
└── scanner-diagnostics/      诊断快照与采集文件
```

源码部署需从 `target/release/` 复制二进制，并保留运行 SQL、模板和前端产物。发布包已包含这些资源；`config.example.toml` 是待配置模板。

### 路径解析规则

| 配置项 | 相对路径基准 |
| --- | --- |
| `tls.certificate_chain_file`、`tls.private_key_file` | 配置文件所在目录 |
| `frontend.directory`、`maxmind.directory` | 配置文件所在目录 |
| `elasticsearch.ca_certificate_file`、`scanner_diagnostics.directory` | 配置文件所在目录 |
| backup 的可配置本机路径 | 配置文件所在目录，详见[备份指南](PGBACKREST_BACKUP.md) |
| `database.init_database_file`、`database.sql_file_path` | 进程工作目录 |
| `templates.templates_directory`、`log.directory` | 进程工作目录 |

使用绝对路径可以避免换启动目录后找不到文件。`--config` 只指定配置文件，不会自动切换工作目录。

服务用户需要读取配置、证书私钥、SQL、模板和前端资源，以及写入日志和诊断目录。配置与私钥应只允许管理员和服务用户读取；代码目录及前端产物无需开放写权限。

## 数据库

以下示例假设 PostgreSQL 已安装并运行，且可通过本机 `postgres` 系统用户执行管理命令。远程或托管数据库由数据库管理员完成等价操作。

```sh
sudo -u postgres createuser --pwprompt --no-superuser --no-createdb --no-createrole network_mapping
sudo -u postgres createdb --owner=network_mapping network_mapping
```

输入应用角色密码，然后测试实际 TCP 登录路径：

```sh
psql -h 127.0.0.1 -p 5432 -U network_mapping -d network_mapping -W \
  -c 'SELECT current_user, current_database();'
```

创建角色和数据库的参数见 PostgreSQL 官方 [createuser](https://www.postgresql.org/docs/18/app-createuser.html) 与 [createdb](https://www.postgresql.org/docs/18/app-createdb.html) 文档。这里引用工具语法，不将 PostgreSQL 18 指定为项目最低版本。

服务端连接到**已存在的数据库**，每次启动执行 `database.init_database_file` 及内置补充迁移。它不会创建数据库或数据库角色。新库应用角色可作为数据库/schema 所有者；已有库必须检查表和 schema 所有权，只有 SELECT/INSERT 权限不足以执行启动升级。

`pg_hba.conf` 应允许配置的用户名、数据库和实际连接来源使用密码认证。

**当前数据库连接使用 `tokio_postgres::NoTls`。** `database.tls = true` 不会启用 PostgreSQL TLS；本指南示例采用本机连接。跨主机部署需要受保护的连接链路，不能用这个字段代替加密连接。

慢 SQL 告警依赖额外启用 `pg_stat_statements`，不是基本启动前提；配置步骤见[健康告警](HEALTH_ALERT.md)。

## 配置

复制仓库 `config.toml` 或发布包 `config.example.toml` 到 `/etc/network-mapping/config.toml`，保留未展示的必填配置段，再修改下列字段。

**当前随仓库提供的模板不能直接启动。** 它含空密钥、空数据库凭据，以及已不支持的 `scan_storage = "postgres"`、关闭 ES 和开启 PG 回退的旧值。需替换为下述 ES 设置，并删除无用途的旧 `elasticsearch.index`。

### 监听、TLS 与长期密钥

分别生成两个不同用途的密钥：

```sh
# server.encrypt_key：32 字节的 Base64，通常为 44 个字符
openssl rand -base64 32

# security.scanner_token_pepper：32 字节的十六进制字符串
openssl rand -hex 32
```

```toml
[server]
host = "127.0.0.1"
port = 9999
encrypt_key = "替换为上面生成的 Base64 密钥"
max_body_size = 67108864

[tls]
certificate_chain_file = "/etc/network-mapping/ssl/cert.pem"
private_key_file = "/etc/network-mapping/ssl/key.pem"

[security]
scanner_token_pepper = "替换为上面生成的十六进制 Pepper"
```

`encrypt_key` 用于系统加密数据，启动检查要求长度为 44 个字符；应使用生成结果并长期保留。`scanner_token_pepper` 至少 32 个字符，变更会使已有扫描器令牌失效。备份与恢复时必须保持密钥一致。

TLS 加载会检查文件可读性和证书/私钥匹配。扫描器和浏览器需信任证书链；私有 CA 应安装到客户端信任链，不应以关闭证书校验作为部署完成的标准。

`127.0.0.1` 适用于同机代理入口。直接向外提供服务时修改监听地址，并按实际需要放行该 HTTPS 端口。服务端自身仍使用 HTTPS，反向代理上游也应使用 HTTPS；可信代理的来源 IP 设置见[双栈与可信代理](DUAL_STACK_SCANNING.md)。

### PostgreSQL 与运行目录

```toml
[database]
host = "127.0.0.1"
port = 5432
username = "network_mapping"
password = "替换为应用角色密码"
db_name = "network_mapping"
pool_max_size = 10
pool_wait_timeout_ms = 2000
pool_create_timeout_ms = 5000
pool_recycle_timeout_ms = 3000
tls = false
init_database_file = "/opt/network-mapping/network-mapping/source/database/init.sql"
sql_file_path = "/opt/network-mapping/network-mapping/source/database/"

[templates]
templates_directory = "/opt/network-mapping/network-mapping/templates/**/*.html"
templates_name = "error.html"

[log]
directory = "/var/log/network-mapping"
file_name = "server.json"
file_rolling = 0
status_duration = 5

[frontend]
directory = "/opt/network-mapping/network-mapping-vue/dist"

[scanner_diagnostics]
directory = "/var/lib/network-mapping/scanner-diagnostics"
```

JSON 通用请求体默认上限为 64 MiB；代理入口需要容纳相同业务请求。诊断实时事件单独限 8 MiB，日志分块最多 4 MiB，详见[诊断协议](SCANNER_DIAGNOSTICS.md#固定目录与文件语义)。

### Elasticsearch

```toml
[elasticsearch]
enabled = true
read_enabled = true
scan_storage = "elasticsearch"
fallback_to_postgres = false
url = "https://127.0.0.1:9200"
expected_version = "9.5.x"
scan_number_of_replicas = 0
write_wait_for_active_shards = "1"
# 私有 CA：填写实际 CA 文件路径。
# ca_certificate_file = "/etc/network-mapping/ssl/es-ca.pem"
# 认证方式二选一：api_key 或 username/password。
# api_key = "替换为有效 API Key"
```

此副本设置适用于单节点验证环境。生产配置副本数与等待分片数应匹配集群节点和故障域；`write_wait_for_active_shards = "all"` 在副本不可用时可能阻止写入。认证不要放进 URL。索引名称默认值、权限需求、迁移与恢复流程见[ES 存储指南](ELASTICSEARCH.md)。

首次空库启动初始化 ES 目标；已有数据时会校验索引和回执关联，缺失索引不能当作空库重新运行。

### 运行策略与可选功能

首次上线保持自动目标的 IPv4/IPv6 开关及 `dns_follow_up.enabled` 关闭。确认授权范围、节点能力和数据上传后，再由管理员发布运行策略。

请求日志、健康监控、自动目标、DNS 后续任务和分析快照的 TOML 值仅在对应数据库记录缺失时初始化；已有记录以数据库为准。修改文件并重启不会覆盖已发布值，详见[运行时配置](RUNTIME_CONFIGURATION.md)。

MaxMind 是可选依赖：将 `GeoLite2-City.mmdb`、`GeoLite2-Country.mmdb` 和 `GeoLite2-ASN.mmdb` 放入 `maxmind.directory`，例如 `/opt/network-mapping/network-mapping/source/maxmind`。文件缺失不阻止启动，情报字段保持为空；更新后需重启。历史 PG 结果的情报刷新仅能与 `--migrate-scan-data-to-elasticsearch` 一起运行，见[ES 迁移](ELASTICSEARCH.md)。

SMTP、平台报告、pgBackRest 备份等功能按需配置，分别见[健康告警](HEALTH_ALERT.md)、[报告](reports.md)和[备份指南](PGBACKREST_BACKUP.md)。

## 首次启动

从部署工作目录，以将来运行服务的同一用户前台启动：

```sh
cd /opt/network-mapping/network-mapping
./network_mapping_server --config /etc/network-mapping/config.toml
```

启动会检查配置、连接 PG、执行初始化 SQL、校验 ES 存储及加载运行策略，再加载 TLS 并绑定监听端口。前端文件缺失只产生警告，服务可能仍能启动，因此需要单独验收页面。

数据库不存在管理员时，正常启动自动创建默认管理员，用户名通常为 `admin`，随机密码一次性输出到终端。`NM_DEFAULT_ADMIN_USERNAME` 可指定默认名前缀；用户名已被占用时可能带后缀，以实际输出为准。凭据不写入滚动 JSON 日志；首次前台启动便于保存凭据，登录后立即改密。

也可使用 CLI 在已有初始化结构中创建或管理账号：

```sh
./network_mapping_server --config /etc/network-mapping/config.toml user create operator --role admin
./network_mapping_server --config /etc/network-mapping/config.toml user password set admin
```

密码交互输入。若自动管理员名称不同，替换最后一个用户名。CLI 同样加载并校验配置，详见[用户管理](USER_MANAGEMENT_CLI.md)。

管理员登录控制台后创建扫描器，保存一次性注册 ID 和 Token。节点配置服务端主机、端口和可信 TLS 后注册，确认心跳在线，再对一个已授权的小范围目标执行首个任务。节点部署与持久化目录见[扫描器项目](https://github.com/wshijiang/Network-Mapping-Scanner)。

## 服务托管

首次验收通过后，再交由 systemd。仓库中的 `network-mapping-server.service` 含占位用户和路径，不能原样安装；其 `ExecStart=./network_mapping_server` 应替换为绝对路径。以下示例适用于上面的目录布局：

```ini
# /etc/systemd/system/network-mapping-server.service
[Unit]
Description=Network Mapping Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=network-mapping
Group=network-mapping
WorkingDirectory=/opt/network-mapping/network-mapping
ExecStart=/opt/network-mapping/network-mapping/network_mapping_server --config /etc/network-mapping/config.toml
Restart=on-failure
RestartSec=5
UMask=0027

[Install]
WantedBy=multi-user.target
```

数据库可在本机或远端，因此示例不硬编码 `Requires=postgresql.service`。依赖尚未就绪时进程失败并按配置重试；这不代表数据库和 ES 已完成初始化。路径与执行规则见 systemd 官方 [systemd.service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html) 和 [systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)。

以系统管理员身份安装 unit 后执行：

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now network-mapping-server
sudo systemctl status network-mapping-server
sudo journalctl -u network-mapping-server -n 100 --no-pager
```

修改 unit 后先 `daemon-reload` 再重启；修改启动配置后需重启服务。命令含义见 [systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html)。首次自动管理员若在 systemd 下创建，标准输出可能进入 journal，应按凭据管理要求限制日志访问。

## 验收与排障

### 上线验收

- 进程持续运行，日志中无配置、PG 初始化、ES 切换检查或 TLS 加载错误。
- 通过实际 HTTPS 域名访问 `/login`，证书可信且匹配主机名，页面与静态资源完整加载。
- 未登录 API 请求得到 401；登录后控制台、搜索和资产页面正常，未知路径和缺失资源返回 404。
- 扫描器在线，所需 profile 与地址族就绪；首个授权任务完成并能在搜索中查到结果。
- 发布运行配置后读回值与 revision，确认保存生效。多实例的其他进程按当前同步限制处理。
- 保存数据库配置、长期密钥和 TLS 的备份；生产数据恢复需同时考虑 PG 与 ES，不能只备份一个存储。

### 常见问题

| 现象 | 检查方向 |
| --- | --- |
| TOML 解析失败或提示 `postgres` 不支持 | 将旧 ES 存储模式改为 `elasticsearch`，保留完整必填配置段 |
| 密钥长度错误 | `encrypt_key` 使用 44 字符 Base64；Pepper 使用独立随机值且至少 32 字符 |
| PG 连接或初始化失败 | 实际 TCP 密码认证、库名、角色/schema 所有权、SQL 文件路径和读取权限 |
| ES 校验失败 | 版本、认证、CA、索引权限及已有回执关联；禁止用空索引掩盖丢失数据 |
| TLS 加载失败 | PEM 文件、私钥与证书匹配、服务用户权限 |
| 页面或资源 404 | `frontend.directory` 下四个入口和 `assets/` 是否来自完整构建 |
| systemd 反复重启 | 绝对 ExecStart、用户、WorkingDirectory、文件权限及 journal 中首个错误 |
| 改 TOML 后策略不变 | 该策略可能已入库，应在运行时配置页发布 |
| 扫描器在线但无法领任务 | 本地引擎检查、`accepting_tasks`、地址族/profile 能力、维护状态及授权范围 |

终端默认显示启动摘要、警告和错误。排障可增加 `--verbose`；需要 DEBUG 时使用 `--verbose --debug-model`，或设置 `RUST_LOG`。`--verbose` 不改变滚动 JSON 日志内容或级别。扫描器错误与日志采集见[远程诊断](SCANNER_DIAGNOSTICS.md)。
