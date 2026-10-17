# Network Mapping

**分布式网络测绘与资产管理平台**

基于 Rust 与 Vue 构建，提供 IPv4/IPv6 端口发现、服务识别、DNS 测绘、漏洞扫描与资产搜索。服务端负责调度、数据管理和运维，扫描节点执行任务，Web 控制台提供统一操作界面。

[快速开始](#快速开始) · [部署指南](docs/DEPLOYMENT.md) · [功能指南](docs/FEATURES.md) · [文档中心](docs/README.md)

## 核心能力

| 领域 | 能力 |
| --- | --- |
| 扫描编排 | 多节点调度、独立执行实例、IPv4/IPv6 能力匹配、DNS 后续任务 |
| 资产检索 | 组合表达式、跨端点查询、地理信息、资产标签、操作系统线索 |
| 扫描流水线 | 端口发现、服务识别、DNS 解析、Nuclei 漏洞检测 |
| 数据管理 | Elasticsearch 扫描结果存储、PostgreSQL 业务数据与分析快照 |
| 运维治理 | 审计与请求日志、健康告警、扫描器远程诊断、备份、周报/月报 |

## 系统架构

```mermaid
flowchart LR
    UI[Web 控制台] -->|HTTPS API| Server[Rust 服务端]
    Scanner[扫描节点] -->|心跳 / 领取任务 / 上传结果| Server
    Server --> PG[(PostgreSQL)]
    Server --> ES[(Elasticsearch)]
    Scanner --> Engines[masscan / zgrab2 / DNS / Nuclei]
```

三个组件独立维护、独立版本管理：

| 仓库 | 职责 | 技术 |
| --- | --- | --- |
| **本仓库** | API、调度、数据存储、页面托管与运维 | Rust / Actix Web |
| [Network-Mapping-Scanner](https://github.com/wshijiang/Network-Mapping-Scanner) | 扫描任务执行、结果上传与节点诊断 | Rust / Tokio |
| [network-mapping-vue](https://github.com/wshijiang/network-mapping-vue) | Web 控制台、搜索与资产展示 | Vue / Vite |

## 快速开始

标准容器环境可直接按 [Docker 部署指南](docs/DOCKER.md#准备运行配置)安装，镜像包含前端与 SQL，可选自动启动本地 PG/ES。以下为源码运行步骤；发布归档与 systemd 托管、两端联调及升级恢复见[部署指南](docs/DEPLOYMENT.md)。

### 1. 准备环境

| 依赖 | 用途 |
| --- | --- |
| Rust / Cargo | 编译服务端；项目使用 edition 2024 |
| PostgreSQL | 用户、权限、任务、配置、上传回执和分析快照 |
| Elasticsearch 9.5.x | 必需的扫描结果存储与搜索服务 |
| TLS 证书与私钥 | 启用服务端 TLS 时需要（默认开启） |
| 前端 `dist/` | 登录、控制台、搜索和资产页面 |

### 2. 获取并编译

```sh
git clone https://github.com/wshijiang/network-mapping.git
cd network-mapping
cargo build --locked --release
```

### 3. 配置并启动

编辑 `config.toml` 中的数据库连接、Elasticsearch、TLS、前端目录及 `security.scanner_token_pepper`。详细字段和路径规则见[部署指南](docs/DEPLOYMENT.md)。Pepper 应长期固定，修改后已有扫描器令牌会失效。

`tls.enabled` 默认 `true`，旧配置继续使用 HTTPS。需要本地 HTTP 或由同机代理终止 TLS 时，设置 `tls.enabled = false`，同时将 `server.host` 改为 `127.0.0.1` 或 `::1`；此时可省略证书和私钥。非回环绑定会拒绝启动，完整示例见[本地 HTTP](docs/DEPLOYMENT.md#本地-http)。

Docker 默认使用 bridge 网络和 TLS。连接宿主机数据库可使用内置的 `host.docker.internal` 映射；Linux 上需要回环 HTTP 与宿主机代理/数据库时，使用独立的 `docker/compose.host.example.yml`。配置和迁移步骤见[Docker 部署指南](docs/DOCKER.md)。

无需登录的 `GET /healthz`（也支持 `HEAD`）仅返回健康状态码：就绪为 `200`，未就绪为 `503`，响应正文为空，不返回错误详情。检查 PostgreSQL 与 Elasticsearch 的可用性，详见[健康检查 API](docs/DEPLOYMENT.md#健康检查-api)。

```sh
./target/release/network_mapping_server --config config.toml
```

空库首次正常启动会自动创建管理员并在终端显示随机密码；保存凭据，打开配置的 HTTPS 地址登录并改密，再创建和注册扫描器。账号管理见[用户管理 CLI](docs/USER_MANAGEMENT_CLI.md)，完整启动验收见[部署指南](docs/DEPLOYMENT.md#首次启动)。

## 配置与使用

- **启动配置**：连接、证书、密钥和本机路径来自 `config.toml`。
- **运行策略**：数据库已发布值为准；对应 TOML 段仅在记录缺失时初始化。保存接口为 `POST /api/config/runtime/{namespace}`。
- **首次扫描**：确认授权范围和节点能力，再选择“全部”“仅端口”“服务识别”或“仅 DNS”。

首次初始化会沿用 TOML 的扫描启用状态；多实例配置同步存在限制。完整说明见[运行时配置](docs/RUNTIME_CONFIGURATION.md)和[功能指南](docs/FEATURES.md)。

## 模块化与报表渲染更新

服务端按领域组织业务代码；模块运行时和纯邮件渲染是独立 Cargo workspace 包。报表邮件渲染支持内置实现或独立 worker，并可通过管理员接口切换版本。构建、制品布局和生效边界见[模块实现与热更新](docs/MODULE_RUNTIME_IMPLEMENTATION.md)。

## 开发与验证

从本仓库目录运行：

```sh
cargo fmt --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo build --locked --release
```

数据库与服务端集成检查需要有效配置及相应基础设施。修改接口或数据协议时，同步核对扫描器和前端；升级依赖后复核 `source/open_source_projects.json`。

## 文档导航

| 我想了解 | 阅读入口 |
| --- | --- |
| 安装、证书与页面托管 | [部署指南](docs/DEPLOYMENT.md) |
| 镜像、Compose 与容器升级 | [Docker 部署](docs/DOCKER.md) |
| 搜索、扫描模式与自动任务 | [功能指南](docs/FEATURES.md) |
| API、存储、备份与排障 | [文档中心](docs/README.md) |
| 可选登录人机验证 | [Turnstile 部署与排障](docs/HUMAN_VERIFICATION.md) |

## 参与贡献

问题反馈请附组件版本、复现步骤和脱敏日志。提交改动时说明行为变化、配置或 schema 影响及验证结果；界面变更附截图。不要提交真实凭据、运行日志或环境专用配置。

## 许可证

本项目采用 [MIT License](LICENSE)。第三方依赖遵循各自许可证。

## Docker 构建与部署

支持 AMD64/ARM64 镜像自动构建，分支与 PR 验证不发布，正式版本经具体授权后推送 GHCR。
镜像内容、配置、持久化、GitHub 设置及验收见 [Docker 部署指南](docs/DOCKER.md)。
全部环境变量及 Compose 设置见 [Docker 完整配置参考](docs/DOCKER_CONFIGURATION.md)。
