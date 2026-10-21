# Network Mapping 服务端文档

[项目首页](../README.md) · [文档维护与本地预览](DOCUMENTATION.md)

服务端负责扫描调度、资产查询、数据分析、开放平台及系统运维。文档按实际任务分类，左侧导航与下方专题索引保持一致。

## 版本更新

| 文档 | 内容 |
| --- | --- |
| [更新日志](CHANGELOG.md) | 自上次发布 tag 以来的服务端变动、固定比较范围与升级兼容注意 |

## 从这里开始

| 当前任务 | 建议阅读顺序 |
| --- | --- |
| 首次搭建完整系统 | [部署选型与安装顺序](DEPLOYMENT.md) → [Docker 部署](DOCKER.md)或原生安装 → [启动配置检查](CONFIG_CHECK.md) → 部署扫描器并完成联调 |
| 使用控制台与资产搜索 | [功能概览](FEATURES.md) → [搜索语法](SEARCH_SYNTAX.md) → [统计分析](STATISTICS.md)与[报告](reports.md) |
| 配置扫描与自动目标 | [扫描流水线](SCAN_PIPELINE.md) → [双栈与自动目标](DUAL_STACK_SCANNING.md) → [智能分配](SMART_SCANNING.md) |
| 处理运行故障 | [运行时配置](RUNTIME_CONFIGURATION.md) → [健康告警](HEALTH_ALERT.md) → [扫描器诊断](SCANNER_DIAGNOSTICS.md)或[请求日志](REQUEST_LOG.md) |
| 接入外部 API | [API 接入](OPEN_API.md) → [平台管理与上线](OPEN_API_MANAGEMENT.md) → [OpenAPI 3.1 规范](open-api/openapi.json) |
| 扩展服务端 | [模块化当前实现](MODULE_RUNTIME_IMPLEMENTATION.md) → [架构设计与后续边界](MODULAR_ARCHITECTURE.md) → [文档维护](DOCUMENTATION.md) |

首次安装先完成服务端与 Web 托管，再注册扫描器；具体顺序和验收项见部署指南。配置参数、协议细节和排障步骤在对应专题维护。

## 入门部署

| 文档 | 内容 |
| --- | --- |
| [部署选型与原生安装](DEPLOYMENT.md) | 环境准备、组件安装顺序、systemd、升级与验收 |
| [Docker 部署](DOCKER.md) | Compose、首次登录、持久化、升级排障与镜像构建 |
| [Docker 配置参考](DOCKER_CONFIGURATION.md) | 环境变量、默认值、生效方式和 Compose 设置 |
| [启动配置检查](CONFIG_CHECK.md) | 缺省字段提示、配置来源及 Web 检查快照 |
| [登录人机验证](HUMAN_VERIFICATION.md) | 可选 Turnstile 的启用、验证和排障 |
| [用户管理 CLI](USER_MANAGEMENT_CLI.md) | 用户、凭据、会话和登录限制的本地管理 |

## 功能使用

| 文档 | 内容 |
| --- | --- |
| [功能概览](FEATURES.md) | 服务端功能入口、交互约束和专题导读 |
| [操作系统识别](OS_DETECTION.md) | 系统线索、证据、置信度、搜索和升级排障 |
| [Web 框架与组件识别](WEB_DETECTION.md) | 基于 HTTP 证据的技术栈、版本、搜索与边界 |
| [Web 技术目录](WEB_TECHNOLOGY_CATALOG.md) | 支持清单、MinIO/S3/Git 边界及分批扩展 |
| [资产搜索](SEARCH_SYNTAX.md) | 搜索字段、表达式语法、结果语义和 API 契约 |
| [统计分析](STATISTICS.md) | 自定义汇总、图表以及图片和数据导出 |
| [周报与月报](reports.md) | 报表指标、发送计划、归档与恢复 |
| [业务时区与常规设置](SYSTEM_TIME.md) | 时间配置、展示规则及报告时间契约 |

## 扫描与资产

| 文档 | 内容 |
| --- | --- |
| [扫描流水线与结果协议](SCAN_PIPELINE.md) | 扫描阶段、能力声明、结果上传和兼容边界 |
| [双栈与自动目标](DUAL_STACK_SCANNING.md) | IPv4/IPv6 能力调度与自动目标生成 |
| [智能目标与扫描器分配](SMART_SCANNING.md) | 地域调度、自动刷新、任务组与执行反馈 |
| [搜索触发目标更新](SEARCH_TARGET_GENERATION.md) | 更新范围、去重、限制与故障行为 |
| [DNS 测绘](DNS_MAPPING.md) | DNS 任务、解析结果和数据保留 |
| [证书透明度域名发现](DOMAIN_DISCOVERY.md) | crt.sh 发现、完整 SAN 关系、后台恢复和 DNS 验证 |
| [资产端口状态与历史](ASSET_PORT_HISTORY.md) | 端口当前状态、历史记录与回填语义 |
| [扫描器任务恢复协议](scanner-recovery.md) | 服务端任务恢复、检查点和诊断领取 |

## 存储与性能

| 文档 | 内容 |
| --- | --- |
| [Elasticsearch 存储](ELASTICSEARCH.md) | 新安装、存储切换、历史迁移与验收 |
| [扫描写入与资产发布](WRITE_SPEED.md) | 上传边界、投影租约、检查点与写入观测 |
| [扫描分析快照](ANALYTICS_SNAPSHOTS.md) | 快照模式、历史回填和统计口径 |
| [写入压力测试](SCAN_WRITE_STRESS.md) | 压测方法、延迟分布、吞吐与实测记录 |

## 运维排障

| 文档 | 内容 |
| --- | --- |
| [运行时配置](RUNTIME_CONFIGURATION.md) | 配置来源、发布接口、生效方式和实现边界 |
| [慢检测与掉线策略](monitoring-policies.md) | 在线策略管理、冲突恢复及性能统计 |
| [健康监控与告警](HEALTH_ALERT.md) | 监控阈值、慢 SQL 和通知联动 |
| [统一通知渠道](NOTIFICATIONS.md) | 邮件、飞书、Telegram 的事件订阅、投递与排障 |
| [分渠道通知模板](NOTIFICATION_TEMPLATES.md) | 邮件、飞书、Telegram 的独立模板、样式、在线预览和版本发布 |
| [扫描器错误与日志](SCANNER_DIAGNOSTICS.md) | 远程错误事件、日志采集与服务端治理 |
| [请求日志](REQUEST_LOG.md) | 请求采集、查询、错误分类和保留策略 |
| [审计日志](AUDIT_LOG.md) | 操作审计、事件范围和查询约定 |
| [pgBackRest 备份恢复](PGBACKREST_BACKUP.md) | 备份部署、权限、执行与恢复验证 |
| [资源读取与慢依赖隔离](SYSTEM_RESOURCE_RESILIENCE.md) | 资源读取、缓存、上传事务边界与上线检查 |

## 开放平台

| 文档 | 内容 |
| --- | --- |
| [外部 API v1 接入](OPEN_API.md) | 授权、请求参数、数据口径、配额与示例 |
| [平台管理与上线](OPEN_API_MANAGEMENT.md) | 管理 Web、审批、密钥、回调、部署和停用 |
| [实现与回归](OPEN_API_IMPLEMENTATION.md) | 模块、数据模型、事务边界与验证方法 |

## 开发参考

| 文档 | 内容 |
| --- | --- |
| [操作系统识别维护](OS_DETECTION_DEVELOPMENT.md) | 特征字段、异步队列、投影、规则回填与验证 |
| [Web 技术栈识别维护](WEB_DETECTION_DEVELOPMENT.md) | 内置规则、派生队列、回填、验证与后续阶段 |
| [模块化实现与热更新](MODULE_RUNTIME_IMPLEMENTATION.md) | 当前实现：Workspace、报表渲染 Worker、版本切换和回滚 |
| [模块化架构设计](MODULAR_ARCHITECTURE.md) | 整体目标架构与后续设计；已实现能力以实现说明为准 |
| [进程替换原型](examples/modular-hot-update/README.md) | 独立实验：验证进程替换生命周期，未集成生产服务 |
| [文档维护与本地预览](DOCUMENTATION.md) | 内容归属、导航维护、站内链接和 MkDocs 构建检查 |

机器可读接口规范：[下载 OpenAPI 3.1 JSON](open-api/openapi.json)。


## 配套组件

| 组件 | 文档职责 | 入口 |
| --- | --- | --- |
| 服务端 | 系统部署、扫描协议、存储、运维及外部 API | [服务端文档中心](https://github.com/wshijiang/network-mapping/blob/main/docs/README.md) |
| 扫描器 | 节点部署、引擎配置、执行恢复及本地诊断 | [扫描器文档中心](https://github.com/wshijiang/Network-Mapping-Scanner/blob/main/docs/README.md) |
| Web 控制台 | 页面操作、前端集成、组件及交互验证 | [Web 文档中心](https://github.com/wshijiang/network-mapping-vue/blob/main/docs/README.md) |

## 文档维护

新增专题时同步本页与 `mkdocs/mkdocs.yml` 的导航，提交前完成严格构建。内容归属、链接规则和命令见[文档维护与本地预览](DOCUMENTATION.md)。
