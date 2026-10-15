# 文档中心

[返回项目首页](../README.md)

首次使用从项目首页的快速开始进入；部署与日常操作按主题查阅，开发时参考协议或维护指南。

## 入门与操作

| 文档 | 内容 |
| --- | --- |
| [服务端部署指南](DEPLOYMENT.md) | 部署选型、两端安装顺序、原生托管、升级恢复与验收 |
| [Docker 构建与部署](DOCKER.md) | Compose、首次登录与联调、持久化、升级排障及镜像构建发布 |
| [服务端功能指南](FEATURES.md) | 功能入口、交互约束与配置示例 |
| [用户管理 CLI](USER_MANAGEMENT_CLI.md) | 用户、凭据、会话和登录限制的本地管理 |
| [资产搜索语法与 API](SEARCH_SYNTAX.md) | 搜索字段、表达式语法与 API 契约 |

## 外部 API 与开放平台

| 文档 | 内容 |
| --- | --- |
| [外部 API v1](OPEN_API.md) | 80 项接口、授权、请求参数、数据口径与示例 |
| [管理与上线](OPEN_API_MANAGEMENT.md) | 管理 Web、审批、密钥、回调、部署和停用 |
| [实现与回归](OPEN_API_IMPLEMENTATION.md) | 模块、数据模型、事务边界和检查 |
| [OpenAPI 3.1](open-api/openapi.json) | 可导入工具的机器可读规范 |
| [实施验证记录](open-api/verification.md) | 构建、隔离回归、浏览器交互及尚需上线验收的内容 |

## 扫描与资产

| 文档 | 内容 |
| --- | --- |
| [扫描计划与结果协议](SCAN_PIPELINE.md) | 扫描阶段、能力声明和结果上传协议 |
| [双栈扫描、协议能力与自动目标](DUAL_STACK_SCANNING.md) | IPv4/IPv6 能力调度与自动目标生成 |
| [DNS 测绘](DNS_MAPPING.md) | DNS 任务与解析结果处理 |
| [搜索触发目标更新](SEARCH_TARGET_GENERATION.md) | 搜索触发更新的范围、去重与限制 |
| [资产端口状态与历史](ASSET_PORT_HISTORY.md) | 端口当前状态与历史记录语义 |
| [扫描器任务恢复协议](scanner-recovery.md) | 服务端任务恢复与检查点协议 |

## 存储与分析

| 文档 | 内容 |
| --- | --- |
| [Elasticsearch 9.5.x 扫描结果存储](ELASTICSEARCH.md) | 新安装、存储切换与历史数据迁移 |
| [扫描写入与后台资产发布](WRITE_SPEED.md) | 上传边界、投影租约、检查点与写入观测 |
| [扫描写入压力测试](SCAN_WRITE_STRESS.md) | 大数据写入方法、延迟分布、吞吐与实测记录 |
| [扫描分析快照](ANALYTICS_SNAPSHOTS.md) | 分析快照模式与回填 |
| [统计分析](STATISTICS.md) | 自定义汇总、图表及图片和数据导出 |
| [平台周报与月报](reports.md) | 周报、月报、发送计划与归档 |

## 运维与诊断

| 文档 | 内容 |
| --- | --- |
| [服务端运行时配置](RUNTIME_CONFIGURATION.md) | 配置来源、发布接口及当前实现边界 |
| [扫描器错误诊断与日志采集](SCANNER_DIAGNOSTICS.md) | 远程错误事件、日志采集与服务端治理 |
| [请求日志与错误识别](REQUEST_LOG.md) | 请求采集、查询与错误分类 |
| [审计日志](AUDIT_LOG.md) | 操作审计与查询约定 |
| [健康监控与告警](HEALTH_ALERT.md) | 监控阈值、慢 SQL 和邮件告警 |
| [pgBackRest 备份管理使用指南](PGBACKREST_BACKUP.md) | 备份部署、权限、执行与恢复验证 |
| [系统业务时区与常规设置](SYSTEM_TIME.md) | 业务时区与时间展示规则 |
| [系统资源读取与慢依赖隔离](SYSTEM_RESOURCE_RESILIENCE.md) | 资源读取、缓存与慢依赖处理 |
| [SQL 热路径优化与对比](SQL_HOT_PATH_OPTIMIZATION.md) | 认证热路径及性能对比 |

## 架构与开发设计

| 文档 | 内容 |
| --- | --- |
| [服务端模块化与部分热更新方案](MODULAR_ARCHITECTURE.md) | 领域边界、业务 worker 替换、配置同步、任务一致性与迁移阶段；含独立可运行 Rust 原型 |
| [模块系统实现规格与接入步骤](MODULE_RUNTIME_IMPLEMENTATION.md) | 当前领域拆分、独立渲染包、生产接入、热更新配置与管理接口 |

## 文档维护约定

- README 提供项目定位、快速开始和主要入口；详细参数、协议及排障保留在专题文档。
- 接口、配置或行为变更时，同步更新使用说明及配套组件文档。
- 示例使用脱敏值，命令注明运行位置，代码块标明语言。
- 区分当前实现与后续计划，保持相对链接和文档索引有效。

- [智能目标与扫描器分配](SMART_SCANNING.md)：地域调度、自动刷新、任务组与目标连接反馈。
