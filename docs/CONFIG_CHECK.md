# 启动配置检查

服务端启动时检查 `--config` 指定的 TOML 原始字段，再使用程序原有的默认值加载配置。按字段路径比较，而不是按参数数量比较；TOML 点分键和内联表均受支持。

允许提示的字段以本版本仓库根目录追踪的 `config.toml` 为准。代码内部默认字段、未公开的配置段以及仅出现在 Docker 示例中的字段不生成提示，再排除下述数据库管理参数。缺省值取自程序本身，不使用仓库配置中的实际值。

## 文件与 Docker 部署

- 文件部署继续使用原配置路径，例如 `network_mapping_server --config /srv/network-mapping/config.toml`。
- 标准 Docker/Compose 使用镜像默认 `--config-source env`，从内置默认值和 `NM__…` 环境变量生成同一检查快照，无需挂载 TOML；详见 [Docker 部署指南](DOCKER.md)。兼容旧文件挂载时显式使用 `--config-source file --config /etc/network-mapping/config.toml`，检查不写回、不补写或替换文件。
- 路径默认值沿用程序既有行为。文件与 Docker 部署的资源目录可能不同，应按检查详情核对路径和挂载；不会把新版示例中的路径自动覆盖到用户配置。
- 修改 TOML 后重启对应进程；修改 Compose `.env` 后使用 `up -d --force-recreate` 重新注入环境，单纯 restart 不更新环境。Web 的“重新读取”只重新获取启动快照，不重新加载启动配置。

## 提示与来源

启动终端输出检查摘要；正常启动后 JSON 日志记录 `ConfigCheckSummary` 和 `ConfigFieldDefaulted`。必需字段缺失时输出字段名称并终止启动；日志尚未初始化时通过标准错误输出，Docker 可从容器日志查看。

管理员在“系统设置 → 启动配置检查”查看同一快照。接口为 `GET /api/config/check`，非管理员返回 403。详情区展示字段、内置缺省值和处理方式，未启用功能的可选参数默认折叠隐藏。检查只报告未显式配置，不推断它是否在本次升级新增。

公开字段的内置默认值为 `None` 时仍检查缺失，报告的 `default_value` 为 `null`，Web 显示“未设置”，不会将其判为必需字段。备份启用时，缺少 `backup.run_as_user` 会提示以服务进程的操作系统用户执行 pgBackRest，不通过 sudo 切换账户；缺少 `backup.config_file` 会提示使用 pgBackRest 的默认配置文件查找规则。备份关闭时，这些项归入未启用功能的可选参数。配置检查只说明当前行为，不补写账户或配置路径。

`requests`、`monitor`、`automatic_target`、`dns_follow_up`、`analytics_snapshot` 和 `report_mail` 由 Web 控制台管理并存储在数据库中，不生成配置文件缺省提示，不计入启动摘要或字段日志。TOML 的首次初始化种子行为不变，已有数据库运行策略不会被文件覆盖。敏感值及原配置内容不会出现在检查结果中。

报告中的 `public_fields` 只包含公开字段名称。前端根据该清单过滤提示；旧报告使用从对应仓库根目录配置提取的名称清单兼容过滤，同时排除 `database_seed` 和 `remote_override`。仅有这些被过滤项目时不显示导航栏提示。部署参数提示在导航栏居中显示，检查通过时隐藏。

扫描器配置页面同时展示扫描器通过心跳上报的本地配置检查。旧扫描器没有上报时显示“尚未收到”；检查时间是扫描器启动时刻，离线后仍可能展示最后一次快照。

## 数据库兼容

初始化 SQL 添加可空列 `scanner_info.local_config_check JSONB`，通过 `ADD COLUMN IF NOT EXISTS` 兼容已有数据库。旧扫描器的心跳允许缺少此字段，收到不支持检查的心跳时清除此前快照，避免展示旧程序的信息。已有扫描策略、身份、待上传结果均不改变。

## 开发约定

公开范围与默认值分开维护：`build.rs` 从根目录 `config.toml` 提取字段名称，内置值仍来自配置类型的 `Default + Serialize`。新增代码默认字段不会自动产生用户提示；只有公开到根目录配置且不由数据库管理的参数才纳入检查。新增可选段需要加入 `inspect_server`；新增基础必需字段及基础字段默认值需要同步检查目录并添加兼容测试。新增敏感字段必须纳入脱敏规则，禁止从实际用户配置生成可输出的默认值。

修改公开配置字段后运行 `python3 scripts/update-config-fields.py`（Python 3.11+），更新只含名称的 `src/public_config_fields.txt`；本地构建会校验该清单与根目录配置一致。Docker 构建通过 `NM_PUBLIC_CONFIG_FIELDS_FILE` 使用该清单，实际根目录配置不进入构建上下文，也不会嵌入二进制。两种部署的提示范围一致，Docker 示例不扩展公开范围。

该能力不进行字段改名或类型转换迁移；此类变化仍需兼容代码与升级说明。启动时原有的类型、范围和条件依赖校验继续执行。
