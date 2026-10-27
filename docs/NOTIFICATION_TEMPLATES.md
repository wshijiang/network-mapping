# 分渠道通知模板与在线预览

[返回文档中心](README.md) · [配置通知渠道](NOTIFICATIONS.md)

管理员在「设置 → 通知模板」(`/setting/notification-templates`) 中分别选择邮件、飞书或 Telegram。旧地址 `/setting/mail-templates` 继续可用。模板按**渠道类型与事件**配置；多个同类渠道共用相应已发布模板，订阅、目标和凭据仍在「通知渠道」中配置。

## 配置、发布与恢复

1. 选择渠道类型和事件。飞书和 Telegram 各有健康告警、Scanner 掉线、Scanner 恢复、登录、周报、月报六个独立模板；邮件保留既有事件模板，Scanner 掉线/恢复共用邮件模板。
2. 选择纯文本或 HTML 富文本，填写标题、正文。飞书的 HTML 是便于编辑的受限语法，后端会自动转换为 JSON 2.0 消息卡片（`msg_type: interactive`）。
3. 编辑后自动在线预览，也可手动刷新。查看效果、文本和最终消息数据，校验错误会直接显示。机器人模板在预览、保存、发布及历史恢复时同时验证 `warning`、`critical` 两种示例，避免严重告警的条件分支漏检；预览和模板测试可选择 `warning` 或 `critical` 示例。邮件继续使用原有「校验并预览」。
4. 保存草稿不改变实际通知。发布时先保存未保存修改，再发布该草稿。历史版本可恢复为新草稿，重新发布后生效。

飞书和 Telegram 尚未发布自定义模板时，使用参考邮件内容的分事件富文本默认模板。邮件和机器人共用代码编辑器样式、变量补全和点击插入交互。已保存的草稿和已发布模板不会自动覆盖；可点击「载入默认模板」采用新样式，再保存发布。两个渠道及不同事件的草稿、发布版本和版本号彼此独立；邮件模板和归档报告不受机器人模板更改影响。

后台在每次实际发送尝试时读取当前已发布机器人模板。因此等待中和重试中的通知会使用最新发布版本，已经发送的消息不更改。报告机器人与邮件使用同一份统计投影和归档参数快照。默认机器人模板以邮件的核心指标、环比、建议和详情入口组织内容，按消息长度精简展示；完整参数仍可用于自定义模板。邮件报告继续发送生成时归档的正文。

## 支持的格式和样式

| 渠道 | 本功能支持的格式 | 样式与限制 |
| --- | --- | --- |
| 邮件 | HTML + 备用纯文本 | CSS 内联及允许的样式属性；不加载远程样式表，最终以邮件客户端为准 |
| 飞书 | text / interactive 消息卡片 | `b/strong` 粗体、`i/em` 斜体、`s/strike/del` 删除线、`a` 超链接转换为卡片 Markdown；`u/ins` 下划线兼容显示为普通文本，预览与发送一致 |
| Telegram | text / HTML parse_mode | `b/strong` 粗体、`i/em` 斜体、`u/ins` 下划线、`s/strike/del` 删除线、`a` 超链接，另支持 `code`、`pre`、`blockquote`、`tg-spoiler`；本编辑器要求 code/pre/blockquote 单独使用，不能与其他标签嵌套 |

HTML 换行直接输入换行符，不使用 `<br>`、`<p>` 或 `<div>`。链接仅支持带引号的 `href`，且地址必须为不含账号密码的 HTTP/HTTPS URL。HTML 实体支持 `amp/lt/gt/quot/apos` 和有效数字实体。富文本不支持 CSS、任意 HTML 属性、图片、自定义卡片 JSON 或 Telegram 新版 `sendRichMessage`。除上述飞书下划线标签兼容处理外，遇到不支持的格式会拒绝保存/发布。

飞书卡片使用纯文本标题、Markdown 正文、分隔线和事件 ID。健康告警和 Scanner 掉线使用橙色标题，严重级别使用红色，Scanner 恢复使用绿色，其他普通通知使用蓝色。现有 HTML 模板自动适配卡片，无需重新发布或重建渠道；纯文本模板继续发送 `text` 消息。变量和正文中的 Markdown 特殊字符按字面转义，链接目标单独编码，换行转换为卡片支持的换行。

飞书应用机器人接口的富文本 `style` 能力不适用于自定义机器人 Webhook。旧版本包含该字段的消息可能返回 HTTP 200、服务码 `19002`；发送前仍会清理已入队旧 `post` 测试快照中的 `style`，这些快照保持原消息类型，有效期内的失败投递可手动重试。新建富文本测试和真实事件使用卡片。服务码 `19002` / `9499` 记录为 `invalid_payload`（消息格式无效）。

例如选择 HTML 富文本：

```html
<b>{{ alert_type }}</b>
级别：<u>{{ severity }}</u>
{{ summary }}
{% for d in details %}{{ d.label }}：{{ d.value }}
{% endfor %}
<a href="https://your-platform.example/">打开平台</a>
```

如果飞书机器人启用了关键词校验，自定义标题或正文必须保留允许的关键词（例如 `Network Mapping`），否则飞书会拒绝消息。

标题按纯文本输入，不需要 HTML。正文支持 Tera 变量、条件和循环。HTML 模式下变量自动转义；不要对事件变量使用 `safe` 过滤器。用户填写的 HTML 经服务端严格校验后才会生成消息与预览。

变量目录按事件直接复用邮件模板的 `key / label / example`，三种渠道使用相同字段名和结构，数组与嵌套对象均可用 Tera 循环、条件访问：

| 事件 | 邮件、飞书、Telegram 的共享参数 |
| --- | --- |
| 登录 | `system_name`、`username`、`login_time`、`source_ip` |
| 健康告警 | `system_name`、`alert_type`、`severity`、`occurred_at`、`summary`、`details`（label/value） |
| Scanner 掉线/恢复 | `system_name`、`event_label`、`scanner_name`、`scanner_id`、`location`、`last_seen_at`、`event_at`、`detail_path` |
| 周报/月报 | `system_name`、`report_label`、`period_label`、`tasks`、`scan_output`、`recommendations`、`detail_path`、`detail_url`、`report_meta`、`previous_available`、`comparison`、`comparison_rows`、`trend_rows`、`trend_image_url`、`scanners`、`scanner_omitted`、`quality_summary`、`notes` |

登录与健康事件复用已捕获的邮件参数；Scanner 使用同一查询解析详情；新报告在归档时保存 `notification_context`，机器人投递时复用此快照。旧报告没有快照时，从其不可变统计及当前报告展示配置构建投影。参数只投影邮件目录中的字段，不包含收件人、Token、Webhook 或其他凭据。

**登录模板的 `source_ip` 现在也可在飞书和 Telegram 中使用，默认模板会展示来源地址，与邮件保持一致。** 模板测试只使用固定示例地址。旧版机器人 `title/body/severity/event_type/event_id/occurred_at` 通用参数保留兼容，推荐新模板使用对应事件的邮件字段。正文末尾自动附加事件 ID。

样式统一指标题、详情、建议、操作入口等信息结构及受支持的字重、链接、换行；平台字体、颜色、布局不保证逐像素相同。`trend_image_url` 等图片参数仍存在，但机器人不支持直接嵌入邮件图片；相对 `detail_path` 可显示为文本，超链接应使用绝对 HTTP/HTTPS 地址（如报告的 `detail_url`）。

## 在线预览的边界

三个渠道都支持在线预览。邮件使用经过安全处理的浏览器 HTML 预览；飞书、Telegram 使用与实际发送相同的服务端模板渲染结果，浏览器模拟展示字体样式、链接和换行。飞书卡片预览额外显示卡片边框、标题底色和事件 ID 分隔线。

**飞书、Telegram 没有在本项目中接入可嵌入的官方客户端原样预览服务。** 模拟预览不能保证客户端字体、主题、链接确认提示、引用和剧透显示完全一致，页面会明确提示。预览采用固定示例数据，不访问真实用户数据、不发送消息、不打开链接，也不加载外部资源。最终效果应在真实客户端确认。

## 模板测试发送

飞书和 Telegram 编辑器均提供「测试发送」：选择一个同类型且已启用的通知渠道、示例级别，然后发送**当前编辑内容**。无需保存或发布，不修改草稿、版本或生效模板，也不需要输入 Webhook/Token。测试使用与预览相同的邮件示例数据，事件 ID 在入队时生成。

后端校验模板后，将渲染结果作为不可变快照写入现有通知队列。目标类型须匹配、渠道须已启用且未删除；与渠道连通性测试共用每渠道 30 秒限制。队列沿用目标版本检查、签名、加密凭据、维护暂停、重试和结果记录。模板之后的编辑/发布不会改变已排队的测试消息。

页面显示投递 ID，并最多轮询约 60 秒，分别显示排队、发送中、成功、失败/取消；超时或暂时无法查询时可前往通知渠道的投递记录查看。离开页面会取消请求和轮询。`202 Accepted` 只表示入队，只有 `sent` 表示服务商接受。

「通知渠道 → 测试发送」仍发送固定连通性消息；「模板 → 测试发送」发送所选事件的当前模板。二者不会自动保存或发布模板。

## 限制与排障

- 标题模板最多 500 字符，渲染后标题为 1–200 字符且不能换行；正文模板最多 12 KiB，HTTP JSON 请求总大小仍受 16 KiB 限制。
- Telegram 渲染后的可见消息（含标题与事件 ID）不能超过 4096 UTF-16 单位；消息 JSON 限制为 19 KiB。飞书消息 JSON 预留签名空间，模板渲染阶段限制为 19 KiB，最终请求不得超过 20 KiB。
- 示例数据校验通过不保证任意真实数据都不超长。真实事件渲染失败/超限时，投递记录显示 `notification_template_invalid`，不会发送损坏的富文本。修改发布后可手动重试仍符合条件的失败投递。
- 保存、发布和恢复携带 `expectedRevision`。并发冲突返回 409，保留本地编辑；重新加载前自行保存需要保留的文本。切换渠道、事件或离开页面时提示未保存修改。

## API、存储与升级

现有邮件模板 API `/api/mail/templates` 保持兼容。机器人 API 前缀为 `/api/notifications/templates/{provider}/{event}`；`provider` 为 `feishu/telegram`，`event` 为六个通知事件之一。

| 方法及后缀 | 用途 / 请求 |
| --- | --- |
| GET 基础路径 | 返回 source、defaultSource、variables、revision、activeVersion、status、versions |
| POST `/preview?severity=warning` | `{format,titleTemplate,bodyTemplate}`；severity 可为 warning/critical，返回 subject、textBody、htmlBody、payload，不访问数据库 |
| POST `/test` | `{channelId,source,severity}`，返回 202 和 delivery_id，使用当前未保存模板及示例数据入队 |
| POST `/draft` | `{expectedRevision,source}`，保存为新草稿版本 |
| POST `/publish` | `{expectedRevision}`，发布当前草稿 |
| POST `/restore` | `{expectedRevision,version}`，恢复历史版本为新草稿 |

`GET /api/notifications/deliveries/{id}` 返回测试投递状态及公开失败原因，不返回消息正文或凭据。

API 仅管理员可用，写请求受既有 CSRF 校验保护。模板变更与审计记录在同一事务提交；审计记录操作和模板标识，不记录模板正文。模板以 `(provider,event_type)` 隔离，父记录锁及版本号检查保证同一模板的写入顺序。

新安装 `source/database/init.sql` 与幂等升级脚本 `migrate_notification_templates.sql` 均建立 `notification_template`、`notification_template_version` 表，并为 `report_run` 增加可空的 `notification_context` JSONB 快照字段。服务端启动自动执行升级。升级时同步部署前后端；旧版后端回退后只发送旧纯文本格式，新增模板表保留，不删除旧邮件模板或修改归档报告。

验证命令：`cargo test --locked notification::`；使用可丢弃 PostgreSQL 并设置 `NOTIFICATION_TEST_DATABASE_URL` 后运行 `cargo test --locked notification:: -- --ignored`。前端运行 `pnpm test:notifications` 和 `pnpm build`。

协议参考：[飞书卡片 Markdown](https://open.feishu.cn/document/feishu-cards/card-json-v2-components/content-components/rich-text)、[飞书自定义机器人](https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot)、[Telegram HTML](https://core.telegram.org/bots/api#html-style)。
## Telegram 富消息

Telegram 模板可以选择“富消息（sendRichMessage）”；服务器使用受限 HTML 模板生成富消息。新默认的周报和月报模板采用该格式，已发布模板继续使用原有格式。此格式目前仅支持编辑器现有的文本标签，不支持在模板中直接插入图片。
