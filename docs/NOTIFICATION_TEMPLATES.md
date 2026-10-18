# 分渠道通知模板与在线预览

[返回文档中心](README.md) · [配置通知渠道](NOTIFICATIONS.md)

管理员在「设置 → 通知模板」(`/setting/notification-templates`) 中分别选择邮件、飞书或 Telegram。旧地址 `/setting/mail-templates` 继续可用。模板按**渠道类型与事件**配置；多个同类渠道共用相应已发布模板，订阅、目标和凭据仍在「通知渠道」中配置。

## 配置、发布与恢复

1. 选择渠道类型和事件。飞书和 Telegram 各有健康告警、Scanner 掉线、Scanner 恢复、登录、周报、月报六个独立模板；邮件保留既有事件模板，Scanner 掉线/恢复共用邮件模板。
2. 选择纯文本或 HTML 富文本，填写标题、正文。飞书的 HTML 是便于编辑的受限语法，后端会转换为飞书原生 `post` JSON。
3. 编辑后自动在线预览，也可手动刷新。查看效果、文本和最终消息数据，校验错误会直接显示。机器人模板在预览、保存、发布及历史恢复时同时验证 `warning`、`critical` 两种示例，避免严重告警的条件分支漏检；预览效果仍展示 `warning` 示例。邮件继续使用原有「校验并预览」。
4. 保存草稿不改变实际通知。发布时先保存未保存修改，再发布该草稿。历史版本可恢复为新草稿，重新发布后生效。

飞书和 Telegram 尚未发布自定义模板时，沿用内置纯文本内容。两个渠道及不同事件的草稿、发布版本和版本号彼此独立；邮件模板和归档报告不受机器人模板更改影响。

后台在每次实际发送尝试时读取当前已发布机器人模板。因此等待中和重试中的通知会使用最新发布版本，已经发送的消息不更改。报告机器人模板只接收报告完成事件的安全摘要，不接收完整报告。邮件报告继续发送生成时归档的正文。

## 支持的格式和样式

| 渠道 | 本功能支持的格式 | 样式与限制 |
| --- | --- | --- |
| 邮件 | HTML + 备用纯文本 | CSS 内联及允许的样式属性；不加载远程样式表，最终以邮件客户端为准 |
| 飞书 | text / post | `b/strong` 粗体、`i/em` 斜体、`u/ins` 下划线、`s/strike/del` 删除线、`a` 超链接；转换为 `style` 和链接节点 |
| Telegram | text / HTML parse_mode | 上述样式，另支持 `code`、`pre`、`blockquote`、`tg-spoiler`；本编辑器要求 code/pre/blockquote 单独使用，不能与其他标签嵌套 |

HTML 换行直接输入换行符，不使用 `<br>`、`<p>` 或 `<div>`。链接仅支持带引号的 `href`，且地址必须为不含账号密码的 HTTP/HTTPS URL。HTML 实体支持 `amp/lt/gt/quot/apos` 和有效数字实体。富文本不支持 CSS、任意 HTML 属性、图片、卡片 JSON 或 Telegram 新版 `sendRichMessage`；这些属于平台的其他消息能力，不在本次模板编辑范围内。遇到不支持的格式会拒绝保存/发布，而不会悄悄删除样式。

例如选择 HTML 富文本：

```html
<b>{{ title }}</b>
级别：<u>{{ severity }}</u>
{{ body }}
<a href="https://your-platform.example/">打开平台</a>
```

如果飞书机器人启用了关键词校验，自定义标题或正文必须保留允许的关键词（例如 `Network Mapping`），否则飞书会拒绝消息。

标题按纯文本输入，不需要 HTML。正文支持 Tera 变量、条件和循环。HTML 模式下变量自动转义；不要对事件变量使用 `safe` 过滤器。用户填写的 HTML 经服务端严格校验后才会生成消息与预览。

| 变量 | 内容 |
| --- | --- |
| `system_name` | Network Mapping |
| `title` | 安全事件标题，最多取 120 个字符 |
| `body` | 安全事件摘要，最多取 1400 个字符 |
| `severity` | warning / critical |
| `event_type` | 如 health.alert |
| `event_id` | 稳定的事件 UUID |
| `occurred_at` | 事件发生时间，RFC 3339 UTC |

正文末尾始终自动附加事件 ID，便于追踪。机器人不能访问邮件模板中的来源 IP、收件人、原始 SQL 或凭据。

## 在线预览的边界

三个渠道都支持在线预览。邮件使用经过安全处理的浏览器 HTML 预览；飞书、Telegram 使用与实际发送相同的服务端模板渲染结果，浏览器模拟展示字体样式、链接和换行。

**飞书、Telegram 没有在本项目中接入可嵌入的官方客户端原样预览服务。** 模拟预览不能保证客户端字体、主题、链接确认提示、引用和剧透显示完全一致，页面会明确提示。预览采用固定示例数据，不访问真实用户数据、不发送消息、不打开链接，也不加载外部资源。最终效果应在真实客户端确认。

「通知渠道 → 测试发送」仍用于检查目标、凭据和连通性，发送固定测试消息，不使用某一事件的自定义模板。模板是否生效可通过对应实际事件与投递记录确认；发布操作本身不会向外部渠道发送消息。

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
| POST `/preview` | `{format,titleTemplate,bodyTemplate}`；返回 subject、textBody、htmlBody、payload，不访问数据库 |
| POST `/draft` | `{expectedRevision,source}`，保存为新草稿版本 |
| POST `/publish` | `{expectedRevision}`，发布当前草稿 |
| POST `/restore` | `{expectedRevision,version}`，恢复历史版本为新草稿 |

API 仅管理员可用，写请求受既有 CSRF 校验保护。模板变更与审计记录在同一事务提交；审计记录操作和模板标识，不记录模板正文。模板以 `(provider,event_type)` 隔离，父记录锁及版本号检查保证同一模板的写入顺序。

新安装 `source/database/init.sql` 与幂等升级脚本 `migrate_notification_templates.sql` 均建立 `notification_template`、`notification_template_version` 表。服务端启动自动执行升级。升级时同步部署前后端；旧版后端回退后只发送旧纯文本格式，新增模板表保留，不删除旧邮件模板或修改归档报告。

验证命令：`cargo test --locked notification::`；使用可丢弃 PostgreSQL 并设置 `NOTIFICATION_TEST_DATABASE_URL` 后运行 `cargo test --locked notification:: -- --ignored`。前端运行 `pnpm test:notifications` 和 `pnpm build`。

协议参考：[飞书消息结构](https://open.feishu.cn/document/server-docs/im-v1/message-content-description/create_json)、[飞书自定义机器人](https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot)、[Telegram HTML](https://core.telegram.org/bots/api#html-style)。
