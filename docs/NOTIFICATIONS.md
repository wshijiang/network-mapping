# 通知渠道：邮件、飞书与 Telegram

[返回文档中心](README.md)

## 统一管理

管理员在「设置 → 通知渠道」（`/setting/notifications`）管理全部通知方式。邮件、飞书、Telegram 是同级渠道，使用相同的事件目录、启停、最低级别、测试、投递历史及失败重试功能。可以仅启用任意一种，也可以同时开启多个渠道；一个事件会分别进入每个已启用、已订阅渠道的队列，不按优先级或备用关系选择。

每个渠道可单独选择以下通知类型：

| 事件 | 内容 | 级别 |
| --- | --- | --- |
| `health.alert` | 慢请求、5xx、慢 SQL、Elasticsearch 异常等健康告警 | warning / critical |
| `scanner.offline` | Scanner 超过运行策略中的掉线阈值 | warning |
| `scanner.recovered` | 已成功通知掉线的目标恢复连接 | warning |
| `user.login` | 用户完成登录 | warning |
| `report.weekly` | 周报生成并归档完成 | warning |
| `report.monthly` | 月报生成并归档完成 | warning |

「仅严重」只发送 critical 健康告警，登录、Scanner 和报告事件不会通过该级别过滤。健康监控开关、Scanner 检测阈值及维护宽限仍在运行策略中配置。报告生成计划、时间和默认邮件收件管理员仍在报告中心配置；报告计划可在没有邮箱的部署中启用，通知方式由本页面的订阅决定。停用通知渠道不会停用报告归档。

任务错误/完成、日报目前没有落地的事件生产链路，本页面不提供无效开关。新增渠道只接收之后发生的事件，不补发历史消息。

## 添加邮件渠道

1. 选择「邮件」，填写渠道名称、SMTP 服务器域名、SMTPS 端口（通常 465）、发件人邮箱和邮箱授权密钥。发件人地址同时作为 SMTP 登录账号。
2. 可指定收件人，每行一个或用逗号分隔，最多 32 个。留空时使用事件默认收件人：登录通知为该用户本人；报告为报告计划所选管理员（未选则所有有效管理员邮箱）；健康和 Scanner 通知为当前启用的管理员邮箱。
3. 选择事件与级别，保存并启用后点击「测试发送」。测试使用该渠道收件人，默认收件人为空时使用当前管理员名单。没有有效邮箱时记录会显示失败原因。

邮件使用经证书验证的 SMTPS，不关闭 TLS 验证。登录、健康和 Scanner 邮件沿用已发布模板；报告邮件使用归档正文，机器人接收简短摘要。邮件密钥加密存储、不回显，编辑留空保留。一次投递使用一个 SMTP envelope，其他收件人使用 Bcc，不公开完整名单。

原 SMTP 配置会在升级时一次性导入邮件渠道，已实现的通知偏好映射为该渠道订阅；原测试收件人不会变成真实通知收件人。之后重复启动不会覆盖 Web 中的更改。旧设置页只保留统一入口。

报告中心手动发送/重发完整报告邮件、模板测试属于显式邮件操作，继续使用首个未删除邮件渠道的 SMTP 配置；即使仅使用机器人接收自动通知，也可独立配置邮件操作所需的 SMTP。通知订阅不再受旧邮件偏好开关控制。

## 添加飞书渠道

1. 在飞书群添加「自定义机器人」，复制 Webhook；建议启用签名校验并复制签名密钥。
2. 选择「飞书」，填写名称、Webhook、可选签名密钥及事件订阅，保存并启用。
3. 若开启关键词校验，允许固定前缀 **Network Mapping**；若开启 IP 白名单，允许服务实际出口 IP。

仅支持 `https://open.feishu.cn/open-apis/bot/v2/hook/<机器人 UUID>`，不接受任意 Webhook、Lark 国际版域名、查询参数、片段、用户凭据、其他端口和重定向。服务需要允许访问 `open.feishu.cn:443`，无须公开回调入口。

签名按官方协议，以 `timestamp + "\n" + secret` 为 HMAC-SHA256 key，对空消息计算摘要并 Base64 编码。HTTP 成功还必须满足 JSON `code == 0`，兼容 `StatusCode`。签名密钥留空保留；移除须明确勾选清除。

协议参考：[飞书自定义机器人](https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot)。

## 添加 Telegram 渠道

1. 通过 BotFather 创建机器人，取得 Bot Token。不要将 Token 粘贴到日志、截图或公共文档。
2. 将机器人加入群或频道并授予发消息权限；私聊接收人须先向机器人发送 `/start`。
3. 选择「Telegram」，填写 Token 和 Chat ID。支持非零数字 ID（包括负数群 ID）或公开频道 `@名称`。
4. 选择与邮件、飞书相同的事件类型，保存启用并测试。Token 保存后不回显，编辑留空保留。

后端只调用固定的 `https://api.telegram.org/bot<Token>/sendMessage`，不接受自定义服务地址、代理 API 端点或重定向。部署环境需允许 `api.telegram.org:443`。消息为纯文本，关闭链接预览，不拼接 HTML/Markdown 解析指令。请求同时验证 HTTP 状态、`ok` 和消息 ID；限流遵守 `parameters.retry_after`，群权限/目标错误直接记录失败。机器人摘要保留稳定事件 ID，正文按 Telegram 长度限制截短。

协议参考：[Telegram Bot API sendMessage](https://core.telegram.org/bots/api#sendmessage)。

## 启停、编辑与投递记录

- 可同时启用多个同类或不同类渠道；每个渠道有独立的订阅和投递状态。一个渠道失败不会取消其他渠道的任务。
- 渠道类型创建后不可更改；切换类型应新增渠道。
- Webhook、邮箱密钥、Bot Token 和签名密钥均加密存储，不在查询响应、审计或投递错误中回显。
- 保存需带 `expected_revision`。版本冲突返回 409，请刷新后重新编辑。
- 修改、停用或删除取消旧配置的 pending/sending 任务；已发出的请求无法撤回。重新启用只接收新事件。
- 更换目标后不沿用旧目标的 Scanner 掉线收据。恢复只发给当前仍订阅恢复、同一渠道目标已成功接收掉线的渠道；尚未发送的掉线记录会取消。
- 健康告警只在数据库接纳后更新本地冷却，共享闸门拒绝不会延长冷却。
- 每次领取前检查维护状态。批次中开启维护时允许在途完成，后续记录保持待处理；退出后继续领取。
- 离开 Web 页面会取消读取请求并清除刷新定时器，迟到响应不会继续轮询或覆盖已卸载状态。

消息摘要不包含原始 SQL、客户端 IP 或请求正文。登录邮件的私有来源 IP 仅用于邮件模板，不发送给机器人。Webhook、Bot Token、SMTP 密钥和服务商原始错误正文不会写入投递历史。

| 约束 | 当前值 |
| --- | --- |
| 有效渠道 | 最多 32 个 |
| 同渠道测试 | 每 30 秒最多入队一次，须已启用 |
| 同渠道发送 | 数据库协调，每秒最多领取一次真实发送 |
| 请求 / 投递尝试上限 | 10 秒 / 20 秒 |
| 尝试次数 | 每轮最多 5 次；手动重试开启新一轮 |
| 自动重试间隔 | 60、120、240、480 秒；有效服务商限流等待更长时按其等待 |
| 事件有效期 | 24 小时 |
| 服务商响应上限 | 16 KiB |
| 历史保留 | 通常 30 天；未结束 incident 的收据保留至恢复后 30 天 |
| 历史翻页 | 每页 50 条，`before` 游标 |

事件与初始投递在 PostgreSQL 同一事务提交。领取使用 `FOR UPDATE SKIP LOCKED`、领取令牌和 60 秒租约；失效令牌不能覆盖新领取结果。过期/失效任务在有界批次中连续清理，不消耗真实发送配额。

入库后采用至少一次投递，服务商已接受而落库前中断时可能重复。健康信号入库前仍经过现有内存队列，队列满或服务重启可能丢失尚未入库事件；不承诺 exactly-once。

## API、升级与排障

所有接口位于 `/api/notifications`，仅管理员可用，写请求沿用会话、CSRF 和事务审计。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET / POST | `/channels` | 查询 / 创建渠道 |
| PUT / DELETE | `/channels/{id}` | 按版本编辑 / 删除 |
| POST | `/channels/{id}/test` | 测试入队，返回 202 和 delivery_id |
| GET | `/deliveries` | 按 channel_id/status 筛选、游标翻页 |
| POST | `/deliveries/{id}/retry` | 重试仍符合条件的 failed 记录 |

共用字段为 `provider,name,enabled,event_types,minimum_severity,expected_revision`。`provider` 支持 `email/feishu/telegram`，旧飞书客户端未传时默认 feishu。

- 飞书：`webhook_url,signing_secret,clear_signing_secret`。
- Telegram：`bot_token,settings.chat_id`。
- 邮件：`smtp_password,settings.smtp_host,settings.smtp_port,settings.smtp_sender,settings.recipients`。

响应使用 `{success,data}`，仅包含凭据是否配置；DELETE body 为 `{"expected_revision":1}`。编辑凭据留空保留，不可通过 provider 变更复用别类凭据。

升级时先停止仅支持飞书的旧后端实例，再启动新版后端，避免旧 worker 误领新增类型。启动自动执行幂等迁移，`init.sql` 与升级脚本一致。保留 `server.encrypt_key`，否则无法解密历史凭据。回滚前先停用新增的邮件和 Telegram 渠道，再回退前后端；仅支持飞书的旧版本不能处理新 provider。新增表保留即可。SMTP 一次性导入后，以统一页面订阅为准，不从旧偏好重复恢复渠道。

投递一直 pending 时检查计划时间、维护状态、notification-worker 和数据库。`no_recipients` 检查个人/管理员邮箱或指定收件人；`secret_unavailable` 检查服务主密钥；`provider_rejected` 检查机器人目标、权限、签名及访问限制；SMTP 失败检查域名、端口和授权密钥。服务商限流、网络/TLS 和临时故障按有限次数重试，不关闭 TLS 验证。

## 开发验证

```bash
source /workspace/.cloud/env.sh
CARGO_TARGET_DIR=/workspace/.cloud/target cargo test --locked --lib notification::
# 每个数据库测试创建并清理独立 schema，须使用可销毁的开发 PostgreSQL。
NOTIFICATION_TEST_DATABASE_URL='host=127.0.0.1 user=network_mapping dbname=network_mapping' \
  CARGO_TARGET_DIR=/workspace/.cloud/target cargo test --locked --lib notification:: -- --include-ignored
REPORT_TEST_DATABASE_URL='host=127.0.0.1 user=network_mapping dbname=network_mapping' \
  CARGO_TARGET_DIR=/workspace/.cloud/target cargo test --locked --lib reports:: -- --include-ignored
```

测试覆盖三类渠道的同级扇出、独立启停和事件选择、凭据保留/不回显、SMTP 导入幂等、登录隐私、报告归档后入队、并发领取、租约、维护切换与旧有 Scanner 恢复。HTTP 使用本地 fixture；没有真实机器人/SMTP 凭据和允许出口时，不将本地检查表述为外部联调成功。
