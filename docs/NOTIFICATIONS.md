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

旧 Scanner 邮件及已归档自动报告的 pending/sending 任务按原收件人迁入该邮件渠道，保留尝试次数和待重试时间；尚未到期的旧租约结束后才可领取。替代任务与旧任务的取消在同一事务提交，已发送的收件人不会重发，报告中心显式手动邮件不受影响。迁入任务从迁移或可领取时间开始保留 24 小时发送窗口，避免旧事件时间导致升级后立即过期。

缺少可导入 SMTP 时，旧任务保留在原队列，迁移暂不标记完成。管理员从 Web 配置并启用首个有效邮件渠道后，旧队列与回执在保存事务中接入该渠道，无须重启；后续渠道不重复接管历史任务。停用渠道不会触发接管。旧自动报告 worker 在等待期间不消耗自动邮件的尝试次数，显式手动邮件仍正常处理。若旧版已写入完成标记却没有接管渠道，启动或保存邮件配置时会自动修正。不会恢复此前已经 cancelled/failed 的旧任务。

升级前已成功发送的 Scanner 掉线邮件回执一并迁入。恢复只通知原邮件目标及实际收到掉线邮件、当前仍有效的收件人；升级后新增的管理员或渠道不会收到这次历史恢复。已准备的旧恢复邮件继续按原收件人投递，不重复创建邮件，同时保留其他渠道各自的恢复通知。改名、调整订阅保留回执，更换 SMTP 目标或收件人配置不沿用旧回执。

等待邮件配置期间发生的恢复也会在接管时按旧邮件回执补入邮件队列；已由机器人准备或发送的恢复通知不会重开或重复发送。

报告中心手动发送/重发完整报告邮件、模板测试属于显式邮件操作，继续使用首个未删除邮件渠道的 SMTP 配置；即使仅使用机器人接收自动通知，也可独立配置邮件操作所需的 SMTP。通知订阅不再受旧邮件偏好开关控制。

模板格式、在线预览、独立发布及版本恢复见[分渠道通知模板](NOTIFICATION_TEMPLATES.md)。

## 添加飞书渠道

先选择「群聊自定义机器人」或「应用机器人」。类型创建后不可更改；已有飞书渠道按群聊自定义机器人处理。两种机器人发送通知都不需要平台提供公网回调地址。

| 项目 | 群聊自定义机器人 | 应用机器人 |
| --- | --- | --- |
| 创建位置 | 在目标飞书群的群机器人设置中添加 | 在飞书开放平台创建企业自建应用，添加机器人能力 |
| 发送方式 | 向该群机器人的 Webhook 发送消息 | 应用凭据换取 token，以应用身份向指定群发送消息 |
| 目标 | Webhook 绑定创建它的群，不用填写群 ID | 选择群聊或个人聊天，每个渠道配置一个目标；个人 Open ID 通过绑定自动获得 |
| 必填参数 | 渠道名称、Webhook、通知事件；按需配置签名密钥 | 渠道名称、App ID、App Secret、通知事件；群聊另需 chat_id，个人通过绑定码配置 |
| 报告趋势图 | 需额外配置自建应用的 App ID 和 App Secret 用于上传图片；否则只发送文字 | 使用同一应用的 App ID 和 App Secret 上传图片并发送 |
| 权限和发布 | Webhook 文本发送不需要应用 API 权限；图片上传应用需相应权限 | 应用需启用机器人能力、授权所需 API 权限并发布生效，机器人需加入目标群 |

这里的 App Secret 是**应用凭据**；自定义机器人的签名密钥来自群机器人安全设置，两者用途不同，不能互换。Webhook 和两类密钥均应保密。

### 群聊自定义机器人

1. 在飞书群添加「自定义机器人」，复制 Webhook；建议启用签名校验并复制签名密钥。
2. 选择「飞书」，填写名称、Webhook、可选签名密钥及事件订阅，保存并启用。
3. 如需报告趋势图，创建飞书自建应用，开启机器人能力并授予下文的图片上传权限，填写该应用的 App ID 和 App Secret。应用密钥加密保存、不回显，编辑留空保留；更换应用 ID 时须同时输入新密钥。未配置应用凭据时报告只发送文字。
4. 系统先使用应用凭据获取 tenant access token，再上传报告 PNG 获得 image_key，通过自定义机器人 Webhook 将图片加入消息卡片或富文本。上传应用与目标机器人组合须在实际租户验证；无效凭据、权限或网络错误会记录投递失败。渠道测试使用示例文本，不测试报告图片链路。
5. 若开启关键词校验，允许固定前缀 **Network Mapping**；若开启 IP 白名单，允许服务实际出口 IP。

仅支持 `https://open.feishu.cn/open-apis/bot/v2/hook/<机器人 UUID>`，不接受任意 Webhook、Lark 国际版域名、查询参数、片段、用户凭据、其他端口和重定向。服务需要允许访问 `open.feishu.cn:443`，无须公开回调入口。

飞书模板支持纯文本或自动转换为 JSON 2.0 消息卡片（`interactive`）的受限 HTML 富文本；默认使用参考邮件信息结构的消息卡片，包含按事件和级别着色的标题、正文和事件 ID。支持粗体、斜体、删除线和链接，下划线按普通文本显示。

签名按官方协议，以 `timestamp + "\n" + secret` 为 HMAC-SHA256 key，对空消息计算摘要并 Base64 编码。HTTP 成功还必须满足 JSON `code == 0`，兼容 `StatusCode`。签名密钥留空保留；移除须明确勾选清除。

协议参考：[飞书自定义机器人](https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot)。

### 应用机器人

1. 登录[飞书开放平台开发者后台](https://open.feishu.cn/app)，创建企业自建应用，在「添加应用能力」中启用机器人。应用类型、可用范围及企业审批按所在租户的要求配置。
2. 在应用的「权限管理」中申请下表的权限；创建并发布应用版本，完成企业管理员审核或授权，使机器人能力、权限和可用范围实际生效。修改权限后也要按飞书提示发布版本。
3. 在应用的凭证与基础信息页面获取 **App ID** 和 **App Secret**。
4. 群聊目标：在目标群添加该应用机器人，获取 **群聊 ID（chat_id）**，通常以 `oc_` 开头。飞书客户端 7.60 及以上可在群聊右上角进入群设置查看群 ID；其他方法见[群 ID 说明](https://open.feishu.cn/document/server-docs/group/chat/chat-id-description)。目标群须允许机器人发送消息。
5. 个人聊天目标：在本平台选择「个人聊天」，填写渠道名称、App ID、App Secret、事件和最低级别并保存。新渠道在绑定前自动停用。保存后在渠道列表点击「绑定个人」，将页面显示的 `/bind ABC123` 指令私聊发送给该应用机器人（实际代码以页面显示为准）。绑定成功后启用渠道；个人用户须在应用可用范围内。
6. 群聊渠道也可点击「绑定个人」切换目标；绑定成功前原群聊配置继续生效。个人渠道可重新绑定或解除绑定，解除后渠道停用并取消尚未完成的投递。每个渠道对应一个接收者，需要多个接收者时创建多个渠道。应用密钥加密保存、不回显，编辑留空保留；更换 App ID 须同时输入新密钥并重新绑定。

#### 个人绑定的事件订阅

绑定需要飞书应用的「接收消息」事件 `im.message.receive_v1` 和单聊消息读取权限 `im:message.p2p_msg:readonly`。在开放平台的「事件与回调」中选择**使用长连接接收事件**并订阅该事件，按飞书要求发布新版本并完成审批。先保存个人渠道或生成绑定码，让后端启动到飞书的连接，再在飞书后台保存长连接订阅；无须配置公网回调地址。应用还需有下表发送消息权限，才能向绑定成功的用户回复并发送通知。

绑定码由服务端随机生成，使用不含 I、L、O、U 的六位 Crockford Base32 字符，有效期 10 分钟且只能使用一次。页面只在生成时展示明文，关闭后可重新生成；请仅将指令交给预期接收者，任何能看到有效代码并向机器人私聊的人都能绑定。可在窗口取消尚未使用的代码；更改渠道配置也会使旧代码失效。无需查询通讯录或手动填写 Open ID。

必须在与该**应用机器人**的单聊中发送纯文本指令，格式为 `/bind ABC123`，其中代码替换为页面最新显示的六位代码，`/bind` 和代码之间使用一个半角空格。不要添加 @、其他文字或换行，也不要在群聊中发送；重新生成后此前的绑定码立即失效。新建个人渠道绑定前保持停用，绑定成功后需在渠道列表手动启用。

连接由服务端主动发起，允许访问 `open.feishu.cn:443` 和飞书返回的 `*.feishu.cn:443` WebSocket 网关，并遵循渠道的系统、直连或指定代理设置；指定代理失败不会自动直连。同一 App ID 的个人渠道和待绑定渠道须使用相同的 App Secret 及代理设置，否则显示配置冲突。同一应用的多个飞书长连接消费者之间事件会被随机分发：不要让其他程序同时使用该应用的长连接接收事件，否则绑定指令可能被其他程序接走。多后端实例共享数据库时由租约协调一个本平台连接，故障切换可能需要等待租约过期。


#### 发送报告图片所需权限

在飞书权限管理中可按权限标识搜索。飞书的[发送卡片文档](https://open.feishu.cn/document/feishu-cards/send-feishu-card)列出了以下两项消息权限；本平台默认报告模板使用消息卡片，建议按该要求配置：

| 权限名称 | 权限标识 | 用途 |
| --- | --- | --- |
| 以应用的身份发消息 | `im:message:send_as_bot` | 以应用机器人身份发送通知和报告卡片 |
| 获取与发送单聊、群组消息 | `im:message` | 飞书发送卡片文档列出的消息权限，支持向配置的群聊或个人发送 |
| 获取与上传图片或文件资源 | `im:resource` | 上传报告趋势图，取得发送时需要的 `image_key` |
| 获取用户发给机器人的单聊消息 | `im:message.p2p_msg:readonly` | 接收个人绑定指令，并订阅 `im.message.receive_v1` 事件 |

权限的申请与实际生效状态以飞书后台和当前接口文档为准。若租户的权限界面或接口要求变化，请核对[发送消息](https://open.feishu.cn/document/server-docs/im-v1/message/create)、[上传图片](https://open.feishu.cn/document/server-docs/im-v1/image/create)及[配置应用权限](https://open.feishu.cn/document/home/message-development-tutorial/turn-on-app-permissions)。仅发送通知不需要接收事件；使用个人绑定时须配置上述单聊消息权限和事件订阅，不需要读取群聊历史。

系统使用 App ID 和 App Secret 获取 `tenant_access_token`，将报告趋势图作为消息图片上传飞书得到 `image_key`，再把图加入报告卡片或富文本消息并发送给配置的目标。图片上传或消息发送失败会记录失败，不会静默降级为纯文本。

#### 验证与排障

1. 在通知渠道点击「测试发送」，然后在投递记录确认状态为成功，并检查目标群或个人聊天是否收到消息。测试入队不等于送达；该测试**不验证图片上传**。
2. 在报告中心打开已生成的报告，通过「发送报告」选择该飞书渠道，确认投递成功并看到趋势图。自动周报、月报还需要订阅对应的报告事件，最低级别须允许 warning。
3. 认证失败时核对 App ID 和 App Secret 是否属于同一应用，以及应用是否已发布；发送失败时核对消息权限、应用可用范围及目标 ID，群聊还需核对机器人是否已入群，个人目标需确认已绑定且用户在应用可用范围内；图片上传失败时核对 `im:resource` 是否授权并生效。还须检查服务端到 `open.feishu.cn:443` 的网络和渠道代理设置。
4. 个人绑定一直等待时，先核对绑定窗口中的连接状态及上面的单聊指令格式。显示「已连接」只表示 WebSocket 已建立，不代表事件订阅已生效或消息已被处理。检查应用的「事件与回调」是否选择长连接并订阅 `im.message.receive_v1`，单聊权限和应用版本是否已生效，发送人是否在应用可用范围内，以及是否有其他程序使用同一应用的长连接。可在飞书开放平台应用的「日志检索 → 事件日志检索」查看发送时段的事件推送记录，辅助区分未推送与接收后处理失败。当前服务端不会记录收到的消息正文或被过滤的具体原因；没有绑定记录不能单独证明事件没有到达。

每个渠道只对应一个群聊或个人目标。更改目标并保存时，旧配置下未完成投递会被取消，已发出的消息无法撤回；需要多个目标时可创建多个渠道。历史应用机器人渠道默认是群聊；旧版前端无法安全编辑个人聊天渠道，须使用配套新版前端。

自定义机器人附加应用凭据的图片链路同样需要验证实际租户中的图片可见性；仅测试 Webhook 文本成功不能证明图片能显示。两种方式发送到飞书的图片无法通过邮件图片撤销功能收回。

## 添加 Telegram 渠道

1. 通过 BotFather 创建机器人，取得 Bot Token。不要将 Token 粘贴到日志、截图或公共文档。
2. 将机器人加入群或频道并授予发消息权限；私聊接收人须先向机器人发送 `/start`。
3. 选择「Telegram」，填写 Token 和 Chat ID。支持非零数字 ID（包括负数群 ID）或公开频道 `@名称`。
4. 选择与邮件、飞书相同的事件类型，保存启用并测试。Token 保存后不回显，编辑留空保留。

后端仅调用固定 `api.telegram.org` 的 `sendMessage` 或 `sendRichMessage`，不接受自定义服务地址或重定向。部署环境需允许 `api.telegram.org:443`。消息由当前事件的已发布 Telegram 模板渲染；可选择普通文本、普通 HTML 或富消息。周报/月报默认使用富消息并上传趋势图，选择普通消息格式则仅发送文本。请求同时验证 HTTP 状态、`ok` 和消息 ID；限流遵守 `parameters.retry_after`，群权限/目标错误直接记录失败。

协议参考：[Telegram Bot API sendRichMessage](https://core.telegram.org/bots/api#sendrichmessage)。

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

通用消息摘要不包含原始 SQL、客户端 IP 或请求正文。登录事件另外提供与邮件共享的 `source_ip` 参数，飞书和 Telegram 默认模板也会展示登录来源地址；测试使用固定示例。Webhook、Bot Token、SMTP 密钥和服务商原始错误正文不会写入投递历史。

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
| POST / GET / DELETE | `/channels/{id}/feishu-binding` | 管理员生成绑定码、查询状态、取消待绑定代码；POST body 为 `{"expected_revision":1}` |
| DELETE | `/channels/{id}/feishu-binding/recipient` | 解除个人绑定并停用渠道，body 为 `{"expected_revision":1}` |
| POST | `/channels/{id}/test` | 固定连通性测试入队，返回 202 和 delivery_id |
| POST | `/templates/{provider}/{event}/test` | 当前模板及所选级别的示例数据入队，不保存或发布 |
| GET | `/deliveries/{id}` | 查询单条测试投递结果 |
| GET | `/deliveries` | 按 channel_id/status 筛选、游标翻页 |
| POST | `/deliveries/{id}/retry` | 重试仍符合条件的 failed 记录 |

共用字段为 `provider,name,enabled,event_types,minimum_severity,expected_revision`。`provider` 支持 `email/feishu/telegram`，旧飞书客户端未传时默认 feishu。

- 飞书：`settings.feishu_bot_type` 为 `webhook` 或 `app`，历史缺省为自定义机器人。自定义机器人使用 `webhook_url,signing_secret,clear_signing_secret`，可选 `settings.feishu_app_id,feishu_app_secret,clear_feishu_app_secret` 以发送报告图片。应用机器人填写 `settings.feishu_app_id,feishu_app_secret` 和目标：`settings.feishu_target_type` 为 `group` 时填写 `settings.feishu_chat_id`，为 `user` 时可使用绑定接口自动取得 `settings.feishu_open_id`；未绑定的个人渠道必须停用。历史应用渠道缺省为群聊。编辑已有个人渠道时必须明确提供目标类型，避免旧客户端覆盖目标。应用密钥仅写入，响应通过 `feishu_app_secret_configured` 表示是否配置。
- Telegram：`bot_token,settings.chat_id`。
- 邮件：`smtp_password,settings.smtp_host,settings.smtp_port,settings.smtp_sender,settings.recipients`。

响应使用 `{success,data}`，仅包含凭据是否配置；DELETE body 为 `{"expected_revision":1}`。编辑凭据留空保留，不可通过 provider 变更复用别类凭据。

升级时先停止所有旧后端实例，再启动新版后端；迁移完成后只运行新版，避免旧 worker 继续发送已转移的队列或误领新增类型。启动自动执行幂等迁移，`init.sql` 与升级脚本一致。保留 `server.encrypt_key`，否则无法解密历史凭据。回滚前先停用新增的邮件和 Telegram 渠道，再回退前后端；仅支持飞书的旧版本不能处理新 provider。新增表保留即可。SMTP 一次性导入后，以统一页面订阅为准，不从旧偏好重复恢复渠道。

飞书应用机器人需要新前后端配套，先升级全部后端再升级前端。回退到不支持应用机器人的后端前，删除应用机器人渠道并处理其未完成投递；旧版无法解析新增的渠道配置。群聊自定义机器人的原有配置继续使用。

个人聊天渠道也要求先升级全部后端再升级前端；回退到不支持个人目标的后端前，删除个人聊天渠道并处理其未完成投递，避免旧 worker 无法解析个人渠道配置。

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

测试覆盖三类渠道的同级扇出、独立启停和事件选择、凭据保留/不回显、SMTP 导入幂等、旧队列部分成功迁移与去重、历史掉线回执及目标变更、登录隐私、报告归档后入队、并发领取、租约、维护切换与旧有 Scanner 恢复。HTTP 使用本地 fixture；没有真实机器人/SMTP 凭据和允许出口时，不将本地检查表述为外部联调成功。

## 每渠道投递代理

创建/编辑邮件、飞书和 Telegram 渠道时可选择沿用系统、直连或指定代理。system 保持旧行为：HTTP 读取环境代理，SMTP 自身直连；direct 明确不使用 HTTP 环境代理；custom 仅使用指定代理，连接失败不回退直连。不修改进程全局代理变量，各渠道独立建立客户端/连接。

支持 `http://host:port`、`https://host:port`、`socks5://host:port` 和 `socks5h://host:port`。HTTP/HTTPS 可使用默认端口，SOCKS 必须给端口；SOCKS4 不支持。SOCKS5 在服务端解析最终目标，SOCKS5H 把名称交给代理。可在 URL 中填写用户名和密码，特殊字符需 URL 编码；SOCKS 用户名和密码必须同时提供。代理 URL 最多 2048 字节，认证项最多 255 字节，不接受控制字符、路径、query 或 fragment。

HTTPS 代理表示连接到代理本身也使用 TLS；普通 HTTP 代理同样可通过 CONNECT 访问 HTTPS/SMTPS 目标。代理地址及认证信息仅用于后端出站连接，浏览器不会通过这些代理发通知。飞书/Telegram 的固定目标校验和禁重定向仍生效。

邮件通过 SOCKS 或 HTTP(S) CONNECT 建立隧道后，再对真实 SMTP 主机执行 SMTPS TLS/SNI/证书校验及认证，保留单 envelope/Bcc 语义。HTTPS 代理的证书与 SMTP 目标证书分别验证，不能以代理域名代替 SMTP 域名。隧道及发送使用统一超时预算，不支持降级明文或静默改为 STARTTLS。代理可能限制连接非 443 端口，需允许实际 SMTPS 端口。

新请求字段为 proxy_mode（system/direct/custom，可省略保留旧值）、proxy_url（写入专用，编辑留空保留）、clear_proxy（显式清除，可省略；不能同时替换，custom 模式下须先改为 system/direct）。首次选择 custom 必须提供 URL。切换到 system/direct 会清除已存代理 URL。旧客户端不带代理字段时保留已有配置。

代理完整 URL 单独存入加密的 proxy_ciphertext，使用现有 server.encrypt_key；不复用 Bot Token/SMTP 密码/飞书密钥，也不放进可回显的 settings。API 只返回 proxy_mode、proxy_configured 和移除用户名/密码后的 proxy_endpoint；代理认证信息不写入审计、投递记录和错误日志。

保存代理会更新渠道 revision 并按既有规则取消旧排队/在途投递；已经发送的请求不能撤回。仅修改代理不改变 destination_revision，因此原有掉线成功回执仍可关联后续恢复通知。多个渠道不会串用代理。模板测试、手工完整报告邮件及旧 SMTP 测试读取与原传输选择一致的首个未删除邮件渠道代理，避免这些路径静默直连。报告和模板发送以一次查询读取完整 SMTP 目标、密码与代理，避免配置并发变更时混用渠道。

启动时执行 source/database/migrate_notification_proxies.sql（幂等），已有渠道默认 system。先部署后端再部署前端。降级到不支持代理的版本前停用自定义代理渠道，避免旧 worker 直接连接。保留新增列与加密主密钥。

验证包括 HTTP/HTTPS CONNECT、SOCKS5/5H、认证失败、卡住的代理、SMTP 目标 TLS/错误主机名/不可信证书、Bcc、编辑保留与清除、目标版本保持和旧邮件路径代理选择。使用隔离本地 TLS/代理 fixtures，不需要真实通知凭据；本地测试不代表部署网络中的代理可访问。
