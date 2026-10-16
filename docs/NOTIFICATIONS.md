# 通知渠道与飞书接入

[返回文档中心](README.md)

## 当前能力与入口

管理员在 Web 控制台的「设置 → 通知渠道」（`/setting/notifications`）管理飞书群自定义机器人。
支持添加、修改、启用、停用、删除、测试发送、按渠道/状态筛选投递记录及重试失败投递。
通知渠道不依赖 SMTP、管理员邮箱或邮件模板。原有邮件通知开关仍只控制邮件。

当前可订阅：

| 事件 | 说明 | 级别 |
| --- | --- | --- |
| `health.alert` | 慢请求、5xx、慢 SQL、慢 Elasticsearch 操作及 Elasticsearch 异常 | 沿用健康告警的 warning/critical |
| `scanner.offline` | 持续无心跳超过掉线策略阈值 | warning |
| `scanner.recovered` | 已通知掉线的 Scanner 恢复有效心跳 | warning |
| `notification.test` | 管理员手动测试，仅发往选择的渠道 | 不受订阅及最低级别过滤 |

选择「仅严重」会过滤 Scanner 掉线/恢复。健康信号仍受运行策略中的监控开关和规则控制；
Scanner 检测仍使用现有掉线阈值、检查周期和维护宽限。新增渠道不会补发历史事件。
登录通知、任务完成/错误、日报、周报/月报摘要及 Telegram 尚未接入此渠道系统。

## 配置飞书机器人

1. 在目标飞书群添加「自定义机器人」，复制 Webhook 地址。
2. 建议开启签名校验，复制签名密钥。开启后必须在平台填写一致的密钥。
3. 在「通知渠道」添加渠道，填写名称、Webhook、签名密钥，选择事件和最低级别，保存并启用。
4. 点击「测试发送」。界面显示「已入队」表示请求已持久化；以投递记录的「发送成功」和群内实际消息为验收依据。
5. 在运行策略中配置健康监控及 Scanner 状态策略，再观察实际告警。

仅支持 `https://open.feishu.cn/open-apis/bot/v2/hook/<机器人 UUID>`。
不接受任意 Webhook、Lark 国际版域名、用户名密码、查询参数、片段、非 443 端口或重定向。
如机器人开启关键词校验，请配置固定前缀 **Network Mapping**；如开启 IP 白名单，应允许服务实际出口 IP。
所有飞书请求使用继承的代理、受信任 CA 和 TLS 校验；运行环境须允许访问 `open.feishu.cn:443`。
不需要向公网开放机器人回调入口。

飞书签名按官方协议，以 `timestamp + "\n" + secret` 为 HMAC-SHA256 的 key，对空消息计算摘要并 Base64 编码。
每次尝试重新生成时间戳和签名。HTTP 成功后还必须验证 JSON `code == 0`；兼容旧响应的 `StatusCode`。
响应缺失业务码、非 JSON、HTTP 429/5xx 及已识别的限流业务码进入有限重试；签名/权限等业务拒绝直接标记失败。
协议与配额依据：[飞书自定义机器人官方文档](https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot)。

## 编辑、停用和凭据

- Webhook 和签名密钥均加密保存，列表/API 不回传明文、密文或完整 URL，只显示是否已配置。
- 编辑时 Webhook、签名密钥留空表示保留；移除签名必须勾选「清除已保存的签名密钥」。
- 每次保存携带 `expected_revision`，并发编辑版本不符返回 409，应刷新并重新编辑。
- 修改、停用或删除渠道会取消旧配置下的 pending/sending 记录。已发出的网络请求无法撤回，仍可能到达飞书。
- 再次启用只处理新事件，不恢复已取消通知。未更换 Webhook 的渠道继续保留同一目标身份；更换 Webhook 后不会沿用旧目标的掉线收据生成恢复消息。
- 凭据依赖服务现有 `server.encrypt_key`。部署升级应保留此密钥；本功能不自动迁移/轮换主加密密钥。
- 渠道写操作、测试、重试与操作审计在同一数据库事务提交。只有管理员可以使用这些接口，写操作受现有会话与 CSRF 校验保护。

群消息包含系统前缀、类型/级别、平台告警记录或 Scanner 标识及事件 ID；不发送原始 SQL、请求正文、客户端 IP 或完整健康告警详情。
Webhook、签名密钥和飞书原始响应正文不写入投递记录或错误日志。

## 投递与恢复语义

事件与初始投递在 PostgreSQL 事务内写入。健康告警历史、跨实例冷却门和飞书事件同事务提交；
Scanner 掉线事件与 incident 同事务提交。投递队列使用 `FOR UPDATE SKIP LOCKED`、领取令牌和 60 秒租约，
完成更新必须匹配有效领取令牌，进程中断后的过期租约可再次领取。

通知已入库后采用**至少一次**交付，不能承诺 exactly-once：飞书接受后、发送成功落库前崩溃或超时，重试可能重复。
消息附带稳定事件 ID 供定位。健康告警进入数据库前仍使用现有 1024 容量内存队列，满时可能丢弃，服务重启也可能丢失尚未入库事件；
本功能没有将请求链路改为同步写库。健康告警的数据库冷却在多实例/重启之间生效，并允许从 warning 立即升级 critical。
本地冷却缓存只记录数据库接纳的事件，共享冷却拒绝的重复事件不会重新开始本地计时。

默认约束：

| 项目 | 当前值 |
| --- | --- |
| 有效渠道 | 最多 32 个 |
| 同渠道测试 | 每 30 秒最多入队一次，须已启用 |
| 同渠道发送 | 数据库协调，最多每秒一次；建议每个机器人只配置一个渠道 |
| 单次请求/整体投递尝试 | 10 秒 / 20 秒 |
| 尝试次数 | 每轮最多 5 次，含初次；手动重试开启新一轮 |
| 自动重试间隔 | 60、120、240、480 秒；有效 Retry-After 更长时按其等待 |
| 事件有效期 | 24 小时；超过后取消，不无限补发过时告警 |
| 请求/响应正文上限 | 20 KiB / 16 KiB |
| 记录保留 | 终态事件通常保留 30 天；未结束的 Scanner incident 收据保留至恢复后 30 天 |
| 投递列表 | 每页 50 条，`before` 游标翻页 |

每次领取飞书投递前检查维护状态；批次处理中开启维护时，已在途请求允许结束，后续记录保持待处理，退出维护后继续领取。
过期或失效记录按批次连续清理，不占用真实发送的每秒配额。
Scanner 恢复会取消尚未发送的掉线通知，恢复通知只发给同一目标已成功收到掉线消息且当前仍订阅恢复的渠道。
掉线发送尚未完成时，恢复事件对账等待发送状态收敛；停用/删除 Scanner 不发送恢复。

## 排障

| 现象 | 排查方式 |
| --- | --- |
| 测试返回 409 | 渠道是否启用、是否在 30 秒测试间隔内；配置版本是否过时 |
| HTTP 200 仍失败 | 查看「飞书」业务码；检查签名、关键词、出口 IP 白名单 |
| 网络或 TLS 失败 | 检查域名出口策略、代理、CA 信任及机器时间，不关闭 TLS 校验 |
| 一直 pending | 检查计划时间、维护状态、后台 notification-worker 和数据库可用性 |
| `secret_unavailable` | 检查服务主加密密钥是否与保存凭据时一致，必要时重新保存渠道凭据 |
| 无 Scanner 恢复通知 | 必须曾向同一目标成功发送掉线；恢复事件须被订阅，且最低级别允许 warning |
| 改配置后记录 cancelled | 这是取消旧配置投递的预期行为；保存后重新测试 |

修复配置后可对 failed 记录执行重试。已过期、目标改变、Scanner 已恢复等记录不再具有发送条件时会拒绝或取消。

## 管理接口与部署

所有接口位于 `/api/notifications`，沿用管理员会话，写请求附带 `X-CSRF-Token`。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET / POST | `/channels` | 列出 / 创建飞书渠道 |
| PUT / DELETE | `/channels/{id}` | 按版本修改 / 软删除 |
| POST | `/channels/{id}/test` | 持久化测试投递，返回 202 与 delivery_id |
| GET | `/deliveries` | channel_id、status、before 筛选及翻页 |
| POST | `/deliveries/{id}/retry` | 重试仍符合条件的 failed 记录 |

创建/修改字段：`name,enabled,event_types,minimum_severity,webhook_url,signing_secret,clear_signing_secret,expected_revision`。
创建时 Webhook 必填；修改时版本必填。DELETE body 为 `{"expected_revision":1}`。
响应使用 `{success,data}`；错误只返回公开原因，不回显输入凭据。

启动迁移自动执行 `source/database/migrate_notifications.sql`；全新 `init.sql` 同步包含这些表。
后端和前端需配套发布。回滚时先停用新渠道，再回退应用版本；保留新增表和数据，旧版服务可忽略这些表。
后续 Telegram 应新增渠道 provider 与对应发送适配器，复用事件、订阅、队列、管理员接口和投递记录。
当前实现没有 Telegram Token/Chat ID 字段，也不会调用 Telegram API。

## 开发验证

在后端仓库运行：

```bash
source /workspace/.cloud/env.sh
CARGO_TARGET_DIR=/workspace/.cloud/target cargo test --locked --lib notification::
# 使用可销毁的隔离开发 PostgreSQL；测试为每次运行创建并清理独立 schema。
NOTIFICATION_TEST_DATABASE_URL='host=127.0.0.1 user=network_mapping dbname=network_mapping' \
  CARGO_TARGET_DIR=/workspace/.cloud/target cargo test --locked --lib notification:: -- --ignored
```

单元检查覆盖签名向量、URL 约束、飞书业务响应、凭据加密、管理员与 CSRF 限制；
数据库检查覆盖迁移幂等、版本冲突、配置保密、旧队列取消、共享冷却、独占领取、过期租约恢复、重试、Scanner 恢复目标，以及批次中开启维护后暂停领取、允许在途完成和退出后续投。
没有机器人凭据和允许出口时，不能把这些本地检查当作真实飞书联调成功。
