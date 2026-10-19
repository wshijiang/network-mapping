# 登录人机验证

[文档中心](README.md) · [部署指南](DEPLOYMENT.md) · [Docker 配置参考](DOCKER_CONFIGURATION.md)

服务端可选使用 Cloudflare Turnstile 保护密码登录。默认关闭，旧配置和旧登录请求继续可用；启用后，每次 `POST /api/login` 必须携带由小组件取得的证明，并由服务端在密码查询和 Session 创建前验证。

## 部署与启用

先部署支持人机验证的服务端及配套 Vue 前端，再配置开启。服务端镜像使用 `.github/frontend-ref` 固定前端提交；自行替换静态资源时也需使用支持公开配置接口的配套版本。Vue 前端通过服务端读取公开配置，无需重新构建来更换 site key。Cloudflare 账户中创建 Managed 类型 widget，为实际登录域名配置允许列表，并取得 site key 和 secret key。

管理员进入 **设置 → 登录保护**（`/setting/human-verification`），选择 Cloudflare Turnstile，填写 Site Key、Secret Key 和允许域名后保存。页面还可调整超时、单实例并发上限及是否发送访问者 IP。保存成功后新的密码登录使用当前配置，已打开的登录页需刷新，以更新小组件和 CSP。

Secret Key 加密保存在 PostgreSQL，读取接口只返回“是否已配置”。留空表示保留已有 Secret；替换时填写新值；停用后可以显式勾选清除。加密使用 `server.encrypt_key`，请保管并备份该主密钥，恢复数据库时必须使用同一主密钥。不要把 Secret 写入变更说明。

配置首次从文件或环境变量初始化，数据库已有记录时不会被启动配置覆盖。无需新增数据库迁移，复用现有配置及修订表。启动文件仍须合法。以下文件配置只作为首次初始化种子（使用 `--config-source file`）：

```toml
[human_verification]
provider = "turnstile"                  # 默认 none；none 时不加载外部组件
actions = ["login"]
timeout_ms = 3000
connect_timeout_ms = 1000
max_in_flight = 32
send_remote_ip = false

[human_verification.turnstile]
site_key = "replace-with-public-site-key"
secret_key = "replace-with-server-secret"
allowed_hostnames = ["console.example.com"]
```

`actions` 当前必须为 `["login"]`。允许域名按标签边界匹配其本身和所有层级子域名（忽略 ASCII 大小写），与 Cloudflare Hostname Management 一致。例如 `example.com` 包含 `console.example.com` 和 `a.console.example.com`；`console.example.com` 不包含父域、兄弟域或 `notconsole.example.com`。不接受协议、路径、端口或通配符。开启时 site key、secret key、域名列表均必填，配置错误会拒绝启动。旧配置缺少整个段时默认关闭。升级后原有允许域会覆盖其后代；需要缩小范围时请配置具体的登录域。仍严格校验 Siteverify 的 success、hostname 和 action。

`timeout_ms` 为整个外部验证流程的预算，范围 500–10000ms；`connect_timeout_ms` 必须大于零且不超过总预算。`max_in_flight` 为所有 HTTP worker 共享的单进程并发上限，范围 1–256。达到并发上限立即拒绝，不无限排队。在页面保存后对新请求生效，已经开始的验证按原配置完成。

Docker/env 模式使用对应环境变量，完整清单见 [Docker 配置参考](DOCKER_CONFIGURATION.md#登录人机验证)：

```dotenv
NM__HUMAN_VERIFICATION__PROVIDER=turnstile
NM__HUMAN_VERIFICATION__TURNSTILE__SITE_KEY=replace-with-public-site-key
NM__HUMAN_VERIFICATION__TURNSTILE__ALLOWED_HOSTNAMES=["console.example.com"]
NM__HUMAN_VERIFICATION__TURNSTILE__SECRET_KEY_FILE=/run/secrets/turnstile_secret
```

先通过 Compose Secret 或只读挂载提供容器内密钥文件。`_FILE` 与直接的 `NM__HUMAN_VERIFICATION__TURNSTILE__SECRET_KEY` 互斥，即使直接值为空也不能同时设置。不要将真实密钥放入源码、前端 `VITE_*`、镜像构建参数、日志或公开配置响应。env 模式与文件模式独立，env 不覆盖文件模式。

更新容器启动环境需使用 Compose `up -d --force-recreate`；但数据库已有配置时，修改环境变量或文件不会覆盖页面保存的策略。日常调整和停用请使用管理页面。共享同一数据库的实例在每次登录页、公开配置和密码登录请求时读取权威版本，无需重启同步；所有实例必须使用相同的 `server.encrypt_key`。

## 网络、CSP 与行为

浏览器需要加载 `https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit` 及其 iframe；服务端需要通过 HTTPS 访问同域名下的 Siteverify。浏览器和服务端的网络路径应分别验收。此功能不要求网站流量经过 Cloudflare 代理。

开启时服务端为现有 CSP 增加 `script-src 'self' https://challenges.cloudflare.com` 和 `frame-src https://challenges.cloudflare.com`；关闭时保持原有 CSP。如果上游代理也发送 CSP，需同步允许这两种来源。默认不发送 Siteverify 可选的 `remoteip`；启用 `send_remote_ip` 时复用既有可信代理解析结果，不直接信任客户端转发头。

仅保护密码登录，不改变 TOTP、CSRF、账号/IP 限制和登录限流。人机校验通过后仍须通过原有身份验证。扫描器、开放 API、健康检查及已登录会话不需要浏览器挑战。TOTP 阶段不重复使用密码阶段的 token。

证明单次使用；前端在每次登录尝试之后刷新，过期后也会刷新。服务端检查厂商结果中的 `success`、hostname 和 action=`login`。外部服务超时、密钥失效、非法响应和并发耗尽均停止本次登录，不自动关闭保护；验证结果不缓存，也不自动重试。现有限流仍先于外部验证执行。

## API 与排障

管理接口要求管理员身份，写入沿用现有 CSRF 保护，响应不缓存：

- `GET /api/config/human-verification`：返回 `data.revision`、`data.document` 和 `data.secret_key_configured`，不返回 Secret 或密文。
- `PUT /api/config/human-verification`：保存完整配置。示例：

```json
{
  "expected_revision": 1,
  "document": {
    "provider": "turnstile",
    "site_key": "replace-with-public-site-key",
    "allowed_hostnames": ["console.example.com"],
    "timeout_ms": 3000,
    "connect_timeout_ms": 1000,
    "max_in_flight": 32,
    "send_remote_ip": false
  },
  "secret_key": "replace-with-server-secret",
  "clear_secret": false,
  "change_reason": "启用登录保护"
}
```

允许域名最多 32 项，保存时去重并转为小写。`secret_key` 为空或省略时保留当前值；`clear_secret=true` 表示清除，不能同时传入新 Secret，启用状态不能清除必需密钥。请求体上限 16KiB。版本冲突返回 409，页面保留输入并要求重新加载，避免覆盖其他管理员的修改。配置、修订及操作审计在同一事务内提交；修订文档只保存加密后的 Secret，审计只记录版本、服务商及密钥是否变更。此域使用独立接口，不通过 `/api/config/runtime/{namespace}` 管理。

`GET /api/auth/human-verification`（也支持 HEAD）无需登录，仅返回 `schema_version`、provider、受保护动作及 widget 公开参数，并设置 `Cache-Control: no-store`。不返回 secret 或私有部署参数。

读取权威配置失败、记录丢失或配置不可用时，新的登录页、公开配置及密码登录返回 503，不使用旧的“关闭”缓存继续登录。现有会话仍按原规则处理。登录页和公开配置受匿名限流保护。

启用后的登录 JSON：

```json
{
  "username": "example-user",
  "password": "example-password",
  "human_verification": {"token": "opaque-provider-token"}
}
```

客户端不能通过传入 provider、action 或关闭标记跳过服务端配置。登录 JSON 请求体上限为 16KiB，不改变扫描器等其他接口的全局请求体上限。

| HTTP | code | 建议处理 |
| --- | --- | --- |
| 400 | `human_verification_required` | 升级配套前端并完成人机验证；旧客户端在开启后不能继续无证明登录 |
| 400 | `human_verification_invalid_input` | 清除错误证明并重新验证 |
| 403 | `human_verification_failed` | 重新验证；检查域名配置和 action |
| 503 | `human_verification_unavailable` | 按 `Retry-After` 等待，检查服务端外联、密钥及并发预算 |
| 429 | `rate_limit_exceeded` | 按 `Retry-After` 等待，保留既有登录限流 |

响应沿用 `success`、`code`、`message`、`request_id`。通过 request ID 关联请求日志与 `HumanVerificationDenied` 事件；原因仅使用归一化分类，不记录密码、证明或 secret。校验失败不会作为密码错误更新账号状态，也不会创建 Session 或签发认证 Cookie。

若登录页显示“登录验证配置加载失败”，先检查服务端版本、公开接口是否被代理拦截以及网络；前端不会把 404/请求失败视为关闭。若组件加载失败，检查浏览器网络和代理 CSP，恢复后点击重新验证。

## 验收与停用

在预生产使用 [Cloudflare 官方测试 key](https://developers.cloudflare.com/turnstile/troubleshooting/testing/) 验证通过、拒绝和重复错误场景，单独验证域名/action 契约。测试 key 的响应可能不包含生产配置所需的 action/hostname；不能为此在生产逻辑中关闭这些校验。生产应换用真实 key，并在实际浏览器和目标网络中验收。

停用时在“设置 → 登录保护”选择“关闭”并保存，刷新登录页确认组件和 CSP 恢复关闭。需要删除密钥时同时勾选清除 Secret。若回退到不提供公开配置接口的旧服务端，先恢复兼容的旧前端，并按旧版本要求同步部署配置；旧版本不会读取本页面保存的策略。

实现回归：`cargo test --lib human_verification`、配置测试、错误响应/TOTP 测试，以及配套前端的 `test:human-verification` 和生产构建。HTTP mock 覆盖 Siteverify 拒绝、域名/action 错配、非法响应、超时及并发限制，不依赖真实密钥。独立 PostgreSQL 集成测试默认忽略，需将 `HUMAN_VERIFICATION_TEST_DATABASE_URL` 指向可创建隔离 schema 的开发数据库，再执行 `cargo test --lib human_verification::settings::tests::web_configuration_lifecycle -- --ignored`；覆盖管理员/CSRF、加密持久化、并发冲突、多实例新请求生效及配置丢失拒绝登录。

官方接口说明：[服务端验证](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/) · [小组件配置](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/widget-configurations/)。
