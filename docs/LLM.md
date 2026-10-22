# LLM 配置、供应商与在线调试

[文档中心](README.md) · [威胁情报与人工审核](THREAT_INTELLIGENCE.md)

控制台新增 **LLM → 基础 / 供应商**。所有管理、模型刷新和调试接口均限管理员，沿用浏览器登录与 CSRF 校验。

## IOC 提取与在线调试

基础页为 IOC 提取保存唯一的供应商与模型组合。启用前必须选择该供应商中可用且协议已支持的模型；暂停会保留选择。创建供应商或修改供应商默认模型不会自动切换现有提取组合。供应商默认模型只用于首次选择时预填。

原威胁情报页面保留实际启用状态和模型摘要，完整配置移至 LLM。可信结构化 IOC 同步独立运行。模型输出仍经过原文证据校验并生成待审提议，不能绕过人工审核。

在线调试支持临时选择其他供应商和模型、多轮对话、停止生成和新建会话。临时选择不修改 IOC 绑定；切换组合会清空当前对话。对话只保留在当前页面，服务端不建立聊天历史库。未完整、失败或已停止的模型回答不会作为后续对话历史发送。界面以纯文本显示回答。

启用流式后分别接收思考数据与正式回复。思考时显示带 `skeleton skeleton-text` 的
`Thinking...`，默认收起，可点击箭头展开；首段正式回复到达时自动收起，回复继续显示在下方聊天气泡。
完成、出错或停止后停止思考动画，仍可展开已有思考数据；思考文本不加入下一轮聊天历史。
Chat 兼容接口读取 `reasoning_content` / `reasoning`，Responses 读取接口实际返回的思考文本或摘要，
开启推理时在调试请求中申请 `reasoning.summary=auto`。关闭流式时在完整响应后显示可展开的思考数据。完成后展示耗时及供应商实际返回的 token 用量；用量缺失不等于零。
在回复信息的“流式开启／关闭”后显示平均输出速率（token/s），按输出 token 数除以请求总耗时计算，
包含等待和思考时间。生成期间显示“统计中”，缺少用量、失败、停止或耗时无效时显示“—”。
输出速率后显示缓存命中输入 token 数和命中率（缓存命中 token 数 ÷ 输入 token 总数）。
已返回的零命中显示 `0 token`、`0.0%`；未提供缓存用量显示“—”，输入为零或数据无效时不计算命中率。
Chat 流式调试请求使用 `stream_options.include_usage=true` 获取最终用量，不按字符数或分片数估算。在线调试会调用真实供应商，按该供应商账户规则计费。每个管理员同时最多一个调试请求，每实例最多四个；页面断开或停止会取消上游读取，不自动重放付费请求。

## 供应商与模型

供应商支持添加、修改、删除，以及 API 地址、模型列表 URL、API Key、环境变量备用来源、默认协议、模型列表、默认模型、局部请求设置、超时、输出预算和推理强度。

支持 Chat Completions 和 Responses。模型可覆盖供应商默认协议。完整端点必须与该模型协议匹配；以 `/v1` 结尾的基础地址只追加一次 `/chat/completions` 或 `/responses`，其他完整自定义端点原样使用。一个供应商中混用两种协议时，优先配置基础地址。

| 内置模板 | 推理基础地址 | 模型列表地址 |
| --- | --- | --- |
| DeepSeek | `https://api.deepseek.com/v1` | `https://api.deepseek.com/models` |
| OpenCode Go | `https://opencode.ai/inference/go/openai/v1` | `https://opencode.ai/inference/go/v1/models` |
| CommandCode GOAT | `https://api.commandcode.ai/provider/v1` | `https://api.commandcode.ai/provider/v1/models` |

模板创建普通的可编辑供应商，不带凭据、不自动启用，升级不覆盖用户配置。GOAT 使用 CommandCode Provider API，不要省略 `/provider`；OpenCode Go 的模型列表与推理接口使用不同前缀。

刷新模型使用已保存的供应商地址和凭据，仅载入编辑草稿，保存后才生效。兼容 OpenAI `data`、`models` 和直接数组列表，识别 `supported_endpoints`；旧模型缺失时保留并标为不可用，刷新失败保留原草稿。允许手工添加、修改和删除。不能移除当前绑定的模型，需先在基础页更换组合或清空选择。

刷新 API 自身返回远端目录与已保存模型的合并结果；缺失项保留名称及手工协议，空目录会将全部旧模型标为不可用。模型重新出现后恢复可用。保存草稿前需重新选择已失效的默认模型；当前 IOC 绑定失效时也须先更换或清空绑定。刷新本身不改变正在使用的配置。

OpenCode Go 的目录含不同协议。模型没有可靠的协议元数据时标为“待确认／未适配”，需按官方模型文档手工选择 Chat 或 Responses。Anthropic Messages、Google 原生协议尚未适配，不能作为 IOC 或调试模型选择。模型目录不保证账号具备调用权限。

删除当前供应商时可确认“同时暂停 IOC 提取”，服务端在同一事务清空绑定并删除。旧历史提议及已审核情报保留。

## 全局与局部配置

| 项目 | 全局 | 供应商局部 |
| --- | --- | --- |
| 网络代理 | 系统 / 直连 / 指定 | 继承 / 系统 / 直连 / 指定 |
| 请求头 | 使用列表 / 禁用 | 合并全局并覆盖同名项 / 替换列表 / 禁用 |
| Session | 关闭 / 自动 / 固定值 | 继承 / 关闭 / 自动 / 固定值 |
| 流式传输 | 开 / 关 | 继承 / 开 / 关 |

初始配置为系统代理、无额外头、session 关闭、流式关闭。局部“关闭”和“直连”均为显式覆盖，不代表继承。

代理支持 HTTP、HTTPS、SOCKS5、SOCKS5H 及认证。指定代理失败不回退直连，直连显式禁用系统代理。只影响 LLM 推理和模型列表请求，不改变文章来源抓取、可信情报源或通知渠道的网络设置。

头名称不区分大小写。基础 API Key 生成 Bearer Authorization，随后应用全局头和供应商局部头，因此自定义 Authorization 可覆盖 API Key。合并模式可移除某个继承项。Host、Content-Length、Connection、Transfer-Encoding、Cookie 等传输相关头不可自定义。动态 session 头和自定义头重名时拒绝保存。

API Key、完整代理配置、自定义头值和固定 session 值通过现有 AES-GCM 封装加密存储，读取接口不回显。编辑时空值加“已配置”标记表示保留；删除头行表示清除，API Key 使用显式清除选项。数据库凭据优先于环境变量；解密失败不读取另一个凭据替代。

没有数据库 API Key、备用环境变量未设置或为空时，只要继承与覆盖后仍有有效的 Authorization 请求头，在线调试、模型刷新和 IOC 提取均可使用该头认证。局部禁用或移除继承的 Authorization 后不再视为已配置认证；数据库密钥解密失败、环境变量引用非法仍会阻断请求，不改用认证头绕过错误。清除数据库 API Key 后适用同一规则。控制台勾选清除时省略已输入的替换密钥；直接调用 API 时仍不能同时提交非空 credential 与 clear_credential=true。

## Session 与 OpenCode

支持自定义 session 头名称，例如 `x-opencode-session`。自动模式中，同一调试会话沿用稳定标识；新建会话时轮换。IOC 标识由文章、正文版本及运行配置版本区分，避免跨文章共用。固定模式使用管理员明确填写的值。

OpenCode 的 `x-opencode-session` 表示路由／缓存亲和性，不是服务端聊天历史 API；应用仍发送当前多轮消息。当前实现不会复制 OpenCode 登录状态、浏览器 Cookie 或应用登录 session。Session 头只发给推理接口，不发给模型列表接口。

依据：

- [async-openai 0.42.2 自定义头](https://github.com/64bit/async-openai/blob/async-openai-v0.42.2/async-openai/src/config.rs)
- [async-openai 流式与自定义传输](https://github.com/64bit/async-openai/blob/async-openai-v0.42.2/async-openai/src/client.rs)
- [OpenCode session 请求头](https://github.com/anomalyco/opencode/blob/dev/packages/core/src/session/model-request.ts)
- [OpenCode Go 端点](https://github.com/anomalyco/opencode/blob/dev/services/www/src/docs/content/console/go.mdx)
- [CommandCode Provider](https://commandcode.ai/docs/provider)

## API 与运行约束

响应沿用 `{success,data}` 和固定错误代码；秘密、完整上游错误和模型文本不写入审计。

| 方法与路径 | 用途 |
| --- | --- |
| GET `/api/llm/settings` | 单选状态、全局配置、供应商、模板、生效摘要和 revision |
| PUT `/api/llm/settings` | 保存全局及唯一绑定；携带 expected_revision |
| GET/POST `/api/llm/providers` | 读取状态 / 添加供应商 |
| PUT `/api/llm/providers/{id}` | 修改供应商和模型列表；携带 expected_revision |
| DELETE `/api/llm/providers/{id}` | 删除；携带 expected_revision，可用 pause_extraction 同时暂停 |
| POST `/api/llm/providers/{id}/models/refresh` | 读取远端模型，不自动写入配置 |
| POST `/api/llm/debug/chat` | 传 provider_id、model_id、session_id、messages，返回 SSE |

新增与修改供应商的请求为 `{expected_revision,provider}`。调试消息只接受 system（仅首条）、user、assistant 文本，最多 64 条且总内容不超过 128 KiB。SSE 事件为 started、reasoning（思考文本增量）、delta（正式回复增量）、done、error；
非流式 done 可包含 reasoning 文本字段，Responses 的 done 可补齐最终摘要；done 为完整成功，EOF 不作为成功。前端使用 POST fetch 传 CSRF 头，并使用 AbortController 停止。

真实出站延续 HTTPS/443、公网目的地址、DNS 校验、TLS 验证及禁止重定向规则。模型列表上限 2 MiB、500 项；推理响应总上限 16 MiB，流式单行上限 1 MiB。请求超时 1～1800 秒，连接阶段最多 10 秒。代理远端解析目的地址时，代理需执行相同的公网出站边界。

两种协议的流式输出均等待正常完成后才进入 IOC 校验，Chat 检查结束标记，Responses 检查 completed 状态；断流、截断、取消或错误不写入半成品。一次队列尝试仅发一次付费请求。

## 迁移、并发与部署

启动在原威胁情报迁移之后执行 `migrate_llm.sql`。旧 AI 设置生成“迁移的 LLM 供应商”，保留原端点、模型、协议、超时、预算、推理强度、环境变量引用及加密凭据。迁移幂等，不重复添加或覆盖新配置。

新表为 `llm_settings`、`llm_provider`、`llm_model`，数据库以复合外键约束活动模型归属。`intel_settings` 保留作为 IOC worker 的兼容运行投影及版本锁；每次 LLM 配置写入均在同一事务更新投影和 revision。请求开始读取快照，入库时再次锁定、校验版本；供应商切换、修改全局、凭据轮换或暂停后，旧结果不能写入。首版任何 LLM 配置变动都会使正在运行的旧版本提取失效，可在文章页重新提取。

迁移后 GET `/api/intel/settings` 仍返回当前运行投影，旧 PUT 返回 `llm_settings_moved`。必须部署配套控制台；后端发布打包前需将 `.github/frontend-ref` 更新到包含新 LLM 界面的已推送前端提交，不能仍打包旧表单。

升级前备份数据库，保留 `server.encrypt_key`，停止所有旧后端实例后再迁移。旧程序不理解新元数据、多供应商及覆盖规则；回滚须同步恢复对应数据库备份与前端，不能仅替换旧二进制。

验证命令：

```sh
cargo fmt --all --check
cargo test --locked --lib threat_intel -- --include-ignored
```

集成测试需要隔离 PostgreSQL，并设置 `INTEL_TEST_DATABASE_URL`、`NM_INTEL_LOCAL_ROOT` 和 `NM_INTEL_CACHE_ROOT`。测试使用固定协议夹具，不需要真实供应商 API Key；真实账户的连通性、权限与计费须单独验收。
