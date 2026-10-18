# Web 框架与组件识别

[功能概览](FEATURES.md) · [搜索语法](SEARCH_SYNTAX.md) · [开发与维护](WEB_DETECTION_DEVELOPMENT.md)

## 识别在哪里执行

扫描器负责采集，服务端负责识别。当前版本复用 zgrab2 已上传的 HTTP/HTTPS 响应，
不增加目标请求、不执行网页脚本，也不改变扫描计划或结果协议。需要开启服务识别，
仅端口任务没有新的 HTTP 证据。规则更新后可以重新处理历史证据，无需重新访问目标。

首版的识别对象是 **IP 端点的 HTTP 响应视角**（`inference_scope=ip_endpoint`）。
现有扫描器未完整传递域名 Host/SNI；同一 IP 上不同域名可能使用不同应用。
系统不会根据证书 SAN、DNS 关联或同 IP 关系，把某个端点的技术栈复制给其他域名。

## 查看结果

搜索结果、任务详情端口表和资产详情端口表提供“Web 技术栈”。展开后可查看组件、版本、
置信等级、证据类型、规则 ID、字段路径、原始观察引用及证据时间。
搜索页导出当前页 CSV 时同时导出技术栈、识别状态、证据时间、过期标记和规则版本。

| 状态 | 含义 |
| --- | --- |
| `pending` | 后台等待处理已有服务证据 |
| `identified` | 现有响应中命中至少一种技术 |
| `unknown` | HTTP 证据没有足够的已知特征 |
| `partial` | 响应或解析达到上限，已识别项仍可参考，结果可能不完整 |
| `unsupported` | 服务证据 schema 版本暂不支持 |
| `not_web` | 当前观察没有 HTTP/HTTPS 证据，且未声明为 HTTP 服务 |

旧服务端不返回 `web` 时显示“暂无识别结果”。识别异步执行，扫描完成后可能稍晚可见。
证据早于最近端口观察，或超过 30 天时标记为可能过期；新端口发现不代表旧技术栈得到复核。

## 覆盖范围与边界

内置规则覆盖 Nginx、Apache、OpenResty、Caddy、IIS、LiteSpeed、PHP、ASP.NET、Express、
Laravel、WordPress、Drupal、Joomla、Next.js、Nuxt、Angular、Vue、React、jQuery、
Bootstrap、Element Plus、Ant Design、Grafana 和 Jenkins 的部分明确特征。
规则清单以 [rules.json](../src/web_detection/rules.json) 为准；列表不代表每个产品在所有部署下都可被识别。

识别来源包括白名单响应头、Cookie **名称**、HTML generator、明确 DOM 标记及脚本/样式资源路径。
普通正文中提及产品名称、注释、未知协议内容、资源 URL 的主机名及查询参数不参与技术匹配。
版本仅来自明确的版本捕获；缺少版本返回 `null`，存在多个版本时 `version_conflict=true`，
不选择其中一个作为确定版本。不同框架可以共存。

`response_marker` 表示响应特征；`referenced_resource` 表示页面引用了资源，不能证明该库
在运行时被执行。置信度为规则分级，不是统计概率；产品标记也可能由代理或页面伪造。
无法从外部响应证明隐藏的服务端依赖、完整软件物料清单或漏洞存在。

## 搜索

```text
tech = nginx
tech = "jquery@3.7.1"
tech IN (wordpress, drupal)
tech != jquery
web.status = partial
has_endpoint(port = 8443 AND tech = nextjs)
```

`tech`（别名 `web.tech`）使用规则中的组件 ID，支持 `=`、`!=`、`IN`、`NOT IN`、`EXISTS`。
`ID@版本` 在同一个组件内关联名称和版本，避免把 Nginx 的名称与 jQuery 的版本组合。
组件 ID 大小写不敏感，版本按原值精确匹配；不提供独立的非关联版本条件。
`tech != jquery` 包含尚无技术栈结果的端点，需要排除时附加 `web.status = identified`。

## 外部 API 与升级

现有资产 API 新增可审批字段 `web`；仅获批该字段的应用才能返回摘要并使用技术栈搜索。
摘要移除各组件的证据、字段路径和观察索引引用。已有应用不会自动取得新字段权限。
完整字段目录见 [外部 API](OPEN_API.md)。

先部署后端，再部署控制台。服务端启动时幂等创建 Web 派生队列表，并为已有端点索引
添加 `web` mapping；历史成功执行会分批入队，正常服务不向 PostgreSQL 写扫描事实。
不需要升级扫描器。原始 observation、上传回执和 checksum 保持不变。

当前版本尚未实现域名虚拟主机建模、额外 JS/CSS/favicon 下载、Nuclei 独立技术结果或浏览器
运行时识别；分阶段演进见 [开发与维护](WEB_DETECTION_DEVELOPMENT.md)。
