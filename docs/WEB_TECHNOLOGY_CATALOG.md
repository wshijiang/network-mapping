# Web 技术目录与规则扩展

[识别使用说明](WEB_DETECTION.md) · [规则开发与维护](WEB_DETECTION_DEVELOPMENT.md)

## 当前支持目录

当前内置 **86 条规则、52 种技术**，规则版本 `2026-10-18.3`。以下名称是识别对象，命中取决于保留的具体响应。

| 组件 ID | 技术 | 类别 | 证据类型 |
| --- | --- | --- | --- |
| `alpinejs` | Alpine.js | `javascript_library` | HTML 标记或资源路径 |
| `angular` | Angular | `frontend_framework` | HTML 标记或资源路径 |
| `antd` | Ant Design | `ui_library` | HTML 标记或资源路径 |
| `apache` | Apache | `web_server` | 指定响应头 |
| `apexcharts` | ApexCharts | `javascript_library` | HTML 标记或资源路径 |
| `aspnet` | ASP.NET | `backend_framework` | 指定响应头 |
| `astro` | Astro | `frontend_framework` | HTML 标记或资源路径 |
| `bootstrap` | Bootstrap | `ui_library` | HTML 标记或资源路径 |
| `caddy` | Caddy | `web_server` | 指定响应头 |
| `chartjs` | Chart.js | `javascript_library` | HTML 标记或资源路径 |
| `discuz` | Discuz! | `cms` | HTML 标记或资源路径 |
| `docusaurus` | Docusaurus | `site_generator` | HTML 标记或资源路径 |
| `drupal` | Drupal | `cms` | HTML 标记或资源路径 |
| `echarts` | ECharts | `javascript_library` | HTML 标记或资源路径 |
| `element-plus` | Element Plus | `ui_library` | HTML 标记或资源路径 |
| `express` | Express | `backend_framework` | 指定响应头 |
| `gatsby` | Gatsby | `site_generator` | HTML 标记或资源路径 |
| `ghost` | Ghost | `cms` | HTML 标记或资源路径 |
| `git` | Git smart HTTP | `version_control` | Git smart HTTP 协议、指定响应头 |
| `gitlab` | GitLab | `application` | HTML 标记或资源路径 |
| `grafana` | Grafana | `application` | HTML 标记或资源路径 |
| `gunicorn` | Gunicorn | `web_server` | 指定响应头 |
| `highcharts` | Highcharts | `javascript_library` | HTML 标记或资源路径 |
| `htmx` | htmx | `javascript_library` | HTML 标记或资源路径 |
| `jenkins` | Jenkins | `application` | 指定响应头 |
| `jetty` | Jetty | `web_server` | 指定响应头 |
| `joomla` | Joomla | `cms` | HTML 标记或资源路径 |
| `jquery` | jQuery | `javascript_library` | HTML 标记或资源路径 |
| `laravel` | Laravel | `backend_framework` | 专用 Cookie 名称 |
| `layui` | Layui | `ui_library` | HTML 标记或资源路径 |
| `lighttpd` | lighttpd | `web_server` | 指定响应头 |
| `litespeed` | LiteSpeed | `web_server` | 指定响应头 |
| `microsoft-iis` | Microsoft IIS | `web_server` | 指定响应头 |
| `minio` | MinIO | `object_storage` | HTML 标记或资源路径、指定响应头、响应头名称、限定页面标题 |
| `nextjs` | Next.js | `frontend_framework` | HTML 标记或资源路径 |
| `nginx` | Nginx | `web_server` | 指定响应头 |
| `nuxt` | Nuxt | `frontend_framework` | HTML 标记或资源路径 |
| `openresty` | OpenResty | `web_server` | 指定响应头 |
| `php` | PHP | `runtime` | 指定响应头 |
| `phpmyadmin` | phpMyAdmin | `application` | HTML 标记或资源路径 |
| `react` | React | `frontend_framework` | HTML 标记或资源路径 |
| `s3` | S3-compatible storage | `object_storage` | S3 XML 结构、指定响应头、响应头名称 |
| `sveltekit` | SvelteKit | `frontend_framework` | HTML 标记或资源路径 |
| `swagger-ui` | Swagger UI | `api_documentation` | HTML 标记或资源路径、资源路径 |
| `thinkphp` | ThinkPHP | `backend_framework` | 指定响应头 |
| `tornado` | Tornado | `web_server` | 指定响应头 |
| `uvicorn` | Uvicorn | `web_server` | 指定响应头 |
| `vitepress` | VitePress | `site_generator` | HTML 标记或资源路径 |
| `vue` | Vue | `frontend_framework` | HTML 标记或资源路径 |
| `vuetify` | Vuetify | `ui_library` | HTML 标记或资源路径 |
| `werkzeug` | Werkzeug | `web_server` | 指定响应头 |
| `wordpress` | WordPress | `cms` | HTML 标记或资源路径、专用 Cookie 名称 |

## 本轮分批交付

| 批次 | 新增范围 | 累计技术数 |
| --- | --- | --- |
| 第一批（规则版本 2） | Jetty、lighttpd、Gunicorn、Uvicorn、Werkzeug、Tornado、ThinkPHP、Astro、SvelteKit、Gatsby、Docusaurus、VitePress、ECharts、Chart.js、ApexCharts、Highcharts、Vuetify、Layui、Ghost、Discuz!、MinIO、通用 S3、GitLab | 47 |
| 第二批（规则版本 3） | Alpine.js、htmx、phpMyAdmin、Swagger UI、Git 服务；增强 MinIO 控制台和 S3 结构识别，增加 all/any/not 组合条件 | 52 |

两批均继续在服务端处理已有证据，不增加目标探测请求，前端沿用既有技术栈组件。

## MinIO、S3、GitLab 与 Git 服务

- `minio` 识别 MinIO 产品：明确的 `Server: MinIO`；或同一响应同时有专用 deployment-id 和 S3 request-id 头；或标题及 description 同时明确为 MinIO Console。不会保存头内的 ID 值。
- `s3` 识别 S3 兼容接口：明确 `Server: AmazonS3`；或 XML 媒体类型、有效的 S3 XML 结构、request-id 和另一项 S3 响应头同时成立。不把所有 `x-amz-*` 响应归为 S3，也不据此推断 MinIO。
- MinIO 与通用 S3 可以同时命中，分别表示产品身份与接口证据。缺少协议证据时，仅识别 MinIO 不自动补出 S3。
- `gitlab` 识别 GitLab 产品元数据，不自动补出 Git 服务。
- `git` 识别 Git smart HTTP：广告响应媒体类型必须与合法 pkt-line 中的 upload-pack 或 receive-pack 操作一致，也支持有 ls-refs/fetch 能力的协议 v2 广告。Git 的协议版本不作为软件版本。
- Git 识别只使用已保留的实际协议响应；普通网站首页通常没有该响应。本版本不会主动请求 `info/refs`、遍历 `.git`，也不覆盖 `git://` 或 SSH Git。
- Gunicorn、Uvicorn、Werkzeug 不直接推断 Django、FastAPI 或 Flask；Swagger UI 不直接推断后端框架。

## 组合判定与不完整证据

组合规则的全部条件必须来自同一个 HTTP 响应，不能跨 HTTP/HTTPS evidence、观察记录或站点拼接。
phpMyAdmin 需要登录表单中的用户名和密码字段；Swagger UI 需要专用容器及其脚本/样式；
Alpine.js 和 htmx 的 DOM 方式需要多个相关属性，仍标为中置信度。明确包路径是独立资源引用证据。
单独产品文字、通用 DOM ID、单个交互属性、S3 错误文字或 Git 路径不会满足这些组合。

`not` 仅在完整、可检查的 HTTP 头和 HTML 范围中判断缺少特征，截断或缺失输入不会通过否定。
协议解析失败不能用于证明协议不存在，因此协议来源不允许用于 `not`。

## 样本与来源

`src/web_detection/fixtures.json` 是脱敏的合成回归样本，不是线上目标扫描记录。每个新增组件都有正例和明确版本预期，
另有缺少必要条件、跨响应拼接、伪造协议、错误命名空间、DTD、错误 pkt-line 长度和敏感值不泄漏的反例。

- MinIO：[官方响应头实现](https://github.com/minio/minio/blob/RELEASE.2025-04-22T22-12-26Z/cmd/api-headers.go)、[健康检查响应示例](https://github.com/minio/minio/blob/RELEASE.2025-04-22T22-12-26Z/docs/metrics/healthcheck/README.md)。
- S3：[公共响应头](https://docs.aws.amazon.com/AmazonS3/latest/API/RESTCommonResponseHeaders.html)、[ListObjectsV2](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html)。
- Git：[smart HTTP 协议](https://git-scm.com/docs/http-protocol)、[协议 v2](https://git-scm.com/docs/protocol-v2)。

产品规则只识别明确声明的特征，不保证覆盖所有产品版本。资源路径仅证明页面引用该包；隐藏头、重命名资源或缺少协议响应可能无法命中。

## 查询示例

```text
tech = minio
tech = s3
tech = gitlab
tech = git
tech = "jetty@12.0.16"
tech IN (alpinejs, htmx, phpmyadmin, swagger-ui)
```
