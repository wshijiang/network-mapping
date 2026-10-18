# Web 技术目录与规则扩展

[识别使用说明](WEB_DETECTION.md) · [规则开发与维护](WEB_DETECTION_DEVELOPMENT.md)

## 当前支持目录

当前内置 **74 条规则、47 种技术**。以下名称是识别对象，规则命中仍取决于扫描时保留的具体证据。

| 组件 ID | 技术 | 类别 | 证据类型 |
| --- | --- | --- | --- |
| `angular` | Angular | `frontend_framework` | HTML 标记或资源路径 |
| `antd` | Ant Design | `ui_library` | HTML 标记或资源路径 |
| `apache` | Apache | `web_server` | 产品响应头 |
| `apexcharts` | ApexCharts | `javascript_library` | HTML 标记或资源路径 |
| `aspnet` | ASP.NET | `backend_framework` | 产品响应头 |
| `astro` | Astro | `frontend_framework` | HTML 标记或资源路径 |
| `bootstrap` | Bootstrap | `ui_library` | HTML 标记或资源路径 |
| `caddy` | Caddy | `web_server` | 产品响应头 |
| `chartjs` | Chart.js | `javascript_library` | HTML 标记或资源路径 |
| `discuz` | Discuz! | `cms` | HTML 标记或资源路径 |
| `docusaurus` | Docusaurus | `site_generator` | HTML 标记或资源路径 |
| `drupal` | Drupal | `cms` | HTML 标记或资源路径 |
| `echarts` | ECharts | `javascript_library` | HTML 标记或资源路径 |
| `element-plus` | Element Plus | `ui_library` | HTML 标记或资源路径 |
| `express` | Express | `backend_framework` | 产品响应头 |
| `gatsby` | Gatsby | `site_generator` | HTML 标记或资源路径 |
| `ghost` | Ghost | `cms` | HTML 标记或资源路径 |
| `gitlab` | GitLab | `application` | HTML 标记或资源路径 |
| `grafana` | Grafana | `application` | HTML 标记或资源路径 |
| `gunicorn` | Gunicorn | `web_server` | 产品响应头 |
| `highcharts` | Highcharts | `javascript_library` | HTML 标记或资源路径 |
| `jenkins` | Jenkins | `application` | 产品响应头 |
| `jetty` | Jetty | `web_server` | 产品响应头 |
| `joomla` | Joomla | `cms` | HTML 标记或资源路径 |
| `jquery` | jQuery | `javascript_library` | HTML 标记或资源路径 |
| `laravel` | Laravel | `backend_framework` | 专用 Cookie 名称 |
| `layui` | Layui | `ui_library` | HTML 标记或资源路径 |
| `lighttpd` | lighttpd | `web_server` | 产品响应头 |
| `litespeed` | LiteSpeed | `web_server` | 产品响应头 |
| `microsoft-iis` | Microsoft IIS | `web_server` | 产品响应头 |
| `minio` | MinIO | `object_storage` | 产品响应头 |
| `nextjs` | Next.js | `frontend_framework` | HTML 标记或资源路径 |
| `nginx` | Nginx | `web_server` | 产品响应头 |
| `nuxt` | Nuxt | `frontend_framework` | HTML 标记或资源路径 |
| `openresty` | OpenResty | `web_server` | 产品响应头 |
| `php` | PHP | `runtime` | 产品响应头 |
| `react` | React | `frontend_framework` | HTML 标记或资源路径 |
| `s3` | S3-compatible storage | `object_storage` | 产品响应头 |
| `sveltekit` | SvelteKit | `frontend_framework` | HTML 标记或资源路径 |
| `thinkphp` | ThinkPHP | `backend_framework` | 产品响应头 |
| `tornado` | Tornado | `web_server` | 产品响应头 |
| `uvicorn` | Uvicorn | `web_server` | 产品响应头 |
| `vitepress` | VitePress | `site_generator` | HTML 标记或资源路径 |
| `vue` | Vue | `frontend_framework` | HTML 标记或资源路径 |
| `vuetify` | Vuetify | `ui_library` | HTML 标记或资源路径 |
| `werkzeug` | Werkzeug | `web_server` | 产品响应头 |
| `wordpress` | WordPress | `cms` | HTML 标记或资源路径、专用 Cookie 名称 |

## 本轮分批交付

第一批新增 23 种明确特征技术：Jetty、lighttpd、Gunicorn、Uvicorn、Werkzeug、Tornado、ThinkPHP、
Astro、SvelteKit、Gatsby、Docusaurus、VitePress、ECharts、Chart.js、ApexCharts、Highcharts、
Vuetify、Layui、Ghost、Discuz!、MinIO、通用 S3 和 GitLab。规则版本为 `2026-10-18.2`。

第二批计划交付 Alpine.js、htmx、phpMyAdmin、Swagger UI、Git 服务，以及 MinIO 控制台和 S3 的组合识别。
本节的计划项尚未计入上方目录。

## MinIO、S3 与 Git 的边界

- `minio` 识别产品身份；当前明确入口为 `Server: MinIO`，默认没有可确认版本。
- `s3` 表示 S3 兼容接口；第一批仅使用明确 `Server: AmazonS3` 标识。`x-amz-*`、错误正文或 9000 端口不会单独归为 MinIO。
- `gitlab` 识别 GitLab 产品元数据；GitLab 页面不自动代表探测到了 Git 协议服务。
- 通用 Git 服务将在第二批校验 smart HTTP 广告响应的媒体类型与 pkt-line 结构，不凭 `.git` 路径判断。
- Gunicorn、Uvicorn、Werkzeug 不自动推断 Django、FastAPI 或 Flask。

## 样本与来源

`src/web_detection/fixtures.json` 是脱敏的合成回归样本，不是线上目标扫描记录。每个新增组件都有正例和明确版本预期，
反例覆盖普通文字、查询参数、S3 兼容标识与产品身份混淆；规则文件仍是最终可执行清单。

MinIO 服务端标识核对自官方 [响应头实现](https://github.com/minio/minio/blob/RELEASE.2025-04-22T22-12-26Z/cmd/api-headers.go)和
[健康检查响应示例](https://github.com/minio/minio/blob/RELEASE.2025-04-22T22-12-26Z/docs/metrics/healthcheck/README.md)。
S3 的 Server 标识和响应头格式参考 [Amazon S3 公共响应头](https://docs.aws.amazon.com/AmazonS3/latest/API/RESTCommonResponseHeaders.html)。
资源路径仅证明页面引用该包；部署重命名资源、隐藏元数据或移除产品头后可能无法命中。

## 查询示例

```text
tech = minio
tech = s3
tech = gitlab
tech = "jetty@12.0.16"
tech IN (echarts, apexcharts, highcharts)
```
