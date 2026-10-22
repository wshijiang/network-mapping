# 第三方依赖清单维护

`source/open_source_projects.json` 编译进服务端，由
`GET /api/open-source/projects` 提供给控制台的“开源项目”页面。

## 范围与版本口径

- 包含服务端及其本地 workspace crate、扫描器、前端声明的第三方直接包依赖，
  包括运行、构建、开发和测试依赖。同一包只列一次。
- 本地 workspace crate 不作为第三方项目重复列出。Rust 依赖别名按实际包名合并，
  例如服务端的 `reqwest-sdk` 归入 `reqwest`。
- 版本字段记录 `Cargo.toml` / `package.json` 的声明范围，不是已部署版本或上游最新版。
  同一包有多个声明时按清单扫描顺序以 ` / ` 分隔。
- 服务端和扫描器都声明的 Rust 包归为 `shared-rust`；只在一端声明的按实际所属端分类。
- 外部安装的 masscan、zgrab2、Nuclei、PostgreSQL、pgBackRest 等程序、第三方数据文件、
  系统软件和传递依赖不在此包清单范围内，应按实际安装与分发内容另行归档。
  本清单不代替完整 SBOM 或第三方许可证全文。

## 2026-10-22 复核

复核时共 81 个直接包：原有 18 项中删除已移除的 Leaflet，保留并纠正 17 项，新增 64 项。
依赖声明来自三个应用的 manifest 及服务端 workspace 成员。

许可证、仓库和主页以当前锁定版本对应的发布包为依据：Rust 使用
`Cargo.lock` 对应下载包中的 `Cargo.toml` 和许可证文件；前端使用
`pnpm-lock.yaml` 对应安装包中的 `package.json` 和许可证文件。
缺少 homepage 的 crate 使用其 docs.rs 页面；Git 仓库地址规范化为可打开的 HTTPS 地址。
`postgres-from-row` 未声明 SPDX 字段，按发布包中的 MIT `LICENSE` 确认。

特别修正：

- Reqwest 同时由服务端和扫描器使用；服务端同时声明 0.12、0.13（后者使用别名），
  扫描器声明 0.13，不再仅标为扫描器 0.12。
- Axios 声明范围更新为 `^1.20.0`。
- OpenSSL for Rust、tokio-postgres 的仓库地址更新为发布包声明的现有组织地址。
- ApexCharts 5.6.0、ApexMaps 0.3.0、vue3-apexcharts 1.11.1 和 vue-apexmaps 0.3.0
  的发布包 `LICENSE` 均为 ApexCharts 自定义授权，不能标为 MIT。
  清单使用 `LicenseRef-ApexCharts (Community / Commercial / OEM)` 作为说明性标签，
  它不是一条 SPDX 许可证表达式。上游条款见
  [ApexCharts 授权说明](https://apexcharts.com/license/) 和
  [ApexMaps 授权说明](https://apexcharts.com/apexmaps/docs/licensing/)。
  项目页面明确说明源码可见与开源许可证的区别，不对具体部署的授权资格作判断。

## 校验

需要 Python 3.11+，以及三个应用的源码 checkout；不需要下载依赖或访问网络。

```bash
python3 scripts/check-open-source-catalog.py
```

如果其他应用不在默认同级目录：

```bash
python3 scripts/check-open-source-catalog.py --scanner /path/to/scanner --frontend /path/to/frontend
```

脚本检查缺失、多余、重复条目，以及声明范围、所属组件、必需字段和 HTTPS 链接格式。
它不判断许可证全文、上游链接可达性或实际部署版本，升级依赖时仍须人工检查对应发布包，
更新清单与 `last_reviewed`，然后运行该脚本和 `cargo test open_source`。
