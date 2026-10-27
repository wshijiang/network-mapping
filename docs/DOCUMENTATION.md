# 文档维护与本地预览

[文档中心](README.md)

## 内容分工

| 位置 | 用途 |
| --- | --- |
| 仓库根目录 `README.md` | 项目定位、必要依赖、快速开始和主要文档入口 |
| `docs/README.md` | MkDocs 首页、按任务组织的阅读路径和完整专题索引 |
| `docs/` 专题文件 | 操作步骤、参数、协议、设计或排障的详细说明 |
| `mkdocs/mkdocs.yml` | 文档站分组、导航顺序、主题和构建校验 |
| `mkdocs/hooks.py` | 构建时将指向仓库内源码和配置文件的链接转换为 GitHub 链接 |

专题沿用现有文件路径，通过首页和 MkDocs 导航组织分类。新增目录或改名时，同步修改所有引用；已发布路径需要迁移安排。

部署文档说明安装、升级和验收；使用文档说明当前操作；参考文档说明字段、协议和实现边界。当前实现与设计方案分别标注，实验原型和历史验证记录说明适用范围。

## 新增或更新专题

1. 将内容放入对应专题，避免在项目 README、首页和专题内重复维护完整步骤或参数表。
2. 新页面使用一个一级标题，按任务拆分二级和三级标题；命令注明工作目录、依赖和预期结果。
3. 在 `docs/README.md` 的对应分组补充链接与摘要，并同步 `mkdocs/mkdocs.yml` 的 `nav`。两个入口的分类和顺序保持一致。
4. 修改接口、配置或行为时，同步配套组件的说明；示例使用脱敏值，代码块标注语言。
5. 执行严格构建，检查导航、正文链接和锚点；涉及图表或复杂排版时再本地预览。

## 链接与站点规则

- 同一文档站内使用相对 Markdown 路径，例如 `[部署指南](DEPLOYMENT.md)`，由 MkDocs 转换为站点 URL。
- 仓库根文件使用真实相对路径，例如 `[项目首页](../README.md)`。构建钩子会将存在的文档目录外文件转换为 GitHub 链接。
- 跨仓库使用完整 GitHub URL，避免依赖本机三个仓库恰好相邻的目录结构。
- 中文标题锚点由现有 `pymdownx.slugs.slugify` 配置生成，修改标题后同步检查引用。
- 机器可读规范、示例及其他资源保留在 `docs/` 内，通过正文链接访问；Markdown 专题还需加入导航。
- `repo_url`、`edit_uri` 和钩子的 `BRANCH` 决定源码及编辑跳转；调整发布分支时一并核对。

## 安装与预览

以下命令从 `network-mapping` 仓库根目录执行，要求 Python 3.10+：

```sh
python3 -m venv .venv-docs
. .venv-docs/bin/activate
python -m pip install -r mkdocs/requirements.txt
python -m mkdocs serve -f mkdocs/mkdocs.yml
```

打开终端显示的本地地址。中英页面均可预览，文档和导航修改后自动刷新；预览默认仅监听本机。

## 构建检查

在已激活上述虚拟环境的仓库根目录执行：

```sh
python -m mkdocs build --strict -f mkdocs/mkdocs.yml
```

构建产物位于 `mkdocs/site/`，可交给现有静态站点发布流程。虚拟环境和构建产物已在 `.gitignore` 排除，不提交到源码仓库。

严格构建会把未加入导航的 Markdown 页面、失效文档链接及锚点警告视为失败。修复源文件、首页索引或导航后再提交；远程 URL 的可访问性仍需单独核对。


## 多语言与构建

当前语言规则、英文首批覆盖与完整中英构建命令见[语言切换与多语言文档](LOCALIZATION.md)。默认 `mkdocs build`、`mkdocs serve` 与 `python scripts/build-docs.py` 均通过同一构建钩子生成中文及 `en/` 英文页面和资源；发布整个输出目录。
