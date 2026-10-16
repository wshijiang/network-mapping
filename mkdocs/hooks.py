
import re
from pathlib import Path
from urllib.parse import quote, urlsplit

REPO_URL = "https://github.com/wshijiang/network-mapping"
BRANCH = "main"

# 匹配 Markdown 的普通内联链接
LINK_RE = re.compile(r'(?<!!)\]\(([^)\s]+)(\s+"[^"]*")?\)')


def on_page_markdown(markdown, page, config, files):
    docs_dir = Path(config["docs_dir"]).resolve()
    repo_root = docs_dir.parent
    source_file = docs_dir / page.file.src_uri

    def replace_link(match):
        target = match.group(1)
        parsed = urlsplit(target)

        # 只处理相对路径
        if parsed.scheme or parsed.netloc or target.startswith(("/", "#")):
            return match.group(0)

        resolved = (source_file.parent / parsed.path).resolve()

        # docs_dir 内的文件交给 MkDocs 自行处理
        if resolved.is_relative_to(docs_dir):
            return match.group(0)

        # 不允许跳转到仓库以外
        if not resolved.is_relative_to(repo_root):
            return match.group(0)

        # 文件不存在则保留原链接，让 MkDocs 报告
        if not resolved.is_file():
            return match.group(0)

        relative = resolved.relative_to(repo_root).as_posix()
        encoded = quote(relative, safe="/")
        url = f"{REPO_URL}/blob/{BRANCH}/{encoded}"

        if parsed.query:
            url += "?" + parsed.query
        if parsed.fragment:
            url += "#" + parsed.fragment

        return f"]({url}{match.group(2) or ''})"

    return LINK_RE.sub(replace_link, markdown)
