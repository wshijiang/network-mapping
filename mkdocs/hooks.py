import html
import posixpath
import re
from pathlib import Path, PurePosixPath
from urllib.parse import quote, urlsplit

REPO_URL = "https://github.com/wshijiang/network-mapping"
BRANCH = "main"
REPO_ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r'(?<!!)\]\(([^)\s]+)(\s+"[^"]*")?\)')


def on_page_markdown(markdown, page, config, files):
    docs_dir = Path(config["docs_dir"]).resolve()
    source_file = docs_dir / page.file.src_uri

    def replace_link(match):
        target = match.group(1)
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or target.startswith(("/", "#")):
            return match.group(0)
        resolved = (source_file.parent / parsed.path).resolve()
        if resolved.is_relative_to(docs_dir):
            return match.group(0)
        if not resolved.is_relative_to(REPO_ROOT) or not resolved.is_file():
            return match.group(0)
        relative = resolved.relative_to(REPO_ROOT).as_posix()
        url = f"{REPO_URL}/blob/{BRANCH}/{quote(relative, safe='/')}"
        if parsed.query:
            url += "?" + parsed.query
        if parsed.fragment:
            url += "#" + parsed.fragment
        return f"]({url}{match.group(2) or ''})"

    return LINK_RE.sub(replace_link, markdown)


def document_url(source):
    path = PurePosixPath(source)
    if path.name in ("README.md", "index.md"):
        parent = str(path.parent)
        return "" if parent == "." else parent + "/"
    return quote(str(path.with_suffix("")), safe="/") + "/"


def language_links(page, config):
    english = config["extra"].get("locale") == "en"
    source = page.file.src_uri
    current = ("en/" if english else "") + page.url
    links = []
    for language, prefix, name in [("zh-CN", "", "简体中文"), ("en", "en/", "English")]:
        directory = REPO_ROOT / "docs" / prefix
        target = prefix + document_url(source) if (directory / source).is_file() else prefix
        relative = posixpath.relpath(target or ".", current or ".")
        relative = "./" if relative == "." else relative.rstrip("/") + "/"
        links.append({"name": name, "link": relative, "lang": language})
    return links


def on_page_context(context, page, config, nav):
    config["extra"]["alternate"] = language_links(page, config)
    return context


def on_post_page(output, page, config):
    links = language_links(page, config)
    tags = ''.join(f'<link rel="alternate" hreflang="{item["lang"]}" href="{html.escape(item["link"], quote=True)}">' for item in links)
    home = page.file.src_uri in ("README.md", "index.md")
    tags += f'<meta name="network-mapping-docs-home" content="{str(home).lower()}">'
    return output.replace("</head>", tags + "</head>", 1)
