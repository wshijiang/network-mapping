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


def language_links(page, config, *, relative_to_page=True):
    english = config["extra"].get("locale") == "en"
    source = page.file.src_uri
    current = ("en/" if english else "") + (page.url if relative_to_page else "")
    links = []
    for language, prefix, name in [("zh-CN", "", "简体中文"), ("en", "en/", "English")]:
        directory = REPO_ROOT / "docs" / prefix
        target = prefix + document_url(source) if (directory / source).is_file() else prefix
        relative = posixpath.relpath(target or ".", current or ".")
        relative = "./" if relative == "." else relative.rstrip("/") + "/"
        links.append({"name": name, "link": relative, "lang": language})
    return links


def on_page_context(context, page, config, nav):
    # Material applies its `url` filter to both head metadata and menu links.
    # Give it paths relative to the active language root, not to this page.
    config["extra"]["alternate"] = language_links(page, config, relative_to_page=False)
    return context


def on_post_page(output, page, config):
    home = page.file.src_uri in ("README.md", "index.md")
    tag = f'<meta name="network-mapping-docs-home" content="{str(home).lower()}">'
    return output.replace("</head>", tag + "</head>", 1)


def on_post_build(config):
    # Language links are present in every build, including `mkdocs serve` and
    # `gh-deploy`. Build English after the root clean, in the actual output
    # directory (which may be a temporary preview or a custom --site-dir).
    if config["extra"].get("locale") == "en":
        return

    from mkdocs.commands.build import build
    from mkdocs.config import load_config

    english = load_config(
        str(REPO_ROOT / "mkdocs/mkdocs.en.yml"),
        site_dir=str(Path(config["site_dir"]) / "en"),
        site_url=(config["site_url"] or "/").rstrip("/") + "/en/",
        strict=config["strict"],
    )
    english.plugins.on_startup(command="build", dirty=False)
    try:
        build(english)
    finally:
        english.plugins.on_shutdown()


def on_serve(server, config, builder):
    if config["extra"].get("locale") != "en":
        server.watch(str(REPO_ROOT / "mkdocs/mkdocs.en.yml"))
    return server
