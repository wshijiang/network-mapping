"""Exercise the default commands that previously published links to missing English files."""
from functools import partial
from html.parser import HTMLParser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from threading import Thread
import time
import unittest
from urllib.error import URLError
from urllib.parse import unquote, urljoin, urlsplit
from urllib.request import ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "mkdocs/mkdocs.yml"


class PageLinks(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.urls = set()
        self.alternates = []
        self.menu = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("script", "img") and attrs.get("src"):
            self.urls.add(attrs["src"])
        if tag == "link" and attrs.get("rel") in ("stylesheet", "alternate"):
            self.urls.add(attrs["href"])
            if attrs["rel"] == "alternate":
                self.alternates.append((attrs["hreflang"], attrs["href"]))
        if tag == "a" and attrs.get("hreflang"):
            self.urls.add(attrs["href"])
            self.menu.append((attrs["hreflang"], attrs["href"]))


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class DocumentationBuildTests(unittest.TestCase):
    opener = build_opener(ProxyHandler({}))  # Loopback HTTP must stay local.

    def request(self, url):
        with self.opener.open(url, timeout=3) as response:
            self.assertEqual(response.status, 200, url)
            return response.read()

    def check_page(self, url, english=False):
        text = self.request(url).decode()
        self.assertIn('lang="en"' if english else 'lang="zh"', text)
        resources = PageLinks(text).urls
        self.assertTrue(any("language.js" in item for item in resources))
        for resource in resources:
            target = urljoin(url, resource)
            if urlsplit(target).netloc == urlsplit(url).netloc:
                self.assertTrue(self.request(target), target)

    def build(self, command, cwd):
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_default_build_clean_rebuild_and_static_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "preview"
            self.build([sys.executable, "-m", "mkdocs", "build", "--strict", "-f", str(CONFIG),
                        "--site-dir", str(output)], temporary)
            # Verify every generated page's language destinations and local assets,
            # resolving URLs as a browser would under a deployment subpath.
            pages = list(output.rglob("*.html"))
            self.assertTrue((output / "en/index.html").is_file())
            for page in pages:
                if page.name == "404.html":
                    continue  # Error templates use the deployment's absolute site_url.
                path = page.relative_to(output).as_posix().removesuffix("index.html")
                base = "https://example.test/preview/" + path
                links = PageLinks(page.read_text())
                self.assertEqual(len(links.alternates), 2, page)
                self.assertEqual(sorted(links.alternates), sorted(links.menu), page)
                for resource in links.urls:
                    target = urlsplit(urljoin(base, resource))
                    if target.netloc != "example.test":
                        continue
                    self.assertTrue(target.path.startswith("/preview/"), (page, resource))
                    file = output / unquote(target.path.removeprefix("/preview/"))
                    if target.path.endswith("/"):
                        file /= "index.html"
                    self.assertTrue(file.is_file(), (page, resource, file))
            for prefix in ("", "en/"):
                index = json.loads((output / prefix / "search/search_index.json").read_text())
                self.assertTrue(index["docs"])

            # The compatibility script must use the same build and remove stale
            # English files without losing the rebuilt pages or their assets.
            stale = output / "en/stale.txt"
            stale.write_text("old output")
            self.build([sys.executable, str(ROOT / "scripts/build-docs.py"),
                        "--site-dir", str(output)], temporary)
            self.assertFalse(stale.exists())
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=temporary))
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_port}/preview/"
                self.check_page(base)
                self.check_page(base + "en/", english=True)
                self.check_page(base + "en/LOCALIZATION/", english=True)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_default_serve_includes_english_under_subpath(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "preview.yml"
            config.write_text(json.dumps({
                "INHERIT": str(CONFIG), "site_url": "https://example.test/manual/",
                "docs_dir": str(ROOT / "docs"),
                "theme": {"custom_dir": str(ROOT / "mkdocs/overrides")},
                "hooks": [str(ROOT / "mkdocs/hooks.py")],
            }))
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            with (Path(temporary) / "serve.log").open("w+") as log:
                process = subprocess.Popen(
                    [sys.executable, "-m", "mkdocs", "serve", "--strict", "-f", str(config),
                     "-a", f"127.0.0.1:{port}"], cwd=temporary, stdout=log, stderr=log)
                try:
                    base = f"http://127.0.0.1:{port}/manual/"
                    deadline = time.monotonic() + 90
                    while time.monotonic() < deadline and process.poll() is None:
                        try:
                            self.request(base + "en/")
                            break
                        except URLError:
                            time.sleep(0.2)
                    else:
                        log.seek(0)
                        self.fail("English preview did not become available:\n" + log.read())
                    self.check_page(base)
                    self.check_page(base + "en/", english=True)
                    self.check_page(base + "en/DEPLOYMENT/", english=True)
                    self.assertIn(base + "en/", self.request(base + "en/").decode())
                    self.assertTrue(json.loads(self.request(base + "en/search/search_index.json"))["docs"])
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


if __name__ == "__main__":
    unittest.main()
