import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

SPEC = importlib.util.spec_from_file_location("docs_hooks", Path(__file__).with_name("hooks.py"))
hooks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hooks)


class DocumentationLanguageTests(unittest.TestCase):
    def config(self, english=False):
        return {"docs_dir": str(hooks.REPO_ROOT / "docs" / ("en" if english else "")), "extra": {"locale": "en" if english else "zh-CN"}}

    def page(self, source="LOCALIZATION.md", url="LOCALIZATION/"):
        return SimpleNamespace(file=SimpleNamespace(src_uri=source), url=url)

    def test_repository_links_work_from_both_language_roots(self):
        for english, target in [(False, "../README.md"), (True, "../../README.md")]:
            text = f"[source]({target}?plain=1#source)"
            result = hooks.on_page_markdown(text, self.page(), self.config(english), None)
            self.assertIn(hooks.REPO_URL + "/blob/main/README.md?plain=1#source", result)

    def test_missing_external_and_outside_repository_links_are_not_hidden(self):
        for target in ["missing.md", "https://example.com/page", "#section", "../../../outside.txt"]:
            text = f"[link]({target})"
            self.assertEqual(hooks.on_page_markdown(text, self.page(), self.config(True), None), text)
        self.assertEqual(hooks.on_page_markdown("[home](README.md)", self.page(), self.config(True), None), "[home](README.md)")

    def test_translated_counterparts_and_missing_translation_fallback(self):
        links = hooks.language_links(self.page(), self.config())
        self.assertEqual(links[1]["link"], "../en/LOCALIZATION/")
        links = hooks.language_links(self.page(), self.config(True))
        self.assertEqual(links[0]["link"], "../../LOCALIZATION/")
        missing = hooks.language_links(self.page("UNTRANSLATED.md", "UNTRANSLATED/"), self.config())
        self.assertEqual(missing[1]["link"], "../en/")
        home = hooks.language_links(self.page("README.md", ""), self.config(True))
        self.assertEqual(home[0]["link"], "../")

    def test_language_metadata_supports_subpath_preview(self):
        html = hooks.on_post_page("<head></head><body></body>", self.page("README.md", ""), self.config(True))
        self.assertIn('hreflang="zh-CN" href="../"', html)
        self.assertIn('name="network-mapping-docs-home" content="true"', html)
        self.assertNotIn('href="/en/', html)
        assets = hooks.REPO_ROOT / "docs/assets/language.js"
        self.assertEqual(assets.read_bytes(), (hooks.REPO_ROOT / "docs/en/assets/language.js").read_bytes())


if __name__ == "__main__":
    unittest.main()
