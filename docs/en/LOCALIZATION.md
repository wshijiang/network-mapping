# Language selection and documentation maintenance

[Documentation](README.md) · [Source repository](https://github.com/wshijiang/network-mapping)

## Console language

The dashboard, sign-in, standalone search and asset details share English and Simplified Chinese controls. On the first visit, the browser's first preferred language selects the language: any `zh` variant uses Simplified Chinese, any `en` variant uses English, and all other or missing preferences use English. A secondary Chinese preference does not override a different primary language.

A manual selection saves `network_mapping_locale=zh-CN` or `en` in a host-only cookie for one year with `Path=/` and `SameSite=Lax`; HTTPS also uses `Secure`. A valid cookie takes precedence on later visits. Automatic detection does not write a cookie. Invalid or malformed values are ignored. When cookies are blocked, the current page still switches and explains that the preference was not saved.

Switching updates interface text without reloading the app or discarding drafts, filters or unsaved forms. Other open pages synchronize on focus/visibility, and through Cookie Store events when supported. Clearing the cookie restores browser detection.

UI language does not change business time zone, date order, clock format, timestamps, scan targets, protocol identifiers or permissions. Evidence, product names, user input, LLM conversations and saved notification bodies keep their original content. Free-text server responses and historical diagnostics can remain in their original language; they are never sent to a translation service.

## Documentation languages

Chinese keeps the original URLs; English is under `en/`. The menu links to the same translated page when available, otherwise to the language home. The documentation home uses the browser/cookie preference. Selecting a documentation language explicitly saves the same cookie. Menu URLs carry a validated `docs-lang=en` or `docs-lang=zh-CN` parameter, which takes precedence on the destination home even when cookies are rejected. This also works on reload, copied links and new tabs. A fresh home URL without this parameter still uses the cookie/browser preference. Ordinary topic pages are not forced into another language.

Only the home, deployment and language-maintenance pages are translated in this first documentation release. Untranslated topics are explicitly linked to the Chinese reference. Theme strings, search, navigation and edit links are configured independently for each language.

## Build and preview

From the `network-mapping` repository root, with Python 3.10 or newer:

```sh
python3 -m venv .venv-docs
. .venv-docs/bin/activate
python -m pip install -r mkdocs/requirements.txt
python scripts/build-docs.py
python -m http.server 8000 --bind 127.0.0.1 --directory mkdocs/site
```

The build runs strict checks for both languages. The default configuration builds Chinese first, then English with its own pages, CSS/JS, language script and search index under the actual output directory’s `en/`. Standard `python -m mkdocs build --strict -f mkdocs/mkdocs.yml` and `python -m mkdocs serve -f mkdocs/mkdocs.yml` use the same bilingual flow, including custom output and temporary preview directories. Clean rebuilds regenerate both languages; an English build failure fails the whole build. Serve the entire `mkdocs/site/` tree. These commands do not deploy.

Set the default configuration’s `site_url` to the real deployment base before publishing. The bilingual build derives the English base by appending `en/`; the English configuration’s own `site_url` is used only for standalone English builds. The inherited sample domain does not mean this repository has been published there. Each component needs a separate deployment base. The language menu and head metadata use the same relative URL resolution for subpath deployments and local previews.

## English pages or assets return 404

Previously, the default build and preview generated only Chinese while linking to `en/`; rebuilding Chinese also removed existing English output. Rebuild with the updated default command and publish the entire output, including `en/index.html`, `en/assets/` and `en/search/search_index.json`.

Verify HTTP 200 responses for both home pages, `en/DEPLOYMENT/`, the referenced CSS/JS, the language script and English search index. Include the same deployment prefix in every URL when hosting under a subpath. `mkdocs/test_build.py` covers default strict builds, clean rebuilds, custom output, static hosting and bilingual MkDocs preview.

## Maintain translations

Add English files at the same relative path under `docs/en/`, then update the English navigation and home. Preserve commands, configuration keys and version limitations. Change Chinese and corresponding English instructions together with `CHANGELOG.md`. Have deployment, recovery and permission instructions reviewed before publishing.

Run:

```sh
python scripts/build-docs.py
python -m unittest discover -s mkdocs -p 'test_*.py'
node --test mkdocs/language.test.cjs
```

Check language links, missing-translation fallback, search, edit links, anchors and repository file links. The hook derives the repository root from its own location, not from the active language directory. Existing repository files outside the language root link to GitHub; missing/out-of-repository links are not silently rewritten.

The language-script regression checks require Node.js 20.19 or newer and no npm dependencies.
