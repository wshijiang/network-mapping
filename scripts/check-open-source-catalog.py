#!/usr/bin/env python3
"""Check the embedded catalog against the three checked-out applications.

Requires Python 3.11+. Versions are manifest requirements, not lockfile versions.
Local workspace crates and transitive dependencies are deliberately excluded.
"""

import argparse
import json
from pathlib import Path
import sys
import tomllib
from datetime import date


def declared_projects(server, scanner, frontend):
    projects = {}

    def add(package, version, component):
        item = projects.setdefault(package, {"versions": [], "components": set()})
        if version not in item["versions"]:
            item["versions"].append(version)
        item["components"].add(component)

    for root, component in [(server, "backend"), (scanner, "scanner")]:
        manifest = tomllib.loads((root / "Cargo.toml").read_text())
        manifests = [manifest]
        for member in manifest.get("workspace", {}).get("members", []):
            if member == ".":
                continue
            for directory in sorted(root.glob(member)):
                manifests.append(tomllib.loads((directory / "Cargo.toml").read_text()))
        for document in manifests:
            sections = [document]
            sections.extend(document.get("target", {}).values())
            for section in sections:
                for kind in ["dependencies", "build-dependencies", "dev-dependencies"]:
                    for alias, dependency in section.get(kind, {}).items():
                        dependency = {"version": dependency} if isinstance(dependency, str) else dependency
                        if "path" in dependency:
                            continue
                        add(dependency.get("package", alias), dependency["version"], component)

    package = json.loads((frontend / "package.json").read_text())
    for kind in ["dependencies", "devDependencies"]:
        for name, version in package.get(kind, {}).items():
            add(name, version, "frontend")

    return {
        name: {
            "version": " / ".join(item["versions"]),
            "ecosystem": "shared-rust" if item["components"] == {"backend", "scanner"}
            else next(iter(item["components"])),
        }
        for name, item in projects.items()
    }


def main():
    server = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner", type=Path, default=server.parent / "Network-Mapping-Scanner")
    parser.add_argument("--frontend", type=Path, default=server.parent / "network-mapping-vue")
    args = parser.parse_args()
    expected = declared_projects(server, args.scanner, args.frontend)
    catalog = json.loads((server / "source/open_source_projects.json").read_text())
    date.fromisoformat(catalog["last_reviewed"])
    actual = {}
    errors = []
    for project in catalog["projects"]:
        name = project["package"]
        if name in actual:
            errors.append(f"duplicate package: {name}")
        actual[name] = project
        for field in ["name", "usage", "license"]:
            if not project.get(field, "").strip():
                errors.append(f"{name}: missing {field}")
        for field in ["homepage", "repository"]:
            if not project.get(field, "").startswith("https://"):
                errors.append(f"{name}: invalid {field}")
    errors.extend(f"missing package: {name}" for name in sorted(expected.keys() - actual.keys()))
    errors.extend(f"extra package: {name}" for name in sorted(actual.keys() - expected.keys()))
    for name in expected.keys() & actual.keys():
        for field, value in expected[name].items():
            if actual[name][field] != value:
                errors.append(f"{name}: {field} must be {value!r}, got {actual[name][field]!r}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Catalog matches all {len(expected)} declared third-party packages.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
