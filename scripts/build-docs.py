#!/usr/bin/env python3
"""Build both documentation languages without overwriting the other language."""
import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-dir", type=Path, default=ROOT / "mkdocs/site")
    args = parser.parse_args()
    output = args.site_dir.resolve()
    # The default configuration's hook builds English after cleaning the root.
    subprocess.run([sys.executable, "-m", "mkdocs", "build", "--strict", "-f", str(ROOT / "mkdocs/mkdocs.yml"), "--site-dir", str(output)], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
