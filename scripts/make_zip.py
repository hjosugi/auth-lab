#!/usr/bin/env python3
"""Build a distributable zip of the lab (source, drills, attacks, tests, docs).

    python scripts/make_zip.py            # -> dist/auth-lab.zip

Excludes VCS, caches, and any previously built artifacts so the zip is clean
and reproducible.
"""

from __future__ import annotations

import os
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "dist")
OUT = os.path.join(OUT_DIR, "auth-lab.zip")

INCLUDE_DIRS = ["authlab", "drills", "attacks", "tests", "docs", "scripts"]
INCLUDE_FILES = ["README.md", "LICENSE", ".gitignore"]
SKIP_PARTS = {"__pycache__", ".git", ".venv", "dist", ".DS_Store"}


def _keep(path: str) -> bool:
    parts = set(path.split(os.sep))
    if parts & SKIP_PARTS:
        return False
    return not path.endswith((".pyc", ".zip"))


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    count = 0
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in INCLUDE_FILES:
            full = os.path.join(ROOT, name)
            if os.path.exists(full):
                zf.write(full, os.path.join("auth-lab", name))
                count += 1
        for directory in INCLUDE_DIRS:
            base = os.path.join(ROOT, directory)
            for dirpath, dirnames, filenames in os.walk(base):
                dirnames[:] = [d for d in dirnames if d not in SKIP_PARTS]
                for filename in filenames:
                    full = os.path.join(dirpath, filename)
                    rel = os.path.relpath(full, ROOT)
                    if _keep(rel):
                        zf.write(full, os.path.join("auth-lab", rel))
                        count += 1
    size = os.path.getsize(OUT)
    print(f"wrote {OUT} ({count} files, {size / 1024:.0f} KiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
