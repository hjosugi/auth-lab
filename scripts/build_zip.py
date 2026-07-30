#!/usr/bin/env python3
"""Build a deterministic source and learning-material ZIP archive."""

from __future__ import annotations

import pathlib
import zipfile

EXCLUDED_PARTS = {
    ".git",
    ".tmp",
    ".venv",
    "__pycache__",
    "dist",
    "target",
}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}


def included(path: pathlib.Path, root: pathlib.Path) -> bool:
    relative = path.relative_to(root)
    return (
        path.is_file()
        and not any(part in EXCLUDED_PARTS for part in relative.parts)
        and path.suffix not in EXCLUDED_SUFFIXES
        and path.name not in {"site-desktop.png", "site-mobile.png"}
    )


def main() -> None:
    root = pathlib.Path(__file__).resolve().parents[1]
    destination = root / "dist" / "auth-lab-learning-bundle.zip"
    destination.parent.mkdir(exist_ok=True)
    files = sorted(path for path in root.rglob("*") if included(path, root))
    with zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for path in files:
            relative = pathlib.Path("auth-lab") / path.relative_to(root)
            info = zipfile.ZipInfo.from_file(path, arcname=relative.as_posix())
            info.date_time = (2026, 1, 1, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())
    print(f"Built {destination.relative_to(root)} with {len(files)} files.")


if __name__ == "__main__":
    main()
