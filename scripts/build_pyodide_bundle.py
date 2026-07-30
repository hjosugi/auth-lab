#!/usr/bin/env python3
"""Build the deterministic, dependency-free authlab bundle loaded by Pyodide."""

from __future__ import annotations

import argparse
import pathlib
import zipfile

FIXED_TIMESTAMP = (2026, 1, 1, 0, 0, 0)


def source_files(root: pathlib.Path) -> list[pathlib.Path]:
    """Return only importable authlab Python source files."""
    return sorted(path for path in (root / "authlab").rglob("*.py") if path.is_file())


def build_bundle(root: pathlib.Path, destination: pathlib.Path) -> int:
    """Write a reproducible ZIP and return its source-file count."""
    files = source_files(root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for source in files:
            relative = source.relative_to(root)
            info = zipfile.ZipInfo(relative.as_posix(), date_time=FIXED_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, source.read_bytes())
    return len(files)


def main() -> None:
    root = pathlib.Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=root / "docs" / "assets" / "authlab-pyodide.zip",
        help="output ZIP path (default: docs/assets/authlab-pyodide.zip)",
    )
    args = parser.parse_args()
    destination = args.output.resolve()
    count = build_bundle(root, destination)
    try:
        display = destination.relative_to(root)
    except ValueError:
        display = destination
    print(f"Built {display} with {count} Python source files.")


if __name__ == "__main__":
    main()
