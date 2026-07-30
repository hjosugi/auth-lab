#!/usr/bin/env python3
"""Build a deterministic source and learning-material ZIP archive."""

from __future__ import annotations

import pathlib
import subprocess
import zipfile

EXCLUDED_PARTS = {
    ".git",
    ".tmp",
    ".venv",
    "__pycache__",
    "dist",
    "graphify-out",
    "target",
}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}
GENERATED_LEARNING_ASSETS = {
    pathlib.Path("docs/assets/authlab-pyodide.zip"),
}


def included(path: pathlib.Path, root: pathlib.Path) -> bool:
    relative = path.relative_to(root)
    return (
        path.is_file()
        and not any(part in EXCLUDED_PARTS for part in relative.parts)
        and path.suffix not in EXCLUDED_SUFFIXES
        and path.name not in {"site-desktop.png", "site-mobile.png"}
    )


def source_files(root: pathlib.Path) -> list[pathlib.Path]:
    """Return tracked source plus intentional generated learning assets.

    A developer checkout may contain graph output, screenshots, or unrelated
    untracked experiments.  Those must not silently enter a release artifact.
    An unpacked source archive has no Git metadata, so it falls back to the
    files that archive already contains.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
        )
        relative_paths = {
            pathlib.Path(raw.decode("utf-8"))
            for raw in result.stdout.split(b"\0")
            if raw
        }
        relative_paths.update(
            path for path in GENERATED_LEARNING_ASSETS if (root / path).is_file()
        )
        candidates = (root / path for path in relative_paths)
    except (FileNotFoundError, subprocess.CalledProcessError):
        candidates = root.rglob("*")
    return sorted(path for path in candidates if included(path, root))


def main() -> None:
    root = pathlib.Path(__file__).resolve().parents[1]
    destination = root / "dist" / "auth-lab-learning-bundle.zip"
    destination.parent.mkdir(exist_ok=True)
    files = source_files(root)
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
