#!/usr/bin/env python3
"""Run the dependency-free verification suite."""

from __future__ import annotations

import pathlib
import subprocess
import sys


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-v"],
        cwd=root,
        check=False,
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
