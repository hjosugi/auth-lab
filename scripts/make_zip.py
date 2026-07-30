#!/usr/bin/env python3
"""Compatibility entry point for the canonical deterministic bundle builder."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.build_zip import main  # noqa: E402


if __name__ == "__main__":
    main()
