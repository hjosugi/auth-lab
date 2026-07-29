#!/usr/bin/env python3
"""One command to check the whole lab is healthy.

Runs the unittest suite, every drill, and the attack regressions, and exits
non-zero if anything fails. This is the "did I break something" button.

    python scripts/verify.py
"""

from __future__ import annotations

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(label: str, argv: list[str]) -> bool:
    print(f"\n{'=' * 60}\n{label}\n{'=' * 60}")
    env = dict(os.environ, PYTHONPATH=ROOT)
    result = subprocess.run(argv, cwd=ROOT, env=env)
    ok = result.returncode == 0
    print(f"-> {'PASS' if ok else 'FAIL'} ({label})")
    return ok


def main() -> int:
    results = []
    results.append(run("unittest suite (108 tests)",
                       [sys.executable, "-m", "unittest", "discover", "-s", "tests"]))
    results.append(run("drills (run_all)", [sys.executable, "drills/run_all.py"]))
    results.append(run("attack regressions", [sys.executable, "attacks/run_regressions.py"]))

    print(f"\n{'=' * 60}")
    if all(results):
        print("ALL GREEN — tests, drills, and attack regressions pass.")
        return 0
    print("SOMETHING FAILED — see the sections above.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
