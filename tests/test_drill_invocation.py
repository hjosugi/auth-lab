"""The drills must run the way the README says to run them.

The README tells a reader to run `python drills/run_all.py` from a fresh
checkout. That only works if the repo root is on sys.path, and nothing about
invoking a script in a subdirectory puts it there -- Python puts the *script's*
directory on the path, which is `drills/`, not the root. So the drills used to
import authlab only when something upstream had already exported PYTHONPATH,
which `scripts/verify.py` does and a human following the README does not.

These tests run the documented commands in a subprocess with PYTHONPATH
explicitly removed, so a regression shows up here instead of in the first five
minutes of somebody's first day with the repo.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str) -> subprocess.CompletedProcess:
    """Run a command from the repo root with PYTHONPATH unset."""
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    return subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )


class TestDrillsRunAsDocumented(unittest.TestCase):
    def test_run_all_without_pythonpath(self):
        result = _run("drills/run_all.py")
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        self.assertIn("drills passed", result.stdout)

    def test_each_drill_standalone(self):
        """`python drills/03_jwt.py` is how the drill docstrings say to run one."""
        drills = sorted(
            path.name
            for path in (ROOT / "drills").glob("[0-9][0-9]_*.py")
        )
        self.assertGreaterEqual(len(drills), 14, "expected the full drill set")
        for name in drills:
            with self.subTest(drill=name):
                result = _run(f"drills/{name}")
                self.assertEqual(
                    result.returncode, 0, msg=result.stdout + result.stderr
                )


if __name__ == "__main__":
    unittest.main()
