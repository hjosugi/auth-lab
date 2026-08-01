"""AGENTS.md is the repository's stated source of truth, so it must be true.

Two ways it had drifted, both invisible to CI:

1. It claimed a fixed number of drills and attack regressions. Those numbers
   were right when written and wrong once the suite grew, so the file that a
   contributor reads first was quietly lying about what the suite covers.

2. Its verification block listed three commands while CI enforced roughly ten.
   Following the documented list produced a change that looked verified locally
   and then failed in CI -- the same shape as the bug where the site served raw
   Markdown: the checks that ran were not the checks that mattered.

These tests keep the document honest by comparing it against the repository
itself. They need no dependencies, so they run in the ordinary suite.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENTS = ROOT / "AGENTS.md"
CI = ROOT / ".github" / "workflows" / "ci.yml"


def agents_text() -> str:
    return AGENTS.read_text(encoding="utf-8")


class TestAgentsGuideIsAccurate(unittest.TestCase):
    def test_referenced_paths_exist(self) -> None:
        """Every repository path named in AGENTS.md must resolve."""
        text = agents_text()
        # `docs/x.md`, `authlab/`, `tests/browser/y.mjs`, ... in backticks.
        candidates = re.findall(r"`([A-Za-z0-9_][A-Za-z0-9_./-]*\.[A-Za-z0-9]+|[a-z_]+/)`", text)
        missing = sorted({c for c in candidates if not (ROOT / c).exists()})
        self.assertEqual(
            missing, [], f"AGENTS.md names paths that do not exist: {missing}"
        )

    def test_no_hardcoded_suite_counts(self) -> None:
        """A literal drill/regression count in prose goes stale silently.

        The counts change whenever the suite grows. Rather than keep a number
        in sync by hand, AGENTS.md defers to what verify.py prints.
        """
        text = agents_text()
        stale = re.findall(
            r"\b\d+\s+(?:drills?|attack regressions?|tests?)\b", text
        )
        self.assertEqual(
            stale,
            [],
            "AGENTS.md hard-codes a suite size; these drift as the suite grows. "
            f"Found: {stale}",
        )

    def test_documented_js_checks_cover_what_ci_checks(self) -> None:
        """A contributor following AGENTS.md must not miss a file CI checks."""
        ci_files = set(re.findall(r"node --check (\S+)", CI.read_text(encoding="utf-8")))
        self.assertTrue(ci_files, "no node --check steps found in ci.yml")
        documented = agents_text()
        missing = sorted(f for f in ci_files if f not in documented)
        self.assertEqual(
            missing,
            [],
            "CI runs node --check on files AGENTS.md does not mention, so a "
            f"local run would miss them: {missing}",
        )

    def test_documented_verification_mentions_the_docs_build(self) -> None:
        """The strict site build is a CI gate; it has to be in the local list."""
        self.assertIn("mkdocs build --strict", agents_text())


def _run(*args: str) -> subprocess.CompletedProcess:
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


class TestAttackScriptsRunAsDocumented(unittest.TestCase):
    """The attack scripts must run the way the docs spell them out.

    catalog.py used to need `PYTHONPATH=.` while run_regressions.py beside it
    did not, so the docs carried the prefix on one and not the other and the
    obvious command failed. Same root cause as the drills.
    """

    def test_catalog_without_pythonpath(self) -> None:
        result = _run("attacks/catalog.py")
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

    def test_regressions_without_pythonpath(self) -> None:
        result = _run("attacks/run_regressions.py")
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        self.assertIn("refused", result.stdout)

    def test_docs_do_not_prescribe_a_pythonpath_prefix(self) -> None:
        """Now that the scripts stand alone, the prefix is misleading noise."""
        offenders = []
        for md in [ROOT / "README.md", ROOT / "AGENTS.md", *sorted((ROOT / "docs").glob("*.md"))]:
            for line in md.read_text(encoding="utf-8").splitlines():
                if re.search(r"PYTHONPATH=\S*\s+python\s+attacks/", line):
                    offenders.append(f"{md.name}: {line.strip()}")
        self.assertEqual(offenders, [], "attack scripts no longer need PYTHONPATH")


if __name__ == "__main__":
    unittest.main()
