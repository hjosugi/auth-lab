from __future__ import annotations

from pathlib import Path
import subprocess
import unittest

from scripts.build_zip import GENERATED_LEARNING_ASSETS, source_files


ROOT = Path(__file__).resolve().parents[1]


class TestLearningBundleSources(unittest.TestCase):
    def test_checkout_uses_tracked_files_only(self):
        relative = {path.relative_to(ROOT) for path in source_files(ROOT)}
        tracked = {
            Path(raw.decode("utf-8"))
            for raw in subprocess.run(
                ["git", "-C", str(ROOT), "ls-files", "-z"],
                check=True,
                capture_output=True,
            ).stdout.split(b"\0")
            if raw
        }
        generated = {
            path for path in GENERATED_LEARNING_ASSETS if (ROOT / path).is_file()
        }
        self.assertEqual(relative.difference(tracked), generated)
        self.assertIn(Path("README.md"), relative)
        self.assertIn(Path("interop/compose.yaml"), relative)
        self.assertNotIn(Path("graphify-out/graph.json"), relative)
        self.assertNotIn(Path(".tmp/browser-evidence/screenshot.png"), relative)

    def test_generated_pyodide_bundle_is_the_only_untracked_asset_allowlist(self):
        self.assertEqual(
            GENERATED_LEARNING_ASSETS,
            {Path("docs/assets/authlab-pyodide.zip")},
        )


if __name__ == "__main__":
    unittest.main()
