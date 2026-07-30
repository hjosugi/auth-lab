import json
import pathlib
import tempfile
import unittest

from authlab.directory.scim import SCIMError, SCIMServer
from tests.property_fuzz import (
    CampaignConfig,
    minimize_sequence,
    minimize_text,
    run_campaign,
)


class TestPropertyFuzzHarness(unittest.TestCase):
    def test_bounded_campaign_writes_replay_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            report = run_campaign(
                CampaignConfig(
                    seed=12345,
                    cases=4,
                    max_size=64,
                    max_steps=6,
                    deadline_seconds=10,
                ),
                output,
            )

            self.assertTrue(report.success)
            self.assertEqual((output / "seed.txt").read_text().strip(), "12345")
            self.assertEqual(
                json.loads((output / "counterexamples.json").read_text()),
                [],
            )
            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(summary["counterexample_count"], 0)
            self.assertEqual(summary["configuration"]["max_size"], 64)

    def test_delta_minimizers_keep_only_failure_inducing_input(self):
        self.assertEqual(
            minimize_text("safe!padding", lambda value: "!" in value),
            "!",
        )
        self.assertEqual(
            minimize_sequence(
                ["begin", "wrong_state", "replay"],
                lambda value: "replay" in value,
            ),
            ["replay"],
        )

    def test_campaign_rejects_unbounded_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                run_campaign(
                    CampaignConfig(cases=5_001),
                    pathlib.Path(directory),
                )


class TestScimParserBoundary(unittest.TestCase):
    def test_valid_filter_still_matches(self):
        server = SCIMServer()
        server.create_user({"userName": "alice"})
        result = server.list_users('userName eq "alice"')
        self.assertEqual(result["totalResults"], 1)

    def test_blank_and_dangling_filters_are_protocol_errors(self):
        server = SCIMServer()
        server.create_user({"userName": "alice"})
        for malformed in (" ", "(", 'userName eq "alice" and'):
            with self.subTest(malformed=malformed):
                with self.assertRaises(SCIMError):
                    server.list_users(malformed)


if __name__ == "__main__":
    unittest.main()
