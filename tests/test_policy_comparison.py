import json
import unittest

from authlab.authz import (
    AccessRequest,
    CANONICAL_CASES,
    CEDAR_POLICY,
    PolicyComparison,
    PrivacyPreservingDecisionLog,
    REGO_POLICY,
    canonical_dataset,
)


class TestPolicyParity(unittest.TestCase):
    def setUp(self):
        self.dataset = canonical_dataset()
        self.comparison = PolicyComparison(self.dataset)

    def test_canonical_matrix_has_decision_parity(self):
        for name, (request, expected) in CANONICAL_CASES.items():
            with self.subTest(name=name):
                self.assertEqual(self.comparison.require_parity(request), expected)

    def test_tenant_boundary_beats_group_membership(self):
        request, _ = CANONICAL_CASES["tenant-boundary"]
        decisions = self.comparison.decide_all(request)
        self.assertTrue(all(not decision.allowed for decision in decisions.values()))
        self.assertEqual(
            {decision.reason_code for decision in decisions.values()},
            {"tenant-boundary"},
        )

    def test_explicit_deny_beats_owner_allow(self):
        request, _ = CANONICAL_CASES["explicit-deny-owner"]
        decisions = self.comparison.decide_all(request)
        self.assertTrue(all(not decision.allowed for decision in decisions.values()))
        self.assertEqual(
            {decision.reason_code for decision in decisions.values()},
            {"explicit-deny"},
        )

    def test_nested_group_is_transitive(self):
        resolution = self.dataset.resolve_group("alice", "eng")
        self.assertTrue(resolution.matched)
        self.assertEqual(set(resolution.visited), {"eng", "platform"})

    def test_relationship_cycle_is_detected_and_bounded(self):
        dataset = canonical_dataset(
            group_parents={
                "platform": frozenset({"eng"}),
                "eng": frozenset({"platform"}),
            }
        )
        resolution = dataset.resolve_group("alice", "finance")
        self.assertFalse(resolution.matched)
        self.assertTrue(resolution.cycle_detected)
        self.assertFalse(resolution.depth_limited)

    def test_relationship_depth_is_bounded(self):
        parents = {
            f"g{index}": frozenset({f"g{index + 1}"})
            for index in range(5)
        }
        dataset = canonical_dataset(
            group_parents={"platform": frozenset({"g0"}), **parents},
            max_relationship_depth=2,
        )
        resolution = dataset.resolve_group("alice", "g5")
        self.assertFalse(resolution.matched)
        self.assertTrue(resolution.depth_limited)

    def test_list_objects_has_parity_and_cost_metadata(self):
        results = self.comparison.list_objects_all("alice", "read")
        self.assertEqual(set(results), {"RBAC", "ABAC", "ReBAC", "Cedar", "Rego"})
        self.assertEqual(
            {result.object_ids for result in results.values()},
            {("budget",)},
        )
        for result in results.values():
            self.assertEqual(result.candidate_checks, 3)
            self.assertGreaterEqual(result.elapsed_ns, 0)
            self.assertIn("O(", result.strategy)
            self.assertTrue(result.consistency)

    def test_unknown_entities_and_actions_default_deny(self):
        for request in (
            AccessRequest("nobody", "read", "budget"),
            AccessRequest("alice", "read", "missing"),
            AccessRequest("alice", "delete", "budget"),
        ):
            with self.subTest(request=request):
                self.assertFalse(self.comparison.require_parity(request))

    def test_policy_source_exposes_combining_semantics(self):
        self.assertIn("forbid", CEDAR_POLICY)
        self.assertIn("permit", CEDAR_POLICY)
        self.assertIn("default allow := false", REGO_POLICY)
        self.assertIn("graph.reachable", REGO_POLICY)
        self.assertIn("not deny", REGO_POLICY)


class TestPrivacyPreservingDecisionLog(unittest.TestCase):
    def setUp(self):
        comparison = PolicyComparison(canonical_dataset())
        self.request = AccessRequest("bob", "write", "budget")
        self.decision = comparison.decide_all(self.request)["RBAC"]

    def test_log_minimizes_and_pseudonymizes_identifiers(self):
        logger = PrivacyPreservingDecisionLog(b"test-secret-at-least-16-bytes")
        entry = logger.record(
            self.decision,
            self.request,
            occurred_at=1_700_000_000,
            context={
                "request_id": "request-123",
                "risk_bucket": "high",
                "email": "bob@example.test",
                "ip": "192.0.2.10",
                "access_token": "secret-token",
            },
        )
        encoded = json.dumps(entry.to_dict())
        for raw_value in (
            "bob",
            "budget",
            "request-123",
            "bob@example.test",
            "192.0.2.10",
            "secret-token",
            "owner:budget",
        ):
            self.assertNotIn(raw_value, encoded)
        self.assertEqual(entry.risk_bucket, "high")
        self.assertTrue(entry.subject_ref.startswith("hmac-sha256:"))

    def test_pseudonyms_are_stable_and_domain_separated(self):
        logger = PrivacyPreservingDecisionLog(b"test-secret-at-least-16-bytes")
        first = logger.record(
            self.decision, self.request, occurred_at=1_700_000_000
        )
        second = logger.record(
            self.decision, self.request, occurred_at=1_700_000_001
        )
        self.assertEqual(first.subject_ref, second.subject_ref)
        self.assertEqual(first.resource_ref, second.resource_ref)
        self.assertNotEqual(first.subject_ref, first.resource_ref)

    def test_retention_is_enforced(self):
        logger = PrivacyPreservingDecisionLog(
            b"test-secret-at-least-16-bytes", retention_seconds=60
        )
        logger.record(self.decision, self.request, occurred_at=100)
        logger.record(self.decision, self.request, occurred_at=150)
        self.assertEqual(logger.purge(161), 1)
        self.assertEqual(len(logger.entries), 1)

    def test_short_secret_is_rejected(self):
        with self.assertRaises(ValueError):
            PrivacyPreservingDecisionLog(b"too-short")


if __name__ == "__main__":
    unittest.main()
