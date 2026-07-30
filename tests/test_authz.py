import unittest

from authlab.authz import (
    ABAC,
    AbacRequest,
    Effect,
    Policy,
    RBAC,
    all_of,
    attr_equals,
    attr_lte,
    subject_matches_resource_owner,
    time_between,
)
from authlab.authz.rebac import google_drive_model


class TestRBAC(unittest.TestCase):
    def setUp(self):
        self.rbac = RBAC()
        self.rbac.define_role("viewer", ["orders:read"])
        self.rbac.define_role("editor", ["orders:write"], inherits=["viewer"])
        self.rbac.define_role("admin", ["*"], inherits=["editor"])
        self.rbac.assign("alice", "editor")
        self.rbac.assign("root", "admin")

    def test_inheritance(self):
        self.assertTrue(self.rbac.can("alice", "orders:read"))
        self.assertTrue(self.rbac.can("alice", "orders:write"))

    def test_wildcard(self):
        self.assertTrue(self.rbac.can("root", "anything:delete"))

    def test_denied(self):
        self.assertFalse(self.rbac.can("alice", "billing:delete"))

    def test_cycle_detection(self):
        rbac = RBAC()
        rbac.define_role("a", inherits=["b"])
        with self.assertRaises(ValueError):
            rbac.define_role("b", inherits=["a"])

    def test_reverse_query(self):
        self.assertEqual(self.rbac.subjects_with("orders:write"), ["alice", "root"])


class TestABAC(unittest.TestCase):
    def setUp(self):
        self.abac = ABAC([
            Policy("deny-contractor-salary", Effect.DENY, resource_types=["salary"],
                   condition=attr_equals("subject", "employment", "contractor")),
            Policy("owner-read", Effect.ALLOW, actions=["read"], condition=subject_matches_resource_owner()),
            Policy("manager-approve", Effect.ALLOW, actions=["approve"], resource_types=["expense"],
                   condition=all_of(attr_equals("subject", "role", "manager"),
                                    attr_lte("resource", "amount", 100000), time_between(9, 18))),
        ])

    def test_owner_read(self):
        self.assertTrue(self.abac.can(AbacRequest(subject={"sub": "a"}, resource={"type": "d", "owner": "a"}, action="read")))

    def test_default_deny(self):
        self.assertFalse(self.abac.can(AbacRequest(subject={"sub": "a"}, resource={"type": "d", "owner": "b"}, action="read")))

    def test_deny_overrides(self):
        d = self.abac.evaluate(AbacRequest(subject={"sub": "c", "employment": "contractor"},
                                           resource={"type": "salary", "owner": "c"}, action="read"))
        self.assertFalse(d.allowed)

    def test_conditions(self):
        self.assertTrue(self.abac.can(AbacRequest(subject={"role": "manager"},
                                                  resource={"type": "expense", "amount": 50000}, action="approve",
                                                  environment={"hour": 10})))
        self.assertFalse(self.abac.can(AbacRequest(subject={"role": "manager"},
                                                   resource={"type": "expense", "amount": 500000}, action="approve",
                                                   environment={"hour": 10})))
        self.assertFalse(self.abac.can(AbacRequest(subject={"role": "manager"},
                                                   resource={"type": "expense", "amount": 5000}, action="approve",
                                                   environment={"hour": 3})))


class TestReBAC(unittest.TestCase):
    def setUp(self):
        self.z = google_drive_model()
        self.z.write(
            "group:eng#member@user:alice",
            "group:eng#member@group:platform#member",
            "group:platform#member@user:carol",
            "folder:2024#viewer@group:eng#member",
            "document:budget#parent@folder:2024",
            "document:budget#owner@user:erin",
        )

    def test_direct_and_group(self):
        self.assertTrue(self.z.check("document:budget", "viewer", "user:alice"))

    def test_nested_group(self):
        self.assertTrue(self.z.check("document:budget", "viewer", "user:carol"))

    def test_owner_is_editor(self):
        self.assertTrue(self.z.check("document:budget", "editor", "user:erin"))

    def test_denied(self):
        self.assertFalse(self.z.check("document:budget", "viewer", "user:mallory"))

    def test_list_objects(self):
        self.assertIn("document:budget", self.z.list_objects("user:alice", "viewer", "document"))

    def test_wildcard_grant(self):
        self.z.write("document:public#viewer@user:*")
        self.assertTrue(self.z.check("document:public", "viewer", "user:anyone"))

    def test_cycle_safe(self):
        self.z.write("group:platform#member@group:eng#member")
        self.assertFalse(self.z.check("document:budget", "viewer", "user:mallory"))

    def test_expand_reports_cycle(self):
        self.z.write("group:platform#member@group:eng#member")
        expanded = self.z.expand("group:eng", "member")
        self.assertIn('"type": "cycle"', __import__("json").dumps(expanded))

    def test_configurable_depth_limit(self):
        from authlab.authz import ReBAC

        engine = ReBAC(max_depth=1)
        engine.namespace("group").relation("member")
        engine.write(
            "group:a#member@group:b#member",
            "group:b#member@group:c#member",
            "group:c#member@user:alice",
        )
        self.assertFalse(engine.check("group:a", "member", "user:alice"))


if __name__ == "__main__":
    unittest.main()
