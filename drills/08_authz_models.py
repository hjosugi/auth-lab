"""Drill 08 -- RBAC vs ABAC vs ReBAC on the same question."""

from __future__ import annotations

from _util import assert_true, note, step, title

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


def main() -> None:
    title("Drill 08: authorization models")

    step(1, "RBAC: roles inherit, and wildcards are visible in explain().")
    rbac = RBAC()
    rbac.define_role("viewer", ["orders:read"])
    rbac.define_role("editor", ["orders:write"], inherits=["viewer"])
    rbac.define_role("admin", ["*"], inherits=["editor"])
    rbac.assign("alice", "editor")
    rbac.assign("root", "admin")
    assert_true(rbac.can("alice", "orders:read"), "alice inherits orders:read from viewer")
    assert_true(rbac.can("root", "billing:delete"), "root's admin '*' covers everything")
    note(rbac.explain("alice", "orders:read"))
    note("RBAC cannot express 'their own orders' -- that needs ABAC or ReBAC.")

    step(2, "ABAC: deny-overrides, default-deny, with a 'their own' condition.")
    abac = ABAC([
        Policy("deny-contractor-salary", Effect.DENY, resource_types=["salary"],
               condition=attr_equals("subject", "employment", "contractor")),
        Policy("owner-read", Effect.ALLOW, actions=["read"],
               condition=subject_matches_resource_owner()),
        Policy("manager-approve", Effect.ALLOW, actions=["approve"], resource_types=["expense"],
               condition=all_of(attr_equals("subject", "role", "manager"),
                                attr_lte("resource", "amount", 100000),
                                time_between(9, 18), attr_equals("subject", "mfa", True))),
    ])
    assert_true(abac.can(AbacRequest(subject={"sub": "alice"}, resource={"type": "doc", "owner": "alice"}, action="read")),
                "alice reads her own doc")
    assert_true(not abac.can(AbacRequest(subject={"sub": "alice"}, resource={"type": "doc", "owner": "bob"}, action="read")),
                "alice cannot read bob's doc (default deny)")
    decision = abac.evaluate(AbacRequest(subject={"sub": "c1", "employment": "contractor"},
                                         resource={"type": "salary", "owner": "c1"}, action="read"))
    assert_true(not decision.allowed, "explicit deny beats the owner-read allow")
    note(f"contractor reading own salary: {decision.effect.value} ({decision.reason})")

    step(3, "ReBAC: relationships and inheritance (the Google Drive model).")
    z = google_drive_model()
    z.write(
        "group:eng#member@user:alice",
        "group:eng#member@group:platform#member",
        "group:platform#member@user:carol",
        "folder:2024#viewer@group:eng#member",
        "document:budget#parent@folder:2024",
        "document:budget#owner@user:erin",
    )
    assert_true(z.check("document:budget", "viewer", "user:alice"),
                "alice views budget via eng -> folder viewer -> document")
    assert_true(z.check("document:budget", "viewer", "user:carol"),
                "carol views it through a NESTED group (platform in eng)")
    assert_true(z.check("document:budget", "editor", "user:erin"),
                "erin edits it as the document owner")
    assert_true(not z.check("document:budget", "viewer", "user:mallory"),
                "mallory has no path and is denied")
    note(f"alice can view: {z.list_objects('user:alice', 'viewer', 'document')}")
    note(f"budget viewers: {z.list_users('document:budget', 'viewer')}")

    print("\nDrill 08 complete.")


if __name__ == "__main__":
    main()
