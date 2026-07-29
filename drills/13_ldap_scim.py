"""Drill 13 -- LDAP authentication (injection + anon-bind) and SCIM provisioning."""

from __future__ import annotations

from _util import assert_true, expect_reject, note, step, title

from authlab.directory import LDAP, SCIMServer, escape_filter


def main() -> None:
    title("Drill 13: LDAP + SCIM")

    step(1, "Build a small directory with hashed passwords.")
    directory = LDAP()
    directory.add("dc=lab,dc=local", {"objectClass": ["domain"]})
    directory.add("ou=people,dc=lab,dc=local", {"objectClass": ["organizationalUnit"]})
    directory.add("uid=alice,ou=people,dc=lab,dc=local",
                  {"objectClass": ["inetOrgPerson"], "uid": ["alice"], "mail": ["alice@lab.local"]},
                  password="alice-pw")
    directory.add("uid=admin,ou=people,dc=lab,dc=local",
                  {"objectClass": ["inetOrgPerson"], "uid": ["admin"]}, password="admin-pw")
    base = "ou=people,dc=lab,dc=local"

    step(2, "Search-then-bind: correct login works, wrong password does not.")
    assert_true(bool(directory.authenticate("alice", "alice-pw", base_dn=base)), "alice logs in")
    assert_true(not directory.authenticate("alice", "wrong", base_dn=base), "wrong password rejected")

    step(3, "The empty-password anonymous-bind trap is refused.")
    assert_true(not directory.authenticate("alice", "", base_dn=base), "blank password does not authenticate")
    expect_reject("direct simple_bind with empty password", lambda: directory.simple_bind("uid=alice,ou=people,dc=lab,dc=local", ""))

    step(4, "LDAP injection is neutralised by escaping + a real filter parser.")
    assert_true(not directory.authenticate("*)(uid=*", "x", base_dn=base), "injection payload does not log anyone in")
    note(f"payload '*)(uid=*)' escapes to: {escape_filter('*)(uid=*)')}")
    injected = directory.search(base, f"(uid={escape_filter('*)(uid=*')})")
    assert_true(len(injected) == 0, "the escaped filter matches nothing")
    legit = [e.first("uid") for e in directory.search(base, "(uid=a*)")]
    assert_true(set(legit) == {"alice", "admin"}, f"legitimate wildcard search still works: {legit}")

    step(5, "SCIM: provision a user (the IdP creating an account).")
    scim = SCIMServer()
    user = scim.create_user({"userName": "bob", "externalId": "okta-123",
                             "emails": [{"value": "bob@lab.local", "primary": True}], "name": {"givenName": "Bob"}})
    assert_true(scim.is_active(user["id"]), "bob provisioned and active")
    expect_reject("duplicate userName", lambda: scim.create_user({"userName": "bob"}))

    step(6, "SCIM: deactivation (offboarding) is what actually cuts access.")
    scim.deactivate_user(user["id"])
    assert_true(not scim.is_active(user["id"]), "after PATCH active=false, is_active() is False")
    note(f"event log: {scim.events[-1]}")
    note("downstream sessions must consult is_active() -- SCIM only flips the flag.")

    step(7, "SCIM filters are parsed, not string-matched.")
    scim.create_user({"userName": "carol", "active": False, "emails": [{"value": "carol@lab.local"}]})
    assert_true(scim.list_users('emails.value co "lab.local"')["totalResults"] == 2, "filter finds both users by email domain")
    expect_reject("malformed / injected filter", lambda: scim.list_users('userName eq "x") or (1 eq 1'))

    print("\nDrill 13 complete.")


if __name__ == "__main__":
    main()
