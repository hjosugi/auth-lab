"""Drill 10 -- Kerberos SSO and the Active Directory attack family."""

from __future__ import annotations

import pickle

from _util import assert_true, expect_reject, note, step, title

from authlab.kerberos import KDC, KerberizedService, KerberosClient
from authlab.kerberos.kdc import decrypt, encrypt, string_to_key, _serialize
from authlab.kerberos.messages import Authenticator
from authlab.util.clock import FrozenClock


def main() -> None:
    title("Drill 10: Kerberos")
    clock = FrozenClock(1_700_000_000)
    kdc = KDC(realm="LAB.LOCAL", clock=clock)
    kdc.add_principal("alice", "S3cr3t-alice-pw", groups=["Users", "Engineering"])
    kdc.add_principal("HTTP/web.lab.local", "Long-Random-Service-Pw-2846", is_service=True)
    kdc.add_principal("svc_sql", "summer2023", is_service=True)         # weak service password
    kdc.add_principal("svc_legacy", "pw", require_preauth=False)        # preauth disabled
    web = KerberizedService(name="HTTP/web.lab.local", realm="LAB.LOCAL",
                            key=kdc.principals["HTTP/web.lab.local"].key, clock=clock)

    step(1, "kinit: exchange the password once for a TGT.")
    alice = KerberosClient(principal="alice", realm="LAB.LOCAL", kdc=kdc, clock=clock)
    alice.kinit("S3cr3t-alice-pw")
    note("password used exactly once; everything after this is ticket-based (SSO).")

    step(2, "Get a service ticket and authenticate to the web service (mutual).")
    ticket, authenticator = alice.ap_req("HTTP/web.lab.local")
    client, ap_rep = web.ap_req(ticket, authenticator, mutual=True)
    assert_true(client.groups == ["Users", "Engineering"], "service reads authz groups from the ticket")
    assert_true(alice.verify_ap_rep("HTTP/web.lab.local", ap_rep), "client verifies the server (mutual auth)")

    step(3, "An authenticator cannot be replayed.")
    ticket, authenticator = alice.ap_req("HTTP/web.lab.local")
    web.ap_req(ticket, authenticator, mutual=False)
    expect_reject("authenticator replay", lambda: web.ap_req(ticket, authenticator, mutual=False))

    step(4, "Kerberoasting: crack a service password offline from its ticket.")
    material = alice.get_service_ticket("svc_sql")
    cracked = kdc.crack_service_ticket(material.ticket, ["winter2023", "summer2023", "Password1"], "svc_sql")
    note("no failed logins, no lockout, no network traffic to the target.")
    assert_true(cracked == "summer2023", f"cracked svc_sql password offline: {cracked}")

    step(5, "AS-REP roasting: preauth disabled -> anyone can harvest a crackable blob.")
    rep = kdc.as_req("svc_legacy")  # no PA-ENC-TIMESTAMP required
    found = None
    for candidate in ["x", "pw", "abc"]:
        try:
            decrypt(string_to_key(candidate, "LAB.LOCALsvc_legacy"), rep.enc_part)
            found = candidate
            break
        except Exception:  # noqa: BLE001
            pass
    assert_true(found == "pw", "harvested and cracked the AS-REP offline")
    assert_true(any("roastable" in line for line in kdc.log), "KDC logged the preauth-disabled warning")

    step(6, "Golden ticket: forge a TGT straight from the krbtgt key.")
    golden = kdc.forge_golden_ticket("nobody", groups=["Domain Admins"], lifetime=315_360_000)
    session_key = pickle.loads(decrypt(kdc.krbtgt_key, golden.enc_part)).session_key
    tgs = kdc.tgs_req(
        golden,
        encrypt(session_key, _serialize(Authenticator("nobody@LAB.LOCAL", "LAB.LOCAL", clock.now()))),
        "HTTP/web.lab.local",
    )
    forged_sk = pickle.loads(decrypt(session_key, tgs.enc_part))["session_key"]
    client, _ = web.ap_req(
        tgs.ticket,
        encrypt(forged_sk, _serialize(Authenticator("nobody@LAB.LOCAL", "LAB.LOCAL", clock.now()))),
        mutual=False,
    )
    assert_true(client.groups == ["Domain Admins"], "forged 'nobody' as Domain Admins")
    note("the 10-year lifetime is the detection signal: real TGTs last ~10 hours.")

    step(7, "Pass-the-ticket: replay a stolen service ticket with no TGT or password.")
    stolen = alice.service_tickets["HTTP/web.lab.local"]
    attacker = KerberosClient(principal="alice", realm="LAB.LOCAL", kdc=kdc, clock=clock)
    attacker.import_ticket("HTTP/web.lab.local", stolen.ticket, stolen.session_key, stolen.end_time)
    ticket, authenticator = attacker.ap_req("HTTP/web.lab.local")
    client, _ = web.ap_req(ticket, authenticator, mutual=False)
    assert_true(client.name == "alice@LAB.LOCAL", "replayed the stolen ticket from another host")

    print("\nDrill 10 complete.")


if __name__ == "__main__":
    main()
