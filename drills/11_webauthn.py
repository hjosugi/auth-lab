"""Drill 11 -- WebAuthn / passkeys: registration, login, phishing resistance."""

from __future__ import annotations

import json

from _util import assert_true, expect_reject, note, step, title

from authlab.util.encoding import b64u_decode
from authlab.webauthn import RelyingParty, VirtualAuthenticator
from authlab.util.clock import FrozenClock


def main() -> None:
    title("Drill 11: WebAuthn / passkeys")
    clock = FrozenClock(1_700_000_000)
    rp = RelyingParty(rp_id="auth-lab.local", origins=["https://auth-lab.local"], clock=clock)
    authenticator = VirtualAuthenticator()
    user_handle = b"user-alice-0001"

    step(1, "Registration: the authenticator makes a key pair; the RP stores the PUBLIC key.")
    options = rp.registration_options("s1", user_handle, "alice")
    credential = authenticator.make_credential(
        rp_id="auth-lab.local", origin="https://auth-lab.local",
        challenge=b64u_decode(options["challenge"]), user_handle=user_handle, attestation="packed",
    )
    record = rp.verify_registration("s1", credential, user_handle)
    note("nothing secret is stored server-side -- only a public key.")
    assert_true(record.sign_count == 0, "credential registered")

    step(2, "Authentication: sign a fresh challenge; the RP verifies with the public key.")
    options = rp.authentication_options("s2", user_handle)
    assertion = authenticator.get_assertion(
        rp_id="auth-lab.local", origin="https://auth-lab.local", challenge=b64u_decode(options["challenge"]),
    )
    result = rp.verify_authentication("s2", assertion)
    assert_true(result.sign_count == 1, "login verified, signature counter advanced")

    step(3, "Phishing resistance: a look-alike site gets no signature at all.")
    expect_reject(
        "phishing site (auth-1ab.local) requests an assertion",
        lambda: authenticator.get_assertion(rp_id="auth-1ab.local", origin="https://auth-1ab.local", challenge=b"x" * 32),
    )
    note("the authenticator has no key for the wrong rp_id -- there is nothing to phish.")

    step(4, "Even a swapped origin in clientDataJSON is caught by the RP.")
    options = rp.authentication_options("s3", user_handle)
    tampered = authenticator.get_assertion(
        rp_id="auth-lab.local", origin="https://auth-lab.local", challenge=b64u_decode(options["challenge"]),
    )
    data = json.loads(tampered["response"]["clientDataJSON"])
    data["origin"] = "https://auth-lab.local.evil.net"
    tampered["response"]["clientDataJSON"] = json.dumps(data, separators=(",", ":")).encode()
    expect_reject("origin swapped to a suffix domain", lambda: rp.verify_authentication("s3", tampered))

    step(5, "Assertions do not replay (challenge is single use).")
    options = rp.authentication_options("s4", user_handle)
    assertion = authenticator.get_assertion(
        rp_id="auth-lab.local", origin="https://auth-lab.local", challenge=b64u_decode(options["challenge"]),
    )
    rp.verify_authentication("s4", assertion)
    expect_reject("replay the same assertion", lambda: rp.verify_authentication("s4", assertion))

    step(6, "A regressed signature counter looks like a cloned authenticator.")
    options = rp.authentication_options("s5", user_handle)
    cloned = authenticator.get_assertion(
        rp_id="auth-lab.local", origin="https://auth-lab.local",
        challenge=b64u_decode(options["challenge"]), sign_count_override=1,
    )
    expect_reject("counter did not advance", lambda: rp.verify_authentication("s5", cloned))

    step(7, "Syncable passkeys (BE/BS set, counter always 0) are handled correctly.")
    passkey = VirtualAuthenticator(is_platform_passkey=True)
    rp2 = RelyingParty(rp_id="auth-lab.local", origins=["https://auth-lab.local"], clock=clock)
    options = rp2.registration_options("p1", user_handle, "alice")
    cred = passkey.make_credential(rp_id="auth-lab.local", origin="https://auth-lab.local",
                                   challenge=b64u_decode(options["challenge"]), user_handle=user_handle)
    rp2.verify_registration("p1", cred, user_handle)
    for i in range(2):
        options = rp2.authentication_options(f"p{i+2}", user_handle)
        a = passkey.get_assertion(rp_id="auth-lab.local", origin="https://auth-lab.local",
                                  challenge=b64u_decode(options["challenge"]))
        rp2.verify_authentication(f"p{i+2}", a)
    note("two logins with counter=0 both accepted -- correct for a synced passkey.")

    print("\nDrill 11 complete.")


if __name__ == "__main__":
    main()
