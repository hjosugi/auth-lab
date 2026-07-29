"""Drill 07 -- DPoP sender-constrained tokens (RFC 9449)."""

from __future__ import annotations

from _util import assert_true, expect_reject, note, step, title

from authlab.oauth import AuthorizationServer, Client, DPoPClientKey, ResourceServer, User, pkce
from authlab.util.clock import FrozenClock


def main() -> None:
    title("Drill 07: DPoP -- binding a token to a key")
    clock = FrozenClock(1_700_000_000)
    server = AuthorizationServer(clock=clock)
    server.register_client(Client(
        client_id="web-app", redirect_uris=["https://app/cb"],
        scopes=["openid", "orders:read"], token_endpoint_auth_method="none",
    ))
    server.register_user(User(subject="u-alice", username="alice", password_hash="x"))

    step(1, "The client generates a DPoP key and includes its thumbprint in /authorize.")
    key = DPoPClientKey(clock=clock)
    note(f"jkt (key thumbprint): {key.thumbprint[:24]}...")
    verifier, challenge = pkce.generate_pair()
    params = {
        "client_id": "web-app", "redirect_uri": "https://app/cb", "response_type": "code",
        "scope": "openid orders:read", "state": "s",
        "code_challenge": challenge, "code_challenge_method": "S256", "dpop_jkt": key.thumbprint,
    }
    validated = server.validate_authorization_request(params)
    code = server.issue_authorization_code(validated, "u-alice")

    step(2, "Token request carries a DPoP proof; the token comes back bound to the key.")
    proof = key.proof("POST", f"{server.issuer}/token")
    tokens = server.token(
        {"grant_type": "authorization_code", "code": code, "redirect_uri": "https://app/cb",
         "client_id": "web-app", "code_verifier": verifier},
        dpop_proof=proof, token_endpoint_url=f"{server.issuer}/token",
    )
    assert_true(tokens["token_type"] == "DPoP", "token_type is DPoP, not Bearer")
    bound = server.introspect(tokens["access_token"])["cnf"]["jkt"]
    assert_true(bound == key.thumbprint, "token's cnf.jkt matches the client key")

    step(3, "Resource server accepts the token WITH a fresh matching proof.")
    rs = ResourceServer(audience="https://api.auth-lab.local", issuer=server.issuer, jwks=server.jwks, clock=clock)
    url = "https://api.auth-lab.local/orders"
    ok = rs.authenticate(
        f"DPoP {tokens['access_token']}", method="GET", url=url,
        dpop_proof=key.proof("GET", url, access_token=tokens["access_token"]),
    )
    assert_true(bool(ok), "valid DPoP request accepted")

    step(4, "A stolen token is useless to an attacker.")
    expect_reject(
        "stolen token presented as Bearer",
        lambda: rs.authenticate(f"Bearer {tokens['access_token']}", method="GET", url=url),
    )
    attacker = DPoPClientKey(clock=clock)
    expect_reject(
        "stolen token with the attacker's own key",
        lambda: rs.authenticate(f"DPoP {tokens['access_token']}", method="GET", url=url,
                                dpop_proof=attacker.proof("GET", url, access_token=tokens["access_token"])),
    )

    step(5, "A proof is single-use and bound to method + URL.")
    reused = key.proof("GET", url, access_token=tokens["access_token"])
    rs.authenticate(f"DPoP {tokens['access_token']}", method="GET", url=url, dpop_proof=reused)
    expect_reject(
        "replaying the same proof (jti)",
        lambda: rs.authenticate(f"DPoP {tokens['access_token']}", method="GET", url=url, dpop_proof=reused),
    )
    expect_reject(
        "proof minted for another URL",
        lambda: rs.authenticate(f"DPoP {tokens['access_token']}", method="GET", url=url,
                                dpop_proof=key.proof("GET", "https://api.auth-lab.local/admin", access_token=tokens["access_token"])),
    )

    print("\nDrill 07 complete.")


if __name__ == "__main__":
    main()
