"""Drill 05 -- Refresh token rotation and reuse detection."""

from __future__ import annotations

from _util import assert_true, expect_reject, note, step, title

from authlab.oauth import AuthorizationServer, Client, User, pkce
from authlab.util.clock import FrozenClock


def _code_grant(server: AuthorizationServer, scope: str = "openid orders:read orders:write") -> dict:
    verifier, challenge = pkce.generate_pair()
    params = {
        "client_id": "web-app", "redirect_uri": "https://app/cb", "response_type": "code",
        "scope": scope, "state": "s", "code_challenge": challenge, "code_challenge_method": "S256",
    }
    validated = server.validate_authorization_request(params)
    code = server.issue_authorization_code(validated, "u-alice")
    return {
        "grant_type": "authorization_code", "code": code, "redirect_uri": "https://app/cb",
        "client_id": "web-app", "code_verifier": verifier,
    }


def main() -> None:
    title("Drill 05: refresh token rotation + reuse detection")
    clock = FrozenClock(1_700_000_000)
    server = AuthorizationServer(clock=clock)
    server.register_client(Client(
        client_id="web-app", redirect_uris=["https://app/cb"],
        scopes=["openid", "orders:read", "orders:write"], token_endpoint_auth_method="none",
    ))
    server.register_user(User(subject="u-alice", username="alice", password_hash="x"))

    step(1, "Get an initial token set with a refresh token.")
    first = server.token(_code_grant(server))
    r1 = first["refresh_token"]
    note(f"refresh token r1: {r1[:20]}...")

    step(2, "Refresh rotates: r1 is spent and a new r2 comes back.")
    second = server.token({"grant_type": "refresh_token", "refresh_token": r1, "client_id": "web-app"})
    r2 = second["refresh_token"]
    assert_true(r1 != r2, "each refresh returns a brand-new token (rotation)")

    step(3, "Scope may be narrowed on refresh, never widened.")
    third = server.token({"grant_type": "refresh_token", "refresh_token": r2, "client_id": "web-app", "scope": "orders:read"})
    assert_true(third["scope"] == "orders:read", "scope narrowed to orders:read")
    expect_reject(
        "widen scope on refresh",
        lambda: server.token({"grant_type": "refresh_token", "refresh_token": third["refresh_token"],
                              "client_id": "web-app", "scope": "orders:write"}),
    )

    step(4, "Replaying the OLD r1 is detected and revokes the entire family.")
    note("r1 was already rotated away; presenting it again means it leaked.")
    expect_reject(
        "replay of the rotated r1",
        lambda: server.token({"grant_type": "refresh_token", "refresh_token": r1, "client_id": "web-app"}),
    )

    step(5, "After the family is revoked, even the current token is dead.")
    expect_reject(
        "current token after family revoke",
        lambda: server.token({"grant_type": "refresh_token", "refresh_token": third["refresh_token"], "client_id": "web-app"}),
    )
    note("both the legitimate user and the attacker are logged out -- the correct response to a leak.")

    print("\nDrill 05 complete.")


if __name__ == "__main__":
    main()
