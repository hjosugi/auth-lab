"""Drill 06 -- Device code flow (RFC 8628) and client credentials."""

from __future__ import annotations

from _util import assert_true, expect_reject, note, step, title

from authlab.oauth import AuthorizationServer, Client, User
from authlab.util.clock import FrozenClock


def main() -> None:
    title("Drill 06: device code + client credentials")
    clock = FrozenClock(1_700_000_000)
    server = AuthorizationServer(clock=clock)
    server.register_client(Client(
        client_id="tv", redirect_uris=[],
        grant_types=["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
        scopes=["openid", "orders:read"], token_endpoint_auth_method="none",
    ))
    server.register_client(Client(
        client_id="batch", client_secret="secret", grant_types=["client_credentials"],
        scopes=["orders:read"], response_types=[],
    ))
    server.register_user(User(subject="u-alice", username="alice", password_hash="x"))

    step(1, "The TV asks for a device code and shows the user a short code.")
    device = server.device_authorization({"client_id": "tv", "scope": "openid orders:read"})
    note(f"user_code: {device['user_code']}  ->  visit {device['verification_uri']}")
    poll = {"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device["device_code"], "client_id": "tv"}

    step(2, "While the user has not approved, polling returns authorization_pending.")
    expect_reject("poll before approval", lambda: server.token(poll))

    step(3, "Polling faster than the interval returns slow_down.")
    expect_reject("poll too fast", lambda: server.token(poll))

    step(4, "The user approves on their phone; the TV's next poll gets tokens.")
    server.approve_device(device["user_code"], "u-alice", amr=["pwd", "otp"])
    tokens = server.token(poll)
    assert_true("access_token" in tokens and "id_token" in tokens, "TV received tokens after approval")

    step(5, "The device code is single-use.")
    expect_reject("device code reuse", lambda: server.token(poll))

    step(6, "Client credentials: no user, no refresh token, no ID token.")
    cc = server.token({"grant_type": "client_credentials", "client_id": "batch", "client_secret": "secret", "scope": "orders:read"})
    assert_true("refresh_token" not in cc and "id_token" not in cc, "machine token only, as it should be")
    expect_reject(
        "wrong client secret",
        lambda: server.token({"grant_type": "client_credentials", "client_id": "batch", "client_secret": "nope"}),
    )

    print("\nDrill 06 complete.")


if __name__ == "__main__":
    main()
