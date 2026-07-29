"""Drill 04 -- OAuth authorization code + PKCE + OIDC, end to end."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

from _util import assert_true, expect_reject, note, step, title

from authlab.oauth import AuthorizationServer, Client, OAuthClient, ResourceServer, User
from authlab.passwords import PasswordHasher
from authlab.util.clock import FrozenClock


def main() -> None:
    title("Drill 04: authorization code + PKCE + OIDC")
    clock = FrozenClock(1_700_000_000)
    hasher = PasswordHasher()

    server = AuthorizationServer(issuer="https://as.auth-lab.local", clock=clock)
    server.register_client(Client(
        client_id="web-app", redirect_uris=["https://app.auth-lab.local/cb"],
        scopes=["openid", "profile", "email", "orders:read", "orders:write"],
        token_endpoint_auth_method="none", require_pkce=True,
    ))
    server.register_user(User(
        subject="u-alice", username="alice", password_hash=hasher.hash("pw"),
        email="alice@auth-lab.local", email_verified=True, name="Alice",
    ))
    client = OAuthClient(
        client_id="web-app", redirect_uri="https://app.auth-lab.local/cb",
        authorization_endpoint=f"{server.issuer}/authorize", token_endpoint=f"{server.issuer}/token",
        issuer=server.issuer, scope=["openid", "profile", "email", "orders:read"],
        clock=clock, jwks=server.jwks,
    )

    step(1, "Client builds /authorize with state, nonce, and a PKCE challenge.")
    url = client.begin("session-1")
    params = dict(parse_qsl(urlsplit(url).query))
    note(f"challenge sent (hash only): {params['code_challenge'][:24]}...")
    assert_true(params["code_challenge_method"] == "S256", "S256 challenge, verifier never leaves the client")

    step(2, "User authenticates; AS issues a code bound to the challenge.")
    validated = server.validate_authorization_request(params)
    code = server.issue_authorization_code(validated, "u-alice", amr=["pwd", "otp", "mfa"])
    callback = server.authorization_redirect(validated, code)
    note(f"callback: {callback[:56]}...")

    step(3, "Client validates state, then redeems the code with the verifier.")
    token_request = client.handle_callback("session-1", callback)
    tokens = server.token(token_request)
    assert_true("access_token" in tokens and "id_token" in tokens, "got access_token + id_token")

    step(4, "Client fully validates the ID token (signature, iss, aud=client, nonce).")
    id_claims = client.validate_id_token(tokens["id_token"])
    note(f"sub={id_claims.sub} aud={id_claims.aud} amr={id_claims.get('amr')} at_hash={bool(id_claims.get('at_hash'))}")
    assert_true(id_claims.aud == ["web-app"], "ID token audience is the CLIENT, not the API")

    step(5, "Resource server accepts the access token and enforces scope.")
    rs = ResourceServer(audience="https://api.auth-lab.local", issuer=server.issuer, jwks=server.jwks, clock=clock)
    at_claims = rs.authenticate(f"Bearer {tokens['access_token']}")
    rs.require_scope(at_claims, "orders:read")
    assert_true(at_claims.sub == "u-alice", "access token validates, scope satisfied")

    step(6, "Attacks are refused.")
    expect_reject("code replay", lambda: server.token(token_request))
    expect_reject("ID token used at the API", lambda: rs.authenticate(f"Bearer {tokens['id_token']}"))
    expect_reject(
        "evil redirect_uri (prefix trick)",
        lambda: server.validate_authorization_request({**params, "redirect_uri": "https://app.auth-lab.local/cb.evil.net"}),
    )
    expect_reject(
        "state mismatch (login CSRF)",
        lambda: client.handle_callback("session-1", "https://app.auth-lab.local/cb?code=x&state=attacker"),
    )
    expect_reject("BOLA: another user's object", lambda: rs.require_ownership(at_claims, "u-bob"))

    print("\nDrill 04 complete.")


if __name__ == "__main__":
    main()
