#!/usr/bin/env python3
"""Attack regressions: assert that every attack in the catalog is refused.

The catalog (catalog.py) narrates each attack breaking a naive implementation
and then being refused by authlab. This wrapper runs the same defended paths
but as hard assertions, so it can gate CI: if any defence regresses, this
exits non-zero.

    python attacks/run_regressions.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from urllib.parse import parse_qsl, urlsplit

from authlab.crypto import generate_rsa_keypair
from authlab.jose import HS256, JWK, JWKSet, JWS, JWT, JWTValidator, RS256
from authlab.jose.errors import JOSEError
from authlab.oauth import (
    AuthorizationServer, Client, InvalidGrant, InvalidRequest, InvalidScope,
    OAuthClient, ResourceServer, Unauthorized, User, pkce,
)
from authlab.oauth.resource_server import Forbidden
from authlab.util.clock import FrozenClock
from authlab.util.encoding import b64u_decode, int_to_bytes, json_b64u

PASSED = 0
FAILED = 0


def must_reject(label: str, fn) -> None:
    global PASSED, FAILED
    try:
        fn()
    except Exception:  # noqa: BLE001 - any refusal is a pass
        PASSED += 1
        print(f"  [refused ] {label}")
        return
    FAILED += 1
    print(f"  [ACCEPTED] {label}  <-- REGRESSION")


def main() -> int:
    clock = FrozenClock(1_700_000_000)
    key = generate_rsa_keypair(2048)
    jwks = JWKSet([JWK.from_rsa_public(key.public, kid="k1")])
    token = JWT(clock).issue(key, RS256, issuer="iss", subject="s", audience="api", kid="k1")
    validator = JWTValidator(issuer="iss", audience="api", allowed_algorithms=["RS256"],
                             key=jwks.resolver(), clock=clock)
    header, payload, signature = token.split(".")

    print("JWT:")
    must_reject("alg=none", lambda: validator.validate(f"{json_b64u({'alg': 'none'})}.{payload}."))
    public_bytes = int_to_bytes(key.n, key.key_size_bytes)
    import json
    confused = JWS.sign(json.loads(b64u_decode(payload)), public_bytes, HS256, kid="k1")
    must_reject("RS256->HS256 confusion", lambda: validator.validate(confused))
    must_reject("jwk header injection",
                lambda: JWS.verify(f"{json_b64u({'alg': 'RS256', 'jwk': {}})}.{payload}.{signature}", key.public, ["RS256"]))
    tampered = json.loads(b64u_decode(payload)); tampered["sub"] = "admin"
    must_reject("payload tampering", lambda: validator.validate(f"{header}.{json_b64u(tampered)}.{signature}"))

    server = AuthorizationServer(issuer="https://as.local", clock=clock)
    server.register_client(Client(client_id="web-app", redirect_uris=["https://app/cb"],
                                  scopes=["openid", "orders:read", "orders:write"], token_endpoint_auth_method="none"))
    server.register_user(User(subject="u-alice", username="alice", password_hash="x"))

    def valid_params(**over):
        p = {"client_id": "web-app", "redirect_uri": "https://app/cb", "response_type": "code",
             "scope": "openid orders:read", "state": "s",
             "code_challenge": pkce.generate_pair()[1], "code_challenge_method": "S256"}
        p.update(over)
        return p

    print("OAuth:")
    must_reject("missing state (login CSRF)", lambda: server.validate_authorization_request({k: v for k, v in valid_params().items() if k != "state"}))
    must_reject("missing PKCE", lambda: server.validate_authorization_request({k: v for k, v in valid_params().items() if k != "code_challenge"}))
    must_reject("redirect_uri prefix", lambda: server.validate_authorization_request(valid_params(redirect_uri="https://app/cb.evil")))
    must_reject("scope escalation", lambda: server.validate_authorization_request(valid_params(scope="openid admin")))

    validated = server.validate_authorization_request(valid_params())
    code = server.issue_authorization_code(validated, "u-alice")
    req = {"grant_type": "authorization_code", "code": code, "redirect_uri": "https://app/cb",
           "client_id": "web-app", "code_verifier": pkce.create_verifier()}
    # wrong verifier
    must_reject("wrong PKCE verifier", lambda: server.token(req))

    v2, c2 = pkce.generate_pair()
    validated2 = server.validate_authorization_request(valid_params(code_challenge=c2))
    code2 = server.issue_authorization_code(validated2, "u-alice")
    good_req = {"grant_type": "authorization_code", "code": code2, "redirect_uri": "https://app/cb",
                "client_id": "web-app", "code_verifier": v2}
    server.token(good_req)
    must_reject("authorization code replay", lambda: server.token(good_req))

    # A fresh flow for the refresh-reuse test (the code-replay above revoked
    # the previous subject's tokens, which is the correct behaviour).
    vr, cr = pkce.generate_pair()
    validated_r = server.validate_authorization_request(valid_params(code_challenge=cr))
    code_r = server.issue_authorization_code(validated_r, "u-alice")
    tokens = server.token({"grant_type": "authorization_code", "code": code_r, "redirect_uri": "https://app/cb",
                           "client_id": "web-app", "code_verifier": vr})
    r1 = tokens["refresh_token"]
    server.token({"grant_type": "refresh_token", "refresh_token": r1, "client_id": "web-app"})
    must_reject("refresh token reuse", lambda: server.token({"grant_type": "refresh_token", "refresh_token": r1, "client_id": "web-app"}))

    print("Resource server:")
    id_token = server.issue_id_token(server.store.clients["web-app"], "u-alice", None, ["pwd"], clock.now())
    rs = ResourceServer(audience="https://api.auth-lab.local", issuer=server.issuer, jwks=server.jwks, clock=clock)
    must_reject("ID token used as access token", lambda: rs.authenticate(f"Bearer {id_token}"))

    v3, c3 = pkce.generate_pair()
    validated3 = server.validate_authorization_request(valid_params(code_challenge=c3))
    code3 = server.issue_authorization_code(validated3, "u-alice")
    at = server.token({"grant_type": "authorization_code", "code": code3, "redirect_uri": "https://app/cb",
                       "client_id": "web-app", "code_verifier": v3})["access_token"]
    claims = rs.authenticate(f"Bearer {at}")
    must_reject("insufficient scope", lambda: rs.require_scope(claims, "admin"))
    must_reject("BOLA (another user's object)", lambda: rs.require_ownership(claims, "u-bob"))

    print("Client:")
    client = OAuthClient(client_id="web-app", redirect_uri="https://app/cb",
                         authorization_endpoint=f"{server.issuer}/authorize",
                         token_endpoint=f"{server.issuer}/token", issuer=server.issuer, clock=clock)
    client.begin("s1")
    must_reject("state mismatch (login CSRF)", lambda: client.handle_callback("s1", "https://app/cb?code=x&state=attacker"))

    print(f"\n{'=' * 50}")
    print(f"{PASSED} attacks refused, {FAILED} regressions.")
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
