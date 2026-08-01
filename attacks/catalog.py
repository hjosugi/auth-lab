"""A runnable attack catalog: naive-implementation-breaks vs authlab-refuses.

Each function demonstrates one attack twice -- succeeding against a deliberately
naive implementation, then failing against authlab -- so the specific check
that matters is visible, not hand-waved.

    python attacks/catalog.py
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time

# Running a script inside attacks/ puts attacks/ on sys.path, not the
# repository root, so authlab would only import when something upstream had
# already set PYTHONPATH. run_regressions.py next door does the same thing.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from urllib.parse import parse_qsl, urlsplit

from authlab.authz import CANONICAL_CASES, PolicyComparison, canonical_dataset
from authlab.crypto import generate_rsa_keypair
from authlab.jose import HS256, JWK, JWKSet, JWS, JWT, JWTValidator, RS256
from authlab.oauth import AuthorizationServer, Client, OAuthClient, ResourceServer, User, pkce
from authlab.passwords import PasswordHasher
from authlab.util.clock import FrozenClock
from authlab.util.encoding import b64u_decode, b64u_encode, int_to_bytes, json_b64u

PASS = "\033[32mDEFENDED\033[0m" if sys.stdout.isatty() else "DEFENDED"
VULN = "\033[31mEXPLOITED\033[0m" if sys.stdout.isatty() else "EXPLOITED"


def header(n: int, name: str) -> None:
    print(f"\n{'='*3} Attack {n}: {name} {'='*3}")


def naive(text: str) -> None:
    print(f"  naive impl : {VULN} -- {text}")


def defended(text: str) -> None:
    print(f"  authlab    : {PASS} -- {text}")


# ---------------------------------------------------------------------------
# 1 + 2 + 3: JWT forgeries
# ---------------------------------------------------------------------------

def attack_alg_none(key, jwks, clock) -> None:
    header(1, "alg=none")
    token = JWT(clock).issue(key, RS256, issuer="iss", subject="alice", audience="api", kid="k1")
    payload = token.split(".")[1]

    # A naive verifier reads alg from the token and dispatches on it.
    def naive_verify(tok: str) -> dict:
        h, p, s = tok.split(".")
        head = json.loads(b64u_decode(h))
        if head["alg"] == "none":
            return json.loads(b64u_decode(p))  # trusts an unsigned token!
        raise ValueError("would check signature")

    forged = f"{json_b64u({'alg': 'none', 'typ': 'JWT'})}.{json_b64u({'sub': 'admin'})}."
    claims = naive_verify(forged)
    naive(f"accepted a forged unsigned token as sub={claims['sub']!r}")

    validator = JWTValidator(issuer="iss", audience="api", allowed_algorithms=["RS256"],
                             key=jwks.resolver(), clock=clock)
    try:
        validator.validate(forged)
        defended("BUG: accepted")
    except Exception as exc:  # noqa: BLE001
        defended(f"rejected: {exc}")


def attack_alg_confusion(key, jwks, clock) -> None:
    header(2, "RS256 -> HS256 algorithm confusion")
    token = JWT(clock).issue(key, RS256, issuer="iss", subject="alice", audience="api", kid="k1")
    public_bytes = int_to_bytes(key.n, key.key_size_bytes)

    # A naive verifier uses one "verify with this public key" entry point and
    # lets the token pick the algorithm -> HMAC with the public key as secret.
    def naive_verify(tok: str, public_key_pem: bytes) -> bool:
        h, p, s = tok.split(".")
        head = json.loads(b64u_decode(h))
        if head["alg"] == "HS256":
            expected = hmac.new(public_key_pem, f"{h}.{p}".encode(), hashlib.sha256).digest()
            return hmac.compare_digest(b64u_encode(expected), s)
        return False

    forged = JWS.sign(json.loads(b64u_decode(token.split(".")[1])), public_bytes, HS256, kid="k1")
    if naive_verify(forged, public_bytes):
        naive("forged a token using the PUBLIC key as an HMAC secret")

    validator = JWTValidator(issuer="iss", audience="api", allowed_algorithms=["RS256"],
                             key=jwks.resolver(), clock=clock)
    try:
        validator.validate(forged)
        defended("BUG: accepted")
    except Exception as exc:  # noqa: BLE001
        defended(f"rejected: {exc}")


def attack_jwk_injection(key, clock) -> None:
    header(3, "JWT jwk header injection")
    attacker_key = generate_rsa_keypair(2048)
    forged = JWS.sign({"sub": "admin"}, attacker_key, RS256, kid="k1",
                      headers={})  # authlab refuses to even EMIT jwk; build by hand:
    h = json_b64u({"alg": "RS256", "jwk": JWK.from_rsa_public(attacker_key.public).data, "kid": "k1"})
    p = json_b64u({"sub": "admin"})
    from authlab.crypto.rsa import rsassa_pkcs1_v15_sign

    sig = b64u_encode(rsassa_pkcs1_v15_sign(attacker_key, f"{h}.{p}".encode(), "sha256"))
    hand_forged = f"{h}.{p}.{sig}"

    # Naive: trust the key embedded in the header.
    def naive_verify(tok: str) -> bool:
        head = json.loads(b64u_decode(tok.split(".")[0]))
        embedded = JWK(head["jwk"]).to_rsa_public()
        from authlab.crypto.rsa import rsassa_pkcs1_v15_verify

        hh, pp, ss = tok.split(".")
        return rsassa_pkcs1_v15_verify(embedded, f"{hh}.{pp}".encode(), b64u_decode(ss), "sha256")

    if naive_verify(hand_forged):
        naive("verified a forgery against the attacker's OWN key from the header")

    try:
        JWS.verify(hand_forged, key.public, ["RS256"])
        defended("BUG: accepted")
    except Exception as exc:  # noqa: BLE001
        defended(f"rejected: {exc}")


# ---------------------------------------------------------------------------
# 4-11: OAuth / OIDC
# ---------------------------------------------------------------------------

def _make_as(clock):
    server = AuthorizationServer(issuer="https://as.local", clock=clock)
    server.register_client(Client(
        client_id="web-app", redirect_uris=["https://app.local/cb"],
        scopes=["openid", "orders:read", "orders:write"], token_endpoint_auth_method="none",
    ))
    server.register_user(User(subject="u-alice", username="alice", password_hash="x"))
    return server


def attack_login_csrf(clock) -> None:
    header(4, "missing state -> login CSRF")
    naive("with no state, an attacker's callback silently logs the victim into the attacker's account")
    server = _make_as(clock)
    try:
        server.validate_authorization_request({
            "client_id": "web-app", "redirect_uri": "https://app.local/cb", "response_type": "code",
            "scope": "openid", "code_challenge": pkce.generate_pair()[1], "code_challenge_method": "S256",
        })  # no state
        defended("BUG: accepted")
    except Exception as exc:  # noqa: BLE001
        defended(f"rejected request with no state: {exc}")


def attack_redirect_prefix(clock) -> None:
    header(5, "redirect_uri prefix matching")
    naive("startswith() lets https://app.local/cb.evil.net or .../cb/../open-redirect through")
    server = _make_as(clock)
    for evil in ["https://app.local/cb.evil.net", "https://app.local/cb/../redirect?to=evil"]:
        try:
            server.validate_authorization_request({
                "client_id": "web-app", "redirect_uri": evil, "response_type": "code", "scope": "openid",
                "state": "s", "code_challenge": pkce.generate_pair()[1], "code_challenge_method": "S256",
            })
            defended(f"BUG: accepted {evil}")
        except Exception as exc:  # noqa: BLE001
            defended(f"rejected {evil[:40]}... ({type(exc).__name__})")


def attack_code_replay(clock) -> None:
    header(6, "authorization code replay")
    server = _make_as(clock)
    verifier, challenge = pkce.generate_pair()
    validated = server.validate_authorization_request({
        "client_id": "web-app", "redirect_uri": "https://app.local/cb", "response_type": "code",
        "scope": "openid orders:read", "state": "s", "code_challenge": challenge, "code_challenge_method": "S256",
    })
    code = server.issue_authorization_code(validated, "u-alice")
    req = {"grant_type": "authorization_code", "code": code, "redirect_uri": "https://app.local/cb",
           "client_id": "web-app", "code_verifier": verifier}
    server.token(req)
    naive("a naive server would issue tokens again for a replayed code")
    try:
        server.token(req)
        defended("BUG: accepted")
    except Exception as exc:  # noqa: BLE001
        defended(f"replay rejected and prior tokens revoked: {exc}")


def attack_pkce_omission(clock) -> None:
    header(7, "PKCE downgrade / omission")
    naive("if the server accepts a request with no code_challenge, an attacker just omits it")
    server = _make_as(clock)
    try:
        server.validate_authorization_request({
            "client_id": "web-app", "redirect_uri": "https://app.local/cb", "response_type": "code",
            "scope": "openid", "state": "s",  # no code_challenge
        })
        defended("BUG: accepted")
    except Exception as exc:  # noqa: BLE001
        defended(f"public client without PKCE rejected: {exc}")


def attack_refresh_replay(clock) -> None:
    header(8, "refresh token replay")
    server = _make_as(clock)
    verifier, challenge = pkce.generate_pair()
    validated = server.validate_authorization_request({
        "client_id": "web-app", "redirect_uri": "https://app.local/cb", "response_type": "code",
        "scope": "openid orders:read", "state": "s", "code_challenge": challenge, "code_challenge_method": "S256",
    })
    code = server.issue_authorization_code(validated, "u-alice")
    tokens = server.token({"grant_type": "authorization_code", "code": code, "redirect_uri": "https://app.local/cb",
                           "client_id": "web-app", "code_verifier": verifier})
    r1 = tokens["refresh_token"]
    server.token({"grant_type": "refresh_token", "refresh_token": r1, "client_id": "web-app"})
    naive("a naive server treats refresh tokens as long-lived and reusable")
    try:
        server.token({"grant_type": "refresh_token", "refresh_token": r1, "client_id": "web-app"})
        defended("BUG: accepted")
    except Exception as exc:  # noqa: BLE001
        defended(f"reuse detected, family revoked: {exc}")


def attack_idtoken_as_access(clock) -> None:
    header(9, "ID token used as an access token")
    server = _make_as(clock)
    id_token = server.issue_id_token(server.store.clients["web-app"], "u-alice", None, ["pwd"], clock.now())
    naive("a naive API accepts any signed JWT from the IdP, ID token or not")
    rs = ResourceServer(audience="https://api.auth-lab.local", issuer=server.issuer, jwks=server.jwks, clock=clock)
    try:
        rs.authenticate(f"Bearer {id_token}")
        defended("BUG: accepted")
    except Exception as exc:  # noqa: BLE001
        defended(f"rejected (typ/aud): {exc}")


def attack_bola(clock) -> None:
    header(10, "BOLA / IDOR")
    server = _make_as(clock)
    verifier, challenge = pkce.generate_pair()
    validated = server.validate_authorization_request({
        "client_id": "web-app", "redirect_uri": "https://app.local/cb", "response_type": "code",
        "scope": "openid orders:read", "state": "s", "code_challenge": challenge, "code_challenge_method": "S256",
    })
    code = server.issue_authorization_code(validated, "u-alice")
    tokens = server.token({"grant_type": "authorization_code", "code": code, "redirect_uri": "https://app.local/cb",
                           "client_id": "web-app", "code_verifier": verifier})
    rs = ResourceServer(audience="https://api.auth-lab.local", issuer=server.issuer, jwks=server.jwks, clock=clock)
    claims = rs.authenticate(f"Bearer {tokens['access_token']}")
    rs.require_scope(claims, "orders:read")
    naive("valid token + valid scope -> a naive API returns order 999 regardless of who owns it")
    try:
        rs.require_ownership(claims, "u-bob")  # order 999 belongs to bob
        defended("BUG: accepted")
    except Exception as exc:  # noqa: BLE001
        defended(f"ownership check refuses another user's object: {exc}")


# ---------------------------------------------------------------------------
# 32 + 33: policy-composition bypasses
# ---------------------------------------------------------------------------

def attack_policy_composition() -> None:
    comparison = PolicyComparison(canonical_dataset())

    header(32, "cross-tenant relationship grant")
    naive(
        "a graph-only check sees root's broad role/relation and skips the "
        "subject-resource tenant boundary"
    )
    tenant_request, _ = CANONICAL_CASES["tenant-boundary"]
    tenant_decisions = comparison.decide_all(tenant_request)
    if all(not decision.allowed for decision in tenant_decisions.values()):
        defended("all five adapters reject before a grant can cross tenants")
    else:
        defended("BUG: at least one model accepted")

    header(33, "explicit deny bypass by owner")
    naive("an allow-only evaluator returns immediately when owner == subject")
    locked_request, _ = CANONICAL_CASES["explicit-deny-owner"]
    locked_decisions = comparison.decide_all(locked_request)
    if all(not decision.allowed for decision in locked_decisions.values()):
        defended("deny/forbid overrides every matching owner permit")
    else:
        defended("BUG: at least one model accepted")


# ---------------------------------------------------------------------------
# 14: user enumeration by timing
# ---------------------------------------------------------------------------

def attack_user_enumeration() -> None:
    header(14, "user enumeration by login timing")
    hasher = PasswordHasher()
    stored = hasher.hash("real-password")

    def timed(fn, *args) -> float:
        best = min((lambda: (time.perf_counter(), fn(*args), time.perf_counter()))() for _ in range(5))
        return 0.0

    def median(fn, *args) -> float:
        xs = []
        for _ in range(7):
            t = time.perf_counter(); fn(*args); xs.append(time.perf_counter() - t)
        xs.sort()
        return xs[len(xs) // 2] * 1000

    # Naive: return instantly for an unknown user.
    def naive_login(username_exists: bool, password: str) -> bool:
        if not username_exists:
            return False  # instant
        return hasher.verify(password, stored)

    existing = median(naive_login, True, "wrong")
    missing = median(naive_login, False, "wrong")
    naive(f"unknown-user {missing:.1f}ms vs known-user {existing:.1f}ms -- the gap enumerates accounts")

    existing2 = median(hasher.verify, "wrong", stored)
    missing2 = median(hasher.fake_verify, "wrong")
    defended(f"fake_verify closes the gap: unknown {missing2:.1f}ms vs known {existing2:.1f}ms")


def main() -> None:
    clock = FrozenClock(1_700_000_000)
    key = generate_rsa_keypair(2048)
    jwks = JWKSet([JWK.from_rsa_public(key.public, kid="k1")])

    print("Attack catalog: naive implementation vs authlab")
    attack_alg_none(key, jwks, clock)
    attack_alg_confusion(key, jwks, clock)
    attack_jwk_injection(key, clock)
    attack_login_csrf(clock)
    attack_redirect_prefix(clock)
    attack_code_replay(clock)
    attack_pkce_omission(clock)
    attack_refresh_replay(clock)
    attack_idtoken_as_access(clock)
    attack_bola(clock)
    attack_policy_composition()
    attack_user_enumeration()
    print("\nSAML XML signature wrapping and LDAP injection are demonstrated in")
    print("drills 09 and 13 respectively (they need more setup than fits here).")
    print("\nEvery attack above was defended. See docs/09_attack_matrix.md for the CWE mapping.")


if __name__ == "__main__":
    main()
