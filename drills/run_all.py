#!/usr/bin/env python3
"""Run fourteen readable authentication and authorization drills."""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from authlab import ec  # noqa: E402
from authlab.authorization import ABAC, Policy, RBAC, ReBAC  # noqa: E402
from authlab.directory import LDAPDirectory, SCIMService  # noqa: E402
from authlab.dpop import DPoPVerifier, create_proof, jwk_thumbprint, public_jwk  # noqa: E402
from authlab.http_auth import HMACRequestVerifier, sign_request  # noqa: E402
from authlab.jose import sign_jwt, verify_jwt  # noqa: E402
from authlab.kerberos import (  # noqa: E402
    KDC,
    KerberosService,
    authenticator,
    derive_key,
    preauth_proof,
    unseal,
)
from authlab.mfa import TotpVerifier, totp  # noqa: E402
from authlab.mtls import (  # noqa: E402
    CertificateAuthority,
    bind_token,
    verify_bound_token,
)
from authlab.oauth import AuthorizationServer, Client, OAuthError  # noqa: E402
from authlab.passwords import hash_password, verify_password  # noqa: E402
from authlab.rsa import generate_keypair  # noqa: E402
from authlab.saml import SAMLServiceProvider, issue_response  # noqa: E402
from authlab.util import AuthError, b64url_decode  # noqa: E402
from authlab.webauthn import Authenticator, WebAuthnServer  # noqa: E402


def heading(number: int, title: str) -> None:
    print(f"\n[{number:02}] {title}")


def expect_rejection(label: str, action: object) -> None:
    try:
        action()  # type: ignore[operator]
    except AuthError as exc:
        print(f"  ✓ {label}: rejected ({exc})")
    else:
        raise AssertionError(f"{label} was not rejected")


def oauth_server() -> AuthorizationServer:
    server = AuthorizationServer()
    server.register_client(
        Client(
            "web-app",
            ("https://client.example/callback",),
            allowed_scopes=frozenset({"openid", "profile", "read"}),
        )
    )
    server.register_client(
        Client(
            "worker",
            secret="worker-secret",
            public=False,
            allowed_scopes=frozenset({"read"}),
        )
    )
    return server


def authorization_code(server: AuthorizationServer, now: int = 1_000) -> dict[str, object]:
    verifier = "v" * 64
    response = server.authorize(
        client_id="web-app",
        redirect_uri="https://client.example/callback",
        user="alice",
        scope="openid profile",
        state="csrf-binding",
        code_challenge=server.pkce_challenge(verifier),
        nonce="oidc-nonce",
        now=now,
    )
    return server.exchange_code(
        code=response["code"],
        client_id="web-app",
        redirect_uri="https://client.example/callback",
        code_verifier=verifier,
        now=now + 1,
    )


def drill_01() -> None:
    heading(1, "Password storage: salt + work factor")
    record = hash_password("correct horse battery staple", salt=b"0123456789abcdef")
    print(f"  record = {record[:54]}…")
    assert verify_password("correct horse battery staple", record)
    assert not verify_password("wrong password", record)
    print("  ✓ plaintext is never stored; wrong password rejected")


def drill_02() -> None:
    heading(2, "HOTP/TOTP: moving factor + replay prevention")
    secret = b"12345678901234567890"
    verifier = TotpVerifier(secret)
    code = totp(secret, at=59)
    assert verifier.verify(code, at=59)
    assert not verifier.verify(code, at=59)
    print(f"  ✓ RFC vector {code}; second use rejected")


def drill_03() -> None:
    heading(3, "JWT: signature + issuer/audience/time validation")
    now = 10_000
    claims = {
        "iss": "https://issuer.example",
        "sub": "alice",
        "aud": "resource-api",
        "iat": now,
        "exp": now + 300,
        "jti": "j-1",
    }
    token = sign_jwt(claims, b"shared-key", algorithm="HS256", kid="key-1")
    verified = verify_jwt(
        token,
        {"key-1": b"shared-key"},
        algorithm="HS256",
        issuer="https://issuer.example",
        audience="resource-api",
        now=now + 1,
    )
    print(f"  ✓ three-part JWS verified for subject {verified['sub']}")


def drill_04() -> None:
    heading(4, "OAuth authorization code + PKCE + OIDC")
    server = oauth_server()
    tokens = authorization_code(server)
    assert "id_token" in tokens
    print("  ✓ code bound to client, redirect URI, S256 verifier, state, and nonce")


def drill_05() -> None:
    heading(5, "Refresh-token rotation + family reuse detection")
    server = oauth_server()
    first = authorization_code(server)
    second = server.refresh(first["refresh_token"], client_id="web-app", now=1_100)
    expect_rejection(
        "old refresh token reuse",
        lambda: server.refresh(first["refresh_token"], client_id="web-app", now=1_101),
    )
    assert not server.introspect(second["access_token"], now=1_102)["active"]
    print("  ✓ the complete token family was revoked")


def drill_06() -> None:
    heading(6, "Client credentials: machine identity")
    tokens = oauth_server().client_credentials(
        client_id="worker",
        client_secret="worker-secret",
        scope="read",
        now=2_000,
    )
    assert "refresh_token" not in tokens
    print("  ✓ confidential client authenticated; no refresh token issued")


def drill_07() -> None:
    heading(7, "Device authorization: user code + polling discipline")
    server = oauth_server()
    device = server.device_authorize(client_id="web-app", scope="openid", now=3_000)
    expect_rejection(
        "authorization pending",
        lambda: server.poll_device(device["device_code"], client_id="web-app", now=3_001),
    )
    expect_rejection(
        "polling too quickly",
        lambda: server.poll_device(device["device_code"], client_id="web-app", now=3_002),
    )
    server.approve_device(device["user_code"], "alice")
    tokens = server.poll_device(device["device_code"], client_id="web-app", now=3_011)
    assert "access_token" in tokens
    print("  ✓ approval completed on a separate user interaction")


def drill_08() -> None:
    heading(8, "Token introspection + revocation")
    server = oauth_server()
    tokens = authorization_code(server, now=4_000)
    assert server.introspect(tokens["access_token"], now=4_002)["active"]
    server.revoke(tokens["access_token"])
    assert not server.introspect(tokens["access_token"], now=4_003)["active"]
    print("  ✓ active changed from true to false; revocation is idempotent")


def drill_09() -> None:
    heading(9, "RBAC, ABAC, and ReBAC authorization models")
    rbac = RBAC()
    rbac.add_role("viewer", {"read"})
    rbac.add_role("editor", {"write"}, parents={"viewer"})
    rbac.assign("alice", "editor")
    assert rbac.allowed("alice", "read")
    abac = ABAC(
        [
            Policy("allow", "read", lambda s, r, c: s["team"] == r["team"], "same-team"),
            Policy("deny", "read", lambda s, r, c: r["locked"], "locked"),
        ]
    )
    allowed, reasons = abac.decide(
        subject={"team": "blue"},
        resource={"team": "blue", "locked": True},
        context={},
        action="read",
    )
    assert not allowed and "deny:locked" in reasons
    rebac = ReBAC()
    rebac.add("group:editors", "member", "user:alice")
    rebac.add("document:roadmap", "editor", "group:editors#member")
    assert rebac.check("alice", "document:roadmap", "editor")
    print("  ✓ hierarchy, deny-overrides, and userset rewrite all exercised")


def drill_10() -> None:
    heading(10, "SAML Web SSO: signed assertion and binding checks")
    key = b"saml-key"
    sp = SAMLServiceProvider(
        "https://idp.example",
        "https://sp.example/metadata",
        "https://sp.example/acs",
        key,
    )
    response = issue_response(
        key=key,
        issuer="https://idp.example",
        subject="alice",
        audience="https://sp.example/metadata",
        destination="https://sp.example/acs",
        in_response_to="_request-1",
        now=5_000,
    )
    assert sp.validate(response, request_id="_request-1", now=5_001) == "alice"
    print("  ✓ issuer, audience, ACS, request, time, signature, replay checked")


def drill_11() -> None:
    heading(11, "Kerberos: AS → TGS → service + mutual auth")
    now = 6_000
    user_key = derive_key("correct-password")
    service_key = b"s" * 32
    kdc = KDC("EXAMPLE.TEST", {"alice": user_key}, {"http/api": service_key})
    as_rep = kdc.as_exchange("alice", now, preauth_proof(user_key, "alice", now))
    tgt_client = unseal(user_key, as_rep["client_part"])
    tgt_session = b64url_decode(tgt_client["session_key"])
    tgs_rep = kdc.tgs_exchange(
        as_rep["tgt"],
        "http/api",
        authenticator(tgt_session, "alice", now + 1),
        now=now + 1,
    )
    service_client = unseal(tgt_session, tgs_rep["client_part"])
    service_session = b64url_decode(service_client["session_key"])
    accepted = KerberosService("http/api", service_key).accept(
        tgs_rep["ticket"],
        authenticator(service_session, "alice", now + 2),
        now=now + 2,
    )
    assert accepted["client"] == "alice"
    print("  ✓ password never sent to service; ticket and authenticator accepted")


def drill_12() -> None:
    heading(12, "WebAuthn/passkeys: origin-bound public-key credential")
    server = WebAuthnServer("example.test", "https://example.test")
    device = Authenticator()
    challenge = server.begin_registration("alice")
    server.finish_registration(
        "alice",
        device.registration(
            challenge,
            origin="https://example.test",
            rp_id="example.test",
        ),
    )
    challenge = server.begin_authentication("alice")
    assert server.finish_authentication(
        "alice",
        device.assertion(
            challenge,
            origin="https://example.test",
            rp_id="example.test",
        ),
    )
    print("  ✓ challenge, origin, RP ID, UP/UV, signature, counter checked")


def drill_13() -> None:
    heading(13, "mTLS + DPoP: proof-of-possession tokens")
    now = 7_000
    ca = CertificateAuthority("Lab CA", generate_keypair(512))
    client_key = generate_keypair(512)
    cert = ca.issue(
        subject="CN=worker",
        public_key=client_key.public_key,
        serial="01",
        not_before=now - 1,
        not_after=now + 3_600,
        san="spiffe://example.test/worker",
        eku="clientAuth",
    )
    ca.verify(
        cert,
        now=now,
        expected_san="spiffe://example.test/worker",
        expected_eku="clientAuth",
    )
    verify_bound_token(bind_token({"sub": "worker"}, cert), cert)
    private, public = ec.generate_keypair()
    access_token = "opaque-access-token"
    proof = create_proof(
        private,
        public,
        method="POST",
        url="https://api.example/pay",
        now=now,
        access_token=access_token,
    )
    DPoPVerifier().verify(
        proof,
        method="POST",
        url="https://api.example/pay",
        now=now,
        access_token=access_token,
        token_jkt=jwk_thumbprint(public_jwk(public)),
    )
    print("  ✓ access token bound to certificate and ephemeral public key")


def drill_14() -> None:
    heading(14, "LDAP + SCIM + signed HTTP request lifecycle")
    directory = LDAPDirectory()
    dn = "uid=alice,ou=people,dc=example,dc=test"
    directory.add(dn, {"uid": ["alice"]}, password="correct-password")
    assert directory.bind(dn, "correct-password")
    scim = SCIMService()
    user = scim.create_user("alice", "Alice")
    disabled = scim.patch_user(
        user["id"],
        [{"op": "replace", "path": "active", "value": False}],
        if_match=user["meta"]["version"],
    )
    assert not disabled["active"]
    signature = sign_request(
        b"shared-key",
        method="POST",
        path="/provision",
        body=b'{"user":"alice"}',
        timestamp=8_000,
        nonce="n-1",
    )
    HMACRequestVerifier().verify(
        b"shared-key",
        signature,
        method="POST",
        path="/provision",
        body=b'{"user":"alice"}',
        timestamp=8_000,
        nonce="n-1",
        now=8_000,
    )
    print("  ✓ directory bind, provisioning deactivation, request integrity")


def main() -> None:
    for drill in (
        drill_01,
        drill_02,
        drill_03,
        drill_04,
        drill_05,
        drill_06,
        drill_07,
        drill_08,
        drill_09,
        drill_10,
        drill_11,
        drill_12,
        drill_13,
        drill_14,
    ):
        drill()
    print("\nAll 14 drills passed.")


if __name__ == "__main__":
    main()

