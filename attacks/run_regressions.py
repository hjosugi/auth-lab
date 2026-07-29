#!/usr/bin/env python3
"""Safe local regressions for common authentication design failures."""

from __future__ import annotations

import base64
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from authlab import ec  # noqa: E402
from authlab.dpop import DPoPVerifier, create_proof  # noqa: E402
from authlab.jose import TokenError, sign_jwt, verify_jwt  # noqa: E402
from authlab.oauth import AuthorizationServer, Client  # noqa: E402
from authlab.saml import SAMLServiceProvider, issue_response  # noqa: E402
from authlab.util import AuthError, b64url_encode  # noqa: E402
from authlab.webauthn import Authenticator, WebAuthnServer  # noqa: E402


def rejected(name: str, action: object) -> None:
    try:
        action()  # type: ignore[operator]
    except (AuthError, TokenError):
        print(f"PASS  {name}")
    else:
        raise AssertionError(f"VULNERABLE: {name}")


def jwt_cases() -> None:
    now = 10_000
    claims = {
        "iss": "https://issuer.example",
        "sub": "alice",
        "aud": "api",
        "iat": now,
        "exp": now + 300,
        "jti": "j-1",
    }
    none_header = b64url_encode(b'{"alg":"none","kid":"k1","typ":"JWT"}')
    body = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    rejected(
        "JWT alg=none",
        lambda: verify_jwt(
            f"{none_header}.{body}.",
            {"k1": b"secret"},
            algorithm="HS256",
            issuer="https://issuer.example",
            audience="api",
            now=now,
        ),
    )
    token = sign_jwt(claims, b"secret", algorithm="HS256", kid="k1")
    left, middle, signature = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(left + "=="))
    header["jku"] = "https://attacker.invalid/jwks.json"
    injected = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    rejected(
        "JWT attacker-controlled jku",
        lambda: verify_jwt(
            f"{injected}.{middle}.{signature}",
            {"k1": b"secret"},
            algorithm="HS256",
            issuer="https://issuer.example",
            audience="api",
            now=now,
        ),
    )


def oauth_cases() -> None:
    server = AuthorizationServer()
    server.register_client(
        Client(
            "web",
            ("https://client.example/callback",),
            allowed_scopes=frozenset({"openid"}),
        )
    )
    verifier = "v" * 64
    rejected(
        "OAuth redirect URI prefix match",
        lambda: server.authorize(
            client_id="web",
            redirect_uri="https://client.example/callback/attacker",
            user="alice",
            scope="openid",
            state="state",
            code_challenge=server.pkce_challenge(verifier),
            now=1_000,
        ),
    )
    rejected(
        "OAuth missing state",
        lambda: server.authorize(
            client_id="web",
            redirect_uri="https://client.example/callback",
            user="alice",
            scope="openid",
            state="",
            code_challenge=server.pkce_challenge(verifier),
            now=1_000,
        ),
    )


def saml_case() -> None:
    key = b"saml-key"
    xml = issue_response(
        key=key,
        issuer="https://idp.example",
        subject="alice",
        audience="https://sp.example/metadata",
        destination="https://sp.example/acs",
        in_response_to="_request",
        now=2_000,
    )
    wrapped = xml.replace(
        "</samlp:Response>",
        '<saml:Assertion ID="_unsigned"><saml:Subject>admin</saml:Subject>'
        "</saml:Assertion></samlp:Response>",
    )
    sp = SAMLServiceProvider(
        "https://idp.example",
        "https://sp.example/metadata",
        "https://sp.example/acs",
        key,
    )
    rejected(
        "SAML duplicate/wrapping assertion",
        lambda: sp.validate(wrapped, request_id="_request", now=2_001),
    )


def webauthn_and_dpop_cases() -> None:
    server = WebAuthnServer("example.test", "https://example.test")
    device = Authenticator()
    challenge = server.begin_registration("alice")
    rejected(
        "WebAuthn evil origin",
        lambda: server.finish_registration(
            "alice",
            device.registration(
                challenge,
                origin="https://evil.example",
                rp_id="example.test",
            ),
        ),
    )
    private, public = ec.generate_keypair()
    proof = create_proof(
        private,
        public,
        method="GET",
        url="https://api.example/resource",
        now=3_000,
    )
    rejected(
        "DPoP wrong method binding",
        lambda: DPoPVerifier().verify(
            proof,
            method="POST",
            url="https://api.example/resource",
            now=3_001,
        ),
    )


def main() -> None:
    jwt_cases()
    oauth_cases()
    saml_case()
    webauthn_and_dpop_cases()
    print("\nAll attack regressions were rejected.")


if __name__ == "__main__":
    main()

