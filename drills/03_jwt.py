"""Drill 03 -- JWT: minting, full claim validation, and the classic forgeries."""

from __future__ import annotations

import json

from _util import assert_true, expect_reject, note, step, title

from authlab.crypto import generate_rsa_keypair
from authlab.jose import HS256, JWK, JWKSet, JWS, JWT, JWTValidator, RS256
from authlab.util.clock import FrozenClock
from authlab.util.encoding import b64u_decode, int_to_bytes, json_b64u


def main() -> None:
    title("Drill 03: JWT / JOSE")
    clock = FrozenClock(1_700_000_000)
    key = generate_rsa_keypair(2048)
    jwks = JWKSet([JWK.from_rsa_public(key.public, kid="k1")])

    step(1, "Mint an RS256 access token and validate every claim.")
    token = JWT(clock).issue(
        key, RS256, issuer="https://idp.lab", subject="u-1", audience="api://orders",
        lifetime=300, kid="k1", extra_claims={"scope": "orders:read"},
    )
    note(f"token: {token[:48]}...")
    validator = JWTValidator(
        issuer="https://idp.lab", audience="api://orders",
        allowed_algorithms=["RS256"], key=jwks.resolver(), clock=clock,
    )
    claims = validator.validate(token)
    assert_true(claims.sub == "u-1" and "orders:read" in claims.scopes, "valid token, claims readable")

    header, payload, signature = token.split(".")

    step(2, "alg=none forgery is refused.")
    expect_reject(
        "alg=none",
        lambda: validator.validate(f"{json_b64u({'alg': 'none', 'typ': 'JWT'})}.{payload}."),
    )

    step(3, "Tampering the payload breaks the signature.")
    tampered = json.loads(b64u_decode(payload))
    tampered["scope"] = "admin:*"
    expect_reject("payload tampering", lambda: validator.validate(f"{header}.{json_b64u(tampered)}.{signature}"))

    step(4, "Algorithm confusion (RS256 -> HS256 with the public key as secret) is refused.")
    public_bytes = int_to_bytes(key.n, key.key_size_bytes)
    confused = JWS.sign(json.loads(b64u_decode(payload)), public_bytes, HS256, kid="k1")
    expect_reject("RS256->HS256 confusion", lambda: validator.validate(confused))

    step(5, "Wrong audience is refused (an ID token cannot be replayed at an API).")
    expect_reject(
        "wrong audience",
        lambda: JWTValidator(
            issuer="https://idp.lab", audience="api://billing",
            allowed_algorithms=["RS256"], key=jwks.resolver(), clock=clock,
        ).validate(token),
    )

    step(6, "Expired token is refused.")
    late = FrozenClock(1_700_000_000 + 400)
    expect_reject(
        "expired",
        lambda: JWTValidator(
            issuer="https://idp.lab", audience="api://orders",
            allowed_algorithms=["RS256"], key=jwks.resolver(), clock=late,
        ).validate(token),
    )

    step(7, "A header-supplied key (jwk) is refused.")
    expect_reject(
        "jwk header injection",
        lambda: JWS.verify(f"{json_b64u({'alg': 'RS256', 'jwk': {'kty': 'RSA'}})}.{payload}.{signature}",
                           key.public, ["RS256"]),
    )

    step(8, "An unknown kid finds no key.")
    expect_reject(
        "unknown kid",
        lambda: validator.validate(
            JWT(clock).issue(key, RS256, issuer="https://idp.lab", subject="u", audience="api://orders", kid="gone")
        ),
    )

    print("\nDrill 03 complete.")


if __name__ == "__main__":
    main()
