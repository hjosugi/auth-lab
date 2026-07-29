"""Strict JWS/JWT helpers with algorithm pinning and claim validation."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from .rsa import RSAKeyPair, RSAPublicKey, sign_rs256, verify_rs256
from .util import (
    AuthError,
    ReplayCache,
    b64url_decode,
    b64url_encode,
    canonical_json,
    json_from_bytes,
    secure_equal,
    unix_time,
)


class TokenError(AuthError):
    pass


def sign_jwt(
    claims: dict[str, Any],
    key: bytes | RSAKeyPair,
    *,
    algorithm: str,
    kid: str,
    token_type: str = "JWT",
) -> str:
    header = {"alg": algorithm, "kid": kid, "typ": token_type}
    signing_input = (
        b64url_encode(canonical_json(header))
        + "."
        + b64url_encode(canonical_json(claims))
    ).encode("ascii")
    if algorithm == "HS256" and isinstance(key, bytes):
        signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    elif algorithm == "RS256" and isinstance(key, RSAKeyPair):
        signature = sign_rs256(key, signing_input)
    else:
        raise TokenError("key type does not match the pinned algorithm")
    return signing_input.decode("ascii") + "." + b64url_encode(signature)


def _audience_matches(actual: Any, expected: str) -> bool:
    if isinstance(actual, str):
        return actual == expected
    if isinstance(actual, list):
        return expected in actual and all(isinstance(value, str) for value in actual)
    return False


def verify_jwt(
    token: str,
    keys: dict[str, bytes | RSAPublicKey],
    *,
    algorithm: str,
    issuer: str,
    audience: str,
    now: int | None = None,
    leeway: int = 30,
    required_type: str = "JWT",
    replay_cache: ReplayCache | None = None,
) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("compact JWS must have three parts")
    header = json_from_bytes(b64url_decode(parts[0]))
    claims = json_from_bytes(b64url_decode(parts[1]))
    if any(name in header for name in ("jku", "jwk", "x5u")):
        raise TokenError("remote or embedded verification keys are forbidden")
    if header.get("alg") != algorithm or header.get("typ") != required_type:
        raise TokenError("algorithm or token type mismatch")
    kid = header.get("kid")
    if not isinstance(kid, str) or kid not in keys:
        raise TokenError("unknown signing key")
    signature = b64url_decode(parts[2])
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    key = keys[kid]
    if algorithm == "HS256" and isinstance(key, bytes):
        expected = hmac.new(key, signing_input, hashlib.sha256).digest()
        valid = secure_equal(expected, signature)
    elif algorithm == "RS256" and isinstance(key, RSAPublicKey):
        valid = verify_rs256(key, signing_input, signature)
    else:
        raise TokenError("verification key type mismatch")
    if not valid:
        raise TokenError("invalid signature")
    current = unix_time() if now is None else now
    if claims.get("iss") != issuer:
        raise TokenError("issuer mismatch")
    if not _audience_matches(claims.get("aud"), audience):
        raise TokenError("audience mismatch")
    for name in ("exp", "iat"):
        if not isinstance(claims.get(name), int):
            raise TokenError(f"missing or invalid {name}")
    if current >= claims["exp"] + leeway:
        raise TokenError("token expired")
    if claims["iat"] > current + leeway:
        raise TokenError("token issued in the future")
    if isinstance(claims.get("nbf"), int) and current + leeway < claims["nbf"]:
        raise TokenError("token is not active yet")
    if replay_cache is not None:
        jti = claims.get("jti")
        if not isinstance(jti, str):
            raise TokenError("jti is required for replay protection")
        replay_cache.consume(jti, claims["exp"], current)
    return claims

