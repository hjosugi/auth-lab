"""OAuth DPoP proof creation and verification using P-256."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from . import ec
from .util import (
    AuthError,
    ReplayCache,
    b64url_decode,
    b64url_encode,
    canonical_json,
    json_from_bytes,
    random_token,
)


def public_jwk(public: tuple[int, int]) -> dict[str, str]:
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(public[0].to_bytes(32, "big")),
        "y": b64url_encode(public[1].to_bytes(32, "big")),
    }


def jwk_thumbprint(jwk: dict[str, str]) -> str:
    required = {name: jwk[name] for name in ("crv", "kty", "x", "y")}
    return b64url_encode(hashlib.sha256(canonical_json(required)).digest())


def _normalized_htu(url: str) -> str:
    split = urlsplit(url)
    if split.scheme not in {"http", "https"} or not split.netloc:
        raise AuthError("DPoP htu must be an absolute HTTP URL")
    return urlunsplit((split.scheme.lower(), split.netloc.lower(), split.path or "/", "", ""))


def create_proof(
    private: int,
    public: tuple[int, int],
    *,
    method: str,
    url: str,
    now: int,
    access_token: str | None = None,
    nonce: str | None = None,
) -> str:
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk(public)}
    claims: dict[str, Any] = {
        "jti": random_token(12),
        "htm": method.upper(),
        "htu": _normalized_htu(url),
        "iat": now,
    }
    if access_token is not None:
        claims["ath"] = b64url_encode(hashlib.sha256(access_token.encode()).digest())
    if nonce is not None:
        claims["nonce"] = nonce
    left = b64url_encode(canonical_json(header))
    middle = b64url_encode(canonical_json(claims))
    signing_input = f"{left}.{middle}".encode()
    r, s = ec.sign(private, signing_input)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{left}.{middle}.{b64url_encode(signature)}"


@dataclass
class DPoPVerifier:
    replay_cache: ReplayCache = field(default_factory=ReplayCache)
    max_age: int = 300

    def verify(
        self,
        proof: str,
        *,
        method: str,
        url: str,
        now: int,
        access_token: str | None = None,
        token_jkt: str | None = None,
        required_nonce: str | None = None,
    ) -> dict[str, Any]:
        parts = proof.split(".")
        if len(parts) != 3:
            raise AuthError("invalid DPoP compact JWS")
        header = json_from_bytes(b64url_decode(parts[0]))
        claims = json_from_bytes(b64url_decode(parts[1]))
        if header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256":
            raise AuthError("DPoP type or algorithm mismatch")
        jwk = header.get("jwk")
        if not isinstance(jwk, dict) or set(("kty", "crv", "x", "y")) - jwk.keys():
            raise AuthError("DPoP proof must contain a public JWK")
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            raise AuthError("unsupported DPoP key")
        public = (
            int.from_bytes(b64url_decode(str(jwk["x"])), "big"),
            int.from_bytes(b64url_decode(str(jwk["y"])), "big"),
        )
        raw_signature = b64url_decode(parts[2])
        if len(raw_signature) != 64:
            raise AuthError("invalid ES256 signature length")
        signature = (
            int.from_bytes(raw_signature[:32], "big"),
            int.from_bytes(raw_signature[32:], "big"),
        )
        if not ec.verify(public, f"{parts[0]}.{parts[1]}".encode(), signature):
            raise AuthError("invalid DPoP signature")
        if claims.get("htm") != method.upper() or claims.get("htu") != _normalized_htu(url):
            raise AuthError("DPoP request binding mismatch")
        issued = claims.get("iat")
        if not isinstance(issued, int) or abs(now - issued) > self.max_age:
            raise AuthError("DPoP proof is outside the accepted time window")
        if required_nonce is not None and claims.get("nonce") != required_nonce:
            raise AuthError("DPoP nonce mismatch")
        if access_token is not None:
            expected = b64url_encode(hashlib.sha256(access_token.encode()).digest())
            if claims.get("ath") != expected:
                raise AuthError("DPoP access-token hash mismatch")
        if token_jkt is not None and jwk_thumbprint(jwk) != token_jkt:
            raise AuthError("DPoP key is not bound to the access token")
        jti = claims.get("jti")
        if not isinstance(jti, str):
            raise AuthError("DPoP jti is required")
        self.replay_cache.consume(jti, issued + self.max_age + 1, now)
        return claims

