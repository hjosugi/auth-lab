"""JWKS: JSON Web Key Set (RFC 7517).

A JWKS is how a resource server learns an IdP's public keys without anyone
copying a PEM around by hand. The IdP publishes

    GET /.well-known/jwks.json  ->  {"keys": [ {kty, kid, use, alg, n, e}, ... ]}

and the RS caches it, looking up by the token's `kid`.

Why a *set* and not one key: key rotation. To rotate without downtime the IdP
publishes the new key alongside the old one, starts signing with the new
`kid`, and removes the old key only after every outstanding token has expired.
An RS that caches a single key, or that caches the set forever, breaks at
exactly that moment -- which is why the refresh-on-unknown-kid path below
matters, along with a rate limit so an attacker cannot turn it into a way to
hammer the IdP by sending tokens with random kids.

An RSA public key in JWK form is just the two integers, base64url big-endian:
  n = modulus, e = public exponent.
Note the fixed-width encoding for n: it must be exactly the modulus size in
bytes, so a modulus whose top byte is zero still encodes to 256 bytes for a
2048-bit key. Trimming that leading zero is a classic interop bug.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable

from ..crypto.ec import (
    CURVES_BY_JOSE_CRV,
    Curve,
    ECPrivateKey,
    ECPublicKey,
    Point,
    is_on_curve,
)
from ..crypto.ed25519 import KEY_SIZE as ED25519_KEY_SIZE
from ..crypto.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from ..crypto.rsa import RSAPrivateKey, RSAPublicKey
from ..util.encoding import (
    b64u_decode,
    b64u_decode_int,
    b64u_encode,
    b64u_encode_int,
    json_compact,
)


@dataclass(frozen=True)
class JWK:
    """A single JSON Web Key. RSA public/private and oct (symmetric)."""

    data: dict[str, Any]

    @property
    def kid(self) -> str | None:
        return self.data.get("kid")

    @property
    def kty(self) -> str:
        return self.data.get("kty", "")

    @property
    def alg(self) -> str | None:
        return self.data.get("alg")

    @classmethod
    def from_rsa_public(
        cls, key: RSAPublicKey, kid: str | None = None, alg: str = "RS256", use: str = "sig"
    ) -> "JWK":
        data = {
            "kty": "RSA",
            "use": use,   # "sig" or "enc" -- a signing key must not be reused for encryption
            "alg": alg,
            "n": b64u_encode_int(key.n, key.key_size_bytes),  # fixed width, see module docstring
            "e": b64u_encode_int(key.e),
        }
        data["kid"] = kid or cls.thumbprint(data)
        return cls(data)

    @classmethod
    def from_rsa_private(
        cls, key: RSAPrivateKey, kid: str | None = None, alg: str = "RS256"
    ) -> "JWK":
        """Full private JWK. Never publish this -- it is here for key storage."""
        public = cls.from_rsa_public(key.public, kid=kid, alg=alg)
        size = key.key_size_bytes
        half = (key.p.bit_length() + 7) // 8
        data = dict(public.data)
        data.update(
            {
                "d": b64u_encode_int(key.d, size),
                "p": b64u_encode_int(key.p, half),
                "q": b64u_encode_int(key.q, half),
                "dp": b64u_encode_int(key.dp, half),
                "dq": b64u_encode_int(key.dq, half),
                "qi": b64u_encode_int(key.qinv, half),
            }
        )
        return cls(data)

    @classmethod
    def from_ec_public(
        cls, key: ECPublicKey, kid: str | None = None, alg: str | None = None, use: str = "sig"
    ) -> "JWK":
        """RFC 7518 section 6.2: an EC key is the curve name and two coordinates.

        Both coordinates are padded to the curve's field width. Trimming a
        leading zero byte is the same interop bug as trimming an RSA modulus,
        and it bites more often here because P-521 coordinates start with a
        zero byte roughly half the time.
        """
        curve = key.curve
        data = {
            "kty": "EC",
            "use": use,
            "alg": alg or curve.jose_alg,
            "crv": curve.jose_crv,
            "x": b64u_encode_int(key.x, curve.field_bytes),
            "y": b64u_encode_int(key.y, curve.field_bytes),
        }
        data["kid"] = kid or cls.thumbprint(data)
        return cls(data)

    @classmethod
    def from_ec_private(
        cls, key: ECPrivateKey, kid: str | None = None, alg: str | None = None
    ) -> "JWK":
        """Full private EC JWK. Never publish this."""
        public = cls.from_ec_public(key.public, kid=kid, alg=alg)
        data = dict(public.data)
        data["d"] = b64u_encode_int(key.d, key.curve.field_bytes)
        return cls(data)

    @classmethod
    def from_okp_public(
        cls,
        key: Ed25519PublicKey,
        kid: str | None = None,
        alg: str = "EdDSA",
        use: str = "sig",
    ) -> "JWK":
        """RFC 8037: octet key pair. One coordinate, because the point is
        compressed -- an Ed25519 public key is already just 32 bytes."""
        data = {
            "kty": "OKP",
            "use": use,
            "alg": alg,
            "crv": "Ed25519",
            "x": b64u_encode(key.data),
        }
        data["kid"] = kid or cls.thumbprint(data)
        return cls(data)

    @classmethod
    def from_okp_private(
        cls, key: Ed25519PrivateKey, kid: str | None = None, alg: str = "EdDSA"
    ) -> "JWK":
        """Full private OKP JWK. `d` is the 32-byte seed, not the expanded
        scalar -- a distinction that silently breaks key import when a library
        writes one and reads the other."""
        public = cls.from_okp_public(key.public, kid=kid, alg=alg)
        data = dict(public.data)
        data["d"] = b64u_encode(key.seed)
        return cls(data)

    @classmethod
    def from_secret(cls, secret: bytes, kid: str, alg: str = "HS256") -> "JWK":
        return cls({"kty": "oct", "kid": kid, "alg": alg, "k": b64u_encode(secret)})

    @staticmethod
    def thumbprint(data: dict[str, Any]) -> str:
        """RFC 7638 JWK thumbprint, the canonical way to name a key.

        The hash covers only the required members, in lexicographic order,
        with no whitespace. That canonicalisation is the point: two servers
        that received the same key in different JSON layouts still compute
        the same kid.
        """
        kty = data.get("kty")
        if kty == "RSA":
            required = {"e": data["e"], "kty": "RSA", "n": data["n"]}
        elif kty == "oct":
            required = {"k": data["k"], "kty": "oct"}
        elif kty == "EC":
            required = {"crv": data["crv"], "kty": "EC", "x": data["x"], "y": data["y"]}
        elif kty == "OKP":
            # RFC 8037 section 2: crv, kty, x -- no y, the point is compressed.
            required = {"crv": data["crv"], "kty": "OKP", "x": data["x"]}
        else:
            raise ValueError(f"cannot compute thumbprint for kty={kty!r}")
        canonical = json_compact({k: required[k] for k in sorted(required)})
        return b64u_encode(hashlib.sha256(canonical).digest())

    def public(self) -> "JWK":
        """Strip private members, so a key set can be published safely."""
        private_members = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
        return JWK({k: v for k, v in self.data.items() if k not in private_members})

    def to_rsa_public(self) -> RSAPublicKey:
        if self.kty != "RSA":
            raise ValueError(f"not an RSA key: kty={self.kty!r}")
        return RSAPublicKey(n=b64u_decode_int(self.data["n"]), e=b64u_decode_int(self.data["e"]))

    @property
    def curve(self) -> Curve:
        """The named curve for an EC key, resolved strictly.

        `crv` is what pins the key to one algorithm. A JWKS that says P-256
        while carrying 48-byte coordinates is either corrupt or an attempt at
        cross-curve confusion, so the width check below is not optional.
        """
        if self.kty != "EC":
            raise ValueError(f"not an EC key: kty={self.kty!r}")
        name = self.data.get("crv")
        curve = CURVES_BY_JOSE_CRV.get(name) if isinstance(name, str) else None
        if curve is None:
            raise ValueError(f"unsupported EC curve: {name!r}")
        return curve

    def to_ec_public(self) -> ECPublicKey:
        curve = self.curve
        x_raw, y_raw = b64u_decode(self.data["x"]), b64u_decode(self.data["y"])
        if len(x_raw) != curve.field_bytes or len(y_raw) != curve.field_bytes:
            raise ValueError(
                f"{curve.jose_crv} coordinates must be {curve.field_bytes} bytes each"
            )
        point = Point(int.from_bytes(x_raw, "big"), int.from_bytes(y_raw, "big"), curve)
        if not is_on_curve(point):
            # Invalid-curve attack: a point that is not on the curve can leak
            # the private scalar of whoever does arithmetic with it.
            raise ValueError(f"JWK point is not on {curve.jose_crv}")
        return ECPublicKey(point)

    def to_okp_public(self) -> Ed25519PublicKey:
        if self.kty != "OKP":
            raise ValueError(f"not an OKP key: kty={self.kty!r}")
        if self.data.get("crv") != "Ed25519":
            # X25519 is a key-agreement curve and cannot sign. Accepting it
            # here would be a type confusion, not a missing feature.
            raise ValueError(f"unsupported OKP curve: {self.data.get('crv')!r}")
        raw = b64u_decode(self.data["x"])
        if len(raw) != ED25519_KEY_SIZE:
            raise ValueError(f"Ed25519 x must be {ED25519_KEY_SIZE} bytes, got {len(raw)}")
        return Ed25519PublicKey(raw)

    def key_material(self) -> Any:
        """The object the JWS layer expects, typed per kty.

        Returning a *typed* object rather than raw bytes is what makes
        algorithm confusion impossible one layer up: `Algorithm.verify` for
        HS256 rejects anything that is not bytes, so an RSA or EC public key
        can never be reinterpreted as an HMAC secret.
        """
        if self.kty == "RSA":
            return self.to_rsa_public()
        if self.kty == "EC":
            return self.to_ec_public()
        if self.kty == "OKP":
            return self.to_okp_public()
        if self.kty == "oct":
            return b64u_decode(self.data["k"])
        raise ValueError(f"unsupported kty: {self.kty!r}")


@dataclass
class JWKSet:
    """A set of keys, resolvable by kid, with a refresh hook for rotation."""

    keys: list[JWK] = field(default_factory=list)
    # Called when a kid is not in the cache; should return a fresh JWKSet.
    fetch: Callable[[], "JWKSet"] | None = None
    _refreshes: int = 0
    max_refreshes: int = 5

    def add(self, key: JWK) -> "JWKSet":
        self.keys.append(key)
        return self

    def by_kid(self, kid: str | None) -> JWK | None:
        if kid is None:
            # No kid: only unambiguous if the set holds exactly one key.
            # Guessing among several is how a rotation turns into an outage
            # or, worse, into a signature checked against the wrong key.
            return self.keys[0] if len(self.keys) == 1 else None
        for key in self.keys:
            if key.kid == kid:
                return key
        if self.fetch is not None and self._refreshes < self.max_refreshes:
            # Unknown kid usually means the IdP rotated. Re-fetch once, but
            # cap it: otherwise a token with a random kid becomes a way to
            # make us DoS the IdP on every request.
            self._refreshes += 1
            refreshed = self.fetch()
            self.keys = refreshed.keys
            for key in self.keys:
                if key.kid == kid:
                    return key
        return None

    def resolver(self) -> Callable[[dict[str, Any]], Any]:
        """A key-resolver callable for JWS.verify, keyed on the header's kid."""

        def resolve(header: dict[str, Any]) -> Any:
            jwk = self.by_kid(header.get("kid"))
            if jwk is None:
                return None
            return jwk.key_material()

        return resolve

    def public_set(self) -> dict[str, Any]:
        """The JSON body to serve at /.well-known/jwks.json."""
        return {"keys": [k.public().data for k in self.keys]}

    @classmethod
    def from_json(cls, document: dict[str, Any]) -> "JWKSet":
        return cls(keys=[JWK(k) for k in document.get("keys", [])])
