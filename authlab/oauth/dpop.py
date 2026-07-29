"""DPoP: Demonstrating Proof of Possession at the Application Layer (RFC 9449).

A bearer token is a bearer token: whoever holds it, uses it. Steal one from a
log, a referrer header, or a compromised proxy and you are the user until it
expires. DPoP fixes that by binding the token to a key the client holds.

How it works:

  1. The client generates a key pair (P-256, in a browser it lives in
     IndexedDB as a non-extractable CryptoKey).
  2. On every request -- token endpoint AND resource server -- it sends a
     `DPoP:` header containing a short JWT signed by that key. The proof's
     JOSE header carries the PUBLIC key inline as `jwk`, and the payload
     carries `htm` (HTTP method), `htu` (URL), `iat`, and `jti`.
  3. The AS computes the RFC 7638 thumbprint of that public key and puts it
     in the access token as `cnf: {"jkt": "..."}`.
  4. The resource server checks: proof signature valid, htm/htu match THIS
     request, iat is recent, jti not seen before, and
     thumbprint(proof.jwk) == token.cnf.jkt. It also checks `ath`, the hash
     of the access token, so a proof captured for one token cannot be reused
     with another.

A stolen access token is now useless without the private key.

Note the deliberate contrast with authlab.jose.jws, which refuses the `jwk`
header outright. Here the inline key is correct and required -- because the
proof is not the thing being trusted. The jwk only proves "whoever made this
proof holds the key whose thumbprint is in the token", and the token, signed
by the AS, is what carries the authority. Trusting a token's own `jwk` would
be a bypass; trusting a proof's `jwk` *against a thumbprint from a verified
token* is the whole design.

The remaining gaps DPoP does not close:
  * A client whose device is fully compromised loses the key too.
  * Without a server-supplied nonce, a proof can be precomputed. The
    `DPoP-Nonce` header (and the `use_dpop_nonce` error) lets the server force
    freshness; we implement both.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ..crypto.ec import (
    ECPrivateKey,
    ECPublicKey,
    Point,
    ecdsa_sign,
    ecdsa_verify,
    generate_ec_keypair,
    signature_from_raw,
    signature_to_raw,
)
from ..jose.jwks import JWK
from ..util.clock import Clock, SystemClock
from ..util.ct import constant_time_equals, random_token
from ..util.encoding import (
    b64u_decode,
    b64u_decode_int,
    b64u_encode,
    b64u_encode_int,
    b64u_json,
    json_b64u,
)
from .errors import InvalidDPoPProof, UseDPoPNonce

DPOP_TYP = "dpop+jwt"
# How far the proof's iat may be from our clock. RFC 9449 suggests "a few
# seconds"; we allow a minute in each direction because laptops sleep.
DEFAULT_MAX_AGE = 60


def ec_public_jwk(key: ECPublicKey) -> dict[str, Any]:
    """A P-256 public key as a JWK (RFC 7518 section 6.2)."""
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u_encode_int(key.x, 32),
        "y": b64u_encode_int(key.y, 32),
    }


def ec_public_from_jwk(data: dict[str, Any]) -> ECPublicKey:
    if data.get("kty") != "EC" or data.get("crv") != "P-256":
        raise InvalidDPoPProof("DPoP proof key must be an EC P-256 key")
    if "d" in data:
        # A proof that leaks its own private key is either a broken client or
        # an attempt to confuse the parser. Refuse it either way.
        raise InvalidDPoPProof("DPoP proof header must not contain a private key")
    try:
        key = ECPublicKey(Point(b64u_decode_int(data["x"]), b64u_decode_int(data["y"])))
    except KeyError as exc:
        raise InvalidDPoPProof(f"malformed EC JWK: missing {exc}") from exc
    from ..crypto.ec import is_on_curve

    if not is_on_curve(key.point):
        raise InvalidDPoPProof("DPoP proof key is not a valid P-256 point")
    return key


def jkt(public_jwk: dict[str, Any]) -> str:
    """RFC 7638 thumbprint of a JWK -- the value that goes in `cnf.jkt`."""
    return JWK.thumbprint(public_jwk)


def normalize_htu(url: str) -> str:
    """The `htu` claim is the request URI without query or fragment.

    Query is excluded because a client cannot always predict the exact query
    the server sees (proxies reorder and add parameters). Scheme and host are
    lowercased so a proof for HTTPS://API.example is not treated as different
    from https://api.example.
    """
    parts = urlsplit(url)
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, "", ""))


def access_token_hash(access_token: str) -> str:
    """`ath`: base64url(SHA-256(access token)), binding a proof to one token."""
    return b64u_encode(hashlib.sha256(access_token.encode("ascii")).digest())


@dataclass
class DPoPClientKey:
    """The client side: holds the key and mints proofs."""

    private: ECPrivateKey = field(default_factory=generate_ec_keypair)
    clock: Clock = field(default_factory=SystemClock)

    @property
    def public_jwk(self) -> dict[str, Any]:
        return ec_public_jwk(self.private.public)

    @property
    def thumbprint(self) -> str:
        return jkt(self.public_jwk)

    def proof(
        self,
        method: str,
        url: str,
        *,
        access_token: str | None = None,
        nonce: str | None = None,
    ) -> str:
        """Mint a DPoP proof JWT for one specific request."""
        header = {"typ": DPOP_TYP, "alg": "ES256", "jwk": self.public_jwk}
        payload: dict[str, Any] = {
            "jti": random_token(16),
            "htm": method.upper(),
            "htu": normalize_htu(url),
            "iat": self.clock.now(),
        }
        if access_token is not None:
            payload["ath"] = access_token_hash(access_token)
        if nonce is not None:
            payload["nonce"] = nonce
        signing_input = f"{json_b64u(header)}.{json_b64u(payload)}".encode("ascii")
        signature = signature_to_raw(ecdsa_sign(self.private, signing_input))
        return f"{signing_input.decode('ascii')}.{b64u_encode(signature)}"


@dataclass
class DPoPVerifier:
    """The server side: validates proofs and tracks jti replay."""

    clock: Clock = field(default_factory=SystemClock)
    max_age: int = DEFAULT_MAX_AGE
    require_nonce: bool = False
    # jti -> expiry. In production this is Redis with a TTL, sized to
    # max_age * 2; keeping them forever is a memory leak, dropping them early
    # re-opens the replay window.
    seen: dict[str, int] = field(default_factory=dict)
    current_nonce: str | None = None

    def issue_nonce(self) -> str:
        self.current_nonce = random_token(16)
        return self.current_nonce

    def _purge(self) -> None:
        now = self.clock.now()
        for key in [k for k, exp in self.seen.items() if exp < now]:
            del self.seen[key]

    def verify(
        self,
        proof: str,
        method: str,
        url: str,
        *,
        access_token: str | None = None,
        expected_jkt: str | None = None,
    ) -> str:
        """Verify a proof and return the key thumbprint. Raises on failure."""
        if not proof:
            raise InvalidDPoPProof("missing DPoP proof")
        parts = proof.split(".")
        if len(parts) != 3:
            raise InvalidDPoPProof("DPoP proof is not a compact JWS")
        header_seg, payload_seg, signature_seg = parts

        try:
            header = __import__("json").loads(b64u_decode(header_seg))
            payload = __import__("json").loads(b64u_decode(payload_seg))
            signature = b64u_decode(signature_seg)
        except Exception as exc:  # noqa: BLE001
            raise InvalidDPoPProof(f"malformed DPoP proof: {exc}") from exc

        if header.get("typ") != DPOP_TYP:
            # The typ check is what stops a DPoP proof being replayed as an
            # access token, or an access token being submitted as a proof.
            raise InvalidDPoPProof(f"typ must be {DPOP_TYP!r}")
        if header.get("alg") != "ES256":
            raise InvalidDPoPProof("only ES256 DPoP proofs are accepted")
        if "jwk" not in header:
            raise InvalidDPoPProof("DPoP proof must carry its public key in the jwk header")

        public = ec_public_from_jwk(header["jwk"])
        signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
        if not ecdsa_verify(public, signing_input, signature_from_raw(signature)):
            raise InvalidDPoPProof("DPoP proof signature is invalid")

        if payload.get("htm", "").upper() != method.upper():
            raise InvalidDPoPProof(f"htm mismatch: proof is for {payload.get('htm')!r}")
        if payload.get("htu") != normalize_htu(url):
            raise InvalidDPoPProof(f"htu mismatch: proof is for {payload.get('htu')!r}")

        iat = payload.get("iat")
        if not isinstance(iat, int):
            raise InvalidDPoPProof("iat is missing or not an integer")
        now = self.clock.now()
        if abs(now - iat) > self.max_age:
            raise InvalidDPoPProof(f"proof iat is outside the +/-{self.max_age}s window")

        jti = payload.get("jti")
        if not isinstance(jti, str) or not jti:
            raise InvalidDPoPProof("jti is missing")
        self._purge()
        if jti in self.seen:
            raise InvalidDPoPProof("DPoP proof replay detected (jti already used)")

        if self.require_nonce:
            supplied = payload.get("nonce")
            if supplied is None:
                raise UseDPoPNonce("a server-supplied DPoP nonce is required")
            if self.current_nonce is None or not constant_time_equals(
                str(supplied), self.current_nonce
            ):
                raise UseDPoPNonce("DPoP nonce is stale")

        if access_token is not None:
            ath = payload.get("ath")
            if ath is None:
                raise InvalidDPoPProof("ath is required when presenting an access token")
            if not constant_time_equals(str(ath), access_token_hash(access_token)):
                raise InvalidDPoPProof("ath does not match the presented access token")

        thumbprint = jkt(header["jwk"])
        if expected_jkt is not None and not constant_time_equals(thumbprint, expected_jkt):
            # This is the check that makes a stolen token useless.
            raise InvalidDPoPProof("proof key does not match the token's cnf.jkt binding")

        self.seen[jti] = now + self.max_age * 2
        return thumbprint
