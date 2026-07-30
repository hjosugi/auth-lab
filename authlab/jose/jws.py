"""JWS: JSON Web Signature, compact serialization (RFC 7515).

A compact JWS is three base64url segments joined by dots:

    BASE64URL(header) . BASE64URL(payload) . BASE64URL(signature)
    \\_________________________________/
              the signing input

The signing input is the *text* of the first two segments, including their
dot. This matters more than it looks: a verifier must sign over the bytes it
received, never over a re-serialization of the parsed JSON. Re-serializing
loses key order and whitespace and will silently break interop -- or worse,
let two different byte strings verify against one signature.

The three ways JWS verification is broken in the wild, all implemented as
rejections here:

1. alg=none. RFC 7515 defines an "unsecured JWS" with an empty signature. A
   verifier that reads `alg` from the token and dispatches on it will happily
   accept a forged token that says alg=none. Fix: the caller declares which
   algorithms are acceptable; the header's alg is only ever *checked against*
   that list, never used to choose.

2. Algorithm confusion (RS256 -> HS256). If the verifier picks HMAC because
   the header said so, and passes it the RSA public key as the HMAC secret,
   then anyone holding the public key -- which is public -- can mint tokens.
   Same fix: the expected algorithm comes from configuration, and a key is
   typed, so an RSA key cannot be fed to an HMAC algorithm.

3. Trusting header-supplied keys. `jwk`, `jku`, and `x5u` let a token carry
   or point at its own key. A verifier that follows them lets the attacker
   supply the key that validates their own forgery. We reject those headers
   outright and resolve keys only through a configured JWKS by `kid`.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from ..crypto.ec import (
    SECP256R1,
    SECP384R1,
    SECP521R1,
    Curve,
    ECPrivateKey,
    ECPublicKey,
    ecdsa_sign,
    ecdsa_verify,
    signature_from_raw,
    signature_to_raw,
)
from ..crypto.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
    ed25519_sign,
    ed25519_verify,
)
from ..crypto.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
    rsassa_pkcs1_v15_sign,
    rsassa_pkcs1_v15_verify,
)
from ..util.ct import constant_time_equals
from ..util.encoding import b64u_decode, b64u_encode, b64u_json, json_b64u
from .errors import InvalidSignature, InvalidToken

# Headers that let a token nominate its own verification key. Accepting any of
# these from an untrusted token is a complete authentication bypass.
FORBIDDEN_HEADERS = ("jwk", "jku", "x5u", "x5c")


@dataclass(frozen=True)
class Algorithm:
    name: str
    kind: str  # "HMAC", "RSA", "ECDSA", or "EdDSA"
    hash_name: str
    # Only meaningful for ECDSA: RFC 7518 pins one curve per algorithm name,
    # so a P-256 key can never be used to satisfy an ES384 header.
    curve: Curve | None = None

    def sign(self, key: Any, signing_input: bytes) -> bytes:
        if self.kind == "HMAC":
            if not isinstance(key, (bytes, bytearray)):
                raise InvalidSignature(f"{self.name} requires a bytes secret")
            return hmac.new(bytes(key), signing_input, getattr(hashlib, self.hash_name)).digest()
        if self.kind == "RSA":
            if not isinstance(key, RSAPrivateKey):
                raise InvalidSignature(f"{self.name} requires an RSAPrivateKey")
            return rsassa_pkcs1_v15_sign(key, signing_input, self.hash_name)
        if self.kind == "ECDSA":
            if not isinstance(key, ECPrivateKey):
                raise InvalidSignature(f"{self.name} requires an ECPrivateKey")
            self._require_curve(key.curve)
            # RFC 7518 section 3.4: fixed-width R || S, never DER.
            return signature_to_raw(ecdsa_sign(key, signing_input, self.hash_name), key.curve)
        if self.kind == "EdDSA":
            if not isinstance(key, Ed25519PrivateKey):
                raise InvalidSignature(f"{self.name} requires an Ed25519PrivateKey")
            return ed25519_sign(key, signing_input)
        raise InvalidSignature(f"unknown algorithm kind: {self.kind}")

    def verify(self, key: Any, signing_input: bytes, signature: bytes) -> bool:
        if self.kind == "HMAC":
            if not isinstance(key, (bytes, bytearray)):
                # This is the algorithm-confusion guard: an RSA key object can
                # never be silently coerced into an HMAC secret.
                raise InvalidSignature(f"{self.name} requires a bytes secret")
            expected = hmac.new(bytes(key), signing_input, getattr(hashlib, self.hash_name)).digest()
            return constant_time_equals(expected, signature)
        if self.kind == "RSA":
            if isinstance(key, RSAPrivateKey):
                key = key.public
            if not isinstance(key, RSAPublicKey):
                raise InvalidSignature(f"{self.name} requires an RSAPublicKey")
            return rsassa_pkcs1_v15_verify(key, signing_input, signature, self.hash_name)
        if self.kind == "ECDSA":
            if isinstance(key, ECPrivateKey):
                key = key.public
            if not isinstance(key, ECPublicKey):
                raise InvalidSignature(f"{self.name} requires an ECPublicKey")
            self._require_curve(key.curve)
            try:
                parsed = signature_from_raw(signature, key.curve)
            except ValueError:
                # Wrong length is a malformed signature, not a crash. A DER
                # signature pasted into a JWS lands here.
                return False
            return ecdsa_verify(key, signing_input, parsed, self.hash_name)
        if self.kind == "EdDSA":
            if isinstance(key, Ed25519PrivateKey):
                key = key.public
            if not isinstance(key, Ed25519PublicKey):
                raise InvalidSignature(f"{self.name} requires an Ed25519PublicKey")
            return ed25519_verify(key, signing_input, signature)
        raise InvalidSignature(f"unknown algorithm kind: {self.kind}")

    def _require_curve(self, curve: Curve) -> None:
        if self.curve is not None and curve != self.curve:
            raise InvalidSignature(
                f"{self.name} is defined over {self.curve.jose_crv}, "
                f"but the key is on {curve.jose_crv}"
            )


HS256 = Algorithm("HS256", "HMAC", "sha256")
HS384 = Algorithm("HS384", "HMAC", "sha384")
HS512 = Algorithm("HS512", "HMAC", "sha512")
RS256 = Algorithm("RS256", "RSA", "sha256")
RS384 = Algorithm("RS384", "RSA", "sha384")
RS512 = Algorithm("RS512", "RSA", "sha512")
# ES512 is P-521 with SHA-512, not "P-512". There is no P-512 curve. The name
# tracks the hash, and the mismatch trips people up in every JOSE library.
ES256 = Algorithm("ES256", "ECDSA", "sha256", SECP256R1)
ES384 = Algorithm("ES384", "ECDSA", "sha384", SECP384R1)
ES512 = Algorithm("ES512", "ECDSA", "sha512", SECP521R1)
# RFC 8037. "EdDSA" names the signature scheme; the curve lives in the key
# (crv=Ed25519), which is why there is exactly one algorithm identifier here.
EdDSA = Algorithm("EdDSA", "EdDSA", "sha512")

ALGORITHMS: dict[str, Algorithm] = {
    a.name: a
    for a in (
        HS256, HS384, HS512,
        RS256, RS384, RS512,
        ES256, ES384, ES512,
        EdDSA,
    )
}
# Note what is deliberately absent: "none". There is no code path in this
# module that can produce or accept an unsecured JWS.


@dataclass(frozen=True)
class ParsedJWS:
    header: dict[str, Any]
    payload: bytes
    signature: bytes
    signing_input: bytes
    raw: str


class JWS:
    """Sign and verify compact JWS tokens."""

    @staticmethod
    def sign(
        payload: bytes | dict[str, Any],
        key: Any,
        algorithm: Algorithm,
        headers: dict[str, Any] | None = None,
        kid: str | None = None,
        typ: str | None = "JWT",
    ) -> str:
        """Produce a compact JWS.

        `alg` is always written from the Algorithm object, never taken from
        caller-supplied headers, so a caller cannot accidentally emit a token
        whose header disagrees with how it was actually signed.
        """
        header: dict[str, Any] = {"alg": algorithm.name}
        if typ:
            header["typ"] = typ
        if kid:
            header["kid"] = kid
        if headers:
            for name, value in headers.items():
                if name in FORBIDDEN_HEADERS:
                    raise InvalidSignature(f"refusing to emit key-nominating header: {name}")
                if name == "alg":
                    continue
                header[name] = value

        if isinstance(payload, dict):
            payload_segment = json_b64u(payload)
        else:
            payload_segment = b64u_encode(payload)

        signing_input = f"{json_b64u(header)}.{payload_segment}".encode("ascii")
        signature = algorithm.sign(key, signing_input)
        return f"{signing_input.decode('ascii')}.{b64u_encode(signature)}"

    @staticmethod
    def parse(token: str) -> ParsedJWS:
        """Split a compact JWS without verifying anything.

        Useful for reading `kid` before you know which key to use -- and for
        nothing else. Never trust a value that came out of here.
        """
        if not isinstance(token, str):
            raise InvalidToken("token must be a string")
        parts = token.split(".")
        if len(parts) != 3:
            raise InvalidToken(f"compact JWS must have 3 segments, got {len(parts)}")
        header_seg, payload_seg, signature_seg = parts
        if not header_seg or not payload_seg:
            raise InvalidToken("header and payload segments must be non-empty")
        try:
            header = b64u_json(header_seg)
            payload = b64u_decode(payload_seg)
            signature = b64u_decode(signature_seg)
        except Exception as exc:  # noqa: BLE001 - any decode failure is malformed input
            raise InvalidToken(f"could not decode token segments: {exc}") from exc
        if not isinstance(header, dict):
            raise InvalidToken("JOSE header must be a JSON object")
        return ParsedJWS(
            header=header,
            payload=payload,
            signature=signature,
            signing_input=f"{header_seg}.{payload_seg}".encode("ascii"),
            raw=token,
        )

    @staticmethod
    def verify(
        token: str,
        key: Any | Callable[[dict[str, Any]], Any],
        allowed_algorithms: Sequence[str | Algorithm],
        allow_forbidden_headers: bool = False,
    ) -> ParsedJWS:
        """Verify a compact JWS and return it, or raise.

        `allowed_algorithms` is REQUIRED and has no default. That is the whole
        design: there is no way to call this function without stating what you
        will accept, so there is no way to fall into alg=none or algorithm
        confusion by omission.

        `key` may be a callable taking the parsed header, so a caller can look
        the key up by `kid` -- but the lookup happens against a JWKS the
        caller controls, not against anything the token supplied.
        """
        if not allowed_algorithms:
            raise InvalidSignature("allowed_algorithms must not be empty")

        allowed = {a.name if isinstance(a, Algorithm) else str(a) for a in allowed_algorithms}
        if "none" in {a.lower() for a in allowed}:
            raise InvalidSignature("'none' is not an acceptable algorithm")

        parsed = JWS.parse(token)

        if not allow_forbidden_headers:
            for name in FORBIDDEN_HEADERS:
                if name in parsed.header:
                    raise InvalidSignature(
                        f"header '{name}' would let the token choose its own key; rejected"
                    )

        alg_name = parsed.header.get("alg")
        if not isinstance(alg_name, str):
            raise InvalidSignature("missing or non-string 'alg' header")
        if alg_name not in allowed:
            # Covers alg=none and RS256->HS256 downgrade in one check.
            raise InvalidSignature(
                f"algorithm '{alg_name}' is not in the allowed set {sorted(allowed)}"
            )
        algorithm = ALGORITHMS.get(alg_name)
        if algorithm is None:
            raise InvalidSignature(f"unsupported algorithm: {alg_name}")

        if not parsed.signature:
            raise InvalidSignature("empty signature")

        resolved = key(parsed.header) if callable(key) else key
        if resolved is None:
            raise InvalidSignature("no key available for this token")

        if not algorithm.verify(resolved, parsed.signing_input, parsed.signature):
            raise InvalidSignature("signature verification failed")
        return parsed
