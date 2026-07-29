"""Small readable RSA implementation for signatures in this lab.

This module is intentionally not constant-time. Never use it in production.
"""

from __future__ import annotations

import hashlib
import math
import secrets
from dataclasses import dataclass

from .util import AuthError, b64url_encode

_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _is_probable_prime(value: int, rounds: int = 24) -> bool:
    if value < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if value in small:
        return True
    if any(value % prime == 0 for prime in small):
        return False
    d, s = value - 1, 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(rounds):
        base = secrets.randbelow(value - 3) + 2
        x = pow(base, d, value)
        if x in (1, value - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, value)
            if x == value - 1:
                break
        else:
            return False
    return True


def _prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int = 65537

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def jwk(self, *, kid: str) -> dict[str, str]:
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": b64url_encode(self.n.to_bytes(self.size_bytes, "big")),
            "e": b64url_encode(self.e.to_bytes((self.e.bit_length() + 7) // 8, "big")),
        }


@dataclass(frozen=True)
class RSAKeyPair:
    n: int
    e: int
    d: int
    p: int
    q: int

    @property
    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(self.n, self.e)


def generate_keypair(bits: int = 768) -> RSAKeyPair:
    if bits < 512:
        raise AuthError("RSA lab keys must be at least 512 bits")
    e = 65537
    while True:
        p, q = _prime(bits // 2), _prime(bits - bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            return RSAKeyPair(p * q, e, pow(e, -1, phi), p, q)


def _encoded_digest(message: bytes, size: int) -> bytes:
    digest_info = _SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    if size < len(digest_info) + 11:
        raise AuthError("RSA modulus is too small for SHA-256")
    return b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info


def sign_rs256(key: RSAKeyPair, message: bytes) -> bytes:
    size = key.public_key.size_bytes
    encoded = _encoded_digest(message, size)
    return pow(int.from_bytes(encoded, "big"), key.d, key.n).to_bytes(size, "big")


def verify_rs256(key: RSAPublicKey, message: bytes, signature: bytes) -> bool:
    if len(signature) != key.size_bytes:
        return False
    recovered = pow(int.from_bytes(signature, "big"), key.e, key.n).to_bytes(
        key.size_bytes,
        "big",
    )
    return secrets.compare_digest(recovered, _encoded_digest(message, key.size_bytes))

