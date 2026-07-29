"""Minimal P-256 and ECDSA implementation for WebAuthn and DPoP labs.

The arithmetic is variable-time and educational only.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import TypeAlias

from .util import AuthError

Point: TypeAlias = tuple[int, int] | None

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G: Point = (GX, GY)


def is_on_curve(point: Point) -> bool:
    if point is None:
        return True
    x, y = point
    return 0 <= x < P and 0 <= y < P and (y * y - x * x * x - A * x - B) % P == 0


def point_add(left: Point, right: Point) -> Point:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    result = (x3, y3)
    if not is_on_curve(result):
        raise AuthError("elliptic-curve arithmetic failed")
    return result


def scalar_mult(scalar: int, point: Point = G) -> Point:
    if scalar % N == 0 or point is None:
        return None
    if scalar < 0:
        x, y = point
        return scalar_mult(-scalar, (x, -y % P))
    result: Point = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def generate_keypair() -> tuple[int, tuple[int, int]]:
    private = secrets.randbelow(N - 1) + 1
    public = scalar_mult(private)
    if public is None:
        raise AuthError("failed to create P-256 key")
    return private, public


def _deterministic_k(private: int, digest: bytes) -> int:
    x = private.to_bytes(32, "big")
    value = b"\x01" * 32
    key = b"\x00" * 32
    key = hmac.new(key, value + b"\x00" + x + digest, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    key = hmac.new(key, value + b"\x01" + x + digest, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    while True:
        value = hmac.new(key, value, hashlib.sha256).digest()
        candidate = int.from_bytes(value, "big")
        if 1 <= candidate < N:
            return candidate
        key = hmac.new(key, value + b"\x00", hashlib.sha256).digest()
        value = hmac.new(key, value, hashlib.sha256).digest()


def sign(private: int, message: bytes) -> tuple[int, int]:
    digest = hashlib.sha256(message).digest()
    z = int.from_bytes(digest, "big")
    nonce = _deterministic_k(private, digest)
    point = scalar_mult(nonce)
    if point is None:
        raise AuthError("invalid ECDSA nonce")
    r = point[0] % N
    s = (pow(nonce, -1, N) * (z + r * private)) % N
    if not r or not s:
        raise AuthError("invalid ECDSA signature")
    return r, min(s, N - s)


def verify(public: tuple[int, int], message: bytes, signature: tuple[int, int]) -> bool:
    if not is_on_curve(public):
        return False
    r, s = signature
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    inverse = pow(s, -1, N)
    point = point_add(
        scalar_mult(z * inverse % N),
        scalar_mult(r * inverse % N, public),
    )
    return point is not None and point[0] % N == r

