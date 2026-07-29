"""Constant-time comparison and random token generation.

Why constant time matters: a naive `a == b` on bytes returns as soon as it
finds a differing byte. An attacker who can measure that difference can
recover a MAC or a session id one byte at a time -- roughly 256*N guesses
instead of 256**N. `hmac.compare_digest` compares every byte regardless.

Why `secrets` and not `random`: `random` is a Mersenne Twister seeded from a
small state. Observing 624 outputs recovers the whole internal state and lets
you predict every future value. `secrets` reads the OS CSPRNG.
"""

from __future__ import annotations

import hmac
import secrets

from .encoding import b64u_encode


def constant_time_equals(a: bytes | str, b: bytes | str) -> bool:
    """Compare two values without leaking where they diverge."""
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)


def random_bytes(n: int = 32) -> bytes:
    """n cryptographically strong random bytes."""
    return secrets.token_bytes(n)


def random_token(n_bytes: int = 32) -> str:
    """A URL-safe opaque token.

    32 bytes = 256 bits of entropy, which is the usual floor for anything that
    is a bearer credential by itself (session id, authorization code, refresh
    token). 16 bytes is acceptable for short-lived, single-use values.
    """
    return b64u_encode(random_bytes(n_bytes))
