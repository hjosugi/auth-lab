"""HOTP and TOTP implemented directly from RFC 4226 and RFC 6238."""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from .util import AuthError, secure_equal, unix_time


def hotp(
    secret: bytes,
    counter: int,
    *,
    digits: int = 6,
    digest: str = "sha1",
) -> str:
    if counter < 0 or digits not in {6, 7, 8}:
        raise AuthError("invalid HOTP parameters")
    try:
        digestmod = getattr(hashlib, digest)
    except AttributeError as exc:
        raise AuthError("unsupported HOTP digest") from exc
    mac = hmac.new(secret, struct.pack(">Q", counter), digestmod).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def totp(
    secret: bytes,
    *,
    at: int | None = None,
    step: int = 30,
    digits: int = 6,
    digest: str = "sha1",
) -> str:
    current = unix_time() if at is None else at
    return hotp(secret, current // step, digits=digits, digest=digest)


@dataclass
class TotpVerifier:
    secret: bytes
    step: int = 30
    digits: int = 6
    window: int = 1
    last_counter: int = -1

    def verify(self, code: str, *, at: int | None = None) -> bool:
        current = unix_time() if at is None else at
        counter = current // self.step
        for candidate in range(counter - self.window, counter + self.window + 1):
            if candidate <= self.last_counter or candidate < 0:
                continue
            expected = hotp(self.secret, candidate, digits=self.digits)
            if secure_equal(expected, code):
                self.last_counter = candidate
                return True
        return False

