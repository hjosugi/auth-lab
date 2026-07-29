"""HOTP: HMAC-based one-time passwords (RFC 4226).

The whole algorithm is four lines:

    hs      = HMAC-SHA1(secret, counter as 8-byte big-endian)
    offset  = hs[19] & 0x0F                 # low nibble of the last byte
    binary  = (hs[offset..offset+3]) & 0x7FFFFFFF
    code    = binary % 10^digits

Two details people always ask about:

* Why the dynamic offset? To stop anyone from arguing about *which* 4 bytes
  of the MAC to take. Deriving the offset from the MAC itself means an
  attacker cannot steer the choice, and it keeps every byte of the MAC in
  play across counters.

* Why mask off the top bit? Because in 2005 plenty of platforms treated a
  4-byte value as a signed 32-bit int, and a negative modulo would differ
  between languages. Clearing the sign bit makes the result unambiguous.

SHA-1 here is not a weakness: HMAC-SHA1 remains secure even though bare SHA-1
collisions are cheap, because HMAC does not depend on collision resistance.
It is specified as SHA-1 for interoperability -- every authenticator app
supports it, and many support nothing else.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from ..util.ct import constant_time_equals


def hotp(secret: bytes, counter: int, digits: int = 6, algorithm: str = "sha1") -> str:
    """Compute the HOTP value for a counter, zero-padded to `digits`."""
    if counter < 0:
        raise ValueError("counter must be non-negative")
    if not 6 <= digits <= 10:
        raise ValueError("digits must be between 6 and 10")

    counter_bytes = struct.pack(">Q", counter)  # 8-byte big-endian
    mac = hmac.new(secret, counter_bytes, getattr(hashlib, algorithm)).digest()

    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**digits)).zfill(digits)


def hotp_verify(
    secret: bytes,
    code: str,
    counter: int,
    digits: int = 6,
    algorithm: str = "sha1",
    look_ahead: int = 0,
) -> int | None:
    """Verify a HOTP code, scanning forward up to `look_ahead` counters.

    Returns the matching counter (so the server can resynchronise) or None.

    The look-ahead window exists because a hardware token's button can be
    pressed without the code being used, pushing the token ahead of the
    server. Keep the window small: every extra step multiplies an attacker's
    chance of a lucky guess by the same factor.
    """
    for offset in range(look_ahead + 1):
        expected = hotp(secret, counter + offset, digits, algorithm)
        if constant_time_equals(expected, code):
            return counter + offset
    return None
