"""base64url and integer encoding helpers.

base64url (RFC 4648 section 5) is the alphabet used everywhere in JOSE: it
swaps '+/' for '-_' and drops the '=' padding. Dropping padding is not
cosmetic -- a JWT is three base64url segments joined by '.', and '=' would
survive URL encoding badly. So every JOSE segment is unpadded.
"""

from __future__ import annotations

import base64
import json
from typing import Any


def b64u_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(text: str | bytes) -> bytes:
    """Decode unpadded base64url back to bytes.

    We re-add the padding ourselves because base64.urlsafe_b64decode is strict
    about length being a multiple of 4.
    """
    if isinstance(text, bytes):
        text = text.decode("ascii")
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    """Big-endian integer to bytes (I2OSP from RFC 8017).

    When `length` is omitted we use the minimum number of bytes. JOSE requires
    fixed-width encoding for key material (an RSA modulus of 2048 bits is
    always 256 bytes, even if the top byte happens to be zero), so callers
    that build a JWK must pass an explicit length.
    """
    if value < 0:
        raise ValueError("negative integers are not representable")
    if length is None:
        length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def bytes_to_int(data: bytes) -> int:
    """Big-endian bytes to integer (OS2IP from RFC 8017)."""
    return int.from_bytes(data, "big")


def b64u_encode_int(value: int, length: int | None = None) -> str:
    return b64u_encode(int_to_bytes(value, length))


def b64u_decode_int(text: str) -> int:
    return bytes_to_int(b64u_decode(text))


def json_compact(obj: Any) -> bytes:
    """Serialize JSON the way JOSE wants it: no incidental whitespace.

    Note that this is NOT canonical JSON -- key order is whatever the dict
    has. That is fine for JWS because the signature covers the exact bytes we
    emit, not a re-serialization of the parsed object. It is exactly why a
    verifier must sign/verify over the received base64url text and never over
    `json.dumps(json.loads(...))`.
    """
    return json.dumps(obj, separators=(",", ":"), sort_keys=False).encode("utf-8")


def json_b64u(obj: Any) -> str:
    return b64u_encode(json_compact(obj))


def b64u_json(text: str) -> Any:
    return json.loads(b64u_decode(text).decode("utf-8"))
