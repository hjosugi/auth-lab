"""Minimal CBOR (RFC 8949), enough for WebAuthn.

WebAuthn encodes the attestation object and COSE public keys in CBOR rather
than JSON, for two reasons: it is compact (an authenticator is a constrained
device) and it is binary-native, so a public key coordinate does not need
base64.

The encoding is a type in the top 3 bits of the first byte and a length or
value in the low 5:

    0 unsigned int      4 array
    1 negative int      5 map
    2 byte string       6 tag
    3 text string       7 simple/float (20 false, 21 true, 22 null)

Low bits 0-23 are the value itself; 24/25/26/27 mean the value is in the next
1/2/4/8 bytes.

WebAuthn requires CTAP2 canonical CBOR for the parts that get hashed: map
keys sorted by length then bytewise, definite lengths only, shortest-form
integers. We enforce that on encode and reject anything non-canonical on
decode, because a verifier that re-encodes a parsed object non-canonically
will compute the wrong hash and reject valid attestations.
"""

from __future__ import annotations

from typing import Any

MAJOR_UNSIGNED = 0
MAJOR_NEGATIVE = 1
MAJOR_BYTES = 2
MAJOR_TEXT = 3
MAJOR_ARRAY = 4
MAJOR_MAP = 5
MAJOR_SIMPLE = 7


def _encode_head(major: int, value: int) -> bytes:
    """Shortest-form head, as canonical CBOR requires."""
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 0x100:
        return bytes([(major << 5) | 24, value])
    if value < 0x10000:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 0x100000000:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    if value < 0x10000000000000000:
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")
    raise ValueError("integer too large for CBOR")


def _canonical_key(item: tuple[Any, Any]) -> tuple[int, bytes]:
    """CTAP2 canonical map ordering: shorter encoding first, then bytewise."""
    encoded = encode(item[0])
    return (len(encoded), encoded)


def encode(obj: Any) -> bytes:
    """Encode a Python object as canonical CBOR."""
    if obj is False:
        return b"\xf4"
    if obj is True:
        return b"\xf5"
    if obj is None:
        return b"\xf6"
    if isinstance(obj, int):
        if obj >= 0:
            return _encode_head(MAJOR_UNSIGNED, obj)
        return _encode_head(MAJOR_NEGATIVE, -obj - 1)  # -1 encodes as 0
    if isinstance(obj, (bytes, bytearray)):
        return _encode_head(MAJOR_BYTES, len(obj)) + bytes(obj)
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _encode_head(MAJOR_TEXT, len(raw)) + raw
    if isinstance(obj, (list, tuple)):
        return _encode_head(MAJOR_ARRAY, len(obj)) + b"".join(encode(i) for i in obj)
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=_canonical_key)
        body = b"".join(encode(k) + encode(v) for k, v in items)
        return _encode_head(MAJOR_MAP, len(obj)) + body
    raise TypeError(f"cannot CBOR-encode {type(obj).__name__}")


def _decode_head(data: bytes, offset: int) -> tuple[int, int, int]:
    if offset >= len(data):
        raise ValueError("truncated CBOR")
    initial = data[offset]
    major, info = initial >> 5, initial & 0x1F
    offset += 1
    if info < 24:
        return major, info, offset
    size = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
    if size is None:
        # 28-30 are reserved; 31 is an indefinite length, which canonical
        # CBOR forbids and which WebAuthn verifiers must not accept.
        raise ValueError(f"unsupported or indefinite CBOR length (info={info})")
    if offset + size > len(data):
        raise ValueError("truncated CBOR length")
    value = int.from_bytes(data[offset : offset + size], "big")
    return major, value, offset + size


def _decode_at(data: bytes, offset: int) -> tuple[Any, int]:
    major, value, offset = _decode_head(data, offset)
    if major == MAJOR_UNSIGNED:
        return value, offset
    if major == MAJOR_NEGATIVE:
        return -value - 1, offset
    if major == MAJOR_BYTES:
        end = offset + value
        if end > len(data):
            raise ValueError("truncated CBOR byte string")
        return data[offset:end], end
    if major == MAJOR_TEXT:
        end = offset + value
        if end > len(data):
            raise ValueError("truncated CBOR text string")
        return data[offset:end].decode("utf-8"), end
    if major == MAJOR_ARRAY:
        items = []
        for _ in range(value):
            item, offset = _decode_at(data, offset)
            items.append(item)
        return items, offset
    if major == MAJOR_MAP:
        result: dict[Any, Any] = {}
        previous: bytes | None = None
        for _ in range(value):
            key, offset = _decode_at(data, offset)
            encoded_key = encode(key)
            if previous is not None and (len(encoded_key), encoded_key) <= (
                len(previous),
                previous,
            ):
                raise ValueError("CBOR map keys are not in canonical order")
            previous = encoded_key
            item, offset = _decode_at(data, offset)
            if key in result:
                raise ValueError(f"duplicate CBOR map key: {key!r}")
            result[key] = item
        return result, offset
    if major == MAJOR_SIMPLE:
        if value == 20:
            return False, offset
        if value == 21:
            return True, offset
        if value == 22:
            return None, offset
        raise ValueError(f"unsupported CBOR simple value {value}")
    raise ValueError(f"unsupported CBOR major type {major}")


def decode(data: bytes) -> Any:
    """Decode CBOR, rejecting trailing bytes."""
    obj, offset = _decode_at(data, 0)
    if offset != len(data):
        raise ValueError(f"{len(data) - offset} trailing bytes after CBOR value")
    return obj


def decode_prefix(data: bytes) -> tuple[Any, bytes]:
    """Decode one CBOR item and return it with the unconsumed remainder.

    Needed for WebAuthn's attestedCredentialData, where a COSE key is
    followed by nothing in theory but by extension data in practice.
    """
    obj, offset = _decode_at(data, 0)
    return obj, data[offset:]
