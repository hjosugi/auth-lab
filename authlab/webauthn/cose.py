"""COSE keys (RFC 8152), the CBOR cousin of JWK.

WebAuthn carries public keys as COSE_Key structures. It is the same
information as a JWK, with integer labels instead of string names, because
the authenticator is a chip with kilobytes of RAM.

    JWK              COSE label     value
    ----             ----------     -----
    kty              1              2 = EC2 (an elliptic-curve key)
    alg              3              -7 = ES256, -257 = RS256, -8 = EdDSA
    crv              -1             1 = P-256
    x                -2             32 raw bytes
    y                -3             32 raw bytes

Negative labels are not an accident: RFC 8152 reserves positive labels for
COSE-wide parameters and gives each key type its own negative range, so -1
means "crv" for an EC key and "n" for an RSA key. Reading a COSE key without
first checking `kty` is therefore a type-confusion bug waiting to happen,
which is why cose_decode_ec2 checks it before anything else.
"""

from __future__ import annotations

from ..crypto.ec import ECPublicKey, Point, is_on_curve
from ..crypto.cbor import decode, encode
from ..util.encoding import bytes_to_int, int_to_bytes

COSE_KTY = 1
COSE_ALG = 3
COSE_CRV = -1
COSE_X = -2
COSE_Y = -3

KTY_EC2 = 2
KTY_RSA = 3
COSE_ES256 = -7
COSE_RS256 = -257
COSE_EDDSA = -8
CRV_P256 = 1


def cose_encode_ec2(key: ECPublicKey, alg: int = COSE_ES256) -> bytes:
    """Encode a P-256 public key as a COSE_Key."""
    return encode(
        {
            COSE_KTY: KTY_EC2,
            COSE_ALG: alg,
            COSE_CRV: CRV_P256,
            COSE_X: int_to_bytes(key.x, 32),
            COSE_Y: int_to_bytes(key.y, 32),
        }
    )


def cose_decode_ec2(data: bytes | dict) -> ECPublicKey:
    """Decode a COSE_Key into a P-256 public key, validating it fully."""
    key = decode(data) if isinstance(data, (bytes, bytearray)) else data
    if not isinstance(key, dict):
        raise ValueError("COSE key must be a CBOR map")
    if key.get(COSE_KTY) != KTY_EC2:
        raise ValueError(f"expected an EC2 key, got kty={key.get(COSE_KTY)!r}")
    if key.get(COSE_ALG) != COSE_ES256:
        raise ValueError(f"expected ES256, got alg={key.get(COSE_ALG)!r}")
    if key.get(COSE_CRV) != CRV_P256:
        raise ValueError(f"expected P-256, got crv={key.get(COSE_CRV)!r}")
    x, y = key.get(COSE_X), key.get(COSE_Y)
    if not isinstance(x, (bytes, bytearray)) or len(x) != 32:
        raise ValueError("COSE x must be exactly 32 bytes")
    if not isinstance(y, (bytes, bytearray)) or len(y) != 32:
        raise ValueError("COSE y must be exactly 32 bytes")
    point = Point(bytes_to_int(x), bytes_to_int(y))
    if not is_on_curve(point):
        # Never skip this. A point off the curve is an invalid-curve attack.
        raise ValueError("COSE key is not a point on P-256")
    return ECPublicKey(point)
