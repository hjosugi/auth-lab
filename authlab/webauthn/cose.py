"""COSE keys (RFC 8152 / RFC 9052), the CBOR cousin of JWK.

WebAuthn carries public keys as COSE_Key structures. It is the same
information as a JWK, with integer labels instead of string names, because
the authenticator is a chip with kilobytes of RAM.

    JWK              COSE label     value
    ----             ----------     -----
    kty              1              1 = OKP, 2 = EC2, 3 = RSA
    alg              3              -7 = ES256, -8 = EdDSA, -257 = RS256
    crv              -1             1 = P-256, 6 = Ed25519
    x                -2             32 raw bytes (EC2 x, or the whole OKP key)
    y                -3             32 raw bytes (EC2 only)

Negative labels are not an accident: RFC 8152 reserves positive labels for
COSE-wide parameters and gives each key type its own negative range, so -1
means "crv" for an EC key and "n" for an RSA key. Reading a COSE key without
first checking `kty` is therefore a type-confusion bug waiting to happen,
which is why every decoder below checks it before touching anything else.

ES256 (-7) is what essentially every authenticator ships. EdDSA (-8) shows up
on newer security keys and on some platform authenticators. An RP advertises
what it accepts in `pubKeyCredParams`, in preference order, and must then be
able to verify whatever the authenticator picked -- accepting -8 in the
registration request and then only implementing -7 is a live failure mode.
"""

from __future__ import annotations

from typing import Any

from ..crypto.cbor import decode, encode
from ..crypto.ec import ECPublicKey, Point, is_on_curve
from ..crypto.ed25519 import KEY_SIZE as ED25519_KEY_SIZE
from ..crypto.ed25519 import Ed25519PublicKey
from ..util.encoding import bytes_to_int, int_to_bytes

COSE_KTY = 1
COSE_ALG = 3
COSE_CRV = -1
COSE_X = -2
COSE_Y = -3

KTY_OKP = 1
KTY_EC2 = 2
KTY_RSA = 3

COSE_ES256 = -7
COSE_EDDSA = -8
COSE_RS256 = -257

CRV_P256 = 1
CRV_ED25519 = 6

# The algorithms this lab can actually verify, in the order an RP should offer
# them. Advertising an algorithm you cannot verify is a registration that
# succeeds and an authentication that never will.
SUPPORTED_ALGORITHMS = (COSE_ES256, COSE_EDDSA)


def cose_encode_ec2(key: ECPublicKey, alg: int = COSE_ES256) -> bytes:
    """Encode a P-256 public key as a COSE_Key."""
    if key.curve.jose_crv != "P-256":
        raise ValueError(f"WebAuthn ES256 is P-256 only, got {key.curve.jose_crv}")
    return encode(
        {
            COSE_KTY: KTY_EC2,
            COSE_ALG: alg,
            COSE_CRV: CRV_P256,
            COSE_X: int_to_bytes(key.x, 32),
            COSE_Y: int_to_bytes(key.y, 32),
        }
    )


def cose_encode_okp(key: Ed25519PublicKey, alg: int = COSE_EDDSA) -> bytes:
    """Encode an Ed25519 public key as a COSE_Key.

    One coordinate, not two: an Ed25519 public key is already a compressed
    point, so there is no `y` label at all.
    """
    return encode(
        {
            COSE_KTY: KTY_OKP,
            COSE_ALG: alg,
            COSE_CRV: CRV_ED25519,
            COSE_X: key.data,
        }
    )


def cose_decode_ec2(data: bytes | dict) -> ECPublicKey:
    """Decode a COSE_Key into a P-256 public key, validating it fully."""
    key = _as_map(data)
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


def cose_decode_okp(data: bytes | dict) -> Ed25519PublicKey:
    """Decode a COSE_Key into an Ed25519 public key."""
    key = _as_map(data)
    if key.get(COSE_KTY) != KTY_OKP:
        raise ValueError(f"expected an OKP key, got kty={key.get(COSE_KTY)!r}")
    if key.get(COSE_ALG) != COSE_EDDSA:
        raise ValueError(f"expected EdDSA, got alg={key.get(COSE_ALG)!r}")
    if key.get(COSE_CRV) != CRV_ED25519:
        # crv=4 is X25519, a key-agreement curve that cannot sign. Treating
        # the two as interchangeable because both are "curve 25519" is the
        # type confusion this check exists to stop.
        raise ValueError(f"expected Ed25519, got crv={key.get(COSE_CRV)!r}")
    x = key.get(COSE_X)
    if not isinstance(x, (bytes, bytearray)) or len(x) != ED25519_KEY_SIZE:
        raise ValueError(f"COSE x must be exactly {ED25519_KEY_SIZE} bytes")
    return Ed25519PublicKey(bytes(x))


def cose_decode_public_key(data: bytes | dict) -> ECPublicKey | Ed25519PublicKey:
    """Dispatch on `kty`, then on `alg`, and return a typed key.

    The RP never chooses the algorithm from the token it is verifying: it
    reads the key type it stored at registration. This function exists for the
    registration path, where the authenticator's choice is what defines the
    credential from then on.
    """
    key = _as_map(data)
    kty = key.get(COSE_KTY)
    if kty == KTY_EC2:
        return cose_decode_ec2(key)
    if kty == KTY_OKP:
        return cose_decode_okp(key)
    raise ValueError(f"unsupported COSE key type: kty={kty!r}")


def cose_algorithm_of(data: bytes | dict) -> int:
    """Read the `alg` label, rejecting anything this lab cannot verify."""
    key = _as_map(data)
    alg = key.get(COSE_ALG)
    if alg not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"unsupported COSE algorithm: {alg!r}")
    return alg


def _as_map(data: bytes | dict) -> dict[Any, Any]:
    key = decode(data) if isinstance(data, (bytes, bytearray)) else data
    if not isinstance(key, dict):
        raise ValueError("COSE key must be a CBOR map")
    return key
