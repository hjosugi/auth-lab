"""NIST P-256 (secp256r1) and ECDSA, from scratch.

P-256 is the curve behind ES256, which is the algorithm every passkey and
every WebAuthn authenticator uses by default. It is also what most modern
IdPs are moving to for ID tokens: a P-256 signature is 64 bytes against
RSA-2048's 256, and signing is far cheaper.

The curve is y^2 = x^3 + ax + b over F_p, with a = -3. Points form a group
under the chord-and-tangent addition below; "multiplying" a point by a scalar
means adding it to itself that many times, and the discrete log problem --
recovering the scalar from the resulting point -- is what makes it a key.

The one genuinely dangerous part of ECDSA is the per-signature nonce k:

    r = (kG).x mod n
    s = k^-1 (z + r*d) mod n

If k repeats across two signatures, subtracting the two equations recovers k,
and then d = (s*k - z) / r gives up the private key. This is not theoretical:
it is how the PlayStation 3 code-signing key was extracted in 2010 (Sony used
a constant k) and how a long line of Bitcoin wallets lost funds to a broken
RNG on Android. We default to RFC 6979 deterministic k -- derived by HMAC
from the private key and the message -- so a bad RNG cannot cause it.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from ..util.encoding import bytes_to_int, int_to_bytes

# secp256r1 domain parameters (NIST FIPS 186-4 / SEC 2).
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
FIELD_BYTES = 32

SECP256R1_OID = "1.2.840.10045.3.1.7"
EC_PUBLIC_KEY_OID = "1.2.840.10045.2.1"


@dataclass(frozen=True)
class Point:
    """An affine point, or the point at infinity when x and y are None."""

    x: int | None
    y: int | None

    @property
    def is_infinity(self) -> bool:
        return self.x is None or self.y is None


INFINITY = Point(None, None)
G = Point(GX, GY)


def is_on_curve(point: Point) -> bool:
    """Check y^2 == x^3 + ax + b (mod p).

    Always call this on a public key you received from someone else. Skipping
    it enables invalid-curve attacks: an attacker sends a point on a *different*
    curve with a small subgroup, and each exchange leaks a few bits of your
    private scalar until the whole key falls out.
    """
    if point.is_infinity:
        return True
    x, y = point.x, point.y
    if not (0 <= x < P and 0 <= y < P):
        return False
    return (y * y - (x * x * x + A * x + B)) % P == 0


def point_add(p1: Point, p2: Point) -> Point:
    """Chord-and-tangent addition on the curve."""
    if p1.is_infinity:
        return p2
    if p2.is_infinity:
        return p1
    if p1.x == p2.x:
        if (p1.y + p2.y) % P == 0:
            return INFINITY  # P + (-P) = O
        return point_double(p1)
    # slope of the chord through the two points
    lam = ((p2.y - p1.y) * pow(p2.x - p1.x, -1, P)) % P
    x3 = (lam * lam - p1.x - p2.x) % P
    return Point(x3, (lam * (p1.x - x3) - p1.y) % P)


def point_double(point: Point) -> Point:
    """Tangent-line doubling."""
    if point.is_infinity or point.y == 0:
        return INFINITY
    lam = ((3 * point.x * point.x + A) * pow(2 * point.y, -1, P)) % P
    x3 = (lam * lam - 2 * point.x) % P
    return Point(x3, (lam * (point.x - x3) - point.y) % P)


def scalar_mult(k: int, point: Point = G) -> Point:
    """Compute k*P with a Montgomery ladder.

    A plain double-and-add branches on each bit of k, so its timing and power
    trace leak the scalar. The ladder does one double and one add per bit
    regardless of the bit's value. Python integers are not constant time
    anyway -- this is a demonstration of the shape of the defence, not a
    hardened implementation.
    """
    k %= N
    if k == 0 or point.is_infinity:
        return INFINITY
    r0, r1 = INFINITY, point
    for bit in range(k.bit_length() - 1, -1, -1):
        if (k >> bit) & 1:
            r0, r1 = point_add(r0, r1), point_double(r1)
        else:
            r1, r0 = point_add(r0, r1), point_double(r0)
    return r0


@dataclass(frozen=True)
class ECPublicKey:
    point: Point

    @property
    def x(self) -> int:
        return self.point.x

    @property
    def y(self) -> int:
        return self.point.y

    def to_uncompressed(self) -> bytes:
        """SEC1 uncompressed encoding: 0x04 || X || Y, 65 bytes."""
        return b"\x04" + int_to_bytes(self.x, FIELD_BYTES) + int_to_bytes(self.y, FIELD_BYTES)

    @classmethod
    def from_uncompressed(cls, data: bytes) -> "ECPublicKey":
        if len(data) != 65 or data[0] != 0x04:
            raise ValueError("expected a 65-byte SEC1 uncompressed point")
        point = Point(bytes_to_int(data[1:33]), bytes_to_int(data[33:65]))
        if not is_on_curve(point):
            raise ValueError("point is not on the P-256 curve")
        return cls(point)


@dataclass(frozen=True)
class ECPrivateKey:
    d: int

    @property
    def public(self) -> ECPublicKey:
        return ECPublicKey(scalar_mult(self.d, G))


def generate_ec_keypair() -> ECPrivateKey:
    """A random private scalar in [1, n-1]."""
    import secrets

    return ECPrivateKey(secrets.randbelow(N - 1) + 1)


def _bits2int(data: bytes) -> int:
    """RFC 6979 bits2int: take the leftmost qlen bits of the hash."""
    value = bytes_to_int(data)
    excess = len(data) * 8 - N.bit_length()
    return value >> excess if excess > 0 else value


def _rfc6979_k(d: int, digest: bytes, hash_name: str = "sha256") -> int:
    """Deterministic nonce generation (RFC 6979 section 3.2).

    k is derived by HMAC-DRBG from the private key and the message hash. Two
    signatures over the same message reuse the same k -- which is fine, since
    they are the same signature -- but two different messages can never
    collide, and a broken RNG cannot make them collide either.
    """
    hlen = hashlib.new(hash_name).digest_size
    holen = hlen
    x = int_to_bytes(d, FIELD_BYTES)
    h1 = int_to_bytes(_bits2int(digest) % N, FIELD_BYTES)

    v = b"\x01" * holen
    k = b"\x00" * holen
    k = hmac.new(k, v + b"\x00" + x + h1, hash_name).digest()
    v = hmac.new(k, v, hash_name).digest()
    k = hmac.new(k, v + b"\x01" + x + h1, hash_name).digest()
    v = hmac.new(k, v, hash_name).digest()

    while True:
        v = hmac.new(k, v, hash_name).digest()
        candidate = _bits2int(v)
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hash_name).digest()
        v = hmac.new(k, v, hash_name).digest()


def ecdsa_sign(key: ECPrivateKey, message: bytes, hash_name: str = "sha256") -> tuple[int, int]:
    """Sign, returning (r, s). Uses a deterministic nonce by default."""
    digest = hashlib.new(hash_name, message).digest()
    z = _bits2int(digest)
    while True:
        k = _rfc6979_k(key.d, digest, hash_name)
        point = scalar_mult(k, G)
        r = point.x % N
        if r == 0:
            continue
        s = (pow(k, -1, N) * (z + r * key.d)) % N
        if s == 0:
            continue
        # Low-S normalisation. (r, s) and (r, n-s) are both valid, so a
        # signature is malleable unless you pin one form. Bitcoin's BIP-62
        # and WebAuthn's stricter verifiers both require the low form; it also
        # means a signature can safely be used as an idempotency key.
        if s > N // 2:
            s = N - s
        return r, s


def ecdsa_verify(
    key: ECPublicKey, message: bytes, signature: tuple[int, int], hash_name: str = "sha256"
) -> bool:
    """Verify an (r, s) signature."""
    r, s = signature
    if not (1 <= r < N and 1 <= s < N):
        return False
    if not is_on_curve(key.point):
        return False
    digest = hashlib.new(hash_name, message).digest()
    z = _bits2int(digest)
    w = pow(s, -1, N)
    point = point_add(scalar_mult((z * w) % N, G), scalar_mult((r * w) % N, key.point))
    if point.is_infinity:
        return False
    return point.x % N == r


def signature_to_raw(signature: tuple[int, int]) -> bytes:
    """JOSE encoding: R || S, each fixed at 32 bytes (RFC 7518 section 3.4)."""
    r, s = signature
    return int_to_bytes(r, FIELD_BYTES) + int_to_bytes(s, FIELD_BYTES)


def signature_from_raw(data: bytes) -> tuple[int, int]:
    if len(data) != FIELD_BYTES * 2:
        raise ValueError(f"ES256 signature must be 64 bytes, got {len(data)}")
    return bytes_to_int(data[:FIELD_BYTES]), bytes_to_int(data[FIELD_BYTES:])


def signature_to_der(signature: tuple[int, int]) -> bytes:
    """X.509 / WebAuthn encoding: SEQUENCE { INTEGER r, INTEGER s }.

    WebAuthn authenticators emit DER; JOSE wants raw R||S. Converting between
    the two is one of the most common sources of "signature invalid" when
    wiring a passkey backend, because the lengths differ per signature (DER
    integers are variable length and get a leading 0x00 when the top bit is
    set) while the raw form is always exactly 64 bytes.
    """
    from .asn1 import der_integer, der_sequence

    r, s = signature
    return der_sequence(der_integer(r), der_integer(s))


def signature_from_der(data: bytes) -> tuple[int, int]:
    """Parse SEQUENCE { INTEGER r, INTEGER s } strictly."""
    if len(data) < 8 or data[0] != 0x30:
        raise ValueError("not a DER SEQUENCE")
    body, rest = _read_tlv(data, 0x30)
    if rest:
        raise ValueError("trailing bytes after signature SEQUENCE")
    r_bytes, body = _read_tlv(body, 0x02)
    s_bytes, body = _read_tlv(body, 0x02)
    if body:
        raise ValueError("unexpected extra element in signature")
    return bytes_to_int(r_bytes), bytes_to_int(s_bytes)


def _read_tlv(data: bytes, expected_tag: int) -> tuple[bytes, bytes]:
    if not data or data[0] != expected_tag:
        raise ValueError(f"expected DER tag 0x{expected_tag:02x}")
    length = data[1]
    offset = 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4:
            raise ValueError("unsupported DER length form")
        length = bytes_to_int(data[2 : 2 + count])
        offset = 2 + count
    return data[offset : offset + length], data[offset + length :]
