"""NIST prime curves (P-256, P-384, P-521) and ECDSA, from scratch.

P-256 is the curve behind ES256, which is the algorithm every passkey and
every WebAuthn authenticator uses by default. It is also what most modern
IdPs are moving to for ID tokens: a P-256 signature is 64 bytes against
RSA-2048's 256, and signing is far cheaper.

The curve is y^2 = x^3 + ax + b over F_p, with a = -3 for all three NIST
prime curves. Points form a group under the chord-and-tangent addition below;
"multiplying" a point by a scalar means adding it to itself that many times,
and the discrete log problem -- recovering the scalar from the resulting
point -- is what makes it a key.

A curve is *data*, not code: swapping P-256 for P-384 changes six integers and
nothing else. That is why `Curve` below is a plain dataclass and every routine
takes its parameters from the point it was handed. It also means a point from
one curve can never be silently mixed into another curve's arithmetic, which
is the shape of the cross-curve confusion bugs that show up when a library
hardcodes P-256 and then bolts P-384 on later.

The one genuinely dangerous part of ECDSA is the per-signature nonce k:

    r = (kG).x mod n
    s = k^-1 (z + r*d) mod n

If k repeats across two signatures, subtracting the two equations recovers k,
and then d = (s*k - z) / r gives up the private key. This is not theoretical:
it is how the PlayStation 3 code-signing key was extracted in 2010 (Sony used
a constant k) and how a long line of Bitcoin wallets lost funds to a broken
RNG on Android. We default to RFC 6979 deterministic k -- derived by HMAC
from the private key and the message -- so a bad RNG cannot cause it.

Not constant time. Python big integers branch and allocate on value; treat
this module as a readable specification, never as a production primitive.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from ..util.encoding import bytes_to_int, int_to_bytes


@dataclass(frozen=True)
class Curve:
    """Short-Weierstrass domain parameters: y^2 = x^3 + ax + b over F_p."""

    name: str          # SEC 2 name, e.g. "secp256r1"
    p: int             # field prime
    b: int             # curve coefficient (a is always p - 3 here)
    gx: int            # generator x
    gy: int            # generator y
    n: int             # order of the generator
    field_bytes: int   # ceil(bit_length(p) / 8); fixes every encoded width
    oid: str           # ASN.1 object identifier, used by X.509
    jose_crv: str      # RFC 7518 "crv" value, e.g. "P-256"
    jose_alg: str      # the JWS algorithm this curve is paired with
    hash_name: str     # the hash RFC 7518 pairs with that algorithm

    @property
    def a(self) -> int:
        return self.p - 3

    @property
    def generator(self) -> "Point":
        return Point(self.gx, self.gy, self)

    @property
    def infinity(self) -> "Point":
        return Point(None, None, self)


# secp256r1 / prime256v1 domain parameters (NIST FIPS 186-4, SEC 2).
SECP256R1 = Curve(
    name="secp256r1",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    field_bytes=32,
    oid="1.2.840.10045.3.1.7",
    jose_crv="P-256",
    jose_alg="ES256",
    hash_name="sha256",
)

SECP384R1 = Curve(
    name="secp384r1",
    p=int(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
        "ffffffff0000000000000000ffffffff",
        16,
    ),
    b=int(
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
        "c656398d8a2ed19d2a85c8edd3ec2aef",
        16,
    ),
    gx=int(
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
        "5502f25dbf55296c3a545e3872760ab7",
        16,
    ),
    gy=int(
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
        "0a60b1ce1d7e819d7a431d7c90ea0e5f",
        16,
    ),
    n=int(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
        "581a0db248b0a77aecec196accc52973",
        16,
    ),
    field_bytes=48,
    oid="1.3.132.0.34",
    jose_crv="P-384",
    jose_alg="ES384",
    hash_name="sha384",
)

SECP521R1 = Curve(
    name="secp521r1",
    # 2**521 - 1. The only Mersenne prime among the NIST curves, which is why
    # its field elements are 66 bytes and the top byte only ever holds one bit.
    p=(1 << 521) - 1,
    b=int(
        "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1"
        "09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b50"
        "3f00",
        16,
    ),
    gx=int(
        "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d"
        "3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5"
        "bd66",
        16,
    ),
    gy=int(
        "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e"
        "662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd1"
        "6650",
        16,
    ),
    # Grouped the way SEC 2 prints it so the long run of f's stays countable:
    # 01ff | ffffffff x7 | fffffffa | 51868783 ... 91386409
    n=int(
        "01ff"
        "ffffffff" "ffffffff" "ffffffff" "ffffffff" "ffffffff" "ffffffff" "ffffffff"
        "fffffffa"
        "51868783" "bf2f966b" "7fcc0148" "f709a5d0"
        "3bb5c9b8" "899c47ae" "bb6fb71e" "91386409",
        16,
    ),
    field_bytes=66,
    oid="1.3.132.0.35",
    jose_crv="P-521",
    jose_alg="ES512",  # not a typo: ES512 means P-521 with SHA-512
    hash_name="sha512",
)

CURVES_BY_JOSE_CRV: dict[str, Curve] = {c.jose_crv: c for c in (SECP256R1, SECP384R1, SECP521R1)}
CURVES_BY_OID: dict[str, Curve] = {c.oid: c for c in (SECP256R1, SECP384R1, SECP521R1)}

# P-256 stays importable under its old flat names. Everything that existed
# before curves were parameterised keeps working unchanged.
P = SECP256R1.p
A = SECP256R1.a
B = SECP256R1.b
GX = SECP256R1.gx
GY = SECP256R1.gy
N = SECP256R1.n
FIELD_BYTES = SECP256R1.field_bytes

SECP256R1_OID = SECP256R1.oid
SECP384R1_OID = SECP384R1.oid
SECP521R1_OID = SECP521R1.oid
EC_PUBLIC_KEY_OID = "1.2.840.10045.2.1"


@dataclass(frozen=True)
class Point:
    """An affine point, or the point at infinity when x and y are None."""

    x: int | None
    y: int | None
    curve: Curve = field(default=SECP256R1)

    @property
    def is_infinity(self) -> bool:
        return self.x is None or self.y is None


INFINITY = Point(None, None, SECP256R1)
G = Point(SECP256R1.gx, SECP256R1.gy, SECP256R1)


def is_on_curve(point: Point) -> bool:
    """Check y^2 == x^3 + ax + b (mod p) on the point's own curve.

    Always call this on a public key you received from someone else. Skipping
    it enables invalid-curve attacks: an attacker sends a point on a *different*
    curve with a small subgroup, and each exchange leaks a few bits of your
    private scalar until the whole key falls out.
    """
    if point.is_infinity:
        return True
    curve = point.curve
    x, y = point.x, point.y
    if not (0 <= x < curve.p and 0 <= y < curve.p):
        return False
    return (y * y - (x * x * x + curve.a * x + curve.b)) % curve.p == 0


def _same_curve(p1: Point, p2: Point) -> Curve:
    """Refuse to mix curves. Two points only add if they share parameters."""
    if p1.curve is not p2.curve and p1.curve != p2.curve:
        raise ValueError(
            f"cannot combine a {p1.curve.name} point with a {p2.curve.name} point"
        )
    return p1.curve


def point_add(p1: Point, p2: Point) -> Point:
    """Chord-and-tangent addition on the curve."""
    if p1.is_infinity:
        return p2
    if p2.is_infinity:
        return p1
    curve = _same_curve(p1, p2)
    if p1.x == p2.x:
        if (p1.y + p2.y) % curve.p == 0:
            return curve.infinity  # P + (-P) = O
        return point_double(p1)
    # slope of the chord through the two points
    lam = ((p2.y - p1.y) * pow(p2.x - p1.x, -1, curve.p)) % curve.p
    x3 = (lam * lam - p1.x - p2.x) % curve.p
    return Point(x3, (lam * (p1.x - x3) - p1.y) % curve.p, curve)


def point_double(point: Point) -> Point:
    """Tangent-line doubling."""
    curve = point.curve
    if point.is_infinity or point.y == 0:
        return curve.infinity
    lam = ((3 * point.x * point.x + curve.a) * pow(2 * point.y, -1, curve.p)) % curve.p
    x3 = (lam * lam - 2 * point.x) % curve.p
    return Point(x3, (lam * (point.x - x3) - point.y) % curve.p, curve)


def scalar_mult(k: int, point: Point = G) -> Point:
    """Compute k*P with a Montgomery ladder.

    A plain double-and-add branches on each bit of k, so its timing and power
    trace leak the scalar. The ladder does one double and one add per bit
    regardless of the bit's value. Python integers are not constant time
    anyway -- this is a demonstration of the shape of the defence, not a
    hardened implementation.
    """
    curve = point.curve
    k %= curve.n
    if k == 0 or point.is_infinity:
        return curve.infinity
    r0, r1 = curve.infinity, point
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

    @property
    def curve(self) -> Curve:
        return self.point.curve

    def to_uncompressed(self) -> bytes:
        """SEC1 uncompressed encoding: 0x04 || X || Y, 2*field_bytes + 1."""
        size = self.curve.field_bytes
        return b"\x04" + int_to_bytes(self.x, size) + int_to_bytes(self.y, size)

    @classmethod
    def from_uncompressed(cls, data: bytes, curve: Curve = SECP256R1) -> "ECPublicKey":
        size = curve.field_bytes
        if len(data) != 1 + 2 * size or data[0] != 0x04:
            raise ValueError(
                f"expected a {1 + 2 * size}-byte SEC1 uncompressed {curve.jose_crv} point"
            )
        point = Point(bytes_to_int(data[1 : 1 + size]), bytes_to_int(data[1 + size :]), curve)
        if not is_on_curve(point):
            raise ValueError(f"point is not on the {curve.jose_crv} curve")
        return cls(point)


@dataclass(frozen=True)
class ECPrivateKey:
    d: int
    curve: Curve = field(default=SECP256R1)

    @property
    def public(self) -> ECPublicKey:
        return ECPublicKey(scalar_mult(self.d, self.curve.generator))


def generate_ec_keypair(curve: Curve = SECP256R1) -> ECPrivateKey:
    """A random private scalar in [1, n-1]."""
    import secrets

    return ECPrivateKey(secrets.randbelow(curve.n - 1) + 1, curve)


def _bits2int(data: bytes, curve: Curve = SECP256R1) -> int:
    """RFC 6979 bits2int: take the leftmost qlen bits of the hash.

    When the hash is *shorter* than the group order -- SHA-256 against P-384,
    say -- there is nothing to truncate and the value is used whole.
    """
    value = bytes_to_int(data)
    excess = len(data) * 8 - curve.n.bit_length()
    return value >> excess if excess > 0 else value


def _rfc6979_k(d: int, digest: bytes, curve: Curve, hash_name: str) -> int:
    """Deterministic nonce generation (RFC 6979 section 3.2).

    k is derived by HMAC-DRBG from the private key and the message hash. Two
    signatures over the same message reuse the same k -- which is fine, since
    they are the same signature -- but two different messages can never
    collide, and a broken RNG cannot make them collide either.
    """
    holen = hashlib.new(hash_name).digest_size
    rlen = curve.field_bytes
    x = int_to_bytes(d, rlen)
    h1 = int_to_bytes(_bits2int(digest, curve) % curve.n, rlen)

    v = b"\x01" * holen
    k = b"\x00" * holen
    k = hmac.new(k, v + b"\x00" + x + h1, hash_name).digest()
    v = hmac.new(k, v, hash_name).digest()
    k = hmac.new(k, v + b"\x01" + x + h1, hash_name).digest()
    v = hmac.new(k, v, hash_name).digest()

    while True:
        v = hmac.new(k, v, hash_name).digest()
        candidate = _bits2int(v, curve)
        if 1 <= candidate < curve.n:
            return candidate
        k = hmac.new(k, v + b"\x00", hash_name).digest()
        v = hmac.new(k, v, hash_name).digest()


def ecdsa_sign(
    key: ECPrivateKey, message: bytes, hash_name: str | None = None
) -> tuple[int, int]:
    """Sign, returning (r, s). Uses a deterministic nonce by default.

    `hash_name` defaults to the hash RFC 7518 pairs with the key's curve, so
    an ES384 key cannot accidentally be signed with SHA-256.
    """
    curve = key.curve
    hash_name = hash_name or curve.hash_name
    digest = hashlib.new(hash_name, message).digest()
    z = _bits2int(digest, curve)
    while True:
        k = _rfc6979_k(key.d, digest, curve, hash_name)
        point = scalar_mult(k, curve.generator)
        r = point.x % curve.n
        if r == 0:
            continue
        s = (pow(k, -1, curve.n) * (z + r * key.d)) % curve.n
        if s == 0:
            continue
        # Low-S normalisation. (r, s) and (r, n-s) are both valid, so a
        # signature is malleable unless you pin one form. Bitcoin's BIP-62
        # and WebAuthn's stricter verifiers both require the low form; it also
        # means a signature can safely be used as an idempotency key.
        if s > curve.n // 2:
            s = curve.n - s
        return r, s


def ecdsa_verify(
    key: ECPublicKey,
    message: bytes,
    signature: tuple[int, int],
    hash_name: str | None = None,
) -> bool:
    """Verify an (r, s) signature."""
    curve = key.curve
    hash_name = hash_name or curve.hash_name
    r, s = signature
    if not (1 <= r < curve.n and 1 <= s < curve.n):
        return False
    if not is_on_curve(key.point):
        return False
    digest = hashlib.new(hash_name, message).digest()
    z = _bits2int(digest, curve)
    w = pow(s, -1, curve.n)
    point = point_add(
        scalar_mult((z * w) % curve.n, curve.generator),
        scalar_mult((r * w) % curve.n, key.point),
    )
    if point.is_infinity:
        return False
    return point.x % curve.n == r


def signature_to_raw(signature: tuple[int, int], curve: Curve = SECP256R1) -> bytes:
    """JOSE encoding: R || S, each fixed at field_bytes (RFC 7518 section 3.4).

    Fixed width is what makes this parseable: ES256 is always 64 bytes, ES384
    always 96, ES512 always 132. There is no length prefix to read.
    """
    r, s = signature
    return int_to_bytes(r, curve.field_bytes) + int_to_bytes(s, curve.field_bytes)


def signature_from_raw(data: bytes, curve: Curve = SECP256R1) -> tuple[int, int]:
    size = curve.field_bytes
    if len(data) != size * 2:
        raise ValueError(
            f"{curve.jose_alg} signature must be {size * 2} bytes, got {len(data)}"
        )
    return bytes_to_int(data[:size]), bytes_to_int(data[size:])


def signature_to_der(signature: tuple[int, int]) -> bytes:
    """X.509 / WebAuthn encoding: SEQUENCE { INTEGER r, INTEGER s }.

    WebAuthn authenticators emit DER; JOSE wants raw R||S. Converting between
    the two is one of the most common sources of "signature invalid" when
    wiring a passkey backend, because the lengths differ per signature (DER
    integers are variable length and get a leading 0x00 when the top bit is
    set) while the raw form is always exactly 2*field_bytes.
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
