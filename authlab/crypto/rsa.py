"""RSA key generation and RSASSA-PKCS1-v1_5 signatures (RFC 8017), longhand.

This is the algorithm behind RS256, the default signing algorithm for ID
tokens in nearly every OpenID Connect deployment. Reading it once removes a
lot of mystery from "the IdP signs the token and we verify with the JWKS".

Signing is NOT encryption-with-the-private-key, even though PKCS#1 v1.5 makes
it look that way. What we actually do:

  1. hash the message                     H = SHA-256(M)
  2. wrap the hash in a DigestInfo         T = ASN.1(alg=sha256, digest=H)
  3. pad to the modulus size               EM = 0x00 || 0x01 || 0xFF... || 0x00 || T
  4. treat EM as an integer and do         S = EM^d mod n

Verification recomputes steps 1-3 from the message and compares against
S^e mod n. Note that we rebuild the expected EM and compare, rather than
parsing whatever comes out of the exponentiation. Parsing is where Bleichen-
bacher's 2006 "e=3 signature forgery" lived: implementations that scanned for
the DigestInfo instead of checking the full padding accepted garbage after it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ..util.encoding import bytes_to_int, int_to_bytes
from ..util.ct import constant_time_equals
from .primes import generate_prime

# DER-encoded DigestInfo prefixes from RFC 8017 section 9.2, note 1.
# They are constants: the ASN.1 header for "SHA-2xx digest follows".
DIGEST_INFO_PREFIX = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}

DEFAULT_PUBLIC_EXPONENT = 65537  # 0x10001: only 2 set bits, so exponentiation
                                 # is cheap, and it is large enough to defeat
                                 # the low-exponent attacks that killed e=3.


@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int

    @property
    def key_size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    @property
    def key_size_bits(self) -> int:
        return self.n.bit_length()


@dataclass(frozen=True)
class RSAPrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    qinv: int

    @property
    def public(self) -> RSAPublicKey:
        return RSAPublicKey(n=self.n, e=self.e)

    @property
    def key_size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    @property
    def key_size_bits(self) -> int:
        return self.n.bit_length()


def generate_rsa_keypair(bits: int = 2048, e: int = DEFAULT_PUBLIC_EXPONENT) -> RSAPrivateKey:
    """Generate an RSA private key.

    We pick p and q of bits/2 each, and reject pairs that are too close
    together: if |p - q| is small, Fermat factorization finds them almost
    instantly by searching near sqrt(n).
    """
    if bits < 512:
        raise ValueError("refusing to generate a key below 512 bits")
    half = bits // 2

    while True:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue
        # Guard against Fermat factorization: require the primes to differ in
        # their top bits, i.e. |p-q| > 2^(half-100).
        if abs(p - q) < (1 << (half - 100)):
            continue

        n = p * q
        if n.bit_length() != bits:
            continue

        # The private exponent is the inverse of e modulo lambda(n), the
        # Carmichael function. Using lambda rather than phi gives the smallest
        # working d, which is what every modern implementation does.
        lam = _lcm(p - 1, q - 1)
        if _gcd(e, lam) != 1:
            continue
        d = pow(e, -1, lam)

        # Wiener's attack recovers d when d < n^0.25 / 3. With e=65537 this
        # essentially never happens, but the check costs nothing.
        if d.bit_length() <= bits // 4:
            continue

        return RSAPrivateKey(
            n=n,
            e=e,
            d=d,
            # CRT parameters: signing via the Chinese Remainder Theorem works
            # with numbers half the size, which is roughly 3-4x faster.
            dp=d % (p - 1),
            dq=d % (q - 1),
            qinv=pow(q, -1, p),
            p=p,
            q=q,
        )


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _lcm(a: int, b: int) -> int:
    return a // _gcd(a, b) * b


def _rsasp1(key: RSAPrivateKey, m: int) -> int:
    """The private-key primitive: m^d mod n, computed with CRT."""
    if not (0 <= m < key.n):
        raise ValueError("message representative out of range")
    m1 = pow(m, key.dp, key.p)
    m2 = pow(m, key.dq, key.q)
    h = (key.qinv * (m1 - m2)) % key.p
    return m2 + h * key.q


def _rsavp1(key: RSAPublicKey, s: int) -> int:
    """The public-key primitive: s^e mod n."""
    if not (0 <= s < key.n):
        raise ValueError("signature representative out of range")
    return pow(s, key.e, key.n)


def emsa_pkcs1_v15_encode(message: bytes, em_len: int, hash_name: str = "sha256") -> bytes:
    """Build the padded encoded message EM (RFC 8017 section 9.2)."""
    if hash_name not in DIGEST_INFO_PREFIX:
        raise ValueError(f"unsupported hash: {hash_name}")
    digest = hashlib.new(hash_name, message).digest()
    t = DIGEST_INFO_PREFIX[hash_name] + digest

    # At least 8 bytes of 0xFF padding are mandatory; fewer means the modulus
    # is too small for this hash.
    if em_len < len(t) + 11:
        raise ValueError("intended encoded message length too short for this hash")

    ps = b"\xff" * (em_len - len(t) - 3)
    return b"\x00\x01" + ps + b"\x00" + t


def rsassa_pkcs1_v15_sign(key: RSAPrivateKey, message: bytes, hash_name: str = "sha256") -> bytes:
    """Sign `message`, returning a signature exactly key_size_bytes long."""
    em = emsa_pkcs1_v15_encode(message, key.key_size_bytes, hash_name)
    s = _rsasp1(key, bytes_to_int(em))
    return int_to_bytes(s, key.key_size_bytes)


def rsassa_pkcs1_v15_verify(
    key: RSAPublicKey, message: bytes, signature: bytes, hash_name: str = "sha256"
) -> bool:
    """Verify a signature by reconstructing the expected padded block.

    Length is checked first: a signature that is not exactly the modulus size
    is rejected outright, which closes off leading-zero manipulation.
    """
    if len(signature) != key.key_size_bytes:
        return False
    try:
        m = _rsavp1(key, bytes_to_int(signature))
        em = int_to_bytes(m, key.key_size_bytes)
        expected = emsa_pkcs1_v15_encode(message, key.key_size_bytes, hash_name)
    except ValueError:
        return False
    # Full-block comparison. We never parse `em` -- that is the Bleichenbacher
    # e=3 forgery lesson.
    return constant_time_equals(em, expected)
