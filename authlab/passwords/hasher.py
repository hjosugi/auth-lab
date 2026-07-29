"""Password storage: salted, slow, parameterised, and upgradeable.

The four rules, in order of how often they are broken:

1. Never store the password. Store a one-way function of it.
2. Salt per user. Without a salt, identical passwords produce identical
   hashes, so one rainbow table cracks the whole database at once and you can
   see which users share a password just by reading the column.
3. Be slow on purpose. SHA-256 does billions of guesses per second on a GPU.
   scrypt and Argon2 add a *memory* cost, which is what actually hurts GPUs
   and ASICs -- they have thousands of cores but not thousands of independent
   megabytes of fast RAM.
4. Store the parameters next to the hash. Cost factors that were fine in 2015
   are not fine now. If the parameters live in the hash string, you can raise
   them and transparently re-hash each user on their next successful login.

We write the result in a PHC-style string:

    $scrypt$n=16384,r=8,p=1$<salt-b64u>$<hash-b64u>

That format is self-describing: a verifier reads the algorithm and cost out
of the stored value rather than assuming today's defaults, which is what makes
rule 4 possible.

Note on hashlib.scrypt: this calls into OpenSSL, so it is fast native code.
We are not reimplementing scrypt itself here -- the memory-hard mixing is the
one place where a pure-Python version would be so slow it teaches the wrong
lesson. Argon2id would be the modern first choice but has no stdlib binding.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, replace
from typing import Union

from ..util.encoding import b64u_encode, b64u_decode
from ..util.ct import constant_time_equals, random_bytes


@dataclass(frozen=True)
class ScryptParams:
    """scrypt cost parameters (RFC 7914).

    n: CPU/memory cost, must be a power of two. Memory used is about
       128 * n * r bytes, so n=16384, r=8 is about 16 MiB per hash.
    r: block size. Raising r raises memory without raising CPU as sharply.
    p: parallelism. Usually 1; raise it only if you want more CPU cost
       without more memory.
    """

    n: int = 1 << 14  # 16384
    r: int = 8
    p: int = 1
    dklen: int = 32
    name: str = "scrypt"

    def encode(self) -> str:
        return f"n={self.n},r={self.r},p={self.p}"

    def derive(self, password: bytes, salt: bytes) -> bytes:
        # maxmem must be raised above OpenSSL's 32 MiB default once n*r grows.
        maxmem = 128 * self.n * self.r * 2 + (1 << 20)
        return hashlib.scrypt(
            password, salt=salt, n=self.n, r=self.r, p=self.p, dklen=self.dklen, maxmem=maxmem
        )


@dataclass(frozen=True)
class Pbkdf2Params:
    """PBKDF2-HMAC cost parameters (RFC 8018).

    PBKDF2 is only CPU-hard, not memory-hard, so a GPU farm gets far better
    value out of it than out of scrypt. It is here because it is what FIPS
    environments and older Java stacks use, and because it makes the "why
    memory hardness matters" comparison concrete.
    """

    iterations: int = 600_000  # OWASP 2023 floor for PBKDF2-HMAC-SHA256
    hash_name: str = "sha256"
    dklen: int = 32
    name: str = "pbkdf2"

    def encode(self) -> str:
        return f"i={self.iterations},h={self.hash_name}"

    def derive(self, password: bytes, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(self.hash_name, password, salt, self.iterations, self.dklen)


Params = Union[ScryptParams, Pbkdf2Params]


@dataclass(frozen=True)
class PasswordHash:
    algorithm: str
    params: str
    salt: bytes
    digest: bytes

    def encode(self) -> str:
        return f"${self.algorithm}${self.params}${b64u_encode(self.salt)}${b64u_encode(self.digest)}"

    def __str__(self) -> str:  # so that print() shows the storable form
        return self.encode()


def parse_hash(encoded: str) -> PasswordHash:
    """Parse a stored hash string back into its parts."""
    if not encoded.startswith("$"):
        raise ValueError("malformed password hash: missing leading $")
    parts = encoded.split("$")
    # parts[0] is the empty string before the first $
    if len(parts) != 5:
        raise ValueError(f"malformed password hash: expected 4 fields, got {len(parts) - 1}")
    _, algorithm, params, salt_b64, digest_b64 = parts
    return PasswordHash(
        algorithm=algorithm,
        params=params,
        salt=b64u_decode(salt_b64),
        digest=b64u_decode(digest_b64),
    )


def _params_from_encoded(algorithm: str, encoded_params: str) -> Params:
    fields = dict(kv.split("=", 1) for kv in encoded_params.split(",") if kv)
    if algorithm == "scrypt":
        return ScryptParams(n=int(fields["n"]), r=int(fields["r"]), p=int(fields["p"]))
    if algorithm == "pbkdf2":
        return Pbkdf2Params(iterations=int(fields["i"]), hash_name=fields["h"])
    raise ValueError(f"unsupported password hash algorithm: {algorithm}")


class PasswordHasher:
    """Hash and verify passwords, with transparent parameter upgrades."""

    def __init__(self, params: Params | None = None, pepper: bytes | None = None) -> None:
        """
        pepper: an optional secret mixed in before hashing, kept OUTSIDE the
        database (env var, KMS, HSM). A stolen database dump alone is then not
        enough to mount an offline attack. The trade-off is that rotating a
        pepper invalidates every stored hash unless you version it, so treat
        it as defence in depth and never as a replacement for a real KDF.
        """
        self.params: Params = params or ScryptParams()
        self.pepper = pepper

    def _prepare(self, password: str) -> bytes:
        # Unicode normalisation matters: the same visible password typed on
        # macOS (NFD) and Windows (NFC) can be different byte strings.
        # NFKC is what PRECIS / RFC 8265 recommends for passwords.
        import unicodedata

        data = unicodedata.normalize("NFKC", password).encode("utf-8")
        if self.pepper:
            # HMAC rather than concatenation: concatenation of a secret and
            # user input in front of a Merkle-Damgard hash is where length
            # extension attacks live.
            data = hmac.new(self.pepper, data, hashlib.sha256).digest()
        return data

    def hash(self, password: str, salt: bytes | None = None) -> str:
        """Hash a password and return the storable string."""
        salt = salt if salt is not None else random_bytes(16)
        digest = self.params.derive(self._prepare(password), salt)
        return PasswordHash(
            algorithm=self.params.name,
            params=self.params.encode(),
            salt=salt,
            digest=digest,
        ).encode()

    def verify(self, password: str, encoded: str) -> bool:
        """Check a password against a stored hash, in constant time."""
        try:
            stored = parse_hash(encoded)
            params = _params_from_encoded(stored.algorithm, stored.params)
        except (ValueError, KeyError):
            return False
        params = replace(params, dklen=len(stored.digest))
        candidate = params.derive(self._prepare(password), stored.salt)
        return constant_time_equals(candidate, stored.digest)

    def needs_rehash(self, encoded: str) -> bool:
        """True if the stored hash uses weaker parameters than we use now.

        Call this after a *successful* verify -- that is the only moment you
        hold the plaintext password and can re-hash it at the new cost.
        """
        try:
            stored = parse_hash(encoded)
        except ValueError:
            return True
        if stored.algorithm != self.params.name:
            return True
        return stored.params != self.params.encode()

    def fake_verify(self, password: str) -> bool:
        """Burn the same time as a real verify, for users that do not exist.

        Without this, "unknown user" returns in microseconds while "wrong
        password" takes ~50ms, and the login endpoint becomes a user
        enumeration oracle. Always returns False.
        """
        self.verify(password, DUMMY_HASH)
        return False


# A precomputed hash of a random string, used by fake_verify. It is generated
# once at import with the default parameters so the timing matches a real
# lookup. If you raise the default cost, this rises with it.
DUMMY_HASH = PasswordHasher().hash("!! account-does-not-exist !!", salt=b"\x00" * 16)
