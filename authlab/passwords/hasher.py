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
    $argon2id$v=19$m=19456,t=2,p=1$<salt-b64u>$<hash-b64u>

That format is self-describing: a verifier reads the algorithm and cost out
of the stored value rather than assuming today's defaults, which is what makes
rule 4 possible. Argon2 adds one field, `v=`, because the algorithm changed
incompatibly between 1.0 and 1.3 and a stored hash has to say which it is.

Which one to pick:

    Argon2id  first choice. Memory-hard and side-channel aware.
    scrypt    fine. Memory-hard, older, and available from OpenSSL everywhere.
    PBKDF2    only if a compliance regime forces it. CPU-hard only, so a GPU
              farm gets far more value out of it than out of the other two.

Note on hashlib.scrypt: this calls into OpenSSL, so it is fast native code.
We are not reimplementing scrypt itself here -- the memory-hard mixing is the
one place where a pure-Python version would be so slow it teaches the wrong
lesson. Argon2id has no stdlib binding at all, so `authlab/passwords/argon2.py`
implements it from the RFC for reading, and this module prefers the
`argon2-cffi` binding whenever it is installed. See ARGON2 below.

"Constant-time verification" in this module means that the final stored and
candidate digests are compared with `hmac.compare_digest`. The educational
pure-Python Argon2 implementation and Python's surrounding control flow are
not constant time. `fake_verify` separately equalises the KDF work for unknown
and known user names; those are related timing defences, not the same claim.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, replace
from typing import Union

from . import argon2 as argon2_pure
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


def _argon2_backend() -> str:
    """Which Argon2 implementation is available: 'cffi' or 'pure'."""
    try:
        import argon2 as _argon2_cffi  # noqa: F401  (the pip package argon2-cffi)

        return "cffi"
    except ImportError:
        return "pure"


ARGON2_BACKEND = _argon2_backend()

# OWASP's minimum Argon2id configuration: 19 MiB, t=2, p=1. RFC 9106's
# memory-constrained recommendation is a different profile (64 MiB, t=3,
# p=4). This default is still far past what the pure-Python implementation
# will run, which is the intended message: read that module, then install a
# binding.
ARGON2_VARIANTS = {"argon2id": argon2_pure.TYPE_ID,
                   "argon2i": argon2_pure.TYPE_I,
                   "argon2d": argon2_pure.TYPE_D}
ARGON2_CFFI_TYPE_NAMES = {
    "argon2id": "ID",
    "argon2i": "I",
    "argon2d": "D",
}


@dataclass(frozen=True)
class Argon2Params:
    """Argon2 cost parameters (RFC 9106).

    memory_cost is in KiB and is the parameter that matters: it is the one an
    attacker cannot buy their way around with more cores. time_cost is the
    number of passes over that memory; parallelism is how many independent
    lanes fill it.

    The defaults are OWASP's minimum Argon2id configuration. The RFC 9106
    low-memory recommendation is 64 MiB, t=3, p=4. The from-scratch
    implementation in `authlab/passwords/argon2.py` refuses either production
    profile: pure Python needs minutes at those sizes. Use
    `Argon2Params.teaching()` to run the real algorithm at toy cost, or install
    `argon2-cffi` to run production parameters.
    """

    time_cost: int = 2
    memory_cost: int = 19456   # KiB
    parallelism: int = 1
    dklen: int = 32
    variant: str = "argon2id"
    version: int = argon2_pure.VERSION

    @property
    def name(self) -> str:
        return self.variant

    @classmethod
    def teaching(cls, **overrides) -> "Argon2Params":
        """Cost settings small enough for pure Python. NOT SAFE TO STORE.

        64 KiB and two passes is roughly 300x cheaper than the RFC floor. It
        exercises every code path -- both indexing modes, multi-pass XOR, the
        final lane merge -- and protects nothing.
        """
        return cls(**{"time_cost": 2, "memory_cost": 64, "parallelism": 1, **overrides})

    @property
    def is_production_strength(self) -> bool:
        return self.memory_cost >= 19456 and self.time_cost >= 2

    def encode(self) -> str:
        return f"m={self.memory_cost},t={self.time_cost},p={self.parallelism}"

    def derive(self, password: bytes, salt: bytes) -> bytes:
        if ARGON2_BACKEND == "cffi":
            import argon2 as argon2_cffi

            try:
                return argon2_cffi.low_level.hash_secret_raw(
                    secret=password,
                    salt=salt,
                    time_cost=self.time_cost,
                    memory_cost=self.memory_cost,
                    parallelism=self.parallelism,
                    hash_len=self.dklen,
                    type=argon2_cffi.low_level.Type[
                        ARGON2_CFFI_TYPE_NAMES[self.variant]
                    ],
                    version=self.version,
                )
            except Exception as exc:  # native binding exposes its own exception hierarchy
                raise ValueError(f"argon2-cffi rejected the requested parameters: {exc}") from exc
        if self.version != argon2_pure.VERSION:
            raise ValueError(
                f"the from-scratch Argon2 implements version 0x13 only, got 0x{self.version:02x}"
            )
        return argon2_pure.argon2(
            password,
            salt,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            tag_length=self.dklen,
            variant=ARGON2_VARIANTS[self.variant],
        )


Params = Union[ScryptParams, Pbkdf2Params, Argon2Params]


@dataclass(frozen=True)
class PasswordHash:
    algorithm: str
    params: str
    salt: bytes
    digest: bytes
    # Argon2 alone carries a version field, because 1.0 and 1.3 produce
    # different tags from the same inputs and a stored hash must say which.
    version: int | None = None

    def encode(self) -> str:
        version = f"v={self.version}$" if self.version is not None else ""
        return (
            f"${self.algorithm}${version}{self.params}"
            f"${b64u_encode(self.salt)}${b64u_encode(self.digest)}"
        )

    def __str__(self) -> str:  # so that print() shows the storable form
        return self.encode()


def parse_hash(encoded: str) -> PasswordHash:
    """Parse a stored hash string back into its parts.

    Two shapes are accepted, differing only by the optional `v=` field:

        $scrypt$n=16384,r=8,p=1$salt$hash
        $argon2id$v=19$m=19456,t=2,p=1$salt$hash

    One deliberate deviation from the PHC string format: the salt and digest
    are base64url (`-_`), matching the rest of this lab, where PHC specifies
    standard base64 (`+/`). These strings are therefore readable by this
    module and not by argon2-cffi's `verify_secret`. Real deployments should
    keep the standard alphabet.
    """
    if not encoded.startswith("$"):
        raise ValueError("malformed password hash: missing leading $")
    parts = encoded.split("$")
    # parts[0] is the empty string before the first $
    version: int | None = None
    if len(parts) == 6 and parts[2].startswith("v="):
        _, algorithm, version_field, params, salt_b64, digest_b64 = parts
        try:
            version = int(version_field[2:])
        except ValueError as exc:
            raise ValueError(f"malformed version field: {version_field!r}") from exc
    elif len(parts) == 5:
        _, algorithm, params, salt_b64, digest_b64 = parts
    else:
        raise ValueError(f"malformed password hash: unexpected field count {len(parts) - 1}")
    if version is not None and algorithm not in ARGON2_VARIANTS:
        raise ValueError(f"version field is only valid for Argon2, not {algorithm!r}")
    return PasswordHash(
        algorithm=algorithm,
        params=params,
        salt=b64u_decode(salt_b64),
        digest=b64u_decode(digest_b64),
        version=version,
    )


def _params_from_encoded(
    algorithm: str, encoded_params: str, version: int | None = None
) -> Params:
    fields = dict(kv.split("=", 1) for kv in encoded_params.split(",") if kv)
    if algorithm == "scrypt":
        return ScryptParams(n=int(fields["n"]), r=int(fields["r"]), p=int(fields["p"]))
    if algorithm == "pbkdf2":
        return Pbkdf2Params(iterations=int(fields["i"]), hash_name=fields["h"])
    if algorithm in ARGON2_VARIANTS:
        if version is None:
            raise ValueError("Argon2 hashes must carry a v= field")
        return Argon2Params(
            memory_cost=int(fields["m"]),
            time_cost=int(fields["t"]),
            parallelism=int(fields["p"]),
            variant=algorithm,
            version=version,
        )
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
            version=getattr(self.params, "version", None),
        ).encode()

    def verify(self, password: str, encoded: str) -> bool:
        """Check a password and compare the resulting digest in constant time.

        The algorithm and cost come from the *stored* value, not from
        `self.params`. That is what lets one hasher verify hashes written
        years ago at other settings -- and it is why `needs_rehash` exists.

        Only the final digest comparison is constant time. The educational
        pure-Python primitives are explicitly not constant-time implementations.
        """
        try:
            stored = parse_hash(encoded)
            params = _params_from_encoded(stored.algorithm, stored.params, stored.version)
        except (ValueError, KeyError):
            return False
        params = replace(params, dklen=len(stored.digest))
        try:
            candidate = params.derive(self._prepare(password), stored.salt)
        except ValueError:
            # An unsupported cost (for example an Argon2 hash written by a
            # real deployment, being verified by the pure-Python backend) is a
            # failure to verify, not a crash on the login path.
            return False
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
        if stored.version != getattr(self.params, "version", None):
            return True
        return stored.params != self.params.encode()

    def fake_verify(self, password: str) -> bool:
        """Burn the same time as a real verify, for users that do not exist.

        Without this, "unknown user" returns in microseconds while "wrong
        password" takes ~50ms, and the login endpoint becomes a user
        enumeration oracle. Always returns False.
        """
        # The dummy must use *this hasher's* algorithm and cost. Reusing the
        # module's default scrypt hash for an Argon2id login endpoint would
        # bring the user-enumeration timing oracle straight back.
        if self.params == ScryptParams():
            dummy = DUMMY_HASH
        else:
            dummy = PasswordHash(
                algorithm=self.params.name,
                params=self.params.encode(),
                salt=b"\x00" * 16,
                digest=b"\x00" * self.params.dklen,
                version=getattr(self.params, "version", None),
            ).encode()
        self.verify(password, dummy)
        return False


# A precomputed hash of a random string, used by fake_verify. It is generated
# once at import with the default parameters so the timing matches a real
# lookup. If you raise the default cost, this rises with it.
DUMMY_HASH = PasswordHasher().hash("!! account-does-not-exist !!", salt=b"\x00" * 16)
