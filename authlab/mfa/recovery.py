"""Recovery codes: the backup factor everyone forgets to design.

A recovery code is a bearer credential that bypasses MFA, so it deserves the
same treatment as a password:

* generated with a CSPRNG, never a counter or a timestamp
* stored hashed, never in plaintext (a support engineer must not be able to
  read them out of the database)
* single use -- consumed on success, never reusable
* shown to the user exactly once, at enrolment

Because they are high entropy (we use 80 bits) they do not need a slow KDF
the way a human-chosen password does; a single SHA-256 with a salt is enough,
since there is no dictionary to grind through. We still salt so that two users
who somehow got the same code do not share a stored value.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from ..util.ct import constant_time_equals, random_bytes

# Crockford-ish base32: no I, L, O, U -- removes the 1/l/I and 0/O confusions
# when someone reads a code off paper, and dropping U avoids accidental words.
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _format_code(raw: bytes) -> str:
    """Render 10 random bytes as two groups of 5 characters."""
    value = int.from_bytes(raw, "big")
    chars = []
    for _ in range(10):
        chars.append(_ALPHABET[value % 32])
        value //= 32
    text = "".join(chars)
    return f"{text[:5]}-{text[5:]}"


def _normalise(code: str) -> str:
    return code.strip().upper().replace("-", "").replace(" ", "")


@dataclass
class RecoveryCodes:
    """A set of single-use recovery codes, stored as salted hashes."""

    # list of (salt, digest); the plaintext codes exist only in the return
    # value of generate() and are never retained.
    hashes: list[tuple[bytes, bytes]] = field(default_factory=list)
    used: set[int] = field(default_factory=set)

    @classmethod
    def generate(cls, count: int = 10) -> tuple["RecoveryCodes", list[str]]:
        """Create `count` codes. Returns (store, plaintext_codes)."""
        store = cls()
        plaintext = []
        for _ in range(count):
            code = _format_code(random_bytes(10))  # 80 bits
            plaintext.append(code)
            salt = random_bytes(16)
            store.hashes.append((salt, cls._digest(salt, code)))
        return store, plaintext

    @staticmethod
    def _digest(salt: bytes, code: str) -> bytes:
        return hashlib.sha256(salt + _normalise(code).encode("ascii")).digest()

    def consume(self, code: str) -> bool:
        """Check a code and burn it. Returns False if wrong or already used."""
        matched = False
        # Scan every entry even after a match so the timing does not reveal
        # which slot a code lives in.
        for index, (salt, digest) in enumerate(self.hashes):
            if constant_time_equals(self._digest(salt, code), digest) and index not in self.used:
                if not matched:
                    self.used.add(index)
                    matched = True
        return matched

    @property
    def remaining(self) -> int:
        return len(self.hashes) - len(self.used)
