"""Password hashing with self-describing scrypt and PBKDF2 records."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field

from .util import AuthError, b64url_decode, b64url_encode, secure_equal


def hash_password(
    password: str,
    *,
    algorithm: str = "scrypt",
    salt: bytes | None = None,
) -> str:
    if len(password) < 8:
        raise AuthError("password must contain at least 8 characters")
    actual_salt = secrets.token_bytes(16) if salt is None else salt
    password_bytes = password.encode("utf-8")
    if algorithm == "scrypt":
        n, r, p, length = 2**14, 8, 1, 32
        digest = hashlib.scrypt(
            password_bytes,
            salt=actual_salt,
            n=n,
            r=r,
            p=p,
            dklen=length,
        )
        params = f"n={n},r={r},p={p},l={length}"
    elif algorithm == "pbkdf2-sha256":
        iterations, length = 600_000, 32
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password_bytes,
            actual_salt,
            iterations,
            dklen=length,
        )
        params = f"i={iterations},l={length}"
    else:
        raise AuthError("unsupported password algorithm")
    return "$".join(
        [algorithm, params, b64url_encode(actual_salt), b64url_encode(digest)]
    )


def verify_password(password: str, record: str) -> bool:
    try:
        algorithm, params_text, salt_text, digest_text = record.split("$")
        params = dict(part.split("=", 1) for part in params_text.split(","))
        salt = b64url_decode(salt_text)
        expected = b64url_decode(digest_text)
        if algorithm == "scrypt":
            actual = hashlib.scrypt(
                password.encode(),
                salt=salt,
                n=int(params["n"]),
                r=int(params["r"]),
                p=int(params["p"]),
                dklen=int(params["l"]),
            )
        elif algorithm == "pbkdf2-sha256":
            actual = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode(),
                salt,
                int(params["i"]),
                dklen=int(params["l"]),
            )
        else:
            return False
    except (ValueError, KeyError, TypeError):
        return False
    return secure_equal(actual, expected)


@dataclass
class PasswordStore:
    """Tiny user store with a dummy record for user-enumeration resistance."""

    users: dict[str, str] = field(default_factory=dict)
    dummy_record: str = field(
        default_factory=lambda: hash_password(
            "not-a-real-password",
            salt=b"\x00" * 16,
        )
    )

    def register(self, username: str, password: str) -> None:
        key = username.casefold()
        if key in self.users:
            raise AuthError("user already exists")
        self.users[key] = hash_password(password)

    def authenticate(self, username: str, password: str) -> bool:
        key = username.casefold()
        record = self.users.get(key, self.dummy_record)
        valid = verify_password(password, record)
        return valid and key in self.users

