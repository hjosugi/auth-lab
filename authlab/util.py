"""Shared encoding, time, and replay-protection helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any


class AuthError(ValueError):
    """Raised when an authentication or authorization check fails."""


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    if not isinstance(value, str):
        raise AuthError("base64url input must be text")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except Exception as exc:  # binascii exceptions vary by Python version
        raise AuthError("invalid base64url value") from exc


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def json_from_bytes(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthError("invalid JSON") from exc
    if not isinstance(value, dict):
        raise AuthError("JSON value must be an object")
    return value


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def secure_equal(left: bytes | str, right: bytes | str) -> bool:
    if isinstance(left, str):
        left = left.encode("utf-8")
    if isinstance(right, str):
        right = right.encode("utf-8")
    return hmac.compare_digest(left, right)


def random_token(size: int = 32) -> str:
    return b64url_encode(secrets.token_bytes(size))


def unix_time() -> int:
    return int(time.time())


@dataclass
class ReplayCache:
    """Single-process replay cache used by the protocol simulators."""

    entries: dict[str, int] = field(default_factory=dict)

    def consume(self, key: str, expires_at: int, now: int | None = None) -> None:
        current = unix_time() if now is None else now
        self.entries = {item: exp for item, exp in self.entries.items() if exp > current}
        if key in self.entries:
            raise AuthError("replay detected")
        if expires_at <= current:
            raise AuthError("message already expired")
        self.entries[key] = expires_at

