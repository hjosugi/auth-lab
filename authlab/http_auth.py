"""HTTP Basic, Bearer, API key, and HMAC request-signing examples."""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass, field

from .util import AuthError, ReplayCache, secure_equal


def basic_header(username: str, password: str) -> str:
    if ":" in username:
        raise AuthError("Basic username cannot contain a colon")
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {encoded}"


def parse_basic(header: str) -> tuple[str, str]:
    if not header.startswith("Basic "):
        raise AuthError("not an HTTP Basic credential")
    try:
        raw = base64.b64decode(header[6:], validate=True).decode()
        username, password = raw.split(":", 1)
    except (ValueError, UnicodeDecodeError) as exc:
        raise AuthError("invalid HTTP Basic credential") from exc
    return username, password


def bearer_header(token: str) -> str:
    if not token or any(char.isspace() for char in token):
        raise AuthError("invalid bearer token")
    return f"Bearer {token}"


def canonical_request(
    method: str,
    path: str,
    body: bytes,
    timestamp: int,
    nonce: str,
) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join(
        [method.upper(), path, body_hash, str(timestamp), nonce]
    ).encode()


def sign_request(
    secret: bytes,
    *,
    method: str,
    path: str,
    body: bytes,
    timestamp: int,
    nonce: str,
) -> str:
    return hmac.new(
        secret,
        canonical_request(method, path, body, timestamp, nonce),
        hashlib.sha256,
    ).hexdigest()


@dataclass
class HMACRequestVerifier:
    replay_cache: ReplayCache = field(default_factory=ReplayCache)
    max_skew: int = 300

    def verify(
        self,
        secret: bytes,
        signature: str,
        *,
        method: str,
        path: str,
        body: bytes,
        timestamp: int,
        nonce: str,
        now: int,
    ) -> None:
        if abs(now - timestamp) > self.max_skew:
            raise AuthError("request timestamp outside accepted window")
        expected = sign_request(
            secret,
            method=method,
            path=path,
            body=body,
            timestamp=timestamp,
            nonce=nonce,
        )
        if not secure_equal(signature, expected):
            raise AuthError("invalid request signature")
        self.replay_cache.consume(
            f"{timestamp}:{nonce}",
            timestamp + self.max_skew + 1,
            now,
        )

