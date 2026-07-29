"""Readable Kerberos-style AS, TGS, and service-ticket exchange."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field
from typing import Any

from .util import (
    AuthError,
    ReplayCache,
    b64url_decode,
    b64url_encode,
    canonical_json,
    random_token,
    secure_equal,
)


def derive_key(password: str, salt: bytes = b"AUTHLAB.KERBEROS") -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000, dklen=32)


def _stream(key: bytes, nonce: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hmac.new(key, b"stream" + nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        )
        counter += 1
    return bytes(output[:length])


def seal(key: bytes, value: dict[str, Any]) -> str:
    nonce = secrets.token_bytes(16)
    plain = canonical_json(value)
    cipher = bytes(a ^ b for a, b in zip(plain, _stream(key, nonce, len(plain)), strict=True))
    tag = hmac.new(key, b"tag" + nonce + cipher, hashlib.sha256).digest()
    return b64url_encode(nonce + cipher + tag)


def unseal(key: bytes, token: str) -> dict[str, Any]:
    raw = b64url_decode(token)
    if len(raw) < 49:
        raise AuthError("invalid Kerberos container")
    nonce, cipher, tag = raw[:16], raw[16:-32], raw[-32:]
    expected = hmac.new(key, b"tag" + nonce + cipher, hashlib.sha256).digest()
    if not secure_equal(tag, expected):
        raise AuthError("Kerberos container integrity failed")
    plain = bytes(a ^ b for a, b in zip(cipher, _stream(key, nonce, len(cipher)), strict=True))
    try:
        value = json.loads(plain)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthError("invalid Kerberos payload") from exc
    if not isinstance(value, dict):
        raise AuthError("invalid Kerberos payload type")
    return value


@dataclass
class KDC:
    realm: str
    user_keys: dict[str, bytes]
    service_keys: dict[str, bytes]
    tgs_key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    replay_cache: ReplayCache = field(default_factory=ReplayCache)

    def as_exchange(self, user: str, timestamp: int, proof: str) -> dict[str, str]:
        key = self.user_keys.get(user)
        if key is None:
            raise AuthError("unknown Kerberos principal")
        expected = hmac.new(
            key,
            f"AS_REQ|{user}|{timestamp}".encode(),
            hashlib.sha256,
        ).hexdigest()
        if not secure_equal(proof, expected):
            raise AuthError("pre-authentication failed")
        session_key = secrets.token_bytes(32)
        expires = timestamp + 8 * 60 * 60
        tgt = seal(
            self.tgs_key,
            {
                "client": user,
                "realm": self.realm,
                "session_key": b64url_encode(session_key),
                "exp": expires,
                "ticket_id": random_token(12),
            },
        )
        client_part = seal(
            key,
            {
                "session_key": b64url_encode(session_key),
                "exp": expires,
                "tgs": f"krbtgt/{self.realm}",
            },
        )
        return {"tgt": tgt, "client_part": client_part}

    def tgs_exchange(
        self,
        tgt: str,
        service: str,
        authenticator: str,
        *,
        now: int,
    ) -> dict[str, str]:
        tgt_data = unseal(self.tgs_key, tgt)
        if tgt_data.get("exp", 0) <= now:
            raise AuthError("TGT expired")
        session_key = b64url_decode(str(tgt_data["session_key"]))
        auth = unseal(session_key, authenticator)
        if auth.get("client") != tgt_data.get("client"):
            raise AuthError("authenticator principal mismatch")
        timestamp = int(auth.get("timestamp", 0))
        if abs(now - timestamp) > 300:
            raise AuthError("Kerberos clock skew exceeded")
        self.replay_cache.consume(
            f"{auth.get('client')}:{auth.get('nonce')}:{timestamp}",
            now + 301,
            now,
        )
        service_key = self.service_keys.get(service)
        if service_key is None:
            raise AuthError("unknown Kerberos service")
        service_session = secrets.token_bytes(32)
        expires = min(int(tgt_data["exp"]), now + 60 * 60)
        ticket = seal(
            service_key,
            {
                "client": tgt_data["client"],
                "service": service,
                "session_key": b64url_encode(service_session),
                "exp": expires,
                "ticket_id": random_token(12),
            },
        )
        client_part = seal(
            session_key,
            {
                "service": service,
                "session_key": b64url_encode(service_session),
                "exp": expires,
            },
        )
        return {"ticket": ticket, "client_part": client_part}


@dataclass
class KerberosService:
    principal: str
    key: bytes
    replay_cache: ReplayCache = field(default_factory=ReplayCache)

    def accept(self, ticket: str, authenticator: str, *, now: int) -> dict[str, Any]:
        ticket_data = unseal(self.key, ticket)
        if ticket_data.get("service") != self.principal or ticket_data.get("exp", 0) <= now:
            raise AuthError("service ticket binding failed")
        session_key = b64url_decode(str(ticket_data["session_key"]))
        auth = unseal(session_key, authenticator)
        if auth.get("client") != ticket_data.get("client"):
            raise AuthError("service authenticator principal mismatch")
        timestamp = int(auth.get("timestamp", 0))
        if abs(now - timestamp) > 300:
            raise AuthError("service authenticator clock skew exceeded")
        self.replay_cache.consume(
            f"{ticket_data.get('ticket_id')}:{auth.get('nonce')}:{timestamp}",
            now + 301,
            now,
        )
        return {
            "client": ticket_data["client"],
            "mutual_authenticator": seal(session_key, {"timestamp": timestamp + 1}),
        }


def preauth_proof(user_key: bytes, user: str, timestamp: int) -> str:
    return hmac.new(
        user_key,
        f"AS_REQ|{user}|{timestamp}".encode(),
        hashlib.sha256,
    ).hexdigest()


def authenticator(session_key: bytes, user: str, timestamp: int) -> str:
    return seal(
        session_key,
        {"client": user, "timestamp": timestamp, "nonce": random_token(8)},
    )

