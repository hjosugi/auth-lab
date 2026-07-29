"""WebAuthn registration and assertion simulator using P-256."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from . import ec
from .util import AuthError, ReplayCache, b64url_decode, b64url_encode, random_token

FLAG_UP = 0x01
FLAG_UV = 0x04


def client_data(kind: str, challenge: str, origin: str) -> bytes:
    return json.dumps(
        {"type": kind, "challenge": challenge, "origin": origin},
        separators=(",", ":"),
    ).encode("utf-8")


def authenticator_data(rp_id: str, *, flags: int, sign_count: int) -> bytes:
    return (
        hashlib.sha256(rp_id.encode()).digest()
        + bytes([flags])
        + sign_count.to_bytes(4, "big")
    )


def parse_authenticator_data(data: bytes) -> tuple[bytes, int, int]:
    if len(data) != 37:
        raise AuthError("invalid authenticatorData length")
    return data[:32], data[32], int.from_bytes(data[33:], "big")


@dataclass
class Authenticator:
    credential_id: str = field(default_factory=lambda: random_token(20))
    private_key: int = field(init=False)
    public_key: tuple[int, int] = field(init=False)
    sign_count: int = 0

    def __post_init__(self) -> None:
        self.private_key, self.public_key = ec.generate_keypair()

    def registration(self, challenge: str, *, origin: str, rp_id: str) -> dict[str, object]:
        client = client_data("webauthn.create", challenge, origin)
        auth_data = authenticator_data(rp_id, flags=FLAG_UP | FLAG_UV, sign_count=0)
        return {
            "credential_id": self.credential_id,
            "public_key": self.public_key,
            "client_data_json": client,
            "authenticator_data": auth_data,
        }

    def assertion(self, challenge: str, *, origin: str, rp_id: str) -> dict[str, object]:
        self.sign_count += 1
        client = client_data("webauthn.get", challenge, origin)
        auth_data = authenticator_data(
            rp_id,
            flags=FLAG_UP | FLAG_UV,
            sign_count=self.sign_count,
        )
        message = auth_data + hashlib.sha256(client).digest()
        signature = ec.sign(self.private_key, message)
        return {
            "credential_id": self.credential_id,
            "client_data_json": client,
            "authenticator_data": auth_data,
            "signature": signature,
        }


@dataclass
class Credential:
    user: str
    public_key: tuple[int, int]
    sign_count: int


@dataclass
class WebAuthnServer:
    rp_id: str
    origin: str
    credentials: dict[str, Credential] = field(default_factory=dict)
    registration_challenges: dict[str, str] = field(default_factory=dict)
    authentication_challenges: dict[str, str] = field(default_factory=dict)
    replay_cache: ReplayCache = field(default_factory=ReplayCache)

    def begin_registration(self, user: str) -> str:
        challenge = random_token()
        self.registration_challenges[user] = challenge
        return challenge

    def finish_registration(
        self,
        user: str,
        response: dict[str, object],
    ) -> str:
        expected = self.registration_challenges.pop(user, None)
        if expected is None:
            raise AuthError("registration ceremony was not started")
        credential_id = response.get("credential_id")
        public_key = response.get("public_key")
        client_raw = response.get("client_data_json")
        auth_raw = response.get("authenticator_data")
        if not isinstance(credential_id, str) or credential_id in self.credentials:
            raise AuthError("duplicate or invalid credential ID")
        if (
            not isinstance(public_key, tuple)
            or len(public_key) != 2
            or not ec.is_on_curve(public_key)
            or not isinstance(client_raw, bytes)
            or not isinstance(auth_raw, bytes)
        ):
            raise AuthError("malformed registration response")
        client = json.loads(client_raw)
        if (
            client.get("type") != "webauthn.create"
            or client.get("challenge") != expected
            or client.get("origin") != self.origin
        ):
            raise AuthError("registration clientData mismatch")
        rp_hash, flags, count = parse_authenticator_data(auth_raw)
        if rp_hash != hashlib.sha256(self.rp_id.encode()).digest():
            raise AuthError("rpIdHash mismatch")
        if flags & (FLAG_UP | FLAG_UV) != FLAG_UP | FLAG_UV:
            raise AuthError("user presence and verification are required")
        self.credentials[credential_id] = Credential(user, public_key, count)
        return credential_id

    def begin_authentication(self, user: str) -> str:
        challenge = random_token()
        self.authentication_challenges[user] = challenge
        return challenge

    def finish_authentication(
        self,
        user: str,
        response: dict[str, object],
    ) -> bool:
        expected = self.authentication_challenges.pop(user, None)
        if expected is None:
            raise AuthError("authentication ceremony was not started")
        credential_id = response.get("credential_id")
        client_raw = response.get("client_data_json")
        auth_raw = response.get("authenticator_data")
        signature = response.get("signature")
        if (
            not isinstance(credential_id, str)
            or credential_id not in self.credentials
            or not isinstance(client_raw, bytes)
            or not isinstance(auth_raw, bytes)
            or not isinstance(signature, tuple)
        ):
            raise AuthError("malformed assertion")
        credential = self.credentials[credential_id]
        if credential.user != user:
            raise AuthError("credential belongs to another user")
        client = json.loads(client_raw)
        if (
            client.get("type") != "webauthn.get"
            or client.get("challenge") != expected
            or client.get("origin") != self.origin
        ):
            raise AuthError("assertion clientData mismatch")
        rp_hash, flags, sign_count = parse_authenticator_data(auth_raw)
        if rp_hash != hashlib.sha256(self.rp_id.encode()).digest():
            raise AuthError("rpIdHash mismatch")
        if flags & (FLAG_UP | FLAG_UV) != FLAG_UP | FLAG_UV:
            raise AuthError("user presence and verification are required")
        if credential.sign_count and sign_count <= credential.sign_count:
            raise AuthError("sign counter rollback; cloned authenticator suspected")
        message = auth_raw + hashlib.sha256(client_raw).digest()
        if not ec.verify(credential.public_key, message, signature):
            raise AuthError("invalid assertion signature")
        credential.sign_count = sign_count
        self.replay_cache.consume(
            b64url_encode(hashlib.sha256(message).digest()),
            expires_at=2**31,
            now=0,
        )
        return True

