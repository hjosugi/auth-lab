"""In-memory OAuth 2.0 and OpenID Connect authorization server lab."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from .jose import sign_jwt
from .util import AuthError, b64url_encode, random_token, secure_equal, unix_time


class OAuthError(AuthError):
    def __init__(self, error: str, description: str):
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description


@dataclass(frozen=True)
class Client:
    client_id: str
    redirect_uris: tuple[str, ...] = ()
    secret: str | None = None
    public: bool = True
    allowed_scopes: frozenset[str] = frozenset({"openid", "profile"})


@dataclass
class AuthorizationCode:
    client_id: str
    redirect_uri: str
    user: str
    scope: tuple[str, ...]
    challenge: str
    nonce: str | None
    expires_at: int
    used: bool = False
    token_family: str | None = None


@dataclass
class TokenRecord:
    client_id: str
    subject: str
    scope: tuple[str, ...]
    token_type: str
    expires_at: int
    family: str
    active: bool = True
    used: bool = False


@dataclass
class DeviceGrant:
    client_id: str
    scope: tuple[str, ...]
    user_code: str
    expires_at: int
    interval: int
    subject: str | None = None
    approved: bool = False
    last_poll: int | None = None


@dataclass
class AuthorizationServer:
    issuer: str = "https://as.example.test"
    signing_key: bytes = b"local-oidc-signing-key-change-me"
    clients: dict[str, Client] = field(default_factory=dict)
    codes: dict[str, AuthorizationCode] = field(default_factory=dict)
    tokens: dict[str, TokenRecord] = field(default_factory=dict)
    devices: dict[str, DeviceGrant] = field(default_factory=dict)

    def register_client(self, client: Client) -> None:
        if client.client_id in self.clients:
            raise OAuthError("invalid_client", "client already registered")
        self.clients[client.client_id] = client

    def _client(self, client_id: str) -> Client:
        try:
            return self.clients[client_id]
        except KeyError as exc:
            raise OAuthError("invalid_client", "unknown client") from exc

    @staticmethod
    def pkce_challenge(verifier: str) -> str:
        if not 43 <= len(verifier) <= 128:
            raise OAuthError("invalid_request", "PKCE verifier length is invalid")
        return b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())

    def authorize(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        user: str,
        scope: str,
        state: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
        nonce: str | None = None,
        now: int | None = None,
    ) -> dict[str, str]:
        client = self._client(client_id)
        if redirect_uri not in client.redirect_uris:
            raise OAuthError("invalid_request", "redirect_uri must match exactly")
        if not state:
            raise OAuthError("invalid_request", "state is required")
        if code_challenge_method != "S256" or not code_challenge:
            raise OAuthError("invalid_request", "PKCE S256 is required")
        scopes = tuple(dict.fromkeys(scope.split()))
        if not set(scopes) <= client.allowed_scopes:
            raise OAuthError("invalid_scope", "scope is not allowed")
        current = unix_time() if now is None else now
        code = random_token()
        self.codes[code] = AuthorizationCode(
            client_id,
            redirect_uri,
            user,
            scopes,
            code_challenge,
            nonce,
            current + 120,
        )
        return {"code": code, "state": state}

    def _new_token_pair(
        self,
        *,
        client_id: str,
        subject: str,
        scope: tuple[str, ...],
        family: str | None,
        now: int,
        nonce: str | None = None,
        include_id_token: bool = False,
    ) -> dict[str, Any]:
        actual_family = random_token(12) if family is None else family
        access = random_token()
        refresh = random_token()
        self.tokens[access] = TokenRecord(
            client_id,
            subject,
            scope,
            "access_token",
            now + 600,
            actual_family,
        )
        self.tokens[refresh] = TokenRecord(
            client_id,
            subject,
            scope,
            "refresh_token",
            now + 86_400,
            actual_family,
        )
        response: dict[str, Any] = {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": 600,
            "refresh_token": refresh,
            "scope": " ".join(scope),
        }
        if include_id_token:
            claims = {
                "iss": self.issuer,
                "sub": subject,
                "aud": client_id,
                "iat": now,
                "exp": now + 300,
                "nonce": nonce,
                "amr": ["pwd", "otp", "mfa"],
                "jti": random_token(12),
            }
            response["id_token"] = sign_jwt(
                claims,
                self.signing_key,
                algorithm="HS256",
                kid="oidc-lab",
            )
        return response

    def exchange_code(
        self,
        *,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        current = unix_time() if now is None else now
        record = self.codes.get(code)
        if record is None:
            raise OAuthError("invalid_grant", "unknown authorization code")
        if record.used:
            if record.token_family:
                self._revoke_family(record.token_family)
            raise OAuthError("invalid_grant", "code replay detected; token family revoked")
        record.used = True
        if record.expires_at <= current:
            raise OAuthError("invalid_grant", "authorization code expired")
        if record.client_id != client_id or record.redirect_uri != redirect_uri:
            raise OAuthError("invalid_grant", "code binding mismatch")
        challenge = self.pkce_challenge(code_verifier)
        if not secure_equal(challenge, record.challenge):
            raise OAuthError("invalid_grant", "PKCE verification failed")
        response = self._new_token_pair(
            client_id=client_id,
            subject=record.user,
            scope=record.scope,
            family=None,
            now=current,
            nonce=record.nonce,
            include_id_token="openid" in record.scope,
        )
        record.token_family = self.tokens[response["access_token"]].family
        return response

    def refresh(
        self,
        refresh_token: str,
        *,
        client_id: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        current = unix_time() if now is None else now
        record = self.tokens.get(refresh_token)
        if record is None or record.token_type != "refresh_token":
            raise OAuthError("invalid_grant", "unknown refresh token")
        if record.used:
            self._revoke_family(record.family)
            raise OAuthError("invalid_grant", "refresh token reuse detected")
        if not record.active or record.expires_at <= current or record.client_id != client_id:
            raise OAuthError("invalid_grant", "refresh token is inactive")
        record.used = True
        record.active = False
        return self._new_token_pair(
            client_id=record.client_id,
            subject=record.subject,
            scope=record.scope,
            family=record.family,
            now=current,
        )

    def client_credentials(
        self,
        *,
        client_id: str,
        client_secret: str,
        scope: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        client = self._client(client_id)
        if client.public or client.secret is None or not secure_equal(
            client.secret,
            client_secret,
        ):
            raise OAuthError("invalid_client", "client authentication failed")
        scopes = tuple(dict.fromkeys(scope.split()))
        if not set(scopes) <= client.allowed_scopes:
            raise OAuthError("invalid_scope", "scope is not allowed")
        current = unix_time() if now is None else now
        response = self._new_token_pair(
            client_id=client_id,
            subject=client_id,
            scope=scopes,
            family=None,
            now=current,
        )
        refresh = response.pop("refresh_token")
        del self.tokens[refresh]
        return response

    def device_authorize(
        self,
        *,
        client_id: str,
        scope: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        client = self._client(client_id)
        scopes = tuple(dict.fromkeys(scope.split()))
        if not set(scopes) <= client.allowed_scopes:
            raise OAuthError("invalid_scope", "scope is not allowed")
        current = unix_time() if now is None else now
        device_code = random_token()
        user_code = random_token(6)[:8].upper()
        self.devices[device_code] = DeviceGrant(
            client_id,
            scopes,
            user_code,
            current + 600,
            5,
        )
        return {
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": f"{self.issuer}/device",
            "expires_in": 600,
            "interval": 5,
        }

    def approve_device(self, user_code: str, subject: str) -> None:
        grant = next(
            (item for item in self.devices.values() if item.user_code == user_code),
            None,
        )
        if grant is None:
            raise OAuthError("invalid_request", "unknown user code")
        grant.subject = subject
        grant.approved = True

    def poll_device(
        self,
        device_code: str,
        *,
        client_id: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        current = unix_time() if now is None else now
        grant = self.devices.get(device_code)
        if grant is None or grant.client_id != client_id:
            raise OAuthError("invalid_grant", "unknown device code")
        if grant.expires_at <= current:
            raise OAuthError("expired_token", "device code expired")
        if grant.last_poll is not None and current - grant.last_poll < grant.interval:
            grant.interval += 5
            raise OAuthError("slow_down", "polling too quickly")
        grant.last_poll = current
        if not grant.approved or grant.subject is None:
            raise OAuthError("authorization_pending", "user has not approved yet")
        del self.devices[device_code]
        return self._new_token_pair(
            client_id=client_id,
            subject=grant.subject,
            scope=grant.scope,
            family=None,
            now=current,
            include_id_token="openid" in grant.scope,
        )

    def introspect(self, token: str, *, now: int | None = None) -> dict[str, Any]:
        current = unix_time() if now is None else now
        record = self.tokens.get(token)
        if record is None or not record.active or record.expires_at <= current:
            return {"active": False}
        return {
            "active": True,
            "client_id": record.client_id,
            "sub": record.subject,
            "scope": " ".join(record.scope),
            "token_type": record.token_type,
            "exp": record.expires_at,
        }

    def revoke(self, token: str) -> None:
        record = self.tokens.get(token)
        if record is not None:
            record.active = False

    def _revoke_family(self, family: str) -> None:
        for record in self.tokens.values():
            if record.family == family:
                record.active = False

    def userinfo(self, access_token: str, *, now: int | None = None) -> dict[str, str]:
        data = self.introspect(access_token, now=now)
        if not data["active"]:
            raise OAuthError("invalid_token", "access token is inactive")
        return {"sub": data["sub"], "preferred_username": data["sub"]}

    def discovery(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "userinfo_endpoint": f"{self.issuer}/userinfo",
            "jwks_uri": f"{self.issuer}/jwks.json",
            "code_challenge_methods_supported": ["S256"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
        }

