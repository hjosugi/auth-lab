"""Data model and in-memory storage for the authorization server.

Everything here is a dataclass and a dict. Swapping the store for a database
is the only change a real deployment needs -- but note which fields exist,
because each one is carrying a security property:

  AuthorizationCode.used          -> single-use enforcement / replay detection
  RefreshToken.family_id          -> rotation reuse detection
  RefreshToken.rotated_to         -> which token superseded this one
  AccessToken.cnf_jkt / cnf_x5t   -> sender constraint (DPoP / mTLS)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..util.ct import random_token


@dataclass
class Client:
    """A registered OAuth client.

    `public` clients (SPAs, mobile apps) cannot keep a secret: anything
    shipped to a user's device is readable by that user. They therefore get
    no client_secret, must use PKCE, and must not be issued long-lived
    refresh tokens without rotation.
    """

    client_id: str
    client_secret: str | None = None
    redirect_uris: list[str] = field(default_factory=list)
    grant_types: list[str] = field(default_factory=lambda: ["authorization_code", "refresh_token"])
    response_types: list[str] = field(default_factory=lambda: ["code"])
    scopes: list[str] = field(default_factory=list)
    # "none" (public), "client_secret_basic", "client_secret_post",
    # "private_key_jwt", or "tls_client_auth"
    token_endpoint_auth_method: str = "client_secret_basic"
    require_pkce: bool = True
    name: str = ""
    # RFC 8705: bind issued tokens to the client's TLS certificate.
    tls_client_certificate_bound_access_tokens: bool = False
    # RFC 9449: require a DPoP proof on token requests.
    require_dpop: bool = False
    jwks: dict[str, Any] | None = None  # for private_key_jwt
    # FAPI 2.0 Security Profile normally prohibits AS-side refresh rotation
    # for sender-constrained confidential clients.
    rotate_refresh_tokens: bool = True
    # CIBA registration metadata. No network call is made by the lab.
    backchannel_token_delivery_mode: str = "poll"
    backchannel_client_notification_endpoint: str | None = None
    # RFC 9701 responses may only disclose token data to registered audiences.
    introspection_audiences: list[str] = field(default_factory=list)

    @property
    def is_public(self) -> bool:
        # A private_key_jwt or mTLS client has no shared secret but is still
        # confidential because it authenticates with proof of key possession.
        return self.token_endpoint_auth_method == "none"


@dataclass
class User:
    subject: str
    username: str
    password_hash: str
    email: str = ""
    name: str = ""
    email_verified: bool = False
    totp_secret: bytes | None = None
    groups: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)


@dataclass
class AuthorizationCode:
    code: str
    client_id: str
    subject: str
    redirect_uri: str
    scope: list[str]
    expires_at: int
    code_challenge: str | None = None
    code_challenge_method: str = "S256"
    nonce: str | None = None
    # amr = authentication methods references: how the user proved who they
    # are on THIS login. A relying party that requires MFA checks this rather
    # than trusting that the IdP always does MFA.
    amr: list[str] = field(default_factory=list)
    auth_time: int = 0
    used: bool = False
    resource: list[str] = field(default_factory=list)
    dpop_jkt: str | None = None
    authorization_details: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AccessToken:
    token: str
    client_id: str
    subject: str | None
    scope: list[str]
    expires_at: int
    issued_at: int
    token_type: str = "Bearer"
    audience: list[str] = field(default_factory=list)
    revoked: bool = False
    # Sender-constraint confirmation values (RFC 7800 `cnf`).
    cnf_jkt: str | None = None   # DPoP key thumbprint
    cnf_x5t: str | None = None   # mTLS certificate thumbprint
    jti: str = field(default_factory=lambda: random_token(16))
    authorization_details: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class RefreshToken:
    token: str
    client_id: str
    subject: str
    scope: list[str]
    expires_at: int
    # All descendants of one original grant share a family_id. When a token is
    # replayed we revoke the entire family, because we cannot tell whether the
    # legitimate client or the attacker is the one holding the current token.
    family_id: str
    used: bool = False
    revoked: bool = False
    rotated_to: str | None = None
    cnf_jkt: str | None = None
    cnf_x5t: str | None = None
    authorization_details: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class DeviceCode:
    device_code: str
    user_code: str
    client_id: str
    scope: list[str]
    expires_at: int
    interval: int = 5
    approved: bool = False
    denied: bool = False
    subject: str | None = None
    last_polled_at: int = 0
    amr: list[str] = field(default_factory=list)


@dataclass
class Store:
    """In-memory storage. One dict per record type, plus a replay cache."""

    clients: dict[str, Client] = field(default_factory=dict)
    users: dict[str, User] = field(default_factory=dict)
    codes: dict[str, AuthorizationCode] = field(default_factory=dict)
    access_tokens: dict[str, AccessToken] = field(default_factory=dict)
    refresh_tokens: dict[str, RefreshToken] = field(default_factory=dict)
    device_codes: dict[str, DeviceCode] = field(default_factory=dict)
    # jti values already seen, for one-time-use proofs (DPoP, private_key_jwt).
    seen_jtis: dict[str, int] = field(default_factory=dict)
    # Audit trail, so drills can show what the server actually did.
    events: list[tuple[str, str]] = field(default_factory=list)

    def log(self, kind: str, message: str) -> None:
        self.events.append((kind, message))

    def user_by_username(self, username: str) -> User | None:
        for user in self.users.values():
            if user.username == username:
                return user
        return None

    def revoke_refresh_family(self, family_id: str) -> int:
        """Revoke every refresh token descended from one authorization.

        This is the response to a detected replay. It is deliberately brutal:
        the legitimate user gets logged out and has to re-authenticate, which
        is the correct trade when a token has demonstrably leaked.
        """
        count = 0
        for token in self.refresh_tokens.values():
            if token.family_id == family_id and not token.revoked:
                token.revoked = True
                count += 1
        return count

    def revoke_access_for_family_subject(self, client_id: str, subject: str) -> int:
        count = 0
        for token in self.access_tokens.values():
            if token.client_id == client_id and token.subject == subject and not token.revoked:
                token.revoked = True
                count += 1
        return count
