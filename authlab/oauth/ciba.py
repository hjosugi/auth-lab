"""OpenID Connect Client-Initiated Backchannel Authentication (CIBA) Core 1.0.

No request is sent through the consumption device's browser.  The client
starts an authenticated backchannel request, the user approves on a separate
authentication device, and the result is delivered in poll, ping, or push
mode.  This lab returns delivery envelopes instead of contacting real URLs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..util.clock import Clock, SystemClock
from ..util.ct import random_token
from .authorization_server import AuthorizationServer
from .errors import (
    AccessDenied,
    AuthorizationPending,
    ExpiredTokenError,
    InvalidGrant,
    InvalidRequest,
    SlowDown,
    UnauthorizedClient,
)

CIBA_GRANT_TYPE = "urn:openid:params:grant-type:ciba"


@dataclass
class BackchannelAuthentication:
    auth_req_id: str
    client_id: str
    scope: list[str]
    login_hint: str
    binding_message: str | None
    expires_at: int
    interval: int
    mode: str
    notification_endpoint: str | None
    notification_token: str | None
    tls_client_cert_thumbprint: str | None
    subject: str | None = None
    amr: list[str] = field(default_factory=list)
    denied: bool = False
    used: bool = False
    last_polled_at: int | None = None


@dataclass
class CIBAService:
    server: AuthorizationServer
    clock: Clock = field(default_factory=SystemClock)
    lifetime: int = 300
    interval: int = 5
    requests: dict[str, BackchannelAuthentication] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.clock.__class__ is SystemClock and self.server.clock.__class__ is not SystemClock:
            self.clock = self.server.clock

    def start(
        self,
        params: dict[str, Any],
        *,
        basic_auth: tuple[str, str] | None = None,
        tls_client_cert_thumbprint: str | None = None,
    ) -> dict[str, Any]:
        client = self.server.authenticate_client(
            params,
            basic_auth=basic_auth,
            tls_client_cert_thumbprint=tls_client_cert_thumbprint,
        )
        if CIBA_GRANT_TYPE not in client.grant_types:
            raise UnauthorizedClient("client is not registered for CIBA")
        scope = str(params.get("scope") or "").split()
        if "openid" not in scope:
            raise InvalidRequest("CIBA requires the openid scope")

        hints = [
            params.get(name)
            for name in ("login_hint", "login_hint_token", "id_token_hint")
            if params.get(name)
        ]
        if len(hints) != 1 or not isinstance(hints[0], str):
            raise InvalidRequest("CIBA requires exactly one user hint")
        binding_message = params.get("binding_message")
        if binding_message is not None and (
            not isinstance(binding_message, str)
            or not 0 < len(binding_message) <= 20
            or not binding_message.isprintable()
        ):
            raise InvalidRequest("binding_message must be 1..20 printable characters")

        mode = client.backchannel_token_delivery_mode
        if mode not in {"poll", "ping", "push"}:
            raise InvalidRequest(f"unsupported CIBA delivery mode: {mode}")
        notification_token = params.get("client_notification_token")
        if mode in {"ping", "push"} and (
            not client.backchannel_client_notification_endpoint
            or not isinstance(notification_token, str)
            or len(notification_token) < 16
        ):
            raise InvalidRequest("ping/push CIBA needs an endpoint and notification token")

        requested_expiry = params.get("requested_expiry", self.lifetime)
        if not isinstance(requested_expiry, int) or not 1 <= requested_expiry <= self.lifetime:
            raise InvalidRequest(f"requested_expiry must be 1..{self.lifetime}")
        auth_req_id = random_token(32)
        self.requests[auth_req_id] = BackchannelAuthentication(
            auth_req_id=auth_req_id,
            client_id=client.client_id,
            scope=scope,
            login_hint=hints[0],
            binding_message=binding_message,
            expires_at=self.clock.now() + requested_expiry,
            interval=self.interval,
            mode=mode,
            notification_endpoint=client.backchannel_client_notification_endpoint,
            notification_token=notification_token if isinstance(notification_token, str) else None,
            tls_client_cert_thumbprint=tls_client_cert_thumbprint,
        )
        return {
            "auth_req_id": auth_req_id,
            "expires_in": requested_expiry,
            "interval": self.interval,
        }

    def approve(
        self,
        auth_req_id: str,
        subject: str,
        *,
        amr: list[str] | None = None,
    ) -> dict[str, Any] | None:
        record = self._record(auth_req_id)
        if subject not in self.server.store.users:
            raise InvalidRequest("unknown CIBA subject")
        record.subject = subject
        record.amr = amr or ["pwd"]
        if record.mode == "poll":
            return None
        if record.mode == "ping":
            return {
                "mode": "ping",
                "endpoint": record.notification_endpoint,
                "authorization": f"Bearer {record.notification_token}",
                "body": {"auth_req_id": auth_req_id},
            }
        tokens = self._tokens(
            record,
            tls_client_cert_thumbprint=record.tls_client_cert_thumbprint,
        )
        return {
            "mode": "push",
            "endpoint": record.notification_endpoint,
            "authorization": f"Bearer {record.notification_token}",
            "body": tokens,
        }

    def deny(self, auth_req_id: str) -> None:
        self._record(auth_req_id).denied = True

    def token(
        self,
        params: dict[str, Any],
        *,
        basic_auth: tuple[str, str] | None = None,
        tls_client_cert_thumbprint: str | None = None,
    ) -> dict[str, Any]:
        if params.get("grant_type") != CIBA_GRANT_TYPE:
            raise InvalidGrant("wrong grant_type for CIBA")
        client = self.server.authenticate_client(
            params,
            basic_auth=basic_auth,
            tls_client_cert_thumbprint=tls_client_cert_thumbprint,
        )
        record = self._record(str(params.get("auth_req_id") or ""))
        if record.client_id != client.client_id:
            raise InvalidGrant("auth_req_id is bound to another client")
        if record.mode == "push":
            raise InvalidGrant("push mode does not use the token endpoint")
        if record.denied:
            raise AccessDenied("the user denied the CIBA request")
        if record.subject is None:
            now = self.clock.now()
            if record.last_polled_at is not None and now - record.last_polled_at < record.interval:
                record.interval += 5
                record.last_polled_at = now
                raise SlowDown("CIBA polling faster than interval")
            record.last_polled_at = now
            raise AuthorizationPending("CIBA authentication is still pending")
        return self._tokens(record, tls_client_cert_thumbprint=tls_client_cert_thumbprint)

    def _record(self, auth_req_id: str) -> BackchannelAuthentication:
        record = self.requests.get(auth_req_id)
        if record is None or record.used:
            raise InvalidGrant("invalid auth_req_id")
        if self.clock.now() > record.expires_at:
            raise ExpiredTokenError("auth_req_id has expired")
        return record

    def _tokens(
        self,
        record: BackchannelAuthentication,
        *,
        tls_client_cert_thumbprint: str | None,
    ) -> dict[str, Any]:
        client = self.server.store.clients[record.client_id]
        if (
            client.tls_client_certificate_bound_access_tokens
            and tls_client_cert_thumbprint != record.tls_client_cert_thumbprint
        ):
            raise InvalidGrant("CIBA token request uses a different client certificate")
        record.used = True
        return self.server._issue_token_set(
            client=client,
            subject=record.subject,
            scope=record.scope,
            nonce=None,
            amr=record.amr,
            auth_time=self.clock.now(),
            audience=self.server.known_resources[:1],
            cnf_jkt=None,
            cnf_x5t=(
                record.tls_client_cert_thumbprint
                if client.tls_client_certificate_bound_access_tokens
                else None
            ),
            include_refresh=True,
        )
