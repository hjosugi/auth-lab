"""OAuth 2.0 Pushed Authorization Requests (PAR), RFC 9126."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from ..util.clock import Clock, SystemClock
from ..util.ct import random_token
from .authorization_server import AuthorizationServer
from .errors import InvalidRequest, InvalidRequestURI
from .jar import JWTAuthorizationRequests

PAR_URN_PREFIX = "urn:ietf:params:oauth:request_uri:"
CLIENT_AUTH_FIELDS = {"client_secret", "client_assertion", "client_assertion_type"}


@dataclass
class PushedAuthorizationRequest:
    request_uri: str
    client_id: str
    params: dict[str, Any]
    expires_at: int
    used: bool = False


@dataclass
class PushedAuthorizationRequests:
    """Authenticate, validate, store, and resolve short-lived PAR references."""

    server: AuthorizationServer
    jar: JWTAuthorizationRequests | None = None
    clock: Clock = field(default_factory=SystemClock)
    lifetime: int = 90
    requests: dict[str, PushedAuthorizationRequest] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.clock.__class__ is SystemClock and self.server.clock.__class__ is not SystemClock:
            self.clock = self.server.clock
        if not 0 < self.lifetime < 600:
            raise ValueError("PAR lifetime must be between 1 and 599 seconds")

    def push(
        self,
        params: dict[str, Any],
        *,
        basic_auth: tuple[str, str] | None = None,
        tls_client_cert_thumbprint: str | None = None,
        require_signed_request: bool = False,
    ) -> dict[str, Any]:
        if "request_uri" in params:
            raise InvalidRequest("request_uri is not accepted at the PAR endpoint")
        client = self.server.authenticate_client(
            params,
            basic_auth=basic_auth,
            tls_client_cert_thumbprint=tls_client_cert_thumbprint,
        )

        if "request" in params:
            if self.jar is None:
                raise InvalidRequest("signed Request Objects are not configured")
            effective = self.jar.validate(
                str(params["request"]),
                outer_client_id=client.client_id,
            )
        else:
            if require_signed_request:
                raise InvalidRequest("this profile requires a signed Request Object at PAR")
            effective = deepcopy({
                name: value
                for name, value in params.items()
                if name not in CLIENT_AUTH_FIELDS
            })

        effective["client_id"] = client.client_id
        self.server.validate_authorization_request(effective)
        request_uri = PAR_URN_PREFIX + random_token(24)
        self.requests[request_uri] = PushedAuthorizationRequest(
            request_uri=request_uri,
            client_id=client.client_id,
            params=deepcopy(effective),
            expires_at=self.clock.now() + self.lifetime,
        )
        self.server.store.log("par_pushed", f"request for {client.client_id}")
        return {"request_uri": request_uri, "expires_in": self.lifetime}

    def authorize(self, params: dict[str, Any]) -> dict[str, Any]:
        """Resolve a PAR reference at the actual authorization decision point."""

        unexpected = set(params) - {"client_id", "request_uri"}
        if unexpected:
            raise InvalidRequestURI(
                f"front-channel parameters are limited to client_id and request_uri: {unexpected}"
            )
        request_uri = params.get("request_uri")
        client_id = params.get("client_id")
        if not isinstance(request_uri, str) or request_uri not in self.requests:
            raise InvalidRequestURI("unknown request_uri")
        record = self.requests[request_uri]
        if record.used:
            raise InvalidRequestURI("request_uri replay detected")
        if self.clock.now() > record.expires_at:
            raise InvalidRequestURI("request_uri has expired")
        if client_id != record.client_id:
            raise InvalidRequestURI("request_uri is bound to another client")
        record.used = True
        return self.server.validate_authorization_request(record.params)
