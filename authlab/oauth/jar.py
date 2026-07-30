"""JWT-Secured Authorization Requests (JAR), RFC 9101.

A Request Object signs the authorization parameters with a key registered to
the client.  The browser may carry the JWT, but it cannot silently replace a
redirect URI, scope, PKCE challenge, or payment instruction.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ..jose.errors import JOSEError
from ..jose.jwks import JWK, JWKSet
from ..jose.jws import JWS, RS256
from ..jose.jwt import JWT
from ..util.clock import Clock, SystemClock
from ..util.ct import random_token
from .errors import InvalidRequestObject

REQUEST_OBJECT_TYP = "oauth-authz-req+jwt"
REGISTERED_CLAIMS = {"iss", "aud", "iat", "nbf", "exp", "jti"}


@dataclass
class JWTAuthorizationRequests:
    """Issue and verify signed OAuth Request Objects."""

    authorization_server_issuer: str
    clock: Clock = field(default_factory=SystemClock)
    maximum_lifetime: int = 300
    client_keys: dict[str, JWKSet] = field(default_factory=dict)
    seen_jtis: dict[str, int] = field(default_factory=dict)

    def register_client_key(self, client_id: str, key: JWK) -> None:
        key_set = self.client_keys.setdefault(client_id, JWKSet())
        key_set.add(key.public())

    def issue(
        self,
        params: dict[str, Any],
        private_key: Any,
        *,
        kid: str,
        lifetime: int = 60,
        not_before: int | None = None,
    ) -> str:
        client_id = params.get("client_id")
        if not isinstance(client_id, str) or not client_id:
            raise InvalidRequestObject("client_id is required in a Request Object")
        if "request" in params or "request_uri" in params:
            raise InvalidRequestObject("Request Objects must not contain request or request_uri")
        if lifetime <= 0 or lifetime > self.maximum_lifetime:
            raise InvalidRequestObject(
                f"Request Object lifetime must be 1..{self.maximum_lifetime} seconds"
            )
        now = self.clock.now()
        claims = dict(params)
        claims.update(
            {
                "iss": client_id,
                "aud": self.authorization_server_issuer,
                "iat": now,
                "nbf": now if not_before is None else not_before,
                "exp": now + lifetime,
                "jti": random_token(16),
            }
        )
        return JWS.sign(claims, private_key, RS256, kid=kid, typ=REQUEST_OBJECT_TYP)

    def validate(self, request_object: str, *, outer_client_id: str | None = None) -> dict[str, Any]:
        try:
            untrusted = JWT.peek(request_object).raw
            client_id = untrusted.get("iss")
            if not isinstance(client_id, str) or client_id not in self.client_keys:
                raise InvalidRequestObject("Request Object issuer is not a registered client")
            parsed = JWS.verify(
                request_object,
                self.client_keys[client_id].resolver(),
                [RS256],
            )
            claims = json.loads(parsed.payload)
        except InvalidRequestObject:
            raise
        except (JOSEError, ValueError, json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
            raise InvalidRequestObject("Request Object signature or JSON is invalid") from exc

        if parsed.header.get("typ") != REQUEST_OBJECT_TYP:
            raise InvalidRequestObject(f"unexpected Request Object typ: {parsed.header.get('typ')!r}")
        if not isinstance(claims, dict):
            raise InvalidRequestObject("Request Object claims must be a JSON object")
        if claims.get("iss") != client_id or claims.get("client_id") != client_id:
            raise InvalidRequestObject("iss and client_id must identify the same client")
        if outer_client_id is not None and outer_client_id != client_id:
            raise InvalidRequestObject("outer client_id does not match the Request Object")

        audience = claims.get("aud")
        audiences = [audience] if isinstance(audience, str) else audience
        if not isinstance(audiences, list) or self.authorization_server_issuer not in audiences:
            raise InvalidRequestObject("Request Object audience does not include this AS")

        now = self.clock.now()
        for name in ("iat", "nbf", "exp"):
            if not isinstance(claims.get(name), int):
                raise InvalidRequestObject(f"Request Object {name} must be an integer")
        if claims["iat"] > now + 60:
            raise InvalidRequestObject("Request Object iat is too far in the future")
        if claims["nbf"] > now + 60:
            raise InvalidRequestObject("Request Object is not active yet")
        if claims["exp"] < now:
            raise InvalidRequestObject("Request Object has expired")
        if (
            claims["exp"] < claims["nbf"]
            or claims["exp"] < claims["iat"]
            or claims["exp"] - claims["nbf"] > self.maximum_lifetime
        ):
            raise InvalidRequestObject("Request Object lifetime is too long")

        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti:
            raise InvalidRequestObject("Request Object jti is required")
        if jti in self.seen_jtis:
            raise InvalidRequestObject("Request Object replay detected")
        self.seen_jtis[jti] = claims["exp"]

        if "request" in claims or "request_uri" in claims:
            raise InvalidRequestObject("Request Object recursively names request/request_uri")
        return {name: value for name, value in claims.items() if name not in REGISTERED_CLAIMS}
