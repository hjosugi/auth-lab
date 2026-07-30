"""JWT Secured Authorization Response Mode (JARM), OpenID Final."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlsplit

from ..jose.errors import JOSEError
from ..jose.jwks import JWKSet
from ..jose.jws import JWS, RS256
from ..util.clock import Clock, SystemClock
from ..util.ct import constant_time_equals, random_token
from .errors import InvalidAuthorizationResponse

JARM_TYP = "oauth-authz-resp+jwt"


@dataclass
class JWTAuthorizationResponses:
    issuer: str
    signing_key: Any
    signing_kid: str
    clock: Clock = field(default_factory=SystemClock)
    lifetime: int = 60
    seen_jtis: set[str] = field(default_factory=set)

    def issue(self, client_id: str, response: dict[str, Any]) -> str:
        if ("code" in response) == ("error" in response):
            raise InvalidAuthorizationResponse("JARM response needs exactly one of code or error")
        now = self.clock.now()
        claims = {
            "iss": self.issuer,
            "aud": client_id,
            "iat": now,
            "exp": now + self.lifetime,
            "jti": random_token(16),
            **response,
        }
        return JWS.sign(
            claims,
            self.signing_key,
            RS256,
            kid=self.signing_kid,
            typ=JARM_TYP,
        )

    def redirect(self, redirect_uri: str, response_jwt: str) -> str:
        separator = "&" if urlsplit(redirect_uri).query else "?"
        return f"{redirect_uri}{separator}{urlencode({'response': response_jwt})}"

    def validate(
        self,
        response_jwt: str,
        *,
        client_id: str,
        server_jwks: JWKSet,
        expected_state: str | None = None,
    ) -> dict[str, Any]:
        try:
            parsed = JWS.verify(response_jwt, server_jwks.resolver(), [RS256])
            claims = json.loads(parsed.payload)
        except (JOSEError, ValueError, json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
            raise InvalidAuthorizationResponse("JARM signature or JSON is invalid") from exc
        if parsed.header.get("typ") != JARM_TYP:
            raise InvalidAuthorizationResponse("unexpected JARM typ")
        if not isinstance(claims, dict):
            raise InvalidAuthorizationResponse("JARM payload must be an object")
        if claims.get("iss") != self.issuer:
            raise InvalidAuthorizationResponse("JARM issuer mismatch")
        audience = claims.get("aud")
        audiences = [audience] if isinstance(audience, str) else audience
        if not isinstance(audiences, list) or client_id not in audiences:
            raise InvalidAuthorizationResponse("JARM audience mismatch")
        now = self.clock.now()
        if (
            not isinstance(claims.get("iat"), int)
            or not isinstance(claims.get("exp"), int)
            or claims["iat"] > now + 60
            or claims["exp"] < claims["iat"]
            or claims["exp"] - claims["iat"] > 600
            or now > claims["exp"]
        ):
            raise InvalidAuthorizationResponse("JARM response expired")
        if ("code" in claims) == ("error" in claims):
            raise InvalidAuthorizationResponse("JARM payload needs exactly one of code or error")
        jti = claims.get("jti")
        if not isinstance(jti, str) or jti in self.seen_jtis:
            raise InvalidAuthorizationResponse("JARM response replay detected")
        if expected_state is not None:
            state = claims.get("state")
            if not isinstance(state, str) or not constant_time_equals(state, expected_state):
                raise InvalidAuthorizationResponse("JARM state mismatch")
        self.seen_jtis.add(jti)
        return claims
