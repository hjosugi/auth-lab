"""OpenID FAPI 2.0 Message Signing (Final).

This optional profile adds integrity and origin authentication to messages
that the Security Profile otherwise protects through channels and bindings:
JAR at PAR, JARM at the authorization response, and RFC 9701 signed token
introspection responses.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..jose.errors import JOSEError
from ..jose.jwks import JWKSet
from ..jose.jws import JWS, RS256
from .errors import InvalidAuthorizationResponse, InvalidClient
from .fapi2_security import FAPI2SecurityProfile
from .jarm import JWTAuthorizationResponses
from .models import Client

INTROSPECTION_TYP = "token-introspection+jwt"
INTROSPECTION_MEDIA_TYPE = "application/token-introspection+jwt"


@dataclass
class FAPI2MessageSigning:
    security: FAPI2SecurityProfile
    jarm: JWTAuthorizationResponses

    def pushed_authorization_request(
        self,
        params: dict[str, Any],
        *,
        basic_auth: tuple[str, str] | None = None,
        tls_client_cert_thumbprint: str | None = None,
    ) -> dict[str, Any]:
        return self.security.pushed_authorization_request(
            params,
            basic_auth=basic_auth,
            tls_client_cert_thumbprint=tls_client_cert_thumbprint,
            require_signed_request=True,
        )

    def authorization_response(self, validated: dict[str, Any], code: str) -> str:
        client_id = validated["client"].client_id
        return self.jarm.issue(
            client_id,
            {
                "code": code,
                "state": validated["state"],
            },
        )

    def signed_introspection(
        self,
        token_value: str,
        *,
        resource_server: Client,
        audience: str,
        basic_auth: tuple[str, str] | None = None,
        tls_client_cert_thumbprint: str | None = None,
    ) -> dict[str, str]:
        """Return an authenticated RFC 9701 response envelope."""

        server = self.security.server
        authenticated = server.authenticate_client(
            {"client_id": resource_server.client_id},
            basic_auth=basic_auth,
            tls_client_cert_thumbprint=tls_client_cert_thumbprint,
        )
        if authenticated.client_id != resource_server.client_id:
            raise InvalidClient("resource server authentication mismatch")
        if audience not in resource_server.introspection_audiences:
            raise InvalidClient("resource server is not registered for this introspection audience")
        introspection = server.introspect(token_value, authenticated)
        record = server.store.access_tokens.get(token_value)
        if record is None or audience not in record.audience:
            introspection = {"active": False}
        claims = {
            "iss": server.issuer,
            "aud": audience,
            "iat": server.clock.now(),
            "token_introspection": introspection,
        }
        response_jwt = JWS.sign(
            claims,
            server.signing_key,
            RS256,
            kid=server.signing_kid,
            typ=INTROSPECTION_TYP,
        )
        return {"content_type": INTROSPECTION_MEDIA_TYPE, "body": response_jwt}

    def validate_introspection_response(
        self,
        response_jwt: str,
        *,
        audience: str,
        server_jwks: JWKSet,
    ) -> dict[str, Any]:
        try:
            parsed = JWS.verify(response_jwt, server_jwks.resolver(), [RS256])
            claims = json.loads(parsed.payload)
        except (JOSEError, ValueError, json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
            raise InvalidAuthorizationResponse(
                "signed introspection signature or JSON is invalid"
            ) from exc
        if parsed.header.get("typ") != INTROSPECTION_TYP:
            raise InvalidAuthorizationResponse("unexpected signed introspection typ")
        if not isinstance(claims, dict) or claims.get("iss") != self.security.server.issuer:
            raise InvalidAuthorizationResponse("signed introspection issuer mismatch")
        received_audience = claims.get("aud")
        audiences = [received_audience] if isinstance(received_audience, str) else received_audience
        if not isinstance(audiences, list) or audience not in audiences:
            raise InvalidAuthorizationResponse("signed introspection audience mismatch")
        now = self.security.server.clock.now()
        if (
            not isinstance(claims.get("iat"), int)
            or claims["iat"] > now + 60
            or now - claims["iat"] > 300
        ):
            raise InvalidAuthorizationResponse("signed introspection iat is invalid")
        body = claims.get("token_introspection")
        if not isinstance(body, dict) or not isinstance(body.get("active"), bool):
            raise InvalidAuthorizationResponse("signed introspection body is invalid")
        return body

    def metadata(self) -> dict[str, Any]:
        return {
            **self.security.metadata(),
            "require_signed_request_object": True,
            "request_object_signing_alg_values_supported": ["RS256"],
            "authorization_signing_alg_values_supported": ["RS256"],
            "introspection_signing_alg_values_supported": ["RS256"],
            "introspection_response_content_type": INTROSPECTION_MEDIA_TYPE,
        }
