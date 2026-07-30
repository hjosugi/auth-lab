"""OpenID FAPI 2.0 Security Profile (Final).

The profile composes existing OAuth mechanisms into one stricter contract:
authenticated PAR, authorization code plus S256 PKCE, confidential clients,
short-lived codes, issuer-bound responses, and sender-constrained tokens.
Message signing is deliberately kept in ``fapi2_message_signing.py`` because
the two Final specifications are independently deployable and testable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit

from .authorization_server import AuthorizationServer
from .errors import InvalidRequest, UnauthorizedClient
from .models import Client
from .par import PushedAuthorizationRequests

FAPI_CLIENT_AUTH_METHODS = {"private_key_jwt", "tls_client_auth"}


@dataclass
class FAPI2SecurityProfile:
    server: AuthorizationServer
    par: PushedAuthorizationRequests

    def validate_client(self, client: Client) -> None:
        if client.is_public or client.token_endpoint_auth_method not in FAPI_CLIENT_AUTH_METHODS:
            raise UnauthorizedClient("FAPI 2.0 requires an asymmetric confidential client")
        if not (client.require_dpop or client.tls_client_certificate_bound_access_tokens):
            raise UnauthorizedClient("FAPI 2.0 requires DPoP or mTLS sender-constrained tokens")
        if "refresh_token" in client.grant_types and client.rotate_refresh_tokens:
            raise UnauthorizedClient(
                "FAPI 2.0 sender-constrained refresh tokens must not use AS-side rotation"
            )
        if self.server.code_lifetime > 60:
            raise InvalidRequest("FAPI 2.0 authorization codes must expire within 60 seconds")

    def pushed_authorization_request(
        self,
        params: dict[str, Any],
        *,
        basic_auth: tuple[str, str] | None = None,
        tls_client_cert_thumbprint: str | None = None,
        require_signed_request: bool = False,
    ) -> dict[str, Any]:
        client_id = basic_auth[0] if basic_auth else params.get("client_id")
        client = self.server.store.clients.get(str(client_id or ""))
        if client is None:
            raise UnauthorizedClient("unknown FAPI client")
        self.validate_client(client)
        if "request" not in params:
            self._validate_request_shape(params, client)
        result = self.par.push(
            params,
            basic_auth=basic_auth,
            tls_client_cert_thumbprint=tls_client_cert_thumbprint,
            require_signed_request=require_signed_request,
        )
        try:
            self._validate_request_shape(
                self.par.requests[result["request_uri"]].params,
                client,
            )
        except Exception:
            del self.par.requests[result["request_uri"]]
            raise
        return result

    @staticmethod
    def _validate_request_shape(params: dict[str, Any], client: Client) -> None:
        if params.get("response_type") != "code":
            raise InvalidRequest("FAPI 2.0 supports response_type=code")
        if not params.get("redirect_uri"):
            raise InvalidRequest("FAPI PAR requires redirect_uri")
        if not params.get("code_challenge") or params.get("code_challenge_method") != "S256":
            raise InvalidRequest("FAPI PAR requires PKCE with S256")
        if client.require_dpop and not params.get("dpop_jkt"):
            raise InvalidRequest("FAPI DPoP clients must bind the authorization code to dpop_jkt")

    def authorize(self, params: dict[str, Any]) -> dict[str, Any]:
        """Only a previously authenticated PAR reference may reach consent."""

        return self.par.authorize(params)

    def authorization_redirect(self, validated: dict[str, Any], code: str) -> str:
        query = urlencode(
            {
                "code": code,
                "state": validated["state"],
                "iss": self.server.issuer,
            }
        )
        separator = "&" if urlsplit(validated["redirect_uri"]).query else "?"
        return f"{validated['redirect_uri']}{separator}{query}"

    def token(
        self,
        params: dict[str, Any],
        *,
        basic_auth: tuple[str, str] | None = None,
        dpop_proof: str | None = None,
        token_endpoint_url: str | None = None,
        tls_client_cert_thumbprint: str | None = None,
    ) -> dict[str, Any]:
        client_id = basic_auth[0] if basic_auth else params.get("client_id")
        client = self.server.store.clients.get(str(client_id or ""))
        if client is None:
            raise UnauthorizedClient("unknown FAPI client")
        self.validate_client(client)
        result = self.server.token(
            params,
            basic_auth=basic_auth,
            dpop_proof=dpop_proof,
            token_endpoint_url=token_endpoint_url,
            tls_client_cert_thumbprint=tls_client_cert_thumbprint,
        )
        access = self.server.store.access_tokens[result["access_token"]]
        if not (access.cnf_jkt or access.cnf_x5t):
            raise InvalidRequest("FAPI 2.0 refused an unbound bearer access token")
        return result

    def metadata(self) -> dict[str, Any]:
        return {
            **self.server.metadata(),
            "pushed_authorization_request_endpoint": f"{self.server.issuer}/par",
            "require_pushed_authorization_requests": True,
            "authorization_response_iss_parameter_supported": True,
            "require_signed_request_object": False,
        }
