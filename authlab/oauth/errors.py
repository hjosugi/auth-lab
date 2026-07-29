"""OAuth 2.0 error responses (RFC 6749 sections 4.1.2.1 and 5.2).

The error codes are part of the protocol, not decoration -- a client is
expected to branch on them (for example, `invalid_grant` on a refresh means
"start a new authorization", while `invalid_client` means "your credentials
are wrong, retrying will not help").

Two rules that are easy to get wrong:

* Errors that happen BEFORE the redirect_uri is validated must NOT redirect.
  If client_id or redirect_uri is bad, render an error page. Redirecting an
  error to an unvalidated URI turns the authorization endpoint into an open
  redirector, which is half of a phishing chain.

* `invalid_grant` is deliberately vague. It covers an expired code, a reused
  code, a wrong PKCE verifier, and a revoked refresh token. Telling the
  caller which one hands an attacker a probing oracle.
"""

from __future__ import annotations


class OAuthError(Exception):
    """Base OAuth error, carrying the wire representation."""

    error = "invalid_request"
    status = 400

    def __init__(self, description: str = "", error: str | None = None, status: int | None = None):
        self.description = description
        if error:
            self.error = error
        if status:
            self.status = status
        super().__init__(f"{self.error}: {description}" if description else self.error)

    def to_dict(self) -> dict[str, str]:
        body = {"error": self.error}
        if self.description:
            body["error_description"] = self.description
        return body


class InvalidRequest(OAuthError):
    error = "invalid_request"


class InvalidClient(OAuthError):
    error = "invalid_client"
    status = 401


class InvalidGrant(OAuthError):
    """Code/token is expired, revoked, reused, or does not match the client."""

    error = "invalid_grant"


class UnauthorizedClient(OAuthError):
    error = "unauthorized_client"


class UnsupportedGrantType(OAuthError):
    error = "unsupported_grant_type"


class InvalidScope(OAuthError):
    error = "invalid_scope"


class AccessDenied(OAuthError):
    error = "access_denied"


class UnsupportedResponseType(OAuthError):
    error = "unsupported_response_type"


class ServerError(OAuthError):
    error = "server_error"
    status = 500


class AuthorizationPending(OAuthError):
    """Device flow: the user has not finished approving yet (RFC 8628)."""

    error = "authorization_pending"


class SlowDown(OAuthError):
    """Device flow: the client is polling faster than the interval allows."""

    error = "slow_down"


class ExpiredTokenError(OAuthError):
    error = "expired_token"


class InvalidTarget(OAuthError):
    """RFC 8707: the requested `resource` is not one this AS serves."""

    error = "invalid_target"


class InvalidDPoPProof(OAuthError):
    """RFC 9449."""

    error = "invalid_dpop_proof"


class UseDPoPNonce(OAuthError):
    error = "use_dpop_nonce"
