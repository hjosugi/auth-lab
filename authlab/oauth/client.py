"""The OAuth client / OIDC relying party.

The client's security job is smaller than the server's but not small:

  * generate `state` and `nonce` per attempt, store them server-side (or in a
    signed, httpOnly cookie) keyed to the browser session, and check them on
    the way back. `state` unvalidated = login CSRF: an attacker starts a flow
    with THEIR account, hands you the callback URL, and you end up silently
    logged in as them -- then type your credit card into their account.
  * generate a PKCE verifier per attempt and never reuse it.
  * pin the redirect_uri.
  * validate the ID token fully (this is not optional just because it came
    over TLS from the token endpoint -- the point is validating it the same
    way whether it arrived by front channel or back channel).
  * store tokens somewhere JavaScript cannot read them. For a browser app
    that means an httpOnly, Secure, SameSite cookie holding a session id, with
    the tokens server-side -- the "backend for frontend" pattern. localStorage
    means one XSS is a total, silent, permanent account takeover.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

from ..jose.jwks import JWKSet
from ..jose.jwt import JWTClaims, JWTValidator
from ..util.clock import Clock, SystemClock
from ..util.ct import constant_time_equals, random_token
from . import pkce
from .errors import InvalidRequest


@dataclass
class PendingAuthorization:
    """Per-attempt state. Lives server-side, keyed by the browser session."""

    state: str
    nonce: str
    code_verifier: str
    redirect_uri: str
    scope: list[str]
    created_at: int


@dataclass
class OAuthClient:
    """A relying party driving the authorization code flow with PKCE."""

    client_id: str
    redirect_uri: str
    authorization_endpoint: str
    token_endpoint: str
    issuer: str
    client_secret: str | None = None
    scope: list[str] = field(default_factory=lambda: ["openid", "profile"])
    clock: Clock = field(default_factory=SystemClock)
    jwks: JWKSet | None = None
    # session_id -> PendingAuthorization. A dict here; Redis in production.
    pending: dict[str, PendingAuthorization] = field(default_factory=dict)
    state_ttl: int = 600

    def begin(self, session_id: str, extra: dict[str, str] | None = None) -> str:
        """Build the /authorize URL and remember what we sent."""
        verifier, challenge = pkce.generate_pair("S256")
        pending = PendingAuthorization(
            state=random_token(16),
            nonce=random_token(16),
            code_verifier=verifier,
            redirect_uri=self.redirect_uri,
            scope=list(self.scope),
            created_at=self.clock.now(),
        )
        self.pending[session_id] = pending

        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.scope),
            "state": pending.state,
            "nonce": pending.nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if extra:
            params.update(extra)
        return f"{self.authorization_endpoint}?{urlencode(params)}"

    def handle_callback(self, session_id: str, callback_url: str) -> dict[str, str]:
        """Validate the redirect we got back. Returns the token request params.

        Everything here runs BEFORE we spend the code. A callback that fails
        any of these checks must not reach the token endpoint at all.
        """
        pending = self.pending.get(session_id)
        if pending is None:
            raise InvalidRequest("no authorization in progress for this session")
        if self.clock.now() - pending.created_at > self.state_ttl:
            del self.pending[session_id]
            raise InvalidRequest("authorization attempt expired")

        query = dict(parse_qsl(urlsplit(callback_url).query))

        if "error" in query:
            del self.pending[session_id]
            raise InvalidRequest(
                f"authorization failed: {query['error']}: {query.get('error_description', '')}"
            )

        state = query.get("state")
        if not state or not constant_time_equals(state, pending.state):
            # The CSRF check. Note that it compares against state stored for
            # THIS session -- a global set of valid states would let an
            # attacker's state pass in a victim's session.
            raise InvalidRequest("state mismatch: possible login CSRF, refusing the callback")

        code = query.get("code")
        if not code:
            raise InvalidRequest("no code in callback")

        # The verifier is consumed here and only here.
        del self.pending[session_id]
        params = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": pending.redirect_uri,
            "client_id": self.client_id,
            "code_verifier": pending.code_verifier,
        }
        if self.client_secret:
            params["client_secret"] = self.client_secret
        self._last_nonce = pending.nonce
        return params

    def validate_id_token(self, id_token: str, nonce: str | None = None) -> JWTClaims:
        """Full ID token validation, as a relying party must do it."""
        if self.jwks is None:
            raise InvalidRequest("no JWKS configured; cannot validate the ID token")
        validator = JWTValidator(
            issuer=self.issuer,
            # An ID token's audience is the client_id. This is the check that
            # stops one tenant's ID token being accepted by another app.
            audience=self.client_id,
            allowed_algorithms=["RS256"],
            key=self.jwks.resolver(),
            clock=self.clock,
            require_claims=("iss", "sub", "aud", "exp", "iat"),
            expected_typ="JWT",
        )
        return validator.validate(id_token, nonce=nonce or getattr(self, "_last_nonce", None))

    def authorization_header(self) -> dict[str, str]:
        """client_secret_basic: base64(client_id:client_secret) in Basic auth."""
        import base64

        if not self.client_secret:
            return {}
        raw = f"{self.client_id}:{self.client_secret}".encode("utf-8")
        return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}
