"""A resource server: the API that consumes access tokens.

The resource server is where most real breaches happen, because it is the
part teams write themselves. The authorization server is usually a product
(Keycloak, Auth0, Entra); the API middleware that decides "is this token good
enough for this endpoint" is bespoke, and every bespoke one skips something.

The checklist this class enforces, in order:

  1. Signature, against the AS's JWKS by `kid`, with the algorithm fixed to
     what the AS actually uses. (alg=none / confusion)
  2. `typ` is at+jwt, not JWT. An ID token must never work here.
  3. `iss` matches the AS we trust.
  4. `aud` contains US. Not "is present" -- contains us. (Token from another
     API is not a token for this API.)
  5. `exp` / `nbf` / `iat`, with minimal leeway.
  6. Sender constraint, if the token has a `cnf`: a DPoP proof matching
     `cnf.jkt`, or a TLS client certificate matching `cnf["x5t#S256"]`. A
     token with a cnf presented as a plain Bearer token is REJECTED -- the
     downgrade is the whole attack.
  7. Scope for this endpoint.
  8. Only then: is this specific user allowed to touch this specific object?
     Scope is not authorization. `orders:read` says the client may read
     orders; it says nothing about whose. That last gap is BOLA/IDOR, the
     number one item on the OWASP API Security Top 10, and no token check
     will ever close it -- see require_ownership below.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from ..jose.errors import ClaimError, InvalidSignature, JOSEError
from ..jose.jwks import JWKSet
from ..jose.jwt import JWTClaims, JWTValidator
from ..util.clock import Clock, SystemClock
from ..util.ct import constant_time_equals
from .dpop import DPoPVerifier, access_token_hash


class Unauthorized(Exception):
    """401: no credential, or the credential is not valid."""

    status = 401

    def __init__(self, message: str, error: str = "invalid_token"):
        self.error = error
        super().__init__(message)

    def www_authenticate(self, scheme: str = "Bearer", realm: str = "api") -> str:
        return f'{scheme} realm="{realm}", error="{self.error}", error_description="{self}"'


class Forbidden(Exception):
    """403: the credential is valid but does not permit this."""

    status = 403

    def __init__(self, message: str, error: str = "insufficient_scope"):
        self.error = error
        super().__init__(message)


@dataclass
class ResourceServer:
    """Validates access tokens for one API identity."""

    audience: str
    issuer: str
    jwks: JWKSet
    clock: Clock = field(default_factory=SystemClock)
    allowed_algorithms: Sequence[str] = ("RS256",)
    leeway: int = 30
    require_typ: str | None = "at+jwt"
    dpop: DPoPVerifier | None = None

    def __post_init__(self) -> None:
        if self.dpop is None:
            self.dpop = DPoPVerifier(clock=self.clock)
        self._validator = JWTValidator(
            issuer=self.issuer,
            audience=self.audience,
            allowed_algorithms=self.allowed_algorithms,
            key=self.jwks.resolver(),
            clock=self.clock,
            leeway=self.leeway,
            require_claims=("iss", "sub", "aud", "exp", "iat"),
            expected_typ=self.require_typ,
        )

    @staticmethod
    def parse_authorization_header(header: str | None) -> tuple[str, str]:
        """Split 'Bearer abc' / 'DPoP abc' into (scheme, token)."""
        if not header:
            raise Unauthorized("missing Authorization header", error="invalid_request")
        parts = header.split(None, 1)
        if len(parts) != 2:
            raise Unauthorized("malformed Authorization header", error="invalid_request")
        scheme, token = parts[0], parts[1].strip()
        if scheme.lower() not in ("bearer", "dpop"):
            raise Unauthorized(f"unsupported scheme: {scheme!r}", error="invalid_request")
        return scheme, token

    def authenticate(
        self,
        authorization_header: str | None,
        *,
        method: str = "GET",
        url: str | None = None,
        dpop_proof: str | None = None,
        tls_client_cert_thumbprint: str | None = None,
    ) -> JWTClaims:
        """Steps 1-6. Returns the validated claims or raises Unauthorized."""
        scheme, token = self.parse_authorization_header(authorization_header)

        try:
            claims = self._validator.validate(token)
        except InvalidSignature as exc:
            raise Unauthorized(str(exc)) from exc
        except ClaimError as exc:
            raise Unauthorized(str(exc)) from exc
        except JOSEError as exc:
            raise Unauthorized(str(exc)) from exc

        cnf = claims.get("cnf")
        if cnf:
            if not isinstance(cnf, dict):
                raise Unauthorized("malformed cnf claim")

            if "jkt" in cnf:
                if scheme.lower() != "dpop":
                    # Presenting a DPoP-bound token as Bearer is the downgrade.
                    raise Unauthorized(
                        "this token is DPoP-bound and must be presented with the DPoP scheme"
                    )
                if not dpop_proof:
                    raise Unauthorized("missing DPoP proof header", error="invalid_dpop_proof")
                if url is None:
                    raise Unauthorized("cannot validate DPoP proof without the request URL")
                try:
                    self.dpop.verify(
                        dpop_proof, method, url, access_token=token, expected_jkt=cnf["jkt"]
                    )
                except Exception as exc:  # noqa: BLE001
                    raise Unauthorized(str(exc), error="invalid_dpop_proof") from exc

            if "x5t#S256" in cnf:
                if tls_client_cert_thumbprint is None:
                    raise Unauthorized(
                        "this token is certificate-bound but no client certificate was presented"
                    )
                if not constant_time_equals(tls_client_cert_thumbprint, cnf["x5t#S256"]):
                    raise Unauthorized("client certificate does not match the token binding")
        elif scheme.lower() == "dpop" and dpop_proof:
            # A proof without a binding is not an error, but it buys nothing.
            pass

        return claims

    @staticmethod
    def require_scope(claims: JWTClaims, *required: str, mode: str = "all") -> None:
        """Step 7. `mode="all"` requires every scope; `"any"` requires one."""
        held = set(claims.scopes)
        needed = set(required)
        satisfied = needed <= held if mode == "all" else bool(needed & held)
        if not satisfied:
            raise Forbidden(
                f"insufficient scope: need {sorted(needed)} ({mode}), token has {sorted(held)}"
            )

    @staticmethod
    def require_ownership(claims: JWTClaims, owner_subject: str) -> None:
        """Step 8. The check that scope can never do for you.

        The bug this prevents, in its most common form:

            GET /orders/{id}
            token is valid, scope is orders:read  ->  200 OK

        ...for ANY id, including other customers' orders. That is BOLA
        (Broken Object Level Authorization), OWASP API1:2023. The fix is
        always the same shape: load the object, compare its owner to the
        token's subject, and 404 rather than 403 if they differ -- 403 tells
        the attacker the id exists, which is half of what they wanted.
        """
        if not constant_time_equals(claims.sub or "", owner_subject):
            raise Forbidden("this object does not belong to the authenticated subject", error="access_denied")


@dataclass
class IntrospectingResourceServer:
    """The other half of the token-format decision: opaque tokens.

    JWT access tokens are self-contained -- fast to validate, impossible to
    revoke before expiry. Opaque tokens are the reverse: every request costs
    a call to the AS, but revocation is instant and the token reveals nothing
    if it leaks into a log.

    The usual answer is: JWTs with short lifetimes for high-traffic APIs,
    opaque tokens when instant revocation matters more than latency, and
    caching introspection results for a few seconds when you want both.
    """

    audience: str
    introspect: Callable[[str], dict[str, Any]]
    clock: Clock = field(default_factory=SystemClock)
    cache_ttl: int = 0
    _cache: dict[str, tuple[int, dict[str, Any]]] = field(default_factory=dict)

    def authenticate(self, authorization_header: str | None) -> JWTClaims:
        _, token = ResourceServer.parse_authorization_header(authorization_header)
        now = self.clock.now()

        if self.cache_ttl:
            cached = self._cache.get(token)
            if cached and cached[0] > now:
                result = cached[1]
            else:
                result = self.introspect(token)
                self._cache[token] = (now + self.cache_ttl, result)
        else:
            result = self.introspect(token)

        if not result.get("active"):
            raise Unauthorized("token is not active")
        audiences = result.get("aud") or []
        if isinstance(audiences, str):
            audiences = [audiences]
        if audiences and self.audience not in audiences:
            raise Unauthorized(f"token audience {audiences} does not include {self.audience!r}")
        return JWTClaims(result)
