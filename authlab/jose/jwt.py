"""JWT: JSON Web Token (RFC 7519), which is a JWS whose payload is claims.

The signature is the easy half. The half that gets people breached is claim
validation, so this module makes every check explicit and mandatory-by-default.

The registered claims and what each one actually defends against:

  iss  issuer     -- which authorization server minted this. Without it, a
                     token from *any* IdP you trust works at *every* service.
  sub  subject    -- who the token is about. Stable and opaque; never an
                     email, because emails get reassigned.
  aud  audience   -- who this token is FOR. This is the one people skip, and
                     skipping it is how an ID token gets replayed at an API,
                     or how a token for service A is accepted by service B.
  exp  expiry     -- hard stop. Short for access tokens (minutes).
  nbf  not before -- earliest usable time. Guards against tokens minted ahead
                     of a scheduled change.
  iat  issued at  -- when minted. Lets a resource server apply its own
                     max-age policy, stricter than exp.
  jti  JWT ID     -- unique id, so a one-time token can be marked as used.

`leeway` exists because clocks disagree. Sixty seconds is generous; anything
above a couple of minutes means expiry has stopped meaning much.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

from ..util.clock import Clock, SystemClock
from ..util.ct import random_token
from .errors import ClaimError, ExpiredToken, InvalidToken
from .jws import JWS, Algorithm, ParsedJWS


@dataclass
class JWTClaims:
    """Parsed claims with typed access to the registered ones."""

    raw: dict[str, Any]

    def __getitem__(self, key: str) -> Any:
        return self.raw[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.raw.get(key, default)

    def __contains__(self, key: str) -> bool:
        return key in self.raw

    def __repr__(self) -> str:
        return f"JWTClaims({self.raw!r})"

    @property
    def iss(self) -> str | None:
        return self.raw.get("iss")

    @property
    def sub(self) -> str | None:
        return self.raw.get("sub")

    @property
    def aud(self) -> list[str]:
        """Audience, always normalised to a list.

        RFC 7519 allows aud to be a string OR an array of strings. Code that
        assumes one shape and receives the other either crashes or, worse,
        does `aud == "api"` against a list and silently skips the check.
        """
        value = self.raw.get("aud")
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return [str(v) for v in value]

    @property
    def exp(self) -> int | None:
        return self.raw.get("exp")

    @property
    def nbf(self) -> int | None:
        return self.raw.get("nbf")

    @property
    def iat(self) -> int | None:
        return self.raw.get("iat")

    @property
    def jti(self) -> str | None:
        return self.raw.get("jti")

    @property
    def scopes(self) -> list[str]:
        """OAuth `scope` is a single space-delimited string (RFC 8693)."""
        value = self.raw.get("scope")
        if isinstance(value, str):
            return value.split()
        if isinstance(value, list):
            return [str(v) for v in value]
        return []


class JWT:
    """Mint JWTs."""

    def __init__(self, clock: Clock | None = None) -> None:
        self.clock = clock or SystemClock()

    def issue(
        self,
        key: Any,
        algorithm: Algorithm,
        *,
        issuer: str,
        subject: str,
        audience: str | Sequence[str],
        lifetime: int = 300,
        not_before: int | None = None,
        extra_claims: dict[str, Any] | None = None,
        kid: str | None = None,
        typ: str = "JWT",
        jti: str | None = None,
    ) -> str:
        """Mint a signed JWT with the registered claims filled in.

        Default lifetime is 5 minutes. An access token that lives for hours is
        a revocation problem you cannot solve: there is no way to withdraw a
        stateless token before it expires, so "short" is the only lever.
        """
        now = self.clock.now()
        claims: dict[str, Any] = {
            "iss": issuer,
            "sub": subject,
            "aud": list(audience) if not isinstance(audience, str) else audience,
            "iat": now,
            "exp": now + lifetime,
            "jti": jti or random_token(16),
        }
        if not_before is not None:
            claims["nbf"] = not_before
        if extra_claims:
            claims.update(extra_claims)
        return JWS.sign(claims, key, algorithm, kid=kid, typ=typ)

    @staticmethod
    def peek(token: str) -> JWTClaims:
        """Read claims WITHOUT verifying. For logging and debugging only.

        Named `peek` rather than `decode` on purpose. Every JWT library that
        called this `decode()` produced a generation of code that decoded and
        then used the result.
        """
        import json

        parsed = JWS.parse(token)
        try:
            return JWTClaims(json.loads(parsed.payload.decode("utf-8")))
        except Exception as exc:  # noqa: BLE001
            raise InvalidToken(f"payload is not JSON: {exc}") from exc


@dataclass
class JWTValidator:
    """Verify a JWT's signature and then every claim that matters.

    Construct one per (issuer, audience) pair you accept -- a resource server
    validating tokens from two IdPs should hold two validators, not one loose
    one.
    """

    issuer: str
    audience: str
    allowed_algorithms: Sequence[str | Algorithm]
    key: Any | Callable[[dict[str, Any]], Any]
    clock: Clock = field(default_factory=SystemClock)
    leeway: int = 60
    require_claims: Iterable[str] = ("iss", "sub", "aud", "exp", "iat")
    max_age: int | None = None
    expected_typ: str | None = None

    def validate(self, token: str, *, nonce: str | None = None) -> JWTClaims:
        """Verify signature then claims. Raises on the first failure."""
        import json

        parsed: ParsedJWS = JWS.verify(token, self.key, self.allowed_algorithms)

        if self.expected_typ is not None:
            typ = parsed.header.get("typ")
            # Compared case-insensitively: RFC 7519 says typ is case-sensitive
            # in principle but recommends tolerating case for legacy senders.
            if typ is None or str(typ).lower() != self.expected_typ.lower():
                raise ClaimError(f"unexpected typ header: {typ!r} (want {self.expected_typ!r})")

        try:
            payload = json.loads(parsed.payload.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise InvalidToken(f"payload is not JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise InvalidToken("JWT payload must be a JSON object")
        claims = JWTClaims(payload)

        for name in self.require_claims:
            if name not in claims.raw:
                raise ClaimError(f"missing required claim: {name}")

        if claims.iss != self.issuer:
            raise ClaimError(f"issuer mismatch: {claims.iss!r} (want {self.issuer!r})")

        if self.audience not in claims.aud:
            # The check that stops an ID token being replayed at an API.
            raise ClaimError(f"aud mismatch: {claims.aud!r} does not contain {self.audience!r}")

        now = self.clock.now()

        exp = claims.exp
        if exp is not None:
            if not isinstance(exp, (int, float)):
                raise ClaimError("exp must be a number")
            if now > exp + self.leeway:
                raise ExpiredToken(f"token expired at {int(exp)}, now {now}")

        nbf = claims.nbf
        if nbf is not None:
            if not isinstance(nbf, (int, float)):
                raise ClaimError("nbf must be a number")
            if now + self.leeway < nbf:
                raise ExpiredToken(f"token not valid before {int(nbf)}, now {now}")

        iat = claims.iat
        if iat is not None:
            if not isinstance(iat, (int, float)):
                raise ClaimError("iat must be a number")
            # A token minted in the future means a broken clock or a forged
            # claim; either way it is not something to accept quietly.
            if iat > now + self.leeway:
                raise ClaimError(f"iat is in the future: {int(iat)} > {now}")
            if self.max_age is not None and now - iat > self.max_age + self.leeway:
                raise ExpiredToken(f"token older than max_age={self.max_age}s")

        if nonce is not None:
            # OIDC: the nonce binds an ID token to the browser session that
            # started the flow, which is what stops a stolen-but-valid ID
            # token from being injected into someone else's login.
            actual = claims.get("nonce")
            if actual is None:
                raise ClaimError("nonce required but absent from token")
            from ..util.ct import constant_time_equals

            if not constant_time_equals(str(actual), nonce):
                raise ClaimError("nonce mismatch")

        return claims
