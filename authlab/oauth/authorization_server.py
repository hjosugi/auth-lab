"""An OAuth 2.0 authorization server.

Grants implemented:
  authorization_code  (RFC 6749 4.1) with mandatory PKCE (RFC 7636)
  refresh_token       (RFC 6749 6) with rotation and reuse detection
  client_credentials  (RFC 6749 4.4) for machine-to-machine
  device_code         (RFC 8628) for TVs and CLIs

Deliberately NOT implemented, because OAuth 2.1 removes them:
  implicit ("response_type=token") -- returns the access token in the URL
      fragment, so it lands in browser history, referrer headers, and every
      analytics script on the page. Replaced by authorization_code + PKCE.
  resource owner password credentials -- the client handles the user's actual
      password, which defeats the point of OAuth and makes MFA and federation
      impossible. Replaced by the device or authorization code flow.

Also implemented: introspection (RFC 7662), revocation (RFC 7009),
resource indicators (RFC 8707), and sender-constrained tokens via DPoP
(RFC 9449) and mTLS (RFC 8705).

The API is plain Python -- `authorize()`, `token()`, `introspect()` -- so
drills can drive the protocol without a socket. authlab.web wraps it in HTTP.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlsplit

from ..jose.jwks import JWK, JWKSet
from ..jose.jws import RS256
from ..jose.jwt import JWT
from ..util.clock import Clock, SystemClock
from ..util.ct import constant_time_equals, random_token
from ..util.encoding import b64u_encode
from . import pkce
from .dpop import DPoPVerifier, jkt
from .errors import (
    AccessDenied,
    AuthorizationPending,
    ExpiredTokenError,
    InvalidClient,
    InvalidDPoPProof,
    InvalidGrant,
    InvalidRequest,
    InvalidScope,
    InvalidTarget,
    SlowDown,
    UnauthorizedClient,
    UnsupportedGrantType,
    UnsupportedResponseType,
)
from .models import (
    AccessToken,
    AuthorizationCode,
    Client,
    DeviceCode,
    RefreshToken,
    Store,
    User,
)

# A user_code a human has to read off a TV screen and type on a phone.
# The alphabet omits vowels (so no accidental words) and the digits and
# letters that look alike.
USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"


@dataclass
class AuthorizationServer:
    """The AS. Holds the store, the signing keys, and the policy."""

    issuer: str = "https://as.auth-lab.local"
    store: Store = field(default_factory=Store)
    clock: Clock = field(default_factory=SystemClock)
    access_token_lifetime: int = 300        # 5 minutes
    refresh_token_lifetime: int = 1_209_600 # 14 days
    code_lifetime: int = 60                 # RFC 6749: "maximum of 10 minutes"; 1 is plenty
    device_code_lifetime: int = 600
    id_token_lifetime: int = 300
    jwt_access_tokens: bool = True
    signing_key: Any = None
    signing_kid: str = "as-sign-1"
    jwks: JWKSet = field(default_factory=JWKSet)
    dpop: DPoPVerifier | None = None
    supported_scopes: list[str] = field(
        default_factory=lambda: [
            "openid", "profile", "email", "offline_access",
            "orders:read", "orders:write", "admin",
        ]
    )
    known_resources: list[str] = field(default_factory=lambda: ["https://api.auth-lab.local"])

    def __post_init__(self) -> None:
        if self.signing_key is None:
            from ..crypto.rsa import generate_rsa_keypair

            self.signing_key = generate_rsa_keypair(2048)
        if not self.jwks.keys:
            self.jwks.add(JWK.from_rsa_public(self.signing_key.public, kid=self.signing_kid))
        if self.dpop is None:
            self.dpop = DPoPVerifier(clock=self.clock)
        self._jwt = JWT(self.clock)

    # ------------------------------------------------------------------
    # registration helpers
    # ------------------------------------------------------------------

    def register_client(self, client: Client) -> Client:
        if not client.redirect_uris and "authorization_code" in client.grant_types:
            raise InvalidRequest("an authorization_code client needs at least one redirect_uri")
        for uri in client.redirect_uris:
            self._assert_registrable_redirect_uri(uri)
        self.store.clients[client.client_id] = client
        return client

    def register_user(self, user: User) -> User:
        self.store.users[user.subject] = user
        return user

    @staticmethod
    def _assert_registrable_redirect_uri(uri: str) -> None:
        """Reject redirect URIs that are dangerous to register at all."""
        parts = urlsplit(uri)
        if parts.fragment:
            raise InvalidRequest("redirect_uri must not contain a fragment")
        if "*" in uri:
            # Wildcards are how "https://*.example.com" becomes
            # "https://evil.example.com.attacker.net".
            raise InvalidRequest("wildcard redirect_uris are not allowed")
        if parts.scheme in ("http", "https") and not parts.netloc:
            raise InvalidRequest("redirect_uri must be absolute")
        if parts.scheme == "http" and parts.hostname not in ("localhost", "127.0.0.1", "[::1]"):
            # http is permitted only for native apps on loopback (RFC 8252).
            raise InvalidRequest("http redirect_uris are only allowed on loopback")

    # ------------------------------------------------------------------
    # authorization endpoint
    # ------------------------------------------------------------------

    def validate_authorization_request(self, params: dict[str, str]) -> dict[str, Any]:
        """Validate an /authorize request BEFORE showing a login page.

        Order matters. client_id and redirect_uri are validated first and
        their failures must render an error page, never redirect -- see
        errors.py. Everything after that may be reported back to the client
        by redirecting with `error=`.
        """
        client_id = params.get("client_id")
        if not client_id:
            raise InvalidRequest("client_id is required")
        client = self.store.clients.get(client_id)
        if client is None:
            raise InvalidClient(f"unknown client_id: {client_id!r}")

        redirect_uri = params.get("redirect_uri")
        if not redirect_uri:
            if len(client.redirect_uris) != 1:
                raise InvalidRequest("redirect_uri is required when several are registered")
            redirect_uri = client.redirect_uris[0]
        # EXACT string match against the registered set. Not prefix, not
        # startswith, not "same host". Prefix matching is how
        # https://app.example/cb is turned into
        # https://app.example/cb.attacker.net or .../cb/../../open-redirect.
        if not any(constant_time_equals(redirect_uri, r) for r in client.redirect_uris):
            raise InvalidRequest(f"redirect_uri {redirect_uri!r} is not registered for this client")

        response_type = params.get("response_type", "")
        if response_type not in client.response_types:
            raise UnsupportedResponseType(f"response_type {response_type!r} not allowed")
        if response_type != "code":
            # Guard rail: this server issues codes only.
            raise UnsupportedResponseType("only response_type=code is supported (OAuth 2.1)")

        scope = (params.get("scope") or "").split()
        unknown = [s for s in scope if s not in self.supported_scopes]
        if unknown:
            raise InvalidScope(f"unknown scope(s): {' '.join(unknown)}")
        not_allowed = [s for s in scope if client.scopes and s not in client.scopes]
        if not_allowed:
            raise InvalidScope(f"client may not request: {' '.join(not_allowed)}")

        challenge = params.get("code_challenge")
        method = params.get("code_challenge_method", "plain")
        if client.require_pkce or client.is_public:
            if not challenge:
                # Without this the whole mechanism is opt-out by the attacker.
                raise InvalidRequest("code_challenge is required (PKCE)")
            if method != "S256":
                raise InvalidRequest("code_challenge_method must be S256")

        state = params.get("state")
        if not state:
            # Not strictly required by RFC 6749, but a client without state
            # has no CSRF defence on its redirect endpoint, so we refuse.
            raise InvalidRequest("state is required by this server (CSRF defence)")

        resource = params.get("resource")
        resources = [resource] if isinstance(resource, str) and resource else []
        for target in resources:
            if target not in self.known_resources:
                raise InvalidTarget(f"unknown resource: {target!r}")

        return {
            "client": client,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "nonce": params.get("nonce"),
            "code_challenge": challenge,
            "code_challenge_method": method if challenge else "S256",
            "resource": resources,
            "dpop_jkt": params.get("dpop_jkt"),
        }

    def issue_authorization_code(
        self,
        validated: dict[str, Any],
        subject: str,
        amr: list[str] | None = None,
        auth_time: int | None = None,
    ) -> str:
        """Mint a code after the user has actually authenticated."""
        now = self.clock.now()
        code = AuthorizationCode(
            code=random_token(32),
            client_id=validated["client"].client_id,
            subject=subject,
            redirect_uri=validated["redirect_uri"],
            scope=validated["scope"],
            expires_at=now + self.code_lifetime,
            code_challenge=validated.get("code_challenge"),
            code_challenge_method=validated.get("code_challenge_method", "S256"),
            nonce=validated.get("nonce"),
            amr=amr or ["pwd"],
            auth_time=auth_time if auth_time is not None else now,
            resource=validated.get("resource", []),
            dpop_jkt=validated.get("dpop_jkt"),
        )
        self.store.codes[code.code] = code
        self.store.log("code_issued", f"code for {subject} / {code.client_id}")
        return code.code

    def authorization_redirect(self, validated: dict[str, Any], code: str) -> str:
        """Build the 302 Location for a successful authorization."""
        query = urlencode({"code": code, "state": validated["state"]})
        separator = "&" if urlsplit(validated["redirect_uri"]).query else "?"
        return f"{validated['redirect_uri']}{separator}{query}"

    def error_redirect(self, redirect_uri: str, state: str | None, error: str, description: str) -> str:
        params = {"error": error, "error_description": description}
        if state:
            params["state"] = state
        separator = "&" if urlsplit(redirect_uri).query else "?"
        return f"{redirect_uri}{separator}{urlencode(params)}"

    # ------------------------------------------------------------------
    # client authentication
    # ------------------------------------------------------------------

    def authenticate_client(
        self, params: dict[str, str], *, basic_auth: tuple[str, str] | None = None,
        tls_client_cert_thumbprint: str | None = None,
    ) -> Client:
        """Authenticate the client at the token endpoint."""
        if basic_auth is not None:
            client_id, secret = basic_auth
        else:
            client_id = params.get("client_id", "")
            secret = params.get("client_secret", "")

        if not client_id:
            raise InvalidClient("client_id is required")
        client = self.store.clients.get(client_id)
        if client is None:
            # Same error and same timing as a bad secret: distinguishing them
            # turns the token endpoint into a client enumeration oracle.
            raise InvalidClient("client authentication failed")

        if client.token_endpoint_auth_method == "none":
            if secret:
                raise InvalidClient("public client must not send a client_secret")
            return client

        if client.token_endpoint_auth_method == "tls_client_auth":
            if tls_client_cert_thumbprint is None:
                raise InvalidClient("client authentication failed")
            return client

        if not client.client_secret or not constant_time_equals(secret or "", client.client_secret):
            raise InvalidClient("client authentication failed")
        return client

    # ------------------------------------------------------------------
    # token endpoint
    # ------------------------------------------------------------------

    def token(
        self,
        params: dict[str, str],
        *,
        basic_auth: tuple[str, str] | None = None,
        dpop_proof: str | None = None,
        token_endpoint_url: str | None = None,
        tls_client_cert_thumbprint: str | None = None,
    ) -> dict[str, Any]:
        """The token endpoint. Dispatches on grant_type."""
        grant_type = params.get("grant_type")
        if not grant_type:
            raise InvalidRequest("grant_type is required")

        client = self.authenticate_client(
            params, basic_auth=basic_auth,
            tls_client_cert_thumbprint=tls_client_cert_thumbprint,
        )
        if grant_type not in client.grant_types:
            raise UnauthorizedClient(f"client may not use grant_type={grant_type!r}")

        cnf_jkt = None
        if dpop_proof is not None:
            url = token_endpoint_url or f"{self.issuer}/token"
            cnf_jkt = self.dpop.verify(dpop_proof, "POST", url)
        elif client.require_dpop:
            raise InvalidDPoPProof("this client must present a DPoP proof")

        cnf_x5t = tls_client_cert_thumbprint if client.tls_client_certificate_bound_access_tokens else None

        if grant_type == "authorization_code":
            return self._grant_authorization_code(client, params, cnf_jkt, cnf_x5t)
        if grant_type == "refresh_token":
            return self._grant_refresh_token(client, params, cnf_jkt, cnf_x5t)
        if grant_type == "client_credentials":
            return self._grant_client_credentials(client, params, cnf_jkt, cnf_x5t)
        if grant_type == "urn:ietf:params:oauth:grant-type:device_code":
            return self._grant_device_code(client, params, cnf_jkt, cnf_x5t)
        raise UnsupportedGrantType(f"unsupported grant_type: {grant_type!r}")

    def _grant_authorization_code(
        self, client: Client, params: dict[str, str], cnf_jkt: str | None, cnf_x5t: str | None
    ) -> dict[str, Any]:
        code_value = params.get("code")
        if not code_value:
            raise InvalidRequest("code is required")
        code = self.store.codes.get(code_value)
        if code is None:
            raise InvalidGrant("invalid or unknown code")

        if code.used:
            # A code is single use. A second presentation means either the
            # client retried badly or the code leaked and someone else got
            # there first. We cannot tell which, so we assume the worst and
            # revoke everything the code produced (RFC 6749 section 4.1.2).
            self.store.log("code_replay", f"code replayed for {code.subject}")
            revoked = self.store.revoke_access_for_family_subject(code.client_id, code.subject)
            for token in self.store.refresh_tokens.values():
                if token.client_id == code.client_id and token.subject == code.subject:
                    token.revoked = True
                    revoked += 1
            raise InvalidGrant(f"code replay detected: {revoked} token(s) revoked")

        if code.client_id != client.client_id:
            # A code minted for client A must not be redeemable by client B,
            # even if B authenticates correctly.
            raise InvalidGrant("code was not issued to this client")
        if self.clock.now() > code.expires_at:
            raise InvalidGrant("code has expired")

        redirect_uri = params.get("redirect_uri")
        if redirect_uri is None or not constant_time_equals(redirect_uri, code.redirect_uri):
            # Re-checking the redirect_uri at redemption stops a code obtained
            # via one (attacker-influenced) URI being spent against another.
            raise InvalidGrant("redirect_uri does not match the authorization request")

        if code.code_challenge:
            pkce.verify(
                params.get("code_verifier", ""),
                code.code_challenge,
                code.code_challenge_method,
            )
        elif client.is_public:
            raise InvalidGrant("PKCE is required for public clients")

        if code.dpop_jkt and code.dpop_jkt != cnf_jkt:
            raise InvalidDPoPProof("DPoP key does not match the dpop_jkt from the authorization request")

        code.used = True
        self.store.log("code_redeemed", f"{code.subject} / {client.client_id}")

        return self._issue_token_set(
            client=client,
            subject=code.subject,
            scope=code.scope,
            nonce=code.nonce,
            amr=code.amr,
            auth_time=code.auth_time,
            audience=code.resource or self.known_resources[:1],
            cnf_jkt=cnf_jkt,
            cnf_x5t=cnf_x5t,
            include_refresh=True,
        )

    def _grant_refresh_token(
        self, client: Client, params: dict[str, str], cnf_jkt: str | None, cnf_x5t: str | None
    ) -> dict[str, Any]:
        value = params.get("refresh_token")
        if not value:
            raise InvalidRequest("refresh_token is required")
        token = self.store.refresh_tokens.get(value)
        if token is None:
            raise InvalidGrant("invalid refresh token")

        if token.used or token.revoked:
            # Rotation reuse detection. A rotated token is never valid twice;
            # seeing it again means two parties hold tokens from one family,
            # and one of them is not the user. Kill the whole family.
            count = self.store.revoke_refresh_family(token.family_id)
            self.store.revoke_access_for_family_subject(token.client_id, token.subject)
            self.store.log(
                "refresh_reuse",
                f"reuse of family {token.family_id[:8]}: {count} token(s) revoked",
            )
            raise InvalidGrant(f"refresh token reuse detected: family revoked ({count} tokens)")

        if token.client_id != client.client_id:
            raise InvalidGrant("refresh token was not issued to this client")
        if self.clock.now() > token.expires_at:
            raise InvalidGrant("refresh token has expired")

        if token.cnf_jkt and token.cnf_jkt != cnf_jkt:
            raise InvalidDPoPProof("refresh token is bound to a different DPoP key")
        if token.cnf_x5t and token.cnf_x5t != cnf_x5t:
            raise InvalidGrant("refresh token is bound to a different client certificate")

        requested = (params.get("scope") or "").split()
        if requested:
            # Scope may be narrowed on refresh, never widened -- otherwise a
            # leaked read-only token upgrades itself to admin.
            widened = [s for s in requested if s not in token.scope]
            if widened:
                raise InvalidScope(f"cannot widen scope on refresh: {' '.join(widened)}")
            scope = requested
        else:
            scope = token.scope

        token.used = True
        result = self._issue_token_set(
            client=client,
            subject=token.subject,
            scope=scope,
            nonce=None,
            amr=[],
            auth_time=0,
            audience=self.known_resources[:1],
            cnf_jkt=token.cnf_jkt or cnf_jkt,
            cnf_x5t=token.cnf_x5t or cnf_x5t,
            include_refresh=True,
            family_id=token.family_id,
            issue_id_token=False,
        )
        token.rotated_to = result["refresh_token"]
        return result

    def _grant_client_credentials(
        self, client: Client, params: dict[str, str], cnf_jkt: str | None, cnf_x5t: str | None
    ) -> dict[str, Any]:
        if client.is_public:
            # There is no "confidential" about a client that ships its secret
            # to a browser, so machine-to-machine is off the table for it.
            raise UnauthorizedClient("public clients cannot use client_credentials")
        scope = (params.get("scope") or " ".join(client.scopes)).split()
        not_allowed = [s for s in scope if client.scopes and s not in client.scopes]
        if not_allowed:
            raise InvalidScope(f"client may not request: {' '.join(not_allowed)}")

        # No user is involved, so there is no subject, no refresh token
        # (just ask again -- you have the secret), and no ID token.
        return self._issue_token_set(
            client=client,
            subject=None,
            scope=scope,
            nonce=None,
            amr=[],
            auth_time=0,
            audience=self.known_resources[:1],
            cnf_jkt=cnf_jkt,
            cnf_x5t=cnf_x5t,
            include_refresh=False,
            issue_id_token=False,
        )

    def _grant_device_code(
        self, client: Client, params: dict[str, str], cnf_jkt: str | None, cnf_x5t: str | None
    ) -> dict[str, Any]:
        value = params.get("device_code")
        if not value:
            raise InvalidRequest("device_code is required")
        device = self.store.device_codes.get(value)
        if device is None or device.client_id != client.client_id:
            raise InvalidGrant("invalid device_code")
        now = self.clock.now()
        if now > device.expires_at:
            raise ExpiredTokenError("device_code has expired")
        if device.denied:
            raise AccessDenied("the user denied the request")
        if not device.approved:
            # Rate limiting is part of the spec, not an add-on: a device that
            # polls in a tight loop is indistinguishable from a brute force
            # against the user_code space.
            if device.last_polled_at and now - device.last_polled_at < device.interval:
                device.last_polled_at = now
                raise SlowDown("polling faster than the interval")
            device.last_polled_at = now
            raise AuthorizationPending("the user has not approved yet")

        del self.store.device_codes[value]  # single use
        return self._issue_token_set(
            client=client,
            subject=device.subject,
            scope=device.scope,
            nonce=None,
            amr=device.amr,
            auth_time=now,
            audience=self.known_resources[:1],
            cnf_jkt=cnf_jkt,
            cnf_x5t=cnf_x5t,
            include_refresh=True,
        )

    # ------------------------------------------------------------------
    # token minting
    # ------------------------------------------------------------------

    def _issue_token_set(
        self,
        client: Client,
        subject: str | None,
        scope: list[str],
        nonce: str | None,
        amr: list[str],
        auth_time: int,
        audience: list[str],
        cnf_jkt: str | None,
        cnf_x5t: str | None,
        include_refresh: bool,
        family_id: str | None = None,
        issue_id_token: bool = True,
    ) -> dict[str, Any]:
        now = self.clock.now()
        token_type = "DPoP" if cnf_jkt else "Bearer"

        extra: dict[str, Any] = {"scope": " ".join(scope), "client_id": client.client_id}
        cnf: dict[str, str] = {}
        if cnf_jkt:
            cnf["jkt"] = cnf_jkt
        if cnf_x5t:
            cnf["x5t#S256"] = cnf_x5t
        if cnf:
            extra["cnf"] = cnf

        if self.jwt_access_tokens:
            access_value = self._jwt.issue(
                self.signing_key,
                RS256,
                issuer=self.issuer,
                subject=subject or f"client:{client.client_id}",
                audience=audience or [self.issuer],
                lifetime=self.access_token_lifetime,
                kid=self.signing_kid,
                # RFC 9068: an access token must be typed so it can never be
                # mistaken for an ID token by a resource server.
                typ="at+jwt",
                extra_claims=extra,
            )
        else:
            access_value = random_token(32)

        access = AccessToken(
            token=access_value,
            client_id=client.client_id,
            subject=subject,
            scope=scope,
            expires_at=now + self.access_token_lifetime,
            issued_at=now,
            token_type=token_type,
            audience=audience,
            cnf_jkt=cnf_jkt,
            cnf_x5t=cnf_x5t,
        )
        self.store.access_tokens[access_value] = access

        response: dict[str, Any] = {
            "access_token": access_value,
            "token_type": token_type,
            "expires_in": self.access_token_lifetime,
            "scope": " ".join(scope),
        }

        if include_refresh and subject is not None:
            refresh_value = random_token(32)
            self.store.refresh_tokens[refresh_value] = RefreshToken(
                token=refresh_value,
                client_id=client.client_id,
                subject=subject,
                scope=scope,
                expires_at=now + self.refresh_token_lifetime,
                family_id=family_id or random_token(16),
                cnf_jkt=cnf_jkt,
                cnf_x5t=cnf_x5t,
            )
            response["refresh_token"] = refresh_value

        if issue_id_token and subject is not None and "openid" in scope:
            response["id_token"] = self.issue_id_token(
                client, subject, nonce, amr, auth_time, access_value
            )
        return response

    def issue_id_token(
        self,
        client: Client,
        subject: str,
        nonce: str | None,
        amr: list[str],
        auth_time: int,
        access_token: str | None = None,
    ) -> str:
        """Mint an OIDC ID token.

        Note the audience: an ID token's `aud` is the CLIENT, not the API.
        That is the whole reason an ID token must never be sent to a resource
        server as a credential -- and why a correctly written resource server
        rejects it. The RS expects aud=itself.
        """
        user = self.store.users.get(subject)
        claims: dict[str, Any] = {"auth_time": auth_time or self.clock.now()}
        if nonce:
            claims["nonce"] = nonce
        if amr:
            claims["amr"] = amr
        if access_token:
            # `at_hash` binds the ID token to the access token delivered with
            # it: left-most half of SHA-256 of the access token, base64url.
            digest = hashlib.sha256(access_token.encode("ascii")).digest()
            claims["at_hash"] = b64u_encode(digest[: len(digest) // 2])
        if user:
            claims.update({"preferred_username": user.username})
            if user.email:
                claims["email"] = user.email
                claims["email_verified"] = user.email_verified
            if user.name:
                claims["name"] = user.name
        return self._jwt.issue(
            self.signing_key,
            RS256,
            issuer=self.issuer,
            subject=subject,
            audience=client.client_id,
            lifetime=self.id_token_lifetime,
            kid=self.signing_kid,
            typ="JWT",
            extra_claims=claims,
        )

    # ------------------------------------------------------------------
    # device authorization (RFC 8628)
    # ------------------------------------------------------------------

    def device_authorization(self, params: dict[str, str]) -> dict[str, Any]:
        client_id = params.get("client_id")
        client = self.store.clients.get(client_id or "")
        if client is None:
            raise InvalidClient("unknown client")
        scope = (params.get("scope") or "").split()
        now = self.clock.now()
        import secrets

        user_code = "".join(secrets.choice(USER_CODE_ALPHABET) for _ in range(8))
        device = DeviceCode(
            device_code=random_token(32),
            user_code=f"{user_code[:4]}-{user_code[4:]}",
            client_id=client.client_id,
            scope=scope,
            expires_at=now + self.device_code_lifetime,
            interval=5,
        )
        self.store.device_codes[device.device_code] = device
        return {
            "device_code": device.device_code,
            "user_code": device.user_code,
            "verification_uri": f"{self.issuer}/device",
            "verification_uri_complete": f"{self.issuer}/device?user_code={device.user_code}",
            "expires_in": self.device_code_lifetime,
            "interval": device.interval,
        }

    def approve_device(self, user_code: str, subject: str, amr: list[str] | None = None) -> bool:
        """The user, on their phone, approves the TV."""
        normalized = user_code.strip().upper()
        for device in self.store.device_codes.values():
            if constant_time_equals(device.user_code, normalized):
                if self.clock.now() > device.expires_at:
                    raise ExpiredTokenError("this code has expired")
                device.approved = True
                device.subject = subject
                device.amr = amr or ["pwd"]
                return True
        return False

    def deny_device(self, user_code: str) -> bool:
        normalized = user_code.strip().upper()
        for device in self.store.device_codes.values():
            if constant_time_equals(device.user_code, normalized):
                device.denied = True
                return True
        return False

    # ------------------------------------------------------------------
    # introspection (RFC 7662) and revocation (RFC 7009)
    # ------------------------------------------------------------------

    def introspect(self, token_value: str, client: Client | None = None) -> dict[str, Any]:
        """Report on a token.

        The endpoint MUST be authenticated -- an open introspection endpoint
        is a free token-validity oracle. And an unknown token returns exactly
        `{"active": false}` with no hint about why.
        """
        record = self.store.access_tokens.get(token_value)
        now = self.clock.now()
        if record is None or record.revoked or now > record.expires_at:
            return {"active": False}
        body = {
            "active": True,
            "scope": " ".join(record.scope),
            "client_id": record.client_id,
            "token_type": record.token_type,
            "exp": record.expires_at,
            "iat": record.issued_at,
            "iss": self.issuer,
            "aud": record.audience,
            "jti": record.jti,
        }
        if record.subject:
            body["sub"] = record.subject
            user = self.store.users.get(record.subject)
            if user:
                body["username"] = user.username
        cnf = {}
        if record.cnf_jkt:
            cnf["jkt"] = record.cnf_jkt
        if record.cnf_x5t:
            cnf["x5t#S256"] = record.cnf_x5t
        if cnf:
            body["cnf"] = cnf
        return body

    def revoke(self, token_value: str, client: Client, token_type_hint: str | None = None) -> None:
        """Revoke a token.

        RFC 7009 says respond 200 even for an unknown token -- otherwise the
        endpoint tells an attacker which of their guesses were real tokens.
        Revoking a refresh token takes its whole family with it.
        """
        access = self.store.access_tokens.get(token_value)
        if access is not None and access.client_id == client.client_id:
            access.revoked = True
            self.store.log("revoked", f"access token for {access.subject}")
            return
        refresh = self.store.refresh_tokens.get(token_value)
        if refresh is not None and refresh.client_id == client.client_id:
            count = self.store.revoke_refresh_family(refresh.family_id)
            self.store.log("revoked", f"refresh family {refresh.family_id[:8]} ({count} tokens)")

    # ------------------------------------------------------------------
    # metadata
    # ------------------------------------------------------------------

    def metadata(self) -> dict[str, Any]:
        """RFC 8414 authorization server metadata / OIDC discovery."""
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "userinfo_endpoint": f"{self.issuer}/userinfo",
            "jwks_uri": f"{self.issuer}/.well-known/jwks.json",
            "introspection_endpoint": f"{self.issuer}/introspect",
            "revocation_endpoint": f"{self.issuer}/revoke",
            "device_authorization_endpoint": f"{self.issuer}/device_authorization",
            "end_session_endpoint": f"{self.issuer}/logout",
            "scopes_supported": self.supported_scopes,
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
                "tls_client_auth",
            ],
            "code_challenge_methods_supported": ["S256"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "claims_supported": [
                "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "amr",
                "email", "email_verified", "name", "preferred_username",
            ],
            "tls_client_certificate_bound_access_tokens": True,
        }

    def jwks_document(self) -> dict[str, Any]:
        return self.jwks.public_set()
