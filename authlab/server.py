"""A tiny HTTP wrapper so the OAuth/OIDC server can be driven with curl.

This exists so a drill can be "run this, then curl these endpoints" rather
than only "call these Python functions". It is a thin translation layer over
AuthorizationServer -- every real decision still lives in authlab.oauth. It is
NOT hardened for the public internet; it is a teaching harness.

Run it:  python -m authlab.server
Then:    curl http://127.0.0.1:8080/.well-known/openid-configuration
"""

from __future__ import annotations

import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .oauth import AuthorizationServer, Client, OAuthError, User, pkce
from .oauth.resource_server import Forbidden, ResourceServer, Unauthorized
from .passwords import PasswordHasher


def build_demo_server(issuer: str = "http://127.0.0.1:8080") -> AuthorizationServer:
    """A ready-to-poke AS with one user and a couple of clients."""
    hasher = PasswordHasher()
    server = AuthorizationServer(issuer=issuer)
    server.register_client(
        Client(
            client_id="web-app",
            redirect_uris=["http://127.0.0.1:9090/callback"],
            scopes=["openid", "profile", "email", "orders:read", "orders:write", "offline_access"],
            token_endpoint_auth_method="none",
            require_pkce=True,
            name="Demo SPA",
        )
    )
    server.register_client(
        Client(
            client_id="service",
            client_secret="service-secret",
            grant_types=["client_credentials"],
            scopes=["orders:read"],
            response_types=[],
            name="Batch job",
        )
    )
    server.register_user(
        User(
            subject="u-alice",
            username="alice",
            password_hash=hasher.hash("password123"),
            email="alice@auth-lab.local",
            email_verified=True,
            name="Alice Example",
        )
    )
    return server


class Handler(BaseHTTPRequestHandler):
    server_version = "authlab/1.0"
    authorization_server: AuthorizationServer
    hasher: PasswordHasher

    def log_message(self, format: str, *args) -> None:  # quieter output
        pass

    # -- helpers ------------------------------------------------------

    def _json(self, status: int, body: dict) -> None:
        payload = json.dumps(body, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def _basic_auth(self) -> tuple[str, str] | None:
        header = self.headers.get("Authorization", "")
        if header.startswith("Basic "):
            decoded = base64.b64decode(header[6:]).decode("utf-8")
            client_id, _, secret = decoded.partition(":")
            return client_id, secret
        return None

    # -- routing ------------------------------------------------------

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path, query = parsed.path, {k: v[0] for k, v in parse_qs(parsed.query).items()}
        server = self.authorization_server

        if path in ("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"):
            self._json(200, server.metadata())
        elif path == "/.well-known/jwks.json":
            self._json(200, server.jwks_document())
        elif path == "/authorize":
            self._authorize(query)
        elif path == "/userinfo":
            self._userinfo()
        elif path == "/":
            self._json(200, {"service": "authlab demo", "discovery": "/.well-known/openid-configuration"})
        else:
            self._json(404, {"error": "not_found", "path": path})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        server = self.authorization_server
        form = self._form()

        try:
            if path == "/token":
                dpop = self.headers.get("DPoP")
                result = server.token(
                    form, basic_auth=self._basic_auth(), dpop_proof=dpop,
                    token_endpoint_url=f"{server.issuer}/token",
                )
                self._json(200, result)
            elif path == "/introspect":
                auth = self._basic_auth()
                if auth is None:
                    self._json(401, {"error": "invalid_client"})
                    return
                client = server.authenticate_client({}, basic_auth=auth)
                self._json(200, server.introspect(form.get("token", ""), client))
            elif path == "/revoke":
                auth = self._basic_auth()
                client = server.authenticate_client({}, basic_auth=auth) if auth else None
                if client:
                    server.revoke(form.get("token", ""), client)
                self._json(200, {})
            elif path == "/device_authorization":
                self._json(200, server.device_authorization(form))
            elif path == "/login":
                self._login(form)
            else:
                self._json(404, {"error": "not_found", "path": path})
        except OAuthError as exc:
            self._json(exc.status, exc.to_dict())

    # -- endpoints ----------------------------------------------------

    def _authorize(self, query: dict[str, str]) -> None:
        server = self.authorization_server
        try:
            validated = server.validate_authorization_request(query)
        except OAuthError as exc:
            self._json(exc.status, exc.to_dict())
            return
        # A real AS renders a login form here. For the demo we auto-approve
        # the seeded user so the flow can be scripted end to end.
        code = server.issue_authorization_code(validated, "u-alice", amr=["pwd"])
        location = server.authorization_redirect(validated, code)
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def _userinfo(self) -> None:
        server = self.authorization_server
        rs = ResourceServer(
            audience=server.known_resources[0] if server.known_resources else server.issuer,
            issuer=server.issuer,
            jwks=server.jwks,
            require_typ=None,  # userinfo accepts the access token as-is
        )
        try:
            claims = rs.authenticate(self.headers.get("Authorization"))
        except (Unauthorized, Forbidden) as exc:
            self.send_response(exc.status)
            self.send_header("WWW-Authenticate", 'Bearer error="invalid_token"')
            self.end_headers()
            return
        user = server.store.users.get(claims.sub or "")
        body = {"sub": claims.sub}
        if user:
            body.update(
                {"name": user.name, "preferred_username": user.username, "email": user.email,
                 "email_verified": user.email_verified}
            )
        self._json(200, body)

    def _login(self, form: dict[str, str]) -> None:
        """Verify a username/password, for demonstrating password auth over HTTP."""
        server = self.authorization_server
        user = server.store.user_by_username(form.get("username", ""))
        password = form.get("password", "")
        if user is None:
            self.hasher.fake_verify(password)  # constant time for unknown users
            self._json(401, {"error": "invalid_credentials"})
            return
        if self.hasher.verify(password, user.password_hash):
            self._json(200, {"authenticated": True, "sub": user.subject})
        else:
            self._json(401, {"error": "invalid_credentials"})


def main(port: int = 8080) -> None:
    server = build_demo_server(issuer=f"http://127.0.0.1:{port}")
    Handler.authorization_server = server
    Handler.hasher = PasswordHasher()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"authlab demo AS on http://127.0.0.1:{port}")
    print(f"  discovery: http://127.0.0.1:{port}/.well-known/openid-configuration")
    print(f"  jwks:      http://127.0.0.1:{port}/.well-known/jwks.json")
    print("Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")


if __name__ == "__main__":
    import sys

    main(int(sys.argv[1]) if len(sys.argv) > 1 else 8080)
