import unittest

from authlab.oauth import (
    AuthorizationServer,
    Client,
    DPoPClientKey,
    InvalidGrant,
    InvalidRequest,
    InvalidScope,
    OAuthClient,
    ResourceServer,
    Unauthorized,
    User,
    Forbidden,
    pkce,
)
from authlab.util.clock import FrozenClock


def code_grant(server, scope="openid orders:read orders:write", dpop_jkt=None):
    verifier, challenge = pkce.generate_pair()
    params = {
        "client_id": "web-app", "redirect_uri": "https://app/cb", "response_type": "code",
        "scope": scope, "state": "s", "code_challenge": challenge, "code_challenge_method": "S256",
    }
    if dpop_jkt:
        params["dpop_jkt"] = dpop_jkt
    validated = server.validate_authorization_request(params)
    code = server.issue_authorization_code(validated, "u-alice")
    return {"grant_type": "authorization_code", "code": code, "redirect_uri": "https://app/cb",
            "client_id": "web-app", "code_verifier": verifier}


class OAuthTestCase(unittest.TestCase):
    def setUp(self):
        self.clock = FrozenClock(1_700_000_000)
        self.server = AuthorizationServer(issuer="https://as.local", clock=self.clock)
        self.server.register_client(Client(
            client_id="web-app", redirect_uris=["https://app/cb"],
            scopes=["openid", "profile", "email", "orders:read", "orders:write", "offline_access"],
            token_endpoint_auth_method="none",
        ))
        self.server.register_client(Client(
            client_id="svc", client_secret="secret", grant_types=["client_credentials"],
            scopes=["orders:read"], response_types=[],
        ))
        self.server.register_user(User(subject="u-alice", username="alice", password_hash="x"))


class TestAuthorizationRequest(OAuthTestCase):
    def test_requires_state(self):
        with self.assertRaises(InvalidRequest):
            self.server.validate_authorization_request({
                "client_id": "web-app", "redirect_uri": "https://app/cb", "response_type": "code",
                "scope": "openid", "code_challenge": pkce.generate_pair()[1], "code_challenge_method": "S256",
            })

    def test_requires_pkce(self):
        with self.assertRaises(InvalidRequest):
            self.server.validate_authorization_request({
                "client_id": "web-app", "redirect_uri": "https://app/cb", "response_type": "code",
                "scope": "openid", "state": "s",
            })

    def test_exact_redirect_uri(self):
        for evil in ["https://app/cb.evil", "https://app/cb/extra", "https://app/CB", "http://app/cb"]:
            with self.assertRaises(InvalidRequest):
                self.server.validate_authorization_request({
                    "client_id": "web-app", "redirect_uri": evil, "response_type": "code",
                    "scope": "openid", "state": "s",
                    "code_challenge": pkce.generate_pair()[1], "code_challenge_method": "S256",
                })

    def test_scope_escalation(self):
        with self.assertRaises(InvalidScope):
            self.server.validate_authorization_request({
                "client_id": "web-app", "redirect_uri": "https://app/cb", "response_type": "code",
                "scope": "openid admin", "state": "s",
                "code_challenge": pkce.generate_pair()[1], "code_challenge_method": "S256",
            })


class TestTokenEndpoint(OAuthTestCase):
    def test_code_grant(self):
        tokens = self.server.token(code_grant(self.server))
        self.assertIn("access_token", tokens)
        self.assertIn("id_token", tokens)
        self.assertIn("refresh_token", tokens)

    def test_code_replay_revokes(self):
        req = code_grant(self.server)
        self.server.token(req)
        with self.assertRaises(InvalidGrant):
            self.server.token(req)

    def test_pkce_wrong_verifier(self):
        req = code_grant(self.server)
        req["code_verifier"] = "A" * 43
        with self.assertRaises(InvalidGrant):
            self.server.token(req)

    def test_code_bound_to_client(self):
        req = code_grant(self.server)
        req["client_id"] = "svc"
        with self.assertRaises(Exception):
            self.server.token(req, basic_auth=("svc", "secret"))

    def test_refresh_rotation(self):
        tokens = self.server.token(code_grant(self.server))
        r1 = tokens["refresh_token"]
        rotated = self.server.token({"grant_type": "refresh_token", "refresh_token": r1, "client_id": "web-app"})
        self.assertNotEqual(r1, rotated["refresh_token"])

    def test_refresh_reuse_detection(self):
        tokens = self.server.token(code_grant(self.server))
        r1 = tokens["refresh_token"]
        self.server.token({"grant_type": "refresh_token", "refresh_token": r1, "client_id": "web-app"})
        with self.assertRaises(InvalidGrant):
            self.server.token({"grant_type": "refresh_token", "refresh_token": r1, "client_id": "web-app"})

    def test_refresh_no_scope_widening(self):
        tokens = self.server.token(code_grant(self.server, scope="orders:read orders:write"))
        narrowed = self.server.token({"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
                                      "client_id": "web-app", "scope": "orders:read"})
        with self.assertRaises(InvalidScope):
            self.server.token({"grant_type": "refresh_token", "refresh_token": narrowed["refresh_token"],
                               "client_id": "web-app", "scope": "orders:write"})

    def test_client_credentials(self):
        tokens = self.server.token({"grant_type": "client_credentials", "client_id": "svc",
                                    "client_secret": "secret", "scope": "orders:read"})
        self.assertNotIn("refresh_token", tokens)
        self.assertNotIn("id_token", tokens)

    def test_client_credentials_wrong_secret(self):
        with self.assertRaises(Exception):
            self.server.token({"grant_type": "client_credentials", "client_id": "svc", "client_secret": "no"})


class TestDeviceFlow(OAuthTestCase):
    def setUp(self):
        super().setUp()
        self.server.register_client(Client(
            client_id="tv", grant_types=["urn:ietf:params:oauth:grant-type:device_code"],
            scopes=["openid"], token_endpoint_auth_method="none", response_types=[],
        ))

    def test_pending_then_approve(self):
        device = self.server.device_authorization({"client_id": "tv", "scope": "openid"})
        poll = {"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device["device_code"], "client_id": "tv"}
        with self.assertRaises(Exception):
            self.server.token(poll)
        self.server.approve_device(device["user_code"], "u-alice")
        tokens = self.server.token(poll)
        self.assertIn("access_token", tokens)


class TestResourceServer(OAuthTestCase):
    def _access_token(self):
        return self.server.token(code_grant(self.server))["access_token"]

    def test_valid_token(self):
        rs = ResourceServer(audience="https://api.auth-lab.local", issuer=self.server.issuer,
                            jwks=self.server.jwks, clock=self.clock)
        claims = rs.authenticate(f"Bearer {self._access_token()}")
        self.assertEqual(claims.sub, "u-alice")

    def test_id_token_rejected(self):
        id_token = self.server.issue_id_token(self.server.store.clients["web-app"], "u-alice", None, ["pwd"], self.clock.now())
        rs = ResourceServer(audience="https://api.auth-lab.local", issuer=self.server.issuer,
                            jwks=self.server.jwks, clock=self.clock)
        with self.assertRaises(Unauthorized):
            rs.authenticate(f"Bearer {id_token}")

    def test_scope_enforcement(self):
        rs = ResourceServer(audience="https://api.auth-lab.local", issuer=self.server.issuer,
                            jwks=self.server.jwks, clock=self.clock)
        claims = rs.authenticate(f"Bearer {self._access_token()}")
        with self.assertRaises(Forbidden):
            rs.require_scope(claims, "admin")

    def test_ownership(self):
        rs = ResourceServer(audience="https://api.auth-lab.local", issuer=self.server.issuer,
                            jwks=self.server.jwks, clock=self.clock)
        claims = rs.authenticate(f"Bearer {self._access_token()}")
        rs.require_ownership(claims, "u-alice")
        with self.assertRaises(Forbidden):
            rs.require_ownership(claims, "u-bob")


class TestDPoP(OAuthTestCase):
    def test_bound_token(self):
        key = DPoPClientKey(clock=self.clock)
        req = code_grant(self.server, scope="openid orders:read", dpop_jkt=key.thumbprint)
        proof = key.proof("POST", f"{self.server.issuer}/token")
        tokens = self.server.token(req, dpop_proof=proof, token_endpoint_url=f"{self.server.issuer}/token")
        self.assertEqual(tokens["token_type"], "DPoP")

        rs = ResourceServer(audience="https://api.auth-lab.local", issuer=self.server.issuer,
                            jwks=self.server.jwks, clock=self.clock)
        url = "https://api.auth-lab.local/orders"
        ok = rs.authenticate(f"DPoP {tokens['access_token']}", method="GET", url=url,
                             dpop_proof=key.proof("GET", url, access_token=tokens["access_token"]))
        self.assertTrue(ok)

    def test_stolen_token_as_bearer_rejected(self):
        key = DPoPClientKey(clock=self.clock)
        req = code_grant(self.server, scope="openid orders:read", dpop_jkt=key.thumbprint)
        tokens = self.server.token(req, dpop_proof=key.proof("POST", f"{self.server.issuer}/token"),
                                   token_endpoint_url=f"{self.server.issuer}/token")
        rs = ResourceServer(audience="https://api.auth-lab.local", issuer=self.server.issuer,
                            jwks=self.server.jwks, clock=self.clock)
        with self.assertRaises(Unauthorized):
            rs.authenticate(f"Bearer {tokens['access_token']}", method="GET", url="https://api.auth-lab.local/orders")


class TestClientCSRF(OAuthTestCase):
    def test_state_mismatch(self):
        client = OAuthClient(client_id="web-app", redirect_uri="https://app/cb",
                             authorization_endpoint=f"{self.server.issuer}/authorize",
                             token_endpoint=f"{self.server.issuer}/token", issuer=self.server.issuer,
                             clock=self.clock)
        client.begin("s1")
        with self.assertRaises(InvalidRequest):
            client.handle_callback("s1", "https://app/cb?code=x&state=attacker")


if __name__ == "__main__":
    unittest.main()
