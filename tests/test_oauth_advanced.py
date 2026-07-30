"""Success and negative tests for the advanced OAuth/FAPI profiles."""

from __future__ import annotations

import json
import unittest

from authlab.crypto.rsa import generate_rsa_keypair
from authlab.jose.jwks import JWK, JWKSet
from authlab.jose.jws import JWS, RS256
from authlab.oauth import (
    AuthorizationPending,
    AuthorizationServer,
    CIBAService,
    CIBA_GRANT_TYPE,
    Client,
    FAPI2MessageSigning,
    FAPI2SecurityProfile,
    INTROSPECTION_MEDIA_TYPE,
    InvalidAuthorizationDetails,
    InvalidAuthorizationResponse,
    InvalidClient,
    InvalidGrant,
    InvalidRequest,
    InvalidRequestObject,
    InvalidRequestURI,
    JWTAuthorizationRequests,
    JWTAuthorizationResponses,
    PushedAuthorizationRequests,
    UnauthorizedClient,
    User,
    pkce,
)
from authlab.oauth.authorization_server import CLIENT_ASSERTION_TYPE
from authlab.util.clock import FrozenClock
from authlab.util.ct import random_token


class AdvancedOAuthTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_key = generate_rsa_keypair(512)
        cls.client_key = generate_rsa_keypair(512)

    def setUp(self):
        self.clock = FrozenClock()
        self.server = AuthorizationServer(
            issuer="https://as.local",
            clock=self.clock,
            signing_key=self.server_key,
        )
        self.server.register_user(
            User(subject="u-alice", username="alice", password_hash="fixture")
        )
        self.server.register_client(
            Client(
                client_id="fapi",
                redirect_uris=["https://client.local/cb"],
                scopes=["openid", "orders:read", "offline_access"],
                token_endpoint_auth_method="tls_client_auth",
                tls_client_certificate_bound_access_tokens=True,
                rotate_refresh_tokens=False,
            )
        )
        self.server.register_client(
            Client(
                client_id="rs",
                client_secret="rs-secret",
                grant_types=["client_credentials"],
                response_types=[],
                token_endpoint_auth_method="client_secret_basic",
                introspection_audiences=["https://api.auth-lab.local"],
            )
        )
        self.jar = JWTAuthorizationRequests(self.server.issuer, clock=self.clock)
        self.jar.register_client_key(
            "fapi", JWK.from_rsa_public(self.client_key.public, kid="client-sign-1")
        )
        self.par = PushedAuthorizationRequests(self.server, jar=self.jar, clock=self.clock)
        self.security = FAPI2SecurityProfile(self.server, self.par)
        self.jarm = JWTAuthorizationResponses(
            self.server.issuer,
            self.server.signing_key,
            self.server.signing_kid,
            clock=self.clock,
        )
        self.message_signing = FAPI2MessageSigning(self.security, self.jarm)

    def authorization_params(self) -> tuple[dict[str, str], str]:
        verifier, challenge = pkce.generate_pair()
        return (
            {
                "client_id": "fapi",
                "redirect_uri": "https://client.local/cb",
                "response_type": "code",
                "scope": "openid orders:read offline_access",
                "state": "browser-state",
                "nonce": "oidc-nonce",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": "https://api.auth-lab.local",
            },
            verifier,
        )

    def push_and_authorize(self) -> tuple[dict, str]:
        params, verifier = self.authorization_params()
        pushed = self.security.pushed_authorization_request(
            params, tls_client_cert_thumbprint="cert-A"
        )
        validated = self.security.authorize(
            {"client_id": "fapi", "request_uri": pushed["request_uri"]}
        )
        return validated, verifier


class TestPAR(AdvancedOAuthTestCase):
    def test_par_binds_authenticated_request(self):
        validated, _ = self.push_and_authorize()
        self.assertEqual(validated["client"].client_id, "fapi")
        self.assertEqual(validated["redirect_uri"], "https://client.local/cb")

    def test_front_channel_cannot_override_par(self):
        params, _ = self.authorization_params()
        pushed = self.security.pushed_authorization_request(
            params, tls_client_cert_thumbprint="cert-A"
        )
        with self.assertRaises(InvalidRequestURI):
            self.security.authorize(
                {
                    "client_id": "fapi",
                    "request_uri": pushed["request_uri"],
                    "redirect_uri": "https://attacker.invalid/cb",
                }
            )

    def test_nested_parameters_are_snapshotted_at_par(self):
        params, _ = self.authorization_params()
        params["authorization_details"] = [
            {"type": "payment_initiation", "actions": ["initiate"]}
        ]
        pushed = self.security.pushed_authorization_request(
            params, tls_client_cert_thumbprint="cert-A"
        )
        params["authorization_details"][0]["actions"][0] = "attacker-rewrite"
        validated = self.security.authorize(
            {"client_id": "fapi", "request_uri": pushed["request_uri"]}
        )
        self.assertEqual(
            validated["authorization_details"][0]["actions"],
            ["initiate"],
        )


class TestJAR(AdvancedOAuthTestCase):
    def test_signed_request_object_round_trip(self):
        params, _ = self.authorization_params()
        request_object = self.jar.issue(
            params, self.client_key, kid="client-sign-1"
        )
        claims = self.jar.validate(request_object, outer_client_id="fapi")
        self.assertEqual(claims["redirect_uri"], params["redirect_uri"])

    def test_tampered_request_object_is_rejected(self):
        params, _ = self.authorization_params()
        request_object = self.jar.issue(
            params, self.client_key, kid="client-sign-1"
        )
        header, payload, signature = request_object.split(".")
        altered = f"{header}.{payload[:-1]}A.{signature}"
        with self.assertRaises(InvalidRequestObject):
            self.jar.validate(altered, outer_client_id="fapi")


class TestJARM(AdvancedOAuthTestCase):
    def test_signed_authorization_response_round_trip(self):
        response = self.jarm.issue("fapi", {"code": "code-1", "state": "state-1"})
        claims = self.jarm.validate(
            response,
            client_id="fapi",
            server_jwks=self.server.jwks,
            expected_state="state-1",
        )
        self.assertEqual(claims["code"], "code-1")

    def test_state_substitution_is_rejected(self):
        response = self.jarm.issue("fapi", {"code": "code-1", "state": "attacker"})
        with self.assertRaises(InvalidAuthorizationResponse):
            self.jarm.validate(
                response,
                client_id="fapi",
                server_jwks=self.server.jwks,
                expected_state="state-1",
            )


class TestRAR(AdvancedOAuthTestCase):
    def test_authorization_details_follow_the_grant(self):
        params, verifier = self.authorization_params()
        detail = {
            "type": "payment_initiation",
            "actions": ["initiate"],
            "locations": ["https://api.auth-lab.local/payments"],
            "instructedAmount": {"currency": "JPY", "amount": "1250"},
        }
        params["authorization_details"] = json.dumps([detail])
        validated = self.server.validate_authorization_request(params)
        code = self.server.issue_authorization_code(validated, "u-alice")
        tokens = self.server.token(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://client.local/cb",
                "client_id": "fapi",
                "code_verifier": verifier,
            },
            tls_client_cert_thumbprint="cert-A",
        )
        self.assertEqual(tokens["authorization_details"], [detail])
        introspection = self.server.introspect(
            tokens["access_token"], self.server.store.clients["rs"]
        )
        self.assertEqual(introspection["authorization_details"], [detail])

    def test_unsupported_detail_type_is_rejected(self):
        params, _ = self.authorization_params()
        params["authorization_details"] = [{"type": "root_access"}]
        with self.assertRaises(InvalidAuthorizationDetails):
            self.server.validate_authorization_request(params)


class TestCIBA(AdvancedOAuthTestCase):
    def setUp(self):
        super().setUp()
        self.server.register_client(
            Client(
                client_id="ciba-client",
                client_secret="ciba-secret",
                grant_types=[CIBA_GRANT_TYPE],
                response_types=[],
                scopes=["openid"],
            )
        )
        self.ciba = CIBAService(self.server, clock=self.clock)

    def test_poll_mode_approval_issues_tokens(self):
        started = self.ciba.start(
            {
                "client_id": "ciba-client",
                "scope": "openid",
                "login_hint": "alice",
                "binding_message": "Approve 42",
            },
            basic_auth=("ciba-client", "ciba-secret"),
        )
        self.ciba.approve(started["auth_req_id"], "u-alice", amr=["hwk"])
        tokens = self.ciba.token(
            {
                "grant_type": CIBA_GRANT_TYPE,
                "client_id": "ciba-client",
                "auth_req_id": started["auth_req_id"],
            },
            basic_auth=("ciba-client", "ciba-secret"),
        )
        self.assertIn("id_token", tokens)

    def test_token_poll_before_approval_is_pending(self):
        started = self.ciba.start(
            {
                "client_id": "ciba-client",
                "scope": "openid",
                "login_hint": "alice",
            },
            basic_auth=("ciba-client", "ciba-secret"),
        )
        with self.assertRaises(AuthorizationPending):
            self.ciba.token(
                {
                    "grant_type": CIBA_GRANT_TYPE,
                    "client_id": "ciba-client",
                    "auth_req_id": started["auth_req_id"],
                },
                basic_auth=("ciba-client", "ciba-secret"),
            )

    def test_certificate_binding_survives_backchannel_approval(self):
        self.server.register_client(
            Client(
                client_id="ciba-mtls",
                grant_types=[CIBA_GRANT_TYPE],
                response_types=[],
                scopes=["openid"],
                token_endpoint_auth_method="tls_client_auth",
                tls_client_certificate_bound_access_tokens=True,
            )
        )
        started = self.ciba.start(
            {
                "client_id": "ciba-mtls",
                "scope": "openid",
                "login_hint": "alice",
            },
            tls_client_cert_thumbprint="cert-A",
        )
        self.ciba.approve(started["auth_req_id"], "u-alice")
        with self.assertRaises(InvalidGrant):
            self.ciba.token(
                {
                    "grant_type": CIBA_GRANT_TYPE,
                    "client_id": "ciba-mtls",
                    "auth_req_id": started["auth_req_id"],
                },
                tls_client_cert_thumbprint="cert-B",
            )


class TestFAPI2Security(AdvancedOAuthTestCase):
    def test_par_code_and_token_are_bound(self):
        validated, verifier = self.push_and_authorize()
        code = self.server.issue_authorization_code(validated, "u-alice")
        redirect = self.security.authorization_redirect(validated, code)
        self.assertIn("iss=https%3A%2F%2Fas.local", redirect)
        tokens = self.security.token(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://client.local/cb",
                "client_id": "fapi",
                "code_verifier": verifier,
            },
            tls_client_cert_thumbprint="cert-A",
        )
        self.assertEqual(tokens["token_type"], "Bearer")
        self.assertEqual(
            self.server.store.access_tokens[tokens["access_token"]].cnf_x5t,
            "cert-A",
        )

    def test_public_client_is_rejected(self):
        self.server.register_client(
            Client(
                client_id="public",
                redirect_uris=["https://public.local/cb"],
                token_endpoint_auth_method="none",
            )
        )
        with self.assertRaises(UnauthorizedClient):
            self.security.validate_client(self.server.store.clients["public"])

    def test_dpop_client_requires_code_binding(self):
        self.server.register_client(
            Client(
                client_id="fapi-dpop",
                redirect_uris=["https://dpop.local/cb"],
                scopes=["openid"],
                token_endpoint_auth_method="tls_client_auth",
                require_dpop=True,
                rotate_refresh_tokens=False,
            )
        )
        _, challenge = pkce.generate_pair()
        with self.assertRaises(InvalidRequest):
            self.security.pushed_authorization_request(
                {
                    "client_id": "fapi-dpop",
                    "redirect_uri": "https://dpop.local/cb",
                    "response_type": "code",
                    "scope": "openid",
                    "state": "state",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                },
                tls_client_cert_thumbprint="cert-A",
            )


class TestFAPI2MessageSigning(AdvancedOAuthTestCase):
    def test_jar_jarm_and_signed_introspection(self):
        params, verifier = self.authorization_params()
        request_object = self.jar.issue(
            params, self.client_key, kid="client-sign-1"
        )
        pushed = self.message_signing.pushed_authorization_request(
            {"client_id": "fapi", "request": request_object},
            tls_client_cert_thumbprint="cert-A",
        )
        validated = self.security.authorize(
            {"client_id": "fapi", "request_uri": pushed["request_uri"]}
        )
        code = self.server.issue_authorization_code(validated, "u-alice")
        response = self.message_signing.authorization_response(validated, code)
        response_claims = self.jarm.validate(
            response,
            client_id="fapi",
            server_jwks=self.server.jwks,
            expected_state="browser-state",
        )
        tokens = self.security.token(
            {
                "grant_type": "authorization_code",
                "code": response_claims["code"],
                "redirect_uri": "https://client.local/cb",
                "client_id": "fapi",
                "code_verifier": verifier,
            },
            tls_client_cert_thumbprint="cert-A",
        )
        envelope = self.message_signing.signed_introspection(
            tokens["access_token"],
            resource_server=self.server.store.clients["rs"],
            audience="https://api.auth-lab.local",
            basic_auth=("rs", "rs-secret"),
        )
        self.assertEqual(envelope["content_type"], INTROSPECTION_MEDIA_TYPE)
        body = self.message_signing.validate_introspection_response(
            envelope["body"],
            audience="https://api.auth-lab.local",
            server_jwks=self.server.jwks,
        )
        self.assertTrue(body["active"])

    def test_signed_introspection_is_audience_bound(self):
        validated, verifier = self.push_and_authorize()
        code = self.server.issue_authorization_code(validated, "u-alice")
        tokens = self.security.token(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://client.local/cb",
                "client_id": "fapi",
                "code_verifier": verifier,
            },
            tls_client_cert_thumbprint="cert-A",
        )
        envelope = self.message_signing.signed_introspection(
            tokens["access_token"],
            resource_server=self.server.store.clients["rs"],
            audience="https://api.auth-lab.local",
            basic_auth=("rs", "rs-secret"),
        )
        with self.assertRaises(InvalidAuthorizationResponse):
            self.message_signing.validate_introspection_response(
                envelope["body"],
                audience="https://other-api.local",
                server_jwks=self.server.jwks,
            )


class TestPrivateKeyJWT(AdvancedOAuthTestCase):
    def setUp(self):
        super().setUp()
        self.server.register_client(
            Client(
                client_id="signed-client",
                redirect_uris=["https://signed.local/cb"],
                token_endpoint_auth_method="private_key_jwt",
                jwks=JWKSet(
                    [JWK.from_rsa_public(self.client_key.public, kid="client-sign-1")]
                ).public_set(),
            )
        )

    def assertion(self, *, jti: str) -> str:
        return JWS.sign(
            {
                "iss": "signed-client",
                "sub": "signed-client",
                "aud": "https://as.local",
                "iat": self.clock.now(),
                "exp": self.clock.now() + 60,
                "jti": jti,
            },
            self.client_key,
            RS256,
            kid="client-sign-1",
            typ="JWT",
        )

    def test_registered_key_authenticates_client(self):
        assertion = self.assertion(jti=random_token(8))
        client = self.server.authenticate_client(
            {
                "client_id": "signed-client",
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": assertion,
            }
        )
        self.assertEqual(client.client_id, "signed-client")

    def test_client_assertion_replay_is_rejected(self):
        assertion = self.assertion(jti="one-use-jti")
        params = {
            "client_id": "signed-client",
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": assertion,
        }
        self.server.authenticate_client(params)
        with self.assertRaises(InvalidClient):
            self.server.authenticate_client(params)


if __name__ == "__main__":
    unittest.main()
