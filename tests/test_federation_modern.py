"""Tests for federation, modern credentials, and directory protocols."""

from __future__ import annotations

import unittest

from authlab import ec
from authlab.directory import LDAPDirectory, SCIMService, escape_filter
from authlab.dpop import DPoPVerifier, create_proof, jwk_thumbprint, public_jwk
from authlab.kerberos import (
    KDC,
    KerberosService,
    authenticator,
    derive_key,
    preauth_proof,
    unseal,
)
from authlab.mtls import (
    CertificateAuthority,
    bind_token,
    verify_bound_token,
)
from authlab.rsa import generate_keypair
from authlab.saml import SAMLServiceProvider, issue_response
from authlab.util import AuthError, b64url_decode
from authlab.webauthn import Authenticator, WebAuthnServer


class SAMLTests(unittest.TestCase):
    def test_strict_saml_validation_and_replay(self) -> None:
        key = b"saml-lab-key"
        sp = SAMLServiceProvider(
            "https://idp.example",
            "https://sp.example/metadata",
            "https://sp.example/acs",
            key,
        )
        response = issue_response(
            key=key,
            issuer="https://idp.example",
            subject="alice",
            audience="https://sp.example/metadata",
            destination="https://sp.example/acs",
            in_response_to="_request-1",
            now=10_000,
        )
        self.assertEqual(sp.validate(response, request_id="_request-1", now=10_001), "alice")
        with self.assertRaises(AuthError):
            sp.validate(response, request_id="_request-1", now=10_002)


class KerberosTests(unittest.TestCase):
    def test_as_tgs_service_and_mutual_authentication(self) -> None:
        now = 20_000
        user_key = derive_key("correct-password")
        service_key = b"s" * 32
        kdc = KDC("EXAMPLE.TEST", {"alice": user_key}, {"http/api": service_key})
        as_rep = kdc.as_exchange("alice", now, preauth_proof(user_key, "alice", now))
        client_tgt = unseal(user_key, as_rep["client_part"])
        tgt_session = b64url_decode(client_tgt["session_key"])
        tgs_rep = kdc.tgs_exchange(
            as_rep["tgt"],
            "http/api",
            authenticator(tgt_session, "alice", now + 1),
            now=now + 1,
        )
        client_service = unseal(tgt_session, tgs_rep["client_part"])
        service_session = b64url_decode(client_service["session_key"])
        service = KerberosService("http/api", service_key)
        accepted = service.accept(
            tgs_rep["ticket"],
            authenticator(service_session, "alice", now + 2),
            now=now + 2,
        )
        self.assertEqual(accepted["client"], "alice")


class WebAuthnTests(unittest.TestCase):
    def test_registration_assertion_and_origin_binding(self) -> None:
        server = WebAuthnServer("example.test", "https://example.test")
        authenticator_device = Authenticator()
        challenge = server.begin_registration("alice")
        credential_id = server.finish_registration(
            "alice",
            authenticator_device.registration(
                challenge,
                origin="https://example.test",
                rp_id="example.test",
            ),
        )
        self.assertEqual(credential_id, authenticator_device.credential_id)
        auth_challenge = server.begin_authentication("alice")
        self.assertTrue(
            server.finish_authentication(
                "alice",
                authenticator_device.assertion(
                    auth_challenge,
                    origin="https://example.test",
                    rp_id="example.test",
                ),
            )
        )


class MutualTLSTests(unittest.TestCase):
    def test_certificate_validation_and_token_binding(self) -> None:
        ca = CertificateAuthority("Auth Lab CA", generate_keypair(512))
        client_key = generate_keypair(512)
        cert = ca.issue(
            subject="CN=worker",
            public_key=client_key.public_key,
            serial="01",
            not_before=30_000,
            not_after=40_000,
            san="spiffe://example.test/worker",
            eku="clientAuth",
        )
        ca.verify(
            cert,
            now=35_000,
            expected_san="spiffe://example.test/worker",
            expected_eku="clientAuth",
        )
        claims = bind_token({"sub": "worker"}, cert)
        verify_bound_token(claims, cert)


class DPoPTests(unittest.TestCase):
    def test_request_and_token_binding_with_replay_rejection(self) -> None:
        private, public = ec.generate_keypair()
        token = "access-token"
        proof = create_proof(
            private,
            public,
            method="GET",
            url="https://api.example/resource?ignored=yes",
            now=50_000,
            access_token=token,
            nonce="server-nonce",
        )
        verifier = DPoPVerifier()
        claims = verifier.verify(
            proof,
            method="GET",
            url="https://api.example/resource",
            now=50_001,
            access_token=token,
            token_jkt=jwk_thumbprint(public_jwk(public)),
            required_nonce="server-nonce",
        )
        self.assertEqual(claims["htm"], "GET")
        with self.assertRaises(AuthError):
            verifier.verify(
                proof,
                method="GET",
                url="https://api.example/resource",
                now=50_002,
                access_token=token,
            )


class DirectoryTests(unittest.TestCase):
    def test_ldap_bind_escape_and_search(self) -> None:
        directory = LDAPDirectory()
        directory.add(
            "uid=alice,ou=people,dc=example,dc=test",
            {"uid": ["alice"], "mail": ["alice@example.test"]},
            password="correct-password",
        )
        self.assertTrue(
            directory.bind(
                "uid=alice,ou=people,dc=example,dc=test",
                "correct-password",
            )
        )
        self.assertFalse(
            directory.bind(
                "uid=missing,ou=people,dc=example,dc=test",
                "correct-password",
            )
        )
        self.assertEqual(escape_filter("alice*)(uid=*"), r"alice\2a\29\28uid=\2a")
        self.assertEqual(
            len(
                directory.search(
                    base_dn="ou=people,dc=example,dc=test",
                    attribute="uid",
                    value="alice",
                )
            ),
            1,
        )

    def test_scim_lifecycle_and_optimistic_concurrency(self) -> None:
        scim = SCIMService()
        created = scim.create_user("alice", "Alice")
        updated = scim.patch_user(
            created["id"],
            [{"op": "replace", "path": "active", "value": False}],
            if_match=created["meta"]["version"],
        )
        self.assertFalse(updated["active"])
        with self.assertRaises(AuthError):
            scim.patch_user(
                created["id"],
                [{"op": "replace", "path": "active", "value": True}],
                if_match=created["meta"]["version"],
            )


if __name__ == "__main__":
    unittest.main()

