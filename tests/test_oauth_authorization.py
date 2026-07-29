"""Tests for OAuth, OIDC, and authorization models."""

from __future__ import annotations

import unittest

from authlab.authorization import ABAC, Policy, RBAC, ReBAC
from authlab.oauth import AuthorizationServer, Client, OAuthError


def server() -> AuthorizationServer:
    instance = AuthorizationServer()
    instance.register_client(
        Client(
            "web-app",
            ("https://client.example/callback",),
            allowed_scopes=frozenset({"openid", "profile", "read", "write"}),
        )
    )
    instance.register_client(
        Client(
            "worker",
            secret="worker-secret",
            public=False,
            allowed_scopes=frozenset({"read", "write"}),
        )
    )
    return instance


class OAuthTests(unittest.TestCase):
    verifier = "a" * 64

    def authorization_code(self, instance: AuthorizationServer) -> dict[str, object]:
        result = instance.authorize(
            client_id="web-app",
            redirect_uri="https://client.example/callback",
            user="alice",
            scope="openid profile",
            state="csrf-state",
            code_challenge=instance.pkce_challenge(self.verifier),
            nonce="oidc-nonce",
            now=1_000,
        )
        return instance.exchange_code(
            code=result["code"],
            client_id="web-app",
            redirect_uri="https://client.example/callback",
            code_verifier=self.verifier,
            now=1_001,
        )

    def test_authorization_code_pkce_oidc_and_replay(self) -> None:
        instance = server()
        response = instance.authorize(
            client_id="web-app",
            redirect_uri="https://client.example/callback",
            user="alice",
            scope="openid profile",
            state="csrf-state",
            code_challenge=instance.pkce_challenge(self.verifier),
            nonce="oidc-nonce",
            now=1_000,
        )
        tokens = instance.exchange_code(
            code=response["code"],
            client_id="web-app",
            redirect_uri="https://client.example/callback",
            code_verifier=self.verifier,
            now=1_001,
        )
        self.assertIn("id_token", tokens)
        self.assertEqual(instance.userinfo(tokens["access_token"], now=1_002)["sub"], "alice")
        with self.assertRaisesRegex(OAuthError, "code replay"):
            instance.exchange_code(
                code=response["code"],
                client_id="web-app",
                redirect_uri="https://client.example/callback",
                code_verifier=self.verifier,
                now=1_003,
            )
        self.assertFalse(instance.introspect(tokens["access_token"], now=1_004)["active"])

    def test_refresh_rotation_and_family_reuse_detection(self) -> None:
        instance = server()
        first = self.authorization_code(instance)
        second = instance.refresh(first["refresh_token"], client_id="web-app", now=1_100)
        with self.assertRaisesRegex(OAuthError, "reuse"):
            instance.refresh(first["refresh_token"], client_id="web-app", now=1_101)
        self.assertFalse(instance.introspect(second["access_token"], now=1_102)["active"])

    def test_client_credentials_has_no_refresh_token(self) -> None:
        tokens = server().client_credentials(
            client_id="worker",
            client_secret="worker-secret",
            scope="read",
            now=2_000,
        )
        self.assertNotIn("refresh_token", tokens)

    def test_device_code_pending_slow_down_and_approval(self) -> None:
        instance = server()
        device = instance.device_authorize(
            client_id="web-app",
            scope="openid",
            now=3_000,
        )
        with self.assertRaisesRegex(OAuthError, "authorization_pending"):
            instance.poll_device(device["device_code"], client_id="web-app", now=3_001)
        with self.assertRaisesRegex(OAuthError, "slow_down"):
            instance.poll_device(device["device_code"], client_id="web-app", now=3_002)
        instance.approve_device(device["user_code"], "alice")
        tokens = instance.poll_device(
            device["device_code"],
            client_id="web-app",
            now=3_011,
        )
        self.assertIn("id_token", tokens)

    def test_redirect_uri_is_exact_and_revocation_is_idempotent(self) -> None:
        instance = server()
        with self.assertRaisesRegex(OAuthError, "exactly"):
            instance.authorize(
                client_id="web-app",
                redirect_uri="https://client.example/callback/evil",
                user="alice",
                scope="openid",
                state="state",
                code_challenge=instance.pkce_challenge(self.verifier),
                now=4_000,
            )
        instance.revoke("unknown-token")


class AuthorizationTests(unittest.TestCase):
    def test_rbac_hierarchy(self) -> None:
        rbac = RBAC()
        rbac.add_role("viewer", {"document:read"})
        rbac.add_role("editor", {"document:write"}, parents={"viewer"})
        rbac.assign("alice", "editor")
        self.assertTrue(rbac.allowed("alice", "document:read"))
        self.assertTrue(rbac.allowed("alice", "document:write"))

    def test_abac_deny_overrides(self) -> None:
        engine = ABAC(
            [
                Policy(
                    "allow",
                    "read",
                    lambda subject, resource, context: subject["id"] == resource["owner"],
                    "allow-owner",
                ),
                Policy(
                    "deny",
                    "read",
                    lambda subject, resource, context: resource["locked"],
                    "deny-locked",
                ),
            ]
        )
        decision, reasons = engine.decide(
            subject={"id": "alice"},
            resource={"owner": "alice", "locked": True},
            context={},
            action="read",
        )
        self.assertFalse(decision)
        self.assertIn("deny:deny-locked", reasons)

    def test_rebac_userset_and_inheritance(self) -> None:
        rebac = ReBAC()
        rebac.add("group:editors", "member", "user:alice")
        rebac.add("document:roadmap", "editor", "group:editors#member")
        self.assertTrue(rebac.check("alice", "document:roadmap", "editor"))
        self.assertIn("document:roadmap", rebac.list_objects("alice", "editor"))


if __name__ == "__main__":
    unittest.main()
