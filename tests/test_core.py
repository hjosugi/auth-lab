"""Tests for password, MFA, JOSE, and HTTP authentication primitives."""

from __future__ import annotations

import json
import unittest

from authlab.http_auth import (
    HMACRequestVerifier,
    basic_header,
    parse_basic,
    sign_request,
)
from authlab.jose import TokenError, sign_jwt, verify_jwt
from authlab.mfa import TotpVerifier, hotp, totp
from authlab.passwords import PasswordStore, hash_password, verify_password
from authlab.rsa import generate_keypair
from authlab.util import AuthError, b64url_encode


class PasswordTests(unittest.TestCase):
    def test_scrypt_and_pbkdf2_records(self) -> None:
        for algorithm in ("scrypt", "pbkdf2-sha256"):
            record = hash_password(
                "correct horse battery staple",
                algorithm=algorithm,
                salt=b"0123456789abcdef",
            )
            self.assertTrue(verify_password("correct horse battery staple", record))
            self.assertFalse(verify_password("wrong", record))

    def test_store_uses_dummy_hash_for_unknown_user(self) -> None:
        store = PasswordStore()
        store.register("alice", "long-secret")
        self.assertTrue(store.authenticate("alice", "long-secret"))
        self.assertFalse(store.authenticate("missing", "long-secret"))


class MFATests(unittest.TestCase):
    def test_hotp_rfc_4226_vectors(self) -> None:
        secret = b"12345678901234567890"
        expected = [
            "755224",
            "287082",
            "359152",
            "969429",
            "338314",
            "254676",
            "287922",
            "162583",
            "399871",
            "520489",
        ]
        self.assertEqual([hotp(secret, i) for i in range(10)], expected)

    def test_totp_replay_is_rejected(self) -> None:
        secret = b"12345678901234567890"
        verifier = TotpVerifier(secret)
        code = totp(secret, at=59)
        self.assertTrue(verifier.verify(code, at=59))
        self.assertFalse(verifier.verify(code, at=59))


class JOSETests(unittest.TestCase):
    claims = {
        "iss": "https://issuer.example",
        "sub": "alice",
        "aud": "api",
        "iat": 1_700_000_000,
        "exp": 1_700_000_600,
        "jti": "test-jti",
    }

    def test_hs256_is_pinned_and_tampering_is_rejected(self) -> None:
        token = sign_jwt(self.claims, b"secret", algorithm="HS256", kid="h1")
        verified = verify_jwt(
            token,
            {"h1": b"secret"},
            algorithm="HS256",
            issuer="https://issuer.example",
            audience="api",
            now=1_700_000_100,
        )
        self.assertEqual(verified["sub"], "alice")
        left, middle, signature = token.split(".")
        forged_claims = {**self.claims, "sub": "mallory"}
        forged_middle = b64url_encode(
            json.dumps(forged_claims, separators=(",", ":"), sort_keys=True).encode()
        )
        with self.assertRaises(TokenError):
            verify_jwt(
                f"{left}.{forged_middle}.{signature}",
                {"h1": b"secret"},
                algorithm="HS256",
                issuer="https://issuer.example",
                audience="api",
                now=1_700_000_100,
            )

    def test_rs256_round_trip(self) -> None:
        key = generate_keypair(512)
        token = sign_jwt(self.claims, key, algorithm="RS256", kid="r1")
        verified = verify_jwt(
            token,
            {"r1": key.public_key},
            algorithm="RS256",
            issuer="https://issuer.example",
            audience="api",
            now=1_700_000_100,
        )
        self.assertEqual(verified["sub"], "alice")


class HTTPAuthTests(unittest.TestCase):
    def test_basic_and_signed_request(self) -> None:
        self.assertEqual(parse_basic(basic_header("alice", "secret")), ("alice", "secret"))
        verifier = HMACRequestVerifier()
        signature = sign_request(
            b"shared-key",
            method="POST",
            path="/payments",
            body=b'{"amount":100}',
            timestamp=1000,
            nonce="n-1",
        )
        verifier.verify(
            b"shared-key",
            signature,
            method="POST",
            path="/payments",
            body=b'{"amount":100}',
            timestamp=1000,
            nonce="n-1",
            now=1000,
        )
        with self.assertRaises(AuthError):
            verifier.verify(
                b"shared-key",
                signature,
                method="POST",
                path="/payments",
                body=b'{"amount":100}',
                timestamp=1000,
                nonce="n-1",
                now=1000,
            )


if __name__ == "__main__":
    unittest.main()
