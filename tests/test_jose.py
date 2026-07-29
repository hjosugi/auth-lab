import json
import unittest

from authlab.crypto import generate_rsa_keypair
from authlab.jose import (
    HS256,
    JWK,
    JWKSet,
    JWS,
    JWT,
    JWTValidator,
    RS256,
    ClaimError,
    ExpiredToken,
    InvalidSignature,
)
from authlab.util.clock import FrozenClock
from authlab.util.encoding import b64u_decode, int_to_bytes, json_b64u


class TestJWS(unittest.TestCase):
    def test_hmac_roundtrip(self):
        token = JWS.sign({"a": 1}, b"secret-key-16byte", HS256)
        parsed = JWS.verify(token, b"secret-key-16byte", ["HS256"])
        self.assertEqual(json.loads(parsed.payload)["a"], 1)

    def test_empty_allowed_algorithms(self):
        token = JWS.sign({"a": 1}, b"k" * 16, HS256)
        with self.assertRaises(InvalidSignature):
            JWS.verify(token, b"k" * 16, [])

    def test_none_never_accepted(self):
        with self.assertRaises(InvalidSignature):
            JWS.verify("x.y.z", b"k", ["none"])


class TestJWTValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = generate_rsa_keypair(2048)

    def setUp(self):
        self.clock = FrozenClock(1_700_000_000)
        self.jwks = JWKSet([JWK.from_rsa_public(self.key.public, kid="k1")])
        self.token = JWT(self.clock).issue(
            self.key, RS256, issuer="iss", subject="s", audience="api",
            lifetime=300, kid="k1", extra_claims={"scope": "read"},
        )
        self.validator = JWTValidator(
            issuer="iss", audience="api", allowed_algorithms=["RS256"],
            key=self.jwks.resolver(), clock=self.clock,
        )

    def test_valid(self):
        claims = self.validator.validate(self.token)
        self.assertEqual(claims.sub, "s")
        self.assertEqual(claims.scopes, ["read"])

    def test_alg_none(self):
        payload = self.token.split(".")[1]
        with self.assertRaises(InvalidSignature):
            self.validator.validate(f"{json_b64u({'alg': 'none'})}.{payload}.")

    def test_algorithm_confusion(self):
        payload = json.loads(b64u_decode(self.token.split(".")[1]))
        public_bytes = int_to_bytes(self.key.n, self.key.key_size_bytes)
        confused = JWS.sign(payload, public_bytes, HS256, kid="k1")
        with self.assertRaises(InvalidSignature):
            self.validator.validate(confused)

    def test_wrong_audience(self):
        validator = JWTValidator(issuer="iss", audience="other", allowed_algorithms=["RS256"],
                                 key=self.jwks.resolver(), clock=self.clock)
        with self.assertRaises(ClaimError):
            validator.validate(self.token)

    def test_wrong_issuer(self):
        validator = JWTValidator(issuer="other", audience="api", allowed_algorithms=["RS256"],
                                 key=self.jwks.resolver(), clock=self.clock)
        with self.assertRaises(ClaimError):
            validator.validate(self.token)

    def test_expired(self):
        late = JWTValidator(issuer="iss", audience="api", allowed_algorithms=["RS256"],
                            key=self.jwks.resolver(), clock=FrozenClock(1_700_000_400))
        with self.assertRaises(ExpiredToken):
            late.validate(self.token)

    def test_tampered_payload(self):
        h, p, s = self.token.split(".")
        tampered = json.loads(b64u_decode(p))
        tampered["scope"] = "admin"
        with self.assertRaises(InvalidSignature):
            self.validator.validate(f"{h}.{json_b64u(tampered)}.{s}")

    def test_jwk_header_rejected(self):
        h, p, s = self.token.split(".")
        with self.assertRaises(InvalidSignature):
            JWS.verify(f"{json_b64u({'alg': 'RS256', 'jwk': {}})}.{p}.{s}", self.key.public, ["RS256"])

    def test_nonce_check(self):
        token = JWT(self.clock).issue(self.key, RS256, issuer="iss", subject="s", audience="api",
                                      kid="k1", extra_claims={"nonce": "abc"})
        self.assertTrue(self.validator.validate(token, nonce="abc"))
        with self.assertRaises(ClaimError):
            self.validator.validate(token, nonce="wrong")

    def test_typ_check(self):
        validator = JWTValidator(issuer="iss", audience="api", allowed_algorithms=["RS256"],
                                 key=self.jwks.resolver(), clock=self.clock, expected_typ="at+jwt")
        with self.assertRaises(ClaimError):
            validator.validate(self.token)  # default typ is JWT


class TestJWKThumbprint(unittest.TestCase):
    def test_rfc7638_deterministic(self):
        key = generate_rsa_keypair(2048)
        a = JWK.from_rsa_public(key.public).kid
        b = JWK.from_rsa_public(key.public).kid
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
