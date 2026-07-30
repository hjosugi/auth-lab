import json
import unittest

from authlab.crypto import generate_rsa_keypair
from authlab.crypto.ec import SECP256R1, SECP384R1, SECP521R1, generate_ec_keypair
from authlab.crypto.ed25519 import Ed25519PrivateKey, generate_ed25519_keypair
from authlab.jose import (
    ES256,
    ES384,
    ES512,
    EdDSA,
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
from authlab.util.encoding import b64u_decode, b64u_encode, int_to_bytes, json_b64u


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


class TestECDSAAlgorithms(unittest.TestCase):
    CASES = ((ES256, SECP256R1, 64), (ES384, SECP384R1, 96), (ES512, SECP521R1, 132))

    def test_roundtrip(self):
        for algorithm, curve, width in self.CASES:
            with self.subTest(alg=algorithm.name):
                key = generate_ec_keypair(curve)
                token = JWS.sign({"a": 1}, key, algorithm)
                parsed = JWS.verify(token, key.public, [algorithm.name])
                self.assertEqual(json.loads(parsed.payload)["a"], 1)
                self.assertEqual(len(b64u_decode(token.split(".")[2])), width)

    def test_tampered_payload_rejected(self):
        key = generate_ec_keypair()
        token = JWS.sign({"amount": 1}, key, ES256)
        header, _, signature = token.split(".")
        forged = f"{header}.{json_b64u({'amount': 1000})}.{signature}"
        with self.assertRaises(InvalidSignature):
            JWS.verify(forged, key.public, ["ES256"])

    def test_curve_is_pinned_to_the_algorithm(self):
        # RFC 7518 fixes one curve per ES* name. A P-256 key must not satisfy
        # an ES384 header just because both are "ECDSA".
        key = generate_ec_keypair(SECP256R1)
        with self.assertRaises(InvalidSignature):
            JWS.sign({"a": 1}, key, ES384)

    def test_der_signature_is_not_accepted(self):
        # The classic JOSE/WebAuthn encoding mix-up: DER instead of raw R||S.
        from authlab.crypto.ec import ecdsa_sign, signature_to_der

        key = generate_ec_keypair()
        signing_input = "eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ"
        der = signature_to_der(ecdsa_sign(key, signing_input.encode("ascii"), "sha256"))
        token = f"{signing_input}.{b64u_encode(der)}"
        with self.assertRaises(InvalidSignature):
            JWS.verify(token, key.public, ["ES256"])

    def test_wrong_key_rejected(self):
        key = generate_ec_keypair()
        other = generate_ec_keypair()
        token = JWS.sign({"a": 1}, key, ES256)
        with self.assertRaises(InvalidSignature):
            JWS.verify(token, other.public, ["ES256"])

    def test_rsa_key_cannot_satisfy_es256(self):
        key = generate_ec_keypair()
        token = JWS.sign({"a": 1}, key, ES256)
        with self.assertRaises(InvalidSignature):
            JWS.verify(token, b"a-shared-secret", ["ES256"])


class TestEdDSAAlgorithm(unittest.TestCase):
    # RFC 8037 appendix A.4: the canonical Ed25519 JWS.
    RFC8037_SEED = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
    RFC8037_X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    RFC8037_JWS = (
        "eyJhbGciOiJFZERTQSJ9"
        ".RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
        ".hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5B"
        "hVsPt9g7sVvpAr_MuM0KAg"
    )

    def setUp(self):
        self.key = Ed25519PrivateKey(b64u_decode(self.RFC8037_SEED))

    def test_rfc8037_public_key(self):
        self.assertEqual(b64u_encode(self.key.public.data), self.RFC8037_X)

    def test_rfc8037_signature_matches(self):
        # Sign the exact protected header from the RFC so the signing input
        # is byte-identical: {"alg":"EdDSA"} with no typ.
        token = JWS.sign(b"Example of Ed25519 signing", self.key, EdDSA, typ=None)
        self.assertEqual(token, self.RFC8037_JWS)

    def test_rfc8037_verifies(self):
        parsed = JWS.verify(self.RFC8037_JWS, self.key.public, ["EdDSA"])
        self.assertEqual(parsed.payload, b"Example of Ed25519 signing")

    def test_tampered_payload_rejected(self):
        header, _, signature = self.RFC8037_JWS.split(".")
        forged = f"{header}.{b64u_encode(b'Example of Ed25519 forging')}.{signature}"
        with self.assertRaises(InvalidSignature):
            JWS.verify(forged, self.key.public, ["EdDSA"])

    def test_wrong_key_rejected(self):
        with self.assertRaises(InvalidSignature):
            JWS.verify(self.RFC8037_JWS, generate_ed25519_keypair().public, ["EdDSA"])

    def test_eddsa_not_in_allowed_set(self):
        token = JWS.sign({"a": 1}, self.key, EdDSA)
        with self.assertRaises(InvalidSignature):
            JWS.verify(token, self.key.public, ["ES256", "RS256"])


class TestECAndOKPKeySets(unittest.TestCase):
    def test_ec_jwk_roundtrip_and_thumbprint(self):
        for curve in (SECP256R1, SECP384R1, SECP521R1):
            with self.subTest(curve=curve.jose_crv):
                key = generate_ec_keypair(curve)
                jwk = JWK.from_ec_public(key.public)
                self.assertEqual(jwk.data["crv"], curve.jose_crv)
                self.assertEqual(len(b64u_decode(jwk.data["x"])), curve.field_bytes)
                self.assertEqual(jwk.to_ec_public().point, key.public.point)
                # kid defaults to the RFC 7638 thumbprint.
                self.assertEqual(jwk.kid, JWK.thumbprint(jwk.data))

    def test_okp_jwk_roundtrip(self):
        key = generate_ed25519_keypair()
        jwk = JWK.from_okp_public(key.public)
        self.assertEqual(jwk.data["crv"], "Ed25519")
        self.assertEqual(jwk.to_okp_public().data, key.public.data)

    def test_private_members_are_stripped_when_published(self):
        for jwk in (
            JWK.from_ec_private(generate_ec_keypair()),
            JWK.from_okp_private(generate_ed25519_keypair()),
        ):
            with self.subTest(kty=jwk.kty):
                self.assertIn("d", jwk.data)
                self.assertNotIn("d", jwk.public().data)

    def test_jwks_resolves_ec_key_by_kid(self):
        key = generate_ec_keypair()
        jwks = JWKSet([JWK.from_ec_public(key.public, kid="ec1")])
        token = JWS.sign({"a": 1}, key, ES256, kid="ec1")
        parsed = JWS.verify(token, jwks.resolver(), ["ES256"])
        self.assertEqual(json.loads(parsed.payload)["a"], 1)

    def test_jwks_resolves_okp_key_by_kid(self):
        key = generate_ed25519_keypair()
        jwks = JWKSet([JWK.from_okp_public(key.public, kid="ed1")])
        token = JWS.sign({"a": 1}, key, EdDSA, kid="ed1")
        parsed = JWS.verify(token, jwks.resolver(), ["EdDSA"])
        self.assertEqual(json.loads(parsed.payload)["a"], 1)

    def test_crv_must_match_coordinate_width(self):
        # A JWK claiming P-256 while carrying P-384 coordinates is either
        # corrupt or an attempt at cross-curve confusion.
        key = generate_ec_keypair(SECP384R1)
        jwk = JWK.from_ec_public(key.public)
        lying = JWK({**jwk.data, "crv": "P-256"})
        with self.assertRaises(ValueError):
            lying.to_ec_public()

    def test_off_curve_jwk_rejected(self):
        key = generate_ec_keypair()
        jwk = JWK.from_ec_public(key.public)
        moved = JWK({**jwk.data, "y": b64u_encode(b"\x01" * 32)})
        with self.assertRaises(ValueError):
            moved.to_ec_public()

    def test_x25519_is_not_a_signing_key(self):
        key = generate_ed25519_keypair()
        jwk = JWK.from_okp_public(key.public)
        agreement = JWK({**jwk.data, "crv": "X25519"})
        with self.assertRaises(ValueError):
            agreement.to_okp_public()

    def test_small_order_okp_key_is_rejected(self):
        identity = JWK(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": b64u_encode(b"\x01" + b"\x00" * 31),
            }
        )
        with self.assertRaises(ValueError):
            identity.to_okp_public()


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

    def test_es256_token_passes_jwt_validator(self):
        key = generate_ec_keypair(SECP256R1)
        jwks = JWKSet([JWK.from_ec_public(key.public, kid="ec1")])
        token = JWT(self.clock).issue(
            key,
            ES256,
            issuer="iss",
            subject="ec-subject",
            audience="api",
            kid="ec1",
        )
        validator = JWTValidator(
            issuer="iss",
            audience="api",
            allowed_algorithms=["ES256"],
            key=jwks.resolver(),
            clock=self.clock,
        )
        self.assertEqual(validator.validate(token).sub, "ec-subject")

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
