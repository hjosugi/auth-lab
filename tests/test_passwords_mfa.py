import hashlib
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from authlab.mfa import RecoveryCodes, TOTP, hotp, totp
from authlab.passwords import hasher as password_hasher
from authlab.passwords import (
    ARGON2_BACKEND,
    Argon2Params,
    PasswordHasher,
    Pbkdf2Params,
    ScryptParams,
    parse_hash,
)
from authlab.passwords.argon2 import TYPE_D, TYPE_I, TYPE_ID, Argon2Error, argon2
from authlab.util.clock import FrozenClock


class TestPasswordHasher(unittest.TestCase):
    def setUp(self):
        self.hasher = PasswordHasher()

    def test_roundtrip(self):
        stored = self.hasher.hash("secret")
        self.assertTrue(self.hasher.verify("secret", stored))
        self.assertFalse(self.hasher.verify("wrong", stored))

    def test_salt_differs(self):
        self.assertNotEqual(self.hasher.hash("x"), self.hasher.hash("x"))

    def test_format(self):
        self.assertTrue(self.hasher.hash("x").startswith("$scrypt$"))

    def test_pure_python_pbkdf2_fallback_matches_native_backend(self):
        params = Pbkdf2Params(iterations=23, dklen=48)
        expected = params.derive(b"password", b"salt")
        with patch.object(hashlib, "pbkdf2_hmac", None):
            actual = params.derive(b"password", b"salt")
        self.assertEqual(actual, expected)

    def test_dummy_hash_is_structural_and_import_does_not_run_scrypt(self):
        stored = parse_hash(password_hasher.DUMMY_HASH)
        self.assertEqual(stored.algorithm, "scrypt")
        self.assertEqual(stored.digest, b"\x00" * 32)

    def test_needs_rehash(self):
        weak = PasswordHasher(Pbkdf2Params(iterations=1000)).hash("x")
        self.assertTrue(self.hasher.needs_rehash(weak))
        self.assertFalse(self.hasher.needs_rehash(self.hasher.hash("x")))

    def test_cross_algorithm_verify(self):
        weak = PasswordHasher(Pbkdf2Params(iterations=1000)).hash("x")
        self.assertTrue(self.hasher.verify("x", weak))

    def test_pepper(self):
        peppered = PasswordHasher(pepper=b"pep")
        stored = peppered.hash("x")
        self.assertTrue(peppered.verify("x", stored))
        self.assertFalse(PasswordHasher().verify("x", stored))

    def test_fake_verify_false(self):
        self.assertFalse(self.hasher.fake_verify("anything"))

    def test_unicode_normalisation(self):
        # NFC vs NFD forms of the same string must verify against each other.
        stored = self.hasher.hash("café")  # composed
        self.assertTrue(self.hasher.verify("café", stored))  # decomposed

    def test_malformed_hash(self):
        self.assertFalse(self.hasher.verify("x", "not-a-hash"))


class TestArgon2(unittest.TestCase):
    """RFC vectors plus the password-storage integration around the primitive."""

    # RFC 9106 sections 5.1-5.3. A self-roundtrip would only prove that our
    # encoder and verifier share the same bug; these published tags prove
    # compatibility with independent implementations.
    RFC9106_TAGS = {
        TYPE_D: "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
        TYPE_I: "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
        TYPE_ID: "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
    }

    def test_rfc9106_vectors(self):
        for variant, expected in self.RFC9106_TAGS.items():
            with self.subTest(variant=variant):
                tag = argon2(
                    b"\x01" * 32,
                    b"\x02" * 16,
                    time_cost=3,
                    memory_cost=32,
                    parallelism=4,
                    tag_length=32,
                    variant=variant,
                    secret=b"\x03" * 8,
                    associated_data=b"\x04" * 12,
                )
                self.assertEqual(tag.hex(), expected)

    def test_argon2id_phc_roundtrip_and_wrong_password(self):
        hasher = PasswordHasher(Argon2Params.teaching())
        stored = hasher.hash("correct horse", salt=b"\x02" * 16)
        parsed = parse_hash(stored)
        self.assertEqual(parsed.algorithm, "argon2id")
        self.assertEqual(parsed.version, 19)
        self.assertEqual(parsed.params, "m=64,t=2,p=1")
        self.assertTrue(hasher.verify("correct horse", stored))
        self.assertFalse(hasher.verify("wrong battery", stored))
        self.assertFalse(hasher.needs_rehash(stored))

    def test_parameter_tampering_breaks_the_tag(self):
        hasher = PasswordHasher(Argon2Params.teaching())
        stored = hasher.hash("secret", salt=b"\x02" * 16)
        self.assertFalse(hasher.verify("secret", stored.replace("t=2", "t=1", 1)))

    def test_version_field_is_argon2_only(self):
        with self.assertRaises(ValueError):
            parse_hash("$scrypt$v=19$n=16384,r=8,p=1$AA$AA")

    def test_pure_backend_refuses_production_cost(self):
        if ARGON2_BACKEND != "pure":
            self.skipTest("argon2-cffi is installed, so the native backend owns production cost")
        with self.assertRaises(Argon2Error):
            Argon2Params().derive(b"password", b"\x02" * 16)

    def test_fake_verify_uses_argon2_cost(self):
        hasher = PasswordHasher(Argon2Params.teaching(memory_cost=32, time_cost=1))
        self.assertFalse(hasher.fake_verify("unknown user password"))

    def test_optional_cffi_backend_selects_argon2id(self):
        called = {}

        def hash_secret_raw(**kwargs):
            called.update(kwargs)
            return b"\xaa" * kwargs["hash_len"]

        fake_argon2 = SimpleNamespace(
            low_level=SimpleNamespace(
                Type={"ID": "native-id", "I": "native-i", "D": "native-d"},
                hash_secret_raw=hash_secret_raw,
            )
        )
        with (
            patch.object(password_hasher, "ARGON2_BACKEND", "cffi"),
            patch.dict(sys.modules, {"argon2": fake_argon2}),
        ):
            result = Argon2Params.teaching().derive(b"password", b"\x02" * 16)
        self.assertEqual(called["type"], "native-id")
        self.assertEqual(result, b"\xaa" * 32)


class TestHOTP(unittest.TestCase):
    def test_rfc4226(self):
        secret = b"12345678901234567890"
        expected = ["755224", "287082", "359152", "969429", "338314",
                    "254676", "287922", "162583", "399871", "520489"]
        self.assertEqual([hotp(secret, c) for c in range(10)], expected)


class TestTOTP(unittest.TestCase):
    def test_rfc6238_sha1(self):
        secret = b"12345678901234567890"
        self.assertEqual(totp(secret, 59, digits=8), "94287082")
        self.assertEqual(totp(secret, 1111111109, digits=8), "07081804")

    def test_rfc6238_sha256(self):
        secret = b"12345678901234567890123456789012"
        self.assertEqual(totp(secret, 59, digits=8, algorithm="sha256"), "46119246")

    def test_rfc6238_sha512(self):
        secret = b"1234567890123456789012345678901234567890123456789012345678901234"
        self.assertEqual(totp(secret, 59, digits=8, algorithm="sha512"), "90693936")

    def test_replay_rejected(self):
        clock = FrozenClock(1_700_000_000)
        validator = TOTP(secret=b"12345678901234567890", clock=clock)
        code = validator.now_code()
        self.assertTrue(validator.verify(code))
        self.assertFalse(validator.verify(code))

    def test_drift_window(self):
        clock = FrozenClock(1_700_000_000)
        validator = TOTP(secret=b"12345678901234567890", clock=clock, window=1)
        code = validator.now_code()
        clock.advance(29)
        self.assertTrue(validator.verify(code))


class TestRecoveryCodes(unittest.TestCase):
    def test_single_use(self):
        store, codes = RecoveryCodes.generate(5)
        self.assertTrue(store.consume(codes[0]))
        self.assertFalse(store.consume(codes[0]))
        self.assertEqual(store.remaining, 4)

    def test_wrong_code(self):
        store, _ = RecoveryCodes.generate(3)
        self.assertFalse(store.consume("00000-00000"))

    def test_normalisation(self):
        store, codes = RecoveryCodes.generate(1)
        self.assertTrue(store.consume(codes[0].lower().replace("-", " ")))


if __name__ == "__main__":
    unittest.main()
