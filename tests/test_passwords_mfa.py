import unittest

from authlab.mfa import RecoveryCodes, TOTP, hotp, totp
from authlab.passwords import PasswordHasher, Pbkdf2Params, ScryptParams
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
