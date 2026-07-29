import unittest

from authlab.crypto import (
    generate_rsa_keypair,
    is_probable_prime,
    rsassa_pkcs1_v15_sign,
    rsassa_pkcs1_v15_verify,
)
from authlab.crypto.ec import (
    ECPublicKey,
    ecdsa_sign,
    ecdsa_verify,
    generate_ec_keypair,
    signature_from_der,
    signature_from_raw,
    signature_to_der,
    signature_to_raw,
    N,
)
from authlab.crypto import aes, cbor


class TestPrimes(unittest.TestCase):
    def test_known_primes(self):
        for p in (2, 3, 5, 7, 97, 7919, 104729):
            self.assertTrue(is_probable_prime(p))

    def test_known_composites(self):
        for n in (0, 1, 4, 100, 7920, 104730, 561):  # 561 is a Carmichael number
            self.assertFalse(is_probable_prime(n))


class TestRSA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = generate_rsa_keypair(2048)

    def test_size(self):
        self.assertEqual(self.key.key_size_bits, 2048)

    def test_sign_verify(self):
        sig = rsassa_pkcs1_v15_sign(self.key, b"hello")
        self.assertEqual(len(sig), 256)
        self.assertTrue(rsassa_pkcs1_v15_verify(self.key.public, b"hello", sig))

    def test_tamper(self):
        sig = rsassa_pkcs1_v15_sign(self.key, b"hello")
        self.assertFalse(rsassa_pkcs1_v15_verify(self.key.public, b"world", sig))
        self.assertFalse(rsassa_pkcs1_v15_verify(self.key.public, b"hello", sig[:-1] + bytes([sig[-1] ^ 1])))

    def test_wrong_length_signature(self):
        sig = rsassa_pkcs1_v15_sign(self.key, b"hello")
        self.assertFalse(rsassa_pkcs1_v15_verify(self.key.public, b"hello", sig[1:]))


class TestECDSA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = generate_ec_keypair()

    def test_sign_verify(self):
        sig = ecdsa_sign(self.key, b"message")
        self.assertTrue(ecdsa_verify(self.key.public, b"message", sig))

    def test_deterministic(self):
        self.assertEqual(ecdsa_sign(self.key, b"m"), ecdsa_sign(self.key, b"m"))

    def test_low_s(self):
        _, s = ecdsa_sign(self.key, b"m")
        self.assertLessEqual(s, N // 2)

    def test_encodings_roundtrip(self):
        sig = ecdsa_sign(self.key, b"m")
        self.assertEqual(signature_from_raw(signature_to_raw(sig)), sig)
        self.assertEqual(signature_from_der(signature_to_der(sig)), sig)
        self.assertEqual(len(signature_to_raw(sig)), 64)

    def test_off_curve_rejected(self):
        with self.assertRaises(ValueError):
            ECPublicKey.from_uncompressed(b"\x04" + b"\x01" * 64)


class TestAES(unittest.TestCase):
    def test_fips197_vectors(self):
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        cases = [
            (bytes.fromhex("000102030405060708090a0b0c0d0e0f"), "69c4e0d86a7b0430d8cdb78070b4c55a"),
            (bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617"), "dda97ca4864cdfe06eaf70a0ec0d7191"),
            (bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), "8ea2b7ca516745bfeafc49904b496089"),
        ]
        for key, expected in cases:
            self.assertEqual(aes.AES(key).encrypt_block(pt).hex(), expected)
            self.assertEqual(aes.AES(key).decrypt_block(bytes.fromhex(expected)), pt)

    def test_encrypt_then_mac(self):
        ct = aes.encrypt_then_mac(b"k" * 32, b"m" * 32, b"payload across multiple blocks!!")
        self.assertEqual(aes.verify_then_decrypt(b"k" * 32, b"m" * 32, ct), b"payload across multiple blocks!!")

    def test_tamper_rejected(self):
        ct = bytearray(aes.encrypt_then_mac(b"k" * 32, b"m" * 32, b"data"))
        ct[20] ^= 1
        with self.assertRaises(ValueError):
            aes.verify_then_decrypt(b"k" * 32, b"m" * 32, bytes(ct))


class TestCBOR(unittest.TestCase):
    def test_rfc8949_vectors(self):
        cases = [(0, "00"), (23, "17"), (24, "1818"), (-1, "20"), (b"\x01\x02", "420102"),
                 ("IETF", "6449455446"), ([1, 2, 3], "83010203"), ({1: 2, 3: 4}, "a201020304"),
                 (True, "f5"), (False, "f4"), (None, "f6")]
        for value, hexstr in cases:
            self.assertEqual(cbor.encode(value).hex(), hexstr)
            self.assertEqual(cbor.decode(bytes.fromhex(hexstr)), value)

    def test_non_canonical_rejected(self):
        with self.assertRaises(ValueError):
            cbor.decode(bytes.fromhex("a203040102"))  # map keys out of order

    def test_trailing_bytes_rejected(self):
        with self.assertRaises(ValueError):
            cbor.decode(b"\x00\x00")


if __name__ == "__main__":
    unittest.main()
