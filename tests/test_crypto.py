import unittest

from authlab.crypto import (
    generate_rsa_keypair,
    is_probable_prime,
    rsassa_pkcs1_v15_sign,
    rsassa_pkcs1_v15_verify,
)
from authlab.crypto.ec import (
    SECP256R1,
    SECP384R1,
    SECP521R1,
    ECPrivateKey,
    ECPublicKey,
    Point,
    ecdsa_sign,
    ecdsa_verify,
    generate_ec_keypair,
    is_on_curve,
    point_add,
    scalar_mult,
    signature_from_der,
    signature_from_raw,
    signature_to_der,
    signature_to_raw,
    N,
)
from authlab.crypto.ed25519 import (
    L,
    Ed25519PrivateKey,
    Ed25519PublicKey,
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_keypair,
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


class TestCurveParameters(unittest.TestCase):
    """Guard the domain parameters themselves.

    A mistyped digit in a curve constant does not raise: it silently produces
    a different group, where signing still "works" and verification fails in
    ways that look like an encoding bug. These two checks catch it.
    """

    CURVES = (SECP256R1, SECP384R1, SECP521R1)

    def test_generator_is_on_its_curve(self):
        for curve in self.CURVES:
            with self.subTest(curve=curve.name):
                self.assertTrue(is_on_curve(curve.generator))

    def test_generator_order(self):
        for curve in self.CURVES:
            with self.subTest(curve=curve.name):
                self.assertTrue(scalar_mult(curve.n, curve.generator).is_infinity)

    def test_field_width_matches_prime(self):
        for curve in self.CURVES:
            with self.subTest(curve=curve.name):
                self.assertEqual(curve.field_bytes, (curve.p.bit_length() + 7) // 8)

    def test_es512_is_p521(self):
        # The name tracks the hash, not the curve. There is no P-512.
        self.assertEqual(SECP521R1.jose_alg, "ES512")
        self.assertEqual(SECP521R1.jose_crv, "P-521")


class TestECDSAOtherCurves(unittest.TestCase):
    def test_sign_verify_each_curve(self):
        for curve in (SECP384R1, SECP521R1):
            with self.subTest(curve=curve.name):
                key = generate_ec_keypair(curve)
                sig = ecdsa_sign(key, b"message")
                self.assertTrue(ecdsa_verify(key.public, b"message", sig))
                self.assertFalse(ecdsa_verify(key.public, b"messagf", sig))

    def test_raw_signature_width_is_fixed(self):
        for curve, width in ((SECP256R1, 64), (SECP384R1, 96), (SECP521R1, 132)):
            with self.subTest(curve=curve.name):
                key = generate_ec_keypair(curve)
                raw = signature_to_raw(ecdsa_sign(key, b"m"), curve)
                self.assertEqual(len(raw), width)

    def test_raw_signature_rejects_wrong_width(self):
        key = generate_ec_keypair(SECP384R1)
        raw = signature_to_raw(ecdsa_sign(key, b"m"), SECP384R1)
        with self.assertRaises(ValueError):
            signature_from_raw(raw, SECP521R1)

    def test_cannot_mix_curves(self):
        # A P-256 point plus a P-384 point is not a typo the maths can absorb.
        with self.assertRaises(ValueError):
            point_add(SECP256R1.generator, SECP384R1.generator)

    def test_p384_key_is_not_on_p256(self):
        key = generate_ec_keypair(SECP384R1)
        smuggled = Point(key.public.x, key.public.y, SECP256R1)
        self.assertFalse(is_on_curve(smuggled))


class TestEd25519(unittest.TestCase):
    # RFC 8032 section 7.1.
    VECTORS = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
            "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69d"
            "a085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3a"
            "c18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ]

    def test_rfc8032_vectors(self):
        for seed, public, message, signature in self.VECTORS:
            with self.subTest(message=message or "(empty)"):
                key = Ed25519PrivateKey(bytes.fromhex(seed))
                self.assertEqual(key.public.data.hex(), public)
                msg = bytes.fromhex(message)
                self.assertEqual(ed25519_sign(key, msg).hex(), signature)
                self.assertTrue(ed25519_verify(key.public, msg, bytes.fromhex(signature)))

    def test_tampered_message_rejected(self):
        key = generate_ed25519_keypair()
        sig = ed25519_sign(key, b"transfer 10")
        self.assertFalse(ed25519_verify(key.public, b"transfer 20", sig))

    def test_signing_is_deterministic(self):
        # No RNG in the signing path at all: the nonce is a hash.
        key = generate_ed25519_keypair()
        self.assertEqual(ed25519_sign(key, b"m"), ed25519_sign(key, b"m"))

    def test_s_above_group_order_rejected(self):
        # Malleability: without the S < L check, S and S+L both verify.
        key = generate_ed25519_keypair()
        sig = ed25519_sign(key, b"m")
        s = int.from_bytes(sig[32:], "little")
        malleable = sig[:32] + ((s + L) % (1 << 256)).to_bytes(32, "little")
        self.assertFalse(ed25519_verify(key.public, b"m", malleable))

    def test_wrong_length_inputs_rejected(self):
        key = generate_ed25519_keypair()
        self.assertFalse(ed25519_verify(key.public, b"m", b"\x00" * 63))
        with self.assertRaises(ValueError):
            Ed25519PublicKey(b"\x00" * 31)
        with self.assertRaises(ValueError):
            Ed25519PrivateKey(b"\x00" * 33)

    def test_non_canonical_public_key_rejected(self):
        with self.assertRaises(ValueError):
            Ed25519PublicKey(b"\xff" * 32)

    def test_identity_public_key_forgery_rejected(self):
        # Without subgroup validation A=identity makes verification independent
        # of the message: choose S=1 and R=B, then [S]B = R + [k]A for every k.
        identity = b"\x01" + b"\x00" * 31
        with self.assertRaises(ValueError):
            Ed25519PublicKey(identity)


class TestECDSAKnownAnswers(unittest.TestCase):
    """RFC 6979 known-answer tests.

    Round-tripping our own signatures only proves we agree with ourselves. A
    published vector is what proves the nonce derivation, the hash truncation,
    and the group arithmetic all match every other implementation.
    """

    # RFC 6979 A.2.5 and A.2.6, message "sample". The RFC prints the raw s;
    # we normalise to low-s, so the expected value is min(s, n - s).
    VECTORS = [
        (
            SECP256R1, "sha256",
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
            "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
            "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
        ),
        (
            SECP384R1, "sha384",
            "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8"
            "96D5724E4C70A825F872C9EA60D2EDF5",
            "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C"
            "81A648152E44ACF96E36DD1E80FABE46",
            "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F"
            "A329C145786E679E7B82C71A38628AC8",
        ),
    ]

    def test_rfc6979_vectors(self):
        for curve, hash_name, d_hex, r_hex, s_hex in self.VECTORS:
            with self.subTest(curve=curve.jose_crv):
                key = ECPrivateKey(int(d_hex, 16), curve)
                r, s = ecdsa_sign(key, b"sample", hash_name)
                expected_s = int(s_hex, 16)
                self.assertEqual(r, int(r_hex, 16))
                self.assertEqual(s, min(expected_s, curve.n - expected_s))
                self.assertTrue(ecdsa_verify(key.public, b"sample", (r, s), hash_name))

    def test_signature_does_not_transfer_between_curves(self):
        p256 = generate_ec_keypair(SECP256R1)
        p384 = generate_ec_keypair(SECP384R1)
        sig = ecdsa_sign(p256, b"m", "sha256")
        self.assertFalse(ecdsa_verify(p384.public, b"m", sig, "sha384"))


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
