"""AES-128/192/256 and CBC mode, written out longhand.

Kerberos needs a symmetric cipher and the standard library has none, so here
it is. AES is a substitution-permutation network: 10/12/14 rounds of

    SubBytes    -> byte-wise S-box, the only non-linear step
    ShiftRows   -> rotate row i left by i, so bytes diffuse across columns
    MixColumns  -> multiply each column by a fixed matrix in GF(2^8)
    AddRoundKey -> XOR in this round's key

The last round drops MixColumns (it would be undone by the inverse anyway and
adds nothing). The key schedule expands the key into one round key per round.

Two warnings that matter more than the cipher itself:

* CBC without authentication is not secure. An attacker who can flip
  ciphertext bits flips the corresponding plaintext bits in the *next* block,
  and if the server distinguishes "bad padding" from "bad content" they can
  decrypt everything one byte at a time -- the padding oracle. So the CBC
  helper here always pairs with an HMAC in encrypt-then-MAC order, which is
  the only one of the three orderings that is generically safe.

* This is not constant-time. Table-driven AES in any language leaks through
  cache timing; real implementations use AES-NI. Never ship this.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod

from ..util.ct import constant_time_equals, random_bytes

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)
_INV_SBOX = bytes(256)
_inv = bytearray(256)
for _i, _v in enumerate(_SBOX):
    _inv[_v] = _i
_INV_SBOX = bytes(_inv)

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


def _xtime(a: int) -> int:
    """Multiply by 2 in GF(2^8) modulo the AES polynomial x^8+x^4+x^3+x+1."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gmul(a: int, b: int) -> int:
    """Multiply two field elements."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


class AES:
    """A single AES key, expanded once and reused."""

    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes")
        self.key = key
        self.nk = len(key) // 4              # key length in 32-bit words
        self.rounds = self.nk + 6            # 10, 12, or 14
        self.round_keys = self._expand_key(key)

    def _expand_key(self, key: bytes) -> list[list[int]]:
        words = [list(key[4 * i : 4 * i + 4]) for i in range(self.nk)]
        for i in range(self.nk, 4 * (self.rounds + 1)):
            temp = list(words[i - 1])
            if i % self.nk == 0:
                temp = temp[1:] + temp[:1]                       # RotWord
                temp = [_SBOX[b] for b in temp]                  # SubWord
                temp[0] ^= _RCON[i // self.nk - 1]               # Rcon
            elif self.nk > 6 and i % self.nk == 4:
                temp = [_SBOX[b] for b in temp]                  # AES-256 extra SubWord
            words.append([words[i - self.nk][j] ^ temp[j] for j in range(4)])
        return words

    @staticmethod
    def _add_round_key(state: list[int], words: list[list[int]]) -> None:
        for col in range(4):
            for row in range(4):
                state[col * 4 + row] ^= words[col][row]

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("AES block must be 16 bytes")
        state = list(block)
        self._add_round_key(state, self.round_keys[0:4])

        for rnd in range(1, self.rounds + 1):
            state = [_SBOX[b] for b in state]
            state = self._shift_rows(state)
            if rnd != self.rounds:
                state = self._mix_columns(state)
            self._add_round_key(state, self.round_keys[rnd * 4 : rnd * 4 + 4])
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("AES block must be 16 bytes")
        state = list(block)
        self._add_round_key(state, self.round_keys[self.rounds * 4 : self.rounds * 4 + 4])

        for rnd in range(self.rounds - 1, -1, -1):
            state = self._inv_shift_rows(state)
            state = [_INV_SBOX[b] for b in state]
            self._add_round_key(state, self.round_keys[rnd * 4 : rnd * 4 + 4])
            if rnd != 0:
                state = self._inv_mix_columns(state)
        return bytes(state)

    # The state is column-major: byte index = column*4 + row.
    @staticmethod
    def _shift_rows(s: list[int]) -> list[int]:
        out = list(s)
        for row in range(1, 4):
            for col in range(4):
                out[col * 4 + row] = s[((col + row) % 4) * 4 + row]
        return out

    @staticmethod
    def _inv_shift_rows(s: list[int]) -> list[int]:
        out = list(s)
        for row in range(1, 4):
            for col in range(4):
                out[((col + row) % 4) * 4 + row] = s[col * 4 + row]
        return out

    @staticmethod
    def _mix_columns(s: list[int]) -> list[int]:
        out = list(s)
        for col in range(4):
            a = s[col * 4 : col * 4 + 4]
            out[col * 4 + 0] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
            out[col * 4 + 1] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
            out[col * 4 + 2] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
            out[col * 4 + 3] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)
        return out

    @staticmethod
    def _inv_mix_columns(s: list[int]) -> list[int]:
        out = list(s)
        for col in range(4):
            a = s[col * 4 : col * 4 + 4]
            out[col * 4 + 0] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
            out[col * 4 + 1] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
            out[col * 4 + 2] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
            out[col * 4 + 3] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)
        return out


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Pad so the length is a multiple of the block size.

    A full block of padding is added when the input already fits, otherwise
    the decoder could not tell padding from data.
    """
    pad = block_size - (len(data) % block_size)
    return data + bytes([pad]) * pad


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Strip PKCS#7 padding, validating it fully."""
    if not data or len(data) % block_size:
        raise ValueError("invalid padded length")
    pad = data[-1]
    if pad == 0 or pad > block_size or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid padding")
    return data[:-pad]


def cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes | None = None) -> bytes:
    """AES-CBC. Returns iv || ciphertext.

    The IV must be unpredictable, not merely unique: a predictable IV is what
    made BEAST work against TLS 1.0. Generate it from the CSPRNG every time.
    """
    iv = iv if iv is not None else random_bytes(16)
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    cipher = AES(key)
    padded = pkcs7_pad(plaintext)
    out = bytearray()
    previous = iv
    for offset in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[offset : offset + 16], previous))
        previous = cipher.encrypt_block(block)
        out += previous
    return iv + bytes(out)


def cbc_decrypt(key: bytes, data: bytes) -> bytes:
    """Decrypt iv || ciphertext produced by cbc_encrypt."""
    if len(data) < 32 or (len(data) - 16) % 16:
        raise ValueError("invalid ciphertext length")
    cipher = AES(key)
    iv, body = data[:16], data[16:]
    out = bytearray()
    previous = iv
    for offset in range(0, len(body), 16):
        block = body[offset : offset + 16]
        decrypted = cipher.decrypt_block(block)
        out += bytes(a ^ b for a, b in zip(decrypted, previous))
        previous = block
    return pkcs7_unpad(bytes(out))


def encrypt_then_mac(enc_key: bytes, mac_key: bytes, plaintext: bytes) -> bytes:
    """Authenticated encryption: CBC first, then HMAC over the ciphertext.

    Encrypt-then-MAC is the ordering to use. MAC-then-encrypt (what TLS did
    until 1.2, and what Kerberos's older enctypes do) forces the receiver to
    decrypt attacker-controlled bytes before it has verified anything, which
    is exactly the door a padding oracle walks through.
    """
    ciphertext = cbc_encrypt(enc_key, plaintext)
    tag = hmac_mod.new(mac_key, ciphertext, hashlib.sha256).digest()
    return ciphertext + tag


def verify_then_decrypt(enc_key: bytes, mac_key: bytes, data: bytes) -> bytes:
    """Check the tag in constant time BEFORE touching the ciphertext."""
    if len(data) < 32 + 16 + 16:
        raise ValueError("ciphertext too short")
    ciphertext, tag = data[:-32], data[-32:]
    expected = hmac_mod.new(mac_key, ciphertext, hashlib.sha256).digest()
    if not constant_time_equals(expected, tag):
        # Note that the error is identical whatever went wrong. Distinguishing
        # "bad MAC" from "bad padding" is the padding oracle.
        raise ValueError("authentication failed")
    return cbc_decrypt(enc_key, ciphertext)
