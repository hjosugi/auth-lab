"""Just enough DER to export an RSA key as PEM.

A JWKS carries RSA keys as base64url integers, so strictly we do not need DER
at all. But every time you hand a key to another tool -- openssl, a Java
keystore, curl --cert -- you hand it PEM, and PEM is base64 of DER. Being
able to see the four bytes that turn an integer into "an ASN.1 INTEGER"
removes the last bit of magic from key files.

DER is TLV: a tag byte, a length, then the value.
  INTEGER    = 0x02
  BIT STRING = 0x03
  OCTET STR  = 0x04
  NULL       = 0x05
  OID        = 0x06
  SEQUENCE   = 0x30 (constructed)
"""

from __future__ import annotations

import base64

from ..util.encoding import int_to_bytes


def _der_length(n: int) -> bytes:
    """DER length encoding: short form below 128, else long form."""
    if n < 0x80:
        return bytes([n])
    body = int_to_bytes(n)
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(value)) + value


def der_integer(value: int) -> bytes:
    """Encode a non-negative integer as an ASN.1 INTEGER.

    ASN.1 INTEGERs are signed two's complement, so a value whose top bit is
    set needs a leading 0x00 or it would be read as negative. This is why RSA
    moduli in DER so often start with 00.
    """
    body = int_to_bytes(value)
    if body[0] & 0x80:
        body = b"\x00" + body
    return _tlv(0x02, body)


def der_sequence(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def der_null() -> bytes:
    return b"\x05\x00"


def der_oid(dotted: str) -> bytes:
    """Encode an OID. We only ever need rsaEncryption = 1.2.840.113549.1.1.1."""
    parts = [int(x) for x in dotted.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append((part & 0x7F) | 0x80)
            part >>= 7
        body += bytes(reversed(chunk))
    return _tlv(0x06, body)


def der_bit_string(data: bytes) -> bytes:
    """BIT STRING with zero unused trailing bits."""
    return _tlv(0x03, b"\x00" + data)


def der_octet_string(data: bytes) -> bytes:
    return _tlv(0x04, data)


RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1"


def der_encode_rsa_public_key(n: int, e: int, pkcs8: bool = True) -> bytes:
    """Encode a public key.

    pkcs8=False gives PKCS#1 ("BEGIN RSA PUBLIC KEY"): just SEQUENCE(n, e).
    pkcs8=True gives SubjectPublicKeyInfo ("BEGIN PUBLIC KEY"), which wraps
    that in an algorithm identifier. SPKI is what almost everything expects.
    """
    pkcs1 = der_sequence(der_integer(n), der_integer(e))
    if not pkcs8:
        return pkcs1
    alg = der_sequence(der_oid(RSA_ENCRYPTION_OID), der_null())
    return der_sequence(alg, der_bit_string(pkcs1))


def der_encode_rsa_private_key(
    n: int, e: int, d: int, p: int, q: int, dp: int, dq: int, qinv: int, pkcs8: bool = True
) -> bytes:
    """Encode a private key as PKCS#1 or (wrapped) PKCS#8."""
    pkcs1 = der_sequence(
        der_integer(0),  # version: two-prime
        der_integer(n),
        der_integer(e),
        der_integer(d),
        der_integer(p),
        der_integer(q),
        der_integer(dp),
        der_integer(dq),
        der_integer(qinv),
    )
    if not pkcs8:
        return pkcs1
    alg = der_sequence(der_oid(RSA_ENCRYPTION_OID), der_null())
    return der_sequence(der_integer(0), alg, der_octet_string(pkcs1))


def pem_wrap(der: bytes, label: str) -> str:
    """Wrap DER bytes in a PEM armour with 64-character lines."""
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"
