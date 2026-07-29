"""A minimal X.509 v3 certificate authority.

mTLS is the one protocol in this repo you cannot really learn from a diagram,
because everything interesting is in the certificate chain. So we mint real
certificates here -- a self-signed CA, a server certificate, and client
certificates -- and Python's own `ssl` module accepts them, which means the
mTLS drill performs a genuine TLS handshake with genuine client-certificate
verification. Nothing is simulated.

A certificate is a signed statement with three parts:

    Certificate ::= SEQUENCE {
        tbsCertificate       TBSCertificate,   -- the claims
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING }      -- CA's signature over the DER
                                               -- of tbsCertificate

"tbs" is To Be Signed. The verifier re-encodes nothing: it takes the exact
DER bytes of the tbsCertificate as they appeared on the wire and checks the
signature over them. That is the same rule as JWS, for the same reason.

What actually gets checked in a chain (and what people forget):

  * signature by the issuer's public key, up to a trusted root
  * validity window on EVERY certificate in the chain, not just the leaf
  * basicConstraints cA=TRUE on every intermediate -- the check whose absence
    let anyone with any valid leaf certificate sign certificates for any
    domain in the 2002 and 2009 rounds of this bug
  * keyUsage / extendedKeyUsage matching the purpose (serverAuth vs clientAuth)
  * the name: subjectAltName, not the CN. CN has been deprecated for host
    matching since RFC 2818 and browsers stopped honouring it in 2017.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from ..util.ct import random_bytes
from .asn1 import (
    RSA_ENCRYPTION_OID,
    _tlv,
    der_bit_string,
    der_encode_rsa_public_key,
    der_encode_rsa_private_key,
    der_integer,
    der_null,
    der_octet_string,
    der_oid,
    der_sequence,
    pem_wrap,
)
from .rsa import RSAPrivateKey, rsassa_pkcs1_v15_sign

SHA256_WITH_RSA_OID = "1.2.840.113549.1.1.11"

# Distinguished-name attribute types.
DN_OIDS = {
    "CN": "2.5.4.3",
    "O": "2.5.4.10",
    "OU": "2.5.4.11",
    "C": "2.5.4.6",
    "ST": "2.5.4.8",
    "L": "2.5.4.7",
}

EXT_OIDS = {
    "subjectKeyIdentifier": "2.5.29.14",
    "keyUsage": "2.5.29.15",
    "subjectAltName": "2.5.29.17",
    "basicConstraints": "2.5.29.19",
    "authorityKeyIdentifier": "2.5.29.35",
    "extKeyUsage": "2.5.29.37",
}

EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"

# keyUsage bit positions from RFC 5280 section 4.2.1.3.
KU_DIGITAL_SIGNATURE = 0
KU_KEY_ENCIPHERMENT = 2
KU_KEY_CERT_SIGN = 5
KU_CRL_SIGN = 6


def der_utf8_string(text: str) -> bytes:
    return _tlv(0x0C, text.encode("utf-8"))


def der_ia5_string(text: str) -> bytes:
    return _tlv(0x16, text.encode("ascii"))


def der_boolean(value: bool) -> bytes:
    return _tlv(0x01, b"\xff" if value else b"\x00")


def der_set(*items: bytes) -> bytes:
    return _tlv(0x31, b"".join(items))


def der_utc_time(when: datetime) -> bytes:
    """UTCTime: YYMMDDHHMMSSZ. Valid only through 2049 -- after that RFC 5280
    requires GeneralizedTime, which is the Y2050 problem certificates have."""
    return _tlv(0x17, when.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def der_explicit(tag_number: int, content: bytes) -> bytes:
    """A context-specific EXPLICIT tag: [n] wrapping the inner encoding."""
    return _tlv(0xA0 | tag_number, content)


def der_implicit_primitive(tag_number: int, content: bytes) -> bytes:
    """A context-specific IMPLICIT primitive tag, used by GeneralName."""
    return _tlv(0x80 | tag_number, content)


def der_bit_string_bits(bit_positions: list[int]) -> bytes:
    """Encode a BIT STRING from a list of set bit positions (keyUsage)."""
    if not bit_positions:
        return _tlv(0x03, b"\x00")
    highest = max(bit_positions)
    length = highest // 8 + 1
    data = bytearray(length)
    for bit in bit_positions:
        data[bit // 8] |= 0x80 >> (bit % 8)
    unused = 7 - (highest % 8)
    return _tlv(0x03, bytes([unused]) + bytes(data))


def encode_name(attributes: dict[str, str]) -> bytes:
    """Encode a distinguished name.

    Order matters for byte-exact issuer/subject matching during chain
    building, so we emit a fixed, conventional order rather than dict order.
    """
    order = ["C", "ST", "L", "O", "OU", "CN"]
    rdns = []
    for key in order:
        if key in attributes:
            rdns.append(
                der_set(der_sequence(der_oid(DN_OIDS[key]), der_utf8_string(attributes[key])))
            )
    return der_sequence(*rdns)


def encode_extension(oid: str, critical: bool, value: bytes) -> bytes:
    parts = [der_oid(oid)]
    if critical:
        # DEFAULT FALSE, so DER forbids emitting the boolean when it is false.
        parts.append(der_boolean(True))
    parts.append(der_octet_string(value))
    return der_sequence(*parts)


def subject_key_identifier(n: int, e: int) -> bytes:
    """SHA-1 of the BIT STRING contents of the SPKI (RFC 5280 method 1).

    SHA-1 here is a naming convention, not a security control -- it identifies
    which key signed what during chain building. A collision would not forge
    anything on its own.
    """
    spki = der_encode_rsa_public_key(n, e, pkcs8=True)
    # Reach into the SPKI to hash just the public key bits.
    inner = der_encode_rsa_public_key(n, e, pkcs8=False)
    assert inner in spki
    return hashlib.sha1(inner).digest()


@dataclass
class Certificate:
    """A minted certificate plus the private key that goes with it."""

    der: bytes
    private_key: RSAPrivateKey
    subject: dict[str, str]
    serial: int
    tbs_der: bytes = b""
    _extra: dict = field(default_factory=dict)

    def pem(self) -> str:
        return pem_wrap(self.der, "CERTIFICATE")

    def key_pem(self) -> str:
        return pem_wrap(
            der_encode_rsa_private_key(
                self.private_key.n,
                self.private_key.e,
                self.private_key.d,
                self.private_key.p,
                self.private_key.q,
                self.private_key.dp,
                self.private_key.dq,
                self.private_key.qinv,
                pkcs8=True,
            ),
            "PRIVATE KEY",
        )

    def fingerprint_sha256(self) -> bytes:
        """SHA-256 over the full DER certificate.

        This is the value RFC 8705 puts in a token's `cnf.x5t#S256` claim to
        bind an access token to the client certificate that requested it.
        """
        return hashlib.sha256(self.der).digest()


class CertificateAuthority:
    """A tiny CA that issues server and client certificates."""

    def __init__(
        self,
        common_name: str = "auth-lab Root CA",
        organization: str = "auth-lab",
        key: RSAPrivateKey | None = None,
        days: int = 3650,
        key_bits: int = 2048,
    ) -> None:
        from .rsa import generate_rsa_keypair

        self.key = key or generate_rsa_keypair(key_bits)
        self.name = {"CN": common_name, "O": organization}
        self.certificate = self._self_sign(days)

    def _validity(self, days: int) -> bytes:
        now = datetime.now(timezone.utc)
        # Backdate slightly so a client with a marginally slow clock does not
        # reject a certificate that was issued a moment ago.
        not_before = now - timedelta(minutes=5)
        not_after = now + timedelta(days=days)
        return der_sequence(der_utc_time(not_before), der_utc_time(not_after))

    def _self_sign(self, days: int) -> Certificate:
        serial = int.from_bytes(random_bytes(16), "big") >> 1  # positive, 127 bits
        extensions = [
            # cA=TRUE with pathLen=0: this root may sign leaf certificates but
            # not further CAs. Marking it critical means a client that does not
            # understand basicConstraints must reject the certificate rather
            # than ignore the limit.
            encode_extension(
                EXT_OIDS["basicConstraints"], True, der_sequence(der_boolean(True), der_integer(0))
            ),
            encode_extension(
                EXT_OIDS["keyUsage"],
                True,
                der_bit_string_bits([KU_KEY_CERT_SIGN, KU_CRL_SIGN, KU_DIGITAL_SIGNATURE]),
            ),
            encode_extension(
                EXT_OIDS["subjectKeyIdentifier"],
                False,
                der_octet_string(subject_key_identifier(self.key.n, self.key.e)),
            ),
        ]
        return self._issue(
            subject=self.name,
            public_key=(self.key.n, self.key.e),
            private_key=self.key,
            serial=serial,
            validity=self._validity(days),
            extensions=extensions,
        )

    def _issue(
        self,
        subject: dict[str, str],
        public_key: tuple[int, int],
        private_key: RSAPrivateKey,
        serial: int,
        validity: bytes,
        extensions: list[bytes],
    ) -> Certificate:
        n, e = public_key
        alg = der_sequence(der_oid(SHA256_WITH_RSA_OID), der_null())
        tbs = der_sequence(
            der_explicit(0, der_integer(2)),  # version v3
            der_integer(serial),
            alg,
            encode_name(self.name),  # issuer
            validity,
            encode_name(subject),
            der_encode_rsa_public_key(n, e, pkcs8=True),
            der_explicit(3, der_sequence(*extensions)),
        )
        signature = rsassa_pkcs1_v15_sign(self.key, tbs, "sha256")
        certificate = der_sequence(tbs, alg, der_bit_string(signature))
        return Certificate(
            der=certificate, private_key=private_key, subject=subject, serial=serial, tbs_der=tbs
        )

    def issue(
        self,
        common_name: str,
        *,
        dns_names: list[str] | None = None,
        ip_addresses: list[str] | None = None,
        client_auth: bool = False,
        server_auth: bool = False,
        organization: str | None = None,
        days: int = 825,
        key: RSAPrivateKey | None = None,
        key_bits: int = 2048,
    ) -> Certificate:
        """Issue a leaf certificate.

        825 days is the CA/Browser Forum's old maximum; public CAs are now at
        398 and heading to 47. Short lifetimes are the practical answer to
        revocation, because CRL and OCSP have never worked reliably -- a
        browser that cannot reach the OCSP responder soft-fails and proceeds.
        """
        from .rsa import generate_rsa_keypair

        leaf_key = key or generate_rsa_keypair(key_bits)
        subject = {"CN": common_name}
        if organization:
            subject["O"] = organization

        ekus = []
        if server_auth:
            ekus.append(der_oid(EKU_SERVER_AUTH))
        if client_auth:
            ekus.append(der_oid(EKU_CLIENT_AUTH))

        extensions = [
            # cA=FALSE, critical: a leaf must never be usable as a CA.
            encode_extension(EXT_OIDS["basicConstraints"], True, der_sequence()),
            encode_extension(
                EXT_OIDS["keyUsage"],
                True,
                der_bit_string_bits([KU_DIGITAL_SIGNATURE, KU_KEY_ENCIPHERMENT]),
            ),
            encode_extension(
                EXT_OIDS["subjectKeyIdentifier"],
                False,
                der_octet_string(subject_key_identifier(leaf_key.n, leaf_key.e)),
            ),
            encode_extension(
                EXT_OIDS["authorityKeyIdentifier"],
                False,
                der_sequence(
                    der_implicit_primitive(0, subject_key_identifier(self.key.n, self.key.e))
                ),
            ),
        ]
        if ekus:
            extensions.append(
                encode_extension(EXT_OIDS["extKeyUsage"], False, der_sequence(*ekus))
            )

        general_names = []
        for name in dns_names or []:
            general_names.append(der_implicit_primitive(2, name.encode("ascii")))  # dNSName
        for address in ip_addresses or []:
            packed = bytes(int(part) for part in address.split("."))
            general_names.append(der_implicit_primitive(7, packed))  # iPAddress
        if general_names:
            # SAN is what actually gets matched against the hostname. If it is
            # present, CN is ignored entirely.
            extensions.append(
                encode_extension(
                    EXT_OIDS["subjectAltName"], False, der_sequence(*general_names)
                )
            )

        serial = int.from_bytes(random_bytes(16), "big") >> 1
        return self._issue(
            subject=subject,
            public_key=(leaf_key.n, leaf_key.e),
            private_key=leaf_key,
            serial=serial,
            validity=self._validity(days),
            extensions=extensions,
        )

    def ca_pem(self) -> str:
        return self.certificate.pem()
