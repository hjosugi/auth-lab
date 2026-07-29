"""Educational certificate chain and OAuth certificate-bound token checks."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .rsa import RSAKeyPair, RSAPublicKey, sign_rs256, verify_rs256
from .util import AuthError, b64url_encode, canonical_json


@dataclass(frozen=True)
class Certificate:
    subject: str
    issuer: str
    serial: str
    public_key: RSAPublicKey
    not_before: int
    not_after: int
    san: str
    eku: str
    signature: bytes

    def payload(self) -> bytes:
        return canonical_json(
            {
                "subject": self.subject,
                "issuer": self.issuer,
                "serial": self.serial,
                "n": str(self.public_key.n),
                "e": self.public_key.e,
                "not_before": self.not_before,
                "not_after": self.not_after,
                "san": self.san,
                "eku": self.eku,
            }
        )

    def thumbprint(self) -> str:
        return b64url_encode(hashlib.sha256(self.payload() + self.signature).digest())


@dataclass
class CertificateAuthority:
    name: str
    key: RSAKeyPair

    def issue(
        self,
        *,
        subject: str,
        public_key: RSAPublicKey,
        serial: str,
        not_before: int,
        not_after: int,
        san: str,
        eku: str,
    ) -> Certificate:
        unsigned = Certificate(
            subject,
            self.name,
            serial,
            public_key,
            not_before,
            not_after,
            san,
            eku,
            b"",
        )
        return Certificate(
            **{
                **unsigned.__dict__,
                "signature": sign_rs256(self.key, unsigned.payload()),
            }
        )

    def verify(
        self,
        certificate: Certificate,
        *,
        now: int,
        expected_san: str,
        expected_eku: str,
    ) -> None:
        if certificate.issuer != self.name:
            raise AuthError("certificate issuer mismatch")
        if not certificate.not_before <= now < certificate.not_after:
            raise AuthError("certificate is outside its validity window")
        if certificate.san != expected_san or certificate.eku != expected_eku:
            raise AuthError("certificate identity or usage mismatch")
        if not verify_rs256(
            self.key.public_key,
            certificate.payload(),
            certificate.signature,
        ):
            raise AuthError("certificate signature invalid")


def bind_token(token_claims: dict[str, object], certificate: Certificate) -> dict[str, object]:
    return {**token_claims, "cnf": {"x5t#S256": certificate.thumbprint()}}


def verify_bound_token(token_claims: dict[str, object], certificate: Certificate) -> None:
    confirmation = token_claims.get("cnf")
    if (
        not isinstance(confirmation, dict)
        or confirmation.get("x5t#S256") != certificate.thumbprint()
    ):
        raise AuthError("access token is not bound to this client certificate")

