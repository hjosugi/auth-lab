from .authenticator import VirtualAuthenticator, StoredCredential
from .relying_party import (
    RelyingParty,
    WebAuthnError,
    RegisteredCredential,
    verify_credential_signature,
)
from .cose import (
    cose_encode_ec2,
    cose_decode_ec2,
    cose_encode_okp,
    cose_decode_okp,
    cose_decode_public_key,
    cose_algorithm_of,
    COSE_ES256,
    COSE_EDDSA,
    SUPPORTED_ALGORITHMS,
)

__all__ = [
    "VirtualAuthenticator",
    "StoredCredential",
    "RelyingParty",
    "WebAuthnError",
    "RegisteredCredential",
    "verify_credential_signature",
    "cose_encode_ec2",
    "cose_decode_ec2",
    "cose_encode_okp",
    "cose_decode_okp",
    "cose_decode_public_key",
    "cose_algorithm_of",
    "COSE_ES256",
    "COSE_EDDSA",
    "SUPPORTED_ALGORITHMS",
]
