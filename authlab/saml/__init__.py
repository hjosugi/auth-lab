from .signature import sign_element, verify_signature, canonicalize, XMLSignatureError
from .protocol import (
    ServiceProvider,
    IdentityProvider,
    SAMLError,
    NAMEID_EMAIL,
    NAMEID_PERSISTENT,
    NAMEID_TRANSIENT,
)

__all__ = [
    "sign_element",
    "verify_signature",
    "canonicalize",
    "XMLSignatureError",
    "ServiceProvider",
    "IdentityProvider",
    "SAMLError",
    "NAMEID_EMAIL",
    "NAMEID_PERSISTENT",
    "NAMEID_TRANSIENT",
]
