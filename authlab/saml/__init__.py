from .signature import sign_element, verify_signature, canonicalize, XMLSignatureError
from .c14n import exclusive_canonicalize, CanonicalizationError
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
    "exclusive_canonicalize",
    "CanonicalizationError",
    "XMLSignatureError",
    "ServiceProvider",
    "IdentityProvider",
    "SAMLError",
    "NAMEID_EMAIL",
    "NAMEID_PERSISTENT",
    "NAMEID_TRANSIENT",
]
