"""JOSE error types.

Deliberately fine-grained so drills can assert on *why* a token was rejected.
In production you would collapse all of these into a single opaque "invalid
token" for the caller while logging the specific reason server-side -- telling
an attacker whether the signature or the audience failed is free information.
"""


class JOSEError(Exception):
    """Base class for everything in authlab.jose."""


class InvalidToken(JOSEError):
    """The token is structurally malformed."""


class InvalidSignature(JOSEError):
    """The signature does not verify, or the algorithm is not acceptable."""


class ExpiredToken(JOSEError):
    """The token is outside its validity window (exp / nbf)."""


class ClaimError(JOSEError):
    """A registered or required claim is missing or has the wrong value."""
