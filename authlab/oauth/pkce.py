"""PKCE: Proof Key for Code Exchange (RFC 7636).

The problem PKCE solves: the authorization code comes back to the client
through the *browser*, as a query parameter on a redirect. On mobile, the
redirect lands on a custom URI scheme (myapp://callback) that any other
installed app can also register. A malicious app that wins that race gets the
code -- and for a public client with no secret, the code alone is enough to
get tokens.

PKCE binds the code to whoever started the flow:

  1. Client invents a random `code_verifier` (43-128 chars) and keeps it.
  2. Sends `code_challenge = BASE64URL(SHA256(verifier))` with `S256` on the
     authorization request. Only the hash travels through the browser.
  3. Redeems the code at the token endpoint with the raw verifier.
  4. AS recomputes the hash and compares. An attacker holding a stolen code
     cannot produce the verifier, because SHA-256 does not run backwards.

Two things that are non-negotiable:

* `plain` is not PKCE. It sends the verifier through the browser, which is
  exactly the channel we assumed was compromised. It exists only for devices
  that genuinely cannot compute SHA-256. Refuse it.

* If the AS accepts a request with NO code_challenge, an attacker simply
  omits it -- the downgrade defeats the whole mechanism. So the AS must
  require PKCE for public clients (and OAuth 2.1 requires it for all clients).

PKCE is not a replacement for `state`. PKCE protects the code; `state`
protects against CSRF on the redirect itself. Modern practice is to use both,
or to use OIDC `nonce` plus `state`.
"""

from __future__ import annotations

import hashlib
import re

from ..util.ct import constant_time_equals, random_bytes
from ..util.encoding import b64u_encode
from .errors import InvalidGrant, InvalidRequest

# RFC 7636 section 4.1: 43-128 characters from the unreserved set.
VERIFIER_PATTERN = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")


def create_verifier(n_bytes: int = 32) -> str:
    """A fresh code_verifier. 32 random bytes base64url-encode to 43 chars,
    the RFC minimum, and carry a full 256 bits of entropy."""
    return b64u_encode(random_bytes(n_bytes))


def create_challenge(verifier: str, method: str = "S256") -> str:
    """Derive the code_challenge from a verifier."""
    if method == "S256":
        return b64u_encode(hashlib.sha256(verifier.encode("ascii")).digest())
    if method == "plain":
        # Provided so the drill can demonstrate why it is useless. Never use it.
        return verifier
    raise InvalidRequest(f"unsupported code_challenge_method: {method}")


def generate_pair(method: str = "S256") -> tuple[str, str]:
    """Convenience: returns (verifier, challenge)."""
    verifier = create_verifier()
    return verifier, create_challenge(verifier, method)


def verify(verifier: str, challenge: str, method: str = "S256", allow_plain: bool = False) -> None:
    """Check a verifier against a stored challenge. Raises InvalidGrant on failure."""
    if method == "plain" and not allow_plain:
        raise InvalidRequest("code_challenge_method=plain is refused by this server")
    if not verifier or not VERIFIER_PATTERN.match(verifier):
        raise InvalidGrant("PKCE verification failed")
    if not constant_time_equals(create_challenge(verifier, method), challenge):
        raise InvalidGrant("PKCE verification failed")
