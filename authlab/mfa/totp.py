"""TOTP: time-based one-time passwords (RFC 6238).

TOTP is HOTP with the counter replaced by a clock:

    T = floor((now - T0) / X)          T0 = 0, X = 30 seconds by convention
    code = HOTP(secret, T)

Everything hard about TOTP is operational, not cryptographic:

* Clock drift. Phones are usually within a second of NTP, but hardware tokens
  drift. A window of +/-1 step (so 90 seconds of validity) is the normal
  compromise. Every extra step you allow is another code an attacker can use.

* Replay. A code stays valid for a whole step, so a phished code can be
  reused within that window. The server MUST remember the last accepted step
  per user and refuse anything at or below it. This is the single most
  commonly missing check in homegrown TOTP.

* Secret handling. The shared secret is symmetric: whoever holds it can mint
  codes forever. It has to be encrypted at rest, and phishing a code once is
  survivable while leaking the secret is not. This is the structural reason
  WebAuthn/passkeys beat TOTP -- there is no shared secret to steal, and the
  signature is bound to the origin so a phishing site cannot replay it.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from urllib.parse import quote, urlencode

from ..util.clock import Clock, SystemClock
from ..util.ct import random_bytes
from .hotp import hotp, hotp_verify


def timecode(now: int, period: int = 30, t0: int = 0) -> int:
    """The TOTP step number for a Unix timestamp."""
    return (now - t0) // period


def totp(
    secret: bytes, now: int, period: int = 30, digits: int = 6, algorithm: str = "sha1", t0: int = 0
) -> str:
    """The TOTP value at a given time."""
    return hotp(secret, timecode(now, period, t0), digits, algorithm)


def totp_verify(
    secret: bytes,
    code: str,
    now: int,
    period: int = 30,
    digits: int = 6,
    algorithm: str = "sha1",
    window: int = 1,
    t0: int = 0,
) -> int | None:
    """Verify a TOTP code within +/- `window` steps.

    Returns the matching step number, or None. Callers must persist the
    returned step and reject anything <= it on the next attempt.
    """
    current = timecode(now, period, t0)
    for drift in range(-window, window + 1):
        step = current + drift
        if step < 0:
            continue
        if hotp_verify(secret, code, step, digits, algorithm) is not None:
            return step
    return None


def provisioning_uri(
    secret: bytes,
    account_name: str,
    issuer: str,
    period: int = 30,
    digits: int = 6,
    algorithm: str = "sha1",
) -> str:
    """Build the otpauth:// URI that authenticator apps read from a QR code.

    Format (Google Authenticator's de-facto standard):
      otpauth://totp/Issuer:account?secret=BASE32&issuer=Issuer&...

    The secret is base32 without padding -- base32 because it survives being
    typed by hand from a screen, which base64 does not.
    """
    label = quote(f"{issuer}:{account_name}", safe="")
    params = {
        "secret": base64.b32encode(secret).decode("ascii").rstrip("="),
        "issuer": issuer,
        "algorithm": algorithm.upper(),
        "digits": digits,
        "period": period,
    }
    return f"otpauth://totp/{label}?{urlencode(params)}"


@dataclass
class TOTP:
    """A stateful TOTP validator that refuses replays.

    `last_step` is the state you must persist per user. Keeping it in memory
    means a process restart re-opens the replay window.
    """

    secret: bytes
    period: int = 30
    digits: int = 6
    algorithm: str = "sha1"
    window: int = 1
    last_step: int | None = None
    clock: Clock = SystemClock()

    @classmethod
    def generate(cls, **kwargs) -> "TOTP":
        """New validator with a fresh 20-byte (160-bit) secret, as RFC 4226 recommends."""
        return cls(secret=random_bytes(20), **kwargs)

    def now_code(self, at: int | None = None) -> str:
        return totp(
            self.secret, at if at is not None else self.clock.now(),
            self.period, self.digits, self.algorithm,
        )

    def seconds_remaining(self, at: int | None = None) -> int:
        now = at if at is not None else self.clock.now()
        return self.period - (now % self.period)

    def verify(self, code: str, at: int | None = None) -> bool:
        """Verify and consume a code. A code is accepted at most once."""
        now = at if at is not None else self.clock.now()
        code = code.strip().replace(" ", "")
        step = totp_verify(
            self.secret, code, now, self.period, self.digits, self.algorithm, self.window
        )
        if step is None:
            return False
        if self.last_step is not None and step <= self.last_step:
            return False  # replay, or a code from a step we already burned
        self.last_step = step
        return True

    def uri(self, account_name: str, issuer: str) -> str:
        return provisioning_uri(
            self.secret, account_name, issuer, self.period, self.digits, self.algorithm
        )
