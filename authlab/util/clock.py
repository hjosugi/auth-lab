"""An injectable clock.

Every protocol in this repo has time-dependent behaviour: token expiry, TOTP
steps, `nbf`, replay windows. Tests that call time.time() directly are either
slow (they sleep) or flaky (they race the second boundary). So all library
code takes a Clock, and tests pass a FrozenClock they can advance by hand.
"""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> int:
        """Current time as integer seconds since the Unix epoch."""
        ...


class SystemClock:
    """The real wall clock."""

    def now(self) -> int:
        return int(time.time())


class FrozenClock:
    """A clock that only moves when you tell it to."""

    def __init__(self, start: int = 1_700_000_000) -> None:
        self._now = int(start)

    def now(self) -> int:
        return self._now

    def advance(self, seconds: int) -> int:
        self._now += int(seconds)
        return self._now

    def set(self, value: int) -> int:
        self._now = int(value)
        return self._now
