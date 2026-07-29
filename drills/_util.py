"""Shared helpers for drills: pretty section headers and pass/fail markers.

A drill is a runnable, narrated walk through one protocol. Run one directly
(`python drills/05_refresh_rotation.py`) or all of them via
`python drills/run_all.py`. Each drill is self-checking: it asserts the
security property it is demonstrating, so a regression in the library turns a
drill red instead of quietly lying.
"""

from __future__ import annotations

import sys

GREEN = "\033[32m"
RED = "\033[31m"
CYAN = "\033[36m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

_use_color = sys.stdout.isatty()


def _c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}" if _use_color else text


def title(text: str) -> None:
    line = "=" * len(text)
    print(f"\n{_c(text, BOLD)}\n{_c(line, DIM)}")


def step(number: int | str, text: str) -> None:
    print(f"{_c(f'[{number}]', CYAN)} {text}")


def note(text: str) -> None:
    print(f"    {_c(text, DIM)}")


def good(text: str) -> None:
    print(f"    {_c('OK', GREEN)}  {text}")


def blocked(text: str) -> None:
    print(f"    {_c('BLOCKED', GREEN)} {text}")


def expect_reject(label: str, fn) -> None:
    """Run fn, which MUST raise. Print the rejection reason; assert if it does not."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - drills catch broadly on purpose
        blocked(f"{label} -> {type(exc).__name__}: {str(exc)[:80]}")
        return
    print(f"    {_c('BUG', RED)} {label} was ACCEPTED but should have been rejected")
    raise AssertionError(f"{label} should have been rejected")


def assert_true(condition: bool, label: str) -> None:
    if condition:
        good(label)
    else:
        print(f"    {_c('FAIL', RED)} {label}")
        raise AssertionError(label)
