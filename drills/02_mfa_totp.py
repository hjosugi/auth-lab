"""Drill 02 -- TOTP/HOTP against the RFC vectors, replay, and recovery codes."""

from __future__ import annotations

from _util import assert_true, note, step, title

from authlab.mfa import RecoveryCodes, TOTP, hotp, totp
from authlab.util.clock import FrozenClock


def main() -> None:
    title("Drill 02: multi-factor (TOTP / HOTP)")

    step(1, "HOTP matches the RFC 4226 Appendix D test vectors.")
    secret = b"12345678901234567890"
    expected = ["755224", "287082", "359152", "969429", "338314"]
    got = [hotp(secret, counter) for counter in range(5)]
    note(f"counters 0..4 -> {got}")
    assert_true(got == expected, "HOTP matches the published vectors")

    step(2, "TOTP matches the RFC 6238 Appendix B vector (SHA-1, 8 digits, t=59).")
    assert_true(totp(secret, 59, digits=8) == "94287082", "TOTP(t=59) == 94287082")

    step(3, "A code is accepted once, then refused (replay protection).")
    clock = FrozenClock(1_700_000_000)
    validator = TOTP(secret=secret, clock=clock)
    code = validator.now_code()
    note(f"current code: {code}, {validator.seconds_remaining()}s remaining in this step")
    assert_true(validator.verify(code), "first use accepted")
    assert_true(not validator.verify(code), "same code within the step is refused (replay)")

    step(4, "A code from the previous step is refused once we advance.")
    old_code = validator.now_code()
    clock.advance(30)
    assert_true(not validator.verify(old_code), "stale code from the prior step is refused")

    step(5, "Clock drift within +/- one step is tolerated.")
    clock2 = FrozenClock(1_700_000_000)
    v2 = TOTP(secret=secret, clock=clock2, window=1)
    code_now = v2.now_code()
    clock2.advance(29)  # still within the same or adjacent step
    assert_true(v2.verify(code_now), "code accepted across a 29s drift")

    step(6, "Recovery codes are single-use.")
    store, codes = RecoveryCodes.generate(5)
    note(f"issued {len(codes)} codes, e.g. {codes[0]}")
    assert_true(store.consume(codes[0]), "a valid recovery code works once")
    assert_true(not store.consume(codes[0]), "the same code cannot be reused")
    assert_true(store.remaining == 4, "four codes remain")

    step(7, "provisioning URI for a QR code.")
    note(TOTP(secret=secret).uri("alice@auth-lab", "auth-lab"))

    print("\nDrill 02 complete.")


if __name__ == "__main__":
    main()
