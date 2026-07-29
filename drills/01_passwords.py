"""Drill 01 -- Password storage, timing, and rehash-on-login.

Learn by watching: what a stored hash actually looks like, why login timing
must not leak whether a user exists, and how a cost upgrade rolls out without
asking anyone to reset their password.
"""

from __future__ import annotations

import statistics
import time

from _util import assert_true, good, note, step, title

from authlab.passwords import PasswordHasher, Pbkdf2Params, ScryptParams


def main() -> None:
    title("Drill 01: password storage")
    hasher = PasswordHasher()

    step(1, "Hash a password. The stored string is self-describing.")
    stored = hasher.hash("correct horse battery staple")
    note(stored)
    note("$scrypt$ params $ salt $ hash  -- algorithm and cost travel with the hash")

    step(2, "Verify: right password accepts, wrong password rejects.")
    assert_true(hasher.verify("correct horse battery staple", stored), "correct password verifies")
    assert_true(not hasher.verify("wrong", stored), "wrong password rejected")

    step(3, "Salt makes identical passwords hash differently.")
    a = hasher.hash("same-password")
    b = hasher.hash("same-password")
    assert_true(a != b, "two hashes of the same password differ (per-user salt)")

    step(4, "User enumeration: existing-but-wrong vs non-existent must match in time.")

    def median_ms(fn, *args) -> float:
        samples = []
        for _ in range(7):
            start = time.perf_counter()
            fn(*args)
            samples.append((time.perf_counter() - start) * 1000)
        return statistics.median(samples)

    existing = median_ms(hasher.verify, "wrong-password", stored)
    missing = median_ms(hasher.fake_verify, "wrong-password")
    note(f"existing user, wrong password: {existing:.1f} ms")
    note(f"non-existent user (fake_verify): {missing:.1f} ms")
    assert_true(abs(existing - missing) < existing * 0.5, "timings are within 50% (no enumeration oracle)")

    step(5, "Cost upgrade: an old PBKDF2 hash still verifies and is flagged for rehash.")
    legacy = PasswordHasher(Pbkdf2Params(iterations=1000)).hash("legacy-pw")
    note(f"legacy hash: {legacy[:40]}...")
    assert_true(hasher.verify("legacy-pw", legacy), "legacy hash still verifies")
    assert_true(hasher.needs_rehash(legacy), "needs_rehash flags the weak parameters")
    if hasher.verify("legacy-pw", legacy) and hasher.needs_rehash(legacy):
        upgraded = hasher.hash("legacy-pw")
        note(f"transparently rehashed to: {upgraded[:24]}...")
        assert_true(not hasher.needs_rehash(upgraded), "upgraded hash no longer needs rehash")

    step(6, "A pepper adds a secret kept outside the database.")
    peppered = PasswordHasher(pepper=b"kept-in-KMS-not-the-DB")
    p = peppered.hash("pw")
    assert_true(peppered.verify("pw", p), "verifies with the right pepper")
    assert_true(not PasswordHasher().verify("pw", p), "same password fails without the pepper")

    print("\nDrill 01 complete.")


if __name__ == "__main__":
    main()
