"""Probable-prime generation for RSA key generation.

RSA needs two large primes. "Large" here means 1024 bits each for a 2048-bit
modulus. There is no practical way to *prove* a random 1024-bit number prime
in a few milliseconds, so every real implementation uses a probabilistic test
and accepts an astronomically small error rate.

Miller-Rabin: write n-1 = d * 2^s with d odd. For a random base a, if n is
prime then either a^d == 1 (mod n) or a^(d*2^r) == -1 (mod n) for some
0 <= r < s. A composite that survives one round is called a strong liar; at
most 1/4 of bases are liars, so k rounds give an error bound of 4^-k. With
k=40 that is under 2^-80, far below the odds of a cosmic ray flipping the
answer anyway.
"""

from __future__ import annotations

import secrets

# Trial division against small primes rejects roughly 80% of odd candidates
# before we ever pay for a modular exponentiation. This is the single biggest
# speedup in a pure-Python keygen.
_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
    317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
    419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499,
    503, 509, 521, 523, 541,
]


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin primality test with `rounds` random bases."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # n - 1 = d * 2^s, d odd
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # 2 <= a <= n-2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # definitely composite
    return True


def generate_prime(bits: int, rounds: int = 40) -> int:
    """A random probable prime with exactly `bits` bits.

    The two high bits are forced on. Setting the top bit guarantees the length;
    setting the second bit guarantees that p*q for two such primes has exactly
    2*bits bits, so a "2048-bit key" really is 2048 bits and not occasionally
    2047. The low bit is forced on because every prime above 2 is odd.
    """
    if bits < 16:
        raise ValueError("refusing to generate a toy prime below 16 bits")
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if is_probable_prime(candidate, rounds):
            return candidate
