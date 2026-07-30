"""Argon2 (RFC 9106), from scratch. TEACHING IMPLEMENTATION -- NOT FOR PRODUCTION.

Argon2id won the 2015 Password Hashing Competition and is the current first
choice for password storage. Read this module to see *why* it is different
from PBKDF2, then use `argon2-cffi` (or your platform's binding) to actually
store passwords. There is a hard parameter cap below that stops this code
being used at real cost settings, because pure Python is roughly four orders
of magnitude too slow to reach them.

What Argon2 buys you over PBKDF2:

    PBKDF2 is CPU-hard only. Its state is a few hundred bytes, so an attacker
    fits thousands of independent instances on one GPU, or bakes it into an
    ASIC for a few dollars per hash-rate unit. Your server pays for the
    iterations; the attacker barely does.

    Argon2 is memory-hard. Filling m KiB and reading it back in an order that
    depends on the data forces the attacker to hold m KiB per guess. A GPU has
    thousands of cores and nowhere near thousands of independent megabytes of
    fast RAM, so the parallelism advantage collapses. Memory is the one cost
    that does not get cheaper by specialising the silicon.

The three variants, and why `id` is the answer:

    Argon2d  data-DEPENDENT indexing. Maximum resistance to GPU/ASIC attack,
             but the memory access pattern depends on the password, so it
             leaks through cache-timing side channels. Fine for proof of work
             where nobody shares your CPU.
    Argon2i  data-INDEPENDENT indexing. Side-channel safe, but the predictable
             access pattern allows time-memory trade-off attacks.
    Argon2id first half of the first pass uses Argon2i indexing, the rest uses
             Argon2d. Side-channel resistance where it matters (the early
             passes handle the secret most directly) and TMTO resistance
             everywhere else. This is what RFC 9106 tells you to pick.

Structure, in the order the code below runs:

    H0     = BLAKE2b-512 over every parameter and every input. Changing any
             parameter changes every block, which is why the cost settings
             cannot be stripped off a stored hash.
    B[i][j] 1 KiB blocks in a p x q grid. Lane i is a chain; column j depends
             on j-1 and on one *reference* block chosen by the indexing rule.
    G       the compression function: a BLAKE2b round applied first across
             rows, then across columns, so one block's change diffuses into
             all 1024 bytes.
    Tag     the last block of every lane, XORed together and hashed to the
             requested length.

Not constant time, and not resistant to anything. Python integers allocate on
value and every list index is a bounds-checked object dereference.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

BLOCK_SIZE = 1024          # bytes per memory block
WORDS_PER_BLOCK = 128      # 1024 / 8
SYNC_POINTS = 4            # slices per pass; the parallelism barrier count
VERSION = 0x13             # 1.3, the only version RFC 9106 defines

TYPE_D = 0
TYPE_I = 1
TYPE_ID = 2

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1

# Pure Python fills roughly 1 MiB per second on a modern laptop. Production
# settings start at 19 MiB (RFC 9106's second recommended option) and go up
# from there, so anything past this cap would take minutes per login and
# teach the wrong lesson about what Argon2 costs.
TEACHING_MAX_MEMORY_KIB = 1024


class Argon2Error(ValueError):
    """Bad parameters or bad inputs."""


def _rotr64(value: int, count: int) -> int:
    return ((value >> count) | (value << (64 - count))) & MASK64


def _mix(v: list[int], a: int, b: int, c: int, d: int) -> None:
    """The Argon2 variant of the BLAKE2b round function.

    The extra `2 * lower32(x) * lower32(y)` term is not in BLAKE2b. It is a
    64-bit multiplication, deliberately chosen because multiplication has
    higher latency than XOR and addition on every real CPU -- it raises the
    cost of the *depth* of the computation, which an attacker cannot
    parallelise away.
    """
    va, vb, vc, vd = v[a], v[b], v[c], v[d]

    va = (va + vb + 2 * (va & MASK32) * (vb & MASK32)) & MASK64
    vd = _rotr64(vd ^ va, 32)
    vc = (vc + vd + 2 * (vc & MASK32) * (vd & MASK32)) & MASK64
    vb = _rotr64(vb ^ vc, 24)
    va = (va + vb + 2 * (va & MASK32) * (vb & MASK32)) & MASK64
    vd = _rotr64(vd ^ va, 16)
    vc = (vc + vd + 2 * (vc & MASK32) * (vd & MASK32)) & MASK64
    vb = _rotr64(vb ^ vc, 63)

    v[a], v[b], v[c], v[d] = va, vb, vc, vd


def _permute(v: list[int]) -> None:
    """RFC 9106 permutation P over 16 words: four columns, then four diagonals."""
    _mix(v, 0, 4, 8, 12)
    _mix(v, 1, 5, 9, 13)
    _mix(v, 2, 6, 10, 14)
    _mix(v, 3, 7, 11, 15)
    _mix(v, 0, 5, 10, 15)
    _mix(v, 1, 6, 11, 12)
    _mix(v, 2, 7, 8, 13)
    _mix(v, 3, 4, 9, 14)


def _compress(x: list[int], y: list[int], out: list[int], xor_into_out: bool) -> None:
    """G(X, Y): permute rows, then columns, then XOR the input back in.

    Doing rows and then columns is what makes one changed byte reach all 1024
    output bytes. The final XOR with R is what makes G non-invertible, which
    is what stops an attacker walking the lane backwards from the tag.
    """
    r = [x[i] ^ y[i] for i in range(WORDS_PER_BLOCK)]
    q = list(r)

    # Eight rows of 16 words.
    for row in range(8):
        base = row * 16
        block = q[base : base + 16]
        _permute(block)
        q[base : base + 16] = block

    # Eight columns; column c is words (2c, 2c+1) of every row.
    for col in range(8):
        idx = []
        for row in range(8):
            idx.append(row * 16 + 2 * col)
            idx.append(row * 16 + 2 * col + 1)
        block = [q[i] for i in idx]
        _permute(block)
        for position, i in enumerate(idx):
            q[i] = block[position]

    if xor_into_out:
        for i in range(WORDS_PER_BLOCK):
            out[i] ^= q[i] ^ r[i]
    else:
        for i in range(WORDS_PER_BLOCK):
            out[i] = q[i] ^ r[i]


def _blake2b_long(out_len: int, data: bytes) -> bytes:
    """H', the variable-length hash of RFC 9106 section 3.2.

    BLAKE2b maxes out at 64 bytes of output, so longer outputs are produced by
    chaining and taking the first 32 bytes of each link. The length is hashed
    in as a prefix, which is what stops two different requested lengths
    producing a prefix relationship.
    """
    prefix = struct.pack("<I", out_len)
    if out_len <= 64:
        return hashlib.blake2b(prefix + data, digest_size=out_len).digest()

    result = bytearray()
    block = hashlib.blake2b(prefix + data, digest_size=64).digest()
    result += block[:32]
    produced = 32
    while out_len - produced > 64:
        block = hashlib.blake2b(block, digest_size=64).digest()
        result += block[:32]
        produced += 32
    result += hashlib.blake2b(block, digest_size=out_len - produced).digest()
    return bytes(result)


def _words(data: bytes) -> list[int]:
    return list(struct.unpack("<128Q", data))


def _bytes(words: list[int]) -> bytes:
    return struct.pack("<128Q", *words)


@dataclass(frozen=True)
class _Context:
    lanes: int
    columns: int          # q, blocks per lane
    segment: int          # q / 4, blocks per slice per lane
    passes: int
    variant: int


def _address_block(ctx: _Context, block_index: int, position: tuple[int, int, int]) -> list[int]:
    """Argon2i pseudo-random addresses: G(0, G(0, counter_block)).

    The addresses depend only on the position in the schedule, never on the
    password, which is exactly what removes the cache-timing side channel.
    """
    pass_number, lane, slice_number = position
    counter = [0] * WORDS_PER_BLOCK
    counter[0] = pass_number
    counter[1] = lane
    counter[2] = slice_number
    counter[3] = ctx.lanes * ctx.columns
    counter[4] = ctx.passes
    counter[5] = ctx.variant
    counter[6] = block_index

    zero = [0] * WORDS_PER_BLOCK
    first = [0] * WORDS_PER_BLOCK
    _compress(zero, counter, first, False)
    result = [0] * WORDS_PER_BLOCK
    _compress(zero, first, result, False)
    return result


def _reference_index(
    ctx: _Context,
    j1: int,
    j2: int,
    pass_number: int,
    lane: int,
    slice_number: int,
    index_in_segment: int,
) -> tuple[int, int]:
    """Pick the reference block (RFC 9106 section 3.4.1 and 3.4.2).

    The quadratic `x - x*x/2^32` mapping is deliberate: it biases the choice
    towards *recent* blocks. Recent blocks are the ones an attacker running a
    memory-reduced trade-off is least likely to still have, so the bias raises
    the cost of storing less than m.
    """
    if pass_number == 0 and slice_number == 0:
        reference_lane = lane
    else:
        reference_lane = j2 % ctx.lanes

    same_lane = reference_lane == lane
    if pass_number == 0:
        if slice_number == 0:
            area = index_in_segment - 1
        elif same_lane:
            area = slice_number * ctx.segment + index_in_segment - 1
        else:
            area = slice_number * ctx.segment - (1 if index_in_segment == 0 else 0)
    elif same_lane:
        area = ctx.columns - ctx.segment + index_in_segment - 1
    else:
        area = ctx.columns - ctx.segment - (1 if index_in_segment == 0 else 0)

    relative = (j1 * j1) >> 32
    relative = area - 1 - ((area * relative) >> 32)

    if pass_number == 0:
        start = 0
    else:
        start = 0 if slice_number == SYNC_POINTS - 1 else (slice_number + 1) * ctx.segment
    return reference_lane, (start + relative) % ctx.columns


def argon2(
    password: bytes,
    salt: bytes,
    *,
    time_cost: int,
    memory_cost: int,
    parallelism: int,
    tag_length: int = 32,
    variant: int = TYPE_ID,
    secret: bytes = b"",
    associated_data: bytes = b"",
    allow_slow: bool = False,
) -> bytes:
    """Compute an Argon2 tag. `memory_cost` is in KiB, as everywhere else."""
    if parallelism < 1:
        raise Argon2Error("parallelism must be at least 1")
    if time_cost < 1:
        raise Argon2Error("time_cost must be at least 1")
    if memory_cost < 8 * parallelism:
        raise Argon2Error(f"memory_cost must be at least 8*parallelism ({8 * parallelism} KiB)")
    if tag_length < 4:
        raise Argon2Error("tag_length must be at least 4 bytes")
    if len(salt) < 8:
        raise Argon2Error("salt must be at least 8 bytes (RFC 9106 requires 16 for passwords)")
    if variant not in (TYPE_D, TYPE_I, TYPE_ID):
        raise Argon2Error(f"unknown Argon2 variant: {variant}")
    if memory_cost > TEACHING_MAX_MEMORY_KIB and not allow_slow:
        raise Argon2Error(
            f"this pure-Python Argon2 refuses memory_cost > {TEACHING_MAX_MEMORY_KIB} KiB "
            "because it would take minutes per hash. Install argon2-cffi for real "
            "parameters, or pass allow_slow=True if you are deliberately measuring."
        )

    # Number of blocks, rounded down to a multiple of 4*p so every slice of
    # every lane is the same size.
    blocks = (memory_cost // (SYNC_POINTS * parallelism)) * (SYNC_POINTS * parallelism)
    columns = blocks // parallelism
    ctx = _Context(
        lanes=parallelism,
        columns=columns,
        segment=columns // SYNC_POINTS,
        passes=time_cost,
        variant=variant,
    )

    # H0 binds every parameter into the first block. Strip a cost factor off a
    # stored hash and the tag changes, so downgrade is not a silent option.
    h0 = hashlib.blake2b(
        struct.pack(
            "<IIIIII",
            parallelism,
            tag_length,
            memory_cost,
            time_cost,
            VERSION,
            variant,
        )
        + struct.pack("<I", len(password)) + password
        + struct.pack("<I", len(salt)) + salt
        + struct.pack("<I", len(secret)) + secret
        + struct.pack("<I", len(associated_data)) + associated_data,
        digest_size=64,
    ).digest()

    memory: list[list[int]] = [[0] * WORDS_PER_BLOCK for _ in range(blocks)]

    def block_at(lane: int, column: int) -> list[int]:
        return memory[lane * columns + column]

    for lane in range(parallelism):
        for column in (0, 1):
            seed = h0 + struct.pack("<II", column, lane)
            memory[lane * columns + column] = _words(_blake2b_long(BLOCK_SIZE, seed))

    for pass_number in range(time_cost):
        for slice_number in range(SYNC_POINTS):
            # Argon2id: data-independent addressing for the first half of the
            # first pass, data-dependent from then on.
            use_independent = variant == TYPE_I or (
                variant == TYPE_ID and pass_number == 0 and slice_number < SYNC_POINTS // 2
            )
            for lane in range(parallelism):
                addresses: list[int] = []
                address_counter = 0

                start = 2 if (pass_number == 0 and slice_number == 0) else 0
                for index_in_segment in range(start, ctx.segment):
                    column = slice_number * ctx.segment + index_in_segment
                    previous = block_at(lane, (column - 1) % columns)

                    if use_independent:
                        if index_in_segment % WORDS_PER_BLOCK == 0 or not addresses:
                            address_counter += 1
                            addresses = _address_block(
                                ctx, address_counter, (pass_number, lane, slice_number)
                            )
                        word = addresses[index_in_segment % WORDS_PER_BLOCK]
                    else:
                        word = previous[0]
                    j1 = word & MASK32
                    j2 = (word >> 32) & MASK32

                    reference_lane, reference_column = _reference_index(
                        ctx, j1, j2, pass_number, lane, slice_number, index_in_segment
                    )
                    reference = block_at(reference_lane, reference_column)
                    _compress(
                        previous,
                        reference,
                        block_at(lane, column),
                        xor_into_out=pass_number > 0,
                    )

    final = list(block_at(0, columns - 1))
    for lane in range(1, parallelism):
        other = block_at(lane, columns - 1)
        for i in range(WORDS_PER_BLOCK):
            final[i] ^= other[i]

    return _blake2b_long(tag_length, _bytes(final))
