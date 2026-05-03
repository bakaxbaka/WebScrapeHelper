"""Discrete-log solvers for the Bitcoin Puzzle Transaction.

Three flavours, ranged search [a, b]:

* ``brute_force_solve``: O(b - a) time, trivial. Only useful below ~2^24.
* ``bsgs_solve``:        O(sqrt(b - a)) time AND memory. Best up to ~2^40
                         on this CPU.
* ``kangaroo_solve``:    O(sqrt(b - a)) time, O(1) memory (Pollard's
                         lambda with distinguished points). Beyond ~2^40
                         this is the only viable path; it's also the
                         algorithm the public puzzle community uses on
                         GPUs for the high puzzles.

All operations go through ``coincurve`` (libsecp256k1 bindings); raw
EC speed on this VM is ≈160k point additions per second per core, so
puzzles past ~2^36 are not realistically solvable in a CPU-only Devin
session no matter which algorithm we pick.
"""
from __future__ import annotations

import logging
import math
import os
import time
from dataclasses import dataclass
from typing import Optional

from coincurve import PrivateKey, PublicKey

logger = logging.getLogger(__name__)

N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
G = PrivateKey.from_int(1).public_key


# ----- Point helpers (operate in compressed-bytes form for hashing) ---------

def _scalar_mul(k: int) -> PublicKey:
    """k*G via libsecp256k1 (constant-time scalar mult)."""
    return PrivateKey.from_int(k % N).public_key


def _add(p: PublicKey, q: PublicKey) -> Optional[PublicKey]:
    """Affine addition over secp256k1.

    Returns ``None`` when the sum is the point at infinity (i.e. ``p + q``
    has no valid affine representation, which coincurve rejects).
    Callers are expected to handle the ``None`` case as "logical zero".
    """
    try:
        return PublicKey.combine_keys([p, q])
    except ValueError:
        return None


def _neg(p: PublicKey) -> PublicKey:
    """Point negation: flip the y-parity prefix byte of the compressed form."""
    cb = bytearray(p.format(compressed=True))
    cb[0] ^= 0x01  # 0x02 <-> 0x03
    return PublicKey(bytes(cb))


def _key(p: PublicKey) -> bytes:
    """Stable hashable key for a point (33-byte compressed form)."""
    return p.format(compressed=True)


# ----- Solver result --------------------------------------------------------

@dataclass
class SolveResult:
    found: bool
    d: Optional[int]
    elapsed_s: float
    steps: int
    algorithm: str
    notes: str = ""


# ----- 1) Brute force -------------------------------------------------------

def brute_force_solve(target: PublicKey, range_low: int, range_high: int,
                       max_steps: Optional[int] = None) -> SolveResult:
    """Iterate d = range_low, range_low+1, ..., compare d*G to target."""
    start = time.time()
    target_key = _key(target)
    p = _scalar_mul(range_low)
    if _key(p) == target_key:
        return SolveResult(True, range_low, time.time() - start, 1, "brute_force")
    width = range_high - range_low + 1
    if max_steps is None:
        max_steps = width
    steps = min(width, max_steps)
    for i in range(1, steps):
        p = _add(p, G)
        if _key(p) == target_key:
            return SolveResult(True, range_low + i, time.time() - start, i + 1, "brute_force")
    return SolveResult(False, None, time.time() - start, steps, "brute_force",
                       notes=f"exhausted {steps} of {width} candidates")


# ----- 2) BSGS --------------------------------------------------------------

def bsgs_solve(target: PublicKey, range_low: int, range_high: int,
               m: Optional[int] = None,
               max_memory_entries: int = 1 << 24) -> SolveResult:
    """Baby-step giant-step on the interval [range_low, range_high].

    Returns d such that target == d*G (with d in [range_low, range_high]).
    """
    start = time.time()
    width = range_high - range_low + 1
    if m is None:
        m = max(1, math.isqrt(width) + 1)
    if m > max_memory_entries:
        return SolveResult(False, None, time.time() - start, 0, "bsgs",
                           notes=f"m={m} exceeds max_memory_entries={max_memory_entries}; use kangaroo")

    # Shift target: target' = target - range_low * G
    # Edge case: if target == range_low * G the shift is the point at infinity
    # which coincurve refuses to represent. Detect that directly.
    target_low_key = _key(_scalar_mul(range_low))
    target_key = _key(target)
    if target_low_key == target_key:
        return SolveResult(True, range_low, time.time() - start, 1, "bsgs")
    target_shifted = _add(target, _neg(_scalar_mul(range_low)))

    # Baby steps: table[j*G] = j  for j in [1, m]. (We've already handled j=0.)
    table: dict[bytes, int] = {}
    p = G
    table[_key(p)] = 1
    for j in range(2, m + 1):
        p = _add(p, G)
        table[_key(p)] = j

    # Giant step factor: -m * G (so each iteration we add this to target_shifted)
    mG = _scalar_mul(m)
    neg_mG = _neg(mG)
    cur = target_shifted
    # i=0 case: target' itself in baby steps => d = range_low + j
    if _key(cur) in table:
        j = table[_key(cur)]
        d = range_low + j
        if range_low <= d <= range_high:
            return SolveResult(True, d, time.time() - start,
                               m + 1, "bsgs")
    # Iterate giant steps. ``cur = target' - i*mG``. If we ever land on the
    # identity (``cur is None``), the discrete log is exactly ``i*m``: that
    # corresponds to ``j=0`` which isn't in the baby-step table by design,
    # so check it explicitly and continue from ``-mG`` next round.
    for i in range(1, m + 2):
        cur = _add(cur, neg_mG)
        if cur is None:
            d = range_low + i * m
            if range_low <= d <= range_high:
                return SolveResult(True, d, time.time() - start,
                                   m + i + 1, "bsgs")
            cur = _neg(mG)  # next iteration: -2*mG, -3*mG, ...
            continue
        k = _key(cur)
        if k in table:
            j = table[k]
            d = range_low + i * m + j
            if range_low <= d <= range_high:
                return SolveResult(True, d, time.time() - start,
                                   m + i + 1, "bsgs")
    return SolveResult(False, None, time.time() - start, 2 * m,
                       "bsgs", notes="not in interval (within m^2 candidates)")


# ----- 3) Pollard's kangaroo (lambda with distinguished points) -------------

def _pseudo_random_jump(p: PublicKey, n_jumps: int, mask: int) -> int:
    """Index into the jump table. Uses low bits of x-coordinate."""
    cb = p.format(compressed=True)
    return int.from_bytes(cb[-4:], "big") & mask


def kangaroo_solve(target: PublicKey, range_low: int, range_high: int,
                    max_steps: Optional[int] = None,
                    n_jumps: int = 32,
                    distinguished_bits: Optional[int] = None,
                    seed: int = 0) -> SolveResult:
    """Pollard's lambda (kangaroo) on [range_low, range_high] with
    distinguished-point collision detection.

    Single-CPU implementation. For low-bit puzzles this is slower than
    BSGS; its job in this framework is to cover ranges where BSGS's
    sqrt(W) memory exceeds RAM (puzzles ≥ ~40 bits).
    """
    start = time.time()
    width = range_high - range_low + 1
    if width <= 1:
        if width == 1 and _key(_scalar_mul(range_low)) == _key(target):
            return SolveResult(True, range_low, time.time() - start, 1, "kangaroo")
        return SolveResult(False, None, time.time() - start, 0, "kangaroo",
                           notes="empty range")

    sqrt_w = max(1, math.isqrt(width))
    if max_steps is None:
        max_steps = 16 * sqrt_w
    if distinguished_bits is None:
        # ~sqrt(W) distinguished points expected per kangaroo
        distinguished_bits = max(4, int(math.log2(sqrt_w) // 2))
    dist_mask = (1 << distinguished_bits) - 1

    # Jump table: ``n_jumps`` powers of 2 with mean ≈ sqrt(W)/2 (Pollard's
    # original recommendation). Seed selects which subset.
    jump_mask = n_jumps - 1
    assert (n_jumps & jump_mask) == 0, "n_jumps must be a power of 2"
    log_sqrt_w = max(1, int(math.log2(sqrt_w)))
    rng = (seed * 0x9E3779B97F4A7C15 + 1) & ((1 << 64) - 1)
    jump_distances: list[int] = []
    jump_points: list[PublicKey] = []
    for i in range(n_jumps):
        rng = (rng * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        # Distance is 2^(i mod log_sqrt_w), then OR'd with low bits of rng to
        # de-correlate jumps across seeds.
        base = 1 << (i % log_sqrt_w)
        jitter = rng & (base - 1) if base > 1 else 0
        d = max(1, base | jitter)
        jump_distances.append(d)
        jump_points.append(_scalar_mul(d))

    # Tame kangaroo starts at midpoint of the range.
    mid = range_low + (width // 2)
    tame_d = mid
    tame_p = _scalar_mul(mid)

    # Wild kangaroo starts at the target.
    wild_d = 0
    wild_p = target

    seen_tame: dict[bytes, int] = {}
    seen_wild: dict[bytes, int] = {}
    steps = 0
    while steps < max_steps:
        steps += 2

        # Tame jump
        idx = _pseudo_random_jump(tame_p, n_jumps, jump_mask)
        tame_d += jump_distances[idx]
        tame_p = _add(tame_p, jump_points[idx])
        tame_key = _key(tame_p)
        if int.from_bytes(tame_key[-2:], "big") & dist_mask == 0:
            if tame_key in seen_wild:
                wd = seen_wild[tame_key]
                d = (tame_d - wd) % N
                if range_low <= d <= range_high and _key(_scalar_mul(d)) == _key(target):
                    return SolveResult(True, d, time.time() - start, steps, "kangaroo")
            seen_tame[tame_key] = tame_d

        # Wild jump
        idx = _pseudo_random_jump(wild_p, n_jumps, jump_mask)
        wild_d += jump_distances[idx]
        wild_p = _add(wild_p, jump_points[idx])
        wild_key = _key(wild_p)
        if int.from_bytes(wild_key[-2:], "big") & dist_mask == 0:
            if wild_key in seen_tame:
                td = seen_tame[wild_key]
                d = (td - wild_d) % N
                if range_low <= d <= range_high and _key(_scalar_mul(d)) == _key(target):
                    return SolveResult(True, d, time.time() - start, steps, "kangaroo")
            seen_wild[wild_key] = wild_d

    return SolveResult(False, None, time.time() - start, steps, "kangaroo",
                       notes=f"exhausted {steps} steps without collision; "
                              "kangaroo is probabilistic, retry with different seed")


# ----- High-level dispatch ---------------------------------------------------

def select_algorithm(width: int) -> str:
    if width <= (1 << 22):
        return "brute_force"
    if width <= (1 << 40):
        return "bsgs"
    return "kangaroo"


def solve(target: PublicKey, range_low: int, range_high: int,
          algorithm: Optional[str] = None,
          max_steps: Optional[int] = None) -> SolveResult:
    width = range_high - range_low + 1
    algo = algorithm or select_algorithm(width)
    logger.info("solve: range_low=%d, range_high=%d, width=2^%.1f, algo=%s",
                range_low, range_high, math.log2(width), algo)
    if algo == "brute_force":
        return brute_force_solve(target, range_low, range_high, max_steps)
    if algo == "bsgs":
        return bsgs_solve(target, range_low, range_high)
    if algo == "kangaroo":
        return kangaroo_solve(target, range_low, range_high, max_steps)
    raise ValueError(f"unknown algorithm: {algo}")
