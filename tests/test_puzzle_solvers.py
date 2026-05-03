"""Validate the discrete-log solvers against
1. Publicly-known low puzzles (ground-truth d, derived target pubkey).
2. Synthetic puzzles up to a bit depth that's tractable on this CPU.

Run::

    python tests/test_puzzle_solvers.py
"""
from __future__ import annotations

import secrets
import sys
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from coincurve import PrivateKey  # noqa: E402

from puzzles.bitcoin_puzzles import _KNOWN_SOLUTIONS, get_puzzle  # noqa: E402
from puzzles.solvers import bsgs_solve, brute_force_solve, kangaroo_solve  # noqa: E402


def test_brute_force_recovers_low_puzzles():
    for n in sorted(_KNOWN_SOLUTIONS.keys()):
        p = get_puzzle(n)
        r = brute_force_solve(p.pubkey, p.range_low, p.range_high)
        assert r.found and r.d == p.known_d, f"puzzle {n}: {r}"


def test_bsgs_recovers_low_puzzles():
    for n in sorted(_KNOWN_SOLUTIONS.keys()):
        p = get_puzzle(n)
        r = bsgs_solve(p.pubkey, p.range_low, p.range_high)
        assert r.found and r.d == p.known_d, f"puzzle {n}: {r}"


def _synthetic(bits: int) -> tuple[int, int, int, "PrivateKey"]:
    rl = 1 << (bits - 1)
    rh = (1 << bits) - 1
    d = secrets.SystemRandom().randint(rl, rh)
    return d, rl, rh, PrivateKey.from_int(d).public_key


def test_bsgs_synthetic_up_to_36_bits():
    for bits in [16, 20, 24, 28, 32, 36]:
        d, rl, rh, pub = _synthetic(bits)
        r = bsgs_solve(pub, rl, rh)
        assert r.found and r.d == d, f"bsgs {bits} bits: {r}"


def test_bsgs_does_not_return_d_outside_range():
    """Regression for Devin Review on PR #7: with width=1 the baby step
    table covers offsets > width, and the i=0 path used to return a d
    outside [range_low, range_high]. Make sure BSGS now reports
    not-found instead of falsely claiming d=range_low+j.
    """
    from coincurve import PrivateKey
    # range = {42}: target=43*G is NOT in the range, BSGS must report not-found.
    target = PrivateKey.from_int(43).public_key
    r = bsgs_solve(target, 42, 42)
    assert not r.found, f"bsgs reported false positive: {r}"

    target = PrivateKey.from_int(102).public_key
    r = bsgs_solve(target, 100, 101)
    assert not r.found, f"bsgs reported false positive: {r}"


def test_kangaroo_synthetic_up_to_28_bits():
    """Kangaroo is probabilistic; run with a generous budget."""
    for bits in [16, 20, 24, 28]:
        d, rl, rh, pub = _synthetic(bits)
        r = kangaroo_solve(pub, rl, rh, max_steps=50 * (1 << (bits // 2 + 1)))
        assert r.found and r.d == d, f"kangaroo {bits} bits: {r}"


if __name__ == "__main__":
    test_brute_force_recovers_low_puzzles()
    print("PASS  brute_force on puzzles 1-15")
    test_bsgs_recovers_low_puzzles()
    print("PASS  bsgs       on puzzles 1-15")
    test_bsgs_synthetic_up_to_36_bits()
    print("PASS  bsgs       on synthetic 16-36 bits")
    test_bsgs_does_not_return_d_outside_range()
    print("PASS  bsgs       rejects targets outside the range (regression)")
    test_kangaroo_synthetic_up_to_28_bits()
    print("PASS  kangaroo   on synthetic 16-28 bits")
    print("\nALL PUZZLE SOLVER TESTS PASSED")
