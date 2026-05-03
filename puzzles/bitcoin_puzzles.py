"""Bitcoin Puzzle Transaction metadata + known solutions for low puzzles.

The puzzle private keys for puzzles 1-15 are public knowledge documented
in countless public sources (privatekeys.pw, BitcoinTalk threads, GitHub
solver repos). They are reproduced here purely so the solvers in
``puzzles.solvers`` can be validated against ground truth before being
pointed at higher (still-unsolved) puzzles.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from coincurve import PrivateKey, PublicKey


# Public, well-documented private keys for the low puzzles. These are the
# canonical "satoshi_rising 2015" answers; the addresses they unlock have
# been swept many times since.
_KNOWN_SOLUTIONS: dict[int, int] = {
    1: 0x0000000000000000000000000000000000000000000000000000000000000001,
    2: 0x0000000000000000000000000000000000000000000000000000000000000003,
    3: 0x0000000000000000000000000000000000000000000000000000000000000007,
    4: 0x0000000000000000000000000000000000000000000000000000000000000008,
    5: 0x0000000000000000000000000000000000000000000000000000000000000015,
    6: 0x0000000000000000000000000000000000000000000000000000000000000031,
    7: 0x000000000000000000000000000000000000000000000000000000000000004C,
    8: 0x00000000000000000000000000000000000000000000000000000000000000E0,
    9: 0x00000000000000000000000000000000000000000000000000000000000001D3,
    10: 0x0000000000000000000000000000000000000000000000000000000000000202,
    11: 0x0000000000000000000000000000000000000000000000000000000000000483,
    12: 0x0000000000000000000000000000000000000000000000000000000000000A7B,
    13: 0x0000000000000000000000000000000000000000000000000000000000001460,
    14: 0x0000000000000000000000000000000000000000000000000000000000002930,
    15: 0x00000000000000000000000000000000000000000000000000000000000068F3,
}


@dataclass
class Puzzle:
    n: int                       # bit number (1..160)
    range_low: int               # inclusive lower bound for d
    range_high: int              # inclusive upper bound for d
    pubkey: PublicKey            # target pubkey (d * G)
    known_d: Optional[int]       # ground-truth d if publicly known, else None

    @property
    def width(self) -> int:
        return self.range_high - self.range_low + 1

    @property
    def address(self) -> str:
        # P2PKH from compressed pubkey (matches the addresses on the chain
        # for the Bitcoin Puzzle Tx outputs).
        from attached_assets.utils import public_key_to_p2pkh_address
        return public_key_to_p2pkh_address(self.pubkey.format(compressed=True))


def get_puzzle(n: int) -> Puzzle:
    """Return the puzzle metadata for puzzle ``n`` (1 ≤ n ≤ 160).

    For puzzles where we have a publicly-known solution in ``_KNOWN_SOLUTIONS``
    we derive the pubkey from it; that exact pubkey matches the historical
    target. For unsolved high puzzles we also need the on-chain pubkey but
    that requires fetching from blockchain.info — those callers should set
    ``pubkey`` themselves.
    """
    if not 1 <= n <= 160:
        raise ValueError(f"puzzle index out of range: {n}")
    range_low = 1 << (n - 1)  # puzzle N: d in [2^(N-1), 2^N - 1]
    range_high = (1 << n) - 1
    d = _KNOWN_SOLUTIONS.get(n)
    if d is None:
        raise NotImplementedError(
            f"puzzle {n} solution is not embedded; fetch the on-chain pubkey "
            "and construct Puzzle(...) directly to attempt it"
        )
    pub = PrivateKey.from_int(d).public_key
    return Puzzle(
        n=n,
        range_low=range_low,
        range_high=range_high,
        pubkey=pub,
        known_d=d,
    )


def all_known_puzzles() -> list[Puzzle]:
    return [get_puzzle(n) for n in sorted(_KNOWN_SOLUTIONS.keys())]
