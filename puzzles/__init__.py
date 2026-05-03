"""Bitcoin Puzzle Transaction (2015) data and solvers.

The "Bitcoin Puzzle" is a public cryptographic challenge created in 2015
where 160 addresses were funded with private keys deliberately drawn from
known small ranges:

    puzzle N has privkey d ∈ [2^(N-1), 2^N - 1]

The creator topped up the addresses in 2017. Solvers in the community use
GPU brute force / Pollard's kangaroo / BSGS to find the keys; whoever
finds the key gets the funds. As of late-2024 puzzles 1-66 have been
solved publicly, plus 70 and a handful in between; the rest are open.

This package contains:

* ``bitcoin_puzzles``: known metadata + solutions for puzzles 1-32 (used
  to validate the solvers below).
* ``solvers``: brute force, BSGS, Pollard's kangaroo (CPU implementations
  on top of coincurve / libsecp256k1).
"""
