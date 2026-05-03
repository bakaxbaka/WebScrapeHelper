"""End-to-end verification that ``signature_extractor`` produces real
per-input ECDSA message hashes ``z`` such that the standard reused-nonce
recovery formula yields the correct private key (i.e. the one that
actually signed the transaction).

Run as::

    python -m pytest tests/test_signature_extractor.py -v

or as a standalone script::

    python tests/test_signature_extractor.py
"""
from __future__ import annotations

import json
import sys
import hashlib
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import requests  # noqa: E402
from coincurve import PublicKey  # noqa: E402

from signature_extractor import extract_signatures, parse_der_signature  # noqa: E402

N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


def fetch_json(txid: str) -> dict:
    return requests.get(f"https://blockchain.info/rawtx/{txid}", timeout=15).json()


def fetch_raw_hex(txid: str) -> str:
    return requests.get(f"https://blockchain.info/rawtx/{txid}?format=hex", timeout=15).text


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def recover_d(r: int, s1: int, z1: int, s2: int, z2: int) -> int:
    k = ((z1 - z2) * pow(s1 - s2, -1, N)) % N
    d = ((s1 * k - z1) * pow(r, -1, N)) % N
    return d


def pubkey_from_d(d: int, compressed: bool) -> bytes:
    from coincurve import PrivateKey
    return PrivateKey.from_int(d).public_key.format(compressed=compressed)


def test_schneider_2012_recovery():
    """tx 9ec4...c4b1 has reused r across 2 inputs; with real z values the
    standard nonce-reuse formula MUST recover the private key whose pubkey
    matches the one in each scriptSig."""
    txid = "9ec4bc49e828d924af1d1029cacf709431abbde46d59554b62bc270e3b29c4b1"
    sigs = extract_signatures(txid, fetch_json, fetch_raw_hex)
    assert len(sigs) == 2, sigs
    for s in sigs:
        assert s["z"] is not None, s
        assert s["sighash_type"] == 1, s
        assert s["script_type"] == "p2pkh", s
    s1, s2 = sigs
    assert s1["r"] == s2["r"], "this tx is the canonical reused-r demo"

    d = recover_d(s1["r"], s1["s"], s1["z"], s2["s"], s2["z"])
    print(f"Recovered d = 0x{d:064x}")

    # Both inputs sign with the same key; their pubkeys (uncompressed) must match.
    assert s1["pubkey"] == s2["pubkey"], (s1["pubkey"], s2["pubkey"])
    pubkey_from_sig = s1["pubkey"]

    # Determine compression from leading byte and reconstruct from d.
    compressed = pubkey_from_sig[0] in (0x02, 0x03)
    derived = pubkey_from_d(d, compressed=compressed)
    print(f"Pubkey from d = {derived.hex()}")
    print(f"Pubkey in tx  = {pubkey_from_sig.hex()}")

    if pubkey_from_sig[0] == 0x04:
        # Uncompressed in scriptSig — derive uncompressed for comparison too.
        derived_u = pubkey_from_d(d, compressed=False)
        assert derived_u == pubkey_from_sig
    else:
        assert derived == pubkey_from_sig


def test_der_parser_strict_lengths():
    """Round-trip a known-good DER signature blob."""
    # A real DER from input 0 of the Schneider tx (ends with 0x01 SIGHASH_ALL).
    der_hex = (
        "30440220d47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad1"
        "022044e1ff2dfd8102cf7a47c21d5c9fd5701610d04953c6836596b4fe9dd2f53e3e01"
    )
    parsed = parse_der_signature(bytes.fromhex(der_hex))
    assert parsed is not None
    assert parsed["sighash_type"] == 1
    assert parsed["r"] == 0xd47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad1
    assert parsed["s"] == 0x44e1ff2dfd8102cf7a47c21d5c9fd5701610d04953c6836596b4fe9dd2f53e3e


def test_der_parser_rejects_garbage():
    """The old loose parser scanned for 0x30 anywhere in the script; this one
    must not return anything for blobs that don't decode cleanly."""
    # 65-byte DER-shaped junk like the ones in the user's analyzer dump.
    junk_hex = (
        "830b0cbe780683903c4a12d09a4e2676f6ed2d52188f558d5d128357a6200220"
        "079772f28002c81b93c537bf7109e68185a03115d63a91ee511f326479fd611a01"
    )
    assert parse_der_signature(bytes.fromhex(junk_hex)) is None


if __name__ == "__main__":
    test_der_parser_strict_lengths()
    test_der_parser_rejects_garbage()
    test_schneider_2012_recovery()
    print("\nALL TESTS PASSED")
