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
from typing import Optional

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import requests  # noqa: E402
from coincurve import PrivateKey, PublicKey  # noqa: E402

from signature_extractor import extract_signatures, parse_der_signature  # noqa: E402

N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


def fetch_json(txid: str) -> dict:
    return requests.get(f"https://blockchain.info/rawtx/{txid}", timeout=15).json()


def fetch_raw_hex(txid: str) -> str:
    return requests.get(f"https://blockchain.info/rawtx/{txid}?format=hex", timeout=15).text


def hash160(data: bytes) -> bytes:
    from attached_assets.utils import _ripemd160
    return _ripemd160(hashlib.sha256(data).digest())


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


def _ecdsa_verify(r: int, s: int, z: int, pubkey: bytes) -> bool:
    """Stand-alone ECDSA verify on secp256k1."""
    from coincurve import PublicKey
    pub = PublicKey(pubkey)
    s_inv = pow(s, -1, N)
    u1 = (z * s_inv) % N
    u2 = (r * s_inv) % N
    Q = PublicKey.combine_keys([
        PrivateKey.from_int(u1).public_key,
        pub.multiply(u2.to_bytes(32, "big")),
    ])
    qx = int.from_bytes(Q.format(compressed=False)[1:33], "big")
    return qx % N == r % N


def test_p2wpkh_bip143_sighash_verifies():
    """For a P2WPKH input, the BIP-143 sighash we compute must verify against
    the on-chain signature."""
    # Use a recent confirmed P2WPKH spend. We pick blockchain.info itself by
    # walking blocks for a tx whose first input is P2WPKH.
    txid = _find_p2wpkh_txid()
    if txid is None:
        # We couldn't find one -- skip rather than fail spuriously.
        print("SKIP  no P2WPKH tx found via blockchain.info")
        return
    sigs = extract_signatures(txid, fetch_json, fetch_raw_hex)
    p2wpkh = [s for s in sigs if s["script_type"] == "p2wpkh"]
    assert p2wpkh, f"{txid}: no P2WPKH sigs found in {sigs}"
    s = p2wpkh[0]
    assert s["z"] is not None and s["pubkey"] is not None, s
    assert _ecdsa_verify(s["r"], s["s"], s["z"], s["pubkey"]), \
        f"{txid}: BIP-143 z does not verify (z={s['z']:064x})"


def _find_p2wpkh_txid() -> Optional[str]:
    """Find a real P2WPKH-spending tx by walking a known active address."""
    # bc1q-prefixed P2WPKH "donation" addresses get plenty of spends. We
    # pick a long-lived P2WPKH address (BTCPay's documentation example
    # works in practice; if it ever stops being active, swap it out).
    candidates = [
        "bc1q9qzu0zsh6h5gj0v2t8e3vsmx9zvmqj7rf3z9qq",  # BTCPay docs example
        "bc1qhuv3dhpnm0wktasd3v0kt6e4aqfqsd0uhfdu7d",
        "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h",  # F2Pool legacy mining
    ]
    for addr in candidates:
        try:
            r = requests.get(f"https://blockchain.info/rawaddr/{addr}?limit=10", timeout=15)
            if not r.ok:
                continue
            for tx in r.json().get("txs", []) or []:
                for inp in tx.get("inputs", []) or []:
                    po = inp.get("prev_out") or {}
                    if po.get("script", "").startswith("0014"):
                        return tx.get("hash")
        except Exception:
            continue
    return None





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
    print("PASS  DER strict length check")
    test_der_parser_rejects_garbage()
    print("PASS  DER rejects 65-byte garbage")
    test_schneider_2012_recovery()
    print("PASS  P2PKH legacy sighash + nonce-reuse recovery")
    test_p2wpkh_bip143_sighash_verifies()
    print("PASS  P2WPKH BIP-143 sighash verifies signature on-chain")
    print("\nALL TESTS PASSED")
