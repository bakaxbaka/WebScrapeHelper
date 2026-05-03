"""End-to-end test for address_analyzer.

Uses the Schneider 2012 demo: address 1HKywxiL4JziqXrzLKhmB6a74ma6kxbSDj
made the canonical reused-r transaction
9ec4bc49e828d924af1d1029cacf709431abbde46d59554b62bc270e3b29c4b1, and the
recipient key 1BFhrfTTZP3Nw4BNy4eX4KFLsn9ZeijcMm has been long-empty
public knowledge since 2012. Running the address analyzer on either
should walk the full history, parse every signature, and (because that
tx contains an in-tx reused-r) recover the private key end-to-end and
hand back the matching address.

This test reuses the local fetcher functions so it talks to
blockchain.info exactly the way `btc_analyzer.analyze_address` does in
production.
"""
from __future__ import annotations

import sys
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from address_analyzer import analyze_address  # noqa: E402

# Address whose private key was recovered from the demo tx -- this is the
# address that *signed* both inputs (uncompressed pubkey -> P2PKH).
SCHNEIDER_ADDR = "1BFhrfTTZP3Nw4BNy4eX4KFLsn9ZeijcMm"
SCHNEIDER_TXID = "9ec4bc49e828d924af1d1029cacf709431abbde46d59554b62bc270e3b29c4b1"
EXPECTED_D_HEX = "0xc477f9f65c22cce20657faa5b2d1d8122336f851a508a1ed04e479c34985bf96"


_CACHED_REPORT = None


def _get_report():
    global _CACHED_REPORT
    if _CACHED_REPORT is None:
        _CACHED_REPORT = analyze_address(SCHNEIDER_ADDR, max_txs=200)
    return _CACHED_REPORT


def test_analyzer_recovers_key_via_reuse():
    rep = _get_report()

    # If blockchain.info rate-limited or was unreachable, skip rather than
    # fail -- this is a network test that depends on a public free API.
    if rep.transactions_analyzed == 0 and rep.notes:
        try:
            import pytest  # type: ignore
        except ImportError:
            import unittest
            raise unittest.SkipTest(f"blockchain.info unavailable: {rep.notes[0]}")
        pytest.skip(f"blockchain.info unavailable: {rep.notes[0]}")

    # Sanity: framework parsed transactions and produced signatures.
    assert rep.transactions_analyzed >= 1, rep
    assert rep.signatures_total >= 2, rep

    # The framework must see at least one reused-r group.
    assert (rep.in_tx_reused_r or rep.cross_tx_reused_r or rep.reused_r_groups), \
        f"no reused-r found; in_tx={len(rep.in_tx_reused_r)}, " \
        f"cross_tx={len(rep.cross_tx_reused_r)}, groups={len(rep.reused_r_groups)}"

    # And recover the private key end-to-end. This is the key assertion --
    # the d we recover must be the actual Schneider 2012 key, not a fabricated
    # value from the formula plugged with arbitrary inputs.
    assert any(k["private_key_hex"].lower() == EXPECTED_D_HEX
                for k in rep.recovered_keys), \
        f"recovered_keys did not include expected d {EXPECTED_D_HEX}; " \
        f"got {[k['private_key_hex'] for k in rep.recovered_keys]}"


if __name__ == "__main__":
    print(f"Running address_analyzer.analyze_address against {SCHNEIDER_ADDR} ...")
    rep = _get_report()
    print(f"\ntotal_tx_count        : {rep.total_tx_count}")
    print(f"transactions_analyzed : {rep.transactions_analyzed}")
    print(f"signatures_total      : {rep.signatures_total}")
    print(f"signatures_by_type    : {rep.signatures_by_type}")
    print(f"low_s_count           : {rep.low_s_count}")
    print(f"in_tx_reused_r        : {len(rep.in_tx_reused_r)}")
    print(f"cross_tx_reused_r     : {len(rep.cross_tx_reused_r)}")
    print(f"recovered_keys        : {len(rep.recovered_keys)}")
    for k in rep.recovered_keys[:3]:
        print(f"  -> {k['private_key_hex']}  WIF={k['wif_uncompressed']}")
        print(f"     uncompressed addr={k.get('address_uncompressed')}  via={k['recovered_via']}")
    print(f"biased_nonce_candidates: {len(rep.biased_nonce_candidates)}")
    for c in rep.biased_nonce_candidates[:5]:
        print(f"  -> txid={c['txid']} vin={c['vin']} k_bits={c['k_bit_length']}")
    print(f"elapsed_s             : {rep.elapsed_s:.1f}s")
    if rep.notes:
        print(f"\nnotes ({len(rep.notes)}):")
        for n in rep.notes[:5]:
            print(f"  - {n}")

    # Run the actual assertion.
    test_analyzer_recovers_key_via_reuse()
    print("\nPASS  recovers Schneider 2012 d via cross-tx index on full address history")
