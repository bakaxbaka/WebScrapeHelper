"""Service layer for Bitcoin analysis and ECDSA calculations.

HTTP routes should stay thin and delegate work here. This module contains no
Flask request/response handling.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

from address_analyzer import analyze_address as comprehensive_analyze
from attached_assets.utils import format_hex
from btc_analyzer import BTCAnalyzer

logger = logging.getLogger(__name__)


class BitcoinService:
    def __init__(self, analyzer: BTCAnalyzer | None = None):
        self.analyzer = analyzer or BTCAnalyzer()

    def analyze_transaction(self, tx_id: str) -> dict[str, Any]:
        return self.analyzer.analyze_transaction(tx_id)

    def analyze_address(self, address: str, max_txs: int = 500) -> dict[str, Any]:
        report = comprehensive_analyze(address, max_txs=max_txs)
        return report.to_dict()

    def known_addresses(self) -> Any:
        from attached_assets.address_list import ADDRESSES_TO_CHECK
        return ADDRESSES_TO_CHECK

    def calculate_nonce(self, r: int, s1: int, s2: int, z1: int, z2: int) -> dict[str, Any]:
        n = self.analyzer.curve.order
        if not (0 < r < n and 0 < s1 < n and 0 < s2 < n):
            raise ValueError("r and s values must be in the secp256k1 scalar range")
        if s1 == s2:
            raise ValueError("S values are identical - cannot calculate nonce")
        s_diff = (s1 - s2) % n
        k = ((z1 - z2) % n) * pow(s_diff, -1, n) % n
        if k == 0:
            raise ValueError("Calculated nonce is zero")
        return {
            "success": True,
            "nonce": format_hex(k),
            "method": "Nonce Reuse Recovery",
            "formula": "k = (z1 - z2) / (s1 - s2) mod n",
            "inputs": {"r": format_hex(r), "s1": format_hex(s1), "s2": format_hex(s2), "z1": format_hex(z1), "z2": format_hex(z2)},
        }

    def calculate_nonce_from_private_key(self, r: int, s: int, z: int, x: int) -> dict[str, Any]:
        n = self.analyzer.curve.order
        if not (0 < r < n and 0 < s < n and 0 < x < n):
            raise ValueError("r, s and private key must be in the secp256k1 scalar range")
        k = ((z + r * x) % n) * pow(s, -1, n) % n
        if k == 0:
            raise ValueError("Calculated nonce is zero")
        return {
            "success": True,
            "nonce": format_hex(k),
            "method": "Nonce from Known Private Key",
            "formula": "k = (z + r*x) / s mod n",
            "inputs": {"r": format_hex(r), "s": format_hex(s), "z": format_hex(z), "x": format_hex(x)},
        }

    def recover_with_known_nonce(self, r: int, s: int, z: int, k: int) -> dict[str, Any]:
        n = self.analyzer.curve.order
        if not all(0 < value < n for value in (r, s, k)):
            raise ValueError("r, s and k must be in the secp256k1 scalar range")
        x = ((s * k - z) % n) * pow(r, -1, n) % n
        if not (0 < x < n):
            raise ValueError("Calculated private key is invalid")
        return {
            "success": True,
            "method": "Known Nonce Recovery",
            "private_key": format_hex(x),
            "formula": "x = ((s * k - z) * r^-1) mod n",
            "inputs": {"r": format_hex(r), "s": format_hex(s), "z": format_hex(z), "k": format_hex(k)},
        }

    def analyze_ecdsa_pair(self, r1: int, s1: int, z1: int, r2: int, s2: int, z2: int) -> dict[str, Any]:
        n = self.analyzer.curve.order
        if r1 != r2:
            raise ValueError("R values must match for nonce-reuse analysis")
        if not all(0 < value < n for value in (r1, s1, s2)):
            raise ValueError("r and s values must be in the secp256k1 scalar range")
        s_diff = (s1 - s2) % n
        if s_diff == 0:
            raise ValueError("S values are identical; nonce cannot be recovered")
        k = ((z1 - z2) % n) * pow(s_diff, -1, n) % n
        if k == 0:
            raise ValueError("Calculated nonce is zero")
        x = ((s1 * k - z1) % n) * pow(r1, -1, n) % n
        if not (0 < x < n):
            raise ValueError("Calculated private key is invalid")
        return {
            "success": True,
            "k": format_hex(k),
            "x": format_hex(x),
            "extracted_params": {name: format_hex(value) for name, value in {
                "r1": r1, "s1": s1, "m1": z1, "r2": r2, "s2": s2, "m2": z2
            }.items()},
        }

    def scan_recent_block(self, limit: int = 20) -> dict[str, Any]:
        response = requests.get("https://blockchain.info/latestblock", timeout=10)
        response.raise_for_status()
        block_hash = response.json().get("hash")
        if not block_hash:
            raise ValueError("Latest block response did not contain a block hash")
        block_response = requests.get(f"https://blockchain.info/rawblock/{block_hash}", timeout=10)
        block_response.raise_for_status()
        transactions = block_response.json().get("tx", [])
        results = []
        for tx in transactions[:limit]:
            tx_id = tx.get("hash")
            if not tx_id:
                continue
            try:
                result = self.analyze_transaction(tx_id)
                if result.get("private_keys_found", 0) > 0:
                    results.append({"tx_id": tx_id, "private_keys_found": result.get("private_keys_found"), "weak_signatures": result.get("weak_signatures", [])})
            except Exception:
                logger.exception("Failed to analyze transaction %s during block scan", tx_id)
        return {"success": True, "scanned_transactions": min(limit, len(transactions)), "weak_signatures_found": len(results), "results": results, "block_hash": block_hash}

    def monitor_mempool(self, limit: int = 10) -> dict[str, Any]:
        response = requests.get("https://blockchain.info/unconfirmed-transactions?format=json", timeout=10)
        response.raise_for_status()
        transactions = response.json().get("txs", [])
        results = []
        for tx in transactions[:limit]:
            tx_id = tx.get("hash")
            if not tx_id:
                continue
            try:
                result = self.analyze_transaction(tx_id)
                if result.get("private_keys_found", 0) > 0:
                    results.append({"tx_id": tx_id, "fee": tx.get("fee", 0), "size": tx.get("size", 0), "private_keys_found": result.get("private_keys_found"), "timestamp": tx.get("time", 0)})
            except Exception:
                logger.exception("Failed to analyze mempool transaction %s", tx_id)
        return {"success": True, "mempool_scanned": min(limit, len(transactions)), "vulnerable_transactions": len(results), "results": results}
