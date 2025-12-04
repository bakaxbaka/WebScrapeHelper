"""Lightweight helpers to fetch blockchain data for scanners and analyzers."""

from typing import Dict, Optional

import requests


def fetch_transaction(tx_id: str) -> Optional[Dict]:
    """Fetch raw transaction details from blockchain.info."""
    try:
        response = requests.get(f"https://blockchain.info/rawtx/{tx_id}", timeout=15)
        if response.ok:
            return response.json()
    except Exception:
        pass
    return None


def extract_signature_components(tx_data: Dict):
    """Placeholder to mirror legacy API surface; btc_analyzer performs detailed parsing."""
    if not isinstance(tx_data, dict):
        return []
    return tx_data.get("inputs", [])
