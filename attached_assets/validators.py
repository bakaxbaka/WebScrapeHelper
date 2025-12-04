"""Validation helpers for API inputs."""

import re

_TX_ID_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def validate_transaction_id(tx_id: str) -> bool:
    """Return ``True`` when ``tx_id`` is a 64-character hex string."""
    if not isinstance(tx_id, str):
        return False
    return bool(_TX_ID_PATTERN.fullmatch(tx_id.strip()))
