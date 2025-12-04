"""Utility helpers used by the Bitcoin analysis tools."""

import hashlib
from typing import Union


def format_hex(value: Union[int, bytes, str]) -> str:
    """Return a hex string with ``0x`` prefix and even length."""
    if isinstance(value, bytes):
        hex_value = value.hex()
    elif isinstance(value, int):
        hex_value = hex(value)[2:]
    else:
        hex_value = str(value)
        if hex_value.startswith("0x"):
            hex_value = hex_value[2:]
    if len(hex_value) % 2:
        hex_value = f"0{hex_value}"
    return f"0x{hex_value.lower()}"


def calculate_message_hash(message_hex: str) -> bytes:
    """Calculate the double-SHA256 hash of a hex-encoded message."""
    if message_hex.startswith("0x"):
        message_hex = message_hex[2:]
    message_bytes = bytes.fromhex(message_hex)
    return hashlib.sha256(hashlib.sha256(message_bytes).digest()).digest()


def int_to_bytes(value: int, length: int = 32) -> bytes:
    """Convert an integer to big-endian bytes, padded to ``length``."""
    return value.to_bytes(length, byteorder="big")


def bytes_to_int(value: bytes) -> int:
    """Convert a byte sequence to an integer."""
    return int.from_bytes(value, byteorder="big")
