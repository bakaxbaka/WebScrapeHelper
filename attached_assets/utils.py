"""Utility helpers used by the Bitcoin analysis tools."""

import hashlib
from typing import Union

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


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


def _base58_check_encode(payload: bytes) -> str:
    """Encode payload using Base58Check (Bitcoin address encoding)."""
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    value = payload + checksum

    # Convert to integer for Base58 conversion
    num = int.from_bytes(value, "big")
    encoded = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded

    # Preserve leading zeros as "1"
    leading_zeros = len(value) - len(value.lstrip(b"\x00"))
    return "1" * leading_zeros + encoded


def private_key_to_wif(private_key: int, compressed: bool = True, testnet: bool = False) -> str:
    """Convert an integer private key into Wallet Import Format (WIF)."""
    if not isinstance(private_key, int):
        raise TypeError("private_key must be an integer")

    if not (0 < private_key < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141):
        raise ValueError("private_key is out of range for secp256k1")

    prefix = b"\xef" if testnet else b"\x80"
    key_bytes = private_key.to_bytes(32, "big")
    payload = prefix + key_bytes + (b"\x01" if compressed else b"")
    return _base58_check_encode(payload)


def public_key_to_p2pkh_address(public_key_bytes: bytes, testnet: bool = False) -> str:
    """Convert a public key byte string to a P2PKH Bitcoin address."""
    if not isinstance(public_key_bytes, (bytes, bytearray)):
        raise TypeError("public_key_bytes must be bytes")

    sha_hash = hashlib.sha256(public_key_bytes).digest()
    ripe_hash = hashlib.new("ripemd160", sha_hash).digest()
    prefix = b"\x6f" if testnet else b"\x00"
    return _base58_check_encode(prefix + ripe_hash)
