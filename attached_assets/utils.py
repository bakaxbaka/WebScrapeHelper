"""Utility helpers used by the Bitcoin analysis tools."""

import hashlib
from typing import Union

import base58
from ecdsa import SECP256k1, SigningKey


def private_key_to_wif(private_key: Union[str, int], compressed: bool = True) -> str:
    """Convert a private key (hex string or int) to Wallet Import Format (WIF)."""
    if isinstance(private_key, int):
        private_key_bytes = private_key.to_bytes(32, 'big')
    else:
        private_key_hex = private_key
        if private_key_hex.startswith("0x"):
            private_key_hex = private_key_hex[2:]
        private_key_bytes = bytes.fromhex(private_key_hex.zfill(64))
    
    if compressed:
        extended_key = b'\x80' + private_key_bytes + b'\x01'
    else:
        extended_key = b'\x80' + private_key_bytes
    
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    
    return base58.b58encode(extended_key + checksum).decode('utf-8')


def public_key_to_p2pkh_address(public_key_bytes: bytes) -> str:
    """Convert a public key (bytes) to a P2PKH Bitcoin address."""
    sha256_hash = hashlib.sha256(public_key_bytes).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    
    versioned_payload = b'\x00' + ripemd160_hash
    
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    
    return base58.b58encode(versioned_payload + checksum).decode('utf-8')


def private_key_to_public_key(private_key: Union[str, int], compressed: bool = True) -> bytes:
    """Convert a private key (hex string or int) to a public key (bytes)."""
    if isinstance(private_key, int):
        private_key_bytes = private_key.to_bytes(32, 'big')
    else:
        private_key_hex = private_key
        if private_key_hex.startswith("0x"):
            private_key_hex = private_key_hex[2:]
        private_key_bytes = bytes.fromhex(private_key_hex.zfill(64))
    signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    
    if compressed:
        x = verifying_key.pubkey.point.x()
        y = verifying_key.pubkey.point.y()
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        return prefix + x.to_bytes(32, 'big')
    else:
        return b'\x04' + verifying_key.to_string()


def private_key_to_address(private_key: Union[str, int], compressed: bool = True) -> str:
    """Convert a private key (hex string or int) directly to a Bitcoin address."""
    public_key = private_key_to_public_key(private_key, compressed)
    return public_key_to_p2pkh_address(public_key)


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
