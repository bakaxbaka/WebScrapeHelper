"""Real Bitcoin signature extraction with proper DER parsing and per-input
SIGHASH_ALL message hash computation.

This module replaces the lossy "fabricated sighash" path that PR #4 removed.
It walks the raw transaction hex, parses each input's scriptSig (or witness
for SegWit v0 P2WPKH/P2WSH), DER-decodes the signature, and computes the
real per-input ECDSA message hash ``z`` so that downstream nonce-reuse /
nonce-bias recovery actually produces correct private keys.

Supported:
* Legacy P2PKH SIGHASH_ALL (BIP-66 / pre-SegWit), incl. anyonecanpay/none/single
  combinations encoded in the trailing sighash byte.
* SegWit v0 P2WPKH SIGHASH_ALL (BIP-143).

Out of scope (returns ``z=None`` for those inputs, consistent with the
PR #4 contract):
* P2SH-wrapped multisig where the redeem script is not derivable from the
  scriptSig stack (rare, and easy to add later).
* Taproot v1 / Schnorr (a different signature scheme entirely).
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80


def _dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    n = buf[pos]
    pos += 1
    if n < 0xfd:
        return n, pos
    if n == 0xfd:
        return int.from_bytes(buf[pos:pos + 2], "little"), pos + 2
    if n == 0xfe:
        return int.from_bytes(buf[pos:pos + 4], "little"), pos + 4
    return int.from_bytes(buf[pos:pos + 8], "little"), pos + 8


def _encode_varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xffffffff:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _read_script(buf: bytes, pos: int) -> tuple[bytes, int]:
    length, pos = _read_varint(buf, pos)
    return buf[pos:pos + length], pos + length


@dataclass
class ParsedTx:
    version: int
    is_segwit: bool
    inputs: List[Dict]   # [{'prev_hash','prev_idx','script_sig','sequence','witness'}]
    outputs: List[Dict]  # [{'value','script_pubkey'}]
    locktime: int
    raw: bytes


def parse_raw_tx(raw_hex: str) -> ParsedTx:
    """Parse a raw Bitcoin transaction (hex) including SegWit-marker form."""
    raw = bytes.fromhex(raw_hex)
    pos = 0
    version = int.from_bytes(raw[pos:pos + 4], "little")
    pos += 4

    is_segwit = False
    if raw[pos] == 0x00 and raw[pos + 1] == 0x01:
        is_segwit = True
        pos += 2  # marker + flag

    n_in, pos = _read_varint(raw, pos)
    inputs: List[Dict] = []
    for _ in range(n_in):
        prev_hash = raw[pos:pos + 32][::-1].hex()  # display as txid (big-endian)
        pos += 32
        prev_idx = int.from_bytes(raw[pos:pos + 4], "little")
        pos += 4
        script_sig, pos = _read_script(raw, pos)
        sequence = int.from_bytes(raw[pos:pos + 4], "little")
        pos += 4
        inputs.append({
            "prev_hash": prev_hash,
            "prev_idx": prev_idx,
            "script_sig": script_sig,
            "sequence": sequence,
            "witness": [],
        })

    n_out, pos = _read_varint(raw, pos)
    outputs: List[Dict] = []
    for _ in range(n_out):
        value = int.from_bytes(raw[pos:pos + 8], "little")
        pos += 8
        script_pubkey, pos = _read_script(raw, pos)
        outputs.append({"value": value, "script_pubkey": script_pubkey})

    if is_segwit:
        for inp in inputs:
            n_items, pos = _read_varint(raw, pos)
            items = []
            for _ in range(n_items):
                item, pos = _read_script(raw, pos)
                items.append(item)
            inp["witness"] = items

    locktime = int.from_bytes(raw[pos:pos + 4], "little")
    pos += 4

    return ParsedTx(version, is_segwit, inputs, outputs, locktime, raw)


def parse_der_signature(sig_with_hashtype: bytes) -> Optional[Dict]:
    """Parse a DER-encoded ECDSA signature with trailing 1-byte sighash type.

    Returns dict {'r','s','sighash_type'} on success, else ``None``.
    Strict on length fields; permissive on minimal-encoding (because the
    Bitcoin chain has plenty of historic non-strict-DER sigs).
    """
    if len(sig_with_hashtype) < 9:
        return None
    sighash_type = sig_with_hashtype[-1]
    der = sig_with_hashtype[:-1]
    if der[0] != 0x30:
        return None
    total_len = der[1]
    if total_len + 2 != len(der):
        return None
    pos = 2
    if der[pos] != 0x02:
        return None
    r_len = der[pos + 1]
    pos += 2
    r_bytes = der[pos:pos + r_len]
    pos += r_len
    if pos >= len(der) or der[pos] != 0x02:
        return None
    s_len = der[pos + 1]
    pos += 2
    s_bytes = der[pos:pos + s_len]
    pos += s_len
    if pos != len(der):
        return None
    r = int.from_bytes(r_bytes, "big")
    s = int.from_bytes(s_bytes, "big")
    return {"r": r, "s": s, "sighash_type": sighash_type}


def _iter_pushed_items(script: bytes):
    """Iterate (item, opcode) for each PUSHBYTES on a Bitcoin script."""
    pos = 0
    while pos < len(script):
        op = script[pos]
        pos += 1
        if 0x01 <= op <= 0x4b:
            length = op
            yield script[pos:pos + length]
            pos += length
        elif op == 0x4c:
            length = script[pos]
            pos += 1
            yield script[pos:pos + length]
            pos += length
        elif op == 0x4d:
            length = int.from_bytes(script[pos:pos + 2], "little")
            pos += 2
            yield script[pos:pos + length]
            pos += length
        elif op == 0x4e:
            length = int.from_bytes(script[pos:pos + 4], "little")
            pos += 4
            yield script[pos:pos + length]
            pos += length
        else:
            # Non-push opcode -- ignore for our extractor purposes.
            continue


def split_p2pkh_script_sig(script_sig: bytes) -> Optional[Dict]:
    """Split a standard P2PKH scriptSig <sig> <pubkey> into its parts."""
    items = list(_iter_pushed_items(script_sig))
    if len(items) != 2:
        return None
    sig, pubkey = items
    if not (33 <= len(pubkey) <= 65):
        return None
    if pubkey[0] not in (0x02, 0x03, 0x04):
        return None
    return {"sig": sig, "pubkey": pubkey}


def legacy_sighash(tx: ParsedTx, input_index: int, subscript: bytes,
                   sighash_type: int) -> bytes:
    """Compute legacy (pre-SegWit) Bitcoin sighash for an input.

    Implements SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, with optional
    SIGHASH_ANYONECANPAY flag, exactly per Bitcoin Core's
    SignatureHash() in script/interpreter.cpp.
    """
    base_type = sighash_type & 0x1f
    anyone = bool(sighash_type & SIGHASH_ANYONECANPAY)

    out = bytearray()
    out += tx.version.to_bytes(4, "little")

    # Inputs
    if anyone:
        out += _encode_varint(1)
        inp = tx.inputs[input_index]
        out += bytes.fromhex(inp["prev_hash"])[::-1]
        out += inp["prev_idx"].to_bytes(4, "little")
        out += _encode_varint(len(subscript)) + subscript
        out += inp["sequence"].to_bytes(4, "little")
    else:
        out += _encode_varint(len(tx.inputs))
        for i, inp in enumerate(tx.inputs):
            out += bytes.fromhex(inp["prev_hash"])[::-1]
            out += inp["prev_idx"].to_bytes(4, "little")
            if i == input_index:
                out += _encode_varint(len(subscript)) + subscript
            else:
                out += _encode_varint(0)
            if i != input_index and base_type in (SIGHASH_NONE, SIGHASH_SINGLE):
                out += (0).to_bytes(4, "little")
            else:
                out += inp["sequence"].to_bytes(4, "little")

    # Outputs
    if base_type == SIGHASH_NONE:
        out += _encode_varint(0)
    elif base_type == SIGHASH_SINGLE:
        if input_index >= len(tx.outputs):
            # SIGHASH_SINGLE bug: hash of 0x01...01
            return b"\x01" + b"\x00" * 31
        out += _encode_varint(input_index + 1)
        for i in range(input_index):
            out += (0xffffffffffffffff).to_bytes(8, "little")
            out += _encode_varint(0)
        o = tx.outputs[input_index]
        out += o["value"].to_bytes(8, "little")
        out += _encode_varint(len(o["script_pubkey"])) + o["script_pubkey"]
    else:  # SIGHASH_ALL (default)
        out += _encode_varint(len(tx.outputs))
        for o in tx.outputs:
            out += o["value"].to_bytes(8, "little")
            out += _encode_varint(len(o["script_pubkey"])) + o["script_pubkey"]

    out += tx.locktime.to_bytes(4, "little")
    out += sighash_type.to_bytes(4, "little")
    return _dsha256(bytes(out))


def bip143_sighash(tx: ParsedTx, input_index: int, script_code: bytes,
                   amount: int, sighash_type: int) -> bytes:
    """Compute BIP-143 SegWit-v0 sighash for an input.

    ``script_code`` for P2WPKH is ``OP_DUP OP_HASH160 <20-byte-hash>
    OP_EQUALVERIFY OP_CHECKSIG`` (i.e. a synthesised P2PKH).
    """
    base_type = sighash_type & 0x1f
    anyone = bool(sighash_type & SIGHASH_ANYONECANPAY)

    if not anyone:
        prevouts = b"".join(
            bytes.fromhex(i["prev_hash"])[::-1] + i["prev_idx"].to_bytes(4, "little")
            for i in tx.inputs
        )
        hash_prevouts = _dsha256(prevouts)
    else:
        hash_prevouts = b"\x00" * 32

    if not anyone and base_type not in (SIGHASH_NONE, SIGHASH_SINGLE):
        seqs = b"".join(i["sequence"].to_bytes(4, "little") for i in tx.inputs)
        hash_sequence = _dsha256(seqs)
    else:
        hash_sequence = b"\x00" * 32

    if base_type not in (SIGHASH_NONE, SIGHASH_SINGLE):
        outs = b"".join(
            o["value"].to_bytes(8, "little")
            + _encode_varint(len(o["script_pubkey"])) + o["script_pubkey"]
            for o in tx.outputs
        )
        hash_outputs = _dsha256(outs)
    elif base_type == SIGHASH_SINGLE and input_index < len(tx.outputs):
        o = tx.outputs[input_index]
        hash_outputs = _dsha256(
            o["value"].to_bytes(8, "little")
            + _encode_varint(len(o["script_pubkey"])) + o["script_pubkey"]
        )
    else:
        hash_outputs = b"\x00" * 32

    inp = tx.inputs[input_index]
    preimage = (
        tx.version.to_bytes(4, "little")
        + hash_prevouts
        + hash_sequence
        + bytes.fromhex(inp["prev_hash"])[::-1]
        + inp["prev_idx"].to_bytes(4, "little")
        + _encode_varint(len(script_code)) + script_code
        + amount.to_bytes(8, "little")
        + inp["sequence"].to_bytes(4, "little")
        + hash_outputs
        + tx.locktime.to_bytes(4, "little")
        + sighash_type.to_bytes(4, "little")
    )
    return _dsha256(preimage)


def extract_signatures(tx_id: str,
                        fetch_json: Callable[[str], Dict],
                        fetch_raw_hex: Callable[[str], str]) -> List[Dict]:
    """Extract real (r, s, z, pubkey, sighash_type) tuples from a transaction.

    Each returned dict has:
        r, s, z              -- ints (z is the real per-input ECDSA message)
        sighash_type         -- int (1 = SIGHASH_ALL, etc.)
        pubkey               -- compressed/uncompressed bytes (where derivable)
        input_index, txid    -- provenance
        script_type          -- 'p2pkh' | 'p2wpkh' | 'p2sh' | 'unknown'
    Inputs we cannot derive z for (e.g. unsupported P2SH redeem scripts)
    are returned with ``z=None``.
    """
    tx_json = fetch_json(tx_id)
    raw_hex = fetch_raw_hex(tx_id)
    tx = parse_raw_tx(raw_hex)

    sigs: List[Dict] = []
    for i, inp in enumerate(tx.inputs):
        po = tx_json.get("inputs", [{}])[i].get("prev_out", {}) if i < len(tx_json.get("inputs", [])) else {}
        prev_script = bytes.fromhex(po.get("script", "")) if po.get("script") else b""
        prev_value = po.get("value", 0)

        # ---- Legacy P2PKH ----
        parts = split_p2pkh_script_sig(inp["script_sig"]) if inp["script_sig"] else None
        if parts is not None:
            der = parse_der_signature(parts["sig"])
            if der is None:
                logger.warning("Input %d: scriptSig present but DER parse failed", i)
                continue
            z = legacy_sighash(tx, i, prev_script, der["sighash_type"])
            sigs.append({
                "input_index": i,
                "txid": tx_id,
                "script_type": "p2pkh",
                "r": der["r"],
                "s": der["s"],
                "z": int.from_bytes(z, "big"),
                "sighash_type": der["sighash_type"],
                "pubkey": parts["pubkey"],
            })
            continue

        # ---- SegWit v0 P2WPKH ----
        if not inp["script_sig"] and len(inp["witness"]) == 2:
            sig_bytes, pubkey = inp["witness"]
            der = parse_der_signature(sig_bytes)
            if der is None or len(pubkey) != 33 or pubkey[0] not in (0x02, 0x03):
                logger.warning("Input %d: P2WPKH-shaped witness but parse failed", i)
                continue
            ripemd160 = hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()
            script_code = b"\x76\xa9\x14" + ripemd160 + b"\x88\xac"
            z = bip143_sighash(tx, i, script_code, prev_value, der["sighash_type"])
            sigs.append({
                "input_index": i,
                "txid": tx_id,
                "script_type": "p2wpkh",
                "r": der["r"],
                "s": der["s"],
                "z": int.from_bytes(z, "big"),
                "sighash_type": der["sighash_type"],
                "pubkey": pubkey,
            })
            continue

        # ---- Unsupported (e.g. P2SH multisig where we'd need the redeem script) ----
        sigs.append({
            "input_index": i,
            "txid": tx_id,
            "script_type": "unknown",
            "r": None, "s": None, "z": None,
            "sighash_type": None, "pubkey": None,
        })

    return sigs
