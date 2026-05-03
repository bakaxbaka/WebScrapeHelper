"""Comprehensive Bitcoin signature extraction with per-input sighash.

Replaces the PR #6 P2PKH+P2WPKH-only parser. Handles every common script
type a real address can have signatures in, computes the correct ECDSA
``z`` per Bitcoin Core's ``SignatureHash()`` (legacy), BIP-143 (SegWit
v0), or BIP-341 tagged hash (SegWit v1 / Taproot key-path), and returns
a uniform dict per signature.

Supported input types
---------------------
* ``p2pk``           -- legacy pay-to-pubkey (rare, but appears on early-2010 addresses).
* ``p2pkh``          -- legacy pay-to-pubkey-hash. Most-common pre-2017.
* ``p2wpkh``         -- SegWit v0 pay-to-witness-pubkey-hash.
* ``p2sh-p2wpkh``    -- nested SegWit P2WPKH wrapped in P2SH.
* ``p2sh-multisig``  -- legacy P2SH multisig where the redeem script is the
                        last item in the scriptSig stack.
* ``p2wsh``          -- SegWit v0 P2WSH where the witness script is the
                        last witness item (multisig + simple OP_CHECKSIG).
* ``p2sh-p2wsh``     -- nested SegWit P2WSH.
* ``bare-multisig``  -- legacy bare ``<m> <pk1>..<pkn> <n> CHECKMULTISIG``
                        scriptPubKey.
* ``p2tr-keypath``   -- BIP-341 Taproot key-path. Schnorr, not ECDSA --
                        surfaced with ``schnorr=True`` so downstream
                        recovery skips the ECDSA-only formulas.

For each non-Schnorr signature we return a real per-input ECDSA message
hash ``z`` (32 bytes, big-endian int). For Taproot key-path signatures we
return the BIP-341 message digest in the same field but flag ``schnorr``
so callers don't try to apply ECDSA nonce-reuse / lattice attacks to it.

Anything we genuinely cannot reconstruct ``z`` for (truly custom P2SH
scripts whose redeem script we can't recover) is returned with
``z=None`` and ``script_type='unknown'`` so it is not silently dropped.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from attached_assets.utils import _ripemd160

logger = logging.getLogger(__name__)

# ----- sighash flags --------------------------------------------------------

SIGHASH_DEFAULT = 0x00         # BIP-341 only; equivalent to ALL for legacy.
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80


def _dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hash160(data: bytes) -> bytes:
    return _ripemd160(hashlib.sha256(data).digest())


def _tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP-340 tagged hash."""
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + data).digest()


# ----- low-level varint / push helpers --------------------------------------


def _read_varint(buf: bytes, pos: int) -> Tuple[int, int]:
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


def _read_script(buf: bytes, pos: int) -> Tuple[bytes, int]:
    length, pos = _read_varint(buf, pos)
    return buf[pos:pos + length], pos + length


def _iter_script_ops(script: bytes):
    """Iterate (op, push_data) for each opcode/push in a Bitcoin script.

    For non-push opcodes, push_data is ``None``. For push opcodes (0x01-0x4b
    and 0x4c/0x4d/0x4e), push_data is the pushed bytes.
    """
    pos = 0
    while pos < len(script):
        op = script[pos]
        pos += 1
        if 0x01 <= op <= 0x4b:
            yield op, script[pos:pos + op]
            pos += op
        elif op == 0x4c and pos < len(script):
            length = script[pos]
            pos += 1
            yield op, script[pos:pos + length]
            pos += length
        elif op == 0x4d and pos + 2 <= len(script):
            length = int.from_bytes(script[pos:pos + 2], "little")
            pos += 2
            yield op, script[pos:pos + length]
            pos += length
        elif op == 0x4e and pos + 4 <= len(script):
            length = int.from_bytes(script[pos:pos + 4], "little")
            pos += 4
            yield op, script[pos:pos + length]
            pos += length
        else:
            yield op, None


def _script_pushes(script: bytes) -> List[bytes]:
    """Return only the pushed byte arrays from a script (drop opcodes)."""
    return [data for _, data in _iter_script_ops(script) if data is not None]


# ----- ParsedTx ------------------------------------------------------------


@dataclass
class ParsedTx:
    version: int
    is_segwit: bool
    inputs: List[Dict[str, Any]]
    outputs: List[Dict[str, Any]]
    locktime: int
    raw: bytes


def parse_raw_tx(raw_hex: str) -> ParsedTx:
    """Parse a raw Bitcoin transaction (hex) into structured form."""
    raw = bytes.fromhex(raw_hex)
    pos = 0
    version = int.from_bytes(raw[pos:pos + 4], "little")
    pos += 4

    is_segwit = False
    if raw[pos] == 0x00 and raw[pos + 1] == 0x01:
        is_segwit = True
        pos += 2

    n_in, pos = _read_varint(raw, pos)
    inputs: List[Dict[str, Any]] = []
    for _ in range(n_in):
        prev_hash = raw[pos:pos + 32][::-1].hex()
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
    outputs: List[Dict[str, Any]] = []
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


# ----- DER --------------------------------------------------------------


def parse_der_signature(sig_with_hashtype: bytes) -> Optional[Dict[str, int]]:
    """Strict DER decode of an ECDSA signature with trailing sighash byte."""
    if len(sig_with_hashtype) < 9:
        return None
    sighash_type = sig_with_hashtype[-1]
    der = sig_with_hashtype[:-1]
    if not der or der[0] != 0x30:
        return None
    total_len = der[1]
    if total_len + 2 != len(der):
        return None
    pos = 2
    if pos >= len(der) or der[pos] != 0x02:
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
    return {"r": int.from_bytes(r_bytes, "big"),
            "s": int.from_bytes(s_bytes, "big"),
            "sighash_type": sighash_type}


def parse_schnorr_signature(sig: bytes) -> Optional[Dict[str, int]]:
    """Parse a BIP-340 Schnorr signature (64 bytes, optional 1-byte sighash)."""
    if len(sig) == 64:
        sighash_type = SIGHASH_DEFAULT
        body = sig
    elif len(sig) == 65:
        sighash_type = sig[-1]
        body = sig[:64]
    else:
        return None
    return {"r": int.from_bytes(body[:32], "big"),
            "s": int.from_bytes(body[32:], "big"),
            "sighash_type": sighash_type}


# ----- script-type detection -------------------------------------------------


SCRIPT_P2PK = "p2pk"
SCRIPT_P2PKH = "p2pkh"
SCRIPT_P2SH = "p2sh"
SCRIPT_P2WPKH = "p2wpkh"
SCRIPT_P2WSH = "p2wsh"
SCRIPT_P2SH_P2WPKH = "p2sh-p2wpkh"
SCRIPT_P2SH_P2WSH = "p2sh-p2wsh"
SCRIPT_P2SH_MULTISIG = "p2sh-multisig"
SCRIPT_BARE_MULTISIG = "bare-multisig"
SCRIPT_P2TR = "p2tr-keypath"
SCRIPT_UNKNOWN = "unknown"


def detect_output_script_type(script: bytes) -> str:
    """Identify a scriptPubKey by its standard template."""
    if not script:
        return SCRIPT_UNKNOWN
    # P2PK: <push_pubkey> OP_CHECKSIG
    if len(script) in (35, 67) and script[-1] == 0xac and script[0] in (0x21, 0x41):
        return SCRIPT_P2PK
    # P2PKH: 0x76 0xa9 0x14 <20> 0x88 0xac
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[-2:] == b"\x88\xac":
        return SCRIPT_P2PKH
    # P2SH: 0xa9 0x14 <20> 0x87
    if len(script) == 23 and script[:2] == b"\xa9\x14" and script[-1] == 0x87:
        return SCRIPT_P2SH
    # P2WPKH: 0x00 0x14 <20>
    if len(script) == 22 and script[:2] == b"\x00\x14":
        return SCRIPT_P2WPKH
    # P2WSH: 0x00 0x20 <32>
    if len(script) == 34 and script[:2] == b"\x00\x20":
        return SCRIPT_P2WSH
    # P2TR: 0x51 0x20 <32>
    if len(script) == 34 and script[:2] == b"\x51\x20":
        return SCRIPT_P2TR
    # Bare multisig: <OP_m> <push_pk1> ... <push_pkn> <OP_n> 0xae
    if script and script[-1] == 0xae:
        ops = list(_iter_script_ops(script))
        if len(ops) >= 4 and ops[-1][0] == 0xae:
            n_op = ops[-2][0]
            m_op = ops[0][0]
            if 0x51 <= m_op <= 0x60 and 0x51 <= n_op <= 0x60:
                pks = [d for op, d in ops[1:-2] if d is not None and len(d) in (33, 65)]
                if len(pks) == (n_op - 0x50):
                    return SCRIPT_BARE_MULTISIG
    return SCRIPT_UNKNOWN


def parse_redeem_or_witness_script(rs: bytes) -> Optional[Dict[str, Any]]:
    """Recognise standard redeem/witness script shapes.

    Returns a dict describing the script, or ``None`` if unrecognised.
    """
    if not rs:
        return None
    # P2WPKH (used inside P2SH-P2WPKH redeem script)
    if len(rs) == 22 and rs[:2] == b"\x00\x14":
        return {"type": SCRIPT_P2WPKH, "pkh": rs[2:]}
    # P2WSH (used inside P2SH-P2WSH redeem script)
    if len(rs) == 34 and rs[:2] == b"\x00\x20":
        return {"type": SCRIPT_P2WSH, "wsh": rs[2:]}
    # CHECKSIG-only redeem script: <pubkey> OP_CHECKSIG
    if rs[-1] == 0xac and len(rs) in (35, 67) and rs[0] in (0x21, 0x41):
        # mirror P2PK
        return {"type": SCRIPT_P2PK, "pubkey": _script_pushes(rs)[0]}
    # Multisig redeem/witness: <m> <pk1>..<pkn> <n> CHECKMULTISIG
    if rs[-1] == 0xae:
        ops = list(_iter_script_ops(rs))
        if len(ops) >= 4 and ops[-1][0] == 0xae:
            n_op = ops[-2][0]
            m_op = ops[0][0]
            if 0x51 <= m_op <= 0x60 and 0x51 <= n_op <= 0x60:
                pubkeys = [d for op, d in ops[1:-2] if d is not None and len(d) in (33, 65)]
                if len(pubkeys) == (n_op - 0x50):
                    return {"type": "multisig",
                            "m": m_op - 0x50, "n": n_op - 0x50,
                            "pubkeys": pubkeys}
    return None


# ----- legacy / BIP-143 / BIP-341 sighash -----------------------------------


def legacy_sighash(tx: ParsedTx, input_index: int, subscript: bytes,
                   sighash_type: int) -> bytes:
    """Bitcoin Core ``SignatureHash()`` for legacy (non-SegWit) inputs."""
    base_type = sighash_type & 0x1f
    anyone = bool(sighash_type & SIGHASH_ANYONECANPAY)

    out = bytearray()
    out += tx.version.to_bytes(4, "little")

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

    if base_type == SIGHASH_NONE:
        out += _encode_varint(0)
    elif base_type == SIGHASH_SINGLE:
        if input_index >= len(tx.outputs):
            return b"\x01" + b"\x00" * 31
        out += _encode_varint(input_index + 1)
        for _ in range(input_index):
            out += (0xffffffffffffffff).to_bytes(8, "little")
            out += _encode_varint(0)
        o = tx.outputs[input_index]
        out += o["value"].to_bytes(8, "little")
        out += _encode_varint(len(o["script_pubkey"])) + o["script_pubkey"]
    else:
        out += _encode_varint(len(tx.outputs))
        for o in tx.outputs:
            out += o["value"].to_bytes(8, "little")
            out += _encode_varint(len(o["script_pubkey"])) + o["script_pubkey"]

    out += tx.locktime.to_bytes(4, "little")
    out += sighash_type.to_bytes(4, "little")
    return _dsha256(bytes(out))


def bip143_sighash(tx: ParsedTx, input_index: int, script_code: bytes,
                   amount: int, sighash_type: int) -> bytes:
    """BIP-143 sighash for SegWit-v0 inputs (P2WPKH and P2WSH)."""
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


def bip341_sighash(tx: ParsedTx, input_index: int,
                    spent_amounts: List[int],
                    spent_scripts: List[bytes],
                    sighash_type: int = SIGHASH_DEFAULT,
                    annex: Optional[bytes] = None) -> bytes:
    """BIP-341 (Taproot) key-path sighash. Schnorr message; not ECDSA z."""
    base_type = sighash_type & 0x03
    anyone = bool(sighash_type & SIGHASH_ANYONECANPAY)

    pre = bytearray()
    pre += b"\x00"  # epoch
    pre += bytes([sighash_type])
    pre += tx.version.to_bytes(4, "little")
    pre += tx.locktime.to_bytes(4, "little")
    if not anyone:
        pre += _sha256(b"".join(
            bytes.fromhex(i["prev_hash"])[::-1] + i["prev_idx"].to_bytes(4, "little")
            for i in tx.inputs))
        pre += _sha256(b"".join(v.to_bytes(8, "little") for v in spent_amounts))
        pre += _sha256(b"".join(
            _encode_varint(len(s)) + s for s in spent_scripts))
        pre += _sha256(b"".join(i["sequence"].to_bytes(4, "little") for i in tx.inputs))
    if base_type == SIGHASH_DEFAULT or base_type == SIGHASH_ALL:
        outs = b"".join(
            o["value"].to_bytes(8, "little")
            + _encode_varint(len(o["script_pubkey"])) + o["script_pubkey"]
            for o in tx.outputs)
        pre += _sha256(outs)
    spend_type = (1 if annex is not None else 0)
    pre += bytes([spend_type])
    if anyone:
        inp = tx.inputs[input_index]
        pre += bytes.fromhex(inp["prev_hash"])[::-1]
        pre += inp["prev_idx"].to_bytes(4, "little")
        pre += spent_amounts[input_index].to_bytes(8, "little")
        s = spent_scripts[input_index]
        pre += _encode_varint(len(s)) + s
        pre += inp["sequence"].to_bytes(4, "little")
    else:
        pre += input_index.to_bytes(4, "little")
    if annex is not None:
        pre += _sha256(_encode_varint(len(annex)) + annex)
    if base_type == SIGHASH_SINGLE:
        o = tx.outputs[input_index]
        pre += _sha256(o["value"].to_bytes(8, "little")
                        + _encode_varint(len(o["script_pubkey"])) + o["script_pubkey"])
    return _tagged_hash("TapSighash", bytes(pre))


# ----- per-input extraction --------------------------------------------------


def _build_p2pkh_script_code(pkh: bytes) -> bytes:
    return b"\x76\xa9\x14" + pkh + b"\x88\xac"


def _make_sig_record(*, txid, input_index, script_type, der, pubkey, z,
                     schnorr=False, redeem_script=None) -> Dict[str, Any]:
    return {
        "txid": txid,
        "input_index": input_index,
        "script_type": script_type,
        "r": der["r"],
        "s": der["s"],
        "sighash_type": der["sighash_type"],
        "pubkey": pubkey,
        "z": int.from_bytes(z, "big") if z is not None else None,
        "schnorr": schnorr,
        "redeem_script": redeem_script.hex() if redeem_script else None,
    }


def _extract_for_input(tx: ParsedTx, i: int, txid: str,
                        prev_script: bytes, prev_value: int,
                        spent_amounts: List[int],
                        spent_scripts: List[bytes]) -> List[Dict[str, Any]]:
    inp = tx.inputs[i]
    out: List[Dict[str, Any]] = []
    sp_type = detect_output_script_type(prev_script) if prev_script else SCRIPT_UNKNOWN

    # ----- P2PK (legacy) -----
    if sp_type == SCRIPT_P2PK:
        # scriptSig: <sig>
        items = _script_pushes(inp["script_sig"])
        if len(items) == 1:
            der = parse_der_signature(items[0])
            if der is not None:
                pubkey = _script_pushes(prev_script)[0]
                z = legacy_sighash(tx, i, prev_script, der["sighash_type"])
                out.append(_make_sig_record(
                    txid=txid, input_index=i, script_type=SCRIPT_P2PK,
                    der=der, pubkey=pubkey, z=z))
                return out

    # ----- P2PKH (legacy) -----
    if sp_type == SCRIPT_P2PKH or (sp_type == SCRIPT_UNKNOWN and inp["script_sig"]):
        items = _script_pushes(inp["script_sig"])
        if len(items) == 2 and 33 <= len(items[1]) <= 65 and items[1][0] in (0x02, 0x03, 0x04):
            der = parse_der_signature(items[0])
            if der is not None:
                pubkey = items[1]
                # Subscript for legacy P2PKH is the full prev scriptPubKey.
                subscript = prev_script if prev_script else _build_p2pkh_script_code(_hash160(pubkey))
                z = legacy_sighash(tx, i, subscript, der["sighash_type"])
                out.append(_make_sig_record(
                    txid=txid, input_index=i, script_type=SCRIPT_P2PKH,
                    der=der, pubkey=pubkey, z=z))
                return out

    # ----- P2WPKH -----
    if sp_type == SCRIPT_P2WPKH:
        if not inp["script_sig"] and len(inp["witness"]) == 2:
            sig_bytes, pubkey = inp["witness"]
            der = parse_der_signature(sig_bytes)
            if der is not None and len(pubkey) == 33 and pubkey[0] in (0x02, 0x03):
                script_code = _build_p2pkh_script_code(_hash160(pubkey))
                z = bip143_sighash(tx, i, script_code, prev_value, der["sighash_type"])
                out.append(_make_sig_record(
                    txid=txid, input_index=i, script_type=SCRIPT_P2WPKH,
                    der=der, pubkey=pubkey, z=z))
                return out

    # ----- P2SH variants -----
    if sp_type == SCRIPT_P2SH:
        items = list(_script_pushes(inp["script_sig"]))
        if items:
            redeem = items[-1]
            sigs_in_sig = items[:-1]
            # Verify HASH160(redeem) == hash in prev_script
            redeem_hash = _hash160(redeem)
            if prev_script[3:23] != redeem_hash:
                logger.debug("Input %d: P2SH redeem hash mismatch (could be non-standard)", i)
            shape = parse_redeem_or_witness_script(redeem)

            # P2SH-P2WPKH (nested SegWit P2WPKH)
            if shape and shape["type"] == SCRIPT_P2WPKH and len(inp["witness"]) == 2:
                sig_bytes, pubkey = inp["witness"]
                der = parse_der_signature(sig_bytes)
                if der is not None and len(pubkey) == 33 and pubkey[0] in (0x02, 0x03):
                    script_code = _build_p2pkh_script_code(_hash160(pubkey))
                    z = bip143_sighash(tx, i, script_code, prev_value, der["sighash_type"])
                    out.append(_make_sig_record(
                        txid=txid, input_index=i, script_type=SCRIPT_P2SH_P2WPKH,
                        der=der, pubkey=pubkey, z=z, redeem_script=redeem))
                    return out

            # P2SH-P2WSH (nested SegWit P2WSH)
            if shape and shape["type"] == SCRIPT_P2WSH and inp["witness"]:
                witness_script = inp["witness"][-1]
                wshape = parse_redeem_or_witness_script(witness_script)
                if wshape and wshape["type"] == "multisig":
                    # witness stack: [<empty>, sig1, sig2, ..., witness_script]
                    sigs = inp["witness"][1:-1]
                    for sig_bytes in sigs:
                        der = parse_der_signature(sig_bytes)
                        if der is None:
                            continue
                        z = bip143_sighash(tx, i, witness_script, prev_value, der["sighash_type"])
                        # We don't know which pubkey signed without testing each;
                        # leave pubkey=None and let the recovery layer try.
                        out.append(_make_sig_record(
                            txid=txid, input_index=i, script_type=SCRIPT_P2SH_P2WSH,
                            der=der, pubkey=None, z=z, redeem_script=witness_script))
                    if out:
                        return out

            # Legacy P2SH multisig
            if shape and shape["type"] == "multisig":
                for sig_bytes in sigs_in_sig:
                    if not sig_bytes:
                        continue
                    der = parse_der_signature(sig_bytes)
                    if der is None:
                        continue
                    z = legacy_sighash(tx, i, redeem, der["sighash_type"])
                    out.append(_make_sig_record(
                        txid=txid, input_index=i, script_type=SCRIPT_P2SH_MULTISIG,
                        der=der, pubkey=None, z=z, redeem_script=redeem))
                if out:
                    return out

            # P2SH wrapping a CHECKSIG-only redeem script (rare)
            if shape and shape["type"] == SCRIPT_P2PK and len(sigs_in_sig) == 1:
                der = parse_der_signature(sigs_in_sig[0])
                if der is not None:
                    pubkey = shape["pubkey"]
                    z = legacy_sighash(tx, i, redeem, der["sighash_type"])
                    out.append(_make_sig_record(
                        txid=txid, input_index=i, script_type="p2sh-p2pk",
                        der=der, pubkey=pubkey, z=z, redeem_script=redeem))
                    return out

    # ----- P2WSH (native SegWit) -----
    if sp_type == SCRIPT_P2WSH and inp["witness"]:
        witness_script = inp["witness"][-1]
        wsh_check = _sha256(witness_script)
        if prev_script[2:34] != wsh_check:
            logger.debug("Input %d: P2WSH witness script hash mismatch", i)
        shape = parse_redeem_or_witness_script(witness_script)
        if shape and shape["type"] == "multisig":
            sigs = inp["witness"][1:-1]
            for sig_bytes in sigs:
                der = parse_der_signature(sig_bytes)
                if der is None:
                    continue
                z = bip143_sighash(tx, i, witness_script, prev_value, der["sighash_type"])
                out.append(_make_sig_record(
                    txid=txid, input_index=i, script_type=SCRIPT_P2WSH,
                    der=der, pubkey=None, z=z, redeem_script=witness_script))
            if out:
                return out
        if shape and shape["type"] == SCRIPT_P2PK and len(inp["witness"]) >= 2:
            sig_bytes = inp["witness"][0]
            der = parse_der_signature(sig_bytes)
            if der is not None:
                pubkey = shape["pubkey"]
                z = bip143_sighash(tx, i, witness_script, prev_value, der["sighash_type"])
                out.append(_make_sig_record(
                    txid=txid, input_index=i, script_type=SCRIPT_P2WSH,
                    der=der, pubkey=pubkey, z=z, redeem_script=witness_script))
                return out

    # ----- Bare multisig (legacy) -----
    if sp_type == SCRIPT_BARE_MULTISIG:
        items = _script_pushes(inp["script_sig"])
        # Often <0> <sig1> <sig2> ... -- the leading 0 is OP_0 (no push), so
        # _script_pushes already drops it.
        for sig_bytes in items:
            der = parse_der_signature(sig_bytes)
            if der is None:
                continue
            z = legacy_sighash(tx, i, prev_script, der["sighash_type"])
            out.append(_make_sig_record(
                txid=txid, input_index=i, script_type=SCRIPT_BARE_MULTISIG,
                der=der, pubkey=None, z=z, redeem_script=prev_script))
        if out:
            return out

    # ----- Taproot (BIP-341 key-path) -----
    if sp_type == SCRIPT_P2TR and inp["witness"]:
        witness = list(inp["witness"])
        annex = None
        if witness and witness[-1] and witness[-1][0] == 0x50:
            annex = witness[-1]
            witness = witness[:-1]
        if len(witness) == 1:
            sig_bytes = witness[0]
            sch = parse_schnorr_signature(sig_bytes)
            if sch is not None and len(spent_amounts) == len(tx.inputs):
                z = bip341_sighash(tx, i, spent_amounts, spent_scripts,
                                    sch["sighash_type"], annex=annex)
                out.append(_make_sig_record(
                    txid=txid, input_index=i, script_type=SCRIPT_P2TR,
                    der=sch, pubkey=prev_script[2:34], z=z, schnorr=True))
                return out

    # ----- Fallback -----
    out.append({
        "txid": txid, "input_index": i, "script_type": SCRIPT_UNKNOWN,
        "r": None, "s": None, "sighash_type": None,
        "pubkey": None, "z": None, "schnorr": False,
        "redeem_script": None,
    })
    return out


def extract_signatures(tx_id: str,
                        fetch_json: Callable[[str], Dict],
                        fetch_raw_hex: Callable[[str], str]) -> List[Dict[str, Any]]:
    """Extract every signature from a transaction along with real ``z``.

    ``fetch_json`` returns a blockchain.info-style ``rawtx`` dict (we only use
    ``inputs[*].prev_out.script`` and ``inputs[*].prev_out.value``).
    ``fetch_raw_hex`` returns the raw transaction hex (for proper parsing).
    """
    tx_json = fetch_json(tx_id)
    raw_hex = fetch_raw_hex(tx_id)
    tx = parse_raw_tx(raw_hex)

    spent_amounts: List[int] = []
    spent_scripts: List[bytes] = []
    for i in range(len(tx.inputs)):
        if i < len(tx_json.get("inputs", [])):
            po = tx_json["inputs"][i].get("prev_out", {}) or {}
        else:
            po = {}
        spent_amounts.append(int(po.get("value", 0)))
        spent_scripts.append(bytes.fromhex(po.get("script", "")) if po.get("script") else b"")

    sigs: List[Dict[str, Any]] = []
    for i in range(len(tx.inputs)):
        sigs.extend(_extract_for_input(tx, i, tx_id,
                                        spent_scripts[i], spent_amounts[i],
                                        spent_amounts, spent_scripts))
    return sigs
