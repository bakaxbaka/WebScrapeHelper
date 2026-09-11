"""JSON API routes.

All request parsing/HTTP concerns live here; analysis and calculations live in
webapp.services.bitcoin.
"""

from __future__ import annotations

import logging
import re
from functools import wraps
from typing import Any, Callable

import requests
from flask import Blueprint, current_app, jsonify, request

from attached_assets.validators import validate_transaction_id
from webapp.services.bitcoin import BitcoinService

logger = logging.getLogger(__name__)
api_bp = Blueprint("api", __name__)
_service: BitcoinService | None = None

BTC_ADDRESS_RE = re.compile(r"^(?:[13][1-9A-HJ-NP-Za-km-z]{25,34}|bc1[02-9ac-hj-np-z]{6,87})$")
HEX_FIELDS = ("r", "s", "z", "k", "x", "r1", "s1", "z1", "r2", "s2", "z2", "m1", "m2")


def get_service() -> BitcoinService:
    global _service
    if _service is None:
        _service = BitcoinService()
    return _service


def json_route(fn: Callable[..., Any]):
    """Convert unexpected route exceptions into a consistent JSON response."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except requests.RequestException as exc:
            logger.warning("Upstream network error: %s", exc)
            return jsonify(error="Upstream Bitcoin service unavailable", status=502), 502
        except ValueError as exc:
            return jsonify(error=str(exc), status=400), 400
        except Exception:
            logger.exception("Unhandled API error in %s", fn.__name__)
            return jsonify(error="Internal server error", status=500), 500
    return wrapper


def body() -> dict[str, Any]:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValueError("JSON object body is required")
    return data


def require_fields(data: dict[str, Any], *fields: str) -> None:
    missing = [field for field in fields if field not in data or data[field] in (None, "")]
    if missing:
        raise ValueError("Missing required fields: " + ", ".join(missing))


def parse_int(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        raise ValueError(f"{name} must be hexadecimal or integer")
    value = value.strip().lower()
    if value.startswith("0x"):
        value = value[2:]
    if not value or not re.fullmatch(r"[0-9a-f]+", value):
        raise ValueError(f"{name} must be a hexadecimal value")
    return int(value, 16)


def parse_hex_fields(data: dict[str, Any], *fields: str) -> dict[str, int]:
    return {field: parse_int(data[field], field) for field in fields}


def validate_address(address: Any) -> str:
    if not isinstance(address, str) or not BTC_ADDRESS_RE.fullmatch(address.strip()):
        raise ValueError("Invalid Bitcoin address format")
    return address.strip()


def _safe_address_scan_result(result: dict[str, Any], address: str) -> dict[str, Any]:
    """Return address-scan findings without exposing secret key material."""
    safe = dict(result)
    recovered = safe.pop("recovered_keys", []) or []
    safe["recovered_key_count"] = len(recovered)
    safe["private_key_material_exposed"] = False

    repeated = safe.get("reused_r_groups", []) or []
    cross = safe.get("cross_tx_reused_r", []) or []
    within = safe.get("in_tx_reused_r", []) or []
    if cross or within:
        safe["risk_level"] = "high"
        safe["finding_summary"] = "Repeated ECDSA r values were detected; verify the corresponding per-input z values and signatures before classifying the finding as exploitable."
    elif safe.get("signatures_total", 0):
        safe["risk_level"] = "none-observed"
        safe["finding_summary"] = "No repeated ECDSA r values were observed in the analyzed history."
    else:
        safe["risk_level"] = "insufficient-data"
        safe["finding_summary"] = "No ECDSA signatures were available for a cryptographic weakness assessment."
    safe["address"] = address
    safe["scanner"] = "address-history-v1"
    return safe


@api_bp.post("/analyze/transaction")
@json_route
def analyze_transaction():
    data = body()
    require_fields(data, "tx_id")
    tx_id = str(data["tx_id"]).strip()
    if not validate_transaction_id(tx_id):
        raise ValueError("Invalid transaction ID format")
    return jsonify(get_service().analyze_transaction(tx_id))


@api_bp.post("/analyze/address")
@json_route
def analyze_address():
    data = body()
    require_fields(data, "address")
    address = validate_address(data["address"])
    try:
        max_txs = int(data.get("max_txs", current_app.config["ANALYSIS_MAX_TXS"]))
    except (TypeError, ValueError):
        raise ValueError("max_txs must be an integer")
    max_txs = max(1, min(max_txs, 5000))
    result = get_service().analyze_address(address, max_txs=max_txs)
    if isinstance(result, dict) and result.get("error"):
        return jsonify(address=address, error=result["error"], status="failed"), 502
    return jsonify(result)


@api_bp.post("/scan/address")
@json_route
def scan_address():
    """Scan an address history for cryptographic weaknesses.

    This is the UI-facing endpoint. It deliberately strips recovered private-key
    material and returns only vulnerability findings and verification metadata.
    """
    data = body()
    require_fields(data, "address")
    address = validate_address(data["address"])
    try:
        max_txs = int(data.get("max_txs", current_app.config["ANALYSIS_MAX_TXS"]))
    except (TypeError, ValueError):
        raise ValueError("max_txs must be an integer")
    max_txs = max(1, min(max_txs, 5000))
    result = get_service().analyze_address(address, max_txs=max_txs)
    if isinstance(result, dict) and result.get("error"):
        return jsonify(address=address, error=result["error"], status="failed"), 502
    return jsonify(_safe_address_scan_result(result, address))


@api_bp.post("/analyze/ecdsa")
@json_route
def analyze_ecdsa():
    data = body()
    if data.get("tx_id"):
        tx_id = str(data["tx_id"]).strip()
        if not validate_transaction_id(tx_id):
            raise ValueError("Invalid transaction ID format")
        result = get_service().analyze_transaction(tx_id)
        for group in result.get("weak_signatures", []):
            if group.get("type") not in {"nonce_reuse", "reused_r"}:
                continue
            signatures = group.get("all_signatures", [])
            if len(signatures) < 2:
                continue
            first, second = signatures[0], signatures[1]
            if not first.get("message") or not second.get("message"):
                return jsonify(error="Reused r detected, but real per-input message hashes (z) are unavailable. Provide r1/s1/z1/r2/s2/z2 directly."), 400
            params = {
                "r1": parse_int(first["r"], "r1"), "s1": parse_int(first["s"], "s1"), "z1": parse_int(first["message"], "z1"),
                "r2": parse_int(second["r"], "r2"), "s2": parse_int(second["s"], "s2"), "z2": parse_int(second["message"], "z2"),
            }
            response = get_service().analyze_ecdsa_pair(**params)
            response["tx_id"] = tx_id
            response["input_indices"] = {"input_1": first.get("input_index", 0), "input_2": second.get("input_index", 1)}
            return jsonify(response)
        raise ValueError("No nonce reuse detected in transaction")

    require_fields(data, "r1", "s1", "m1", "r2", "s2", "m2")
    values = parse_hex_fields(data, "r1", "s1", "m1", "r2", "s2", "m2")
    return jsonify(get_service().analyze_ecdsa_pair(
        values["r1"], values["s1"], values["m1"], values["r2"], values["s2"], values["m2"]
    ))


@api_bp.post("/calculate/nonce")
@json_route
def calculate_nonce():
    data = body()
    require_fields(data, "r", "s1", "s2", "z1", "z2")
    values = parse_hex_fields(data, "r", "s1", "s2", "z1", "z2")
    return jsonify(get_service().calculate_nonce(**values))


@api_bp.post("/calculate/nonce-from-private-key")
@json_route
def calculate_nonce_from_private_key():
    data = body()
    require_fields(data, "r", "s", "z", "x")
    values = parse_hex_fields(data, "r", "s", "z", "x")
    return jsonify(get_service().calculate_nonce_from_private_key(**values))


@api_bp.post("/recover/low-s-with-nonce")
@json_route
def recover_with_known_nonce():
    data = body()
    require_fields(data, "r", "s", "z", "k")
    values = parse_hex_fields(data, "r", "s", "z", "k")
    return jsonify(get_service().recover_with_known_nonce(**values))


@api_bp.post("/recover/malleability-signatures")
@json_route
def analyze_signature_malleability():
    """Analyze ECDSA signature malleability without falsely claiming key recovery."""
    data = body()
    require_fields(data, "r", "s_values", "z")
    if not isinstance(data["s_values"], list) or len(data["s_values"]) < 2:
        raise ValueError("s_values must contain at least two values")
    r = parse_int(data["r"], "r")
    z = parse_int(data["z"], "z")
    s_values = [parse_int(value, "s") for value in data["s_values"]]
    n = get_service().analyzer.curve.order
    if not 0 < r < n:
        raise ValueError("r must be in the secp256k1 scalar range")
    unique = sorted(set(s_values))
    if any(not 0 < s < n for s in unique):
        raise ValueError("s values must be in the secp256k1 scalar range")
    pairs = []
    for s in unique:
        complement = (n - s) % n
        if complement in unique and s != complement:
            pairs.append({"s": format(s, "064x"), "complement": format(complement, "064x")})
    return jsonify({
        "success": True,
        "method": "ECDSA signature malleability analysis",
        "malleable": bool(pairs),
        "r": format(r, "064x"),
        "z": format(z, "064x"),
        "s_values": [format(s, "064x") for s in unique],
        "malleable_pairs": pairs,
        "private_key_recovered": False,
        "note": "Signature malleability alone does not recover a private key.",
    })


@api_bp.get("/addresses/known")
@json_route
def known_addresses():
    return jsonify(get_service().known_addresses())


@api_bp.get("/auto-scan")
@json_route
def auto_scan():
    return jsonify(get_service().scan_recent_block())


@api_bp.get("/monitor-mempool")
@json_route
def monitor_mempool():
    return jsonify(get_service().monitor_mempool())


@api_bp.get("/health")
def health():
    return jsonify({"status": "ok", "service": "WebScrapeHelper", "api": "v1"})
