"""Comprehensive API contract and validation tests."""

from types import SimpleNamespace

import pytest

import webapp.routes.api as api_module


class FakeService:
    def __init__(self):
        self.analyzer = SimpleNamespace(curve=SimpleNamespace(order=2**256 - 2**32 - 977))

    def analyze_transaction(self, tx_id):
        return {"success": True, "tx_id": tx_id, "weak_signatures": []}

    def analyze_address(self, address, max_txs=500):
        return {"success": True, "address": address, "max_txs": max_txs}

    def analyze_ecdsa_pair(self, r1, s1, z1, r2, s2, z2):
        return {"success": True, "r1": r1, "s1": s1, "z1": z1, "r2": r2, "s2": s2, "z2": z2}

    def calculate_nonce(self, **values):
        return {"success": True, "nonce": "01", "inputs": values}

    def calculate_nonce_from_private_key(self, **values):
        return {"success": True, "nonce": "02", "inputs": values}

    def recover_with_known_nonce(self, **values):
        return {"success": True, "private_key": "03", "inputs": values}

    def known_addresses(self):
        return ["known"]

    def scan_recent_block(self):
        return {"success": True, "scanned_transactions": 0}

    def monitor_mempool(self):
        return {"success": True, "mempool_scanned": 0}


@pytest.fixture()
def fake_service(monkeypatch):
    service = FakeService()
    monkeypatch.setattr(api_module, "_service", service)
    return service


def test_health_contract(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok", "service": "WebScrapeHelper", "api": "v1"}


def test_all_expected_routes_are_registered(app):
    routes = {rule.rule for rule in app.url_map.iter_rules()}
    expected = {
        "/", "/transaction", "/address", "/ecdsa-analysis",
        "/api/analyze/transaction", "/api/analyze/address", "/api/analyze/ecdsa",
        "/api/calculate/nonce", "/api/calculate/nonce-from-private-key",
        "/api/recover/low-s-with-nonce", "/api/recover/malleability-signatures",
        "/api/addresses/known", "/api/auto-scan", "/api/monitor-mempool", "/api/health",
    }
    assert expected <= routes


def test_transaction_requires_json_object(client):
    response = client.post("/api/analyze/transaction", json=[])
    assert response.status_code == 400
    assert "JSON object body is required" in response.get_json()["error"]


def test_transaction_requires_tx_id(client):
    response = client.post("/api/analyze/transaction", json={})
    assert response.status_code == 400
    assert "tx_id" in response.get_json()["error"]


def test_transaction_rejects_malformed_tx_id(client):
    response = client.post("/api/analyze/transaction", json={"tx_id": "not-a-tx"})
    assert response.status_code == 400
    assert "Invalid transaction ID format" in response.get_json()["error"]


def test_transaction_delegates_to_service(client, fake_service):
    tx_id = "00" * 32
    response = client.post("/api/analyze/transaction", json={"tx_id": tx_id})
    assert response.status_code == 200
    assert response.get_json()["tx_id"] == tx_id


def test_address_validation_and_normalization(client, fake_service):
    response = client.post(
        "/api/analyze/address",
        json={"address": "  1BoatSLRHtKNngkdXEeobR76b53LETtpyT  ", "max_txs": 10},
    )
    assert response.status_code == 200
    assert response.get_json()["address"] == "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    assert response.get_json()["max_txs"] == 10


@pytest.mark.parametrize("address", ["", "abc", "0x123", "1invalid0O"])
def test_address_rejects_invalid_formats(client, address):
    response = client.post("/api/analyze/address", json={"address": address})
    assert response.status_code == 400


def test_address_caps_max_txs(client, fake_service):
    response = client.post(
        "/api/analyze/address",
        json={"address": "1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "max_txs": 999999},
    )
    assert response.status_code == 200
    assert response.get_json()["max_txs"] == 5000


@pytest.mark.parametrize("value", ["nope", [], {}, True, None])
def test_numeric_fields_reject_non_hex_values(client, fake_service, value):
    response = client.post(
        "/api/calculate/nonce",
        json={"r": value, "s1": "01", "s2": "02", "z1": "03", "z2": "04"},
    )
    assert response.status_code == 400


def test_hex_parser_accepts_prefixed_and_unprefixed_values(client, fake_service):
    response = client.post(
        "/api/calculate/nonce",
        json={"r": "0x01", "s1": "02", "s2": "03", "z1": "04", "z2": "05"},
    )
    assert response.status_code == 200
    assert response.get_json()["inputs"] == {"r": 1, "s1": 2, "s2": 3, "z1": 4, "z2": 5}


def test_nonce_from_private_key_contract(client, fake_service):
    response = client.post(
        "/api/calculate/nonce-from-private-key",
        json={"r": "01", "s": "02", "z": "03", "x": "04"},
    )
    assert response.status_code == 200
    assert response.get_json()["success"] is True


def test_known_nonce_recovery_contract(client, fake_service):
    response = client.post(
        "/api/recover/low-s-with-nonce",
        json={"r": "01", "s": "02", "z": "03", "k": "04"},
    )
    assert response.status_code == 200
    assert response.get_json()["success"] is True


def test_method_not_allowed_for_post_only_endpoint(client):
    response = client.get("/api/analyze/transaction")
    assert response.status_code == 405
    assert response.get_json()["status"] == 405


def test_unknown_api_endpoint_is_json_404(client):
    response = client.get("/api/does-not-exist")
    assert response.status_code == 404
    assert response.is_json
    assert response.get_json()["status"] == 404


def test_known_addresses_endpoint(client, fake_service):
    response = client.get("/api/addresses/known")
    assert response.status_code == 200
    assert response.get_json() == ["known"]


def test_legacy_transaction_alias_uses_same_contract(client, fake_service):
    response = client.post("/api/analyze_transaction", json={"tx_id": "00" * 32})
    assert response.status_code == 200
    assert response.get_json()["success"] is True


def test_unexpected_service_error_becomes_500(client, monkeypatch):
    class BrokenService:
        def analyze_transaction(self, tx_id):
            raise RuntimeError("boom")

    monkeypatch.setattr(api_module, "_service", BrokenService())
    response = client.post("/api/analyze/transaction", json={"tx_id": "00" * 32})
    assert response.status_code == 500
    assert response.get_json() == {"error": "Internal server error", "status": 500}
