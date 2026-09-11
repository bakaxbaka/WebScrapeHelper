"""Unit tests for external-network service behavior using mocked HTTP responses."""

import requests

import webapp.routes.api as api_module
from webapp.services.bitcoin import BitcoinService


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def test_scan_recent_block_uses_latest_hash_and_limit(monkeypatch):
    calls = []

    def fake_get(url, timeout):
        calls.append((url, timeout))
        if url.endswith("latestblock"):
            return FakeResponse({"hash": "block-hash"})
        return FakeResponse({"tx": [{"hash": "tx1"}, {"hash": "tx2"}, {"hash": "tx3"}]})

    service = BitcoinService()
    monkeypatch.setattr("webapp.services.bitcoin.requests.get", fake_get)
    monkeypatch.setattr(service, "analyze_transaction", lambda tx_id: {"private_keys_found": 0})

    result = service.scan_recent_block(limit=2)

    assert result["success"] is True
    assert result["scanned_transactions"] == 2
    assert result["block_hash"] == "block-hash"
    assert calls == [
        ("https://blockchain.info/latestblock", 10),
        ("https://blockchain.info/rawblock/block-hash", 10),
    ]


def test_monitor_mempool_uses_limit(monkeypatch):
    def fake_get(url, timeout):
        assert url == "https://blockchain.info/unconfirmed-transactions?format=json"
        assert timeout == 10
        return FakeResponse({"txs": [{"hash": "tx1"}, {"hash": "tx2"}]})

    service = BitcoinService()
    monkeypatch.setattr("webapp.services.bitcoin.requests.get", fake_get)
    monkeypatch.setattr(service, "analyze_transaction", lambda tx_id: {"private_keys_found": 0})

    result = service.monitor_mempool(limit=1)

    assert result["success"] is True
    assert result["mempool_scanned"] == 1
    assert result["vulnerable_transactions"] == 0


def test_network_error_is_mapped_to_502(client, monkeypatch):
    class BrokenService:
        def analyze_transaction(self, tx_id):
            raise requests.RequestException("upstream down")

    monkeypatch.setattr(api_module, "_service", BrokenService())
    response = client.post("/api/analyze/transaction", json={"tx_id": "00" * 32})

    assert response.status_code == 502
    assert response.get_json() == {"error": "Upstream Bitcoin service unavailable", "status": 502}
