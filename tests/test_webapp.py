"""Smoke tests for the structured Flask application."""

from webapp import create_app


def test_health_endpoint():
    app = create_app()
    client = app.test_client()
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_expected_routes_are_registered():
    app = create_app()
    routes = {rule.rule for rule in app.url_map.iter_rules()}
    assert "/" in routes
    assert "/transaction" in routes
    assert "/address" in routes
    assert "/ecdsa-analysis" in routes
    assert "/api/analyze/transaction" in routes
    assert "/api/analyze/address" in routes
    assert "/api/analyze/ecdsa" in routes
    assert "/api/calculate/nonce" in routes
    assert "/api/health" in routes
