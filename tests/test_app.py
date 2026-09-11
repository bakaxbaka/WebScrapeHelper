"""Application-factory, error-handler, and security-header tests."""


def test_security_headers_are_present(client):
    response = client.get("/api/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_static_resources_receive_cache_header(client):
    response = client.get("/static/js/api-client.js")
    assert response.status_code == 200
    assert "max-age=3600" in response.headers["Cache-Control"]


def test_html_404_is_not_json(client):
    response = client.get("/route-that-does-not-exist")
    assert response.status_code == 404
    assert response.is_json is False
    assert response.get_data(as_text=True) == "Not Found"


def test_api_404_is_json(client):
    response = client.get("/api/route-that-does-not-exist")
    assert response.status_code == 404
    assert response.get_json() == {"error": "Endpoint not found", "status": 404}


def test_api_405_is_json(client):
    response = client.get("/api/analyze/address")
    assert response.status_code == 405
    assert response.get_json() == {"error": "Method not allowed", "status": 405}


def test_html_routes_render(client):
    for path in ("/", "/transaction", "/address", "/ecdsa-analysis"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "text/html" in response.content_type


def test_app_uses_test_configuration(app):
    assert app.config["TESTING"] is True
    assert app.config["MAX_CONTENT_LENGTH"] > 0
    assert app.config["ANALYSIS_MAX_TXS"] > 0
