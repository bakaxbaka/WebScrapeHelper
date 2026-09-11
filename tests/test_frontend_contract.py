"""Static frontend integration/contract tests."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def test_frontend_controller_assets_exist():
    assert (ROOT / "static/js/api-client.js").is_file()
    assert (ROOT / "static/js/main-controller.js").is_file()
    assert (ROOT / "static/js/ecdsa_analyzer.js").is_file()


def test_base_template_loads_single_application_controller():
    base = read("base.html")
    assert "static/js/api-client.js" in base
    assert "static/js/main-controller.js" in base
    assert "static/js/main.js" not in base


def test_application_frontend_uses_central_api_client():
    controller = read("static/js/main-controller.js")
    analyzer = read("static/js/ecdsa_analyzer.js")
    client = read("static/js/api-client.js")

    assert "apiClient" in controller
    assert "apiClient" in analyzer
    assert "fetch(" in client
    assert "fetch(" not in controller
    assert "fetch(" not in analyzer


def test_api_client_exposes_expected_backend_operations():
    client = read("static/js/api-client.js")
    for operation in (
        "analyzeTransaction",
        "analyzeAddress",
        "analyzeECDSA",
        "calculateNonce",
        "calculateNonceFromPrivateKey",
        "recoverWithKnownNonce",
        "analyzeMalleability",
    ):
        assert operation in client
