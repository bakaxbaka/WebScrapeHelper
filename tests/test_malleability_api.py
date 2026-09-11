"""Tests for the corrected ECDSA signature-malleability endpoint."""

from webapp.services.bitcoin import BitcoinService


N = BitcoinService().analyzer.curve.order


def test_malleability_detects_s_and_n_minus_s(client):
    s = 123456789
    complement = N - s
    response = client.post(
        "/api/recover/malleability-signatures",
        json={"r": "01", "z": "02", "s_values": [format(s, "x"), format(complement, "x")]},
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["malleable"] is True
    assert data["private_key_recovered"] is False
    assert len(data["malleable_pairs"]) == 1


def test_malleability_does_not_flag_unrelated_s_values(client):
    response = client.post(
        "/api/recover/malleability-signatures",
        json={"r": "01", "z": "02", "s_values": ["03", "04"]},
    )
    assert response.status_code == 200
    assert response.get_json()["malleable"] is False


def test_malleability_requires_two_s_values(client):
    response = client.post(
        "/api/recover/malleability-signatures",
        json={"r": "01", "z": "02", "s_values": ["03"]},
    )
    assert response.status_code == 400


def test_malleability_rejects_out_of_range_r(client):
    response = client.post(
        "/api/recover/malleability-signatures",
        json={"r": format(N, "x"), "z": "02", "s_values": ["03", "04"]},
    )
    assert response.status_code == 400
