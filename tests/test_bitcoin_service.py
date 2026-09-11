"""Deterministic unit tests for the Bitcoin/ECDSA service layer."""

from ecdsa import curves

from webapp.services.bitcoin import BitcoinService


N = curves.SECP256k1.order
G = curves.SECP256k1.generator


def make_signature(private_key, nonce, z):
    r = (nonce * G).x() % N
    s = ((z + r * private_key) * pow(nonce, -1, N)) % N
    return r, s


def test_nonce_recovery_formula_round_trip():
    private_key = 0x123456789ABCDEF
    nonce = 0x23456789ABCDEF1
    z1 = 0x111111111111111111
    z2 = 0x222222222222222222
    r1, s1 = make_signature(private_key, nonce, z1)
    r2, s2 = make_signature(private_key, nonce, z2)

    service = BitcoinService()
    result = service.calculate_nonce(r1, s1, s2, z1, z2)

    assert result["success"] is True
    assert int(result["nonce"], 16) == nonce
    assert r1 == r2


def test_ecdsa_pair_recovery_round_trip():
    private_key = 0x3456789ABCDEF123
    nonce = 0x456789ABCDEF1234
    z1 = 0x1010101010101010
    z2 = 0x2020202020202020
    r1, s1 = make_signature(private_key, nonce, z1)
    r2, s2 = make_signature(private_key, nonce, z2)

    service = BitcoinService()
    result = service.analyze_ecdsa_pair(r1, s1, z1, r2, s2, z2)

    assert result["success"] is True
    assert int(result["k"], 16) == nonce
    assert int(result["x"], 16) == private_key


def test_nonce_from_known_private_key_round_trip():
    private_key = 0x5566778899AABBCC
    nonce = 0x1122334455667788
    z = 0x9999999999999999
    r, s = make_signature(private_key, nonce, z)

    service = BitcoinService()
    result = service.calculate_nonce_from_private_key(r, s, z, private_key)

    assert result["success"] is True
    assert int(result["nonce"], 16) == nonce


def test_private_key_recovery_from_known_nonce_round_trip():
    private_key = 0x123456789ABC1234
    nonce = 0xABCD123456789
    z = 0x13579BDF
    r, s = make_signature(private_key, nonce, z)

    service = BitcoinService()
    result = service.recover_with_known_nonce(r, s, z, nonce)

    assert result["success"] is True
    assert int(result["private_key"], 16) == private_key


def test_nonce_recovery_rejects_identical_s_values():
    service = BitcoinService()
    try:
        service.calculate_nonce(1, 2, 2, 3, 4)
    except ValueError as exc:
        assert "identical" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_pair_recovery_rejects_different_r_values():
    service = BitcoinService()
    try:
        service.analyze_ecdsa_pair(1, 2, 3, 4, 5, 6)
    except ValueError as exc:
        assert "R values must match" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_known_nonce_recovery_rejects_zero_nonce():
    service = BitcoinService()
    try:
        service.recover_with_known_nonce(1, 2, 3, 0)
    except ValueError as exc:
        assert "scalar range" in str(exc)
    else:
        raise AssertionError("Expected ValueError")
