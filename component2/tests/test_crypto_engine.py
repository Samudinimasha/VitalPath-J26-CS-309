"""
Unit tests for Component 2: Cryptographic Execution Module (Crypto Engine).
Verifies AES-256-GCM encryption, ECDSA P-256 signatures, SHA-256 integrity,
tamper detection, and adaptive session key rotation.
"""

import pytest
import time
from crypto_engine import CryptoEngine, KeyManager
from classifiers import load_config


@pytest.fixture
def crypto():
    cfg = load_config("config.json")
    return CryptoEngine(config=cfg)


def test_standard_profile_omits_signature(crypto):
    """Standard profile must NOT attach per-packet ECDSA signatures to conserve CPU."""
    payload = {"patient_id": "P01", "vitals": {"hr": 72}}
    secured = crypto.secure_packet(payload, profile="Standard")

    assert secured["profile"] == "Standard"
    assert secured["ecdsa_signature"] is None
    assert len(secured["ciphertext"]) > 0
    assert len(secured["sha256_digest"]) == 64


def test_enhanced_and_maximum_attach_signatures(crypto):
    """Enhanced and Maximum profiles must enforce ECDSA digital signatures."""
    payload = {"patient_id": "P02", "vitals": {"hr": 120}}

    sec_enh = crypto.secure_packet(payload, profile="Enhanced")
    assert sec_enh["ecdsa_signature"] is not None

    sec_max = crypto.secure_packet(payload, profile="Maximum")
    assert sec_max["ecdsa_signature"] is not None


def test_decrypt_and_verify_success(crypto):
    """Verifies end-to-end round-trip encryption and receiver verification."""
    payload = {"patient_id": "P03", "vitals": {"hr": 90, "spo2": 95}}

    for prof in ["Standard", "Enhanced", "Maximum"]:
        sec = crypto.secure_packet(payload, profile=prof)
        ok, dec_payload, msg = crypto.verify_and_decrypt(sec)
        assert ok is True
        assert dec_payload == payload
        assert "successful" in msg


def test_tamper_detection_ciphertext(crypto):
    """Tampering with ciphertext must cause GCM authentication failure."""
    payload = {"patient_id": "P04", "vitals": {"hr": 80}}
    sec = crypto.secure_packet(payload, profile="Enhanced")

    # Flip one character in ciphertext hex
    tampered_ct = list(sec["ciphertext"])
    tampered_ct[0] = "0" if tampered_ct[0] != "0" else "1"
    sec["ciphertext"] = "".join(tampered_ct)

    ok, dec_payload, msg = crypto.verify_and_decrypt(sec)
    assert ok is False
    assert dec_payload is None
    assert "Decryption error" in msg


def test_tamper_detection_signature(crypto):
    """Tampering with ECDSA signature in Enhanced/Maximum profile must be caught."""
    payload = {"patient_id": "P05", "vitals": {"hr": 85}}
    sec = crypto.secure_packet(payload, profile="Enhanced")

    # Corrupt signature
    sig = list(sec["ecdsa_signature"])
    sig[2] = "f" if sig[2] != "f" else "0"
    sec["ecdsa_signature"] = "".join(sig)

    ok, _, msg = crypto.verify_and_decrypt(sec)
    assert ok is False
    assert "signature" in msg.lower()


def test_key_rotation_intervals():
    """Validates scheduled and event-driven key rotation."""
    intervals = {"Standard": 300, "Enhanced": 60, "Maximum": 10}
    km = KeyManager(rotation_intervals=intervals)
    initial_key_id = km.current_key_id

    # 1. No rotation if within window
    rotated = km.check_and_rotate("Standard", handover_event=False, now=km.last_rotation_time + 50)
    assert rotated is False
    assert km.current_key_id == initial_key_id

    # 2. Exceeded Standard interval (300s) -> Rotates
    rotated = km.check_and_rotate("Standard", handover_event=False, now=km.last_rotation_time + 301)
    assert rotated is True
    assert km.current_key_id != initial_key_id

    # 3. Maximum profile handover event trigger -> Immediate rotation
    k2 = km.current_key_id
    rotated_handover = km.check_and_rotate("Maximum", handover_event=True, now=km.last_rotation_time + 1)
    assert rotated_handover is True
    assert km.current_key_id != k2


def test_crypto_latency_budget(crypto):
    """Encryption and signing latency must stay well within the < 15 ms target."""
    payload = {"patient_id": "P06", "vitals": {"hr": 95, "spo2": 93, "bp_sys": 130}}
    times = []

    for _ in range(200):
        t0 = time.perf_counter()
        crypto.secure_packet(payload, profile="Maximum")
        times.append((time.perf_counter() - t0) * 1000.0)

    avg_time = sum(times) / len(times)
    assert avg_time < 5.0, f"Crypto average latency too high: {avg_time:.4f} ms"

