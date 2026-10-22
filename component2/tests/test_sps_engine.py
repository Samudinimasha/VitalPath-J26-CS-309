"""
Unit tests for Component 2: Adaptive Security Decision Engine (SPS Engine).
Validates mathematical correctness, threshold mapping, constraints, and latency targets.
"""

import pytest
import time
from sps_engine import calculate_sps, map_profile, evaluate_security_decision, SPSEngine
from classifiers import load_config


@pytest.fixture
def config():
    return load_config("config.json")


def test_calculate_sps_weights(config):
    """Verifies that weights from config are correctly utilized."""
    # DTS=1.0 (0 risk), CC=0.2, NC=0.0
    # Expected: 0.35 * (1 - 1.0) + 0.45 * 0.2 + 0.20 * 0.0 = 0.09
    score = calculate_sps(dts=1.0, cc=0.2, nc=0.0, config=config)
    assert score == pytest.approx(0.09, abs=1e-4)

    # Worst case: DTS=0.0 (max risk), CC=1.0, NC=1.0
    # Expected: 0.35 * 1.0 + 0.45 * 1.0 + 0.20 * 1.0 = 1.0
    score_worst = calculate_sps(dts=0.0, cc=1.0, nc=1.0, config=config)
    assert score_worst == pytest.approx(1.0, abs=1e-4)


def test_sps_clamping_and_bounds():
    """Ensures SPS calculation safely clamps out-of-bounds inputs and outputs to [0.0, 1.0]."""
    # Negative inputs
    score_low = calculate_sps(dts=-0.5, cc=-1.0, nc=-0.2)
    assert 0.0 <= score_low <= 1.0

    # Over 1.0 inputs
    score_high = calculate_sps(dts=1.5, cc=2.0, nc=1.5)
    assert 0.0 <= score_high <= 1.0


def test_profile_mapping_boundaries(config):
    """Verifies strict boundary adherence against Standard, Enhanced, and Maximum thresholds."""
    std_max = config["profile_thresholds"]["standard_max"]  # 0.40
    enh_max = config["profile_thresholds"]["enhanced_max"]  # 0.75

    # Boundary tests for Standard
    assert map_profile(0.0, config) == "Standard"
    assert map_profile(std_max - 0.01, config) == "Standard"
    assert map_profile(std_max, config) == "Standard"

    # Boundary tests for Enhanced
    assert map_profile(std_max + 0.0001, config) == "Enhanced"
    assert map_profile(0.60, config) == "Enhanced"
    assert map_profile(enh_max, config) == "Enhanced"

    # Boundary tests for Maximum
    assert map_profile(enh_max + 0.0001, config) == "Maximum"
    assert map_profile(1.0, config) == "Maximum"


def test_threat_level_exclusion():
    """
    Architectural requirement test:
    Verifies that SPS engine strictly accepts exactly three inputs (DTS, CC, NC)
    and does not accept or depend on threat level.
    """
    import inspect
    sig = inspect.signature(calculate_sps)
    params = list(sig.parameters.keys())
    assert "threat_level" not in params
    assert params[:3] == ["dts", "cc", "nc"]


def test_sps_engine_class_integration(config):
    """Tests the object-oriented SPSEngine wrapper with caching and fallback."""
    engine = SPSEngine(config=config)
    engine.update_trust("dev_ecg", 0.90)

    # 1. Normal packet from trusted device
    vitals_normal = {"hr": 75, "spo2": 99, "bp_sys": 115, "bp_dia": 75, "rr": 16}
    net_good = {"rtt_ms": 20.0, "packet_loss_pct": 0.1, "handover_active": False}
    decision = engine.evaluate(vitals_normal, net_good, "dev_ecg")

    assert decision["profile"] == "Standard"
    assert decision["key_rotation_seconds"] == 300
    assert decision["factors"]["dts"] == 0.90
    assert decision["factors"]["cc"] == 0.2

    # 2. Critical packet from untrusted device
    engine.update_trust("dev_compromised", 0.10)
    vitals_critical = {"hr": 140, "spo2": 85, "bp_sys": 160, "bp_dia": 100, "rr": 26}
    net_poor = {"rtt_ms": 120.0, "packet_loss_pct": 5.5, "handover_active": True}
    decision_crit = engine.evaluate(vitals_critical, net_poor, "dev_compromised")

    assert decision_crit["profile"] == "Maximum"
    assert decision_crit["key_rotation_seconds"] == 10
    assert decision_crit["sps"] > 0.75


def test_decision_latency_target_nfr1(config):
    """
    Validates NFR1: Decision latency must be strictly under 5.0 ms.
    Targeting 1,000 iterations to verify stability.
    """
    engine = SPSEngine(config=config)
    vitals = {"hr": 80, "spo2": 97, "bp_sys": 120, "bp_dia": 80, "rr": 16}
    net = {"rtt_ms": 25.0, "packet_loss_pct": 0.5, "handover_active": False}

    latencies = []
    for _ in range(1000):
        t0 = time.perf_counter()
        engine.evaluate(vitals, net, "device_test")
        latencies.append((time.perf_counter() - t0) * 1000.0)

    avg_latency = sum(latencies) / len(latencies)
    max_latency = max(latencies)

    # Must be well below 5 ms (in fact Python should do this in < 0.1 ms)
    assert avg_latency < 5.0, f"Average latency exceeded 5 ms: {avg_latency:.4f} ms"
    assert max_latency < 20.0, f"Max spike exceeded per-packet budget: {max_latency:.4f} ms"

