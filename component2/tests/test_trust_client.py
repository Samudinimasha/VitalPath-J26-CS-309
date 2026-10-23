"""
Unit tests for Component 2: SQLite Device Trust Ingestion (trust_client.py).
Verifies retrieval of trust verdicts, fallback behavior, schema compatibility,
and SPS Engine integration.
"""

import os
import sqlite3
import pytest
from trust_client import TrustVerdictClient, insert_trust_verdict, initialize_trust_verdicts_table
from sps_engine import SPSEngine
from classifiers import load_config


TEST_DB_PATH = "test_trust_fixture.db"


@pytest.fixture(autouse=True)
def setup_and_teardown_db():
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
    yield
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)


def test_retrieve_latest_verdict():
    """Verifies that the latest verdict is correctly retrieved from trust_verdicts table."""
    insert_trust_verdict(TEST_DB_PATH, "dev_01", 0.92, "FULL_TRUST", monitoring_flag=False)

    client = TrustVerdictClient(db_path=TEST_DB_PATH, fallback_dts=0.70)
    verdict = client.get_latest_verdict("dev_01")

    assert verdict.is_valid is True
    assert verdict.device_id == "dev_01"
    assert verdict.trust_score == pytest.approx(0.92, abs=1e-3)
    assert verdict.trust_level == "FULL_TRUST"
    assert verdict.monitoring_flag is False


def test_blocked_device_clamped_to_zero():
    """Blocked or rejected devices must yield 0.0 trust score (maximum risk)."""
    insert_trust_verdict(TEST_DB_PATH, "dev_blocked", 0.45, "BLOCKED", monitoring_flag=True)

    client = TrustVerdictClient(db_path=TEST_DB_PATH, fallback_dts=0.70)
    verdict = client.get_latest_verdict("dev_blocked")

    assert verdict.is_valid is True
    assert verdict.trust_score == 0.0
    assert verdict.trust_level == "BLOCKED"
    assert verdict.monitoring_flag is True


def test_fallback_when_device_not_in_db():
    """Unregistered or uncached devices must fall back to default DTS gracefully (NFR2)."""
    insert_trust_verdict(TEST_DB_PATH, "dev_known", 0.90, "FULL_TRUST")

    client = TrustVerdictClient(db_path=TEST_DB_PATH, fallback_dts=0.70)
    verdict = client.get_latest_verdict("dev_unknown_99")

    assert verdict.is_valid is False
    assert verdict.trust_score == 0.70
    assert verdict.trust_level == "FALLBACK"
    assert "NO_VERDICT_FOUND" in verdict.reason


def test_fallback_when_db_missing():
    """If the SQLite DB does not exist, client must not crash and return fallback DTS."""
    client = TrustVerdictClient(db_path="non_existent_path.db", fallback_dts=0.70)
    score = client.get_trust_score("dev_any")

    assert score == 0.70


def test_component1_trust_decisions_compatibility():
    """Verifies compatibility with Component 1's native 'trust_decisions' schema."""
    conn = sqlite3.connect(TEST_DB_PATH)
    conn.execute("""
        CREATE TABLE trust_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            device_id TEXT NOT NULL,
            tier TEXT NOT NULL,
            T REAL,
            C REAL, F REAL, H REAL, B REAL, R REAL,
            gate TEXT,
            reasons TEXT
        );
    """)
    conn.execute(
        "INSERT INTO trust_decisions (ts, device_id, tier, T, gate) VALUES (?, ?, ?, ?, ?)",
        ("2026-10-23T12:00:00", "c1_dev_ecg", "FULL_TRUST", 0.95, None),
    )
    conn.commit()
    conn.close()

    client = TrustVerdictClient(db_path=TEST_DB_PATH, fallback_dts=0.70)
    verdict = client.get_latest_verdict("c1_dev_ecg")

    assert verdict.is_valid is True
    assert verdict.trust_score == pytest.approx(0.95, abs=1e-3)
    assert verdict.trust_level == "FULL_TRUST"
    assert verdict.reason == "FROM_TRUST_DECISIONS"


def test_sps_engine_integration_with_sqlite_client():
    """Verifies that SPSEngine uses the SQLite client's verdict in its SPS calculation."""
    insert_trust_verdict(TEST_DB_PATH, "sensor_ecg", 0.95, "FULL_TRUST", monitoring_flag=False)
    insert_trust_verdict(TEST_DB_PATH, "sensor_rogue", 0.20, "BLOCKED", monitoring_flag=True)

    client = TrustVerdictClient(db_path=TEST_DB_PATH, fallback_dts=0.70)
    cfg = load_config("config.json")
    engine = SPSEngine(config=cfg, trust_client=client)

    vitals = {"hr": 75, "spo2": 98, "bp_sys": 120, "bp_dia": 80, "rr": 16}
    net = {"rtt_ms": 20.0, "packet_loss_pct": 0.1, "handover_active": False}

    # 1. Trusted device -> Standard profile
    res_trusted = engine.evaluate(vitals, net, "sensor_ecg")
    assert res_trusted["factors"]["dts"] == pytest.approx(0.95, abs=1e-3)
    assert res_trusted["profile"] == "Standard"
    assert "trust_verdict" in res_trusted
    assert res_trusted["trust_verdict"]["trust_level"] == "FULL_TRUST"

    # 2. Rogue/Blocked device -> DTS is 0.0 -> Elevated priority
    res_rogue = engine.evaluate(vitals, net, "sensor_rogue")
    assert res_rogue["factors"]["dts"] == 0.0
    assert res_rogue["sps"] > res_trusted["sps"]
    assert res_rogue["trust_verdict"]["trust_level"] == "BLOCKED"
