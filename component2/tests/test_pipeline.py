"""
Unit tests for Component 2: End-to-End Orchestrator Pipeline (pipeline.py).
Tests end-to-end packet processing, latency constraints (NFR1 < 20 ms),
and non-blocking asynchronous metadata export (FR8).
"""

import pytest
import time
from pipeline import VitalPathPipeline, MetadataLogger
from classifiers import load_config


@pytest.fixture
def pipeline():
    cfg = load_config("config.json")
    pipe = VitalPathPipeline(config=cfg, enable_async_logging=True)
    yield pipe
    pipe.shutdown()


def test_end_to_end_packet_processing(pipeline):
    """Verifies that a packet undergoes decision, encryption, and produces secured output."""
    pipeline.update_device_trust("ecg_sensor_01", 0.95)

    packet = {
        "packet_id": "test_pkt_100",
        "device_id": "ecg_sensor_01",
        "patient_id": "PAT_001",
        "vitals": {"hr": 76, "spo2": 99, "bp_sys": 118, "bp_dia": 78, "rr": 16},
    }
    net = {"rtt_ms": 20.0, "packet_loss_pct": 0.2, "handover_active": False}

    secured = pipeline.process_packet(packet, net)

    assert secured["packet_id"] == "test_pkt_100"
    assert secured["profile"] == "Standard"
    assert secured["decision_latency_ms"] < 5.0
    assert secured["total_latency_ms"] < 20.0
    assert "ciphertext" in secured
    assert "nonce" in secured
    assert "sha256_digest" in secured


def test_asynchronous_metadata_logging(pipeline):
    """Verifies that audit metadata is queued and logged asynchronously (FR8)."""
    packet = {
        "packet_id": "test_pkt_audit",
        "device_id": "sensor_audit",
        "patient_id": "PAT_AUDIT",
        "vitals": {"hr": 80, "spo2": 98, "bp_sys": 120, "bp_dia": 80, "rr": 16},
    }
    net = {"rtt_ms": 25.0, "packet_loss_pct": 0.5, "handover_active": False}

    pipeline.process_packet(packet, net)
    time.sleep(0.1)  # Allow background worker to dequeue

    trail = pipeline.logger.get_audit_trail()
    assert len(trail) >= 1
    record = trail[-1]
    assert record["packet_id"] == "test_pkt_audit"
    assert "sps" in record
    assert "profile" in record
    assert "total_latency_ms" in record


def test_pipeline_latency_budget_nfr1(pipeline):
    """Evaluates NFR1: Total per-packet delay must remain below 20 ms across repeated runs."""
    pipeline.update_device_trust("sensor_perf", 0.85)

    packet = {
        "patient_id": "PAT_BENCH",
        "device_id": "sensor_perf",
        "vitals": {"hr": 110, "spo2": 94, "bp_sys": 130, "bp_dia": 85, "rr": 20},
    }
    net = {"rtt_ms": 40.0, "packet_loss_pct": 1.5, "handover_active": False}

    # Run 100 packets through the pipeline
    for _ in range(100):
        res = pipeline.process_packet(packet, net)
        assert res["total_latency_ms"] < 20.0, f"Exceeded 20 ms: {res['total_latency_ms']} ms"

    metrics = pipeline.get_metrics()
    assert metrics["total_packets_processed"] >= 100
    assert metrics["average_total_latency_ms"] < 10.0
    assert metrics["nfr1_compliant"] is True

