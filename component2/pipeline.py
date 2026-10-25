"""
VitalPath: 5G Security Middleware for Connected Ambulance Telemetry
Component 2: End-to-End Pipeline & Orchestrator (pipeline.py)

This module integrates:
  1. Classifiers (CC, NC, DTS)
  2. SPS Engine (Deterministic priority scoring & profile selection)
  3. Crypto Engine (DTLS 1.3/AES-256-GCM, SHA-256, ECDSA P-256, Session Key Rotation)
  4. Asynchronous Logging Interface (FR8 export to Component 4 audit trail)

Latency Budgets (NFR1):
  - Decision Latency: < 5 ms
  - End-to-End Per-Packet Latency: < 20 ms
"""

import time
import queue
import threading
from typing import Dict, Any, Optional, List, Tuple

from classifiers import load_config
from sps_engine import SPSEngine
from crypto_engine import CryptoEngine
from trust_client import TrustVerdictClient, TrustVerdict


class MetadataLogger:
    """
    Asynchronous, non-blocking metadata logger fulfilling FR8:
    Exports transmission audit metadata (packet ID, SPS, profile, latency, timestamp)
    to Component 4 without stalling the real-time telemetry forwarding pipeline.
    """

    def __init__(self, maxsize: int = 10000):
        self._queue: queue.Queue = queue.Queue(maxsize=maxsize)
        self._audit_log: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._running = True
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            daemon=True,
            name="VitalPath-AuditLogger"
        )
        self._worker_thread.start()

    def log_metadata(self, metadata: Dict[str, Any]) -> None:
        """Non-blocking submission of metadata to the asynchronous logging queue."""
        try:
            self._queue.put_nowait(metadata)
        except queue.Full:
            # Drop or handle queue overflow gracefully without blocking edge telemetry
            pass

    def _worker_loop(self) -> None:
        """Background thread consuming metadata from queue."""
        while self._running:
            try:
                record = self._queue.get(timeout=0.05)
                with self._lock:
                    self._audit_log.append(record)
                self._queue.task_done()
            except queue.Empty:
                continue

    def get_audit_trail(self) -> List[Dict[str, Any]]:
        """Returns a snapshot of logged records."""
        with self._lock:
            return list(self._audit_log)

    def close(self, drain_timeout: float = 1.0) -> None:
        """Stops the worker thread after draining remaining queue entries."""
        try:
            self._queue.join()
        except Exception:
            pass
        self._running = False
        self._worker_thread.join(timeout=drain_timeout)


class VitalPathPipeline:
    """
    Main orchestrator for Component 2 (Adaptive Security Decision Engine).
    Processes incoming ambulance telemetry packets, computes SPS, applies
    optimal cryptography, and logs metadata asynchronously.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        config_path: str = "config.json",
        enable_async_logging: bool = True,
        trust_client: Optional[TrustVerdictClient] = None,
    ):
        if config is not None:
            self.config = config
        else:
            self.config = load_config(config_path)

        self.sps_engine = SPSEngine(config=self.config, trust_client=trust_client)
        self.crypto_engine = CryptoEngine(config=self.config)
        self.logger = MetadataLogger() if enable_async_logging else None

        # Cumulative performance counters
        self._total_packets_processed = 0
        self._profile_counts = {"Standard": 0, "Enhanced": 0, "Maximum": 0}
        self._total_latency_ms = 0.0
        self._max_latency_ms = 0.0

    def update_device_trust(self, device_id: str, trust_score: float) -> None:
        """Updates Component 1 cached trust score for a device."""
        self.sps_engine.update_trust(device_id, trust_score)

    def process_packet(
        self,
        packet: Dict[str, Any],
        network_metrics: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Executes end-to-end adaptive security pipeline on a telemetry packet:
          1. Evaluates decision (CC, NC, DTS -> SPS -> Profile) [< 5 ms]
          2. Encapsulates and encrypts telemetry packet [< 15 ms]
          3. Emits audit metadata asynchronously to Component 4
          4. Verifies total processing delay remains under 20 ms (NFR1)

        Parameters:
            packet (dict): Telemetry packet structure, containing at minimum:
                           {
                               "packet_id": str (optional),
                               "device_id": str,
                               "patient_id": str,
                               "vitals": dict
                           }
            network_metrics (dict): 5G channel indicators:
                           {
                               "rtt_ms": float,
                               "packet_loss_pct": float,
                               "handover_active": bool
                           }

        Returns:
            dict: Secure encapsulated packet ready for 5G transmission buffer.
        """
        t_pipeline_start = time.perf_counter()

        packet_id = packet.get("packet_id")
        device_id = packet.get("device_id", "default_sensor")
        vitals = packet.get("vitals", {})
        handover = network_metrics.get("handover_active", False)

        # Stage 1: Adaptive Decision Evaluation
        decision = self.sps_engine.evaluate(
            vitals=vitals,
            network_metrics=network_metrics,
            device_id=device_id,
        )
        profile = decision["profile"]

        # Stage 2: Cryptographic Encapsulation
        sec_packet = self.crypto_engine.secure_packet(
            payload=packet,
            profile=profile,
            packet_id=packet_id,
            handover_event=handover,
        )

        total_latency_ms = (time.perf_counter() - t_pipeline_start) * 1000.0

        # Stage 3: Asynchronous Metadata Logging (FR8)
        audit_record = {
            "packet_id": sec_packet["packet_id"],
            "device_id": device_id,
            "patient_id": packet.get("patient_id", "unknown"),
            "sps": decision["sps"],
            "profile": profile,
            "factors": decision["factors"],
            "decision_latency_ms": decision["decision_latency_ms"],
            "crypto_latency_ms": sec_packet["crypto_latency_ms"],
            "total_latency_ms": round(total_latency_ms, 4),
            "key_id": sec_packet["key_id"],
            "key_rotated": sec_packet["key_rotated"],
            "timestamp": time.time(),
        }

        if self.logger:
            self.logger.log_metadata(audit_record)

        # Update metrics
        self._total_packets_processed += 1
        self._profile_counts[profile] = self._profile_counts.get(profile, 0) + 1
        self._total_latency_ms += total_latency_ms
        if total_latency_ms > self._max_latency_ms:
            self._max_latency_ms = total_latency_ms

        # Attach telemetry middleware transmission headers
        sec_packet["sps"] = decision["sps"]
        sec_packet["factors"] = decision["factors"]
        sec_packet["key_rotation_seconds"] = decision.get("key_rotation_seconds", 60)
        if "trust_verdict" in decision:
            sec_packet["trust_verdict"] = decision["trust_verdict"]
        sec_packet["decision_latency_ms"] = decision["decision_latency_ms"]
        sec_packet["total_latency_ms"] = round(total_latency_ms, 4)

        return sec_packet

    def get_metrics(self) -> Dict[str, Any]:
        """Returns cumulative pipeline performance and adaptation metrics."""
        count = self._total_packets_processed
        avg_lat = (self._total_latency_ms / count) if count > 0 else 0.0
        return {
            "total_packets_processed": count,
            "profile_distribution": dict(self._profile_counts),
            "average_total_latency_ms": round(avg_lat, 4),
            "max_total_latency_ms": round(self._max_latency_ms, 4),
            "nfr1_compliant": self._max_latency_ms < 20.0,
        }

    def shutdown(self) -> None:
        """Gracefully shuts down pipeline logging threads."""
        if self.logger:
            self.logger.close()


if __name__ == "__main__":
    cfg = load_config("config.json")
    pipeline = VitalPathPipeline(config=cfg)

    # Set up device trust cache from Component 1
    pipeline.update_device_trust("ecg_lead_II", 0.95)
    pipeline.update_device_trust("pulse_ox_01", 0.70)
    pipeline.update_device_trust("bp_cuff_unverified", 0.30)

    sample_stream = [
        (
            {
                "packet_id": "pkt_001",
                "patient_id": "PAT_801",
                "device_id": "ecg_lead_II",
                "vitals": {"hr": 74, "spo2": 98, "bp_sys": 118, "bp_dia": 78, "rr": 16},
            },
            {"rtt_ms": 19.5, "packet_loss_pct": 0.1, "handover_active": False},
        ),
        (
            {
                "packet_id": "pkt_002",
                "patient_id": "PAT_801",
                "device_id": "pulse_ox_01",
                "vitals": {"hr": 108, "spo2": 92, "bp_sys": 132, "bp_dia": 85, "rr": 20},
            },
            {"rtt_ms": 42.0, "packet_loss_pct": 1.2, "handover_active": False},
        ),
        (
            {
                "packet_id": "pkt_003",
                "patient_id": "PAT_801",
                "device_id": "bp_cuff_unverified",
                "vitals": {"hr": 150, "spo2": 85, "bp_sys": 165, "bp_dia": 110, "rr": 26},
            },
            {"rtt_ms": 95.0, "packet_loss_pct": 4.5, "handover_active": True},
        ),
    ]

    print("=" * 80)
    print("VitalPath Component 2: End-to-End Orchestrator Pipeline Execution")
    print("=" * 80)

    for pkt, net in sample_stream:
        secured = pipeline.process_packet(pkt, net)
        print(f"\nPacket [{secured['packet_id']}] -> Device: {pkt['device_id']}")
        print(f"  Profile Selected : [{secured['profile']}] (SPS: {secured['sps']:.4f})")
        print(f"  Key ID           : {secured['key_id']} (Rotated: {secured['key_rotated']})")
        print(f"  Decision Latency : {secured['decision_latency_ms']:.4f} ms")
        print(f"  Crypto Latency   : {secured['crypto_latency_ms']:.4f} ms")
        print(f"  Total Delay      : {secured['total_latency_ms']:.4f} ms (Budget: < 20 ms)")

    # Sleep slightly to let async logger process
    time.sleep(0.1)

    print("\n" + "=" * 80)
    print("Cumulative Metrics:")
    metrics = pipeline.get_metrics()
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    print("\nLogged Audit Records in Component 4 Queue:")
    audit_trail = pipeline.logger.get_audit_trail() if pipeline.logger else []
    for entry in audit_trail:
        print(f"  Audit ID: {entry['packet_id']} | Profile: {entry['profile']} | SPS: {entry['sps']:.4f} | Total Latency: {entry['total_latency_ms']} ms")

    pipeline.shutdown()
    print("=" * 80)

