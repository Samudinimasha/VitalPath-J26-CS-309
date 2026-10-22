"""
VitalPath: 5G Security Middleware for Connected Ambulance Telemetry
Component 2: Adaptive Security Decision Engine (SPS Engine)

This module calculates the deterministic Security Priority Score (SPS) and maps
it to one of three cryptographic profiles (Standard, Enhanced, Maximum).

Inputs for SPS (strictly limited to three):
  1. Device Trust Score (DTS): Normalized trust from Component 1 [0.0 - 1.0].
     Lower trust represents higher device risk (1 - DTS).
  2. Clinical Criticality (CC): Medical urgency based on AHA/WHO/ESC guidelines [0.2, 0.6, 1.0].
  3. Network Conditions (NC): Normalized 5G channel latency, loss, and handover [0.0 - 1.0].

Note: External network threat level is strictly excluded from SPS calculation
to preserve deterministic, explainable, and ultra-low latency (< 5 ms) operation.
"""

import time
import json
from typing import Dict, Any, Optional, Tuple

from classifiers import (
    load_config,
    get_clinical_criticality,
    get_network_condition,
    get_device_trust,
)


def calculate_sps(
    dts: float,
    cc: float,
    nc: float,
    config: Optional[Dict[str, Any]] = None,
) -> float:
    """
    Calculates the deterministic Security Priority Score (SPS).

    Formula:
        SPS = (w_dts * (1.0 - DTS)) + (w_cc * CC) + (w_nc * NC)

    Parameters:
        dts (float): Device Trust Score in [0.0, 1.0] (Component 1)
        cc (float): Clinical Criticality score in [0.0, 1.0] (AHA/WHO/ESC)
        nc (float): Network Condition degradation score in [0.0, 1.0] (5G metrics)
        config (dict, optional): Configuration dictionary containing 'sps_weights'.
                                 If omitted, standard defaults are used.

    Returns:
        float: Normalized SPS value clamped between 0.0 and 1.0 (rounded to 4 decimal places).
    """
    if config and "sps_weights" in config:
        weights = config["sps_weights"]
        w_dts = weights.get("w_dts", 0.35)
        w_cc = weights.get("w_cc", 0.45)
        w_nc = weights.get("w_nc", 0.20)
    else:
        w_dts, w_cc, w_nc = 0.35, 0.45, 0.20

    # Ensure inputs are clamped to valid normalized bounds [0.0, 1.0]
    safe_dts = min(1.0, max(0.0, float(dts)))
    safe_cc = min(1.0, max(0.0, float(cc)))
    safe_nc = min(1.0, max(0.0, float(nc)))

    # Invert DTS: Lower device trust represents higher security risk
    device_risk = 1.0 - safe_dts

    # Linear deterministic weighted sum
    sps = (w_dts * device_risk) + (w_cc * safe_cc) + (w_nc * safe_nc)

    # Clamp result between 0.0 and 1.0
    sps_clamped = min(1.0, max(0.0, sps))

    return round(sps_clamped, 4)


def map_profile(
    sps: float,
    config: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Maps a Security Priority Score (SPS) to a cryptographic profile:
      - 'Standard': SPS <= standard_max (default <= 0.40)
      - 'Enhanced': standard_max < SPS <= enhanced_max (default 0.40 < SPS <= 0.75)
      - 'Maximum' : SPS > enhanced_max (default > 0.75)

    Parameters:
        sps (float): Calculated Security Priority Score in [0.0, 1.0].
        config (dict, optional): Configuration dictionary containing 'profile_thresholds'.

    Returns:
        str: 'Standard', 'Enhanced', or 'Maximum'
    """
    if config and "profile_thresholds" in config:
        thresholds = config["profile_thresholds"]
        standard_max = thresholds.get("standard_max", 0.40)
        enhanced_max = thresholds.get("enhanced_max", 0.75)
    else:
        standard_max, enhanced_max = 0.40, 0.75

    if sps <= standard_max:
        return "Standard"
    elif sps <= enhanced_max:
        return "Enhanced"
    else:
        return "Maximum"


def evaluate_security_decision(
    vitals: Dict[str, Any],
    network_metrics: Dict[str, Any],
    device_id: str,
    trust_cache: Dict[str, float],
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    End-to-end evaluation for an incoming telemetry packet:
      1. Evaluates Clinical Criticality (CC) from vital signs.
      2. Evaluates Network Condition (NC) from 5G channel metrics.
      3. Retrieves Device Trust Score (DTS) from Component 1 cache.
      4. Calculates the deterministic SPS.
      5. Maps SPS to the appropriate cryptographic profile.
      6. Records decision latency (target < 5 ms).

    Parameters:
        vitals (dict): Dictionary of vital sign readings (hr, spo2, bp_sys, bp_dia, rr).
        network_metrics (dict): 5G network metrics (rtt_ms, packet_loss_pct, handover_active).
        device_id (str): Unique identifier of the sensor device.
        trust_cache (dict): In-memory cache mapping device IDs to Component 1 trust scores.
        config (dict, optional): Loaded configuration dictionary.

    Returns:
        dict: Full decision metadata including SPS, profile, factors, key rotation, and latency.
    """
    start_time = time.perf_counter()

    if config is None:
        config = load_config()

    # Step 1: Extract the three input factors
    cc = get_clinical_criticality(vitals, config)
    nc = get_network_condition(network_metrics, config)
    dts = get_device_trust(device_id, trust_cache, config)

    # Step 2: Compute deterministic SPS
    sps = calculate_sps(dts=dts, cc=cc, nc=nc, config=config)

    # Step 3: Map SPS to cryptographic profile
    profile = map_profile(sps=sps, config=config)

    # Step 4: Resolve session key rotation duration
    rotation_intervals = config.get("key_rotation_seconds", {
        "Standard": 300,
        "Enhanced": 60,
        "Maximum": 10
    })
    key_rotation_sec = rotation_intervals.get(profile, 60)

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    return {
        "sps": sps,
        "profile": profile,
        "factors": {
            "dts": dts,
            "cc": cc,
            "nc": nc,
        },
        "key_rotation_seconds": key_rotation_sec,
        "decision_latency_ms": round(elapsed_ms, 4),
        "timestamp": time.time(),
    }


class SPSEngine:
    """
    Object-oriented wrapper for the Adaptive Security Decision Engine (Component 2).
    Maintains cached configuration and local device trust state for fast edge processing.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        config_path: str = "config.json",
        trust_cache: Optional[Dict[str, float]] = None,
    ):
        """
        Initializes the SPS Engine.

        Parameters:
            config (dict, optional): Pre-loaded configuration dictionary.
            config_path (str): Filepath to load config if not directly supplied.
            trust_cache (dict, optional): Reference to the in-memory Component 1 trust cache.
        """
        if config is not None:
            self.config = config
        else:
            self.config = load_config(config_path)

        self.trust_cache = trust_cache if trust_cache is not None else {}

    def update_trust(self, device_id: str, trust_score: float) -> None:
        """Asynchronously updates the trust score cache for a device (from Component 1)."""
        self.trust_cache[device_id] = min(1.0, max(0.0, float(trust_score)))

    def calculate_sps(self, dts: float, cc: float, nc: float) -> float:
        """Calculates deterministic SPS using loaded configuration."""
        return calculate_sps(dts=dts, cc=cc, nc=nc, config=self.config)

    def map_profile(self, sps: float) -> str:
        """Maps an SPS value to Standard, Enhanced, or Maximum."""
        return map_profile(sps=sps, config=self.config)

    def evaluate(
        self,
        vitals: Dict[str, Any],
        network_metrics: Dict[str, Any],
        device_id: str,
        trust_cache: Optional[Dict[str, float]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluates an individual telemetry packet.
        Uses internal trust_cache if trust_cache parameter is omitted.
        """
        active_cache = trust_cache if trust_cache is not None else self.trust_cache
        return evaluate_security_decision(
            vitals=vitals,
            network_metrics=network_metrics,
            device_id=device_id,
            trust_cache=active_cache,
            config=self.config,
        )


if __name__ == "__main__":
    # Self-test and performance verification
    cfg = load_config("config.json")
    engine = SPSEngine(config=cfg)

    # Prepopulate sample trust cache (from Component 1)
    engine.update_trust("sensor_ecg_01", 0.95)   # High trust device
    engine.update_trust("sensor_spo2_02", 0.70)  # Borderline trust device
    engine.update_trust("sensor_bp_03", 0.15)    # Low / Degraded trust device

    test_cases = [
        {
            "name": "Scenario 1: Normal Vitals + High Trust + Good Network",
            "expected_profile": "Standard",
            "device": "sensor_ecg_01",
            "vitals": {"hr": 72, "spo2": 99, "bp_sys": 118, "bp_dia": 78, "rr": 15},
            "network": {"rtt_ms": 18.0, "packet_loss_pct": 0.2, "handover_active": False},
        },
        {
            "name": "Scenario 2: Borderline Vitals + Normal Trust + Moderate Network",
            "expected_profile": "Enhanced",
            "device": "sensor_spo2_02",
            "vitals": {"hr": 105, "spo2": 93, "bp_sys": 125, "bp_dia": 82, "rr": 18},
            "network": {"rtt_ms": 45.0, "packet_loss_pct": 1.5, "handover_active": False},
        },
        {
            "name": "Scenario 3: Critical Arrhythmia + Untrusted Device + Poor Link",
            "expected_profile": "Maximum",
            "device": "sensor_bp_03",
            "vitals": {"hr": 145, "spo2": 88, "bp_sys": 160, "bp_dia": 105, "rr": 28},
            "network": {"rtt_ms": 110.0, "packet_loss_pct": 6.0, "handover_active": True},
        },
        {
            "name": "Scenario 4: Routine Vitals + Uncached Device (Default Fallback DTS 0.70)",
            "expected_profile": "Standard",
            "device": "sensor_unknown_99",
            "vitals": {"hr": 75, "spo2": 98, "bp_sys": 120, "bp_dia": 80, "rr": 16},
            "network": {"rtt_ms": 20.0, "packet_loss_pct": 0.1, "handover_active": False},
        },
    ]

    print("=" * 78)
    print("VitalPath Component 2: Adaptive Security Decision Engine Verification")
    print("=" * 78)

    for tc in test_cases:
        res = engine.evaluate(
            vitals=tc["vitals"],
            network_metrics=tc["network"],
            device_id=tc["device"],
        )
        print(f"\n{tc['name']}")
        print(f"  Inputs  -> DTS: {res['factors']['dts']:.2f} | CC: {res['factors']['cc']:.2f} | NC: {res['factors']['nc']:.2f}")
        print(f"  Output  -> SPS: {res['sps']:.4f} => Profile: [{res['profile']}] (Expected: {tc['expected_profile']})")
        print(f"  Config  -> Key Rotation: {res['key_rotation_seconds']}s | Decision Latency: {res['decision_latency_ms']:.4f} ms")

    # Benchmark: Run 1,000 evaluations to verify NFR1 (< 5 ms latency)
    warmup_vitals = {"hr": 75, "spo2": 98, "bp_sys": 120, "bp_dia": 80, "rr": 16}
    warmup_net = {"rtt_ms": 25.0, "packet_loss_pct": 0.5, "handover_active": False}
    
    total_time = 0.0
    iterations = 1000
    for _ in range(iterations):
        t0 = time.perf_counter()
        engine.evaluate(warmup_vitals, warmup_net, "sensor_ecg_01")
        total_time += (time.perf_counter() - t0) * 1000.0

    avg_latency = total_time / iterations
    print("\n" + "=" * 78)
    print(f"Performance Benchmark (over {iterations:,} iterations):")
    print(f"  Average Decision Latency: {avg_latency:.4f} ms (Target: < 5.0 ms)")
    print(f"  NFR1 Compliance: {'PASSED [OK]' if avg_latency < 5.0 else 'FAILED'}")
    print("=" * 78)
