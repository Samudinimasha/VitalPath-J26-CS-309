"""
Fingerprint Match factor (F) - weight 0.25.

At registration the device's MAC address and hardware ID are stored in
the Authorised Device List. At connection time the edge gateway reads
the device's MAC (link layer) and hardware ID (device attestation) and
compares them with the registered values.

    hardware ID  MAC        F      Meaning
    match        match      1.00   same physical device
    match        differs    0.60   NIC replaced / MAC changed after repair
    differs      any        0.00   HARD FAIL: different hardware (clone)
    missing      any        0.00   HARD FAIL: no fingerprint presented

Why a hardware ID mismatch is a hard fail: a clone that has stolen a
genuine device's certificate and private key passes the Certificate
factor (C = 1.0). With F = 0 and healthy H, B, R it would still score
T = 0.75, i.e. conditional access. Different hardware presenting a valid
identity is the definition of a cloned device, so it is blocked outright.
A MAC change alone is softer: MACs are easily spoofed (weak evidence of
identity) and also change legitimately when a network module is replaced.

Comparisons use hmac.compare_digest on SHA-256 digests (constant time).
"""
import hashlib
import hmac
from dataclasses import dataclass, field

from . import config
from .registry import DeviceRecord, DeviceRegistry


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.strip().lower().encode()).digest()


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(_digest(a), _digest(b))


@dataclass
class FingerprintResult:
    score: float
    hard_fail: bool
    checks: dict = field(default_factory=dict)
    reasons: list = field(default_factory=list)


def evaluate_fingerprint(record: DeviceRecord, mac: str | None, hardware_id: str | None,
                         registry: DeviceRegistry | None = None) -> FingerprintResult:
    if not mac or not hardware_id:
        return FingerprintResult(0.0, True, {"presented": False},
                                 ["NO_FINGERPRINT: MAC or hardware ID missing"])

    checks = {"presented": True,
              "hwid_match": _same(hardware_id, record.hardware_id),
              "mac_match": _same(mac, record.mac_address)}

    if not checks["hwid_match"]:
        reasons = [f"HWID_MISMATCH: presented '{hardware_id}', registered "
                   f"'{record.hardware_id}' - CLONE SUSPECTED"]
        # Is this hardware registered under a different identity? (identity swap)
        if registry is not None:
            other = registry.find_by_hardware_id(hardware_id)
            if other and other.device_id != record.device_id:
                reasons.append(f"HWID belongs to registered device {other.device_id}")
        return FingerprintResult(0.0, True, checks, reasons)

    if not checks["mac_match"]:
        return FingerprintResult(config.F_MAC_CHANGED, False, checks,
                                 [f"MAC_CHANGED: presented {mac.lower()}, registered "
                                  f"{record.mac_address} - re-registration needed"])

    return FingerprintResult(1.0, False, checks, ["FINGERPRINT_MATCH"])
