"""
Device Health Status factor (H) - weight 0.20.

Rule-based score from the device's periodic status report, so a
genuine but failing device (flat battery, faulty sensor, stale firmware,
missed heartbeats) loses trust gradually instead of being treated as
either perfect or hostile. This is the "degraded device" scenario.

    H = 0.30 battery + 0.30 sensor_errors + 0.20 firmware + 0.20 heartbeat

Sub-scores (thresholds in config.py):
    battery      >= 50% -> 1.0, 20-50% -> 0.5..1.0, < 20% -> 0.0..0.5
    sensor_errors  0% failed readings -> 1.0, >= 10% -> 0.0 (linear)
    firmware     >= MIN_FIRMWARE -> 1.0, older -> 0.4
    heartbeat    <= 30 s since last -> 1.0, >= 300 s -> 0.0 (linear)
"""
from dataclasses import dataclass, field

from . import config


@dataclass
class HealthReport:
    battery_pct: float
    sensor_error_rate: float      # fraction 0.0-1.0 of failed readings
    firmware_version: str
    heartbeat_age_s: float        # seconds since last heartbeat


@dataclass
class HealthResult:
    score: float
    parts: dict = field(default_factory=dict)
    reasons: list = field(default_factory=list)


def _version(v: str) -> tuple:
    return tuple(int(x) for x in v.split("."))


def _battery(pct: float) -> float:
    if pct >= config.BATTERY_OK_PCT:
        return 1.0
    if pct >= config.BATTERY_LOW_PCT:
        span = config.BATTERY_OK_PCT - config.BATTERY_LOW_PCT
        return 0.5 + 0.5 * (pct - config.BATTERY_LOW_PCT) / span
    return max(0.0, 0.5 * pct / config.BATTERY_LOW_PCT)


def evaluate_health(r: HealthReport) -> HealthResult:
    parts = {
        "battery": _battery(r.battery_pct),
        "sensor_errors": max(0.0, 1 - r.sensor_error_rate / config.SENSOR_ERROR_MAX),
        "firmware": 1.0 if _version(r.firmware_version) >= _version(config.MIN_FIRMWARE)
        else config.FIRMWARE_OUTDATED,
        "heartbeat": 1.0 if r.heartbeat_age_s <= config.HEARTBEAT_OK_S else max(
            0.0, 1 - (r.heartbeat_age_s - config.HEARTBEAT_OK_S)
            / (config.HEARTBEAT_DEAD_S - config.HEARTBEAT_OK_S)),
    }
    score = sum(config.H_WEIGHTS[k] * v for k, v in parts.items())

    reasons = []
    if parts["battery"] < 1:
        reasons.append(f"LOW_BATTERY {r.battery_pct:.0f}%")
    if parts["sensor_errors"] < 1:
        reasons.append(f"SENSOR_ERRORS {r.sensor_error_rate:.0%}")
    if parts["firmware"] < 1:
        reasons.append(f"FIRMWARE_OUTDATED {r.firmware_version} < {config.MIN_FIRMWARE}")
    if parts["heartbeat"] < 1:
        reasons.append(f"STALE_HEARTBEAT {r.heartbeat_age_s:.0f}s")
    return HealthResult(round(score, 4), parts, reasons or ["HEALTHY"])
