"""
Central configuration for the Trusted Device Score.
All weights and thresholds live here so they can be tuned and
justified in one place (TAF J26-CS-309, Component 1).
"""

# T = 0.30C + 0.25F + 0.20H + 0.15B + 0.10R
WEIGHTS = {"C": 0.30, "F": 0.25, "H": 0.20, "B": 0.15, "R": 0.10}
assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9, "weights must sum to 1"

# Trust tiers (TAF): T >= 0.80 full, T >= 0.60 conditional, else blocked
FULL_TRUST_MIN = 0.80
CONDITIONAL_MIN = 0.60

# How often a device must be re-verified, by tier (seconds)
RECHECK_INTERVAL_S = {"FULL_TRUST": 300, "CONDITIONAL": 60}

# A factor below this is listed as a monitoring flag for conditional devices
MONITOR_FLAG_BELOW = 0.80

# ---- Fingerprint factor (F) ----
F_MAC_CHANGED = 0.60      # hardware ID matches, MAC differs (NIC swap / repair)

# ---- Health factor (H) sub-weights and thresholds ----
H_WEIGHTS = {"battery": 0.30, "sensor_errors": 0.30, "firmware": 0.20, "heartbeat": 0.20}
assert abs(sum(H_WEIGHTS.values()) - 1.0) < 1e-9
BATTERY_OK_PCT = 50          # >= this scores 1.0
BATTERY_LOW_PCT = 20         # below this scores < 0.5
SENSOR_ERROR_MAX = 0.10      # 10% failed readings -> 0.0
MIN_FIRMWARE = "2.1.0"       # firmware older than this scores FIRMWARE_OUTDATED
FIRMWARE_OUTDATED = 0.40
HEARTBEAT_OK_S = 30          # last heartbeat within 30 s scores 1.0
HEARTBEAT_DEAD_S = 300       # 5 min silence scores 0.0
