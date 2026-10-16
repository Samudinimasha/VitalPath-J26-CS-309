"""
Trust Scoring Engine - Component 1 decision point.

    T = 0.30C + 0.25F + 0.20H + 0.15B + 0.10R

Decision pipeline for one connection attempt:

  1. ADL gate      device_id not registered / suspended  -> REJECTED
  2. Factors       compute C, F, H, B, R (each 0.0-1.0) and T
  3. Identity gate C or F hard fail (forged/expired/revoked
                   cert, cloned hardware)                -> BLOCKED
  4. Tiers         T >= 0.80 FULL_TRUST
                   T >= 0.60 CONDITIONAL (monitoring flags, faster recheck)
                   T <  0.60 BLOCKED (alert raised)

T is still computed and logged for gated devices ("score_tier"), so the
evaluation can show what the plain weighted formula would have decided
without the identity gate.

Every decision is written to the trust_decisions table: this is the
audit trail, and the history the Reputation factor (R) will be computed
from in the next phase.

PP1 status: C, F, H are computed. B (behavioural consistency) and
R (historical reputation) are accepted as provisional inputs and are
marked as such in every decision.
"""
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from . import config
from .cert_factor import CertificateValidator
from .fingerprint_factor import evaluate_fingerprint
from .health_factor import HealthReport, evaluate_health
from .registry import DeviceRegistry

DECISIONS_SCHEMA = """
CREATE TABLE IF NOT EXISTS trust_decisions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    device_id   TEXT NOT NULL,
    tier        TEXT NOT NULL,
    T           REAL,
    C REAL, F REAL, H REAL, B REAL, R REAL,
    gate        TEXT,
    reasons     TEXT
);
"""


@dataclass
class DeviceClaim:
    """Everything presented / observed when a device tries to connect."""
    device_id: str
    cert_pem: bytes
    mac: str | None
    hardware_id: str | None
    health: HealthReport | None
    behaviour: float | None = None     # B - provisional input (PP1)
    reputation: float | None = None    # R - provisional input (PP1)


@dataclass
class TrustDecision:
    device_id: str
    tier: str                    # FULL_TRUST | CONDITIONAL | BLOCKED | REJECTED
    T: float | None
    factors: dict = field(default_factory=dict)
    score_tier: str | None = None   # tier from T alone, ignoring the identity gate
    gate: str | None = None         # which gate fired, if any
    reasons: list = field(default_factory=list)
    monitoring_flags: list = field(default_factory=list)
    recheck_after_s: int | None = None
    alert: bool = False
    provisional: list = field(default_factory=list)
    timestamp: str = ""

    def to_json(self) -> str:
        """Message handed to Component 2 (transmission) and Component 4 (ledger)."""
        return json.dumps(asdict(self))


def tier_for(t: float) -> str:
    if t >= config.FULL_TRUST_MIN:
        return "FULL_TRUST"
    if t >= config.CONDITIONAL_MIN:
        return "CONDITIONAL"
    return "BLOCKED"


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


class TrustEngine:
    def __init__(self, registry: DeviceRegistry, validator: CertificateValidator):
        self.registry = registry
        self.validator = validator
        self.registry.conn.executescript(DECISIONS_SCHEMA)

    def evaluate(self, claim: DeviceClaim) -> TrustDecision:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")

        # 1. ADL gate - unknown devices never reach scoring
        ok, why = self.registry.is_authorised(claim.device_id)
        if not ok:
            d = TrustDecision(claim.device_id, "REJECTED", None, gate="ADL",
                              reasons=[why], alert=True, timestamp=now)
            return self._log(d)

        record = self.registry.lookup(claim.device_id)

        # 2. Factors
        c = self.validator.evaluate(claim.cert_pem, claim.device_id, record)
        f = evaluate_fingerprint(record, claim.mac, claim.hardware_id, self.registry)
        if claim.health is None:
            h_score, h_reasons = 0.0, ["NO_HEALTH_REPORT"]
        else:
            h = evaluate_health(claim.health)
            h_score, h_reasons = h.score, h.reasons
        provisional = []
        b = _clamp(claim.behaviour) if claim.behaviour is not None else 1.0
        r = _clamp(claim.reputation) if claim.reputation is not None else 1.0
        provisional += ["B", "R"]

        factors = {"C": c.score, "F": f.score, "H": h_score, "B": b, "R": r}
        T = round(sum(config.WEIGHTS[k] * v for k, v in factors.items()), 4)
        score_tier = tier_for(T)
        reasons = ([f"C: {x}" for x in c.reasons] + [f"F: {x}" for x in f.reasons]
                   + [f"H: {x}" for x in h_reasons])

        d = TrustDecision(claim.device_id, score_tier, T, factors, score_tier,
                          reasons=reasons, provisional=provisional, timestamp=now)

        # 3. Identity gate
        if c.hard_fail or f.hard_fail:
            d.tier = "BLOCKED"
            d.gate = "CERTIFICATE" if c.hard_fail else "FINGERPRINT"
            d.alert = True
            return self._log(d)

        # 4. Tier actions
        if d.tier == "CONDITIONAL":
            d.monitoring_flags = [k for k, v in factors.items()
                                  if v < config.MONITOR_FLAG_BELOW]
        if d.tier == "BLOCKED":
            d.alert = True
        d.recheck_after_s = config.RECHECK_INTERVAL_S.get(d.tier)
        return self._log(d)

    def _log(self, d: TrustDecision) -> TrustDecision:
        f = d.factors
        self.registry.conn.execute(
            "INSERT INTO trust_decisions (ts, device_id, tier, T, C, F, H, B, R, gate, reasons)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (d.timestamp, d.device_id, d.tier, d.T, f.get("C"), f.get("F"), f.get("H"),
             f.get("B"), f.get("R"), d.gate, json.dumps(d.reasons)))
        self.registry.conn.commit()
        return d
