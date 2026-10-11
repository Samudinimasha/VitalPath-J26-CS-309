"""Threshold-Based Anomaly Detection Engine (WBS T10).

Runs only on packets that passed the replay gate and were decrypted. Each
vital sign is compared against the clinical threshold table in
``data/thresholds.json`` (AHA / WHO / ESC / NEWS2) and placed in one band:

    normal      matches a published normal range
    critical    matches a published critical limit
    borderline  between normal and critical (gap rule, no single source)
    missing     no reading in this packet; not scored
    invalid     not a finite, non-negative number; not scored as clinical

Every finding cites the rule ID and source from the table (NFR4). Rules use
inclusive cut points unless marked exclusive, so decimal readings such as
100.5 bpm fall into exactly one band.
"""

import json
import math
from dataclasses import dataclass, fields
from enum import Enum
from importlib import resources
from typing import Dict, List, Optional, Tuple

from vitalpath_c3.models import VitalSigns

BORDERLINE_RULE = "R-{vital}-BORDERLINE"
MISSING_RULE = "R-{vital}-MISSING"
INVALID_RULE = "R-{vital}-INVALID"


class Band(str, Enum):
    NORMAL = "normal"
    BORDERLINE = "borderline"
    CRITICAL = "critical"
    MISSING = "missing"
    INVALID = "invalid"


# Order used to pick the most severe clinical band in a packet.
_SEVERITY = {Band.MISSING: 0, Band.NORMAL: 1, Band.BORDERLINE: 2, Band.CRITICAL: 3}


@dataclass(frozen=True)
class ThresholdRule:
    id: str
    band: Band
    source: str
    min: Optional[float] = None
    max: Optional[float] = None
    min_exclusive: bool = False
    max_exclusive: bool = False

    def matches(self, value: float) -> bool:
        if self.min is not None:
            if value < self.min or (self.min_exclusive and value == self.min):
                return False
        if self.max is not None:
            if value > self.max or (self.max_exclusive and value == self.max):
                return False
        return True


@dataclass(frozen=True)
class VitalFinding:
    vital: str
    value: Optional[float]
    band: Band
    rule: str
    source: str = ""


@dataclass(frozen=True)
class ThresholdResult:
    findings: Tuple[VitalFinding, ...]

    @property
    def worst_band(self) -> Band:
        """Most severe clinical band across vitals (invalid is reported separately)."""
        scored = [f.band for f in self.findings if f.band is not Band.INVALID]
        return max(scored, key=_SEVERITY.__getitem__, default=Band.MISSING)

    @property
    def invalid(self) -> Tuple[VitalFinding, ...]:
        return tuple(f for f in self.findings if f.band is Band.INVALID)

    def by_band(self, band: Band) -> Tuple[VitalFinding, ...]:
        return tuple(f for f in self.findings if f.band is band)


class ThresholdTable:
    """Clinical rules for each vital, loaded from JSON."""

    def __init__(self, rules: Dict[str, List[ThresholdRule]]) -> None:
        self.rules = rules

    @classmethod
    def from_dict(cls, data: dict) -> "ThresholdTable":
        sources = data.get("sources", {})
        rules: Dict[str, List[ThresholdRule]] = {}
        for vital, spec in data["vitals"].items():
            parsed = []
            for raw in spec["rules"]:
                rule = ThresholdRule(
                    id=raw["id"],
                    band=Band(raw["band"]),
                    source=raw["source"],
                    min=raw.get("min"),
                    max=raw.get("max"),
                    min_exclusive=raw.get("min_exclusive", False),
                    max_exclusive=raw.get("max_exclusive", False),
                )
                if rule.band not in (Band.NORMAL, Band.CRITICAL):
                    raise ValueError(f"{rule.id}: only normal and critical bands may be listed")
                if rule.min is None and rule.max is None:
                    raise ValueError(f"{rule.id}: needs a min or max")
                for name in rule.source.split(";"):
                    if name.strip() not in sources:
                        raise ValueError(f"{rule.id}: unknown source {name.strip()!r}")
                parsed.append(rule)
            rules[vital] = parsed
        return cls(rules)

    @classmethod
    def load_default(cls) -> "ThresholdTable":
        text = resources.files("vitalpath_c3.data").joinpath("thresholds.json").read_text()
        return cls.from_dict(json.loads(text))


class ThresholdEngine:
    def __init__(self, table: Optional[ThresholdTable] = None) -> None:
        self.table = table or ThresholdTable.load_default()
        known = {f.name for f in fields(VitalSigns)}
        unknown = set(self.table.rules) - known
        if unknown:
            raise ValueError(f"threshold table has vitals not in VitalSigns: {sorted(unknown)}")

    def evaluate(self, vitals: VitalSigns) -> ThresholdResult:
        return ThresholdResult(
            tuple(
                self._classify(name, getattr(vitals, name))
                for name in self.table.rules
            )
        )

    def _classify(self, vital: str, value: object) -> VitalFinding:
        tag = vital.upper()
        if value is None:
            return VitalFinding(vital, None, Band.MISSING, MISSING_RULE.format(vital=tag))
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
            or value < 0
        ):
            return VitalFinding(vital, None, Band.INVALID, INVALID_RULE.format(vital=tag))
        for rule in self.table.rules[vital]:
            if rule.matches(value):
                return VitalFinding(vital, value, rule.band, rule.id, rule.source)
        return VitalFinding(vital, value, Band.BORDERLINE, BORDERLINE_RULE.format(vital=tag))
