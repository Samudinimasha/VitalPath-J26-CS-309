"""Multi-Vital Correlation Engine (WBS T11).

Runs on the same decrypted vitals as the Threshold Engine and cross-checks
pairs of vital signs. Each rule's logic is fixed here; its numeric
parameters and source come from ``data/correlation_rules.json``.

    R-CORR-HR-PULSE     |HR - pulse| above limit           -> inconsistent
    R-CORR-SPO2-HR      SpO2 very low but HR normal (S6)   -> inconsistent
    R-CORR-SHOCK-INDEX  HR / SBP at or above limit         -> concerning
    R-CORR-BP-ORDER     diastolic >= systolic              -> inconsistent

A rule whose inputs are missing or invalid is listed as not evaluated rather
than passed, so the Hybrid Decision Engine can tell "consistent" apart from
"could not check".
"""

import json
import math
from dataclasses import dataclass
from enum import Enum
from importlib import resources
from typing import Callable, Dict, Optional, Tuple

from vitalpath_c3.models import VitalSigns


class Kind(str, Enum):
    INCONSISTENT = "inconsistent"
    CONCERNING = "concerning"


@dataclass(frozen=True)
class CorrelationFinding:
    rule: str
    kind: Kind
    detail: str


@dataclass(frozen=True)
class CorrelationResult:
    findings: Tuple[CorrelationFinding, ...]
    not_evaluated: Tuple[str, ...]

    @property
    def consistent(self) -> bool:
        return not any(f.kind is Kind.INCONSISTENT for f in self.findings)

    def by_kind(self, kind: Kind) -> Tuple[CorrelationFinding, ...]:
        return tuple(f for f in self.findings if f.kind is kind)


def _num(value: object) -> Optional[float]:
    """Return a usable reading or None (missing or invalid)."""
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
    ):
        return float(value)
    return None


# Each check returns None when inputs are unavailable, "" when the pair is
# consistent, or a detail string when the rule fires.
def _hr_pulse(v: VitalSigns, p: dict) -> Optional[str]:
    hr, pulse = _num(v.hr), _num(v.pulse)
    if hr is None or pulse is None:
        return None
    diff = abs(hr - pulse)
    if diff > p["max_difference_bpm"]:
        return f"HR {hr:g} and pulse {pulse:g} differ by {diff:g} bpm (limit {p['max_difference_bpm']:g})"
    return ""


def _spo2_hr(v: VitalSigns, p: dict) -> Optional[str]:
    spo2, hr = _num(v.spo2), _num(v.hr)
    if spo2 is None or hr is None:
        return None
    if spo2 < p["spo2_below"] and p["hr_normal_min"] <= hr <= p["hr_normal_max"]:
        return f"SpO2 {spo2:g}% with normal HR {hr:g} bpm; expected compensatory tachycardia"
    return ""


def _shock_index(v: VitalSigns, p: dict) -> Optional[str]:
    hr, sbp = _num(v.hr), _num(v.sbp)
    if hr is None or not sbp:
        return None
    index = hr / sbp
    if index >= p["shock_index_at_least"]:
        return f"shock index {index:.2f} (HR {hr:g} / SBP {sbp:g}) >= {p['shock_index_at_least']:g}"
    return ""


def _bp_order(v: VitalSigns, p: dict) -> Optional[str]:
    sbp, dbp = _num(v.sbp), _num(v.dbp)
    if sbp is None or dbp is None:
        return None
    if dbp >= sbp:
        return f"diastolic {dbp:g} is not below systolic {sbp:g}"
    return ""


_CHECKS: Dict[str, Callable[[VitalSigns, dict], Optional[str]]] = {
    "R-CORR-HR-PULSE": _hr_pulse,
    "R-CORR-SPO2-HR": _spo2_hr,
    "R-CORR-SHOCK-INDEX": _shock_index,
    "R-CORR-BP-ORDER": _bp_order,
}


class CorrelationEngine:
    def __init__(self, rules: Optional[dict] = None) -> None:
        if rules is None:
            text = resources.files("vitalpath_c3.data").joinpath("correlation_rules.json").read_text()
            rules = json.loads(text)["rules"]
        unknown = set(rules) - set(_CHECKS)
        if unknown:
            raise ValueError(f"no check implemented for rules: {sorted(unknown)}")
        self.rules = {rid: dict(spec, kind=Kind(spec["kind"])) for rid, spec in rules.items()}

    def evaluate(self, vitals: VitalSigns) -> CorrelationResult:
        findings = []
        not_evaluated = []
        for rule_id, params in self.rules.items():
            detail = _CHECKS[rule_id](vitals, params)
            if detail is None:
                not_evaluated.append(rule_id)
            elif detail:
                findings.append(CorrelationFinding(rule_id, params["kind"], detail))
        return CorrelationResult(tuple(findings), tuple(not_evaluated))
