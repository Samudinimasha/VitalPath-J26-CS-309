"""Hybrid Decision Engine (WBS T12).

Combines, for a packet that passed the replay gate and decrypted, the
replay verdict, the Threshold Engine result and the Correlation Engine
result into one deterministic score, NEWS2-style:

    each finding adds points (data/scoring.json)
    total 0      -> ACCEPT, label 'Normal'
    total 1-2    -> FLAG,   label 'Borderline'
    total >= 3   -> FLAG,   label 'Flagged'

This engine never discards. A severe anomaly is flagged and forwarded so the
attending clinician makes the clinical judgement; discarding is reserved for
factual findings made earlier (replay, flood, failed decryption).

Every point in the score is listed with the rule that produced it, so the
decision can be explained line by line (NFR4).
"""

import json
from dataclasses import dataclass
from enum import Enum
from importlib import resources
from typing import List, Optional, Tuple

from vitalpath_c3.engines.correlation import CorrelationResult, Kind
from vitalpath_c3.engines.replay import ReplayOutcome, ReplayVerdict
from vitalpath_c3.engines.threshold import Band, ThresholdResult


class Outcome(str, Enum):
    ACCEPT = "ACCEPT"
    FLAG = "FLAG"


@dataclass(frozen=True)
class Contribution:
    rule: str
    points: int
    reason: str


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    label: str
    score: int
    contributions: Tuple[Contribution, ...]

    def explain(self) -> str:
        lines = [f"{self.outcome.value} '{self.label}' (score {self.score})"]
        lines += [f"  +{c.points}  {c.rule}: {c.reason}" for c in self.contributions]
        return "\n".join(lines)


class HybridDecisionEngine:
    def __init__(self, scoring: Optional[dict] = None) -> None:
        if scoring is None:
            text = resources.files("vitalpath_c3.data").joinpath("scoring.json").read_text()
            scoring = json.loads(text)
        self.points = scoring["points"]
        self.labels = scoring["labels"]
        if not self.labels or "max_score" in self.labels[-1]:
            raise ValueError("the last label must have no max_score so every score has a label")
        if self.labels[0]["max_score"] != 0:
            raise ValueError("the first label must cover score 0 only (it is the ACCEPT label)")

    def decide(
        self,
        replay: ReplayVerdict,
        threshold: ThresholdResult,
        correlation: CorrelationResult,
    ) -> Decision:
        if not replay.passed:
            raise ValueError("discarded packets must not reach the Hybrid Decision Engine")

        contributions: List[Contribution] = []
        if replay.outcome is ReplayOutcome.ACCEPT_FLAGGED:
            contributions.append(
                Contribution(replay.rule.value, self.points["replay_packet_jump"], replay.detail)
            )
        for f in threshold.findings:
            key = {
                Band.BORDERLINE: "threshold_borderline",
                Band.CRITICAL: "threshold_critical",
                Band.INVALID: "threshold_invalid",
            }.get(f.band)
            if key:
                value = "unreadable value" if f.value is None else f"{f.value:g}"
                contributions.append(Contribution(f.rule, self.points[key], f"{f.vital} {value} is {f.band.value}"))
        for f in correlation.findings:
            key = "correlation_inconsistent" if f.kind is Kind.INCONSISTENT else "correlation_concerning"
            contributions.append(Contribution(f.rule, self.points[key], f.detail))

        score = sum(c.points for c in contributions)
        label = next(
            entry["label"] for entry in self.labels if score <= entry.get("max_score", score)
        )
        outcome = Outcome.ACCEPT if label == self.labels[0]["label"] else Outcome.FLAG
        return Decision(outcome, label, score, tuple(contributions))
