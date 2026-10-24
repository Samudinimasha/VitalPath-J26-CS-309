"""Unit tests for the Hybrid Decision Engine (WBS T12).

Inputs are produced by the real Threshold and Correlation engines so the
tests read as clinical scenarios.
"""

import pytest

from vitalpath_c3.engines.correlation import CorrelationEngine
from vitalpath_c3.engines.hybrid import HybridDecisionEngine, Outcome
from vitalpath_c3.engines.replay import ReplayOutcome, ReplayVerdict
from vitalpath_c3.engines.threshold import ThresholdEngine
from vitalpath_c3.packet_models import VitalSigns
from vitalpath_c3.rule_ids import Rule

FRESH = ReplayVerdict(ReplayOutcome.ACCEPT, Rule.REPLAY_ACCEPT, "amb-01", "PKT-000001")
JUMP = ReplayVerdict(ReplayOutcome.ACCEPT_FLAGGED, Rule.PACKET_JUMP, "amb-01", "PKT-009000", "jump of 8999")
NORMAL = dict(hr=75, pulse=74, spo2=98, sbp=120, dbp=78, resp=14)

threshold = ThresholdEngine()
correlation = CorrelationEngine()


@pytest.fixture(scope="module")
def hybrid() -> HybridDecisionEngine:
    return HybridDecisionEngine()


def decide(hybrid, replay=FRESH, **vitals):
    v = VitalSigns(**vitals)
    return hybrid.decide(replay, threshold.evaluate(v), correlation.evaluate(v))


def test_s1_all_normal_is_accepted(hybrid):
    d = decide(hybrid, **NORMAL)
    assert (d.outcome, d.label, d.score) == (Outcome.ACCEPT, "Normal", 0)
    assert d.contributions == ()


def test_s5_impossible_heart_rate_is_flagged_not_discarded(hybrid):
    """S5: HR 300 bpm -> FLAG 'Flagged', forwarded for clinician review."""
    d = decide(hybrid, **{**NORMAL, "hr": 300, "pulse": 300})
    assert (d.outcome, d.label) == (Outcome.FLAG, "Flagged")
    assert "R-HR-CRIT-HIGH" in {c.rule for c in d.contributions}


def test_s6_spo2_inconsistent_with_normal_hr_is_flagged(hybrid):
    """S6: real reading from MIMIC-III 3000003n (SpO2 13.9 with HR 64)."""
    d = decide(hybrid, hr=64.0, pulse=72.3, spo2=13.9)
    assert (d.outcome, d.label) == (Outcome.FLAG, "Flagged")
    rules = {c.rule for c in d.contributions}
    assert {"R-SPO2-CRIT-LOW", "R-CORR-SPO2-HR"} <= rules
    assert d.score == 6


def test_s7_slightly_elevated_hr_is_borderline(hybrid):
    """S7: flag as borderline, not discarded."""
    d = decide(hybrid, **{**NORMAL, "hr": 112, "pulse": 111})
    assert (d.outcome, d.label, d.score) == (Outcome.FLAG, "Borderline", 1)


def test_two_borderline_vitals_stay_borderline(hybrid):
    d = decide(hybrid, **{**NORMAL, "hr": 112, "pulse": 111, "resp": 22})
    assert (d.label, d.score) == ("Borderline", 2)


def test_three_borderline_vitals_add_up_to_flagged(hybrid):
    d = decide(hybrid, **{**NORMAL, "hr": 112, "pulse": 111, "resp": 22, "spo2": 93})
    assert (d.label, d.score) == ("Flagged", 3)


def test_borderline_bp_with_high_shock_index_is_flagged(hybrid):
    # HR 100 is normal and SBP 100 only borderline (1), but HR/SBP = 1.0 adds 2.
    d = decide(hybrid, **{**NORMAL, "hr": 100, "pulse": 100, "sbp": 100, "dbp": 60})
    assert {c.rule for c in d.contributions} == {"R-SBP-BORDERLINE", "R-CORR-SHOCK-INDEX"}
    assert (d.label, d.score) == ("Flagged", 3)


def test_s10_packet_id_jump_is_flagged_even_with_normal_vitals(hybrid):
    """S10: packet ID jump -> flag, possible injection."""
    d = decide(hybrid, replay=JUMP, **NORMAL)
    assert (d.outcome, d.label, d.score) == (Outcome.FLAG, "Flagged", 3)
    assert d.contributions[0].rule == "R-PACKET-JUMP"


def test_invalid_reading_is_flagged(hybrid):
    d = decide(hybrid, **{**NORMAL, "hr": float("nan")})
    assert d.label == "Flagged"
    assert "R-HR-INVALID" in {c.rule for c in d.contributions}


def test_missing_readings_score_nothing(hybrid):
    d = decide(hybrid, hr=80)
    assert (d.outcome, d.label, d.score) == (Outcome.ACCEPT, "Normal", 0)


def test_discarded_packet_rejected(hybrid):
    discarded = ReplayVerdict(ReplayOutcome.DISCARD, Rule.REPLAY_DUPLICATE, "amb-01", "PKT-000001")
    v = VitalSigns(**NORMAL)
    with pytest.raises(ValueError, match="must not reach"):
        hybrid.decide(discarded, threshold.evaluate(v), correlation.evaluate(v))


def test_score_equals_sum_of_listed_contributions(hybrid):
    d = decide(hybrid, hr=150, pulse=100, spo2=88, sbp=85, dbp=90, resp=30)
    assert d.score == sum(c.points for c in d.contributions)
    assert d.score > 0


def test_explain_lists_every_contribution(hybrid):
    d = decide(hybrid, hr=64.0, pulse=72.3, spo2=13.9)
    text = d.explain()
    assert text.splitlines()[0] == "FLAG 'Flagged' (score 6)"
    assert "+3  R-SPO2-CRIT-LOW: spo2 13.9 is critical" in text
    assert "R-CORR-SPO2-HR" in text


def test_custom_scoring():
    hybrid = HybridDecisionEngine(
        {
            "points": {
                "threshold_borderline": 5, "threshold_critical": 5, "threshold_invalid": 5,
                "correlation_concerning": 5, "correlation_inconsistent": 5, "replay_packet_jump": 5,
            },
            "labels": [{"label": "Normal", "max_score": 0}, {"label": "Flagged"}],
        }
    )
    assert decide(hybrid, **{**NORMAL, "hr": 112, "pulse": 111}).label == "Flagged"


@pytest.mark.parametrize(
    "labels, message",
    [
        ([{"label": "Normal", "max_score": 0}, {"label": "Flagged", "max_score": 9}], "last label"),
        ([{"label": "Normal", "max_score": 1}, {"label": "Flagged"}], "first label"),
    ],
)
def test_bad_label_table_rejected(labels, message):
    with pytest.raises(ValueError, match=message):
        HybridDecisionEngine({"points": {}, "labels": labels})
