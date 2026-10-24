"""Unit tests for the Multi-Vital Correlation Engine (WBS T11)."""

import time

import pytest

from vitalpath_c3.engines.correlation import CorrelationEngine, Kind
from vitalpath_c3.packet_models import VitalSigns

NORMAL = dict(hr=75, pulse=74, spo2=98, sbp=120, dbp=78, resp=14)


@pytest.fixture(scope="module")
def engine() -> CorrelationEngine:
    return CorrelationEngine()


def fired(result):
    return {f.rule for f in result.findings}


def test_normal_packet_is_consistent(engine):
    result = engine.evaluate(VitalSigns(**NORMAL))
    assert result.consistent
    assert result.findings == ()
    assert result.not_evaluated == ()


# --- HR vs pulse ------------------------------------------------------------


@pytest.mark.parametrize("pulse, fires", [(95, False), (55, False), (95.1, True), (54.9, True)])
def test_hr_pulse_limit(engine, pulse, fires):
    result = engine.evaluate(VitalSigns(**{**NORMAL, "pulse": pulse}))
    assert ("R-CORR-HR-PULSE" in fired(result)) is fires


def test_hr_pulse_disagreement_is_inconsistent(engine):
    result = engine.evaluate(VitalSigns(**{**NORMAL, "pulse": 218.6}))
    assert not result.consistent
    (finding,) = result.findings
    assert finding.kind is Kind.INCONSISTENT
    assert "differ by" in finding.detail


# --- SpO2 vs HR (S6) --------------------------------------------------------


def test_s6_low_spo2_with_normal_hr_is_inconsistent(engine):
    """Real case from MIMIC-III record 3000003n, minute 112."""
    result = engine.evaluate(VitalSigns(hr=64.0, pulse=72.3, spo2=13.9))
    assert fired(result) == {"R-CORR-SPO2-HR"}
    assert not result.consistent


def test_low_spo2_with_tachycardia_is_consistent(engine):
    result = engine.evaluate(VitalSigns(hr=125, pulse=124, spo2=75))
    assert "R-CORR-SPO2-HR" not in fired(result)


def test_spo2_at_limit_does_not_fire(engine):
    result = engine.evaluate(VitalSigns(hr=75, pulse=75, spo2=80))
    assert "R-CORR-SPO2-HR" not in fired(result)


# --- Shock index ------------------------------------------------------------


def test_shock_index_concerning_when_each_value_acceptable(engine):
    # HR 100 is normal and SBP 100 only borderline, but HR/SBP = 1.0.
    result = engine.evaluate(VitalSigns(**{**NORMAL, "hr": 100, "pulse": 100, "sbp": 100, "dbp": 60}))
    (finding,) = result.findings
    assert finding.rule == "R-CORR-SHOCK-INDEX"
    assert finding.kind is Kind.CONCERNING
    # Concerning is not the same as inconsistent.
    assert result.consistent


def test_shock_index_below_limit(engine):
    result = engine.evaluate(VitalSigns(**{**NORMAL, "hr": 99, "pulse": 99, "sbp": 100, "dbp": 60}))
    assert "R-CORR-SHOCK-INDEX" not in fired(result)


# --- Blood pressure order ---------------------------------------------------


@pytest.mark.parametrize("dbp, fires", [(119, False), (120, True), (130, True)])
def test_diastolic_must_be_below_systolic(engine, dbp, fires):
    result = engine.evaluate(VitalSigns(**{**NORMAL, "dbp": dbp}))
    assert ("R-CORR-BP-ORDER" in fired(result)) is fires


# --- Missing and invalid inputs ---------------------------------------------


def test_rules_without_inputs_are_not_evaluated(engine):
    result = engine.evaluate(VitalSigns(hr=75, spo2=98))
    assert result.findings == ()
    assert set(result.not_evaluated) == {"R-CORR-HR-PULSE", "R-CORR-SHOCK-INDEX", "R-CORR-BP-ORDER"}


@pytest.mark.parametrize("bad", [float("nan"), -1, "75", None])
def test_invalid_input_is_not_evaluated(engine, bad):
    result = engine.evaluate(VitalSigns(**{**NORMAL, "hr": bad}))
    assert {"R-CORR-HR-PULSE", "R-CORR-SPO2-HR", "R-CORR-SHOCK-INDEX"} <= set(result.not_evaluated)


def test_zero_systolic_does_not_divide_by_zero(engine):
    result = engine.evaluate(VitalSigns(hr=75, sbp=0, dbp=0))
    assert "R-CORR-SHOCK-INDEX" in result.not_evaluated


# --- Configuration and performance ------------------------------------------


def test_custom_parameters():
    engine = CorrelationEngine(
        {"R-CORR-HR-PULSE": {"kind": "inconsistent", "max_difference_bpm": 5}}
    )
    assert fired(engine.evaluate(VitalSigns(hr=80, pulse=86))) == {"R-CORR-HR-PULSE"}


def test_unknown_rule_rejected():
    with pytest.raises(ValueError, match="no check implemented"):
        CorrelationEngine({"R-CORR-NEW": {"kind": "concerning"}})


def test_evaluate_is_well_within_latency_budget(engine):
    vitals = VitalSigns(hr=88.4, pulse=87.9, spo2=93.2, sbp=142, dbp=91, resp=22.6)
    n = 20_000
    start = time.perf_counter()
    for _ in range(n):
        engine.evaluate(vitals)
    assert (time.perf_counter() - start) * 1000 / n < 1.0
