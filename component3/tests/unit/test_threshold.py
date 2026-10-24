"""Unit tests for the Threshold-Based Anomaly Detection Engine (WBS T10).

Boundary values follow the draft clinical table in data/thresholds.json.
"""

import json
import time
from importlib import resources

import pytest

from vitalpath_c3.engines.threshold import Band, ThresholdEngine, ThresholdTable
from vitalpath_c3.packet_models import VitalSigns


@pytest.fixture(scope="module")
def engine() -> ThresholdEngine:
    return ThresholdEngine()


def band_of(engine, vital, value):
    result = engine.evaluate(VitalSigns(**{vital: value}))
    (finding,) = [f for f in result.findings if f.vital == vital]
    return finding.band, finding.rule


@pytest.mark.parametrize(
    "vital, value, band",
    [
        # Heart rate: critical <=40, normal 60-100, critical >=131
        ("hr", 40, Band.CRITICAL),
        ("hr", 40.1, Band.BORDERLINE),
        ("hr", 59.9, Band.BORDERLINE),
        ("hr", 60, Band.NORMAL),
        ("hr", 100, Band.NORMAL),
        ("hr", 100.5, Band.BORDERLINE),
        ("hr", 130.9, Band.BORDERLINE),
        ("hr", 131, Band.CRITICAL),
        # SpO2: critical <90, normal >=95
        ("spo2", 89.9, Band.CRITICAL),
        ("spo2", 90, Band.BORDERLINE),
        ("spo2", 94.9, Band.BORDERLINE),
        ("spo2", 95, Band.NORMAL),
        ("spo2", 100, Band.NORMAL),
        # Systolic: critical <=90, normal 111-139, critical >180
        ("sbp", 90, Band.CRITICAL),
        ("sbp", 90.5, Band.BORDERLINE),
        ("sbp", 111, Band.NORMAL),
        ("sbp", 139, Band.NORMAL),
        ("sbp", 139.5, Band.BORDERLINE),
        ("sbp", 180, Band.BORDERLINE),
        ("sbp", 180.1, Band.CRITICAL),
        # Diastolic: normal <90, critical >120, low values not scored
        ("dbp", 40, Band.NORMAL),
        ("dbp", 89.9, Band.NORMAL),
        ("dbp", 90, Band.BORDERLINE),
        ("dbp", 120, Band.BORDERLINE),
        ("dbp", 120.1, Band.CRITICAL),
        # Respiratory rate: critical <=8, normal 12-20, critical >=25
        ("resp", 8, Band.CRITICAL),
        ("resp", 8.5, Band.BORDERLINE),
        ("resp", 12, Band.NORMAL),
        ("resp", 20, Band.NORMAL),
        ("resp", 24.9, Band.BORDERLINE),
        ("resp", 25, Band.CRITICAL),
    ],
)
def test_band_boundaries(engine, vital, value, band):
    assert band_of(engine, vital, value)[0] is band


def test_findings_cite_rule_and_source(engine):
    result = engine.evaluate(VitalSigns(hr=150))
    (hr,) = [f for f in result.findings if f.vital == "hr"]
    assert hr.rule == "R-HR-CRIT-HIGH"
    assert hr.source == "NEWS2"


def test_borderline_cites_gap_rule(engine):
    assert band_of(engine, "hr", 115) == (Band.BORDERLINE, "R-HR-BORDERLINE")


def test_s5_impossible_heart_rate_is_critical(engine):
    """S5: heart rate 300 bpm."""
    result = engine.evaluate(VitalSigns(hr=300, spo2=97, sbp=120, dbp=80, resp=16))
    assert result.worst_band is Band.CRITICAL
    assert [f.vital for f in result.by_band(Band.CRITICAL)] == ["hr"]


def test_s7_slightly_elevated_heart_rate_is_borderline(engine):
    """S7: heart rate slightly elevated but within plausible exertion range."""
    result = engine.evaluate(VitalSigns(hr=112, spo2=97, sbp=125, dbp=80, resp=18))
    assert result.worst_band is Band.BORDERLINE


def test_all_normal_packet(engine):
    result = engine.evaluate(VitalSigns(hr=75, spo2=98, sbp=120, dbp=78, resp=14))
    assert result.worst_band is Band.NORMAL
    assert all(f.band is Band.NORMAL for f in result.findings)


def test_missing_readings_are_not_scored(engine):
    result = engine.evaluate(VitalSigns(hr=75))
    assert result.worst_band is Band.NORMAL
    assert {f.vital for f in result.by_band(Band.MISSING)} == {"spo2", "sbp", "dbp", "resp"}


def test_packet_with_no_readings(engine):
    assert engine.evaluate(VitalSigns()).worst_band is Band.MISSING


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -5, "72", True])
def test_invalid_values_reported_separately(engine, value):
    result = engine.evaluate(VitalSigns(hr=value, spo2=98))
    assert [f.vital for f in result.invalid] == ["hr"]
    assert result.invalid[0].rule == "R-HR-INVALID"
    # An invalid reading does not count as a clinical band.
    assert result.worst_band is Band.NORMAL


def test_every_rule_in_table_has_known_source():
    data = json.loads(
        resources.files("vitalpath_c3.data").joinpath("thresholds.json").read_text()
    )
    for vital, spec in data["vitals"].items():
        for rule in spec["rules"]:
            for name in rule["source"].split(";"):
                assert name.strip() in data["sources"], (vital, rule["id"])


def test_custom_table_can_be_loaded():
    table = ThresholdTable.from_dict(
        {
            "sources": {"TEST": {}},
            "vitals": {
                "hr": {"rules": [{"id": "R-T", "band": "normal", "min": 50, "max": 70, "source": "TEST"}]}
            },
        }
    )
    engine = ThresholdEngine(table)
    assert band_of(engine, "hr", 60)[0] is Band.NORMAL
    assert band_of(engine, "hr", 80)[0] is Band.BORDERLINE


@pytest.mark.parametrize(
    "rule, message",
    [
        ({"id": "R-X", "band": "borderline", "min": 1, "source": "TEST"}, "only normal and critical"),
        ({"id": "R-X", "band": "normal", "source": "TEST"}, "needs a min or max"),
        ({"id": "R-X", "band": "normal", "min": 1, "source": "NOPE"}, "unknown source"),
    ],
)
def test_bad_table_rejected(rule, message):
    with pytest.raises(ValueError, match=message):
        ThresholdTable.from_dict({"sources": {"TEST": {}}, "vitals": {"hr": {"rules": [rule]}}})


def test_unknown_vital_in_table_rejected():
    table = ThresholdTable.from_dict(
        {"sources": {"T": {}}, "vitals": {"temp": {"rules": [{"id": "R", "band": "normal", "min": 1, "source": "T"}]}}}
    )
    with pytest.raises(ValueError, match="not in VitalSigns"):
        ThresholdEngine(table)


def test_evaluate_is_well_within_latency_budget(engine):
    vitals = VitalSigns(hr=88.4, spo2=93.2, sbp=142, dbp=91, resp=22.6)
    n = 20_000
    start = time.perf_counter()
    for _ in range(n):
        engine.evaluate(vitals)
    assert (time.perf_counter() - start) * 1000 / n < 1.0
