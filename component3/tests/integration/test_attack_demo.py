"""Smoke tests for the attack demonstration, so it cannot break before a presentation."""

import pytest

from simulator.attack_demo import SCENARIOS, Demo, strip_colour


@pytest.fixture
def run():
    def _run(name):
        lines = []
        demo = Demo(out=lines.append)
        getattr(demo, name)()
        return strip_colour("\n".join(lines))
    return _run


def decisions(text):
    return [line for line in text.splitlines() if "Decision" in line]


def last_packet_delivered(text):
    return "delivered" in decisions(text)[-1]


@pytest.mark.parametrize("name", [name for _, _, name in SCENARIOS])
def test_every_scenario_runs(run, name):
    assert "Decision" in run(name) or "FLOOD" in run(name) or "Ten normal" in run(name)


def test_replay_is_discarded_before_decryption(run):
    text = run("replay")
    assert "REJECTED" in text and "R-REPLAY-DUPLICATE" in text
    assert "Payload never decrypted" in text


def test_handover_replay_rejected_then_real_packet_accepted(run):
    text = run("handover")
    assert "DISCARD" in decisions(text)[0]
    assert last_packet_delivered(text)


def test_tamper_fails_decryption_then_original_accepted(run):
    text = run("tamper")
    assert "R-DECRYPT-FAILED" in text
    assert last_packet_delivered(text)


def test_fake_jump_discarded_and_stream_continues(run):
    text = run("jump")
    assert "suspicious jump" in text and "R-DECRYPT-FAILED" in text
    assert last_packet_delivered(text)


def test_case_swap_is_discarded_then_original_delivered(run):
    text = run("case_swap")
    assert "case CASE002" in text and "R-DECRYPT-FAILED" in text
    assert last_packet_delivered(text)


def test_heart_rate_300_flagged_not_discarded(run):
    text = run("heart_rate_300")
    assert "HR 300 bpm → CRITICAL" in text
    assert "FLAG 'Flagged'" in text and "DISCARD" not in text


def test_sensor_fault_caught_by_correlation(run):
    text = run("sensor_fault")
    assert "INCONSISTENT" in text and "R-CORR-SPO2-HR" in text


def test_shock_pattern_caught_by_correlation(run):
    text = run("shock")
    assert "CONCERNING" in text and "R-CORR-SHOCK-INDEX" in text
    assert "FLAG 'Flagged'" in text


def test_flood_blocks_thirty(run):
    assert "30 BLOCKED" in run("flood")
