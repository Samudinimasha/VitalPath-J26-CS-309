"""Unit tests for the Replay Detection Engine (WBS T9).

Scenario IDs refer to Table 6 of the Component 3 proposal.
"""

import time

import pytest

from vitalpath_c3.config import ReplayConfig
from vitalpath_c3.engines.replay import ReplayDetectionEngine, ReplayOutcome
from vitalpath_c3.models import SEQ_MAX, PacketHeader
from vitalpath_c3.rules import Rule

T0 = 1_800_000_000.0
DEVICE = "amb-01/ecg"


class FakeClock:
    def __init__(self, now: float = T0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def engine(clock: FakeClock) -> ReplayDetectionEngine:
    return ReplayDetectionEngine(ReplayConfig(), clock=clock)


def hdr(seq, ts=None, device=DEVICE) -> PacketHeader:
    return PacketHeader(device_id=device, seq=seq, timestamp=T0 if ts is None else ts)


def feed(engine, clock, seqs, start_ts=T0, interval=0.1):
    """Send a legitimate stream, advancing the clock with each packet."""
    ts = start_ts
    for seq in seqs:
        clock.now = ts
        verdict = engine.check(hdr(seq, ts))
        assert verdict.outcome is ReplayOutcome.ACCEPT, verdict
        ts += interval
    return ts - interval


# --- Acceptance -------------------------------------------------------------


def test_first_packet_accepted(engine):
    v = engine.check(hdr(0))
    assert v.outcome is ReplayOutcome.ACCEPT
    assert v.rule is Rule.REPLAY_ACCEPT
    assert v.passed


def test_first_packet_may_start_at_any_sequence(engine):
    assert engine.check(hdr(123_456)).outcome is ReplayOutcome.ACCEPT


def test_in_order_stream_accepted(engine, clock):
    feed(engine, clock, range(1, 2001))


def test_gap_in_sequence_within_jump_cap_accepted(engine, clock):
    feed(engine, clock, [1])
    assert engine.check(hdr(1 + 1024, T0 + 0.1)).outcome is ReplayOutcome.ACCEPT


def test_out_of_order_packet_within_window_accepted(engine, clock):
    feed(engine, clock, [1, 2, 4, 5])
    v = engine.check(hdr(3, clock.now))
    assert v.outcome is ReplayOutcome.ACCEPT
    assert v.rule is Rule.REPLAY_ACCEPT


def test_oldest_slot_in_window_accepted(clock):
    engine = ReplayDetectionEngine(ReplayConfig(window_size=8), clock=clock)
    engine.check(hdr(100))
    # Window covers 93..100; 93 is exactly window_size - 1 behind.
    assert engine.check(hdr(93)).outcome is ReplayOutcome.ACCEPT


def test_devices_have_independent_windows(engine):
    assert engine.check(hdr(7, device="amb-01/ecg")).passed
    assert engine.check(hdr(7, device="amb-01/spo2")).passed
    assert engine.check(hdr(7, device="amb-02/ecg")).passed


# --- Rejection: replay ------------------------------------------------------


def test_duplicate_of_highest_rejected(engine):
    """S2: sequence number already seen within the sliding window."""
    engine.check(hdr(10))
    v = engine.check(hdr(10))
    assert v.outcome is ReplayOutcome.DISCARD
    assert v.rule is Rule.REPLAY_DUPLICATE
    assert not v.passed


def test_duplicate_inside_window_rejected(engine, clock):
    feed(engine, clock, range(1, 51))
    v = engine.check(hdr(25, clock.now))
    assert v.outcome is ReplayOutcome.DISCARD
    assert v.rule is Rule.REPLAY_DUPLICATE


def test_out_of_order_packet_rejected_on_second_delivery(engine, clock):
    feed(engine, clock, [1, 2, 4])
    assert engine.check(hdr(3, clock.now)).passed
    assert engine.check(hdr(3, clock.now)).rule is Rule.REPLAY_DUPLICATE


def test_sequence_older_than_window_rejected(clock):
    engine = ReplayDetectionEngine(ReplayConfig(window_size=8), clock=clock)
    engine.check(hdr(100))
    # 92 is window_size behind: outside the window even though never seen.
    v = engine.check(hdr(92))
    assert v.outcome is ReplayOutcome.DISCARD
    assert v.rule is Rule.REPLAY_OUTSIDE_WINDOW


def test_default_window_is_1024(engine, clock):
    engine.check(hdr(2000))
    assert engine.check(hdr(2000 - 1023)).passed
    assert engine.check(hdr(2000 - 1024)).rule is Rule.REPLAY_OUTSIDE_WINDOW


def test_replay_reported_as_replay_even_if_also_stale(engine, clock):
    engine.check(hdr(5, T0))
    clock.now = T0 + 60
    assert engine.check(hdr(5, T0)).rule is Rule.REPLAY_DUPLICATE


def test_rejected_packet_does_not_change_window(engine, clock):
    feed(engine, clock, [1, 2, 3])
    engine.check(hdr(2, clock.now))  # duplicate
    engine.check(hdr(99, clock.now + 10))  # future timestamp
    assert engine.check(hdr(4, clock.now)).rule is Rule.REPLAY_ACCEPT


# --- Timestamps -------------------------------------------------------------


def test_stale_timestamp_rejected(engine, clock):
    clock.now = T0 + 30.001
    v = engine.check(hdr(1, T0))
    assert v.outcome is ReplayOutcome.DISCARD
    assert v.rule is Rule.TS_STALE


def test_timestamp_at_max_age_accepted(engine, clock):
    clock.now = T0 + 30
    assert engine.check(hdr(1, T0)).passed


def test_future_timestamp_rejected(engine):
    v = engine.check(hdr(1, T0 + 2.001))
    assert v.outcome is ReplayOutcome.DISCARD
    assert v.rule is Rule.TS_FUTURE


def test_timestamp_within_future_skew_accepted(engine):
    assert engine.check(hdr(1, T0 + 2.0)).passed


def test_timestamp_regression_beyond_tolerance_rejected(engine, clock):
    clock.now = T0 + 5
    assert engine.check(hdr(10, T0 + 5)).passed
    v = engine.check(hdr(11, T0 + 3.9))
    assert v.outcome is ReplayOutcome.DISCARD
    assert v.rule is Rule.TS_REGRESSION


def test_timestamp_regression_within_tolerance_accepted(engine, clock):
    clock.now = T0 + 5
    assert engine.check(hdr(10, T0 + 5)).passed
    assert engine.check(hdr(9, T0 + 4.0)).passed


# --- Malformed headers (S9) -------------------------------------------------


@pytest.mark.parametrize(
    "header",
    [
        None,
        PacketHeader(device_id=DEVICE, seq=1, timestamp=None),
        PacketHeader(device_id=DEVICE, seq=1, timestamp="1800000000"),
        PacketHeader(device_id=DEVICE, seq=1, timestamp=float("nan")),
        PacketHeader(device_id=DEVICE, seq=1, timestamp=float("inf")),
        PacketHeader(device_id=DEVICE, seq=1, timestamp=True),
        PacketHeader(device_id=DEVICE, seq=None, timestamp=T0),
        PacketHeader(device_id=DEVICE, seq=1.0, timestamp=T0),
        PacketHeader(device_id=DEVICE, seq=True, timestamp=T0),
        PacketHeader(device_id=DEVICE, seq=-1, timestamp=T0),
        PacketHeader(device_id=DEVICE, seq=SEQ_MAX + 1, timestamp=T0),
        PacketHeader(device_id="", seq=1, timestamp=T0),
        PacketHeader(device_id=None, seq=1, timestamp=T0),
    ],
)
def test_malformed_header_discarded(engine, header):
    v = engine.check(header)
    assert v.outcome is ReplayOutcome.DISCARD
    assert v.rule is Rule.MALFORMED_HEADER


def test_max_sequence_value_accepted(engine):
    assert engine.check(hdr(SEQ_MAX)).passed


# --- Sequence jump (S10) ----------------------------------------------------


def test_large_jump_flagged_and_window_not_advanced(engine, clock):
    feed(engine, clock, range(1, 11))
    v = engine.check(hdr(10 + 1025, clock.now))
    assert v.outcome is ReplayOutcome.ACCEPT_FLAGGED
    assert v.rule is Rule.SEQ_JUMP
    assert v.passed
    # Legitimate stream continues unaffected.
    assert engine.check(hdr(11, clock.now)).rule is Rule.REPLAY_ACCEPT


def test_replay_of_flagged_jump_packet_rejected(engine, clock):
    feed(engine, clock, [1])
    engine.check(hdr(5000, clock.now))
    assert engine.check(hdr(5000, clock.now)).rule is Rule.REPLAY_DUPLICATE


def test_jump_confirmed_by_next_packet_resynchronises(engine, clock):
    feed(engine, clock, [1])
    assert engine.check(hdr(5000, clock.now)).rule is Rule.SEQ_JUMP
    v = engine.check(hdr(5001, clock.now))
    assert v.outcome is ReplayOutcome.ACCEPT
    assert v.rule is Rule.SEQ_RESYNC
    # Both packets are now inside the window and cannot be replayed.
    assert engine.check(hdr(5000, clock.now)).rule is Rule.REPLAY_DUPLICATE
    assert engine.check(hdr(5001, clock.now)).rule is Rule.REPLAY_DUPLICATE
    # The pre-jump position is now far outside the window.
    assert engine.check(hdr(2, clock.now)).rule is Rule.REPLAY_OUTSIDE_WINDOW


def test_flagged_packet_recorded_when_stream_catches_up(clock):
    engine = ReplayDetectionEngine(ReplayConfig(max_seq_jump=10), clock=clock)
    feed(engine, clock, [1])
    assert engine.check(hdr(20, clock.now)).rule is Rule.SEQ_JUMP
    feed(engine, clock, range(2, 20), start_ts=clock.now)
    engine.check(hdr(21, clock.now))
    assert engine.check(hdr(20, clock.now)).rule is Rule.REPLAY_DUPLICATE


# --- 5G handover / reconnection (S3, S4, FR2) --------------------------------


def test_handover_next_sequence_after_gap_accepted(engine, clock):
    """S4: legitimate packet right after a handover gap, correct next seq."""
    last_ts = feed(engine, clock, range(1, 101))
    # Connection drops for 3 s while the ambulance changes cell.
    clock.now = last_ts + 3.0
    v = engine.check(hdr(101, clock.now))
    assert v.outcome is ReplayOutcome.ACCEPT
    assert v.rule is Rule.REPLAY_ACCEPT


def test_handover_with_packets_lost_during_gap_accepted(engine, clock):
    """Packets 101-104 lost during handover; stream resumes at 105."""
    last_ts = feed(engine, clock, range(1, 101))
    clock.now = last_ts + 3.0
    assert engine.check(hdr(105, clock.now)).passed
    # A lost packet that is later retransmitted is still accepted once.
    assert engine.check(hdr(102, clock.now)).passed
    assert engine.check(hdr(102, clock.now)).rule is Rule.REPLAY_DUPLICATE


def test_handover_replay_of_pre_reconnection_packet_rejected(engine, clock):
    """S3: after handover, attacker resends a packet captured before it."""
    last_ts = feed(engine, clock, range(1, 101))
    clock.now = last_ts + 3.0
    assert engine.check(hdr(101, clock.now)).passed
    captured = hdr(95, T0 + 94 * 0.1)
    v = engine.check(captured)
    assert v.outcome is ReplayOutcome.DISCARD
    assert v.rule is Rule.REPLAY_DUPLICATE


def test_handover_replay_with_refreshed_timestamp_rejected(engine, clock):
    """Attacker rewrites the clear-text timestamp; sequence still catches it."""
    last_ts = feed(engine, clock, range(1, 101))
    clock.now = last_ts + 3.0
    assert engine.check(hdr(95, clock.now)).rule is Rule.REPLAY_DUPLICATE


def test_window_persists_across_handover(engine, clock):
    """FR2: state is keyed by device, so a reconnection does not reset it."""
    feed(engine, clock, range(1, 11))
    clock.now += 5.0  # reconnection
    assert engine.check(hdr(1, clock.now)).rule is Rule.REPLAY_DUPLICATE
    assert engine.check(hdr(11, clock.now)).passed


# --- Configuration and performance ------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"window_size": 0},
        {"max_seq_jump": 0},
        {"max_age_s": -1},
        {"future_skew_s": -1},
        {"backward_tolerance_s": -1},
    ],
)
def test_invalid_config_rejected(kwargs):
    with pytest.raises(ValueError):
        ReplayConfig(**kwargs)


def test_check_is_well_within_latency_budget(clock):
    engine = ReplayDetectionEngine(ReplayConfig(), clock=clock)
    n = 20_000
    start = time.perf_counter()
    for seq in range(n):
        engine.check(hdr(seq))
    per_packet_ms = (time.perf_counter() - start) * 1000 / n
    # The whole pipeline has 20 ms; the replay gate should use a tiny fraction.
    assert per_packet_ms < 1.0
