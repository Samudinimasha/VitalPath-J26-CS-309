"""Detection scenarios S1-S12 (proposal Table 6) through the full pipeline.

Packets are sealed with the AES-GCM stand-in for Component 2 and sent
through rate limiting, replay detection, decryption, threshold, correlation
and hybrid scoring, exactly as at runtime.
"""

import dataclasses
import json
import time

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vitalpath_c3.crypto.payload_encryption import PayloadDecryptor, seal
from vitalpath_c3.engines.flood_rate_limiter import RateLimiter
from vitalpath_c3.engines.replay import ReplayDetectionEngine
from vitalpath_c3.packet_models import EncryptedPacket, PacketHeader, VitalSigns
from vitalpath_c3.detection_pipeline import Pipeline

T0 = 1_800_000_000.0
KEY = AESGCM.generate_key(bit_length=256)
DEVICE = "amb-01"
NORMAL = VitalSigns(hr=75, pulse=74, spo2=98, sbp=120, dbp=78, resp=14)


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> float:
        return self.now


class CountingDecryptor(PayloadDecryptor):
    """Records how often decryption is attempted (S12)."""

    def __init__(self) -> None:
        super().__init__(lambda device: {DEVICE: KEY}[device])
        self.calls = 0

    def decrypt(self, packet):
        self.calls += 1
        return super().decrypt(packet)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def decryptor() -> CountingDecryptor:
    return CountingDecryptor()


@pytest.fixture
def pipeline(clock, decryptor) -> Pipeline:
    return Pipeline(
        decryptor,
        rate_limiter=RateLimiter(clock=clock),
        replay=ReplayDetectionEngine(clock=clock),
        clock=clock,
    )


CASE = "CASE001"


def packet(n, vitals=NORMAL, ts=None):
    """Genuine sealed packet whose packet ID counter is n (PKT-00000n)."""
    return seal(PacketHeader(DEVICE, f"PKT-{n:06d}", T0 if ts is None else ts, CASE), vitals, KEY)


def stream(pipeline, clock, numbers, interval=1.0):
    """Send a legitimate stream at 1 Hz."""
    for n in numbers:
        r = pipeline.process(packet(n, ts=clock.now))
        assert r.summary.decision == "ACCEPT", r.explain()
        clock.now += interval


def outcome(result):
    return result.summary.decision, result.summary.label


def test_s1_legitimate_packet_accepted(pipeline):
    r = pipeline.process(packet(1))
    assert outcome(r) == ("ACCEPT", "Normal")
    assert r.summary.rules == ()


def test_s2_replayed_packet_discarded(pipeline):
    original = packet(1)
    pipeline.process(original)
    r = pipeline.process(original)
    assert outcome(r) == ("DISCARD", None)
    assert r.summary.rules == ("R-REPLAY-DUPLICATE",)


def test_s3_pre_handover_packet_after_reconnect_discarded(pipeline, clock):
    captured = packet(5, ts=T0 + 4)
    stream(pipeline, clock, range(1, 11))
    clock.now += 3  # handover gap
    stream(pipeline, clock, [11])
    r = pipeline.process(captured)
    assert outcome(r) == ("DISCARD", None)
    assert r.summary.rules == ("R-REPLAY-DUPLICATE",)


def test_s4_correct_next_packet_after_handover_accepted(pipeline, clock):
    stream(pipeline, clock, range(1, 11))
    clock.now += 3  # handover gap
    r = pipeline.process(packet(11, ts=clock.now))
    assert outcome(r) == ("ACCEPT", "Normal")


def test_s5_impossible_heart_rate_flagged_and_forwarded(pipeline):
    r = pipeline.process(packet(1, dataclasses.replace(NORMAL, hr=300, pulse=300)))
    assert outcome(r) == ("FLAG", "Flagged")
    assert "R-HR-CRIT-HIGH" in r.summary.rules


def test_s6_spo2_inconsistent_with_normal_hr_flagged(pipeline):
    r = pipeline.process(packet(1, VitalSigns(hr=64.0, pulse=72.3, spo2=13.9)))
    assert outcome(r) == ("FLAG", "Flagged")
    assert "R-CORR-SPO2-HR" in r.summary.rules


def test_s7_slightly_elevated_hr_borderline_not_discarded(pipeline):
    r = pipeline.process(packet(1, dataclasses.replace(NORMAL, hr=112, pulse=111)))
    assert outcome(r) == ("FLAG", "Borderline")


def test_s8_flood_of_fifty_in_one_second(pipeline, clock):
    results = []
    for n in range(1, 51):
        results.append(pipeline.process(packet(n, ts=clock.now)))
        clock.now += 0.02
    discarded = [r for r in results if r.summary.rules == ("R-RATE-LIMIT",)]
    assert len(discarded) == 30
    assert sum(r.summary.decision == "ACCEPT" for r in results) == 20


def test_s9_corrupted_timestamp_discarded(pipeline, decryptor):
    good = packet(1)
    bad = EncryptedPacket(dataclasses.replace(good.header, timestamp="corrupted"), good.payload)
    r = pipeline.process(bad)
    assert outcome(r) == ("DISCARD", None)
    assert r.summary.rules == ("R-MALFORMED-HEADER",)
    assert decryptor.calls == 0


def test_s10_authentic_packet_id_jump_flagged(pipeline, clock):
    stream(pipeline, clock, range(1, 4))
    r = pipeline.process(packet(50_000, ts=clock.now))
    assert outcome(r) == ("FLAG", "Flagged")
    assert r.summary.rules[0] == "R-PACKET-JUMP"
    # It decrypted authentically, so the window moved and the stream continues.
    r = pipeline.process(packet(50_001, ts=clock.now))
    assert outcome(r) == ("ACCEPT", "Normal")


def test_s10_forged_packet_id_jump_discarded_without_lockout(pipeline, clock):
    stream(pipeline, clock, range(1, 4))
    genuine = packet(50_000, ts=clock.now)
    forged = EncryptedPacket(genuine.header, b"\x00" * len(genuine.payload))
    r = pipeline.process(forged)
    assert outcome(r) == ("DISCARD", None)
    assert r.summary.rules == ("R-DECRYPT-FAILED",)
    stream(pipeline, clock, range(4, 8))


def test_s11_replayed_impossible_value_discarded_before_analysis(pipeline, decryptor):
    original = packet(1, dataclasses.replace(NORMAL, hr=300, pulse=300))
    pipeline.process(original)
    calls_before = decryptor.calls
    r = pipeline.process(original)
    assert outcome(r) == ("DISCARD", None)
    assert r.summary.rules == ("R-REPLAY-DUPLICATE",)
    assert r.decision is None  # threshold and correlation never ran
    assert decryptor.calls == calls_before


def test_s12_replayed_packet_never_decrypted(pipeline, decryptor, clock):
    stream(pipeline, clock, range(1, 6))
    assert decryptor.calls == 5
    for n in range(1, 6):
        r = pipeline.process(packet(n, ts=T0 + n - 1))
        assert r.summary.decision == "DISCARD"
        assert not r.decrypted
    assert decryptor.calls == 5


# --- Beyond Table 6 ----------------------------------------------------------


def test_tampered_payload_discarded_and_does_not_burn_packet_id(pipeline):
    genuine = packet(1)
    payload = bytearray(genuine.payload)
    payload[20] ^= 0xFF
    r = pipeline.process(EncryptedPacket(genuine.header, bytes(payload)))
    assert r.summary.rules == ("R-DECRYPT-FAILED",)
    # The genuine packet with the same packet ID still gets through.
    assert outcome(pipeline.process(genuine)) == ("ACCEPT", "Normal")


def test_replay_verdict_kept_for_each_packet(pipeline, clock):
    stream(pipeline, clock, [1])
    assert pipeline.process(packet(2, ts=clock.now)).replay.passed
    replayed = pipeline.process(packet(2, ts=clock.now))
    assert not replayed.replay.passed
    flood = [pipeline.process(packet(n, ts=clock.now)) for n in range(10, 40)]
    assert flood[-1].replay is None  # stopped by the flood guard before the replay check


def test_results_carry_case_id(pipeline):
    accepted = pipeline.process(packet(1)).summary
    discarded = pipeline.process(packet(1)).summary  # replay
    assert accepted.case_id == discarded.case_id == "CASE001"
    assert (accepted.decision, discarded.decision) == ("ACCEPT", "DISCARD")


def test_component2_style_packet_ids_end_to_end(pipeline):
    """Packets using Component 2's own packet_id style (mimic_00001 ...)."""
    def c2_packet(n):
        return seal(PacketHeader(DEVICE, f"mimic_{n:05d}", T0, CASE), NORMAL, KEY)

    first = c2_packet(1)
    r = pipeline.process(first)
    assert outcome(r) == ("ACCEPT", "Normal")
    assert r.summary.packet_id == "mimic_00001"
    assert outcome(pipeline.process(c2_packet(2))) == ("ACCEPT", "Normal")
    r = pipeline.process(first)
    assert r.summary.rules == ("R-REPLAY-DUPLICATE",)
    assert r.summary.packet_id == "mimic_00001"


def test_relabelling_packet_with_another_case_is_discarded(pipeline):
    """An attacker cannot file a patient's readings under another case."""
    genuine = packet(1)
    relabelled = EncryptedPacket(dataclasses.replace(genuine.header, case_id="CASE002"), genuine.payload)
    r = pipeline.process(relabelled)
    assert r.summary.rules == ("R-DECRYPT-FAILED",)
    assert outcome(pipeline.process(genuine)) == ("ACCEPT", "Normal")


def test_end_to_end_latency_under_20ms(pipeline, clock):
    latencies = []
    for n in range(1, 501):
        clock.now += 0.1
        latencies.append(pipeline.process(packet(n, ts=clock.now)).latency_ms)
    latencies.sort()
    assert latencies[int(len(latencies) * 0.99)] < 20.0
