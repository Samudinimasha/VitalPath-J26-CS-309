"""Component 3 staged detection pipeline.

    1. Rate limiter            flood          -> DISCARD (R-RATE-LIMIT)
    2. Replay Detection        header only    -> DISCARD on replay / bad header
    3. Decrypt payload         only if fresh  -> DISCARD if not authentic
       ... replay window committed only now, after authentication
    4. Threshold + Correlation on decrypted vitals
    5. Hybrid Decision         -> ACCEPT 'Normal' or FLAG 'Borderline'/'Flagged'
    6. Summary of the decision (case, device, packet ID, label, score, rules)

Discards happen only for factual findings (flood, replay, malformed header,
unauthentic payload), never because of what the vital signs say.
"""

import time
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from vitalpath_c3.crypto.payload_encryption import PayloadDecryptor, PayloadError
from vitalpath_c3.engines.correlation import CorrelationEngine, CorrelationResult
from vitalpath_c3.engines.hybrid import Decision, HybridDecisionEngine
from vitalpath_c3.engines.flood_rate_limiter import RateLimiter, RateLimitVerdict
from vitalpath_c3.engines.replay import ReplayDetectionEngine, ReplayOutcome, ReplayVerdict
from vitalpath_c3.engines.threshold import ThresholdEngine, ThresholdResult
from vitalpath_c3.packet_models import EncryptedPacket, VitalSigns
from vitalpath_c3.rule_ids import Rule


@dataclass(frozen=True)
class Summary:
    """The outcome for one packet: which packet, what was decided and why."""

    device_id: object
    packet_id: object
    case_id: object
    decision: str  # ACCEPT, FLAG or DISCARD
    label: Optional[str]  # Normal, Borderline or Flagged; None when discarded
    score: Optional[int]
    rules: Tuple[str, ...]


@dataclass(frozen=True)
class PipelineResult:
    summary: Summary
    decision: Optional[Decision]  # None when the packet was discarded
    detail: str
    latency_ms: float
    decrypted: bool
    # Each stage's own result, for explaining a decision step by step. A stage
    # that was never reached is None.
    rate_limit: Optional[RateLimitVerdict] = None
    replay: Optional[ReplayVerdict] = None
    vitals: Optional[VitalSigns] = None
    threshold: Optional[ThresholdResult] = None
    correlation: Optional[CorrelationResult] = None

    def explain(self) -> str:
        if self.decision is not None:
            return self.decision.explain()
        return f"DISCARD ({self.summary.rules[0]}): {self.detail}"


class Pipeline:
    def __init__(
        self,
        decryptor: PayloadDecryptor,
        rate_limiter: Optional[RateLimiter] = None,
        replay: Optional[ReplayDetectionEngine] = None,
        threshold: Optional[ThresholdEngine] = None,
        correlation: Optional[CorrelationEngine] = None,
        hybrid: Optional[HybridDecisionEngine] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.decryptor = decryptor
        self.rate_limiter = rate_limiter or RateLimiter()
        self.replay = replay or ReplayDetectionEngine(clock=clock)
        self.threshold = threshold or ThresholdEngine()
        self.correlation = correlation or CorrelationEngine()
        self.hybrid = hybrid or HybridDecisionEngine()

    def process(self, packet: EncryptedPacket) -> PipelineResult:
        start = time.perf_counter()
        header = packet.header
        device_id = getattr(header, "device_id", None)

        stages = {}
        admitted = stages["rate_limit"] = self.rate_limiter.admit(device_id)
        if not admitted.allowed:
            return self._finish(start, packet, None, admitted.rule, admitted.detail, False, stages)

        replay = stages["replay"] = self.replay.check(header, commit=False)
        if not replay.passed:
            return self._finish(start, packet, None, replay.rule, replay.detail, False, stages)

        try:
            vitals = stages["vitals"] = self.decryptor.decrypt(packet)
        except PayloadError as err:
            return self._finish(start, packet, None, err.rule, err.detail, True, stages)

        # Authentic: only now does the packet use up its packet ID.
        if not self.replay.commit(header):
            return self._finish(
                start, packet, None, Rule.REPLAY_DUPLICATE, "identical packet already processed", True, stages
            )
        if replay.outcome is ReplayOutcome.ACCEPT_FLAGGED:
            self.replay.confirm_jump(header.device_id, header.number)

        threshold = stages["threshold"] = self.threshold.evaluate(vitals)
        correlation = stages["correlation"] = self.correlation.evaluate(vitals)
        decision = self.hybrid.decide(replay, threshold, correlation)
        return self._finish(start, packet, decision, None, "", True, stages)

    def _finish(self, start, packet, decision, discard_rule, detail, decrypted, stages) -> PipelineResult:
        header = packet.header
        device_id = getattr(header, "device_id", None)
        packet_id = getattr(header, "packet_id", None)
        case_id = getattr(header, "case_id", None)
        if decision is None:
            summary = Summary(device_id, packet_id, case_id, "DISCARD", None, None, (discard_rule.value,))
        else:
            summary = Summary(
                device_id,
                packet_id,
                case_id,
                decision.outcome.value,
                decision.label,
                decision.score,
                tuple(c.rule for c in decision.contributions),
            )
        latency_ms = (time.perf_counter() - start) * 1000
        return PipelineResult(summary, decision, detail, latency_ms, decrypted, **stages)
