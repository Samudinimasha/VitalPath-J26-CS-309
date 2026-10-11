"""Component 3 staged detection pipeline.

    1. Rate limiter            flood          -> DISCARD (R-RATE-LIMIT)
    2. Replay Detection        header only    -> DISCARD on replay / bad header
    3. Decrypt payload         only if fresh  -> DISCARD if not authentic
       ... replay window committed only now, after authentication
    4. Threshold + Correlation on decrypted vitals
    5. Hybrid Decision         -> ACCEPT 'Normal' or FLAG 'Borderline'/'Flagged'
    6. Signed decision record  -> sink for Component 4 (no raw vitals)

Discards happen only for factual findings (flood, replay, malformed header,
unauthentic payload), never because of what the vital signs say.
"""

import time
from dataclasses import dataclass
from typing import Callable, Optional

from vitalpath_c3.crypto.payload import PayloadDecryptor, PayloadError
from vitalpath_c3.engines.correlation import CorrelationEngine
from vitalpath_c3.engines.hybrid import Decision, HybridDecisionEngine
from vitalpath_c3.engines.rate_limiter import RateLimiter
from vitalpath_c3.engines.replay import ReplayDetectionEngine, ReplayOutcome
from vitalpath_c3.engines.threshold import ThresholdEngine
from vitalpath_c3.models import EncryptedPacket
from vitalpath_c3.output.decision_record import DecisionRecord, MemorySink, RecordSigner
from vitalpath_c3.rules import Rule


@dataclass(frozen=True)
class PipelineResult:
    record: DecisionRecord
    decision: Optional[Decision]  # None when the packet was discarded
    detail: str
    latency_ms: float
    decrypted: bool

    def explain(self) -> str:
        if self.decision is not None:
            return self.decision.explain()
        return f"DISCARD ({self.record.rules[0]}): {self.detail}"


class Pipeline:
    def __init__(
        self,
        decryptor: PayloadDecryptor,
        signer: RecordSigner,
        sink=None,
        rate_limiter: Optional[RateLimiter] = None,
        replay: Optional[ReplayDetectionEngine] = None,
        threshold: Optional[ThresholdEngine] = None,
        correlation: Optional[CorrelationEngine] = None,
        hybrid: Optional[HybridDecisionEngine] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.decryptor = decryptor
        self.signer = signer
        self.sink = sink if sink is not None else MemorySink()
        self.rate_limiter = rate_limiter or RateLimiter()
        self.replay = replay or ReplayDetectionEngine(clock=clock)
        self.threshold = threshold or ThresholdEngine()
        self.correlation = correlation or CorrelationEngine()
        self.hybrid = hybrid or HybridDecisionEngine()
        self._clock = clock

    def process(self, packet: EncryptedPacket) -> PipelineResult:
        start = time.perf_counter()
        header = packet.header
        device_id = getattr(header, "device_id", None)

        admitted = self.rate_limiter.admit(device_id)
        if not admitted.allowed:
            return self._finish(start, packet, None, admitted.rule, admitted.detail, decrypted=False)

        replay = self.replay.check(header, commit=False)
        if not replay.passed:
            return self._finish(start, packet, None, replay.rule, replay.detail, decrypted=False)

        try:
            vitals = self.decryptor.decrypt(packet)
        except PayloadError as err:
            return self._finish(start, packet, None, err.rule, err.detail, decrypted=True)

        # Authentic: only now does the packet use up its sequence number.
        if not self.replay.commit(header):
            return self._finish(
                start, packet, None, Rule.REPLAY_DUPLICATE, "identical packet already processed", decrypted=True
            )
        if replay.outcome is ReplayOutcome.ACCEPT_FLAGGED:
            self.replay.confirm_jump(header.device_id, header.seq)

        decision = self.hybrid.decide(
            replay, self.threshold.evaluate(vitals), self.correlation.evaluate(vitals)
        )
        return self._finish(start, packet, decision, None, "", decrypted=True)

    def _finish(self, start, packet, decision, discard_rule, detail, decrypted) -> PipelineResult:
        header = packet.header
        if decision is None:
            record = DecisionRecord(
                device_id=getattr(header, "device_id", None),
                seq=getattr(header, "seq", None),
                received_at=self._clock(),
                decision="DISCARD",
                label=None,
                score=None,
                rules=(discard_rule.value,),
            )
        else:
            record = DecisionRecord(
                device_id=header.device_id,
                seq=header.seq,
                received_at=self._clock(),
                decision=decision.outcome.value,
                label=decision.label,
                score=decision.score,
                rules=tuple(c.rule for c in decision.contributions),
            )
        record = self.signer.sign(record)
        self.sink.append(record)
        latency_ms = (time.perf_counter() - start) * 1000
        return PipelineResult(record, decision, detail, latency_ms, decrypted)
