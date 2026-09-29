"""Replay Detection Engine (WBS T9).

First-stage gate of Component 3. It reads only the clear-text header
(device ID, sequence number, timestamp) and never touches the encrypted
payload, so a packet discarded here is never decrypted.

Per device, the engine keeps an anti-replay window in the style of DTLS
(RFC 6347 s4.1.2.6) and IPsec (RFC 4303 s3.4.3): the highest accepted
sequence number plus a bitmap of which of the ``window_size`` sequence
numbers behind it have been accepted. State is keyed by device ID rather than
by transport session, so the window persists across a 5G handover (FR2).

Checks, in order, each tied to a named rule:

1. Header well-formed                          -> R-MALFORMED-HEADER   (S9)
2. Sequence number not already accepted        -> R-REPLAY-DUPLICATE   (S2, S3)
3. Sequence number not older than the window   -> R-REPLAY-OUTSIDE-WINDOW
4. Timestamp not older than ``max_age_s``      -> R-TS-STALE
5. Timestamp not ahead by more than skew       -> R-TS-FUTURE
6. Timestamp not behind newest by > tolerance  -> R-TS-REGRESSION
7. Forward jump no larger than ``max_seq_jump`` -> R-SEQ-JUMP (flag)   (S10)

Replay checks (2, 3) run before timestamp checks so that a resent packet is
reported as a replay even when its timestamp has also gone stale.
"""

import logging
import math
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, Optional

from vitalpath_c3.config import ReplayConfig
from vitalpath_c3.models import SEQ_MAX, PacketHeader
from vitalpath_c3.rules import Rule

logger = logging.getLogger(__name__)


class ReplayOutcome(str, Enum):
    ACCEPT = "ACCEPT"
    # Passed the replay gate but carries a flag for the Hybrid Decision Engine.
    ACCEPT_FLAGGED = "ACCEPT_FLAGGED"
    DISCARD = "DISCARD"


@dataclass(frozen=True)
class ReplayVerdict:
    outcome: ReplayOutcome
    rule: Rule
    device_id: object
    seq: object
    detail: str = ""

    @property
    def passed(self) -> bool:
        """True if the packet may proceed to decryption."""
        return self.outcome is not ReplayOutcome.DISCARD


@dataclass
class _DeviceWindow:
    highest_seq: int
    # Bit i set means sequence number (highest_seq - i) has been accepted.
    bitmap: int
    highest_ts: float
    # Sequence number of the most recent packet flagged for an excessive jump.
    # It is not merged into the window unless the next packet confirms it.
    pending_jump_seq: Optional[int] = None


class ReplayDetectionEngine:
    def __init__(
        self,
        config: Optional[ReplayConfig] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config or ReplayConfig()
        self._clock = clock
        self._mask = (1 << self.config.window_size) - 1
        self._windows: Dict[str, _DeviceWindow] = {}

    def check(self, header: PacketHeader) -> ReplayVerdict:
        """Validate a packet header and update the device's window if accepted.

        Rejected packets leave the window unchanged.
        """
        problem = _malformed_reason(header)
        if problem:
            return self._discard(header, Rule.MALFORMED_HEADER, problem)

        device_id: str = header.device_id
        seq: int = header.seq
        ts = float(header.timestamp)
        window = self._windows.get(device_id)

        if window is not None:
            offset = window.highest_seq - seq
            if offset >= self.config.window_size:
                return self._discard(
                    header,
                    Rule.REPLAY_OUTSIDE_WINDOW,
                    f"seq {seq} is {offset} behind highest {window.highest_seq}",
                )
            if (offset >= 0 and window.bitmap >> offset & 1) or seq == window.pending_jump_seq:
                return self._discard(header, Rule.REPLAY_DUPLICATE, f"seq {seq} already seen")

        freshness = self._check_freshness(header, ts)
        if freshness is not None:
            return freshness

        if window is None:
            self._windows[device_id] = _DeviceWindow(highest_seq=seq, bitmap=1, highest_ts=ts)
            return _accept(header, Rule.REPLAY_ACCEPT, "first packet for device")

        if ts < window.highest_ts - self.config.backward_tolerance_s:
            return self._discard(
                header,
                Rule.TS_REGRESSION,
                f"timestamp {window.highest_ts - ts:.3f}s behind newest accepted",
            )

        if seq < window.highest_seq:
            # Late but unseen packet inside the window (out-of-order delivery).
            window.bitmap |= 1 << (window.highest_seq - seq)
            return _accept(header, Rule.REPLAY_ACCEPT, "out-of-order within window")

        jump = seq - window.highest_seq
        if jump > self.config.max_seq_jump:
            pending = window.pending_jump_seq
            if pending is not None and 0 < seq - pending <= self.config.max_seq_jump:
                # Two consecutive packets agree on the new position: treat the
                # earlier flagged packet as confirmed and resynchronise.
                self._advance(window, pending, window.highest_ts)
                self._advance(window, seq, ts)
                return _accept(
                    header, Rule.SEQ_RESYNC, f"resynchronised after jump to {pending}"
                )
            window.pending_jump_seq = seq
            logger.warning("Sequence jump: device=%s seq=%s jump=%d", device_id, seq, jump)
            return ReplayVerdict(
                ReplayOutcome.ACCEPT_FLAGGED,
                Rule.SEQ_JUMP,
                device_id,
                seq,
                f"jump of {jump} exceeds {self.config.max_seq_jump}; window not advanced",
            )

        self._advance(window, seq, ts)
        return _accept(header, Rule.REPLAY_ACCEPT, "in sequence")

    def _check_freshness(self, header: PacketHeader, ts: float) -> Optional[ReplayVerdict]:
        now = self._clock()
        if now - ts > self.config.max_age_s:
            return self._discard(header, Rule.TS_STALE, f"packet is {now - ts:.3f}s old")
        if ts - now > self.config.future_skew_s:
            return self._discard(header, Rule.TS_FUTURE, f"packet is {ts - now:.3f}s in the future")
        return None

    def _advance(self, window: _DeviceWindow, seq: int, ts: float) -> None:
        """Slide the window forward so that ``seq`` becomes the highest accepted."""
        shift = seq - window.highest_seq
        window.bitmap = ((window.bitmap << shift) | 1) & self._mask
        window.highest_seq = seq
        window.highest_ts = max(window.highest_ts, ts)
        pending = window.pending_jump_seq
        if pending is not None and pending <= seq:
            # The regular stream has caught up with the flagged packet; record
            # it as seen so it cannot be replayed later.
            offset = seq - pending
            if offset < self.config.window_size:
                window.bitmap |= 1 << offset
            window.pending_jump_seq = None

    def _discard(self, header: PacketHeader, rule: Rule, detail: str) -> ReplayVerdict:
        verdict = ReplayVerdict(
            ReplayOutcome.DISCARD,
            rule,
            getattr(header, "device_id", None),
            getattr(header, "seq", None),
            detail,
        )
        logger.warning(
            "Replay gate discard: rule=%s device=%s seq=%s (%s)",
            rule.value,
            verdict.device_id,
            verdict.seq,
            detail,
        )
        return verdict


def _accept(header: PacketHeader, rule: Rule, detail: str) -> ReplayVerdict:
    return ReplayVerdict(ReplayOutcome.ACCEPT, rule, header.device_id, header.seq, detail)


def _malformed_reason(header: object) -> Optional[str]:
    if not isinstance(header, PacketHeader):
        return "header missing or not a PacketHeader"
    if not isinstance(header.device_id, str) or not header.device_id:
        return "device_id must be a non-empty string"
    # bool is a subclass of int; exclude it explicitly.
    if not isinstance(header.seq, int) or isinstance(header.seq, bool):
        return "seq must be an integer"
    if not 0 <= header.seq <= SEQ_MAX:
        return "seq outside unsigned 64-bit range"
    ts = header.timestamp
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        return "timestamp must be numeric"
    if not math.isfinite(ts):
        return "timestamp must be finite"
    return None
