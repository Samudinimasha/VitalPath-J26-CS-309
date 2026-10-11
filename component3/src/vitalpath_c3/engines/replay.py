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

A flagged jump never moves the window by itself; see ``confirm_jump``.

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
    # It is merged into the window only through confirm_jump().
    pending_jump_seq: Optional[int] = None
    pending_jump_ts: float = 0.0


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

    def check(self, header: PacketHeader, commit: bool = True) -> ReplayVerdict:
        """Validate a packet header against the device's window.

        With ``commit=True`` an accepted packet is recorded at once. The
        pipeline passes ``commit=False`` and calls :meth:`commit` only after
        the payload has decrypted and authenticated, so a forged packet can
        never use up a sequence number and get the genuine packet rejected
        later (the same rule as RFC 4303 s3.4.3). Rejected packets never
        change the window.
        """
        verdict = self._evaluate(header)
        if commit and verdict.passed:
            self._record(header)
        return verdict

    def commit(self, header: PacketHeader) -> bool:
        """Record a packet that passed :meth:`check` and has been authenticated.

        The header is re-checked first, so if an identical packet was committed
        in between, this one is not recorded twice. Returns True if recorded.
        """
        if not self._evaluate(header, log=False).passed:
            return False
        self._record(header)
        return True

    def _evaluate(self, header: PacketHeader, log: bool = True) -> ReplayVerdict:
        discard = self._discard if log else _discard_quietly
        problem = _malformed_reason(header)
        if problem:
            return discard(header, Rule.MALFORMED_HEADER, problem)

        seq: int = header.seq
        ts = float(header.timestamp)
        window = self._windows.get(header.device_id)

        if window is not None:
            offset = window.highest_seq - seq
            if offset >= self.config.window_size:
                return discard(
                    header,
                    Rule.REPLAY_OUTSIDE_WINDOW,
                    f"seq {seq} is {offset} behind highest {window.highest_seq}",
                )
            if (offset >= 0 and window.bitmap >> offset & 1) or seq == window.pending_jump_seq:
                return discard(header, Rule.REPLAY_DUPLICATE, f"seq {seq} already seen")

        now = self._clock()
        if now - ts > self.config.max_age_s:
            return discard(header, Rule.TS_STALE, f"packet is {now - ts:.3f}s old")
        if ts - now > self.config.future_skew_s:
            return discard(header, Rule.TS_FUTURE, f"packet is {ts - now:.3f}s in the future")

        if window is None:
            return _accept(header, Rule.REPLAY_ACCEPT, "first packet for device")

        if ts < window.highest_ts - self.config.backward_tolerance_s:
            return discard(
                header,
                Rule.TS_REGRESSION,
                f"timestamp {window.highest_ts - ts:.3f}s behind newest accepted",
            )

        if seq < window.highest_seq:
            return _accept(header, Rule.REPLAY_ACCEPT, "out-of-order within window")

        jump = seq - window.highest_seq
        if jump > self.config.max_seq_jump:
            if log:
                logger.warning("Sequence jump: device=%s seq=%s jump=%d", header.device_id, seq, jump)
            return ReplayVerdict(
                ReplayOutcome.ACCEPT_FLAGGED,
                Rule.SEQ_JUMP,
                header.device_id,
                seq,
                f"jump of {jump} exceeds {self.config.max_seq_jump}; window not advanced",
            )

        return _accept(header, Rule.REPLAY_ACCEPT, "in sequence")

    def _record(self, header: PacketHeader) -> None:
        """Apply an accepted packet to the window. Assumes _evaluate passed."""
        seq: int = header.seq
        ts = float(header.timestamp)
        window = self._windows.get(header.device_id)
        if window is None:
            self._windows[header.device_id] = _DeviceWindow(highest_seq=seq, bitmap=1, highest_ts=ts)
        elif seq < window.highest_seq:
            # Late but unseen packet inside the window (out-of-order delivery).
            window.bitmap |= 1 << (window.highest_seq - seq)
        elif seq - window.highest_seq > self.config.max_seq_jump:
            # An unauthenticated header alone never moves the window: two forged
            # far-ahead packets must not be able to lock the real device out.
            # The window only moves via confirm_jump(), once decryption has
            # proven the packet authentic.
            window.pending_jump_seq = seq
            window.pending_jump_ts = ts
        else:
            self._advance(window, seq, ts)

    def confirm_jump(self, device_id: str, seq: int) -> bool:
        """Advance the window to a flagged jump once it is proven authentic.

        Called by the pipeline after the packet's payload has decrypted and
        authenticated successfully with Component 2's key material. Returns
        True if the window was moved.
        """
        window = self._windows.get(device_id)
        if window is None or window.pending_jump_seq != seq:
            return False
        self._advance(window, seq, window.pending_jump_ts)
        logger.info(
            "Sequence jump confirmed: rule=%s device=%s seq=%s",
            Rule.SEQ_JUMP_CONFIRMED.value,
            device_id,
            seq,
        )
        return True

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


def _discard_quietly(header: PacketHeader, rule: Rule, detail: str) -> ReplayVerdict:
    return ReplayVerdict(
        ReplayOutcome.DISCARD, rule, getattr(header, "device_id", None), getattr(header, "seq", None), detail
    )


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
