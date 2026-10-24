"""Replay Detection Engine (WBS T9).

First-stage gate of Component 3. It reads only the clear-text header
(device ID, packet ID, timestamp) and never touches the encrypted
payload, so a packet discarded here is never decrypted.

Per device, the engine keeps an anti-replay window in the style of DTLS
(RFC 6347 s4.1.2.6) and IPsec (RFC 4303 s3.4.3): the highest accepted
packet number plus a bitmap of which of the ``window_size`` packet numbers
behind it have been accepted. The packet number is the counter inside
Component 2's packet ID (PKT-000042 -> 42). State is keyed by device ID rather than
by transport session, so the window persists across a 5G handover (FR2).

Checks, in order, each tied to a named rule:

1. Header well-formed                          -> R-MALFORMED-HEADER   (S9)
2. Packet ID not already accepted              -> R-REPLAY-DUPLICATE   (S2, S3)
3. Packet ID not older than the window         -> R-REPLAY-OUTSIDE-WINDOW
4. Timestamp not older than ``max_age_s``      -> R-TS-STALE
5. Timestamp not ahead by more than skew       -> R-TS-FUTURE
6. Timestamp not behind newest by > tolerance  -> R-TS-REGRESSION
7. Forward jump no larger than ``max_packet_jump`` -> R-PACKET-JUMP (flag) (S10)

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

from vitalpath_c3.replay_configurations import ReplayConfig
from vitalpath_c3.packet_models import PACKET_NUMBER_MAX, PacketHeader
from vitalpath_c3.rule_ids import Rule

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
    packet_id: object
    detail: str = ""

    @property
    def passed(self) -> bool:
        """True if the packet may proceed to decryption."""
        return self.outcome is not ReplayOutcome.DISCARD


@dataclass
class _DeviceWindow:
    highest_number: int
    # Bit i set means packet number (highest_number - i) has been accepted.
    bitmap: int
    highest_ts: float
    # Packet number of the most recent packet flagged for an excessive jump.
    # It is merged into the window only through confirm_jump().
    pending_jump_number: Optional[int] = None
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
        never use up a packet ID and get the genuine packet rejected
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

        number: int = header.number
        ts = float(header.timestamp)
        window = self._windows.get(header.device_id)

        if window is not None:
            offset = window.highest_number - number
            if offset >= self.config.window_size:
                return discard(
                    header,
                    Rule.REPLAY_OUTSIDE_WINDOW,
                    f"{header.packet_id} is {offset} behind the newest accepted packet",
                )
            if (offset >= 0 and window.bitmap >> offset & 1) or number == window.pending_jump_number:
                return discard(header, Rule.REPLAY_DUPLICATE, f"{header.packet_id} already seen")

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

        if number < window.highest_number:
            return _accept(header, Rule.REPLAY_ACCEPT, "out-of-order within window")

        jump = number - window.highest_number
        if jump > self.config.max_packet_jump:
            if log:
                logger.warning("Packet ID jump: device=%s packet_id=%s jump=%d", header.device_id, header.packet_id, jump)
            return ReplayVerdict(
                ReplayOutcome.ACCEPT_FLAGGED,
                Rule.PACKET_JUMP,
                header.device_id,
                header.packet_id,
                f"jump of {jump} exceeds {self.config.max_packet_jump}; window not advanced",
            )

        return _accept(header, Rule.REPLAY_ACCEPT, "in order")

    def _record(self, header: PacketHeader) -> None:
        """Apply an accepted packet to the window. Assumes _evaluate passed."""
        number: int = header.number
        ts = float(header.timestamp)
        window = self._windows.get(header.device_id)
        if window is None:
            self._windows[header.device_id] = _DeviceWindow(highest_number=number, bitmap=1, highest_ts=ts)
        elif number < window.highest_number:
            # Late but unseen packet inside the window (out-of-order delivery).
            window.bitmap |= 1 << (window.highest_number - number)
        elif number - window.highest_number > self.config.max_packet_jump:
            # An unauthenticated header alone never moves the window: two forged
            # far-ahead packets must not be able to lock the real device out.
            # The window only moves via confirm_jump(), once decryption has
            # proven the packet authentic.
            window.pending_jump_number = number
            window.pending_jump_ts = ts
        else:
            self._advance(window, number, ts)

    def confirm_jump(self, device_id: str, number: int) -> bool:
        """Advance the window to a flagged jump once it is proven authentic.

        Called by the pipeline after the packet's payload has decrypted and
        authenticated successfully with Component 2's key material. Returns
        True if the window was moved.
        """
        window = self._windows.get(device_id)
        if window is None or window.pending_jump_number != number:
            return False
        self._advance(window, number, window.pending_jump_ts)
        logger.info(
            "Packet ID jump confirmed: rule=%s device=%s number=%s",
            Rule.PACKET_JUMP_CONFIRMED.value,
            device_id,
            number,
        )
        return True

    def _advance(self, window: _DeviceWindow, number: int, ts: float) -> None:
        """Slide the window forward so that ``number`` becomes the highest accepted."""
        shift = number - window.highest_number
        window.bitmap = ((window.bitmap << shift) | 1) & self._mask
        window.highest_number = number
        window.highest_ts = max(window.highest_ts, ts)
        pending = window.pending_jump_number
        if pending is not None and pending <= number:
            # The regular stream has caught up with the flagged packet; record
            # it as seen so it cannot be replayed later.
            offset = number - pending
            if offset < self.config.window_size:
                window.bitmap |= 1 << offset
            window.pending_jump_number = None

    def _discard(self, header: PacketHeader, rule: Rule, detail: str) -> ReplayVerdict:
        verdict = ReplayVerdict(
            ReplayOutcome.DISCARD,
            rule,
            getattr(header, "device_id", None),
            getattr(header, "packet_id", None),
            detail,
        )
        logger.warning(
            "Replay gate discard: rule=%s device=%s packet_id=%s (%s)",
            rule.value,
            verdict.device_id,
            verdict.packet_id,
            detail,
        )
        return verdict


def _discard_quietly(header: PacketHeader, rule: Rule, detail: str) -> ReplayVerdict:
    return ReplayVerdict(
        ReplayOutcome.DISCARD, rule, getattr(header, "device_id", None), getattr(header, "packet_id", None), detail
    )


def _accept(header: PacketHeader, rule: Rule, detail: str) -> ReplayVerdict:
    return ReplayVerdict(ReplayOutcome.ACCEPT, rule, header.device_id, header.packet_id, detail)


def _malformed_reason(header: object) -> Optional[str]:
    if not isinstance(header, PacketHeader):
        return "header missing or not a PacketHeader"
    if not isinstance(header.device_id, str) or not header.device_id:
        return "device_id must be a non-empty string"
    number = header.number
    if number is None:
        return "packet_id must be letters, '_' or '-', then a counter (e.g. PKT-000042)"
    if number > PACKET_NUMBER_MAX:
        return "packet_id counter outside unsigned 64-bit range"
    if header.case_id is not None and (not isinstance(header.case_id, str) or not header.case_id):
        return "case_id must be a non-empty string when present"
    ts = header.timestamp
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        return "timestamp must be numeric"
    if not math.isfinite(ts):
        return "timestamp must be finite"
    return None
