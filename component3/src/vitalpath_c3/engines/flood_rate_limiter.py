"""Per-device flood rate limiter (scenario S8).

Sits in front of the Replay Detection Engine so a packet flood is shed before
any other work is done. Each device may have at most ``max_packets`` packets
admitted in any sliding ``window_s``-second interval; excess packets are
discarded with rule R-RATE-LIMIT.

Arrival times come from the receiver's own monotonic clock, never from the
packet timestamp, which a sender controls. Only admitted packets count
towards the limit, so a flood does not extend its own lockout.
"""

import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Dict

from vitalpath_c3.rule_ids import Rule

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RateLimitConfig:
    max_packets: int = 20
    window_s: float = 1.0

    def __post_init__(self) -> None:
        if self.max_packets <= 0:
            raise ValueError("max_packets must be positive")
        if self.window_s <= 0:
            raise ValueError("window_s must be positive")


@dataclass(frozen=True)
class RateLimitVerdict:
    allowed: bool
    rule: Rule
    detail: str = ""


class RateLimiter:
    def __init__(
        self,
        config: RateLimitConfig = RateLimitConfig(),
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config
        self._clock = clock
        self._arrivals: Dict[object, Deque[float]] = {}

    def admit(self, device_id: object) -> RateLimitVerdict:
        now = self._clock()
        arrivals = self._arrivals.setdefault(device_id, deque())
        while arrivals and now - arrivals[0] >= self.config.window_s:
            arrivals.popleft()
        if len(arrivals) >= self.config.max_packets:
            logger.warning("Rate limit discard: device=%s", device_id)
            return RateLimitVerdict(
                False,
                Rule.RATE_LIMIT,
                f"more than {self.config.max_packets} packets in {self.config.window_s:g}s",
            )
        arrivals.append(now)
        return RateLimitVerdict(True, Rule.RATE_OK)
