"""Tunable parameters for every Component 3 engine, kept in one place.

All values are deliberately explicit so that each decision can be traced back
to a documented configuration, not a learned boundary (NFR4).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ReplayConfig:
    """Configuration for the Replay Detection Engine (WBS T9).

    Times are in seconds; timestamps are UNIX epoch seconds.
    """

    # Number of sequence numbers tracked behind the highest accepted one.
    window_size: int = 1024
    # A packet older than this, relative to the receiver clock, is stale.
    max_age_s: float = 30.0
    # A packet stamped further than this ahead of the receiver clock is rejected.
    future_skew_s: float = 2.0
    # How far a packet's timestamp may fall behind the newest accepted
    # timestamp for that device (tolerates out-of-order delivery).
    backward_tolerance_s: float = 1.0
    # Forward jump in sequence number above which a packet is flagged as a
    # possible injection (scenario S10) and the window is not advanced.
    max_seq_jump: int = 1024

    def __post_init__(self) -> None:
        if self.window_size <= 0:
            raise ValueError("window_size must be positive")
        if self.max_seq_jump <= 0:
            raise ValueError("max_seq_jump must be positive")
        for name in ("max_age_s", "future_skew_s", "backward_tolerance_s"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must be non-negative")
