"""Named detection rules.

Every verdict produced by Component 3 cites exactly one of these rules, so each
accepted, flagged or discarded packet is traceable to an explicit rule (NFR4).
"""

from enum import Enum


class Rule(str, Enum):
    # Replay Detection Engine (T9)
    REPLAY_ACCEPT = "R-REPLAY-ACCEPT"
    REPLAY_DUPLICATE = "R-REPLAY-DUPLICATE"
    REPLAY_OUTSIDE_WINDOW = "R-REPLAY-OUTSIDE-WINDOW"
    TS_STALE = "R-TS-STALE"
    TS_FUTURE = "R-TS-FUTURE"
    TS_REGRESSION = "R-TS-REGRESSION"
    SEQ_JUMP = "R-SEQ-JUMP"
    SEQ_RESYNC = "R-SEQ-RESYNC"
    MALFORMED_HEADER = "R-MALFORMED-HEADER"


RULE_DESCRIPTIONS = {
    Rule.REPLAY_ACCEPT: "Sequence number is new and inside the replay window; timestamp is fresh.",
    Rule.REPLAY_DUPLICATE: "Sequence number was already accepted for this device.",
    Rule.REPLAY_OUTSIDE_WINDOW: "Sequence number is older than the replay window for this device.",
    Rule.TS_STALE: "Timestamp is older than the maximum permitted age.",
    Rule.TS_FUTURE: "Timestamp is further ahead of the receiver clock than the permitted skew.",
    Rule.TS_REGRESSION: "Timestamp falls behind the device's newest accepted timestamp beyond tolerance.",
    Rule.SEQ_JUMP: "Sequence number jumps further ahead than permitted; possible injection.",
    Rule.SEQ_RESYNC: "Packet continues a previously flagged sequence jump; window resynchronised.",
    Rule.MALFORMED_HEADER: "Header is missing a field or a field has an invalid type or value.",
}
