"""Named detection rules.

Every verdict produced by Component 3 cites exactly one of these rules, so each
accepted, flagged or discarded packet is traceable to an explicit rule (NFR4).
"""

from enum import Enum


class Rule(str, Enum):
    # Flood rate limiter (S8)
    RATE_OK = "R-RATE-OK"
    RATE_LIMIT = "R-RATE-LIMIT"
    # Replay Detection Engine (T9)
    REPLAY_ACCEPT = "R-REPLAY-ACCEPT"
    REPLAY_DUPLICATE = "R-REPLAY-DUPLICATE"
    REPLAY_OUTSIDE_WINDOW = "R-REPLAY-OUTSIDE-WINDOW"
    TS_STALE = "R-TS-STALE"
    TS_FUTURE = "R-TS-FUTURE"
    TS_REGRESSION = "R-TS-REGRESSION"
    PACKET_JUMP = "R-PACKET-JUMP"
    PACKET_JUMP_CONFIRMED = "R-PACKET-JUMP-CONFIRMED"
    MALFORMED_HEADER = "R-MALFORMED-HEADER"
    # Payload decryption
    DECRYPT_FAILED = "R-DECRYPT-FAILED"
    PAYLOAD_MALFORMED = "R-PAYLOAD-MALFORMED"


RULE_DESCRIPTIONS = {
    Rule.RATE_OK: "Packet rate for this device is within the permitted limit.",
    Rule.RATE_LIMIT: "Device exceeded the permitted packet rate; excess packet discarded (flooding).",
    Rule.REPLAY_ACCEPT: "Packet ID is new and inside the replay window; timestamp is fresh.",
    Rule.REPLAY_DUPLICATE: "Packet ID was already accepted for this device.",
    Rule.REPLAY_OUTSIDE_WINDOW: "Packet ID is older than the replay window for this device.",
    Rule.TS_STALE: "Timestamp is older than the maximum permitted age.",
    Rule.TS_FUTURE: "Timestamp is further ahead of the receiver clock than the permitted skew.",
    Rule.TS_REGRESSION: "Timestamp falls behind the device's newest accepted timestamp beyond tolerance.",
    Rule.PACKET_JUMP: "Packet ID jumps further ahead than permitted; possible injection.",
    Rule.PACKET_JUMP_CONFIRMED: "Flagged packet ID jump proven authentic by decryption; window advanced.",
    Rule.MALFORMED_HEADER: "Header is missing a field or a field has an invalid type or value.",
    Rule.DECRYPT_FAILED: "Payload failed authenticated decryption: altered in transit, header tampered, or wrong key.",
    Rule.PAYLOAD_MALFORMED: "Payload decrypted but is not a well-formed vital-sign record.",
}
