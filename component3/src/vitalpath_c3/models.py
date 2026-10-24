"""Data shapes shared across Component 3 engines."""

import re
from dataclasses import dataclass
from typing import Optional

# Sequence numbers are unsigned 64-bit counters; wraparound is not handled.
SEQ_MAX = 2**64 - 1

# Component 2's packet_id: letters, '_' or '-', then the counter, e.g.
# mimic_00042, pkt_001, PKT-00001. Anything else (such as Component 2's random
# fallback pkt_9f3a71c2be04) has no usable order and is rejected.
PACKET_ID_PATTERN = re.compile(r"[A-Za-z]+[_-]([0-9]+)")


def packet_id_number(packet_id: object) -> Optional[int]:
    """The counter inside a packet_id, or None if it does not match the pattern."""
    if isinstance(packet_id, str):
        match = PACKET_ID_PATTERN.fullmatch(packet_id)
        if match:
            return int(match.group(1))
    return None


@dataclass(frozen=True)
class PacketHeader:
    """Clear-text metadata that travels alongside the sealed payload.

    This is the only part of a packet the Replay Detection Engine reads.
    Fields are typed loosely on purpose: the engine validates them itself so
    that malformed input from the wire is rejected with a named rule (S9)
    rather than raising.
    """

    device_id: object
    seq: object
    timestamp: object
    # Emergency case the packet belongs to (e.g. CASE001), set by the
    # ambulance from dispatch. Component 4 uses it to decide who may view the
    # telemetry. Optional so packets without one are still checked.
    case_id: object = None
    # Component 2's packet identifier. When a packet has a packet_id but no
    # seq, the sequence number is read from it (mimic_00042 -> 42), so the
    # replay window works on Component 2's own numbering.
    packet_id: object = None

    def __post_init__(self) -> None:
        if self.seq is None and self.packet_id is not None:
            number = packet_id_number(self.packet_id)
            if number is not None:
                object.__setattr__(self, "seq", number)


@dataclass(frozen=True)
class VitalSigns:
    """Decrypted vital-sign readings from one packet. None means no reading
    (sensor disconnected or not measured in this packet)."""

    hr: Optional[float] = None
    spo2: Optional[float] = None
    sbp: Optional[float] = None
    dbp: Optional[float] = None
    resp: Optional[float] = None
    # Pulse rate from the oximeter; not thresholded, used by the correlation
    # engine to cross-check the ECG-derived heart rate.
    pulse: Optional[float] = None


@dataclass(frozen=True)
class EncryptedPacket:
    """A transmitted packet as produced by Component 2."""

    header: PacketHeader
    payload: bytes
