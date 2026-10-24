"""Data shapes shared across Component 3 engines."""

import re
from dataclasses import dataclass
from typing import Optional

# Packet IDs follow Component 2's format: letters, '_' or '-', then a counter
# that rises per device, e.g. PKT-000042, mimic_00042, pkt_001. Anything else
# (such as Component 2's random fallback pkt_9f3a71c2be04) has no usable order
# and is rejected by the Replay Detection Engine.
PACKET_ID_PATTERN = re.compile(r"[A-Za-z]+[_-]([0-9]+)")

# Largest counter accepted in a packet ID (unsigned 64-bit); wraparound is not handled.
PACKET_NUMBER_MAX = 2**64 - 1


def packet_id_number(packet_id: object) -> Optional[int]:
    """The counter inside a packet ID (PKT-000042 -> 42), or None if the ID
    does not follow the agreed format."""
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
    # Component 2's packet identifier; its counter drives replay detection.
    packet_id: object
    timestamp: object
    # Emergency case the packet belongs to (e.g. CASE001), set by the
    # ambulance from dispatch. Component 4 uses it to decide who may view the
    # telemetry. Optional so packets without one are still checked.
    case_id: object = None

    @property
    def number(self) -> Optional[int]:
        """The packet's counter, read from packet_id; None if the ID is unusable."""
        return packet_id_number(self.packet_id)


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
