"""Data shapes shared across Component 3 engines."""

from dataclasses import dataclass

# Sequence numbers are unsigned 64-bit counters; wraparound is not handled.
SEQ_MAX = 2**64 - 1


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


@dataclass(frozen=True)
class EncryptedPacket:
    """A transmitted packet as produced by Component 2."""

    header: PacketHeader
    payload: bytes
