"""Wire format shared by the live simulator sender and receiver.

Each UDP datagram is a JSON object with a clear-text header and an opaque
payload (hex). The payload stands in for Component 2's sealed ciphertext and
is never inspected by the replay gate.
"""

import json

from vitalpath_c3.models import EncryptedPacket, PacketHeader

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5005


def packet_id(count: int) -> str:
    """Packet ID in Component 2's format for the simulator's counter: 42 -> PKT-000042."""
    return f"PKT-{count:06d}"


def encode(device_id, packet_id, timestamp, payload: bytes, case_id=None) -> bytes:
    return json.dumps(
        {"case_id": case_id, "device_id": device_id, "packet_id": packet_id, "timestamp": timestamp,
         "payload": payload.hex()}
    ).encode()


def decode(datagram: bytes) -> EncryptedPacket:
    """Parse a datagram. Missing or undecodable fields become None so the
    replay gate can reject them with a named rule instead of crashing here."""
    try:
        obj = json.loads(datagram)
    except (ValueError, UnicodeDecodeError):
        obj = {}
    if not isinstance(obj, dict):
        obj = {}
    try:
        payload = bytes.fromhex(obj.get("payload", ""))
    except (TypeError, ValueError):
        payload = b""
    header = PacketHeader(
        device_id=obj.get("device_id"),
        timestamp=obj.get("timestamp"),
        case_id=obj.get("case_id"),
        packet_id=obj.get("packet_id"),
    )
    return EncryptedPacket(header=header, payload=payload)
