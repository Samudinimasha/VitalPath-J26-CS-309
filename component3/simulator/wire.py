"""Wire format shared by the live simulator sender and receiver.

Each UDP datagram is a JSON object with a clear-text header and an opaque
payload (hex). The payload stands in for Component 2's sealed ciphertext and
is never inspected by the replay gate.
"""

import json

from vitalpath_c3.models import EncryptedPacket, PacketHeader

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5005


def encode(device_id, seq, timestamp, payload: bytes, case_id=None, packet_id=None) -> bytes:
    fields = {"case_id": case_id, "device_id": device_id, "seq": seq, "timestamp": timestamp}
    if packet_id is not None:
        fields["packet_id"] = packet_id
    fields["payload"] = payload.hex()
    return json.dumps(fields).encode()


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
        seq=obj.get("seq"),
        timestamp=obj.get("timestamp"),
        case_id=obj.get("case_id"),
        packet_id=obj.get("packet_id"),
    )
    return EncryptedPacket(header=header, payload=payload)
