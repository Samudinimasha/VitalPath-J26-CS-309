"""Decision records handed to Component 4 (FR6, FR7, NFR2).

One record per packet, whatever the outcome. A record carries the packet's
identity, the decision, the sensitivity label, the score and the rule IDs
behind it, but never a raw vital-sign value. Each record is signed with
Ed25519 so Component 4 can verify it with Component 3's public key without
being able to forge one.

Records are written as JSON lines to a file; Component 4 reads that file on
its own schedule, so Component 3 never waits for it. The hand-off mechanism is
still to be agreed with Component 4 (see the open agreements document).
"""

import json
import threading
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import List, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


@dataclass(frozen=True)
class DecisionRecord:
    device_id: object
    packet_id: object  # Component 2's packet ID
    received_at: float
    decision: str  # ACCEPT, FLAG or DISCARD
    label: Optional[str]  # Normal, Borderline or Flagged; None when discarded
    score: Optional[int]
    rules: Tuple[str, ...]
    case_id: object = None  # copied from the packet header for Component 4
    signature: str = ""

    def signed_bytes(self) -> bytes:
        """Canonical bytes covered by the signature (everything but the signature)."""
        fields = asdict(self)
        del fields["signature"]
        fields["rules"] = list(self.rules)
        return json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str).encode()

    def to_json(self) -> str:
        return json.dumps({**asdict(self), "rules": list(self.rules)}, default=str)


class RecordSigner:
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key
        self.public_key = private_key.public_key()

    @classmethod
    def generate(cls) -> "RecordSigner":
        return cls(Ed25519PrivateKey.generate())

    def sign(self, record: DecisionRecord) -> DecisionRecord:
        return replace(record, signature=self._key.sign(record.signed_bytes()).hex())


def verify_record(record: DecisionRecord, public_key: Ed25519PublicKey) -> bool:
    """What Component 4 runs to check a record came unaltered from Component 3."""
    try:
        public_key.verify(bytes.fromhex(record.signature), record.signed_bytes())
    except (InvalidSignature, ValueError):
        return False
    return True


class MemorySink:
    """Keeps records in a list; used by tests and the live demo."""

    def __init__(self) -> None:
        self.records: List[DecisionRecord] = []

    def append(self, record: DecisionRecord) -> None:
        self.records.append(record)


class JsonlSink:
    """Appends each record as one JSON line for Component 4 to read later."""

    def __init__(self, path: Union[str, Path]) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def append(self, record: DecisionRecord) -> None:
        with self._lock, open(self.path, "a") as f:
            f.write(record.to_json() + "\n")
