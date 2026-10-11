"""Demo-only key material shared by the simulator sender and receiver.

Real keys come from Component 2. For the demo both sides derive the same
per-device AES-256 key from a fixed label with SHA-256 (hashlib), so no key
has to be copied between terminals. Never use this outside the simulator.
"""

import hashlib

_DEMO_LABEL = b"vitalpath-c3-demo-key/"


def demo_key(device_id: str) -> bytes:
    return hashlib.sha256(_DEMO_LABEL + device_id.encode()).digest()
