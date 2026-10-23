"""Payload sealing and decryption: stand-in for Component 2's encryption.

Component 2's actual cipher has not been fixed yet, so this module uses
AES-256-GCM from the ``cryptography`` package as a stand-in. The clear-text
header (device ID, sequence number, timestamp, case ID) is bound to the
ciphertext as associated data: if anyone alters the header in transit, for
example to file readings under another patient's case, decryption fails.
That is what lets the pipeline trust a flagged sequence jump once its payload
decrypts (see ReplayDetectionEngine.confirm_jump).

Wire layout of the sealed payload: 12-byte nonce || ciphertext || 16-byte tag.
The plaintext is a JSON object of vital signs, e.g. {"hr": 82.0, "spo2": 97}.

Only Component 3 decrypts, and only for packets that passed the replay gate.
"""

import json
import os
from dataclasses import fields
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vitalpath_c3.models import EncryptedPacket, PacketHeader, VitalSigns
from vitalpath_c3.rules import Rule

NONCE_BYTES = 12
_VITAL_FIELDS = {f.name for f in fields(VitalSigns)}


class PayloadError(Exception):
    """Payload could not be turned into vitals; carries the rule that failed."""

    def __init__(self, rule: Rule, detail: str) -> None:
        super().__init__(f"{rule.value}: {detail}")
        self.rule = rule
        self.detail = detail


def header_aad(header: PacketHeader) -> bytes:
    """Canonical encoding of the header used as associated data."""
    return json.dumps(
        [header.device_id, header.seq, header.timestamp, header.case_id], separators=(",", ":")
    ).encode()


def seal(header: PacketHeader, vitals: VitalSigns, key: bytes) -> EncryptedPacket:
    """Encrypt vitals for a header. Used by the simulator and tests in place of Component 2."""
    plaintext = json.dumps(
        {name: getattr(vitals, name) for name in _VITAL_FIELDS if getattr(vitals, name) is not None}
    ).encode()
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header_aad(header))
    return EncryptedPacket(header=header, payload=nonce + ciphertext)


class PayloadDecryptor:
    def __init__(self, key_for_device: Callable[[str], bytes]) -> None:
        """``key_for_device`` returns the key shared with Component 2 for a device."""
        self._key_for_device = key_for_device

    def decrypt(self, packet: EncryptedPacket) -> VitalSigns:
        header = packet.header
        payload = packet.payload
        if len(payload) <= NONCE_BYTES:
            raise PayloadError(Rule.PAYLOAD_MALFORMED, "payload too short")
        try:
            key = self._key_for_device(header.device_id)
        except KeyError:
            raise PayloadError(Rule.DECRYPT_FAILED, "no key for device") from None
        try:
            plaintext = AESGCM(key).decrypt(
                payload[:NONCE_BYTES], payload[NONCE_BYTES:], header_aad(header)
            )
        except InvalidTag:
            raise PayloadError(
                Rule.DECRYPT_FAILED, "authentication failed: payload or header altered, or wrong key"
            ) from None
        try:
            obj = json.loads(plaintext)
        except ValueError:
            raise PayloadError(Rule.PAYLOAD_MALFORMED, "plaintext is not JSON") from None
        if not isinstance(obj, dict):
            raise PayloadError(Rule.PAYLOAD_MALFORMED, "plaintext is not a JSON object")
        # Unknown keys are ignored; value checks are left to the engines so that
        # a bad reading is reported against its own vital.
        return VitalSigns(**{k: v for k, v in obj.items() if k in _VITAL_FIELDS})
