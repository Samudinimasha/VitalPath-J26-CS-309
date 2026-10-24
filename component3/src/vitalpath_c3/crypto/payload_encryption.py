"""Payload sealing and decryption: stand-in for Component 2's encryption.

this module uses AES-256-GCM from the ``cryptography`` package as a stand-in. The clear-text
header (device ID, packet ID, timestamp, case ID) is bound to the
ciphertext as associated data: if anyone alters the header in transit, for
example to file readings under another patient's case, decryption fails.
That is what lets the pipeline trust a flagged packet ID jump once its payload
decrypts (see ReplayDetectionEngine.confirm_jump).

Wire layout of the sealed payload: 12-byte nonce || ciphertext || 16-byte tag.
The plaintext uses Component 2's layout: vital signs inside a "vitals" object,
with Component 2's names (bp_sys, bp_dia, rr), plus pulse when the monitor
provides it, e.g.

    {"vitals": {"hr": 84, "pulse": 83, "spo2": 97, "bp_sys": 122, "bp_dia": 79, "rr": 16}}

Other top-level keys Component 2 adds (patient_id, device_id) are ignored.
The older flat layout using Component 3's own names ({"hr": 84, "sbp": 122, ...})
is still accepted. Inside Component 3 the vitals keep their own names
(VitalSigns: sbp, dbp, resp), so no engine or rule changes.

Only Component 3 decrypts, and only for packets that passed the replay gate.
"""

import json
import os
from dataclasses import fields
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vitalpath_c3.packet_models import EncryptedPacket, PacketHeader, VitalSigns
from vitalpath_c3.rule_ids import Rule

NONCE_BYTES = 12
_VITAL_FIELDS = {f.name for f in fields(VitalSigns)}

# Component 2's vital names -> Component 3's VitalSigns fields.
C2_VITAL_NAMES = {
    "hr": "hr",
    "pulse": "pulse",
    "spo2": "spo2",
    "bp_sys": "sbp",
    "bp_dia": "dbp",
    "rr": "resp",
}
_TO_C2_NAMES = {ours: theirs for theirs, ours in C2_VITAL_NAMES.items()}


class PayloadError(Exception):
    """Payload could not be turned into vitals; carries the rule that failed."""

    def __init__(self, rule: Rule, detail: str) -> None:
        super().__init__(f"{rule.value}: {detail}")
        self.rule = rule
        self.detail = detail


def header_aad(header: PacketHeader) -> bytes:
    """Canonical encoding of the header used as associated data."""
    return json.dumps(
        [header.device_id, header.packet_id, header.timestamp, header.case_id],
        separators=(",", ":"),
    ).encode()


def seal(header: PacketHeader, vitals: VitalSigns, key: bytes) -> EncryptedPacket:
    """Encrypt vitals for a header. Used by the simulator and tests in place of Component 2."""
    plaintext = json.dumps(
        {"vitals": {
            _TO_C2_NAMES[name]: getattr(vitals, name)
            for name in _TO_C2_NAMES
            if getattr(vitals, name) is not None
        }}
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
        if "vitals" in obj:
            vitals = obj["vitals"]
            if not isinstance(vitals, dict):
                raise PayloadError(Rule.PAYLOAD_MALFORMED, '"vitals" is not a JSON object')
            return VitalSigns(**{C2_VITAL_NAMES[k]: v for k, v in vitals.items() if k in C2_VITAL_NAMES})
        return VitalSigns(**{k: v for k, v in obj.items() if k in _VITAL_FIELDS})
