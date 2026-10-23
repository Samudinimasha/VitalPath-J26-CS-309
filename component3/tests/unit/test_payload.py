"""Unit tests for payload sealing and decryption (AES-GCM stand-in for Component 2)."""

import dataclasses
import json
import os
import time

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vitalpath_c3.crypto.payload import (
    NONCE_BYTES,
    PayloadDecryptor,
    PayloadError,
    header_aad,
    seal,
)
from vitalpath_c3.models import EncryptedPacket, PacketHeader, VitalSigns
from vitalpath_c3.rules import Rule

KEY = AESGCM.generate_key(bit_length=256)
HEADER = PacketHeader(device_id="amb-01", seq=42, timestamp=1_800_000_000.25)
VITALS = VitalSigns(hr=82.5, pulse=81.0, spo2=97.0, sbp=121.0, dbp=79.0, resp=16.0)


@pytest.fixture
def decryptor() -> PayloadDecryptor:
    return PayloadDecryptor({"amb-01": KEY}.__getitem__)


def raw_packet(plaintext: bytes, header=HEADER) -> EncryptedPacket:
    nonce = os.urandom(NONCE_BYTES)
    return EncryptedPacket(header, nonce + AESGCM(KEY).encrypt(nonce, plaintext, header_aad(header)))


def test_round_trip(decryptor):
    assert decryptor.decrypt(seal(HEADER, VITALS, KEY)) == VITALS


def test_missing_vitals_round_trip_as_none(decryptor):
    vitals = VitalSigns(hr=70.0)
    assert decryptor.decrypt(seal(HEADER, vitals, KEY)) == vitals


def test_payload_is_not_readable_without_key():
    packet = seal(HEADER, VITALS, KEY)
    assert b"82.5" not in packet.payload
    assert b"hr" not in packet.payload


def test_each_seal_uses_a_fresh_nonce():
    assert seal(HEADER, VITALS, KEY).payload != seal(HEADER, VITALS, KEY).payload


@pytest.mark.parametrize(
    "field, value",
    [("seq", 43), ("timestamp", 1_800_000_000.26), ("device_id", "amb-02"), ("case_id", "CASE002")],
)
def test_tampered_header_fails_authentication(field, value):
    packet = seal(HEADER, VITALS, KEY)
    tampered = EncryptedPacket(dataclasses.replace(HEADER, **{field: value}), packet.payload)
    decryptor = PayloadDecryptor(lambda _device: KEY)
    with pytest.raises(PayloadError) as err:
        decryptor.decrypt(tampered)
    assert err.value.rule is Rule.DECRYPT_FAILED


def test_tampered_payload_fails_authentication(decryptor):
    payload = bytearray(seal(HEADER, VITALS, KEY).payload)
    payload[NONCE_BYTES + 3] ^= 0x01
    with pytest.raises(PayloadError) as err:
        decryptor.decrypt(EncryptedPacket(HEADER, bytes(payload)))
    assert err.value.rule is Rule.DECRYPT_FAILED


def test_wrong_key_fails_authentication():
    packet = seal(HEADER, VITALS, KEY)
    decryptor = PayloadDecryptor(lambda _device: AESGCM.generate_key(bit_length=256))
    with pytest.raises(PayloadError) as err:
        decryptor.decrypt(packet)
    assert err.value.rule is Rule.DECRYPT_FAILED


def test_unknown_device_has_no_key(decryptor):
    packet = seal(dataclasses.replace(HEADER, device_id="amb-99"), VITALS, KEY)
    with pytest.raises(PayloadError) as err:
        decryptor.decrypt(packet)
    assert err.value.rule is Rule.DECRYPT_FAILED


def test_short_payload_is_malformed(decryptor):
    with pytest.raises(PayloadError) as err:
        decryptor.decrypt(EncryptedPacket(HEADER, b"short"))
    assert err.value.rule is Rule.PAYLOAD_MALFORMED


@pytest.mark.parametrize("plaintext", [b"not json", b"[1, 2]", b"72"])
def test_non_object_plaintext_is_malformed(decryptor, plaintext):
    with pytest.raises(PayloadError) as err:
        decryptor.decrypt(raw_packet(plaintext))
    assert err.value.rule is Rule.PAYLOAD_MALFORMED


def test_component2_packet_layout_is_read(decryptor):
    """Thamindu's example plaintext from component2/crypto_engine.py."""
    plaintext = (
        b'{"patient_id": "AMB_PAT_1042", "device_id": "sensor_ecg_01", '
        b'"vitals": {"hr": 84, "spo2": 97, "bp_sys": 122, "bp_dia": 79, "rr": 16}}'
    )
    assert decryptor.decrypt(raw_packet(plaintext)) == VitalSigns(hr=84, spo2=97, sbp=122, dbp=79, resp=16)


def test_pulse_is_kept_in_component2_layout(decryptor):
    plaintext = b'{"vitals": {"hr": 84, "pulse": 83, "spo2": 97}}'
    assert decryptor.decrypt(raw_packet(plaintext)) == VitalSigns(hr=84, pulse=83, spo2=97)


def test_seal_writes_component2_layout():
    packet = seal(HEADER, VITALS, KEY)
    nonce, body = packet.payload[:NONCE_BYTES], packet.payload[NONCE_BYTES:]
    obj = json.loads(AESGCM(KEY).decrypt(nonce, body, header_aad(HEADER)))
    assert obj == {"vitals": {"hr": 82.5, "pulse": 81.0, "spo2": 97.0, "bp_sys": 121.0, "bp_dia": 79.0, "rr": 16.0}}


def test_unknown_vital_names_in_component2_layout_ignored(decryptor):
    plaintext = b'{"vitals": {"hr": 84, "temp": 37.0, "sbp": 120}}'
    assert decryptor.decrypt(raw_packet(plaintext)) == VitalSigns(hr=84)


def test_vitals_not_an_object_is_malformed(decryptor):
    with pytest.raises(PayloadError) as err:
        decryptor.decrypt(raw_packet(b'{"vitals": [84, 97]}'))
    assert err.value.rule is Rule.PAYLOAD_MALFORMED


def test_unknown_keys_ignored_and_bad_values_passed_to_engines(decryptor):
    vitals = decryptor.decrypt(raw_packet(b'{"hr": "fast", "temp": 37.0, "spo2": 98}'))
    # The threshold engine reports "fast" as an invalid HR reading.
    assert vitals == VitalSigns(hr="fast", spo2=98)


def test_decrypt_is_well_within_latency_budget(decryptor):
    packet = seal(HEADER, VITALS, KEY)
    n = 5_000
    start = time.perf_counter()
    for _ in range(n):
        decryptor.decrypt(packet)
    assert (time.perf_counter() - start) * 1000 / n < 1.0
