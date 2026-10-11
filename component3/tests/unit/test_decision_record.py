"""Unit tests for signed decision records (FR6, FR7)."""

import dataclasses
import json

from vitalpath_c3.output.decision_record import (
    DecisionRecord,
    JsonlSink,
    RecordSigner,
    verify_record,
)

RECORD = DecisionRecord(
    device_id="amb-01",
    seq=42,
    received_at=1_800_000_000.5,
    decision="FLAG",
    label="Flagged",
    score=6,
    rules=("R-SPO2-CRIT-LOW", "R-CORR-SPO2-HR"),
)


def test_signed_record_verifies():
    signer = RecordSigner.generate()
    assert verify_record(signer.sign(RECORD), signer.public_key)


def test_altered_label_fails_verification():
    signer = RecordSigner.generate()
    signed = signer.sign(RECORD)
    assert not verify_record(dataclasses.replace(signed, label="Normal"), signer.public_key)


def test_altered_rules_fail_verification():
    signer = RecordSigner.generate()
    signed = signer.sign(RECORD)
    assert not verify_record(dataclasses.replace(signed, rules=()), signer.public_key)


def test_wrong_public_key_fails_verification():
    signed = RecordSigner.generate().sign(RECORD)
    assert not verify_record(signed, RecordSigner.generate().public_key)


def test_unsigned_or_garbage_signature_fails():
    signer = RecordSigner.generate()
    assert not verify_record(RECORD, signer.public_key)
    assert not verify_record(dataclasses.replace(RECORD, signature="zz"), signer.public_key)


def test_jsonl_sink_appends_one_line_per_record(tmp_path):
    signer = RecordSigner.generate()
    sink = JsonlSink(tmp_path / "decisions.jsonl")
    sink.append(signer.sign(RECORD))
    sink.append(signer.sign(dataclasses.replace(RECORD, seq=43)))
    lines = (tmp_path / "decisions.jsonl").read_text().splitlines()
    assert [json.loads(line)["seq"] for line in lines] == [42, 43]


def test_record_from_file_still_verifies(tmp_path):
    """Component 4's view: read the line back and check the signature."""
    signer = RecordSigner.generate()
    sink = JsonlSink(tmp_path / "decisions.jsonl")
    sink.append(signer.sign(RECORD))
    data = json.loads((tmp_path / "decisions.jsonl").read_text())
    restored = DecisionRecord(**{**data, "rules": tuple(data["rules"])})
    assert verify_record(restored, signer.public_key)
