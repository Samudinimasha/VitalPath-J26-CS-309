"""Run one engine on its own with vitals you type in.

Usage (from component3/):
    PYTHONPATH=src python3 -m simulator.try_engines threshold   --hr 150 --spo2 88
    PYTHONPATH=src python3 -m simulator.try_engines correlation --hr 64 --pulse 72 --spo2 13.9
    PYTHONPATH=src python3 -m simulator.try_engines decision    --hr 64 --pulse 72 --spo2 13.9
    PYTHONPATH=src python3 -m simulator.try_engines decryption  --hr 92 --spo2 98

Vitals you leave out count as "no reading". Units: hr and pulse in bpm,
spo2 in %, sbp and dbp in mmHg, resp in breaths per minute.
"""

import argparse
import dataclasses
import os

from vitalpath_c3.crypto.payload_encryption import PayloadDecryptor, PayloadError, seal
from vitalpath_c3.engines.correlation import CorrelationEngine
from vitalpath_c3.engines.hybrid import HybridDecisionEngine
from vitalpath_c3.engines.replay import ReplayOutcome, ReplayVerdict
from vitalpath_c3.engines.threshold import Band, ThresholdEngine
from vitalpath_c3.packet_models import EncryptedPacket, PacketHeader, VitalSigns
from vitalpath_c3.rule_ids import Rule


def show_threshold(vitals):
    print("Threshold Engine: each vital against its clinical limits\n")
    for f in ThresholdEngine().evaluate(vitals).findings:
        value = "-" if f.value is None else f"{f.value:g}"
        source = f"  ({f.source})" if f.source else ""
        print(f"  {f.vital:<6} {value:>6}  {f.band.value.upper():<10} {f.rule}{source}")


def show_correlation(vitals):
    print("Correlation Engine: vitals checked against each other\n")
    result = CorrelationEngine().evaluate(vitals)
    if not result.findings:
        print("  No problems: the vitals agree with each other.")
    for f in result.findings:
        print(f"  {f.kind.value.upper():<13} {f.rule}\n                {f.detail}")
    if result.not_evaluated:
        print(f"\n  Not checked (missing readings): {', '.join(result.not_evaluated)}")


def show_decision(vitals):
    print("Hybrid Decision Engine: threshold + correlation findings added up\n")
    fresh = ReplayVerdict(ReplayOutcome.ACCEPT, Rule.REPLAY_ACCEPT, "MON-01", "PKT-000001")
    decision = HybridDecisionEngine().decide(
        fresh, ThresholdEngine().evaluate(vitals), CorrelationEngine().evaluate(vitals)
    )
    print("  " + decision.explain().replace("\n", "\n  "))


def show_decryption(vitals):
    print("Decryption: lock the vitals, unlock them, then show tampering is caught\n")
    key = os.urandom(32)
    header = PacketHeader("MON-01", "PKT-000001", 1_800_000_000.0, "CASE001")
    packet = seal(header, vitals, key)
    decryptor = PayloadDecryptor(lambda _device: key)
    print(f"  Locked payload : {packet.payload.hex()[:48]}...")
    print(f"  Unlocked       : {decryptor.decrypt(packet)}")
    for label, altered in [
        ("Case changed to CASE002", EncryptedPacket(dataclasses.replace(header, case_id="CASE002"), packet.payload)),
        ("One byte of the payload flipped", EncryptedPacket(header, packet.payload[:-1] + bytes([packet.payload[-1] ^ 1]))),
    ]:
        try:
            decryptor.decrypt(altered)
            print(f"  {label}: accepted (unexpected)")
        except PayloadError as err:
            print(f"  {label}: REJECTED, {err.rule.value}")


ENGINES = {
    "threshold": show_threshold,
    "correlation": show_correlation,
    "decision": show_decision,
    "decryption": show_decryption,
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("engine", choices=ENGINES)
    for name in ("hr", "pulse", "spo2", "sbp", "dbp", "resp"):
        parser.add_argument(f"--{name}", type=float)
    args = parser.parse_args()
    vitals = VitalSigns(**{f.name: getattr(args, f.name) for f in dataclasses.fields(VitalSigns)})
    ENGINES[args.engine](vitals)


if __name__ == "__main__":
    main()
