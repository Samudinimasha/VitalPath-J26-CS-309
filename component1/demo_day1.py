"""
Day 1 demo - Authorised Device List gate + Certificate factor (C).

Run from the project root after building the PKI:
    bash pki/setup_ca.sh
    python3 demo_day1.py
"""
from pathlib import Path

from trust.registry import DeviceRegistry
from trust.cert_factor import CertificateValidator

ROOT = Path(__file__).parent
PKI = ROOT / "pki" / "out"
DB = ROOT / "data" / "adl.db"

# Synthetic hardware identities for the registered fleet (ambulance AMB-CMB-07)
FLEET = [
    ("ECG-01",  "ECG monitor",       "02:1a:7c:00:00:01", "HWID-ECG-7731"),
    ("SPO2-02", "Pulse oximeter",    "02:1a:7c:00:00:02", "HWID-SPO-2214"),
    ("BP-03",   "NIBP cuff",         "02:1a:7c:00:00:03", "HWID-NBP-9902"),
    ("HR-04",   "Heart-rate sensor", "02:1a:7c:00:00:04", "HWID-HRS-4410"),
    ("RR-05",   "Resp. rate sensor", "02:1a:7c:00:00:05", "HWID-RRS-5521"),
]

# Connection attempts: (claimed device_id, certificate presented, scenario)
ATTEMPTS = [
    ("ECG-01",   PKI / "devices/ECG-01.crt",      "Legitimate device"),
    ("SPO2-02",  PKI / "devices/SPO2-02.crt",     "Legitimate device"),
    ("RR-05",    PKI / "devices/RR-05.crt",       "Cert expiring in 10 days"),
    ("BP-03",    PKI / "devices/BP-03.crt",       "Expired certificate"),
    ("HR-04",    PKI / "devices/HR-04.crt",       "Revoked (key compromise)"),
    ("ECG-01",   PKI / "rogue/ECG-01_forged.crt", "Cloned ECG-01, rogue CA"),
    ("SPO2-02",  PKI / "devices/ECG-01.crt",      "SPO2-02 using ECG-01's cert"),
    ("ROGUE-99", PKI / "rogue/ROGUE-99.crt",      "Unknown device"),
]


def main():
    DB.parent.mkdir(exist_ok=True)
    DB.unlink(missing_ok=True)
    reg = DeviceRegistry(DB)
    for dev_id, dev_type, mac, hwid in FLEET:
        reg.register(dev_id, dev_type, "AMB-CMB-07",
                     PKI / f"devices/{dev_id}.crt", mac, hwid)
    print(f"Authorised Device List: {len(reg.all())} devices registered\n")

    validator = CertificateValidator(PKI / "ca/root_ca.crt", PKI / "ca/root_ca.crl")

    print(f"{'Device':<9} {'Scenario':<29} {'ADL gate':<9} {'C':>5}  Outcome / reason")
    print("-" * 100)
    for claimed, cert_path, scenario in ATTEMPTS:
        ok, gate_reason = reg.is_authorised(claimed)
        if not ok:
            print(f"{claimed:<9} {scenario:<29} {'REJECT':<9} {'-':>5}  "
                  f"BLOCKED pre-scoring: {gate_reason}")
            continue
        res = validator.evaluate(cert_path.read_bytes(), claimed, reg.lookup(claimed))
        outcome = "HARD FAIL -> BLOCK" if res.hard_fail else "pass to scoring"
        print(f"{claimed:<9} {scenario:<29} {'PASS':<9} {res.score:>5.2f}  "
              f"{outcome}: {'; '.join(res.reasons)}")


if __name__ == "__main__":
    main()
