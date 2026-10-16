"""
Component 1 demo - full trust pipeline (ADL gate, C, F, H, B, R, T, tiers).

Covers the TAF evaluation scenarios: legitimate, degraded and cloned devices,
plus forged, expired, revoked and unknown devices.

    bash pki/setup_ca.sh
    python3 demo.py
"""
from pathlib import Path

from trust.cert_factor import CertificateValidator
from trust.engine import DeviceClaim, TrustEngine
from trust.health_factor import HealthReport
from trust.registry import DeviceRegistry

ROOT = Path(__file__).parent
PKI = ROOT / "pki" / "out"
DB = ROOT / "data" / "adl.db"

# ---------------- Registered fleet (ambulance AMB-CMB-07) ----------------
#  device_id   type                 MAC                  hardware ID
FLEET = [
    ("ECG-01",  "ECG monitor",       "02:1a:7c:00:00:01", "HWID-ECG-7731"),
    ("SPO2-02", "Pulse oximeter",    "02:1a:7c:00:00:02", "HWID-SPO-2214"),
    ("BP-03",   "NIBP cuff",         "02:1a:7c:00:00:03", "HWID-NBP-9902"),
    ("HR-04",   "Heart-rate sensor", "02:1a:7c:00:00:04", "HWID-HRS-4410"),
    ("RR-05",   "Resp. rate sensor", "02:1a:7c:00:00:05", "HWID-RRS-5521"),
]

# ---------------- Synthetic health reports ----------------
#                 battery %, sensor error rate, firmware, seconds since heartbeat
HEALTHY  = HealthReport(85, 0.00, "2.3.0", 5)
DEGRADED = HealthReport(25, 0.05, "2.0.4", 60)
FAILING  = HealthReport(8,  0.09, "1.9.0", 240)


def cert(rel):
    return (PKI / rel).read_bytes()


# ---------------- Connection attempts ----------------
# DeviceClaim(device_id, certificate, MAC seen, hardware ID seen, health, B, R)
SCENARIOS = [
    ("Legitimate", DeviceClaim(
        "ECG-01", cert("devices/ECG-01.crt"), "02:1a:7c:00:00:01", "HWID-ECG-7731",
        HEALTHY, behaviour=0.95, reputation=1.00)),
    ("Legitimate", DeviceClaim(
        "SPO2-02", cert("devices/SPO2-02.crt"), "02:1a:7c:00:00:02", "HWID-SPO-2214",
        HEALTHY, behaviour=0.90, reputation=0.95)),
    ("MAC changed after repair", DeviceClaim(
        "SPO2-02", cert("devices/SPO2-02.crt"), "02:1a:7c:00:00:99", "HWID-SPO-2214",
        HEALTHY, behaviour=0.90, reputation=0.95)),
    ("Degraded", DeviceClaim(
        "RR-05", cert("devices/RR-05.crt"), "02:1a:7c:00:00:05", "HWID-RRS-5521",
        DEGRADED, behaviour=0.70, reputation=0.80)),
    ("Failing + MAC changed", DeviceClaim(
        "RR-05", cert("devices/RR-05.crt"), "02:1a:7c:00:00:55", "HWID-RRS-5521",
        FAILING, behaviour=0.30, reputation=0.50)),
    ("Clone: stolen cert+key", DeviceClaim(
        "ECG-01", cert("devices/ECG-01.crt"), "02:1a:7c:00:00:01", "HWID-XXX-0666",
        HEALTHY, behaviour=0.90, reputation=1.00)),
    ("Clone: forged cert", DeviceClaim(
        "ECG-01", cert("rogue/ECG-01_forged.crt"), "02:1a:7c:00:00:01", "HWID-ECG-7731",
        HEALTHY, behaviour=0.90, reputation=1.00)),
    ("Expired certificate", DeviceClaim(
        "BP-03", cert("devices/BP-03.crt"), "02:1a:7c:00:00:03", "HWID-NBP-9902",
        HEALTHY, behaviour=0.90, reputation=0.90)),
    ("Revoked certificate", DeviceClaim(
        "HR-04", cert("devices/HR-04.crt"), "02:1a:7c:00:00:04", "HWID-HRS-4410",
        HEALTHY, behaviour=0.90, reputation=0.90)),
    ("Unknown device", DeviceClaim(
        "ROGUE-99", cert("rogue/ROGUE-99.crt"), "02:de:ad:be:ef:99", "HWID-ROGUE",
        HEALTHY)),
]


def main():
    DB.parent.mkdir(exist_ok=True)
    DB.unlink(missing_ok=True)
    reg = DeviceRegistry(DB)
    for dev_id, dev_type, mac, hwid in FLEET:
        reg.register(dev_id, dev_type, "AMB-CMB-07", PKI / f"devices/{dev_id}.crt", mac, hwid)
    engine = TrustEngine(reg, CertificateValidator(PKI / "ca/root_ca.crt",
                                                   PKI / "ca/root_ca.crl"))

    print(f"VitalPath C1 - Trusted Device Score   T = 0.30C + 0.25F + 0.20H + 0.15B + 0.10R")
    print(f"Authorised Device List: {len(reg.all())} devices   "
          f"(B, R provisional for PP1)\n")
    head = (f"{'Device':<9}{'Scenario':<26}{'C':>5}{'F':>5}{'H':>6}{'B':>5}{'R':>5}"
            f"{'T':>7}  {'T alone':<12}{'DECISION'}")
    print(head)
    print("-" * len(head) + "-" * 22)

    decisions = []
    for scenario, claim in SCENARIOS:
        d = engine.evaluate(claim)
        decisions.append((scenario, d))
        if d.T is None:
            nums = f"{'-':>5}{'-':>5}{'-':>6}{'-':>5}{'-':>5}{'-':>7}  {'-':<12}"
        else:
            f = d.factors
            nums = (f"{f['C']:>5.2f}{f['F']:>5.2f}{f['H']:>6.3f}{f['B']:>5.2f}{f['R']:>5.2f}"
                    f"{d.T:>7.3f}  {d.score_tier:<12}")
        verdict = d.tier + (f" ({d.gate} gate)" if d.gate else "")
        if d.monitoring_flags:
            verdict += f" monitor {','.join(d.monitoring_flags)}"
        print(f"{claim.device_id:<9}{scenario:<26}{nums}{verdict}")

    print("\nReasons:")
    for scenario, d in decisions:
        key = [r for r in d.reasons if not r.endswith(("ALL_CHECKS_PASSED",
                                                       "FINGERPRINT_MATCH", "HEALTHY"))]
        if key:
            print(f"  {d.device_id:<9}{scenario:<26}{' | '.join(key)}")

    alerts = sum(d.alert for _, d in decisions)
    print(f"\nAlerts raised: {alerts}   Decisions logged to {DB.relative_to(ROOT)} "
          f"(trust_decisions table)")

    cond = next(d for _, d in decisions if d.tier == "CONDITIONAL")
    print("\nExample decision message passed to Components 2 and 4:")
    print(cond.to_json())


if __name__ == "__main__":
    main()
