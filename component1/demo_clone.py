"""
Step-by-step demo: one stolen-identity (clone) attempt on ECG-01.

Shows each stage of the Component 1 pipeline separately, then confirms
the real TrustEngine gives the same decision and logs it.

    bash pki/setup_ca.sh
    python3 demo_clone.py
"""
import sqlite3
from pathlib import Path

from trust import config
from trust.cert_factor import CertificateValidator
from trust.engine import DeviceClaim, TrustEngine, tier_for
from trust.fingerprint_factor import evaluate_fingerprint
from trust.health_factor import HealthReport, evaluate_health
from trust.registry import DeviceRegistry

ROOT = Path(__file__).parent
PKI = ROOT / "pki" / "out"
DB = ROOT / "data" / "clone_demo.db"

REAL_HWID = "HWID-ECG-7731"
CLONE_HWID = "HWID-XXX-0666"
MAC = "02:1a:7c:00:00:01"
B, R = 0.90, 1.00                       # provisional inputs (same as demo.py)
HEALTHY = HealthReport(85, 0.00, "2.3.0", 5)


def step(n, title):
    print(f"\n[{n}] {title}")


def main():
    DB.parent.mkdir(exist_ok=True)
    DB.unlink(missing_ok=True)
    reg = DeviceRegistry(DB)
    reg.register("ECG-01", "ECG monitor", "AMB-CMB-07",
                 PKI / "devices/ECG-01.crt", MAC, REAL_HWID)
    validator = CertificateValidator(PKI / "ca/root_ca.crt", PKI / "ca/root_ca.crl")
    cert_pem = (PKI / "devices/ECG-01.crt").read_bytes()   # the GENUINE certificate

    print("Stolen-identity attack on ECG-01")
    print(f"  Registered hardware ID : {REAL_HWID}")
    print(f"  Attacker's hardware ID : {CLONE_HWID}")
    print("  Certificate presented  : genuine ECG-01 certificate (stolen)")

    step(1, "Registration check (Authorised Device List)")
    ok, why = reg.is_authorised("ECG-01")
    print(f"    {'PASS' if ok else 'FAIL'} - {why}")
    record = reg.lookup("ECG-01")

    step(2, "Certificate check (C)")
    c = validator.evaluate(cert_pem, "ECG-01", record)
    print(f"    C = {c.score:.2f}   hard fail = {c.hard_fail}   {', '.join(c.reasons)}")

    step(3, "Fingerprint check (F)")
    f = evaluate_fingerprint(record, MAC, CLONE_HWID, reg)
    print(f"    F = {f.score:.2f}   hard fail = {f.hard_fail}")
    for r in f.reasons:
        print(f"    {r}")

    step(4, "Health check (H)")
    h = evaluate_health(HEALTHY)
    print(f"    H = {h.score:.2f}   {', '.join(h.reasons)}")

    step(5, "Total score T")
    w = config.WEIGHTS
    T = w["C"] * c.score + w["F"] * f.score + w["H"] * h.score + w["B"] * B + w["R"] * R
    print(f"    T = 0.30({c.score:g}) + 0.25({f.score:g}) + 0.20({h.score:g})"
          f" + 0.15({B:g}) + 0.10({R:g})")
    print(f"    T = {T:.3f}  ->  score alone says: {tier_for(T)}")

    step(6, "Final decision (real TrustEngine)")
    engine = TrustEngine(reg, validator)
    d = engine.evaluate(DeviceClaim("ECG-01", cert_pem, MAC, CLONE_HWID, HEALTHY,
                                    behaviour=B, reputation=R))
    print(f"    Decision: {d.tier}  (gate: {d.gate})   alert raised: {d.alert}")
    print(f"    Identity gate overrides the score {d.T:.3f} ({d.score_tier}).")

    row = sqlite3.connect(DB).execute(
        "SELECT ts, device_id, tier, T, gate FROM trust_decisions ORDER BY id DESC LIMIT 1"
    ).fetchone()
    print(f"\n    Saved to database (trust_decisions): {row}")


if __name__ == "__main__":
    main()
