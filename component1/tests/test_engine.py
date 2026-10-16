"""Tests for F, H, the scoring engine, tiers and the identity gates.
Run from project root:  python3 -m unittest discover -s tests -v
Requires:  bash pki/setup_ca.sh
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from trust import config                                      # noqa: E402
from trust.cert_factor import CertificateValidator            # noqa: E402
from trust.engine import DeviceClaim, TrustEngine, tier_for   # noqa: E402
from trust.fingerprint_factor import evaluate_fingerprint     # noqa: E402
from trust.health_factor import HealthReport, evaluate_health  # noqa: E402
from trust.registry import DeviceRegistry                     # noqa: E402

PKI = ROOT / "pki" / "out"
HEALTHY = HealthReport(85, 0.0, "2.3.0", 5)
FLEET = {"ECG-01": ("02:1a:7c:00:00:01", "HWID-ECG-7731"),
         "SPO2-02": ("02:1a:7c:00:00:02", "HWID-SPO-2214"),
         "RR-05": ("02:1a:7c:00:00:05", "HWID-RRS-5521"),
         "HR-04": ("02:1a:7c:00:00:04", "HWID-HRS-4410")}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.reg = DeviceRegistry(Path(self.tmp.name) / "adl.db")
        for d, (mac, hw) in FLEET.items():
            self.reg.register(d, "t", "AMB-T", PKI / f"devices/{d}.crt", mac, hw)
        self.engine = TrustEngine(self.reg, CertificateValidator(
            PKI / "ca/root_ca.crt", PKI / "ca/root_ca.crl"))

    def tearDown(self):
        self.reg.conn.close()
        self.tmp.cleanup()

    def claim(self, dev="ECG-01", cert=None, mac=None, hw=None, health=HEALTHY, b=1.0, r=1.0):
        fmac, fhw = FLEET.get(dev, ("00:00:00:00:00:00", "HW-NONE"))
        cert = cert or f"devices/{dev}.crt"
        return DeviceClaim(dev, (PKI / cert).read_bytes(), mac or fmac, hw or fhw,
                           health, b, r)


class TestFingerprint(Base):
    def test_full_match(self):
        r = evaluate_fingerprint(self.reg.lookup("ECG-01"), "02:1A:7C:00:00:01", "HWID-ECG-7731")
        self.assertEqual(r.score, 1.0)   # MAC comparison is case-insensitive

    def test_mac_changed_is_soft(self):
        r = evaluate_fingerprint(self.reg.lookup("ECG-01"), "02:1a:7c:00:00:99", "HWID-ECG-7731")
        self.assertEqual(r.score, config.F_MAC_CHANGED)
        self.assertFalse(r.hard_fail)

    def test_hwid_mismatch_is_hard_fail(self):
        r = evaluate_fingerprint(self.reg.lookup("ECG-01"), "02:1a:7c:00:00:01", "HWID-FAKE")
        self.assertTrue(r.hard_fail)
        self.assertEqual(r.score, 0.0)

    def test_identity_swap_names_real_owner(self):
        r = evaluate_fingerprint(self.reg.lookup("ECG-01"), "02:1a:7c:00:00:01",
                                 "HWID-SPO-2214", self.reg)
        self.assertTrue(any("SPO2-02" in x for x in r.reasons))

    def test_missing_fingerprint(self):
        r = evaluate_fingerprint(self.reg.lookup("ECG-01"), None, "HWID-ECG-7731")
        self.assertTrue(r.hard_fail)


class TestHealth(unittest.TestCase):
    def test_healthy_is_one(self):
        self.assertEqual(evaluate_health(HEALTHY).score, 1.0)

    def test_dead_device_near_zero(self):
        self.assertLess(evaluate_health(HealthReport(0, 0.5, "1.0.0", 9999)).score, 0.1)

    def test_battery_boundaries(self):
        self.assertEqual(evaluate_health(HealthReport(50, 0, "2.3.0", 0)).parts["battery"], 1.0)
        self.assertEqual(evaluate_health(HealthReport(20, 0, "2.3.0", 0)).parts["battery"], 0.5)

    def test_firmware_comparison_is_numeric(self):
        # "2.10.0" must count as newer than "2.1.0" (string compare would fail)
        self.assertEqual(evaluate_health(HealthReport(90, 0, "2.10.0", 0)).parts["firmware"], 1.0)

    def test_degradation_is_monotonic(self):
        scores = [evaluate_health(HealthReport(b, 0, "2.3.0", 0)).score for b in (90, 40, 10)]
        self.assertEqual(scores, sorted(scores, reverse=True))


class TestTiers(unittest.TestCase):
    def test_weights_sum_to_one(self):
        self.assertAlmostEqual(sum(config.WEIGHTS.values()), 1.0)

    def test_threshold_boundaries(self):
        self.assertEqual(tier_for(0.80), "FULL_TRUST")
        self.assertEqual(tier_for(0.7999), "CONDITIONAL")
        self.assertEqual(tier_for(0.60), "CONDITIONAL")
        self.assertEqual(tier_for(0.5999), "BLOCKED")


class TestEngine(Base):
    def test_legitimate_full_trust(self):
        d = self.engine.evaluate(self.claim())
        self.assertEqual(d.tier, "FULL_TRUST")
        self.assertEqual(d.T, 1.0)
        self.assertFalse(d.alert)
        self.assertEqual(d.recheck_after_s, config.RECHECK_INTERVAL_S["FULL_TRUST"])

    def test_degraded_conditional_with_flags(self):
        d = self.engine.evaluate(self.claim("RR-05", health=HealthReport(25, 0.05, "2.0.4", 60),
                                            b=0.7, r=0.8))
        self.assertEqual(d.tier, "CONDITIONAL")
        self.assertIn("H", d.monitoring_flags)
        self.assertEqual(d.recheck_after_s, config.RECHECK_INTERVAL_S["CONDITIONAL"])

    def test_low_score_blocked_with_alert(self):
        d = self.engine.evaluate(self.claim("RR-05", mac="02:1a:7c:00:00:55",
                                            health=HealthReport(8, 0.09, "1.9.0", 240),
                                            b=0.3, r=0.5))
        self.assertEqual(d.tier, "BLOCKED")
        self.assertIsNone(d.gate)          # blocked by score, not by a gate
        self.assertTrue(d.alert)

    def test_clone_blocked_although_score_is_conditional(self):
        d = self.engine.evaluate(self.claim(hw="HWID-XXX-0666", b=0.9))
        self.assertEqual(d.score_tier, "CONDITIONAL")
        self.assertEqual(d.tier, "BLOCKED")
        self.assertEqual(d.gate, "FINGERPRINT")

    def test_forged_cert_blocked_by_certificate_gate(self):
        d = self.engine.evaluate(self.claim(cert="rogue/ECG-01_forged.crt"))
        self.assertEqual(d.tier, "BLOCKED")
        self.assertEqual(d.gate, "CERTIFICATE")

    def test_revoked_blocked(self):
        d = self.engine.evaluate(self.claim("HR-04"))
        self.assertEqual(d.gate, "CERTIFICATE")

    def test_unknown_rejected_without_scoring(self):
        d = self.engine.evaluate(self.claim("ROGUE-99", cert="rogue/ROGUE-99.crt"))
        self.assertEqual(d.tier, "REJECTED")
        self.assertIsNone(d.T)

    def test_missing_health_report_scores_zero(self):
        d = self.engine.evaluate(self.claim(health=None))
        self.assertEqual(d.factors["H"], 0.0)

    def test_out_of_range_inputs_clamped(self):
        d = self.engine.evaluate(self.claim(b=5.0, r=-2.0))
        self.assertEqual((d.factors["B"], d.factors["R"]), (1.0, 0.0))

    def test_decisions_logged(self):
        self.engine.evaluate(self.claim())
        self.engine.evaluate(self.claim("ROGUE-99", cert="rogue/ROGUE-99.crt"))
        n = self.reg.conn.execute("SELECT COUNT(*) FROM trust_decisions").fetchone()[0]
        self.assertEqual(n, 2)

    def test_json_message(self):
        msg = json.loads(self.engine.evaluate(self.claim()).to_json())
        for key in ("device_id", "tier", "T", "factors", "alert", "timestamp"):
            self.assertIn(key, msg)


if __name__ == "__main__":
    unittest.main()
