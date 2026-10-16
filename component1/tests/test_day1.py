"""Unit tests for the ADL gate and Certificate factor (C).
Run from project root:  python3 -m unittest discover -s tests -v
Requires the PKI to be built first:  bash pki/setup_ca.sh
"""
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from trust.registry import DeviceRegistry          # noqa: E402
from trust.cert_factor import CertificateValidator  # noqa: E402

PKI = ROOT / "pki" / "out"


def pem(rel):
    return (PKI / rel).read_bytes()


class TestCertificateFactor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.reg = DeviceRegistry(Path(cls.tmp.name) / "adl.db")
        for d in ("ECG-01", "SPO2-02", "BP-03", "HR-04", "RR-05"):
            cls.reg.register(d, "test", "AMB-T", PKI / f"devices/{d}.crt",
                             "02:00:00:00:00:01", f"HW-{d}")
        cls.v = CertificateValidator(PKI / "ca/root_ca.crt", PKI / "ca/root_ca.crl")

    @classmethod
    def tearDownClass(cls):
        cls.reg.conn.close()
        cls.tmp.cleanup()

    def eval(self, rel, claimed, **kw):
        return self.v.evaluate(pem(rel), claimed, self.reg.lookup(claimed), **kw)

    def test_valid_cert_scores_one(self):
        r = self.eval("devices/ECG-01.crt", "ECG-01")
        self.assertEqual(r.score, 1.0)
        self.assertFalse(r.hard_fail)

    def test_expired_is_hard_fail(self):
        r = self.eval("devices/BP-03.crt", "BP-03")
        self.assertTrue(r.hard_fail)
        self.assertEqual(r.score, 0.0)
        self.assertFalse(r.checks["in_validity_period"])

    def test_revoked_is_hard_fail(self):
        r = self.eval("devices/HR-04.crt", "HR-04")
        self.assertTrue(r.hard_fail)
        self.assertFalse(r.checks["not_revoked"])

    def test_forged_clone_is_hard_fail(self):
        r = self.eval("rogue/ECG-01_forged.crt", "ECG-01")
        self.assertTrue(r.hard_fail)
        self.assertFalse(r.checks["trusted_issuer"])

    def test_cert_reuse_across_devices_is_hard_fail(self):
        r = self.eval("devices/ECG-01.crt", "SPO2-02")
        self.assertTrue(r.hard_fail)
        self.assertFalse(r.checks["cn_matches_id"])

    def test_near_expiry_is_penalised_not_blocked(self):
        r = self.eval("devices/RR-05.crt", "RR-05")
        self.assertFalse(r.hard_fail)
        self.assertEqual(r.score, 0.75)

    def test_valid_cert_becomes_hard_fail_after_expiry(self):
        future = datetime.now(timezone.utc) + timedelta(days=400)
        r = self.eval("devices/ECG-01.crt", "ECG-01", now=future)
        self.assertTrue(r.hard_fail)

    def test_malformed_cert(self):
        r = self.v.evaluate(b"not a certificate", "ECG-01")
        self.assertTrue(r.hard_fail)

    def test_unknown_device_rejected_by_adl(self):
        ok, reason = self.reg.is_authorised("ROGUE-99")
        self.assertFalse(ok)
        self.assertIn("UNKNOWN_DEVICE", reason)

    def test_suspended_device_rejected_by_adl(self):
        self.reg.conn.execute(
            "UPDATE authorised_devices SET status='suspended' WHERE device_id='SPO2-02'")
        ok, _ = self.reg.is_authorised("SPO2-02")
        self.assertFalse(ok)
        self.reg.conn.execute(
            "UPDATE authorised_devices SET status='active' WHERE device_id='SPO2-02'")


if __name__ == "__main__":
    unittest.main()
