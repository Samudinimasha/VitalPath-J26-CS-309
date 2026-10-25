"""
VitalPath Component 1 - demonstration website backend.

Serves web/index.html and exposes the REAL Component 1 engine
(trust/registry.py, cert_factor.py, fingerprint_factor.py,
health_factor.py, engine.py) as a small JSON API, so every decision
shown in the browser is made by the Python TrustEngine and written to
the trust_decisions table.

Standard library only (no new dependencies).

    bash pki/setup_ca.sh          # once, builds the PKI
    python3 web/server.py         # then open http://localhost:8000

API
    GET  /api/status     engine info, PKI certificates, Authorised Device List
    POST /api/evaluate   one connection attempt -> TrustDecision + factor detail
    POST /api/cert       ADL gate + Certificate factor only (demo_day1.py)
    GET  /api/log        latest rows of trust_decisions
    POST /api/device     set a device's ADL status (active | suspended)
    POST /api/reset      rebuild the ADL and clear the decision log
    POST /api/tests      run the unit test suite and return the results
"""
import json
import re
import subprocess
import sys
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Lock

ROOT = Path(__file__).resolve().parent.parent          # component1/
sys.path.insert(0, str(ROOT))

from cryptography import x509                                    # noqa: E402
from cryptography.hazmat.primitives import hashes                # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID   # noqa: E402

from trust.cert_factor import CertificateValidator               # noqa: E402
from trust.engine import DeviceClaim, TrustEngine                # noqa: E402
from trust.fingerprint_factor import evaluate_fingerprint        # noqa: E402
from trust.health_factor import HealthReport, evaluate_health    # noqa: E402
from trust.registry import DeviceRegistry                        # noqa: E402

PKI = ROOT / "pki" / "out"
DB = ROOT / "data" / "web_demo.db"
PAGE = Path(__file__).resolve().parent / "index.html"
PORT = 8000

# Same registered fleet as demo.py (ambulance AMB-CMB-07)
FLEET = [
    ("ECG-01",  "ECG monitor",       "02:1a:7c:00:00:01", "HWID-ECG-7731"),
    ("SPO2-02", "Pulse oximeter",    "02:1a:7c:00:00:02", "HWID-SPO-2214"),
    ("BP-03",   "NIBP cuff",         "02:1a:7c:00:00:03", "HWID-NBP-9902"),
    ("HR-04",   "Heart-rate sensor", "02:1a:7c:00:00:04", "HWID-HRS-4410"),
    ("RR-05",   "Resp. rate sensor", "02:1a:7c:00:00:05", "HWID-RRS-5521"),
]
# Certificates the page may present. Only these files can be chosen.
CERT_FILES = {
    "devices/ECG-01.crt": "device", "devices/SPO2-02.crt": "device",
    "devices/BP-03.crt": "device", "devices/HR-04.crt": "device",
    "devices/RR-05.crt": "device", "rogue/ECG-01_forged.crt": "forged",
    "rogue/ROGUE-99.crt": "rogue",
}

lock = Lock()
state = {}


def build():
    """(Re)create the ADL and engine exactly as demo.py does."""
    DB.parent.mkdir(exist_ok=True)
    if "registry" in state:
        state["registry"].conn.close()
    DB.unlink(missing_ok=True)
    reg = DeviceRegistry(DB)
    for dev_id, dev_type, mac, hwid in FLEET:
        reg.register(dev_id, dev_type, "AMB-CMB-07", PKI / f"devices/{dev_id}.crt", mac, hwid)
    validator = CertificateValidator(PKI / "ca/root_ca.crt", PKI / "ca/root_ca.crl")
    state.update(registry=reg, validator=validator, engine=TrustEngine(reg, validator))


def cert_info(rel, role):
    path = PKI / rel
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    ca = state["validator"].ca
    try:
        cert.verify_directly_issued_by(ca)
        trusted = True
    except Exception:
        trusted = False
    try:
        eku = ExtendedKeyUsageOID.CLIENT_AUTH in cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        eku = False
    crl = state["validator"].crl
    revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number) if crl else None
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return {
        "file": rel, "role": role, "cn": cns[0].value if cns else None,
        "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "X"),
        "nb": cert.not_valid_before_utc.isoformat(), "na": cert.not_valid_after_utc.isoformat(),
        "sha256": cert.fingerprint(hashes.SHA256()).hex(), "trusted": trusted, "eku": eku,
        "revoked": revoked.revocation_date_utc.isoformat() if revoked else None,
        "key": "ECDSA P-256", "pem": path.read_text(),
    }


def openssl_verify(rel):
    try:
        out = subprocess.run(
            ["openssl", "verify", "-CAfile", str(PKI / "ca/root_ca.crt"),
             "-CRLfile", str(PKI / "ca/root_ca.crl"), "-crl_check", str(PKI / rel)],
            capture_output=True, text=True, timeout=10)
        text = (out.stdout + out.stderr)
        m = re.search(r"error \d+ at \d+ depth lookup: .*", text)
        return m.group(0) if m else ("OK" if ": OK" in text else text.strip()[-120:])
    except Exception as exc:  # openssl missing
        return f"openssl not available ({exc.__class__.__name__})"


def status():
    reg, val = state["registry"], state["validator"]
    certs = [cert_info("ca/root_ca.crt", "root")]
    certs += [cert_info(rel, role) for rel, role in CERT_FILES.items()]
    certs.append(cert_info("rogue/rogue_ca.crt", "rogueca"))
    for c in certs:
        if c["role"] != "root":
            c["openssl"] = openssl_verify(c["file"])
    crl = val.crl
    return {
        "engine": "python",
        "crl_last": crl.last_update_utc.isoformat() if crl else None,
        "crl_next": crl.next_update_utc.isoformat() if crl else None,
        "crl_count": len(list(crl)) if crl else 0,
        "certs": certs,
        "adl": [asdict(r) for r in reg.all()],
    }


def evaluate(body):
    reg, val, engine = state["registry"], state["validator"], state["engine"]
    rel = body.get("cert_file")
    if rel not in CERT_FILES:
        raise ValueError("unknown certificate file")
    cert_pem = (PKI / rel).read_bytes()
    h = body.get("health")
    health = None if h is None else HealthReport(
        float(h["battery"]), float(h["err"]), str(h["fw"]), float(h["hb"]))
    claim = DeviceClaim(str(body["device_id"]), cert_pem, body.get("mac") or None,
                        body.get("hw") or None, health,
                        behaviour=float(body.get("B", 1)), reputation=float(body.get("R", 1)))

    # Per-factor detail for the page (same functions the engine calls)
    detail = None
    record = reg.lookup(claim.device_id)
    if record is not None and record.status == "active":
        c = val.evaluate(cert_pem, claim.device_id, record)
        f = evaluate_fingerprint(record, claim.mac, claim.hardware_id, reg)
        hr = evaluate_health(health) if health else None
        detail = {
            "c": {"score": c.score, "hard": c.hard_fail, "checks": c.checks,
                  "reasons": c.reasons, "days_to_expiry": c.days_to_expiry},
            "f": {"score": f.score, "hard": f.hard_fail, "checks": f.checks, "reasons": f.reasons},
            "h": ({"score": hr.score, "parts": hr.parts, "reasons": hr.reasons}
                  if hr else {"score": 0.0, "parts": None, "reasons": ["NO_HEALTH_REPORT"]}),
        }

    d = engine.evaluate(claim)            # the real decision, logged to SQLite
    out = asdict(d)
    out["detail"] = detail
    return out


def cert_only(body):
    """ADL gate + Certificate factor only (what demo_day1.py shows)."""
    reg, val = state["registry"], state["validator"]
    rel = body.get("cert_file")
    if rel not in CERT_FILES:
        raise ValueError("unknown certificate file")
    ok, why = reg.is_authorised(str(body["device_id"]))
    if not ok:
        return {"adl": False, "adl_reason": why}
    c = val.evaluate((PKI / rel).read_bytes(), body["device_id"], reg.lookup(body["device_id"]))
    return {"adl": True, "adl_reason": why, "score": c.score, "hard": c.hard_fail,
            "checks": c.checks, "reasons": c.reasons, "days_to_expiry": c.days_to_expiry}


def decision_log(limit=200):
    rows = state["registry"].conn.execute(
        "SELECT id, ts, device_id, tier, T, C, F, H, B, R, gate, reasons "
        "FROM trust_decisions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) | {"reasons": json.loads(r["reasons"] or "[]")} for r in rows]


def set_device(body):
    status_ = body.get("status")
    if status_ not in ("active", "suspended"):
        raise ValueError("status must be active or suspended")
    reg = state["registry"]
    reg.conn.execute("UPDATE authorised_devices SET status = ? WHERE device_id = ?",
                     (status_, body.get("device_id")))
    reg.conn.commit()
    return {"ok": True}


def run_tests():
    out = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                         cwd=ROOT, capture_output=True, text=True, timeout=120)
    text = out.stderr + out.stdout
    results = [{"name": m.group(1), "cls": m.group(2), "status": m.group(3)}
               for m in re.finditer(r"^(test\w+) \((?:[\w.]+)\.(\w+)\.test\w+\) \.\.\. (ok|FAIL|ERROR|skipped.*)$",
                                    text, re.M)]
    summary = re.search(r"Ran (\d+) tests? in ([\d.]+)s", text)
    return {"results": results, "ran": int(summary.group(1)) if summary else len(results),
            "seconds": float(summary.group(2)) if summary else None,
            "ok": out.returncode == 0, "raw": text[-4000:]}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    def do_GET(self):
        try:
            if self.path in ("/", "/index.html") or self.path.startswith("/#"):
                return self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
            with lock:
                if self.path == "/api/status":
                    return self._send(200, status())
                if self.path.startswith("/api/log"):
                    return self._send(200, decision_log())
            self._send(404, {"error": "not found"})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def do_POST(self):
        try:
            body = self._body()
            if self.path == "/api/tests":
                return self._send(200, run_tests())
            with lock:
                if self.path == "/api/evaluate":
                    return self._send(200, evaluate(body))
                if self.path == "/api/cert":
                    return self._send(200, cert_only(body))
                if self.path == "/api/device":
                    return self._send(200, set_device(body))
                if self.path == "/api/reset":
                    build()
                    return self._send(200, {"ok": True})
            self._send(404, {"error": "not found"})
        except (KeyError, ValueError) as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def log_message(self, fmt, *args):
        sys.stderr.write("  %s\n" % (fmt % args))


def main():
    if not (PKI / "ca/root_ca.crt").exists():
        sys.exit("PKI not found. Run:  bash pki/setup_ca.sh")
    build()
    print(f"VitalPath Component 1 demo  ->  http://localhost:{PORT}")
    print("Engine: Python TrustEngine, decisions logged to", DB.relative_to(ROOT))
    # Single-threaded on purpose: the registry's SQLite connection belongs to one thread.
    try:
        HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
