"""
VitalPath: 5G Security Middleware for Connected Ambulance Telemetry
Component 2: Interactive Web Demo Server (demo_server.py)

Runs a local demonstration server on http://localhost:8080 exposing:
  1. Interactive Web Dashboard UI (index.html)
  2. Live REST API for evaluating custom vital signs, 5G metrics, and device trust
  3. Real MIMIC-III clinical telemetry stream player (4,759 packets)
  4. Real-time cryptographic packet inspection (AES-GCM, ECDSA, SHA-256)
"""

import os
import sys
import json
import time
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import Dict, Any, List

from classifiers import load_config
from pipeline import VitalPathPipeline
from trust_client import TrustVerdictClient, insert_trust_verdict
from dataset_loader import load_mimic_clinical_data, build_telemetry_stream

# Global Pipeline and Dataset instances
CONFIG = load_config("config.json")
PIPELINE = VitalPathPipeline(config=CONFIG, enable_async_logging=True)
STREAM_DATASET: List[Dict[str, Any]] = []
STREAM_INDEX: int = 0

# Runtime injection overrides for interactive live testing
INJECTED_OVERRIDES = {
    "device_id": None,
    "handover_active": None,
    "high_network_jitter": False
}


def analyze_packet_decision(pkt: Dict[str, Any], net: Dict[str, Any], secured: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Generates detailed medical, network, mathematical, and cryptographic explanations for a packet."""
    vitals = pkt.get("vitals", {})
    ranges = config.get("clinical_ranges", {})

    hr = vitals.get("hr", vitals.get("pulse", 75))
    pulse = vitals.get("pulse", hr)
    spo2 = vitals.get("spo2", 98)
    sbp = vitals.get("sbp", vitals.get("bp_sys", 120))
    dbp = vitals.get("dbp", vitals.get("bp_dia", 80))
    resp = vitals.get("resp", vitals.get("rr", 16))

    def evaluate_metric(val, n_min, n_max, c_min, c_max, unit):
        if val < c_min or val > c_max:
            return {"val": val, "status": "CRITICAL", "desc": f"Critical abnormal (<{c_min} or >{c_max} {unit})", "unit": unit}
        if val < n_min or val > n_max:
            return {"val": val, "status": "BORDERLINE", "desc": f"Borderline elevation ({n_min}-{n_max} {unit})", "unit": unit}
        return {"val": val, "status": "NORMAL", "desc": f"Normal resting range ({n_min}-{n_max} {unit})", "unit": unit}

    hr_eval = evaluate_metric(hr, ranges["hr"]["normal_min"], ranges["hr"]["normal_max"], ranges["hr"]["critical_min"], ranges["hr"]["critical_max"], "bpm")
    spo2_status = "CRITICAL" if spo2 < ranges["spo2"]["critical_min"] else ("BORDERLINE" if spo2 < ranges["spo2"]["normal_min"] else "NORMAL")
    spo2_eval = {"val": spo2, "status": spo2_status, "desc": f">={ranges['spo2']['normal_min']}% expected" if spo2_status=="NORMAL" else f"Desaturation (<{ranges['spo2']['critical_min']}%)", "unit": "%"}
    sbp_eval = evaluate_metric(sbp, ranges["bp_sys"]["normal_min"], ranges["bp_sys"]["normal_max"], ranges["bp_sys"]["critical_min"], ranges["bp_sys"]["critical_max"], "mmHg")
    dbp_eval = evaluate_metric(dbp, ranges["bp_dia"]["normal_min"], ranges["bp_dia"]["normal_max"], ranges["bp_dia"]["critical_min"], ranges["bp_dia"]["critical_max"], "mmHg")
    resp_eval = evaluate_metric(resp, ranges["rr"]["normal_min"], ranges["rr"]["normal_max"], ranges["rr"]["critical_min"], ranges["rr"]["critical_max"], "/min")
    pulse_eval = {"val": pulse, "status": "NORMAL" if abs(pulse - hr) <= 5 else "FLAGGED", "desc": f"Consistent with HR (Δ {abs(pulse-hr)} bpm)", "unit": "bpm"}

    factors = secured.get("factors", {})
    dts = factors.get("dts", 0.70)
    cc = factors.get("cc", 0.20)
    nc = factors.get("nc", 0.00)
    sps = secured.get("sps", 0.00)
    profile = secured.get("profile", "Standard")

    w = config.get("sps_weights", {"w_dts": 0.35, "w_cc": 0.45, "w_nc": 0.20})
    w_dts = w.get("w_dts", 0.35)
    w_cc = w.get("w_cc", 0.45)
    w_nc = w.get("w_nc", 0.20)

    term_dts = w_dts * (1.0 - dts)
    term_cc = w_cc * cc
    term_nc = w_nc * nc

    # Why explanation bullets
    bullets = []
    # Clinical
    crit_vitals = [k for k, v in [("HR", hr_eval), ("SpO2", spo2_eval), ("SBP", sbp_eval), ("DBP", dbp_eval), ("RESP", resp_eval)] if v["status"] == "CRITICAL"]
    bord_vitals = [k for k, v in [("HR", hr_eval), ("SpO2", spo2_eval), ("SBP", sbp_eval), ("DBP", dbp_eval), ("RESP", resp_eval)] if v["status"] == "BORDERLINE"]
    if crit_vitals:
        bullets.append(f"Life-critical telemetry in {', '.join(crit_vitals)} drove Clinical Criticality to maximum (CC = 1.00, contributing +{term_cc:.3f} to SPS).")
    elif bord_vitals:
        bullets.append(f"Borderline physiological elevation in {', '.join(bord_vitals)} elevated Clinical Criticality to CC = 0.60 (contributing +{term_cc:.3f} to SPS).")
    else:
        bullets.append(f"All patient vital signs are within normal resting thresholds (CC = 0.20, contributing +{term_cc:.3f} to SPS).")

    # Trust
    dev_id = pkt.get("device_id", "UNKNOWN")
    if dts >= 0.90:
        bullets.append(f"Device '{dev_id}' verified by Component 1 with high trust (DTS = {dts:.2f}) - minimal trust penalty (+{term_dts:.3f}).")
    elif dts >= 0.50:
        bullets.append(f"Device '{dev_id}' has conditional trust (DTS = {dts:.2f}) - moderate trust risk (+{term_dts:.3f}).")
    else:
        bullets.append(f"Device '{dev_id}' is untrusted or blocked by Component 1 (DTS = {dts:.2f}) - maximum trust penalty (+{term_dts:.3f}).")

    # Network
    rtt = net.get("rtt_ms", 20.0)
    loss = net.get("packet_loss_pct", 0.0)
    handover = net.get("handover_active", False)
    if handover:
        bullets.append(f"Active 5G cell handover detected (+0.30 NC penalty) reflecting higher interception and link drop risk.")
    if rtt > 50 or loss > 2.0:
        bullets.append(f"5G link degradation present (RTT = {rtt:.1f}ms, Loss = {loss:.1f}%, NC = {nc:.2f}, contributing +{term_nc:.3f}).")
    else:
        bullets.append(f"5G channel optimal (RTT = {rtt:.1f}ms, Loss = {loss:.1f}%, NC = {nc:.2f}, contributing +{term_nc:.3f}).")

    # Profile summary
    if profile == "Maximum":
        rationale = f"Composite SPS = {sps:.3f} exceeds Maximum threshold (0.75). Enforcing Maximum Security Profile: AES-256-GCM authenticated encryption + ECDSA P-256 digital signature + rapid 10s session key rotation to guarantee patient telemetry integrity during high risk."
    elif profile == "Enhanced":
        rationale = f"Composite SPS = {sps:.3f} falls in Enhanced range (0.40 < SPS <= 0.75). Enforcing Enhanced Security Profile: AES-256-GCM encryption with 60s key rotation; digital signature omitted to preserve 5G channel bandwidth."
    else:
        rationale = f"Composite SPS = {sps:.3f} <= 0.40 threshold. Enforcing Standard Security Profile: AES-256-GCM encryption with 300s session key lifetime, optimizing ambulance edge power and computational overhead."

    return {
        "vitals_eval": {
            "hr": hr_eval,
            "spo2": spo2_eval,
            "sbp": sbp_eval,
            "dbp": dbp_eval,
            "resp": resp_eval,
            "pulse": pulse_eval
        },
        "network_eval": {
            "rtt_ms": rtt,
            "packet_loss_pct": loss,
            "handover_active": handover,
            "nc": nc
        },
        "trust_eval": {
            "device_id": dev_id,
            "dts": dts,
            "inverted_dts": round(1.0 - dts, 3),
            "tier": "FULL_TRUST" if dts >= 0.9 else ("CONDITIONAL" if dts >= 0.5 else "BLOCKED")
        },
        "math_breakdown": {
            "formula": "SPS = (w_dts × (1 - DTS)) + (w_cc × CC) + (w_nc × NC)",
            "w_dts": w_dts,
            "w_cc": w_cc,
            "w_nc": w_nc,
            "term_dts": round(term_dts, 4),
            "term_cc": round(term_cc, 4),
            "term_nc": round(term_nc, 4),
            "sps": round(sps, 4),
            "thresholds": config.get("profile_thresholds", {"standard_max": 0.40, "enhanced_max": 0.75}),
        },
        "why_explanation": {
            "profile": profile,
            "rationale": rationale,
            "factors": bullets
        }
    }


def init_demo_environment():
    """Initializes sample SQLite trust database and preloads the MIMIC-III stream."""
    global STREAM_DATASET

    db_path = "trust.db"
    print(f"[+] Setting up Component 1 SQLite trust database: '{db_path}'...")
    insert_trust_verdict(db_path, "ECG-01", 0.95, "FULL_TRUST", monitoring_flag=False)
    insert_trust_verdict(db_path, "SPO2-02", 0.72, "CONDITIONAL", monitoring_flag=True)
    insert_trust_verdict(db_path, "BP-03", 0.00, "BLOCKED", monitoring_flag=True)
    insert_trust_verdict(db_path, "UNKNOWN-99", 0.70, "FALLBACK", monitoring_flag=True)

    print("[+] Loading real MIMIC-III clinical datasets (data.xlsx, data 2.xlsx, data 3.xlsx)...")
    try:
        clinical_df = load_mimic_clinical_data("..")
        STREAM_DATASET = build_telemetry_stream(clinical_df=clinical_df, parent_dir="..", seed=42)
        print(f"  Successfully loaded {len(STREAM_DATASET):,} telemetry packets.")
    except Exception as e:
        print(f"[!] Warning: Could not load Excel files ({e}). Using synthetic stream.")
        from dataset_loader import build_telemetry_stream as build_synth
        STREAM_DATASET = build_synth(clinical_df=None, parent_dir="..", seed=42)


class VitalPathDemoHandler(SimpleHTTPRequestHandler):
    """HTTP Request Handler providing REST endpoints for Component 2 Demo."""

    def __init__(self, *args, **kwargs):
        # Serve static files from 'web' directory
        super().__init__(*args, directory=os.path.join(os.path.dirname(__file__), "web"), **kwargs)

    def do_GET(self):
        global STREAM_INDEX

        if self.path == "/" or self.path == "/index.html":
            return super().do_GET()

        elif self.path == "/api/stream/next":
            global STREAM_INDEX
            if not STREAM_DATASET:
                self._send_json({"error": "Stream dataset empty"}, status=500)
                return

            item = STREAM_DATASET[STREAM_INDEX % len(STREAM_DATASET)]
            STREAM_INDEX += 1

            pkt = dict(item["packet"])
            pkt["vitals"] = dict(item["packet"]["vitals"])
            net = dict(item["network"])

            # Apply runtime injection overrides if active
            if INJECTED_OVERRIDES["device_id"]:
                pkt["device_id"] = INJECTED_OVERRIDES["device_id"]
            if INJECTED_OVERRIDES["handover_active"] is not None:
                net["handover_active"] = INJECTED_OVERRIDES["handover_active"]
            if INJECTED_OVERRIDES["high_network_jitter"]:
                net["rtt_ms"] = max(net.get("rtt_ms", 20.0), 95.0)
                net["packet_loss_pct"] = max(net.get("packet_loss_pct", 0.1), 4.5)

            secured = PIPELINE.process_packet(pkt, net)
            analysis = analyze_packet_decision(pkt, net, secured, CONFIG)

            resp_payload = {
                "index": STREAM_INDEX,
                "packet_id": secured["packet_id"],
                "device_id": pkt["device_id"],
                "patient_id": pkt.get("patient_id", "AMB_04_P001"),
                "vitals": pkt["vitals"],
                "network": net,
                "sps": secured["sps"],
                "profile": secured["profile"],
                "factors": secured.get("factors", {}),
                "key_id": secured["key_id"],
                "key_rotation_seconds": secured.get("key_rotation_seconds", 60),
                "key_rotated": secured["key_rotated"],
                "ciphertext_sample": secured["ciphertext"][:48] + "...",
                "sha256_digest": secured["sha256_digest"],
                "has_signature": secured["ecdsa_signature"] is not None,
                "decision_latency_ms": secured["decision_latency_ms"],
                "crypto_latency_ms": secured["crypto_latency_ms"],
                "total_latency_ms": secured["total_latency_ms"],
                "analysis": analysis,
            }
            self._send_json(resp_payload)
            return

        elif self.path == "/api/stream/reset":
            STREAM_INDEX = 0
            self._send_json({"status": "Stream reset to packet 0"})
            return

        elif self.path == "/api/metrics":
            metrics = PIPELINE.get_metrics()
            self._send_json(metrics)
            return

        elif self.path == "/api/devices":
            devices = [
                {"device_id": "ECG-01", "name": "12-Lead ECG Monitor", "trust": 0.95, "tier": "FULL_TRUST"},
                {"device_id": "SPO2-02", "name": "Pulse Oximeter", "trust": 0.72, "tier": "CONDITIONAL"},
                {"device_id": "BP-03", "name": "NIBP Cuff (Clone/Compromised)", "trust": 0.00, "tier": "BLOCKED"},
                {"device_id": "UNKNOWN-99", "name": "Unregistered Sensor Patch", "trust": 0.70, "tier": "FALLBACK"},
            ]
            self._send_json({"devices": devices})
            return

        else:
            return super().do_GET()

    def do_POST(self):
        if self.path == "/api/stream/inject":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode("utf-8")) if body else {}

            if "device_id" in data:
                INJECTED_OVERRIDES["device_id"] = data["device_id"] if data["device_id"] != "AUTO" else None
            if "handover_active" in data:
                INJECTED_OVERRIDES["handover_active"] = data["handover_active"]
            if "high_network_jitter" in data:
                INJECTED_OVERRIDES["high_network_jitter"] = bool(data["high_network_jitter"])

            self._send_json({"status": "Overrides updated", "overrides": INJECTED_OVERRIDES})
            return

        elif self.path == "/api/evaluate":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode("utf-8"))

            vitals = data.get("vitals", {})
            net = data.get("network", {})
            device_id = data.get("device_id", "ECG-01")

            packet = {
                "packet_id": f"pkt_demo_{int(time.time()*1000)%100000}",
                "patient_id": "AMB_DEMO_PATIENT",
                "device_id": device_id,
                "vitals": vitals,
            }

            secured = PIPELINE.process_packet(packet, net)
            self._send_json(secured)
            return

        else:
            self._send_json({"error": "Endpoint not found"}, status=404)

    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Mute repetitive static polling logs
        return


def start_server(port: int = 8080, open_browser: bool = True):
    init_demo_environment()
    server_address = ("", port)
    httpd = HTTPServer(server_address, VitalPathDemoHandler)
    url = f"http://localhost:{port}"

    print("\n" + "=" * 78)
    print("VITALPATH COMPONENT 2: INTERACTIVE DEMO SERVER RUNNING")
    print("=" * 78)
    print(f"  Local Web UI  : {url}")
    print(f"  REST API      : {url}/api/stream/next")
    print(f"  Press Ctrl+C in this terminal to stop the server.")
    print("=" * 78 + "\n")

    if open_browser:
        try:
            import subprocess
            if sys.platform == "win32":
                subprocess.Popen(f'explorer "{url}"', shell=True)
            else:
                webbrowser.open(url)
        except Exception:
            try:
                webbrowser.open(url)
            except Exception:
                pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Shutting down VitalPath Demo Server...")
        PIPELINE.shutdown()
        httpd.server_close()
        print("[+] Server stopped cleanly.")


if __name__ == "__main__":
    port = 8080
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    start_server(port=port, open_browser=True)

