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

            pkt = item["packet"]
            net = item["network"]

            secured = PIPELINE.process_packet(pkt, net)

            resp_payload = {
                "index": STREAM_INDEX,
                "packet_id": secured["packet_id"],
                "device_id": pkt["device_id"],
                "vitals": pkt["vitals"],
                "network": net,
                "sps": secured["sps"],
                "profile": secured["profile"],
                "key_id": secured["key_id"],
                "key_rotated": secured["key_rotated"],
                "ciphertext_sample": secured["ciphertext"][:32] + "...",
                "sha256_digest": secured["sha256_digest"],
                "has_signature": secured["ecdsa_signature"] is not None,
                "decision_latency_ms": secured["decision_latency_ms"],
                "crypto_latency_ms": secured["crypto_latency_ms"],
                "total_latency_ms": secured["total_latency_ms"],
            }
            self._send_json(resp_payload)
            return

        elif self.path == "/api/metrics":
            metrics = PIPELINE.get_metrics()
            self._send_json(metrics)
            return

        elif self.path == "/api/devices":
            devices = [
                {"device_id": "ECG-01", "name": "12-Lead ECG Monitor", "trust": 0.95, "tier": "FULL_TRUST"},
                {"device_id": "SPO2-02", "name": "Pulse Oximeter", "trust": 0.72, "tier": "CONDITIONAL"},
                {"device_id": "BP-03", "name": "NIBP Cuff (Clone)", "trust": 0.00, "tier": "BLOCKED"},
                {"device_id": "UNKNOWN-99", "name": "Unregistered Patch", "trust": 0.70, "tier": "FALLBACK"},
            ]
            self._send_json({"devices": devices})
            return

        else:
            return super().do_GET()

    def do_POST(self):
        if self.path == "/api/evaluate":
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
        webbrowser.open(url)

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
