"""Component 3 demonstration website.

Usage (from component3/):
    PYTHONPATH=src python3 -m dashboard.server            # then open http://localhost:8000
    PYTHONPATH=src python3 -m dashboard.server --rate 2   # two packets per second

A simulated ambulance (patient monitor MON-01, case CASE001) streams a real
PhysioNet recording through the real Component 3 pipeline. Attack buttons on
the page inject replays, a 5G handover, tampering and sensor faults. Every
result is pushed to the browser as it happens (server-sent events).

Standard library only: http.server for the web server, threading for the
stream. Demo keys only (see simulator/demo_keys.py). Runs on localhost.
"""

import argparse
import dataclasses
import json
import logging
import os
import queue
import threading
import time
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from simulator.ambulance_sender import endless_vitals
from simulator.attack_demo import WHY_DISCARDED
from simulator.demo_keys import demo_key
from simulator.network_format import packet_id
from vitalpath_c3.crypto.payload_encryption import PayloadDecryptor, seal
from vitalpath_c3.detection_pipeline import Pipeline
from vitalpath_c3.engines.correlation import Kind
from vitalpath_c3.engines.replay import ReplayOutcome
from vitalpath_c3.engines.threshold import Band
from vitalpath_c3.packet_models import EncryptedPacket, PacketHeader, VitalSigns

STATIC = Path(__file__).parent / "static"
DEVICE = "MON-01"
CASE = "CASE001"
UNIT = "AMB-07"

ATTACKS = {
    "replay": "Replay: resend a captured packet",
    "handover": "5G handover + replay",
    "tamper": "Tamper with encrypted data",
    "case_swap": "Relabel to another case",
    "jump": "Fake packet ID jump",
    "stale": "Packet stamped 60 s ago",
    "future": "Packet stamped 10 s ahead",
    "malformed": "Corrupted header",
    "flood": "Flood: 50 packets in 1 s",
    "hr300": "Sensor: heart rate 300",
    "probe_off": "Sensor: oximeter probe slipped",
    "shock": "Clinical: hidden shock pattern",
}


def stages_of(result):
    """Stage-by-stage walk-through of one packet, as data for the page."""
    out = []
    rec = result.summary
    if not result.rate_limit.allowed:
        out.append(["Flood check", "bad", WHY_DISCARDED["R-RATE-LIMIT"], "R-RATE-LIMIT"])
        return out
    out.append(["Flood check", "ok", "within 20 packets per second", ""])
    r = result.replay
    if r.outcome is ReplayOutcome.ACCEPT:
        out.append(["Replay Engine", "ok", "new packet ID, timestamp fresh", r.rule.value])
    elif r.outcome is ReplayOutcome.ACCEPT_FLAGGED:
        out.append(["Replay Engine", "warn", f"suspicious jump: {r.detail}", r.rule.value])
    else:
        out.append(["Replay Engine", "bad", WHY_DISCARDED.get(r.rule.value, r.detail), r.rule.value])
        out.append(["Decrypt", "skip", "never decrypted: stopped before anyone looked inside", ""])
        return out
    if result.vitals is None:
        rule = rec.rules[0]
        out.append(["Decrypt", "bad", WHY_DISCARDED.get(rule, result.detail), rule])
        return out
    out.append(["Decrypt", "ok", "seal intact, vitals read", ""])
    th = [f for f in result.threshold.findings if f.band not in (Band.MISSING, Band.NORMAL)]
    if th:
        for f in th:
            value = "unreadable" if f.value is None else f"{f.value:g}"
            out.append(["Threshold Engine", "bad" if f.band in (Band.CRITICAL, Band.INVALID) else "warn",
                        f"{f.vital.upper()} {value} is {f.band.value}", f.rule])
    else:
        out.append(["Threshold Engine", "ok", "every vital in its normal range", ""])
    if result.correlation.findings:
        for f in result.correlation.findings:
            out.append(["Correlation Engine", "bad" if f.kind is Kind.INCONSISTENT else "warn",
                        f"{f.kind.value}: {f.detail}", f.rule])
    else:
        not_checked = len(result.correlation.not_evaluated)
        note = "vitals agree with each other" + (f" ({not_checked} rules lacked readings)" if not_checked else "")
        out.append(["Correlation Engine", "ok", note, ""])
    return out


class DemoStream:
    """The simulated ambulance, the attacker and the pipeline, run on one worker thread."""

    def __init__(self, data_path, start, rate, handover_gap=3.0):
        self.pipeline = Pipeline(PayloadDecryptor(demo_key))
        self.key = demo_key(DEVICE)
        self.vitals = endless_vitals(data_path, start)
        self.interval = 1.0 / rate
        self.handover_gap = handover_gap
        self.count = 0
        self.sent = []  # genuine packets, as an eavesdropper would capture them
        self.commands = queue.Queue()
        self.events = deque(maxlen=400)
        self.subscribers = []
        self.lock = threading.Lock()
        self.stats = Counter()
        self.latencies = deque(maxlen=2000)
        self.event_id = 0
        self.paused_until = 0.0
        self.incident = None  # most recent handover, for the incident view
        self.stopping = False

    # --- packets -------------------------------------------------------------

    def genuine(self, vitals=None):
        self.count += 1
        header = PacketHeader(DEVICE, packet_id(self.count), time.time(), CASE)
        packet = seal(header, vitals or next(self.vitals), self.key)
        self.sent.append(packet)
        if len(self.sent) > 200:
            self.sent.pop(0)
        return packet

    def process(self, packet, injected=None):
        result = self.pipeline.process(packet)
        rec = result.summary
        replay = None if result.replay is None else ("accepted" if result.replay.passed else "dropped")
        vitals = None if result.vitals is None else {
            k: v for k, v in dataclasses.asdict(result.vitals).items() if v is not None
        }
        bands = {}
        if result.threshold is not None:
            bands = {f.vital: f.band.value for f in result.threshold.findings}
        points = [] if result.decision is None else [
            {"rule": c.rule, "points": c.points, "reason": c.reason} for c in result.decision.contributions
        ]
        with self.lock:
            self.event_id += 1
            event = {
                "id": self.event_id,
                "t": time.time(),
                "packet_id": rec.packet_id if isinstance(rec.packet_id, str) else str(rec.packet_id),
                "device": rec.device_id,
                "case": rec.case_id,
                "injected": injected,
                "replay": replay,
                "decision": rec.decision,
                "label": rec.label,
                "score": rec.score,
                "rules": list(rec.rules),
                "detail": result.detail,
                "latency_ms": round(result.latency_ms, 3),
                "decrypted": result.vitals is not None,
                "vitals": vitals,
                "bands": bands,
                "points": points,
                "stages": stages_of(result),
            }
            self.events.append(event)
            self.stats["packets"] += 1
            self.stats[rec.decision] += 1
            if rec.decision == "DISCARD" and not result.decrypted:
                self.stats["discarded_unopened"] += 1
            self.latencies.append(result.latency_ms)
            if self.incident is not None and self.incident["open"]:
                self.incident["events"].append(event)
            subscribers = list(self.subscribers)
        for q in subscribers:
            q.put(event)
        return event

    # --- attacks -------------------------------------------------------------

    def attack(self, name):
        if name == "replay" and self.sent:
            self.process(self.sent[-min(3, len(self.sent))], "replay")
        elif name == "handover":
            self.incident = {"start": time.time(), "open": True, "events": [], "gap_s": self.handover_gap}
            time.sleep(self.handover_gap)  # link down while the ambulance changes cell
            captured = self.sent[-min(2, len(self.sent))]
            forged = EncryptedPacket(dataclasses.replace(captured.header, timestamp=time.time()), captured.payload)
            self.process(forged, "handover")
            self.incident["end"] = time.time()
            self.process(self.genuine(), "handover-next")
            self.incident["open"] = False
        elif name == "tamper":
            packet = self.genuine()
            body = bytearray(packet.payload)
            body[20] ^= 0xFF
            self.process(EncryptedPacket(packet.header, bytes(body)), "tamper")
            self.process(packet, "tamper-original")
        elif name == "case_swap":
            packet = self.genuine()
            swapped = EncryptedPacket(dataclasses.replace(packet.header, case_id="CASE002"), packet.payload)
            self.process(swapped, "case_swap")
            self.process(packet, "case_swap-original")
        elif name == "jump":
            header = PacketHeader(DEVICE, packet_id(self.count + 50_000), time.time(), CASE)
            self.process(EncryptedPacket(header, os.urandom(60)), "jump")
        elif name in ("stale", "future", "malformed"):
            ts = {"stale": time.time() - 60, "future": time.time() + 10, "malformed": "corrupted"}[name]
            header = PacketHeader(DEVICE, packet_id(self.count + 1), ts, CASE)
            self.process(EncryptedPacket(header, os.urandom(60)), name)
        elif name == "flood":
            for _ in range(50):  # spaced so all 50 fall inside one second
                self.process(self.genuine(), "flood")
                time.sleep(0.015)
        elif name == "hr300":
            v = dataclasses.replace(next(self.vitals), hr=300.0, pulse=300.0)
            self.process(self.genuine(v), "hr300")
        elif name == "probe_off":
            self.process(self.genuine(VitalSigns(hr=64.0, pulse=72.3, spo2=13.9, resp=18.0)), "probe_off")
        elif name == "shock":
            v = VitalSigns(hr=105.0, pulse=104.0, spo2=96.0, sbp=100.0, dbp=62.0, resp=18.0)
            self.process(self.genuine(v), "shock")

    # --- worker --------------------------------------------------------------

    def run(self):
        next_tick = time.time()
        while not self.stopping:
            try:
                name = self.commands.get(timeout=max(0.0, next_tick - time.time()))
                self.attack(name)
                next_tick = time.time() + self.interval
                continue
            except queue.Empty:
                pass
            self.process(self.genuine())
            next_tick += self.interval
            if next_tick < time.time():
                next_tick = time.time() + self.interval

    def snapshot(self):
        with self.lock:
            lat = sorted(self.latencies)
            p99 = lat[min(len(lat) - 1, int(len(lat) * 0.99))] if lat else 0
            incident = None
            if self.incident is not None:
                incident = {k: v for k, v in self.incident.items() if k != "events"}
                incident["events"] = list(self.incident["events"])
            return {
                "device": DEVICE, "case": CASE, "unit": UNIT,
                "attacks": ATTACKS,
                "events": list(self.events),
                "stats": {
                    "packets": self.stats["packets"],
                    "accepted": self.stats["ACCEPT"],
                    "flagged": self.stats["FLAG"],
                    "discarded": self.stats["DISCARD"],
                    "discarded_unopened": self.stats["discarded_unopened"],
                    "mean_ms": round(sum(lat) / len(lat), 3) if lat else 0,
                    "p99_ms": round(p99, 3),
                },
                "incident": incident,
                "settings": {"window": 1024, "max_age_s": 30, "future_skew_s": 2,
                             "backward_tolerance_s": 1, "rate_limit": "20 per second"},
            }


def make_handler(stream):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
            if self.path.startswith("/static/"):
                name = self.path[len("/static/"):]
                target = (STATIC / name).resolve()
                if STATIC.resolve() in target.parents and target.is_file():
                    ctype = {"js": "text/javascript", "css": "text/css"}.get(target.suffix[1:], "application/octet-stream")
                    return self._send(200, target.read_bytes(), ctype + "; charset=utf-8")
                return self._send(404, b"not found", "text/plain")
            if self.path == "/api/state":
                return self._send(200, json.dumps(stream.snapshot()).encode(), "application/json")
            if self.path == "/api/stream":
                return self._events()
            return self._send(404, b"not found", "text/plain")

        def do_POST(self):
            if self.path.startswith("/api/attack/"):
                name = self.path[len("/api/attack/"):]
                if name not in ATTACKS:
                    return self._send(400, b'{"error":"unknown attack"}', "application/json")
                stream.commands.put(name)
                return self._send(202, json.dumps({"queued": name}).encode(), "application/json")
            return self._send(404, b"not found", "text/plain")

        def _events(self):
            q = queue.Queue()
            with stream.lock:
                stream.subscribers.append(q)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                while True:
                    try:
                        event = q.get(timeout=15)
                        self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
                    except queue.Empty:
                        self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                with stream.lock:
                    stream.subscribers.remove(q)

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--rate", type=float, default=1.0, help="genuine packets per second")
    parser.add_argument("--data", default="datasets/bidmc_53n.csv")
    parser.add_argument("--start", type=int, default=60, help="row of the recording to start from")
    args = parser.parse_args()

    logging.getLogger("vitalpath_c3").setLevel(logging.ERROR)
    stream = DemoStream(args.data, args.start, args.rate)
    threading.Thread(target=stream.run, daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(stream))
    server.daemon_threads = True
    print(f"Component 3 demonstration website: http://localhost:{args.port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stream.stopping = True
        server.server_close()


if __name__ == "__main__":
    main()
