"""Live sender: an ambulance streaming real, encrypted vitals over UDP, plus an attacker.

Usage (from component3/):
    PYTHONPATH=src python3 -m simulator.sender                  # legitimate stream only
    PYTHONPATH=src python3 -m simulator.sender --attacks        # stream + scripted attacks
    PYTHONPATH=src python3 -m simulator.sender --data datasets/mimic3wdb_3000003n.csv --rate 10
    PYTHONPATH=src python3 -m simulator.sender --attacks --start 60   # skip bidmc53n's early tachypnoea

Vitals come from a PhysioNet recording (default: bidmc_53n, 1 Hz) and are
sealed with the AES-GCM stand-in for Component 2. With --attacks, after every
--every legitimate packets the next event below is injected:

    replay     attacker resends a captured packet                      (S2)
    handover   link drops 3 s; attacker resends a captured packet with
               a refreshed timestamp; stream resumes with the next seq  (S3, S4)
    reorder    network delivers two packets in swapped order           (legitimate)
    spike      sensor reports heart rate 300 bpm                       (S5)
    jump       attacker injects a far-ahead sequence number            (S10)
    probe-off  oximeter probe slips: SpO2 13.9% with a normal HR       (S6)
    tamper     attacker flips bits in a packet's encrypted payload
    stale      attacker sends a packet stamped 60 s ago
    future     attacker sends a packet stamped 10 s ahead
    malformed  packet arrives with a corrupted timestamp field         (S9)
    flood      50 packets in one second                                (S8)
"""

import argparse
import dataclasses
import itertools
import json
import os
import socket
import time

from simulator.demo_keys import demo_key
from simulator.wire import DEFAULT_HOST, DEFAULT_PORT, encode
from vitalpath_c3.crypto.payload import seal
from vitalpath_c3.data.loaders import load_vitals_csv
from vitalpath_c3.models import PacketHeader, VitalSigns

ATTACKS = ["replay", "handover", "reorder", "spike", "jump", "probe-off",
           "tamper", "stale", "future", "malformed", "flood"]


class Ambulance:
    def __init__(self, sock, addr, device_id, interval, vitals, case_id=None):
        self.sock = sock
        self.addr = addr
        self.device_id = device_id
        self.case_id = case_id
        self.key = demo_key(device_id)
        self.interval = interval
        self.vitals = vitals  # endless iterator of VitalSigns
        self.seq = 0
        self.captured = []  # datagrams an eavesdropper on the link has recorded

    def _datagram(self, seq, vitals, ts=None):
        header = PacketHeader(self.device_id, seq, time.time() if ts is None else ts, self.case_id)
        packet = seal(header, vitals, self.key)
        return encode(header.device_id, header.seq, header.timestamp, packet.payload, self.case_id)

    def _send(self, datagram):
        self.sock.sendto(datagram, self.addr)

    def _next(self, vitals=None):
        """Send the next genuine packet (optionally with chosen vitals)."""
        self.seq += 1
        datagram = self._datagram(self.seq, vitals or next(self.vitals))
        self.captured.append(datagram)
        self._send(datagram)

    def legit(self):
        self._next()
        time.sleep(self.interval)

    def event(self, name):
        say = lambda text: print(f"  >> {text}")
        if name == "replay":
            say(f"ATTACK replay: resending captured seq {self.seq - 2}")
            self._send(self.captured[-3])
        elif name == "handover":
            say("HANDOVER: link down for 3 s ...")
            time.sleep(3)
            old = json.loads(self.captured[-2])
            say(f"ATTACK post-handover replay of seq {old['seq']} with refreshed timestamp")
            self._send(encode(old["device_id"], old["seq"], time.time(), bytes.fromhex(old["payload"]), old["case_id"]))
            say(f"stream resumes with seq {self.seq + 1}")
        elif name == "reorder":
            a, b = self.seq + 1, self.seq + 2
            da, db = self._datagram(a, next(self.vitals)), self._datagram(b, next(self.vitals))
            self.seq = b
            self.captured += [da, db]
            say(f"network reorders: {b} arrives before {a}")
            self._send(db)
            self._send(da)
        elif name == "spike":
            say("SENSOR heart rate 300 bpm")
            self._next(dataclasses.replace(next(self.vitals), hr=300.0, pulse=300.0))
        elif name == "jump":
            seq = self.seq + 50_000
            say(f"ATTACK injected seq {seq} with forged payload")
            self._send(encode(self.device_id, seq, time.time(), os.urandom(60), self.case_id))
        elif name == "probe-off":
            say("SENSOR oximeter probe slipped: SpO2 13.9% with normal HR")
            self._next(VitalSigns(hr=64.0, pulse=72.3, spo2=13.9))
        elif name == "tamper":
            datagram = self._datagram(self.seq + 1, next(self.vitals))
            obj = json.loads(datagram)
            payload = bytearray(bytes.fromhex(obj["payload"]))
            payload[-1] ^= 0xFF
            say(f"ATTACK tampered payload for seq {self.seq + 1}")
            self._send(encode(obj["device_id"], obj["seq"], obj["timestamp"], bytes(payload), obj["case_id"]))
        elif name == "stale":
            say("ATTACK packet stamped 60 s ago")
            self._send(encode(self.device_id, self.seq + 1, time.time() - 60, os.urandom(60), self.case_id))
        elif name == "future":
            say("ATTACK packet stamped 10 s in the future")
            self._send(encode(self.device_id, self.seq + 1, time.time() + 10, os.urandom(60), self.case_id))
        elif name == "malformed":
            say("CORRUPT packet with timestamp field 'corrupted'")
            self._send(encode(self.device_id, self.seq + 1, "corrupted", os.urandom(60), self.case_id))
        elif name == "flood":
            say("FLOOD 50 packets in one second")
            for _ in range(50):
                self._next()
                time.sleep(0.02)
        time.sleep(self.interval)


def endless_vitals(path, start=0):
    rows = [v for _, v in load_vitals_csv(path)[start:] if any(dataclasses.astuple(v))]
    if not rows:
        raise SystemExit(f"{path}: no readings")
    return itertools.cycle(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--device", default="MON-01", help="patient monitor sending the packets")
    parser.add_argument("--case", default="CASE001", help="emergency case ID from dispatch")
    parser.add_argument("--reason", default="cardiac arrest", help="dispatch reason (display only)")
    parser.add_argument("--unit", default="AMB-07", help="ambulance (display only)")
    parser.add_argument("--data", default="datasets/bidmc_53n.csv", help="PhysioNet CSV to stream")
    parser.add_argument("--start", type=int, default=0, help="row of the recording to start from")
    parser.add_argument("--rate", type=float, default=5.0, help="packets per second")
    parser.add_argument("--count", type=int, default=0, help="stop after N legit packets (0 = forever)")
    parser.add_argument("--attacks", action="store_true", help="inject scripted attacks and sensor faults")
    parser.add_argument("--every", type=int, default=10, help="legit packets between events")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    amb = Ambulance(sock, (args.host, args.port), args.device, 1.0 / args.rate,
                    endless_vitals(args.data, args.start), args.case)
    print(f"Dispatch: {args.case} · {args.reason} · {args.unit} assigned (simulated)")
    events = itertools.cycle(ATTACKS)
    print(f"Streaming {args.data} as {args.device} to udp://{args.host}:{args.port} at {args.rate} pkt/s"
          f"{' with attacks' if args.attacks else ''}  (Ctrl+C to stop)")
    try:
        for n in itertools.count(1):
            amb.legit()
            if args.attacks and n % args.every == 0:
                amb.event(next(events))
            if args.count and n >= args.count:
                break
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
    print(f"Sent {amb.seq} genuine packets.")


if __name__ == "__main__":
    main()
