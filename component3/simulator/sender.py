"""Live sender: streams ambulance telemetry over UDP and injects attacks.

Usage (from component3/):
    PYTHONPATH=src python3 -m simulator.sender                  # legitimate stream only
    PYTHONPATH=src python3 -m simulator.sender --attacks        # stream + scripted attacks
    PYTHONPATH=src python3 -m simulator.sender --rate 20 --count 200

With --attacks, after every --every legitimate packets the next attack in the
list below is injected, so every rule can be watched firing in real time:

    replay      resend a packet captured earlier                  (S2)
    handover    pause the stream (cell handover), then resend a
                pre-handover packet with a refreshed timestamp,
                then continue with the correct next seq           (S3, S4)
    reorder     deliver two packets in swapped order              (legitimate)
    jump        inject a sequence number far ahead                (S10)
    stale       resend a packet with an old timestamp
    future      send a packet stamped in the future
    malformed   send a packet with a corrupted timestamp          (S9)
"""

import argparse
import itertools
import os
import socket
import time

from simulator.wire import DEFAULT_HOST, DEFAULT_PORT, encode

ATTACKS = ["replay", "handover", "reorder", "jump", "stale", "future", "malformed"]


class Ambulance:
    def __init__(self, sock, addr, device_id, interval):
        self.sock = sock
        self.addr = addr
        self.device_id = device_id
        self.interval = interval
        self.seq = 0
        self.captured = []  # what an eavesdropper on the link has recorded

    def _send(self, seq, timestamp):
        datagram = encode(self.device_id, seq, timestamp, os.urandom(32))
        self.sock.sendto(datagram, self.addr)

    def _raw(self, datagram: bytes, label: str):
        self.sock.sendto(datagram, self.addr)
        print(f"  >> ATTACK: {label}")

    def legit(self):
        self.seq += 1
        self.captured.append((self.seq, time.time()))
        self._send(self.seq, time.time())
        time.sleep(self.interval)

    def attack(self, name):
        now = time.time()
        if name == "replay":
            seq, ts = self.captured[-3]
            self._raw(encode(self.device_id, seq, ts, os.urandom(32)), f"replay of seq {seq}")
        elif name == "handover":
            print("  >> HANDOVER: link down for 3 s ...")
            time.sleep(3)
            seq, _ = self.captured[-2]
            self._raw(
                encode(self.device_id, seq, time.time(), os.urandom(32)),
                f"post-handover replay of seq {seq} with refreshed timestamp",
            )
            print(f"  >> legit: next seq {self.seq + 1} after reconnection")
        elif name == "reorder":
            a, b = self.seq + 1, self.seq + 2
            self.seq = b
            self.captured += [(a, now), (b, now)]
            print(f"  >> network reorders: {b} arrives before {a}")
            self._send(b, now)
            self._send(a, now)
        elif name == "jump":
            self._raw(encode(self.device_id, self.seq + 50_000, now, os.urandom(32)),
                      f"injected seq {self.seq + 50_000}")
        elif name == "stale":
            self._raw(encode(self.device_id, self.seq + 1, now - 60, os.urandom(32)),
                      "packet stamped 60 s ago")
        elif name == "future":
            self._raw(encode(self.device_id, self.seq + 1, now + 10, os.urandom(32)),
                      "packet stamped 10 s in the future")
        elif name == "malformed":
            self._raw(encode(self.device_id, self.seq + 1, "corrupted", os.urandom(32)),
                      "corrupted timestamp field")
        time.sleep(self.interval)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--device", default="amb-01")
    parser.add_argument("--rate", type=float, default=5.0, help="packets per second")
    parser.add_argument("--count", type=int, default=0, help="stop after N legit packets (0 = forever)")
    parser.add_argument("--attacks", action="store_true", help="inject scripted attacks")
    parser.add_argument("--every", type=int, default=10, help="legit packets between attacks")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    amb = Ambulance(sock, (args.host, args.port), args.device, 1.0 / args.rate)
    attacks = itertools.cycle(ATTACKS)
    print(f"Streaming as {args.device} to udp://{args.host}:{args.port} at {args.rate} pkt/s"
          f"{' with attacks' if args.attacks else ''}  (Ctrl+C to stop)")
    try:
        for n in itertools.count(1):
            amb.legit()
            if args.attacks and n % args.every == 0:
                amb.attack(next(attacks))
            if args.count and n >= args.count:
                break
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
    print(f"Sent {amb.seq} legitimate packets.")


if __name__ == "__main__":
    main()
