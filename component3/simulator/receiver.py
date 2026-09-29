"""Live receiver: runs every incoming UDP packet through the Replay Detection Engine.

Usage (from component3/):
    PYTHONPATH=src python3 -m simulator.receiver [--port 5005]

Press Ctrl+C to stop and print a summary.
"""

import argparse
import logging
import socket
import time
from collections import Counter

from simulator.wire import DEFAULT_HOST, DEFAULT_PORT, decode
from vitalpath_c3.engines.replay import ReplayDetectionEngine, ReplayOutcome

COLOURS = {
    ReplayOutcome.ACCEPT: "\033[32m",  # green
    ReplayOutcome.ACCEPT_FLAGGED: "\033[33m",  # yellow
    ReplayOutcome.DISCARD: "\033[31m",  # red
}
RESET = "\033[0m"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    # Verdict lines below already show discards; keep the engine's log quiet.
    logging.getLogger("vitalpath_c3").setLevel(logging.ERROR)

    engine = ReplayDetectionEngine()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((args.host, args.port))
    except OSError as exc:
        sock.close()
        raise SystemExit(
            f"Cannot listen on udp://{args.host}:{args.port}: {exc.strerror}.\n"
            "Another receiver is probably still running. Stop it with Ctrl+C, "
            "or use a different port with --port (and pass the same --port to the sender)."
        )
    print(f"Replay gate listening on udp://{args.host}:{args.port}  (Ctrl+C to stop)\n")
    print(f"{'device':<10} {'seq':>7}  {'verdict':<15} {'rule':<24} {'latency':>9}  detail")

    counts: Counter = Counter()
    rules: Counter = Counter()
    latencies = []
    try:
        while True:
            datagram, _ = sock.recvfrom(65535)
            packet = decode(datagram)
            start = time.perf_counter()
            verdict = engine.check(packet.header)
            elapsed_ms = (time.perf_counter() - start) * 1000
            latencies.append(elapsed_ms)
            counts[verdict.outcome] += 1
            rules[verdict.rule.value] += 1
            colour = COLOURS[verdict.outcome]
            print(
                f"{str(verdict.device_id):<10} {str(verdict.seq):>7}  "
                f"{colour}{verdict.outcome.value:<15}{RESET} {verdict.rule.value:<24} "
                f"{elapsed_ms:>7.3f}ms  {verdict.detail}"
            )
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

    total = sum(counts.values())
    print(f"\n--- Summary: {total} packets ---")
    for outcome in ReplayOutcome:
        print(f"  {outcome.value:<15} {counts[outcome]}")
    print("  By rule:")
    for rule, n in rules.most_common():
        print(f"    {rule:<24} {n}")
    if latencies:
        latencies.sort()
        p99 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.99))]
        print(
            f"  Replay-gate latency: mean {sum(latencies) / len(latencies):.3f} ms, "
            f"p99 {p99:.3f} ms, max {latencies[-1]:.3f} ms (budget 20 ms end to end)"
        )


if __name__ == "__main__":
    main()
