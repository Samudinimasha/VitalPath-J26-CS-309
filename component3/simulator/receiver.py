"""Live receiver: runs every incoming UDP packet through the full Component 3 pipeline.

Usage (from component3/):
    PYTHONPATH=src python3 -m simulator.receiver [--port 5005] [--explain] [--records decisions.jsonl]

Each packet goes through rate limiting, replay detection, decryption,
threshold and correlation checks and the hybrid decision. One line is printed
per packet; --explain also prints the scoring lines behind every FLAG.
Press Ctrl+C to stop and print a summary.
"""

import argparse
import logging
import socket
from collections import Counter

from simulator.demo_keys import demo_key
from simulator.wire import DEFAULT_HOST, DEFAULT_PORT, decode
from vitalpath_c3.crypto.payload import PayloadDecryptor
from vitalpath_c3.output.decision_record import JsonlSink, MemorySink, RecordSigner
from vitalpath_c3.pipeline import Pipeline

COLOURS = {"ACCEPT": "\033[32m", "FLAG": "\033[33m", "DISCARD": "\033[31m"}
RESET = "\033[0m"
DIM = "\033[2m"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--explain", action="store_true", help="print the scoring behind each FLAG")
    parser.add_argument("--records", help="also append signed decision records to this JSONL file")
    args = parser.parse_args()

    # The verdict lines below already show every discard; keep engine logs quiet.
    logging.getLogger("vitalpath_c3").setLevel(logging.ERROR)

    pipeline = Pipeline(
        PayloadDecryptor(demo_key),
        RecordSigner.generate(),
        sink=JsonlSink(args.records) if args.records else MemorySink(),
    )
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
    print(f"Component 3 pipeline listening on udp://{args.host}:{args.port}  (Ctrl+C to stop)\n")
    print(f"{'device':<8} {'seq':>6}  {'decision':<8} {'label':<10} {'score':>5}  {'latency':>8}  rules / reason")

    decisions: Counter = Counter()
    rules: Counter = Counter()
    latencies = []
    discarded_before_decrypt = 0
    try:
        while True:
            datagram, _ = sock.recvfrom(65535)
            result = pipeline.process(decode(datagram))
            rec = result.record
            latencies.append(result.latency_ms)
            decisions[(rec.decision, rec.label)] += 1
            rules.update(rec.rules)
            if rec.decision == "DISCARD" and not result.decrypted:
                discarded_before_decrypt += 1
            reason = ", ".join(rec.rules) if rec.rules else "-"
            if rec.decision == "DISCARD":
                reason += f"  {DIM}{result.detail}{RESET}"
            print(
                f"{str(rec.device_id):<8} {str(rec.seq):>6}  "
                f"{COLOURS[rec.decision]}{rec.decision:<8} {rec.label or '':<10}{RESET} "
                f"{'' if rec.score is None else rec.score:>5}  {result.latency_ms:>6.2f}ms  {reason}"
            )
            if args.explain and rec.decision == "FLAG":
                for line in result.explain().splitlines()[1:]:
                    print(f"{DIM}{'':>44}{line.strip()}{RESET}")
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

    total = sum(decisions.values())
    print(f"\n--- Summary: {total} packets ---")
    for (decision, label), n in sorted(decisions.items(), key=lambda kv: -kv[1]):
        print(f"  {decision:<8} {label or '':<10} {n}")
    print("  Rules fired:")
    for rule, n in rules.most_common():
        print(f"    {rule:<24} {n}")
    discards = sum(n for (d, _), n in decisions.items() if d == "DISCARD")
    if discards:
        print(f"  Discarded without ever decrypting the payload: {discarded_before_decrypt} of {discards}")
    if latencies:
        latencies.sort()
        p99 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.99))]
        print(
            f"  End-to-end latency: mean {sum(latencies) / len(latencies):.2f} ms, "
            f"p99 {p99:.2f} ms, max {latencies[-1]:.2f} ms (budget 20 ms)"
        )


if __name__ == "__main__":
    main()
