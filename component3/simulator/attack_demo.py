"""Interactive attack demonstration for Component 3.

Usage (from component3/):
    PYTHONPATH=src python3 -m simulator.attack_demo          # pick attacks from a menu
    PYTHONPATH=src python3 -m simulator.attack_demo --auto   # run every scenario in turn

An ambulance streams real PhysioNet vitals (bidmc53n), encrypted. You choose
an attack or a sensor fault, and every packet involved is walked through the
pipeline stage by stage, in plain language, ending with the decision.

The demo uses its own simulated clock, so a 3-second handover or a one-second
flood happens instantly.
"""

import argparse
import dataclasses
import json
import re
import time

from simulator.demo_keys import demo_key
from simulator.ambulance_sender import endless_vitals
from simulator.network_format import packet_id
from vitalpath_c3.crypto.payload_encryption import PayloadDecryptor, seal
from vitalpath_c3.engines.correlation import Kind
from vitalpath_c3.engines.flood_rate_limiter import RateLimiter
from vitalpath_c3.engines.replay import ReplayDetectionEngine, ReplayOutcome
from vitalpath_c3.engines.threshold import Band
from vitalpath_c3.packet_models import EncryptedPacket, PacketHeader, VitalSigns
from vitalpath_c3.detection_pipeline import Pipeline

DEVICE = "MON-01"  # the ambulance's patient monitor
CASE = "CASE001"  # emergency case from (simulated) dispatch
UNIT = "AMB-07"
GREEN, YELLOW, RED, BOLD, DIM, RESET = "\033[32m", "\033[33m", "\033[31m", "\033[1m", "\033[2m", "\033[0m"

WHY_DISCARDED = {
    "R-RATE-LIMIT": "too many packets per second from this device (flood)",
    "R-REPLAY-DUPLICATE": "this packet ID was already received, so this is a copy (replay)",
    "R-REPLAY-OUTSIDE-WINDOW": "packet ID is far older than anything still accepted",
    "R-TS-STALE": "timestamp is too old (more than 30 s)",
    "R-TS-FUTURE": "timestamp is in the future (more than 2 s ahead)",
    "R-TS-REGRESSION": "timestamp goes backwards compared with newer packets",
    "R-MALFORMED-HEADER": "header is damaged or unreadable",
    "R-DECRYPT-FAILED": "the seal is broken: the packet was altered or forged",
    "R-PAYLOAD-MALFORMED": "decrypted data is not a valid vital-sign record",
}

BAND_COLOUR = {Band.NORMAL: GREEN, Band.BORDERLINE: YELLOW, Band.CRITICAL: RED, Band.INVALID: RED}
UNITS = {"hr": "bpm", "pulse": "bpm", "spo2": "%", "sbp": "mmHg", "dbp": "mmHg", "resp": "/min"}


class DemoClock:
    def __init__(self) -> None:
        self.now = time.time()

    def __call__(self) -> float:
        return self.now


def show_vitals(v: VitalSigns) -> str:
    parts = []
    if v.hr is not None:
        parts.append(f"HR {v.hr:g}")
    if v.pulse is not None:
        parts.append(f"pulse {v.pulse:g}")
    if v.spo2 is not None:
        parts.append(f"SpO2 {v.spo2:g}%")
    if v.sbp is not None and v.dbp is not None:
        parts.append(f"BP {v.sbp:g}/{v.dbp:g}")
    if v.resp is not None:
        parts.append(f"RESP {v.resp:g}")
    return " · ".join(parts)


def describe(result) -> list:
    """Plain-language walk through each stage of one packet's processing."""
    lines = []
    step = lambda n, name, text: lines.append(f"  {n} {name:<20} {text}")
    rec = result.summary

    if not result.rate_limit.allowed:
        step("1", "Flood check", f"{RED}✗ BLOCKED{RESET}  {WHY_DISCARDED['R-RATE-LIMIT']}")
    else:
        step("1", "Flood check", f"{GREEN}✓ ok{RESET}")

    r = result.replay
    if r is not None:
        if r.outcome is ReplayOutcome.ACCEPT:
            step("2", "Replay Engine", f"{GREEN}✓ fresh{RESET}  new packet ID, timestamp OK")
        elif r.outcome is ReplayOutcome.ACCEPT_FLAGGED:
            step("2", "Replay Engine", f"{YELLOW}⚠ suspicious jump{RESET}  {r.detail}; passed on to check if genuine")
        else:
            step("2", "Replay Engine", f"{RED}✗ REJECTED{RESET}  {WHY_DISCARDED.get(r.rule.value, r.detail)}  [{r.rule.value}]")

    if rec.decision == "DISCARD" and not result.decrypted:
        lines.append(f"  {DIM}  Payload never decrypted: stopped before anyone looked inside.{RESET}")
    elif result.vitals is None and result.decrypted:
        rule = rec.rules[0]
        step("3", "Decrypt", f"{RED}✗ FAILED{RESET}  {WHY_DISCARDED.get(rule, result.detail)}  [{rule}]")
    elif result.vitals is not None:
        step("3", "Decrypt", f"{GREEN}✓ authentic{RESET}  {show_vitals(result.vitals)}")

    if result.threshold is not None:
        scored = [f for f in result.threshold.findings if f.band is not Band.MISSING]
        if all(f.band is Band.NORMAL for f in scored):
            step("4", "Threshold Engine", f"{GREEN}✓ every vital in its normal range{RESET}")
        else:
            first = True
            for f in scored:
                if f.band is Band.NORMAL:
                    continue
                value = "unreadable" if f.value is None else f"{f.value:g} {UNITS.get(f.vital, '')}"
                text = f"{BAND_COLOUR[f.band]}{f.vital.upper()} {value} → {f.band.value.upper()}{RESET}  [{f.rule}]"
                step("4" if first else " ", "Threshold Engine" if first else "", text)
                first = False

    if result.correlation is not None:
        if not result.correlation.findings:
            step("5", "Correlation Engine", f"{GREEN}✓ vitals agree with each other{RESET}")
        for i, f in enumerate(result.correlation.findings):
            colour = RED if f.kind is Kind.INCONSISTENT else YELLOW
            step("5" if i == 0 else " ", "Correlation Engine" if i == 0 else "",
                 f"{colour}{f.kind.value.upper()}{RESET}  {f.detail}  [{f.rule}]")

    if rec.decision == "DISCARD":
        verdict = f"{RED}{BOLD}DISCARD{RESET}  packet dropped, alert logged"
    elif rec.decision == "ACCEPT":
        verdict = f"{GREEN}{BOLD}ACCEPT 'Normal'{RESET}  delivered to the hospital"
    else:
        colour = RED if rec.label == "Flagged" else YELLOW
        verdict = (f"{colour}{BOLD}FLAG '{rec.label}'{RESET} (score {rec.score})  "
                   f"delivered with a warning for the clinician to review")
    step("→", "Decision", verdict)
    lines.append(f"  {DIM}  {result.latency_ms:.2f} ms{RESET}")
    return lines


class Demo:
    def __init__(self, data_path: str = "datasets/bidmc_53n.csv", start: int = 60, out=print) -> None:
        self.out = out
        self.clock = DemoClock()
        self.pipeline = Pipeline(
            PayloadDecryptor(demo_key),
            rate_limiter=RateLimiter(clock=self.clock),
            replay=ReplayDetectionEngine(clock=self.clock),
            clock=self.clock,
        )
        self.vitals = endless_vitals(data_path, start)
        self.key = demo_key(DEVICE)
        self.count = 0  # genuine packets so far; packet IDs are built from it
        self.sent = []  # every genuine packet, as an eavesdropper would capture it

    # --- sending ------------------------------------------------------------

    def genuine(self, vitals: VitalSigns = None, gap: float = 1.0) -> EncryptedPacket:
        self.clock.now += gap
        self.count += 1
        packet = seal(PacketHeader(DEVICE, packet_id(self.count), self.clock.now, CASE), vitals or next(self.vitals), self.key)
        self.sent.append(packet)
        return packet

    def process(self, packet: EncryptedPacket, caption: str):
        result = self.pipeline.process(packet)
        h = packet.header
        self.out(f"\n{BOLD}{caption}{RESET}  {DIM}(case {h.case_id}, device {h.device_id}, {h.packet_id}){RESET}")
        for line in describe(result):
            self.out(line)
        return result

    def warm_up(self, n: int = 3):
        for _ in range(n):
            self.pipeline.process(self.genuine())

    # --- scenarios ----------------------------------------------------------

    def normal(self):
        self.process(self.genuine(), "Ambulance sends its next packet")

    def replay(self):
        self.warm_up()
        captured = self.sent[-2]
        self.out(f"{DIM}The attacker recorded packet {captured.header.packet_id} earlier and now sends an exact copy.{RESET}")
        self.process(captured, "ATTACKER resends a captured packet")

    def handover(self):
        self.warm_up(5)
        captured = self.sent[-3]
        self.out(f"\n{YELLOW}~~~ 5G handover: the link drops for 3 seconds while the ambulance changes cell tower ~~~{RESET}")
        self.clock.now += 3
        forged = EncryptedPacket(dataclasses.replace(captured.header, timestamp=self.clock.now), captured.payload)
        self.out(f"{DIM}During reconnection the attacker resends packet {captured.header.packet_id}, "
                 f"with its timestamp changed to look fresh.{RESET}")
        self.process(forged, "ATTACKER replays an old packet during the handover")
        self.process(self.genuine(gap=0.2), "Ambulance reconnects and sends its real next packet")

    def tamper(self):
        self.warm_up()
        packet = self.genuine()
        payload = bytearray(packet.payload)
        payload[20] ^= 0xFF
        self.out(f"{DIM}The attacker intercepts the next packet and changes some bytes of the encrypted data "
                 f"(e.g. trying to alter a reading).{RESET}")
        self.process(EncryptedPacket(packet.header, bytes(payload)), "ATTACKER sends an altered packet")
        self.process(packet, "The original, untouched packet arrives")

    def case_swap(self):
        self.warm_up()
        packet = self.genuine()
        swapped = EncryptedPacket(dataclasses.replace(packet.header, case_id="CASE002"), packet.payload)
        self.out(f"{DIM}The attacker intercepts a packet for {CASE} and changes its case number to CASE002, "
                 f"so this patient's readings would be filed under another patient's case.{RESET}")
        self.process(swapped, "ATTACKER relabels a packet with another case number")
        self.process(packet, "The original packet, still labelled " + CASE)

    def jump(self):
        self.warm_up()
        header = PacketHeader(DEVICE, packet_id(self.count + 50_000), self.clock.now, CASE)
        self.out(f"{DIM}The attacker invents a packet ID far ahead of the real ones, hoping to push the window "
                 f"forward and lock the ambulance out. Without the key, it cannot make a valid seal.{RESET}")
        self.process(EncryptedPacket(header, bytes(60)), "ATTACKER injects a fake far-ahead packet")
        self.process(self.genuine(), "Ambulance's next real packet")

    def heart_rate_300(self):
        v = dataclasses.replace(next(self.vitals), hr=300.0, pulse=300.0)
        self.out(f"{DIM}A faulty or compromised sensor reports a heart rate of 300 bpm (physiologically impossible).{RESET}")
        self.process(self.genuine(v), "Ambulance sends a packet with HR 300")

    def sensor_fault(self):
        self.out(f"{DIM}Real case from MIMIC-III record 3000003n: the finger clip slips. SpO2 reads 13.9% "
                 f"while the heart beats calmly at 64.{RESET}")
        self.process(self.genuine(VitalSigns(hr=64.0, pulse=72.3, spo2=13.9, resp=18.0)),
                     "Ambulance sends a packet with a slipped oximeter probe")

    def shock(self):
        self.out(f"{DIM}HR 105 and BP 100/62 each look only mildly abnormal, but together "
                 f"(shock index 105/100 = 1.05) they suggest the patient may be going into shock.{RESET}")
        self.process(self.genuine(VitalSigns(hr=105.0, pulse=104.0, spo2=96.0, sbp=100.0, dbp=62.0, resp=18.0)),
                     "Ambulance sends a packet with a hidden shock pattern")

    def flood(self):
        self.out(f"{DIM}The attacker fires 50 packets within one second.{RESET}")
        results = []
        for _ in range(50):
            results.append(self.pipeline.process(self.genuine(gap=0.02)))
        blocked = sum(r.summary.rules == ("R-RATE-LIMIT",) for r in results)
        self.out(f"\n{BOLD}FLOOD: 50 packets in 1 second{RESET}")
        self.out(f"  1 Flood check         {GREEN}{50 - blocked} let through{RESET}, "
                 f"{RED}{blocked} BLOCKED{RESET}  (limit: 20 per second per device)")
        self.out(f"  {DIM}  Blocked packets were dropped before any other work was done.{RESET}")
        self.clock.now += 1

    def stream(self):
        self.out(f"\n{BOLD}Ten normal packets{RESET}")
        for _ in range(10):
            result = self.pipeline.process(self.genuine())
            rec = result.summary
            colour = GREEN if rec.decision == "ACCEPT" else YELLOW
            self.out(f"  {rec.packet_id:<11} {show_vitals(result.vitals):<44} "
                     f"{colour}{rec.decision} '{rec.label}'{RESET}")


SCENARIOS = [
    ("1", "Normal packet", "normal"),
    ("2", "Replay attack: resend a captured packet", "replay"),
    ("3", "5G handover + replay attack", "handover"),
    ("4", "Tamper attack: alter the encrypted data", "tamper"),
    ("5", "Fake packet ID jump (injection)", "jump"),
    ("c", "Case swap: relabel a packet with another patient's case", "case_swap"),
    ("6", "Anomaly: impossible heart rate (300 bpm)", "heart_rate_300"),
    ("7", "Correlation: sensor fault (SpO2 13.9% with calm HR)", "sensor_fault"),
    ("8", "Correlation: hidden shock pattern", "shock"),
    ("9", "Flood: 50 packets in one second", "flood"),
    ("0", "Stream ten normal packets", "stream"),
]


def strip_colour(text: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", text)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data", default="datasets/bidmc_53n.csv")
    parser.add_argument("--start", type=int, default=60, help="row of the recording to start from")
    parser.add_argument("--auto", action="store_true", help="run every scenario in turn")
    args = parser.parse_args()

    demo = Demo(args.data, args.start)
    print(f"{BOLD}VitalPath Component 3: attack demonstration{RESET}")
    print(f"{DIM}Dispatch (simulated): {CASE} · {UNIT} assigned.{RESET}")
    print(f"{DIM}{UNIT}'s patient monitor {DEVICE} streams real vitals from {args.data}, "
          f"encrypted and tagged {CASE}.{RESET}")

    if args.auto:
        for _, title, name in SCENARIOS:
            print(f"\n{BOLD}{'=' * 20} {title} {'=' * 20}{RESET}")
            getattr(demo, name)()
            input(f"\n{DIM}Press Enter for the next scenario...{RESET}")
        return

    menu = "\n".join(f"  {key}  {title}" for key, title, _ in SCENARIOS)
    actions = {key: name for key, _, name in SCENARIOS}
    while True:
        print(f"\n{BOLD}Choose what happens next:{RESET}\n{menu}\n  q  Quit")
        try:
            choice = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break
        if choice == "q":
            break
        if choice in actions:
            getattr(demo, actions[choice])()
        else:
            print("Please type one of the numbers above, or q.")


if __name__ == "__main__":
    main()
