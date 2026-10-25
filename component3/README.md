# Component 3 - Lightweight Telemetry Anomaly and Replay Detection Engine

Part of **VitalPath: A 5G Security Middleware for Connected Ambulance Telemetry** (J26-CS-309).
Owner: B.S.N. Fernando (IT23382244).

## Pipeline

```
header ──► Replay Detection (T9) ──DISCARD──► replay alert (payload never decrypted)
                 │ pass
                 ▼
           Decrypt payload (key shared internally with C2)
                 ▼
     Threshold (T10) ∥ Multi-Vital Correlation (T11)
                 ▼
           Hybrid Decision (T12) ──► ACCEPT 'Normal' | FLAG 'Borderline' / 'Flagged'
```

No machine learning: every verdict cites a named rule in `src/vitalpath_c3/rule_ids.py`.

## Layout

| Path | Purpose |
|---|---|
| `src/vitalpath_c3/detection_pipeline.py` | Runs every stage in order for each packet |
| `src/vitalpath_c3/engines/flood_rate_limiter.py` | Flood guard: at most 20 packets per second per device (S8) |
| `src/vitalpath_c3/engines/replay.py` | Replay Detection Engine (T9) |
| `src/vitalpath_c3/crypto/payload_encryption.py` | AES-256-GCM decryption (stand-in for Component 2) |
| `src/vitalpath_c3/engines/threshold.py` | Threshold-Based Anomaly Detection Engine (T10) |
| `src/vitalpath_c3/engines/correlation.py` | Multi-Vital Correlation Engine (T11) |
| `src/vitalpath_c3/engines/hybrid.py` | Hybrid Decision Engine (T12) |
| `src/vitalpath_c3/replay_configurations.py` | Replay Engine settings |
| `src/vitalpath_c3/packet_models.py` | Packet header, vitals and encrypted packet shapes |
| `src/vitalpath_c3/rule_ids.py` | Named rule IDs and their meanings |
| `src/vitalpath_c3/data/` | `thresholds.json`, `correlation_rules.json`, `scoring.json`, `physionet_loader.py` |
| `simulator/attack_demo.py` | Menu-driven attack demonstration |
| `simulator/ambulance_sender.py`, `simulator/hospital_receiver.py` | Two-window live demo |
| `simulator/network_format.py`, `simulator/demo_keys.py` | Demo packet format and demo-only keys |
| `simulator/physionet_xlsx_to_csv.py` | Converts PhysioNet Excel exports to CSV |
| `tests/unit/`, `tests/integration/` | Per-engine tests; scenarios S1–S12 through the full pipeline |

## Replay Detection Engine (T9)

DTLS/IPsec-style anti-replay bitmap window per device ID (persists across 5G handover).

| Parameter | Default |
|---|---|
| `window_size` | 1024 packet IDs |
| `max_age_s` | 30 s |
| `future_skew_s` | 2 s |
| `backward_tolerance_s` | 1 s |
| `max_packet_jump` | 1024 |

Packets are identified by Component 2's `packet_id` (e.g. `PKT-000042`); the Replay Engine uses the counter inside it, per device. Counters are unsigned 64-bit; wraparound is not handled.

## Running tests

```bash
cd component3
python3 -m pytest
```

`tests/integration/test_scenarios.py` runs detection scenarios S1-S12 (proposal Table 6) through the full pipeline.

## Attack demonstration

One window, menu-driven: choose an attack or sensor fault and watch each engine handle it, step by step.

```bash
PYTHONPATH=src python3 -m simulator.attack_demo
```

Add `--auto` to run every scenario in turn, or `--quick` for the five-scenario presentation set (press Enter between them).

## Try one engine on its own

Type the vitals and see what a single engine does with them:

```bash
PYTHONPATH=src python3 -m simulator.try_engines threshold   --hr 150 --spo2 88
PYTHONPATH=src python3 -m simulator.try_engines correlation --hr 64 --pulse 72 --spo2 13.9
PYTHONPATH=src python3 -m simulator.try_engines decision    --hr 64 --pulse 72 --spo2 13.9
PYTHONPATH=src python3 -m simulator.try_engines decryption  --hr 92 --spo2 98
PYTHONPATH=src python3 -m simulator.try_engines keys        --hr 92 --spo2 98
```

## Live demo

Two terminals, from `component3/`. The receiver runs the full pipeline; the sender streams a real
PhysioNet recording (encrypted) and, with `--attacks`, injects replays, a handover, sensor faults,
forged and tampered packets, and a flood.

```bash
PYTHONPATH=src python3 -m simulator.hospital_receiver --explain --vitals
```

```bash
PYTHONPATH=src python3 -m simulator.ambulance_sender --attacks --start 60
```

`--start 60` skips the first minute of bidmc53n, where the patient's respiratory rate is high and
most genuine packets are flagged. Stop each with Ctrl+C; the receiver prints a summary.
