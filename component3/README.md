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

No machine learning: every verdict cites a named rule in `src/vitalpath_c3/rules.py`.

## Layout

| Path | Purpose |
|---|---|
| `src/vitalpath_c3/config.py` | All tunable parameters |
| `src/vitalpath_c3/models.py` | Packet / header data shapes |
| `src/vitalpath_c3/rules.py` | Named rule IDs and descriptions |
| `src/vitalpath_c3/engines/` | `replay.py` (T9), threshold (T10), correlation (T11), hybrid (T12) |
| `src/vitalpath_c3/crypto/` | Payload decryption, sensitivity-label signing |
| `src/vitalpath_c3/output/` | Decision records for Component 4 |
| `src/vitalpath_c3/data/` | Clinical thresholds (D2), correlation rules (D3), PhysioNet loader |
| `simulator/` | Synthetic stream and attack generation (replay, handover, injection, flooding) |
| `tests/unit/` | Per-engine unit tests |
| `tests/integration/` | Scenario S1–S12 tests on the full pipeline |
| `benchmarks/` | Latency measurement against the 20 ms budget |

## Replay Detection Engine (T9)

DTLS/IPsec-style anti-replay bitmap window per device ID (persists across 5G handover).

| Parameter | Default |
|---|---|
| `window_size` | 1024 sequence numbers |
| `max_age_s` | 30 s |
| `future_skew_s` | 2 s |
| `backward_tolerance_s` | 1 s |
| `max_seq_jump` | 1024 |

Sequence numbers are unsigned 64-bit; wraparound is not handled.

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

Add `--auto` to run every scenario in turn (press Enter between them).

## Live demo

Two terminals, from `component3/`. The receiver runs the full pipeline; the sender streams a real
PhysioNet recording (encrypted) and, with `--attacks`, injects replays, a handover, sensor faults,
forged and tampered packets, and a flood.

```bash
PYTHONPATH=src python3 -m simulator.receiver --explain
```

```bash
PYTHONPATH=src python3 -m simulator.sender --attacks --start 60
```

`--start 60` skips the first minute of bidmc53n, where the patient's respiratory rate is high and
most genuine packets are flagged. Stop each with Ctrl+C; the receiver prints a summary.
