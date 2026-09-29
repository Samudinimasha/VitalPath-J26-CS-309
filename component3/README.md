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
