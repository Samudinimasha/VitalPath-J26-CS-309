# VitalPath - Component 1: Device Trust Verification Engine

IT23298408 · J26-CS-309

Trusted Device Score: `T = 0.30C + 0.25F + 0.20H + 0.15B + 0.10R`
(≥ 0.80 full trust · ≥ 0.60 conditional with monitoring · < 0.60 blocked + alert)

## Status

| Part | Status |
|---|---|
| VitalPath Root CA + device certificates (OpenSSL, ECDSA P-256) | Done |
| Authorised Device List (SQLite) + unknown-device rejection | Done |
| **C** Certificate validity (chain, expiry, CRL, CN binding, pinning, EKU) | Done |
| **F** Fingerprint match (hardware ID + MAC) | Done |
| **H** Device health (battery, sensor errors, firmware, heartbeat) | Done (rule-based) |
| Scoring engine, three tiers, monitoring flags, alerts, decision log | Done |
| **B** Behavioural consistency vs transmission baseline | Provisional input; PP2 |
| **R** Historical reputation from decision log | Provisional input; PP2 |

## Run (WSL2 Ubuntu)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
bash pki/setup_ca.sh                       # build CA, certs, CRL, attacker certs
python3 demo.py                            # full pipeline, 10 scenarios
python3 -m unittest discover -s tests -v   # 33 tests
```

## Layout

```
pki/setup_ca.sh              CA build, 5 device certs, revocation, attacker certs
trust/config.py              Weights, thresholds, tuning values (one place)
trust/registry.py            Authorised Device List (SQLite), pre-scoring gate
trust/cert_factor.py         C - certificate validity
trust/fingerprint_factor.py  F - hardware ID + MAC match
trust/health_factor.py       H - device health status
trust/engine.py              T, identity gates, tiers, alerts, decision log
demo.py                      Full scenario demo (legitimate / degraded / cloned)
demo_day1.py                 Certificate-factor-only demo
tests/                       33 unit tests
```

## Design decision: identity gates

The weighted formula alone lets attackers through. C and F together are
only 55% of T, so a device with a forged, expired or revoked certificate
(C = 0) or cloned hardware (F = 0) but healthy H, B, R still scores
0.675-0.735, which is conditional access. `demo.py` shows this in the
"T alone" column.

So identity failures are gates, not just low scores:

- **Certificate gate:** forged, expired, revoked or wrong-identity certificate → BLOCKED
- **Fingerprint gate:** hardware ID differs from the registered one (clone) → BLOCKED

Softer problems stay inside the weighted score and produce the graduated
behaviour: certificate near expiry (C = 0.75), MAC changed after repair
(F = 0.60), and degraded health, behaviour or reputation. T is still
computed and logged for gated devices for evaluation.

`pki/out/` contains private keys for test devices only. It is git-ignored.
