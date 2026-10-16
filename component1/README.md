# VitalPath - Component 1: Device Trust Verification Engine

IT23298408 · J26-CS-309

Trusted Device Score: `T = 0.30C + 0.25F + 0.20H + 0.15B + 0.10R`
(≥ 0.80 full trust · ≥ 0.60 conditional · < 0.60 blocked)

## Status

| Part | Status |
|---|---|
| VitalPath Root CA + device certificates (OpenSSL, ECDSA P-256) | Done |
| Authorised Device List (SQLite) + unknown-device rejection | Done |
| Certificate factor **C** (chain, expiry, CRL, CN binding, pinning, EKU) | Done |
| Fingerprint factor **F** (MAC + hardware ID) | Next |
| Scoring engine + three tiers | Next |
| H, B, R factors (placeholders for PP1) | PP2 |

## Run (WSL2 Ubuntu)

```bash
pip install cryptography          # add --break-system-packages if pip refuses
bash pki/setup_ca.sh              # build CA, issue certs, publish CRL
python3 demo_day1.py              # run the 8 connection scenarios
python3 -m unittest discover -s tests -v
```

## Layout

```
pki/setup_ca.sh       CA build + 5 device certs + revocation + attacker certs
trust/registry.py     Authorised Device List (SQLite), pre-scoring gate
trust/cert_factor.py  Certificate Validity factor C
demo_day1.py          Scenario demo for PP1
tests/test_day1.py    10 unit tests
```

## Design decision: certificate hard-fail gate

C is only 30% of T, so a device with a forged or revoked certificate
(C = 0) but perfect other factors would score T = 0.70, which is
conditional access. That is unacceptable, so a forged, expired, revoked
or mis-bound certificate sets `hard_fail` and the device is blocked
regardless of T. Soft issues (renewal window, pin mismatch, missing EKU)
lower C but stay inside the weighted score.

`pki/out/` contains private keys for test devices only. Do not commit it.
