# VitalPath - Component 2: Adaptive Security Decision Engine

**IT23471962 | J26-CS-309**

## System Overview
Operating at the connected ambulance edge gateway, Component 2 dynamically selects the optimal cryptographic protection profile (**Standard**, **Enhanced**, or **Maximum**) for in-flight 5G telemetry packets. It balances data integrity and confidentiality against cellular transmission latency and gateway processing overhead.

### Scoring Model: Security Priority Score (SPS)
Deterministic linear weighted formulation (ML-free, explainable, ultra-low latency):
$$\text{SPS} = w_{\text{dts}} \cdot (1.0 - \text{DTS}) + w_{\text{cc}} \cdot \text{CC} + w_{\text{nc}} \cdot \text{NC}$$

* **$w_{\text{dts}} = 0.35$**: Device Trust Score ($\text{DTS} \in [0.0, 1.0]$) consumed from Component 1 cache. Inverted as $(1.0 - \text{DTS})$ so untrusted devices elevate security priority.
* **$w_{\text{cc}} = 0.45$**: Clinical Criticality ($\text{CC} \in \{0.2, 0.6, 1.0\}$) based on AHA/WHO/ESC guideline boundaries.
* **$w_{\text{nc}} = 0.20$**: 5G Network Conditions ($\text{NC} \in [0.0, 1.0]$) modeling latency (RTT), packet loss, and cellular handover penalties.

---

## Cryptographic Profiles

| Profile | Profile Threshold | Encryption & Integrity | Digital Signature | Session Key Rotation |
| :--- | :--- | :--- | :--- | :--- |
| **Standard** | $\text{SPS} \le 0.40$ | AES-256-GCM (DTLS 1.3) + SHA-256 | None (Conserves gateway CPU) | 300 seconds |
| **Enhanced** | $0.40 < \text{SPS} \le 0.75$ | AES-256-GCM (DTLS 1.3) + SHA-256 | ECDSA (NIST P-256 / SHA-256) | 60 seconds |
| **Maximum** | $\text{SPS} > 0.75$ | AES-256-GCM + strict header binding | ECDSA P-256 with key binding | 10 seconds (or handover triggered) |

---

## Architecture & Code Layout

```
component2/
├── config.json                 # SPS weights, clinical ranges, and rotation thresholds
├── classifiers.py              # Clinical Criticality (CC), Network Conditions (NC), Device Trust (DTS)
├── sps_engine.py               # Deterministic SPS calculation & profile mapping
├── crypto_engine.py            # AES-256-GCM AEAD, ECDSA P-256 signing, and adaptive KeyManager
├── pipeline.py                 # End-to-end pipeline & asynchronous metadata logging (FR8)
├── dataset_loader.py           # Ingestion for MIMIC-III datasets (data.xlsx, data 2.xlsx, data 3.xlsx)
├── benchmark_evaluation.py     # 4,759-packet comparative benchmark against static baselines
├── benchmark_results.json      # Structured benchmark metrics and percentiles
├── requirements.txt            # Python dependencies
├── tests/                      # Automated test suite (16 tests)
│   ├── test_sps_engine.py
│   ├── test_crypto_engine.py
│   └── test_pipeline.py
└── README.md
```

---

## Verification & Benchmarks

* **NFR1 Decision Latency**: **$0.0048\text{ ms}$** average (Target: $< 5.0\text{ ms}$).
* **NFR1 Total Packet Delay**: **$0.0473\text{ ms}$** average, 99th percentile $0.0821\text{ ms}$ (Target: $< 20.0\text{ ms}$).
* **NFR4 Resource Reduction**: Over **43.9%** of routine telemetry packets safely bypass expensive ECDSA signatures under the Standard profile, saving up to ~71.4% processing delay.
* **Test Suite**: 16/16 unit tests passing.

---

## How to Run

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run unit tests
pytest -v

# 3. Run experimental benchmark on real clinical telemetry (4,759 packets)
python benchmark_evaluation.py

# 4. Run end-to-end telemetry pipeline demo
python pipeline.py
```

