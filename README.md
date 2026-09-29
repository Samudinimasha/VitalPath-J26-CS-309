# VitalPath-J26-CS-309

**VitalPath: A 5G Security Middleware for Connected Ambulance Telemetry**

When a patient is in an ambulance, their vital signs (heart rate, SpO2, blood pressure,
ECG, respiratory rate) are streamed over 5G to the receiving hospital so staff can prepare
before arrival. 5G encrypts this traffic, but every time a moving ambulance hands over
between cell towers the secure session is torn down and re-established. Research has shown
this handover window is vulnerable to replayed and injected packets, and existing
connected-ambulance products focus on keeping the connection alive, not on verifying
that the data arriving is fresh, authentic and physiologically plausible.

VitalPath is a middleware layer that runs at the ambulance edge and addresses this gap.
It consists of four independent components that consume a shared telemetry stream in
parallel (fan-out), so no component can stall another:

| # | Component | Responsibility |
|---|-----------|----------------|
| 1 | Device Identity & Trust Verification | Authenticates medical devices (certificates, fingerprinting) and computes a Trusted Device Score |
| 2 | Adaptive Secure Transmission | Encrypts and signs telemetry (DTLS 1.3, ECDSA, SHA-256) for transmission |
| 3 | Telemetry Anomaly & Replay Detection Engine | Detects replayed packets and physiologically impossible or inconsistent vital signs in real time |
| 4 | Forensic Ledger & Emergency Access Control | Records verdicts in a tamper-evident Merkle-chain ledger and enforces role- and context-aware access, including break-glass misuse detection |

## Design principles

- **Explainable, no machine learning.** Every accept, flag or discard decision traces to a
  named, documented rule, so it can be justified to clinicians, auditors and regulators.
- **Real-time.** Detection is designed to stay under 20 ms per packet.
- **Clinician stays in control.** Suspicious vital signs are flagged and forwarded for review,
  never silently dropped; only confirmed replays are discarded.
- **Privacy-preserving.** Raw vital-sign values never leave the detection engine; only
  packet IDs, decisions and signed sensitivity labels are passed on for logging.

## Repository layout

| Folder | Component |
|--------|-----------|
| [`component3/`](component3/) | Telemetry Anomaly & Replay Detection Engine |

## Project

Final-year research project J26-CS-309, B.Sc. (Hons) in Information Technology
Specialising in Cyber Security, Sri Lanka Institute of Information Technology (SLIIT).
Supervisor: Prof. Harinda Fernando · Co-supervisor: Mr. Deemantha Siriwardana
