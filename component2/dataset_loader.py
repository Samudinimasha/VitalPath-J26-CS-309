"""
VitalPath: 5G Security Middleware for Connected Ambulance Telemetry
Component 2: Clinical Telemetry Ingestion (dataset_loader.py)

This module ingests real clinical datasets from PhysioNet MIMIC-III (shared with Component 3):
  1. '../data.xlsx'   (2,519 records: HR, ABPSys, ABPDias, RESP, SpO2, NBPSys, NBPDias)
  2. '../data 2.xlsx' (1,759 records: HR, NBP SYS, NBP DIAS, RESP, %SpO2, AWRR)
  3. '../data 3.xlsx' (481 records: HR, PULSE, RESP, SpO2)

Aligns and normalizes features into canonical VitalPath telemetry packets:
  - 'hr'     : Heart Rate (bpm)
  - 'spo2'   : Peripheral Capillary Oxygen Saturation (%)
  - 'bp_sys' : Systolic Blood Pressure (mmHg)
  - 'bp_dia' : Diastolic Blood Pressure (mmHg)
  - 'rr'     : Respiratory Rate (breaths/min)
"""

import os
import random
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional


def load_mimic_clinical_data(parent_dir: str = "..") -> pd.DataFrame:
    """
    Loads, cleans, and merges the 3 MIMIC-III Excel files from the parent research folder.
    Returns a unified Pandas DataFrame with canonical clinical columns.
    """
    file1 = os.path.join(parent_dir, "data.xlsx")
    file2 = os.path.join(parent_dir, "data 2.xlsx")
    file3 = os.path.join(parent_dir, "data 3.xlsx")

    frames = []

    # 1. Ingest data.xlsx
    if os.path.exists(file1):
        df1 = pd.read_excel(file1)
        # Combine arterial line (ABP) with cuff (NBP), forward-fill time gaps
        bp_sys1 = df1["ABPSys"].replace(0, np.nan).combine_first(df1["NBPSys"]).ffill().bfill().fillna(120.0)
        bp_dia1 = df1["ABPDias"].replace(0, np.nan).combine_first(df1["NBPDias"]).ffill().bfill().fillna(80.0)
        hr1 = df1["HR"].replace(0, np.nan).combine_first(df1["PULSE"]).ffill().bfill().fillna(75.0)
        spo21 = df1["SpO2"].replace(0, np.nan).ffill().bfill().fillna(98.0)
        resp1 = df1["RESP"].replace(0, np.nan).ffill().bfill().fillna(16.0)

        frames.append(pd.DataFrame({
            "hr": hr1,
            "spo2": spo21,
            "bp_sys": bp_sys1,
            "bp_dia": bp_dia1,
            "rr": resp1,
            "source_dataset": "data.xlsx",
        }))
    else:
        print(f"[!] Warning: {file1} not found.")

    # 2. Ingest data 2.xlsx
    if os.path.exists(file2):
        df2 = pd.read_excel(file2)
        bp_sys2 = df2["NBP SYS"].ffill().bfill().fillna(120.0)
        bp_dia2 = df2["NBP DIAS"].ffill().bfill().fillna(80.0)
        hr2 = df2["HR"].combine_first(df2["PULSE"]).ffill().bfill().fillna(75.0)
        spo22 = df2["%SpO2"].ffill().bfill().fillna(98.0)
        resp2 = df2["RESP"].combine_first(df2["AWRR"]).ffill().bfill().fillna(16.0)

        frames.append(pd.DataFrame({
            "hr": hr2,
            "spo2": spo22,
            "bp_sys": bp_sys2,
            "bp_dia": bp_dia2,
            "rr": resp2,
            "source_dataset": "data 2.xlsx",
        }))
    else:
        print(f"[!] Warning: {file2} not found.")

    # 3. Ingest data 3.xlsx
    if os.path.exists(file3):
        df3 = pd.read_excel(file3)
        # Strip extraneous whitespace and trailing commas from header names
        df3.columns = [c.strip().rstrip(",") for c in df3.columns]
        hr3 = df3["HR"].combine_first(df3["PULSE"]).ffill().bfill().fillna(75.0)
        spo23 = df3["SpO2"].ffill().bfill().fillna(98.0)
        resp3 = df3["RESP"].ffill().bfill().fillna(16.0)

        frames.append(pd.DataFrame({
            "hr": hr3,
            "spo2": spo23,
            "bp_sys": 120.0,
            "bp_dia": 80.0,
            "rr": resp3,
            "source_dataset": "data 3.xlsx",
        }))
    else:
        print(f"[!] Warning: {file3} not found.")

    if not frames:
        raise FileNotFoundError(f"None of the 3 Excel datasets found in directory: {parent_dir}")

    combined_df = pd.concat(frames, ignore_index=True)
    return combined_df


def build_telemetry_stream(
    clinical_df: Optional[pd.DataFrame] = None,
    parent_dir: str = "..",
    seed: int = 42,
) -> List[Dict[str, Any]]:
    """
    Transforms the clinical dataset into VitalPath telemetry packets coupled with
    simulated vehicular 5G network channels and Component 1 Device Trust Scores.
    """
    random.seed(seed)
    np.random.seed(seed)

    if clinical_df is None:
        clinical_df = load_mimic_clinical_data(parent_dir=parent_dir)

    # Simulated connected-ambulance sensor profiles
    device_catalog = [
        {"id": "sensor_ecg_lead_II", "trust": 0.95},
        {"id": "sensor_pulse_ox", "trust": 0.88},
        {"id": "sensor_bp_monitor", "trust": 0.75},
        {"id": "sensor_aux_temp", "trust": 0.65},
        {"id": "sensor_unverified_patch", "trust": 0.35},
    ]

    telemetry_stream = []

    for i, row in clinical_df.iterrows():
        # Assign sensor device
        dev = random.choice(device_catalog)

        # Clean individual vital readings
        hr = float(row["hr"])
        spo2 = float(row["spo2"])
        bp_sys = float(row["bp_sys"])
        bp_dia = float(row["bp_dia"])
        rr = float(row["rr"])

        # Simulated 5G channel profile (incorporating vehicular mobility)
        # 70% clean 5G link, 20% moderate channel congestion, 10% cellular handover burst
        net_roll = random.random()
        if net_roll < 0.70:
            rtt = float(np.random.uniform(12.0, 28.0))
            loss = float(np.random.uniform(0.0, 0.8))
            handover = False
        elif net_roll < 0.90:
            rtt = float(np.random.uniform(35.0, 85.0))
            loss = float(np.random.uniform(1.2, 4.0))
            handover = False
        else:
            rtt = float(np.random.uniform(90.0, 220.0))
            loss = float(np.random.uniform(4.5, 9.5))
            handover = True

        packet = {
            "packet_id": f"mimic_{i+1:05d}",
            "patient_id": "AMB_MIMIC_PATIENT",
            "device_id": dev["id"],
            "device_trust": dev["trust"],
            "source_dataset": row["source_dataset"],
            "vitals": {
                "hr": round(hr, 1),
                "spo2": round(spo2, 1),
                "bp_sys": round(bp_sys, 1),
                "bp_dia": round(bp_dia, 1),
                "rr": round(rr, 1),
            },
        }

        network = {
            "rtt_ms": round(rtt, 2),
            "packet_loss_pct": round(loss, 2),
            "handover_active": handover,
        }

        telemetry_stream.append({"packet": packet, "network": network})

    return telemetry_stream


if __name__ == "__main__":
    print("[+] Loading real MIMIC clinical datasets from parent directory...")
    df = load_mimic_clinical_data("..")
    print(f"  Successfully merged {len(df):,} patient records across 3 Excel files.")
    print("\nDataset Composition:")
    print(df["source_dataset"].value_counts().to_string())

    print("\nClinical Vital Distributions:")
    print(df[["hr", "spo2", "bp_sys", "bp_dia", "rr"]].describe().round(2))

    stream = build_telemetry_stream(clinical_df=df)
    print(f"\n[+] Generated {len(stream):,} complete telemetry packets with 5G metrics and device trust.")

