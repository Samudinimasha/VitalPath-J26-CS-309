import json

def load_config(config_path="config.json"):
    """Loads weights and threshold boundaries from the configuration file."""
    with open(config_path, "r") as f:
        return json.load(f)

def get_clinical_criticality(vitals, config):
    """
    Evaluates vital signs against AHA, WHO, and ESC clinical thresholds.
    Returns:
        0.2 for Normal
        0.6 for Borderline
        1.0 for Critical
    """
    ranges = config["clinical_ranges"]
    scores = config["clinical_scores"]
    
    hr = vitals.get("hr", 75)
    spo2 = vitals.get("spo2", 98)
    bp_sys = vitals.get("bp_sys", 120)
    bp_dia = vitals.get("bp_dia", 80)
    rr = vitals.get("rr", 16)

    # 1. Check for life-critical anomalies first
    if (hr < ranges["hr"]["critical_min"] or hr > ranges["hr"]["critical_max"] or
        spo2 < ranges["spo2"]["critical_min"] or
        bp_sys < ranges["bp_sys"]["critical_min"] or bp_sys > ranges["bp_sys"]["critical_max"] or
        bp_dia < ranges["bp_dia"]["critical_min"] or bp_dia > ranges["bp_dia"]["critical_max"] or
        rr < ranges["rr"]["critical_min"] or rr > ranges["rr"]["critical_max"]):
        return scores["critical"]

    # 2. Check for borderline / mild elevation
    if (hr < ranges["hr"]["normal_min"] or hr > ranges["hr"]["normal_max"] or
        spo2 < ranges["spo2"]["normal_min"] or
        bp_sys < ranges["bp_sys"]["normal_min"] or bp_sys > ranges["bp_sys"]["normal_max"] or
        bp_dia < ranges["bp_dia"]["normal_min"] or bp_dia > ranges["bp_dia"]["normal_max"] or
        rr < ranges["rr"]["normal_min"] or rr > ranges["rr"]["normal_max"]):
        return scores["borderline"]

    # 3. All vitals are within normal resting limits
    return scores["normal"]

def get_network_condition(network_metrics, config):
    """
    Evaluates 5G channel latency, loss, and handover status into a normalized 0.0 - 1.0 index.
    0.0 represents an optimal channel; 1.0 represents severe link degradation.
    """
    net_cfg = config["network_ranges"]
    rtt = network_metrics.get("rtt_ms", 20.0)
    loss = network_metrics.get("packet_loss_pct", 0.0)
    handover = network_metrics.get("handover_active", False)

    # Calculate normalized RTT impact (0.0 to 1.0)
    rtt_good = net_cfg["rtt_ms"]["good_max"]
    rtt_poor = net_cfg["rtt_ms"]["poor_min"]
    if rtt <= rtt_good:
        rtt_score = 0.0
    elif rtt >= rtt_poor:
        rtt_score = 1.0
    else:
        rtt_score = (rtt - rtt_good) / (rtt_poor - rtt_good)

    # Calculate normalized packet loss impact (0.0 to 1.0)
    loss_good = net_cfg["packet_loss_pct"]["good_max"]
    loss_poor = net_cfg["packet_loss_pct"]["poor_min"]
    if loss <= loss_good:
        loss_score = 0.0
    elif loss >= loss_poor:
        loss_score = 1.0
    else:
        loss_score = (loss - loss_good) / (loss_poor - loss_good)

    # Combine RTT and loss with an additional penalty if a cell handover is in progress
    combined_nc = (0.5 * rtt_score) + (0.5 * loss_score)
    if handover:
        combined_nc = min(1.0, combined_nc + 0.3)

    return round(combined_nc, 3)

def get_device_trust(device_id, trust_cache, config):
    """
    Asynchronously looks up the latest Device Trust Score (DTS) from Component 1's cache.
    Falls back to a safe default if Component 1 has not evaluated the device yet.
    """
    fallback = config.get("default_dts_fallback", 0.70)
    return trust_cache.get(device_id, fallback)