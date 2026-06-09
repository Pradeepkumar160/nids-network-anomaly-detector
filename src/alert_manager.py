"""Generate alerts from prediction results."""
from datetime import datetime
from typing import List, Dict


BENIGN_LABELS = {"BENIGN", "benign", "normal", "Normal", "0"}


def generate_alerts(predictions: list, timestamps: list = None) -> List[Dict]:
    """Return list of alert dicts for any non-benign prediction."""
    alerts = []
    for idx, pred in enumerate(predictions):
        if str(pred).upper() not in {l.upper() for l in BENIGN_LABELS}:
            alerts.append({
                "packet_index": idx,
                "threat_type": pred,
                "severity": _severity(pred),
                "timestamp": timestamps[idx] if timestamps else datetime.now().strftime("%H:%M:%S"),
            })
    return alerts


def _severity(label: str) -> str:
    label_up = str(label).upper()
    if any(k in label_up for k in ["DOS", "DDOS", "BOTNET", "INFILTRATION"]):
        return "🔴 Critical"
    if any(k in label_up for k in ["PORTSCAN", "BRUTEFORCE", "SSH", "FTP"]):
        return "🟠 High"
    if any(k in label_up for k in ["SLOWLORIS", "HULK", "GOLDENEYE"]):
        return "🟡 Medium"
    return "🟢 Low"
