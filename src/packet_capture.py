"""Live network packet capture using Scapy."""
import pandas as pd
from src.feature_extractor import extract_features, FEATURE_COLUMNS
from src.logger import logger


def capture_packets(interface: str, count: int = 100) -> pd.DataFrame:
    """Capture live packets on the given interface and return features DataFrame."""
    try:
        from scapy.all import sniff
        packets = sniff(iface=interface, count=count, timeout=30)
        records = [extract_features(pkt) for pkt in packets]
        if not records:
            return pd.DataFrame(columns=FEATURE_COLUMNS)
        df = pd.DataFrame(records)
        for col in FEATURE_COLUMNS:
            if col not in df.columns:
                df[col] = 0
        return df[FEATURE_COLUMNS].fillna(0)
    except PermissionError:
        logger.error("Permission denied for packet capture. Run as administrator.")
        raise PermissionError(
            "Packet capture requires Administrator/root privileges.\n"
            "On Windows: Run PowerShell as Administrator.\n"
            "On Linux: Use sudo or grant cap_net_raw capability."
        )
    except Exception as e:
        logger.error(f"Capture error: {e}")
        raise RuntimeError(f"Capture failed: {e}")
