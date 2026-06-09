"""Parse a PCAP/PCAPng file into a DataFrame of features."""
import pandas as pd
from src.feature_extractor import extract_features, FEATURE_COLUMNS
from src.logger import logger


def parse_pcap(file_path: str) -> pd.DataFrame:
    """Read a pcap file and return a DataFrame of packet features."""
    try:
        from scapy.all import rdpcap
        packets = rdpcap(file_path)
        records = [extract_features(pkt) for pkt in packets]
        if not records:
            return pd.DataFrame(columns=FEATURE_COLUMNS)
        df = pd.DataFrame(records)
        # Ensure all expected columns present
        for col in FEATURE_COLUMNS:
            if col not in df.columns:
                df[col] = 0
        return df[FEATURE_COLUMNS].fillna(0)
    except Exception as e:
        logger.error(f"PCAP parse error: {e}")
        return pd.DataFrame(columns=FEATURE_COLUMNS)
