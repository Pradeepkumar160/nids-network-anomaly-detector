"""Feature extraction from Scapy packet objects."""


FEATURE_COLUMNS = [
    "packet_length",
    "ttl",
    "src_port",
    "dst_port",
    "protocol",
    "tcp_flags",
    "icmp_type",
    "icmp_code",
]


def extract_features(packet) -> dict:
    """Extract numeric features from a single Scapy packet."""
    features = {
        "packet_length": len(packet),
        "ttl": 0,
        "src_port": 0,
        "dst_port": 0,
        "protocol": 0,
        "tcp_flags": 0,
        "icmp_type": 0,
        "icmp_code": 0,
    }

    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP

        if IP in packet:
            features["ttl"] = packet[IP].ttl
            features["protocol"] = packet[IP].proto

        if TCP in packet:
            features["src_port"] = packet[TCP].sport
            features["dst_port"] = packet[TCP].dport
            features["tcp_flags"] = int(packet[TCP].flags)
        elif UDP in packet:
            features["src_port"] = packet[UDP].sport
            features["dst_port"] = packet[UDP].dport
        elif ICMP in packet:
            features["icmp_type"] = packet[ICMP].type
            features["icmp_code"] = packet[ICMP].code
    except Exception:
        pass

    return features
