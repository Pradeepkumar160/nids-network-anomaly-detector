"""
Generate a demo CSV dataset compatible with the NIDS trainer.
Produces 5000 rows with realistic-looking network features and mixed labels.
Run: python generate_demo_data.py
"""
import os
import numpy as np
import pandas as pd

SEED = 42
rng = np.random.default_rng(SEED)

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "data", "datasets", "demo_dataset.csv")
os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

N_BENIGN = 3500
N_PORTSCAN = 500
N_DOS = 500
N_BRUTEFORCE = 300
N_BOTNET = 200


def benign(n):
    return pd.DataFrame({
        "packet_length": rng.integers(40, 1500, n),
        "ttl": rng.choice([64, 128, 255], n),
        "src_port": rng.integers(1024, 65535, n),
        "dst_port": rng.choice([80, 443, 53, 22, 8080, 3306], n),
        "protocol": rng.choice([6, 17, 1], n, p=[0.7, 0.25, 0.05]),
        "tcp_flags": rng.integers(0, 32, n),
        "icmp_type": rng.integers(0, 2, n),
        "icmp_code": np.zeros(n, dtype=int),
        "Label": "BENIGN",
    })


def portscan(n):
    return pd.DataFrame({
        "packet_length": rng.integers(40, 80, n),
        "ttl": rng.choice([64, 128], n),
        "src_port": rng.integers(1024, 65535, n),
        "dst_port": rng.integers(1, 1024, n),
        "protocol": np.full(n, 6),
        "tcp_flags": np.full(n, 2),  # SYN
        "icmp_type": np.zeros(n, dtype=int),
        "icmp_code": np.zeros(n, dtype=int),
        "Label": "PortScan",
    })


def dos(n):
    return pd.DataFrame({
        "packet_length": rng.integers(800, 1500, n),
        "ttl": rng.integers(30, 64, n),
        "src_port": rng.integers(1024, 65535, n),
        "dst_port": rng.choice([80, 443], n),
        "protocol": np.full(n, 6),
        "tcp_flags": rng.choice([2, 18, 24], n),
        "icmp_type": np.zeros(n, dtype=int),
        "icmp_code": np.zeros(n, dtype=int),
        "Label": "DoS",
    })


def bruteforce(n):
    return pd.DataFrame({
        "packet_length": rng.integers(100, 300, n),
        "ttl": rng.choice([64, 128], n),
        "src_port": rng.integers(1024, 65535, n),
        "dst_port": rng.choice([22, 21, 3389], n),
        "protocol": np.full(n, 6),
        "tcp_flags": rng.integers(0, 32, n),
        "icmp_type": np.zeros(n, dtype=int),
        "icmp_code": np.zeros(n, dtype=int),
        "Label": "BruteForce",
    })


def botnet(n):
    return pd.DataFrame({
        "packet_length": rng.integers(50, 200, n),
        "ttl": rng.integers(1, 30, n),
        "src_port": rng.integers(1024, 65535, n),
        "dst_port": rng.choice([6667, 6697, 1337, 31337], n),
        "protocol": rng.choice([6, 17], n),
        "tcp_flags": rng.integers(0, 32, n),
        "icmp_type": np.zeros(n, dtype=int),
        "icmp_code": np.zeros(n, dtype=int),
        "Label": "Botnet",
    })


frames = [benign(N_BENIGN), portscan(N_PORTSCAN), dos(N_DOS), bruteforce(N_BRUTEFORCE), botnet(N_BOTNET)]
df = pd.concat(frames, ignore_index=True).sample(frac=1, random_state=SEED).reset_index(drop=True)
df.to_csv(OUTPUT_PATH, index=False)

counts = df["Label"].value_counts()
print(f"[OK] Demo dataset saved to: {OUTPUT_PATH}")
print(f"   Total rows: {len(df)}")
print("   Label distribution:")
for label, count in counts.items():
    print(f"     {label:15s}: {count}")
