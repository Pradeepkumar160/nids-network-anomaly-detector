# NIDS — Network Traffic Anomaly Detector.

> An ML-powered Network Intrusion Detection System built with Python, Streamlit, Scapy, and scikit-learn. Detects network threats in real time via live packet capture or offline PCAP analysis, with an interactive dark-themed dashboard.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-00d4aa?style=for-the-badge&logoColor=white)

---

## What It Does

NIDS watches your network and uses a trained Random Forest classifier to label every packet as benign or a specific threat type — PortScan, DoS, BruteForce, Botnet, and more. Results are visualised instantly in a dashboard with charts, alert tables, and export options.

```
  ┌──────────────────────────────────────┐
  │          Streamlit Dashboard          │
  └────────────┬──────────────┬──────────┘
               │              │
     ┌──────────▼──┐    ┌──────▼──────────┐
     │ PCAP Reader │    │  Live Capture   │
     └──────────┬──┘    └──────┬──────────┘
                └──────┬───────┘
                       │
              ┌────────▼────────┐
              │Feature Extractor│  (Scapy)
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │ Random Forest   │  (scikit-learn)
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │  Alert Engine   │
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │  Plotly Charts  │
              └─────────────────┘
```

---

## Features

- **PCAP Analysis** — Upload `.pcap` or `.pcapng` files for instant offline threat detection
- **Live Packet Capture** — Real-time capture on any network interface (requires admin privileges)
- **ML Model Training** — Train on any labelled CSV dataset; CICIDS2017 format natively supported
- **Interactive Dashboard** — Traffic classification bar chart, protocol pie, port histogram, feature distribution, confusion matrix, accuracy gauge
- **Alert Engine** — Severity-ranked alerts (Critical / High / Medium / Low) with CSV export
- **Auto Interface Detection** — Dropdown of real network interfaces on Windows and Linux
- **Demo Dataset Generator** — Generates 5,000 labelled packets locally; no external data needed
- **Docker Support** — Single command to run the entire app in a container

---

## Tech Stack

| Layer | Technology |
|---|---|
| Dashboard | Streamlit |
| ML Model | scikit-learn (Random Forest) |
| Packet Analysis | Scapy |
| Visualisation | Plotly |
| Data Processing | Pandas, NumPy |
| Model Storage | Joblib |
| Containerisation | Docker + Docker Compose |

---

## Project Structure

```
nids-app/
├── app.py                  # Main Streamlit application
├── generate_demo_data.py   # Demo dataset generator (5,000 rows, 5 classes)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── run.ps1                 # Windows PowerShell launcher
├── run_docker.ps1          # Docker launcher for Windows
│
├── config/
│   └── settings.py         # Paths and thresholds
│
├── src/
│   ├── feature_extractor.py  # Scapy packet → feature dict
│   ├── pcap_reader.py        # PCAP file → DataFrame
│   ├── packet_capture.py     # Live sniff → DataFrame
│   ├── model_trainer.py      # Train + evaluate Random Forest
│   ├── predictor.py          # Load model + run inference
│   ├── alert_manager.py      # Generate severity-ranked alerts
│   ├── dashboard.py          # Plotly chart helpers
│   └── logger.py             # File logger
│
├── data/
│   ├── datasets/             # Training CSVs
│   ├── uploads/              # Uploaded PCAP files
│   └── exports/              # Alert report exports
│
└── models/
    ├── random_forest.pkl     # Trained model bundle
    └── label_encoder.pkl     # Label encoder
```

---

## Quick Start

### Option A — Python (Windows / Linux / macOS)

**1. Clone the repo**
```bash
git clone https://github.com/Pradeepkumar160/nids-network-anomaly-detector.git
cd nids-network-anomaly-detector
```

**2. Create and activate virtual environment**
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Generate demo dataset**
```bash
python generate_demo_data.py
```

**5. Launch the app**
```bash
streamlit run app.py
```

Open **http://localhost:8501** in your browser.

---

### Option B — Docker

```bash
git clone https://github.com/Pradeepkumar160/nids-network-anomaly-detector.git
cd nids-network-anomaly-detector
docker-compose up --build
```

Open **http://localhost:8501** in your browser.

---

## How to Use

### Step 1 — Train the Model
1. Go to **Train Model** in the sidebar
2. Click **"Use Demo Dataset (auto-generate)"** — or upload your own CSV
3. Click **"Start Training"**
4. The model trains in ~10 seconds and shows accuracy, confusion matrix, and per-class report

### Step 2 — Analyse a PCAP File
1. Go to **Analyze PCAP**
2. Upload a `.pcap` or `.pcapng` file
3. View the threat classification, charts, and alert table
4. Export alerts as CSV

### Step 3 — Live Capture *(requires admin)*
1. Go to **Live Capture**
2. Select your network interface from the dropdown
3. Set packet count and click **Start Capture**

> **Windows**: Run PowerShell as Administrator before launching
> **Linux**: `sudo streamlit run app.py`

---

## Dataset Compatibility

Works with any CSV that has a `Label` column and numeric feature columns.

Natively supports **CICIDS2017** format. Download from [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html).

The built-in demo generator produces:

| Label | Count | Description |
|---|---|---|
| BENIGN | 3,500 | Normal traffic |
| PortScan | 500 | Network reconnaissance |
| DoS | 500 | Denial of service |
| BruteForce | 300 | Credential guessing |
| Botnet | 200 | C2 communication |

---

## Model Performance (Demo Dataset)

| Metric | Score |
|---|---|
| Accuracy | ~99.4% |
| Algorithm | Random Forest (100 trees, depth 15) |
| Train/Test Split | 80% / 20% |
| Features | packet_length, ttl, src_port, dst_port, protocol, tcp_flags, icmp_type, icmp_code |

---

## Live Capture Notes

Live packet capture uses **Scapy** under the hood and requires elevated privileges:

- **Windows** — Run PowerShell or Command Prompt as **Administrator**
- **Linux** — Run with `sudo`, or grant capability: `sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)`
- **Docker** — `NET_ADMIN` and `NET_RAW` caps are included in `docker-compose.yml`

---

## Roadmap

- [ ] Isolation Forest for unsupervised anomaly detection
- [ ] XGBoost / LightGBM classifier option
- [ ] SHAP explainability for predictions
- [ ] Real-time streaming alerts via WebSocket
- [ ] Email / Slack / Discord alert integrations
- [ ] Wazuh / ELK / Splunk / Suricata integration
- [ ] Kafka streaming pipeline

---

## Contributing

Pull requests are welcome. For major changes, open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## License

[MIT](LICENSE)

---

## Author

**Pradeep Kumar**
CS Undergrad | Cybersecurity | AI/ML | Full-Stack Developer

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/07pradeepk)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=flat-square&logo=github&logoColor=white)](https://github.com/Pradeepkumar160)

---

> "The quieter you become, the more you are able to hear — in code and in security."
