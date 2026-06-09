"""
Network Traffic Anomaly Detector (NIDS)
ML-powered intrusion detection dashboard built with Streamlit.
"""
import os
import sys
import time
import json
import pandas as pd
import numpy as np
import streamlit as st

# ---------------------------------------------------------------------------
# Path setup — must be before any local imports
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from config.settings import MODEL_PATH, DATASETS_PATH, UPLOADS_PATH, EXPORT_PATH
from src.model_trainer import train_model
from src.pcap_reader import parse_pcap
from src.predictor import predict, model_is_ready
from src.alert_manager import generate_alerts
from src.dashboard import (
    threat_chart,
    protocol_pie,
    port_histogram,
    feature_distribution,
    confusion_heatmap,
    metrics_gauge,
)

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="NIDS — Network Intrusion Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS — dark cyber theme
# ---------------------------------------------------------------------------
st.markdown(
    """
<style>
    /* ── Global ── */
    html, body, [class*="css"] {
        font-family: 'Inter', 'Segoe UI', sans-serif;
    }
    .stApp {
        background: #0d1117;
        color: #e6edf3;
    }

    /* ── Sidebar ── */
    [data-testid="stSidebar"] {
        background: #161b22 !important;
        border-right: 1px solid #30363d;
    }
    [data-testid="stSidebar"] .stSelectbox label,
    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] span {
        color: #8b949e !important;
    }

    /* ── Metric cards ── */
    .metric-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 18px 22px;
        text-align: center;
    }
    .metric-card .label {
        color: #8b949e;
        font-size: 13px;
        text-transform: uppercase;
        letter-spacing: .08em;
        margin-bottom: 6px;
    }
    .metric-card .value {
        color: #00d4aa;
        font-size: 32px;
        font-weight: 700;
        line-height: 1;
    }
    .metric-card .value.danger { color: #ff4444; }
    .metric-card .value.warn  { color: #ffaa00; }

    /* ── Alert table ── */
    .alert-row {
        background: rgba(255,68,68,0.08);
        border-left: 3px solid #ff4444;
        border-radius: 6px;
        padding: 10px 14px;
        margin-bottom: 6px;
        font-size: 14px;
    }
    .alert-row .threat { font-weight: 600; color: #ff4444; }

    /* ── Section headers ── */
    .section-title {
        color: #e6edf3;
        font-size: 18px;
        font-weight: 600;
        margin: 24px 0 12px;
        padding-bottom: 6px;
        border-bottom: 1px solid #30363d;
    }

    /* ── Status badge ── */
    .badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
    }
    .badge.ready   { background: rgba(0,204,102,.15); color: #00cc66; }
    .badge.missing { background: rgba(255,68,68,.15);  color: #ff4444; }

    /* ── Progress bar color ── */
    .stProgress > div > div > div { background-color: #00d4aa !important; }

    /* ── Streamlit overrides ── */
    .stButton > button {
        background: #00d4aa;
        color: #0d1117;
        font-weight: 700;
        border: none;
        border-radius: 8px;
        padding: 8px 22px;
    }
    .stButton > button:hover { background: #00f0c3; }
    .stDataFrame { border: 1px solid #30363d; border-radius: 8px; }
    .stAlert { border-radius: 8px; }
</style>
""",
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.image(
        "https://img.icons8.com/fluency/96/shield.png",
        width=56,
    )
    st.markdown("## 🛡️ NIDS Dashboard")
    st.markdown("---")

    menu = st.selectbox(
        "Navigation",
        ["🏠 Overview", "🧠 Train Model", "📁 Analyze PCAP", "📡 Live Capture", "📊 Analytics"],
        label_visibility="collapsed",
    )

    st.markdown("---")
    # Model status
    if model_is_ready():
        st.markdown('<span class="badge ready">✅ Model Ready</span>', unsafe_allow_html=True)
    else:
        st.markdown('<span class="badge missing">⚠️ No Model</span>', unsafe_allow_html=True)

    st.markdown("")
    st.caption("Network Traffic Anomaly Detector v1.0")


# ---------------------------------------------------------------------------
# Helper: render metric cards
# ---------------------------------------------------------------------------
def metric_card(label: str, value, css_class: str = ""):
    st.markdown(
        f"""<div class="metric-card">
            <div class="label">{label}</div>
            <div class="value {css_class}">{value}</div>
        </div>""",
        unsafe_allow_html=True,
    )


# ===========================================================================
# PAGE: Overview
# ===========================================================================
if menu == "🏠 Overview":
    st.markdown("# 🛡️ Network Traffic Anomaly Detector")
    st.markdown(
        "An ML-powered intrusion detection system for analysing network traffic, "
        "detecting threats, and visualising anomalies in real time."
    )

    st.markdown('<div class="section-title">System Status</div>', unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        metric_card("Model Status", "Ready ✅" if model_is_ready() else "Missing ⚠️",
                    "" if model_is_ready() else "danger")
    with col2:
        datasets = len([f for f in os.listdir(DATASETS_PATH) if f.endswith(".csv")])
        metric_card("Datasets Loaded", datasets)
    with col3:
        exports = len(os.listdir(EXPORT_PATH))
        metric_card("Exports", exports)
    with col4:
        metric_card("Version", "1.0.0")

    st.markdown('<div class="section-title">Quick Start Guide</div>', unsafe_allow_html=True)

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown(
            """
**Step 1 — Generate or upload a dataset**
```
python generate_demo_data.py
```
This creates `data/datasets/demo_dataset.csv` with 5 000 labelled rows.

**Step 2 — Train the model**
Go to **🧠 Train Model** and upload the CSV. Training takes ~10 seconds.

**Step 3 — Analyse traffic**
- Upload a `.pcap` file on **📁 Analyze PCAP**
- Or capture live traffic on **📡 Live Capture** *(admin required)*
"""
        )
    with col_b:
        st.markdown(
            """
**Supported threat types (demo dataset)**
| Label | Description |
|---|---|
| BENIGN | Normal traffic |
| PortScan | Network reconnaissance |
| DoS | Denial of service flood |
| BruteForce | Credential guessing |
| Botnet | C2 communication |

**Dataset compatibility**
The trainer accepts any CSV with a `Label` column and numeric features.
CICIDS2017 format is natively supported.
"""
        )

    st.markdown('<div class="section-title">Architecture</div>', unsafe_allow_html=True)
    st.code(
        """
  ┌─────────────────────────────────────────────────┐
  │                  Streamlit UI                   │
  └──────────┬───────────────────┬──────────────────┘
             │                   │
    ┌────────▼──────┐    ┌───────▼────────┐
    │  PCAP Reader  │    │  Packet Sniffer│
    └────────┬──────┘    └───────┬────────┘
             └────────┬──────────┘
                      │
             ┌────────▼────────┐
             │Feature Extractor│
             └────────┬────────┘
                      │
             ┌────────▼────────┐
             │  Random Forest  │
             └────────┬────────┘
                      │
             ┌────────▼────────┐
             │  Alert Engine   │
             └────────┬────────┘
                      │
             ┌────────▼────────┐
             │    Dashboard    │
             └─────────────────┘
""",
        language="text",
    )


# ===========================================================================
# PAGE: Train Model
# ===========================================================================
elif menu == "🧠 Train Model":
    st.markdown("# 🧠 Train Machine Learning Model")
    st.markdown(
        "Upload a labelled CSV dataset to train a Random Forest classifier. "
        "The dataset must contain numeric feature columns and a **`Label`** column."
    )

    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown('<div class="section-title">Upload Dataset</div>', unsafe_allow_html=True)
        dataset_file = st.file_uploader(
            "Upload Training Dataset (CSV)",
            type=["csv"],
            help="Supported: CICIDS2017 or the demo dataset generated by generate_demo_data.py",
        )

        if st.button("Use Demo Dataset (auto-generate)"):
            with st.spinner("Generating demo dataset…"):
                import subprocess
                result = subprocess.run(
                    [sys.executable, os.path.join(PROJECT_ROOT, "generate_demo_data.py")],
                    capture_output=True, text=True, encoding="utf-8", errors="replace"
                )
            demo_path = os.path.join(DATASETS_PATH, "demo_dataset.csv")
            if os.path.exists(demo_path):
                st.success("Demo dataset generated successfully!")
                demo_path = os.path.join(DATASETS_PATH, "demo_dataset.csv")
                dataset_file = None  # will be picked up below via path
                st.session_state["demo_ready"] = demo_path
            else:
                st.error(f"Error: {result.stderr}")

    with col2:
        st.markdown('<div class="section-title">Training Settings</div>', unsafe_allow_html=True)
        st.info(
            "**Algorithm**: Random Forest (100 trees, max depth 15)\n\n"
            "**Split**: 80% train / 20% test\n\n"
            "**Label column**: `Label` (auto-detected)"
        )

    # Resolve dataset path
    train_path = None
    if dataset_file is not None:
        train_path = os.path.join(DATASETS_PATH, "train.csv")
        with open(train_path, "wb") as f:
            f.write(dataset_file.getbuffer())
        st.success(f"Dataset uploaded: {dataset_file.name}  ({dataset_file.size // 1024} KB)")
    elif st.session_state.get("demo_ready"):
        train_path = st.session_state["demo_ready"]
        st.info(f"Using demo dataset: {train_path}")

    if train_path and os.path.exists(train_path):
        # Preview
        try:
            preview = pd.read_csv(train_path, nrows=5)
            st.markdown('<div class="section-title">Dataset Preview</div>', unsafe_allow_html=True)
            st.dataframe(preview, use_container_width=True)
            full = pd.read_csv(train_path)
            mc1, mc2, mc3 = st.columns(3)
            with mc1:
                metric_card("Total Rows", f"{len(full):,}")
            with mc2:
                metric_card("Features", len(full.columns) - 1)
            with mc3:
                if "Label" in full.columns:
                    metric_card("Classes", full["Label"].nunique())
        except Exception as e:
            st.warning(f"Could not preview dataset: {e}")

        if st.button("🚀 Start Training", type="primary"):
            progress = st.progress(0, text="Initialising…")
            status = st.empty()
            try:
                progress.progress(20, text="Loading dataset…")
                time.sleep(0.3)
                progress.progress(40, text="Splitting data…")
                time.sleep(0.3)
                progress.progress(60, text="Fitting Random Forest…")
                result = train_model(train_path)
                progress.progress(90, text="Saving model…")
                time.sleep(0.3)
                progress.progress(100, text="Done ✅")

                st.success("Model trained successfully!")

                r1, r2, r3, r4 = st.columns(4)
                with r1:
                    metric_card("Accuracy", f"{result['accuracy']:.2%}")
                with r2:
                    metric_card("Train Samples", f"{result['n_train']:,}")
                with r3:
                    metric_card("Test Samples", f"{result['n_test']:,}")
                with r4:
                    metric_card("Classes", len(result["classes"]))

                # Accuracy gauge
                fig_gauge = metrics_gauge(result["accuracy"])
                st.plotly_chart(fig_gauge, use_container_width=True)

                # Confusion matrix
                if result.get("confusion_matrix") is not None:
                    st.markdown('<div class="section-title">Confusion Matrix</div>', unsafe_allow_html=True)
                    fig_cm = confusion_heatmap(result["confusion_matrix"], result["classes"])
                    st.plotly_chart(fig_cm, use_container_width=True)

                # Per-class report
                st.markdown('<div class="section-title">Per-Class Report</div>', unsafe_allow_html=True)
                report_df = pd.DataFrame(result["report"]).transpose().round(3)
                st.dataframe(report_df, use_container_width=True)

            except Exception as e:
                progress.empty()
                st.error(f"Training failed: {e}")


# ===========================================================================
# PAGE: Analyze PCAP
# ===========================================================================
elif menu == "📁 Analyze PCAP":
    st.markdown("# 📁 PCAP File Analysis")
    st.markdown("Upload a `.pcap` or `.pcapng` capture file to run ML-based threat detection.")

    if not model_is_ready():
        st.error("⚠️ No trained model found. Please go to **🧠 Train Model** first.")
        st.stop()

    pcap_file = st.file_uploader("Upload PCAP File", type=["pcap", "pcapng"])

    if pcap_file:
        save_path = os.path.join(UPLOADS_PATH, pcap_file.name)
        with open(save_path, "wb") as f:
            f.write(pcap_file.getbuffer())

        with st.spinner("Parsing packets and running inference…"):
            df = parse_pcap(save_path)

        if df.empty:
            st.error("Could not extract any packets. Is the file a valid PCAP?")
            st.stop()

        preds = predict(df)
        df["prediction"] = preds
        alerts = generate_alerts(preds)

        # ── Summary metrics ──
        n_total = len(df)
        n_threats = sum(1 for p in preds if str(p).upper() != "BENIGN")
        n_benign = n_total - n_threats
        threat_pct = n_threats / n_total * 100 if n_total else 0

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            metric_card("Total Packets", f"{n_total:,}")
        with c2:
            metric_card("Benign", f"{n_benign:,}", "")
        with c3:
            metric_card("Threats", f"{n_threats:,}", "danger" if n_threats else "")
        with c4:
            metric_card("Threat Rate", f"{threat_pct:.1f}%", "warn" if threat_pct > 10 else "")

        # ── Charts ──
        st.markdown('<div class="section-title">Traffic Visualisations</div>', unsafe_allow_html=True)
        ch1, ch2 = st.columns(2)
        with ch1:
            fig_threat = threat_chart(df)
            if fig_threat:
                st.plotly_chart(fig_threat, use_container_width=True)
        with ch2:
            fig_proto = protocol_pie(df)
            if fig_proto:
                st.plotly_chart(fig_proto, use_container_width=True)

        ch3, ch4 = st.columns(2)
        with ch3:
            fig_port = port_histogram(df)
            if fig_port:
                st.plotly_chart(fig_port, use_container_width=True)
        with ch4:
            fig_len = feature_distribution(df, "packet_length")
            if fig_len:
                st.plotly_chart(fig_len, use_container_width=True)

        # ── Alerts ──
        st.markdown('<div class="section-title">🚨 Security Alerts</div>', unsafe_allow_html=True)
        if alerts:
            st.warning(f"{len(alerts)} threat(s) detected in this capture.")
            alerts_df = pd.DataFrame(alerts)
            st.dataframe(alerts_df, use_container_width=True)

            # Export
            export_path = os.path.join(EXPORT_PATH, f"alerts_{pcap_file.name}.csv")
            alerts_df.to_csv(export_path, index=False)
            st.download_button(
                "⬇️ Download Alert Report (CSV)",
                data=alerts_df.to_csv(index=False),
                file_name=f"alerts_{pcap_file.name}.csv",
                mime="text/csv",
            )
        else:
            st.success("✅ No threats detected — traffic looks benign.")

        # ── Raw data ──
        with st.expander("📋 Raw Packet Features & Predictions"):
            st.dataframe(df, use_container_width=True)
            st.download_button(
                "⬇️ Download Full Results (CSV)",
                data=df.to_csv(index=False),
                file_name=f"results_{pcap_file.name}.csv",
                mime="text/csv",
            )


# ===========================================================================
# PAGE: Live Capture
# ===========================================================================
elif menu == "📡 Live Capture":
    st.markdown("# 📡 Live Packet Capture")
    st.markdown(
        "Capture and analyse live network traffic. "
        "**Requires Administrator (Windows) or root (Linux) privileges.**"
    )

    if not model_is_ready():
        st.error("⚠️ No trained model found. Please go to **🧠 Train Model** first.")
        st.stop()

    # Auto-detect available network interfaces
    def get_interfaces():
        ifaces = []
        try:
            import psutil
            ifaces = list(psutil.net_if_addrs().keys())
        except Exception:
            pass
        if not ifaces:
            try:
                from scapy.all import get_if_list
                ifaces = get_if_list()
            except Exception:
                pass
        return ifaces

    available_ifaces = get_interfaces()

    col1, col2 = st.columns([2, 1])
    with col1:
        if available_ifaces:
            st.caption("Detected interfaces — select one:")
            interface = st.selectbox("Network Interface", available_ifaces)
        else:
            interface = st.text_input(
                "Network Interface",
                value="Ethernet",
                help="Windows: Ethernet or Wi-Fi | Linux: eth0, wlan0, lo",
            )
    with col2:
        count = st.number_input("Packet Count", min_value=10, max_value=2000, value=100, step=10)

    st.info("Windows: Run PowerShell as Administrator then: streamlit run app.py  |  Linux: sudo streamlit run app.py")

    if st.button("Start Capture", type="primary"):
        with st.spinner(f"Capturing {count} packets on `{interface}`…"):
            try:
                from src.packet_capture import capture_packets
                df = capture_packets(interface, int(count))

                if df.empty:
                    st.error("No packets captured. Check the interface name and permissions.")
                    st.stop()

                preds = predict(df)
                df["prediction"] = preds
                alerts = generate_alerts(preds)

                n_total = len(df)
                n_threats = sum(1 for p in preds if str(p).upper() != "BENIGN")

                c1, c2, c3 = st.columns(3)
                with c1:
                    metric_card("Captured", n_total)
                with c2:
                    metric_card("Clean", n_total - n_threats)
                with c3:
                    metric_card("Threats", n_threats, "danger" if n_threats else "")

                fig_t = threat_chart(df)
                if fig_t:
                    st.plotly_chart(fig_t, use_container_width=True)

                if alerts:
                    st.warning(f"🚨 {len(alerts)} threat(s) found!")
                    st.dataframe(pd.DataFrame(alerts), use_container_width=True)
                else:
                    st.success("✅ No threats detected.")

                with st.expander("Raw capture data"):
                    st.dataframe(df, use_container_width=True)

            except PermissionError as e:
                st.error(str(e))
            except Exception as e:
                st.error(f"Capture error: {e}")


# ===========================================================================
# PAGE: Analytics
# ===========================================================================
elif menu == "📊 Analytics":
    st.markdown("# 📊 Analytics & Exports")

    st.markdown('<div class="section-title">Saved Exports</div>', unsafe_allow_html=True)
    export_files = [f for f in os.listdir(EXPORT_PATH) if f.endswith(".csv")]
    if not export_files:
        st.info("No exported files yet. Analyse a PCAP file to generate reports.")
    else:
        selected = st.selectbox("Select export file", export_files)
        export_df = pd.read_csv(os.path.join(EXPORT_PATH, selected))
        st.dataframe(export_df, use_container_width=True)

        # Quick chart of selected export
        if "threat_type" in export_df.columns:
            counts = export_df["threat_type"].value_counts().reset_index()
            counts.columns = ["Threat", "Count"]
            import plotly.express as px
            fig = px.bar(
                counts, x="Threat", y="Count",
                color_discrete_sequence=["#ff4444"],
                template="plotly_dark",
            )
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)

    st.markdown('<div class="section-title">Datasets on Disk</div>', unsafe_allow_html=True)
    csv_files = [f for f in os.listdir(DATASETS_PATH) if f.endswith(".csv")]
    if not csv_files:
        st.info("No datasets found. Run `python generate_demo_data.py` or upload a CSV.")
    else:
        for f in csv_files:
            size_kb = os.path.getsize(os.path.join(DATASETS_PATH, f)) // 1024
            st.markdown(f"📄 `{f}` — {size_kb} KB")
