"""Dashboard chart helpers using Plotly."""
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots


PALETTE = {
    "bg": "#0d1117",
    "surface": "#161b22",
    "border": "#30363d",
    "accent": "#00d4aa",
    "danger": "#ff4444",
    "warn": "#ffaa00",
    "safe": "#00cc66",
    "text": "#e6edf3",
}


def _base_layout(title: str = "") -> dict:
    return dict(
        title=dict(text=title, font=dict(color=PALETTE["text"], size=16)),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=PALETTE["text"]),
        margin=dict(l=20, r=20, t=40, b=20),
    )


def threat_chart(df: pd.DataFrame):
    """Horizontal bar chart of prediction counts."""
    if "prediction" not in df.columns or df.empty:
        return None
    counts = df["prediction"].value_counts().reset_index()
    counts.columns = ["Prediction", "Count"]
    colors = [
        PALETTE["danger"] if str(p).upper() != "BENIGN" else PALETTE["safe"]
        for p in counts["Prediction"]
    ]
    fig = go.Figure(
        go.Bar(
            x=counts["Count"],
            y=counts["Prediction"],
            orientation="h",
            marker_color=colors,
            text=counts["Count"],
            textposition="outside",
        )
    )
    fig.update_layout(**_base_layout("Traffic Classification"), xaxis_title="Packets")
    return fig


def protocol_pie(df: pd.DataFrame):
    if "protocol" not in df.columns or df.empty:
        return None
    proto_map = {0: "Other", 6: "TCP", 17: "UDP", 1: "ICMP"}
    df = df.copy()
    df["proto_name"] = df["protocol"].map(proto_map).fillna("Other")
    counts = df["proto_name"].value_counts().reset_index()
    counts.columns = ["Protocol", "Count"]
    fig = px.pie(
        counts,
        names="Protocol",
        values="Count",
        color_discrete_sequence=[PALETTE["accent"], PALETTE["warn"], PALETTE["danger"], "#8888ff"],
        hole=0.45,
    )
    fig.update_layout(**_base_layout("Protocol Distribution"))
    return fig


def port_histogram(df: pd.DataFrame, top_n: int = 15):
    if "dst_port" not in df.columns or df.empty:
        return None
    top = df[df["dst_port"] > 0]["dst_port"].value_counts().head(top_n).reset_index()
    top.columns = ["Port", "Count"]
    fig = go.Figure(
        go.Bar(x=top["Port"].astype(str), y=top["Count"], marker_color=PALETTE["accent"])
    )
    fig.update_layout(**_base_layout(f"Top {top_n} Destination Ports"))
    return fig


def feature_distribution(df: pd.DataFrame, feature: str = "packet_length"):
    if feature not in df.columns or df.empty:
        return None
    fig = px.histogram(
        df,
        x=feature,
        nbins=40,
        color_discrete_sequence=[PALETTE["accent"]],
    )
    fig.update_layout(**_base_layout(f"{feature} Distribution"))
    return fig


def confusion_heatmap(cm, class_names: list):
    import numpy as np
    fig = px.imshow(
        cm,
        labels=dict(x="Predicted", y="Actual", color="Count"),
        x=class_names,
        y=class_names,
        color_continuous_scale=[[0, PALETTE["bg"]], [1, PALETTE["accent"]]],
        text_auto=True,
    )
    fig.update_layout(**_base_layout("Confusion Matrix"))
    return fig


def metrics_gauge(accuracy: float):
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=round(accuracy * 100, 2),
            domain={"x": [0, 1], "y": [0, 1]},
            title={"text": "Model Accuracy (%)", "font": {"color": PALETTE["text"]}},
            number={"suffix": "%", "font": {"color": PALETTE["accent"]}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": PALETTE["text"]},
                "bar": {"color": PALETTE["accent"]},
                "bgcolor": PALETTE["surface"],
                "steps": [
                    {"range": [0, 60], "color": PALETTE["danger"]},
                    {"range": [60, 80], "color": PALETTE["warn"]},
                    {"range": [80, 100], "color": PALETTE["safe"]},
                ],
                "threshold": {
                    "line": {"color": "white", "width": 2},
                    "thickness": 0.75,
                    "value": accuracy * 100,
                },
            },
        )
    )
    fig.update_layout(**_base_layout(), height=250)
    return fig
