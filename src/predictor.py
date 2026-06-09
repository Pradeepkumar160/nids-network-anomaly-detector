"""Load trained model and run inference."""
import os
import pandas as pd
import numpy as np
import joblib
from src.logger import logger

MODEL_PATH_DEFAULT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models", "random_forest.pkl"
)
LABEL_ENCODER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models", "label_encoder.pkl"
)

_cache: dict = {}


def _load(model_path: str = MODEL_PATH_DEFAULT):
    if model_path not in _cache:
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                "No trained model found. Please train a model first via the 'Train Model' page."
            )
        bundle = joblib.load(model_path)
        le = joblib.load(LABEL_ENCODER_PATH) if os.path.exists(LABEL_ENCODER_PATH) else None
        _cache[model_path] = (bundle["model"], bundle["features"], le)
    return _cache[model_path]


def predict(df: pd.DataFrame, model_path: str = MODEL_PATH_DEFAULT) -> list:
    """Run model on DataFrame; returns list of string label predictions."""
    # Invalidate cache if model file was recently updated
    if model_path in _cache:
        del _cache[model_path]

    model, features, le = _load(model_path)

    # Align columns
    for col in features:
        if col not in df.columns:
            df[col] = 0
    X = df[features].fillna(0)

    raw_preds = model.predict(X)

    if le is not None:
        try:
            return list(le.inverse_transform(raw_preds))
        except Exception:
            pass
    return [str(p) for p in raw_preds]


def model_is_ready(model_path: str = MODEL_PATH_DEFAULT) -> bool:
    return os.path.exists(model_path) and os.path.exists(LABEL_ENCODER_PATH)
