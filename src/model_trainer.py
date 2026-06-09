"""Train a Random Forest classifier on a CSV dataset."""
import os
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
from src.feature_extractor import FEATURE_COLUMNS
from src.logger import logger

MODEL_PATH_DEFAULT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models", "random_forest.pkl"
)
LABEL_ENCODER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models", "label_encoder.pkl"
)


def train_model(dataset_path: str, model_path: str = MODEL_PATH_DEFAULT) -> dict:
    """
    Train a Random Forest classifier.
    Returns a dict with accuracy, report, and label names, or raises on failure.
    """
    try:
        df = pd.read_csv(dataset_path)

        # Normalise column names: strip whitespace, handle CICIDS2017 naming
        df.columns = df.columns.str.strip()

        # Find label column — try common variants
        label_col = None
        for candidate in ["Label", "label", "CLASS", "class", "Attack", "attack"]:
            if candidate in df.columns:
                label_col = candidate
                break
        if label_col is None:
            raise ValueError(
                "No label column found. Expected a column named 'Label', 'label', 'CLASS', or 'Attack'."
            )

        # Build feature matrix — use known columns if present, else use all numeric columns
        available_features = [c for c in FEATURE_COLUMNS if c in df.columns]
        if len(available_features) < 3:
            # Fall back: use all numeric columns except label
            numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
            available_features = [c for c in numeric_cols if c != label_col]

        if not available_features:
            raise ValueError("No usable numeric feature columns found in dataset.")

        X = df[available_features].fillna(0)
        y_raw = df[label_col].astype(str).str.strip()

        # Encode labels
        le = LabelEncoder()
        y = le.fit_transform(y_raw)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X_train, y_train)

        preds = model.predict(X_test)
        accuracy = accuracy_score(y_test, preds)
        report = classification_report(y_test, preds, target_names=le.classes_, output_dict=True)
        cm = confusion_matrix(y_test, preds)

        # Persist model and encoder
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        # Save model with feature columns list so predictor can align
        model.feature_names_in_ = available_features  # store for alignment
        joblib.dump({"model": model, "features": available_features}, model_path)
        joblib.dump(le, LABEL_ENCODER_PATH)

        logger.info(f"Model trained. Accuracy={accuracy:.4f}")

        return {
            "accuracy": accuracy,
            "report": report,
            "confusion_matrix": cm,
            "classes": list(le.classes_),
            "features_used": available_features,
            "n_train": len(X_train),
            "n_test": len(X_test),
        }

    except Exception as e:
        logger.error(f"Training error: {e}")
        raise
