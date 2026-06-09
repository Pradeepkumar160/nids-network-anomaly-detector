import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "random_forest.pkl")
EXPORT_PATH = os.path.join(BASE_DIR, "data", "exports")
DATASETS_PATH = os.path.join(BASE_DIR, "data", "datasets")
UPLOADS_PATH = os.path.join(BASE_DIR, "data", "uploads")

DEFAULT_PACKET_COUNT = 100
ANOMALY_THRESHOLD = 0.80

# Ensure all required directories exist on import
for _path in [EXPORT_PATH, DATASETS_PATH, UPLOADS_PATH, os.path.dirname(MODEL_PATH)]:
    os.makedirs(_path, exist_ok=True)
