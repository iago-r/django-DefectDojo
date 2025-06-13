import os
from pathlib import Path

AUTHORIZATION = "<your_dojo_auth_token_here>"

WORKDIR = Path(os.getenv("CRIVO_STORAGE_PATH"))
CVE2META_PICKLE_FP = WORKDIR / "cve-metadata/cve2meta.pkl.gz"
FEATURES_FILE = WORKDIR / "model/finding_features.pkl"
PREDICT_DIR = WORKDIR / "model/predict_votes"
URL_API = "http://nginx:8080/api/v2/risk_triggers/"
TARGET_COLUMN = "ranking"
NUM_ESTIMATORS = 100
MAX_DEPTH = 10
LEARNING_RATE = 0.2
SEVERITY_LABELS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
    "Undefined": -1,
}
CLASS_LABELS = {
    1.0: "Mild",
    2.0: "Moderate",
    3.0: "Severe",
    4.0: "Critical",
}
