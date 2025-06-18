import logging
import re
import time
from pathlib import Path

import dojolib
import numpy as np
import pandas as pd
import requests
from datastore import DataStore
from settings import (
    AUTHORIZATION,
    CVE2META_PICKLE_FP,
    LEARNING_RATE,
    MAX_DEPTH,
    NUM_ESTIMATORS,
    PREDICT_DIR,
    TARGET_COLUMN,
    URL_API,
    WORKDIR,
)
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from xgboost import XGBRegressor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

VOTES_DIR = WORKDIR / "model/user_votes"
FEATURES_DIR = WORKDIR / "model/finding_features"
CLASS_LABELS = {v: k for k, v in dojolib.DojoRanking.CLASS_MAP.items() if v is not None}


def load_combined_data(vote_fp: Path, features_fp: Path, datastore: DataStore) -> pd.DataFrame:
    class_features, class_rankings = dojolib.load_features_rankings(features_fp, vote_fp, datastore)
    return dojolib.get_merged_df(class_features, class_rankings)


def prepare_training_data(training_df: pd.DataFrame) -> pd.DataFrame:
    training_df = training_df[training_df[TARGET_COLUMN].notna()].copy()

    if "vote_class" in training_df.columns:
        training_df = training_df[training_df["vote_class"] != "NA"]
    if "vote_num" in training_df.columns:
        training_df = training_df[training_df["vote_num"] != "NV"]

    for col in dojolib.DojoFindingFeatures.CATEGORICAL_FEATURES:
        training_df[col] = training_df[col].astype("category")

    return training_df


def prepare_prediction_data(pred_df: pd.DataFrame) -> pd.DataFrame:
    pred_df = pred_df[pred_df[TARGET_COLUMN].isna()].copy()
    pred_df = pred_df.set_index("fid", drop=False)

    for col in dojolib.DojoFindingFeatures.CATEGORICAL_FEATURES:
        pred_df[col] = pred_df[col].astype("category")

    return pred_df


def train_model(x: pd.DataFrame, y: pd.Series) -> XGBRegressor:
    model = XGBRegressor(
        n_estimators=NUM_ESTIMATORS,
        learning_rate=LEARNING_RATE,
        max_depth=MAX_DEPTH,
        verbosity=0,
        enable_categorical=True,
    )
    model.fit(x, y)
    return model


def predict(df: pd.DataFrame, model: XGBRegressor, feature_columns: list[str]) -> pd.DataFrame:
    df["predicted_raw_score"] = model.predict(df[feature_columns])
    df["predicted_vote_class"] = np.round(df["predicted_raw_score"])
    df["predicted_vote_label"] = df["predicted_vote_class"].map(CLASS_LABELS)
    return df


def export_predictions_to_json(predictions_df: pd.DataFrame, output_path: Path) -> None:
    df_to_export = predictions_df.assign(id=predictions_df.index)[["id", "user_id", "predicted_vote_label", "predicted_vote_class"]]

    df_to_export.to_json(output_path, orient="records", lines=False, indent=2, force_ascii=False)
    logger.info(f"Exported prediction results to {output_path}")


def request_create_inferences(predict_file_path: Path):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Token {AUTHORIZATION}",
    }
    payload = {
        "inferences": str(predict_file_path),
    }
    response = requests.post(URL_API, headers=headers, json=payload, verify=True, timeout=20)
    logger.info(f"Response from API: {response.status_code} - {response.text}")


def process_prediction_pipeline(vote_fp: Path, features_fp: Path, datastore: DataStore):
    logger.info(f"Processing files:\n- Votes: {vote_fp}\n- Features: {features_fp}")
    class_df = load_combined_data(vote_fp, features_fp, datastore)
    unique_users = class_df["user_id"].dropna().unique()
    if len(unique_users) != 1:
        error_message = (
            f"Expected exactly one user_id in the data, but found {len(unique_users)}: {unique_users}"
        )
        raise ValueError(error_message)
    user_id = int(unique_users[0])
    class_df = class_df.drop(columns=["user_id"])
    training_df = prepare_training_data(class_df)
    columns_to_exclude = ["id", "fid", "ranking", "vote_class", "vote_num"]
    feature_columns = [col for col in training_df.columns if col not in columns_to_exclude]
    model = train_model(training_df[feature_columns], training_df[TARGET_COLUMN])
    prediction_df = prepare_prediction_data(class_df)
    prediction_result = predict(prediction_df, model, feature_columns)
    prediction_result["user_id"] = user_id

    timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
    predict_file = PREDICT_DIR / f"user2data_{user_id}_{timestamp}.json"
    export_predictions_to_json(prediction_result, predict_file)
    request_create_inferences(predict_file)

    vote_fp.unlink(missing_ok=True)
    features_fp.unlink(missing_ok=True)
    logger.info("Cleanup temporary files completed.")


def handle_event(event, datastore):
    vote_fp = Path(event.src_path)
    if vote_fp.suffix != ".pkl":
        return
    logger.info(f"Detected new vote file: {vote_fp.name}")
    match = re.search(r"([^_]+)_(\d{8}_\d{6})_votes\.pkl", vote_fp.name)
    if not match:
        logger.warning(f"Filename does not match expected pattern: {vote_fp.name}")
        return
    user_id = match.group(1)
    timestamp = match.group(2)
    features_fp = FEATURES_DIR / f"{user_id}_{timestamp}_features.pkl"
    if features_fp.exists():
        process_prediction_pipeline(vote_fp, features_fp, datastore)
    else:
        logger.warning(f"Features file not found: {features_fp}")


def main():
    logger.info("Loading datastore...")
    datastore = DataStore()
    datastore.load(metadata_fp=CVE2META_PICKLE_FP)
    logger.info(f"Watching directory: {VOTES_DIR}")
    observer = Observer()

    def on_created(event):
        handle_event(event, datastore)

    event_handler = FileSystemEventHandler()
    event_handler.on_created = on_created
    observer.schedule(event_handler, str(VOTES_DIR), recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
