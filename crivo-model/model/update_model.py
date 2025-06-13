import logging
import sys
from pathlib import Path

import dojolib
import numpy as np
import pandas as pd
import requests
from datastore import DataStore
from settings import (
    AUTHORIZATION,
    CLASS_LABELS,
    CVE2META_PICKLE_FP,
    FEATURES_FILE,
    LEARNING_RATE,
    MAX_DEPTH,
    NUM_ESTIMATORS,
    PREDICT_DIR,
    TARGET_COLUMN,
    URL_API,
)
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBRegressor

logger = logging.getLogger(__name__)

VOTES_FILE = Path(sys.argv[1])


def load_combined_data(datastore: DataStore) -> pd.DataFrame:
    class_features, class_rankings = dojolib.load_features_rankings(FEATURES_FILE, VOTES_FILE, datastore)
    return dojolib.get_merged_df(class_features, class_rankings)


def prepare_training_data(training_df: pd.DataFrame) -> pd.DataFrame:
    training_df = training_df[training_df[TARGET_COLUMN].notna()].copy()

    if "vote_class" in training_df.columns:
        training_df = training_df[training_df["vote_class"] != "NA"]
    if "vote_num" in training_df.columns:
        training_df = training_df[training_df["vote_num"] != "NV"]

    training_df["in_kev"] = training_df["in_kev"].astype(int)
    training_df["has_dns_keyword"] = training_df["has_dns_keyword"].astype(int)

    for col in ["severity", "os", "mitigation"]:
        training_df[col] = LabelEncoder().fit_transform(training_df[col].astype(str))

    return training_df


def prepare_prediction_data(pred_df: pd.DataFrame) -> pd.DataFrame:
    pred_df = pred_df[pred_df[TARGET_COLUMN].isna()].copy()
    pred_df = pred_df.set_index("fid", drop=False)
    pred_df["in_kev"] = pred_df["in_kev"].astype(int)
    pred_df["has_dns_keyword"] = pred_df["has_dns_keyword"].astype(int)

    for col in ["severity", "os", "mitigation"]:
        pred_df[col] = LabelEncoder().fit_transform(pred_df[col].astype(str))

    return pred_df


def train_model(X: pd.DataFrame, y: pd.Series) -> XGBRegressor:
    model = XGBRegressor(
        n_estimators=NUM_ESTIMATORS,
        learning_rate=LEARNING_RATE,
        max_depth=MAX_DEPTH,
        verbosity=0,
        enable_categorical=True,
    )
    model.fit(X, y)
    return model


def predict(df: pd.DataFrame, model: XGBRegressor, feature_columns: list[str]) -> pd.DataFrame:
    df["predicted_raw_score"] = model.predict(df[feature_columns])
    df["predicted_vote_class"] = np.round(df["predicted_raw_score"])
    df["predicted_vote_label"] = df["predicted_vote_class"].map(CLASS_LABELS)
    return df


def rename_file_if_exists(source: Path, target: Path):
    try:
        source.rename(target)
        logger.info(f"Renamed file from {source} to {target}")
    except OSError as e:
        logger.warning(f"Could not rename file: {e}")


def export_predictions_to_json(predictions_df: pd.DataFrame, output_path: Path) -> None:
    df_to_export = predictions_df[["user_id", "predicted_vote_label", "predicted_vote_class"]].copy()
    df_to_export["id"] = predictions_df.index
    df_to_export = df_to_export[["id", "user_id", "predicted_vote_label", "predicted_vote_class"]]

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


def main():
    logger.info("Starting inferences prediction pipeline...")
    datastore = DataStore()
    datastore.load(metadata_fp=CVE2META_PICKLE_FP)
    class_df = load_combined_data(datastore)
    unique_users = class_df["user_id"].dropna().unique()
    if len(unique_users) != 1:
        error_msg = f"Expected a single user_id, but found: {unique_users}"
        raise ValueError(error_msg)
    user_id = int(unique_users[0])
    class_df = class_df.drop(columns=["user_id"])
    training_df = prepare_training_data(class_df)
    columns_to_exclude = ["id", "fid", "ranking", "vote_class", "vote_num"]
    feature_columns = [col for col in training_df.columns if col not in columns_to_exclude]
    model = train_model(training_df[feature_columns], training_df[TARGET_COLUMN])
    prediction_df = prepare_prediction_data(class_df)
    prediction_result = predict(prediction_df, model, feature_columns)
    logger.info("Prediction completed.")
    prediction_result["user_id"] = user_id
    predict_file = PREDICT_DIR / f"user2data_{user_id}.json"
    export_predictions_to_json(prediction_result, predict_file)
    request_create_inferences(predict_file)


if __name__ == "__main__":
    main()
