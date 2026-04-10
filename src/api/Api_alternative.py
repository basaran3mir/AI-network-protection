import logging
import os
import sys
import time
import uuid
from datetime import datetime
from typing import Any, Dict, Tuple

import joblib
import pandas as pd
from dateutil import parser
from flask import Flask, jsonify, request
from flask_cors import CORS

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)

DEBUG_REQUESTS = os.getenv("DEBUG_REQUESTS", "1").lower() in {"1", "true", "yes", "on"}

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.join(current_dir, "..")
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

app = Flask(__name__)
CORS(app)

from app.detection.dtc_model_ops import DtcModelOperations
from app.classification.clf_model_ops import ClfModelOperations

dtc_model_ops = DtcModelOperations()
clf_model_ops = ClfModelOperations()

proto_encoder = joblib.load("src/outputs/encoders/shared_proto_encoder.pkl")
detection_label_encoder = joblib.load("src/outputs/encoders/dtc_label_encoder.pkl")
classification_label_encoder = joblib.load("src/outputs/encoders/clf_label_encoder.pkl")

MODEL_COLUMNS = [
    "Proto","Dur","TotBytes","SrcBytes","DstBytes","TotPkts","SrcPkts","DstPkts",
    "BytesPerSec","PktsPerSec","SrcBytesPerSec","DstBytesPerSec",
    "SrcPktsPerSec","DstPktsPerSec","MeanPktSz","SrcMeanPktSz","DstMeanPktSz",
    "SrcByteShare","DstByteShare","SrcPktShare","DstPktShare",
]

REQUIRED_REQUEST_KEYS = {"local_prefix", "data"}


@app.route("/")
def home():
    return "Aiquila API Home Page"


def debug_request_info(request_id: str, payload: Dict[str, Any] | None) -> None:
    if not DEBUG_REQUESTS:
        return

    logging.info("[%s] Request received", request_id)


def validate_request_payload(payload: Dict[str, Any]) -> Tuple[bool, str]:
    if not payload:
        return False, "Input data is missing."

    missing = REQUIRED_REQUEST_KEYS - set(payload.keys())
    if missing:
        return False, f"Missing keys: {sorted(missing)}"

    if not isinstance(payload["data"], list) or not payload["data"]:
        return False, "'data' must be a non-empty list."

    if not isinstance(payload["local_prefix"], str) or not payload["local_prefix"].strip():
        return False, "'local_prefix' must be a non-empty string."

    return True, ""


def calculate_duration(start_str: Any, end_str: Any) -> float:
    try:
        start = parser.parse(str(start_str))
        end = parser.parse(str(end_str))
        duration = (end - start).total_seconds()
        return duration if duration > 0 else 0.0
    except Exception:
        return 0.0


def safe_numeric(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except Exception:
        return default


def semantic_cleaning(raw_df: pd.DataFrame) -> pd.DataFrame:
    df = raw_df.copy()
    df = df.dropna(subset=["src_ip", "dest_ip", "proto"]).copy()
    return df.reset_index(drop=True)


def map_suricata_to_model_features(raw_df: pd.DataFrame) -> pd.DataFrame:
    df = raw_df.copy()

    df["Proto"] = df["proto"].astype(str).str.lower()
    df["Dur"] = df.apply(
        lambda row: calculate_duration(row.get("flow.start"), row.get("flow.end")), axis=1
    )

    df["SrcBytes"] = df["flow.bytes_toserver"].apply(safe_numeric)
    df["DstBytes"] = df["flow.bytes_toclient"].apply(safe_numeric)
    df["TotBytes"] = df["SrcBytes"] + df["DstBytes"]

    df["SrcPkts"] = df["flow.pkts_toserver"].apply(safe_numeric)
    df["DstPkts"] = df["flow.pkts_toclient"].apply(safe_numeric)
    df["TotPkts"] = df["SrcPkts"] + df["DstPkts"]

    df = df.fillna(0.0)

    for col in MODEL_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0

    return df[MODEL_COLUMNS]


def encode_model_inputs(feature_df: pd.DataFrame) -> pd.DataFrame:
    encoded = feature_df.copy()
    encoded["Proto"] = proto_encoder.transform(encoded["Proto"].tolist())
    return encoded


@app.route("/predict", methods=["POST"])
def predict():
    request_id = uuid.uuid4().hex[:8]
    start_time = time.time()
    payload = request.get_json(silent=True)

    debug_request_info(request_id, payload)

    is_valid, error_message = validate_request_payload(payload)
    if not is_valid:
        return jsonify({"error": error_message}), 400

    raw_input_df = pd.DataFrame(payload["data"])
    local_prefix = payload["local_prefix"].strip()

    clean_df = semantic_cleaning(raw_input_df)

    if clean_df.empty:
        return jsonify({"records": [], "duration": time.time() - start_time})

    model_feature_df = map_suricata_to_model_features(clean_df)
    inference_df = encode_model_inputs(model_feature_df)

    detection_preds = dtc_model_ops.predict(inference_df)
    detection_probs = dtc_model_ops.predict_proba(inference_df)
    detection_confs = detection_probs.max(axis=1).tolist()

    malicious_idxs = [i for i, pred in enumerate(detection_preds) if pred == 1]
    malicious_df = inference_df.iloc[malicious_idxs]

    if not malicious_df.empty:
        classification_preds = clf_model_ops.predict(malicious_df)
        classification_probs = clf_model_ops.predict_proba(malicious_df)
        classification_confs = classification_probs.max(axis=1).tolist()
    else:
        classification_preds = []
        classification_confs = []

    records = []
    cls_idx = 0

    for i, row in clean_df.iterrows():
        detection_label = detection_label_encoder.inverse_transform([int(detection_preds[i])])[0]

        classification_label = None
        classification_conf = None

        if i in malicious_idxs:
            classification_label = classification_label_encoder.inverse_transform(
                [int(classification_preds[cls_idx])]
            )[0]
            classification_conf = float(classification_confs[cls_idx])
            cls_idx += 1

        records.append(
            {
                "record_id": int(i),
                "src_ip": row["src_ip"],
                "dst_ip": row["dest_ip"],
                "detection": detection_label,
                "detection_confidence": float(detection_confs[i]),
                "classification": classification_label,
                "classification_confidence": classification_conf,
            }
        )

    return jsonify({"records": records, "duration": time.time() - start_time})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5005)