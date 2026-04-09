import logging
import os
import sys
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Tuple

import joblib
import pandas as pd
from apscheduler.schedulers.background import BackgroundScheduler
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
    "Proto",
    "Dur",
    "TotBytes",
    "SrcBytes",
    "DstBytes",
    "TotPkts",
    "SrcPkts",
    "DstPkts",
    "BytesPerSec",
    "PktsPerSec",
    "SrcBytesPerSec",
    "DstBytesPerSec",
    "SrcPktsPerSec",
    "DstPktsPerSec",
    "MeanPktSz",
    "SrcMeanPktSz",
    "DstMeanPktSz",
    "SrcByteShare",
    "DstByteShare",
    "SrcPktShare",
    "DstPktShare",
]

REQUIRED_REQUEST_KEYS = {"local_prefix", "data"}


@app.route("/")
def home():
    return "Aiquila API Home Page"


def retrain_models():
    try:
        merge_with_previous_day()

        today = datetime.now()
        base_dir = Path("src/api/auto-update-res")
        today_dir = base_dir / today.strftime("%d%m")
        merged_file = "merged_with_previous_day.csv"

        logging.info("Model re-train is starting.")
        dtc_model_ops.dataset_path = today_dir / merged_file
        dtc_model_ops.train_model()
        dtc_model_ops.model = dtc_model_ops.load_model()
        logging.info("Models updated and loaded.")

    except Exception as exc:
        logging.error("Error while models updating: %s", exc, exc_info=True)


scheduler = BackgroundScheduler()
scheduler.add_job(retrain_models, "cron", hour=4, minute=0, second=10)
scheduler.start()


def debug_request_info(request_id: str, payload: Dict[str, Any] | None) -> None:
    if not DEBUG_REQUESTS:
        return

    interesting_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() in {
            "host",
            "content-type",
            "content-length",
            "user-agent",
            "x-forwarded-for",
            "x-real-ip",
        }
    }

    logging.info(
        "[%s] Request debug -> remote_addr=%s access_route=%s method=%s path=%s headers=%s",
        request_id,
        request.remote_addr,
        list(request.access_route),
        request.method,
        request.path,
        interesting_headers,
    )

    if not payload:
        logging.info("[%s] Payload is empty or invalid JSON.", request_id)
        return

    payload_keys = list(payload.keys())
    data_list = payload.get("data", [])
    first_record = data_list[0] if isinstance(data_list, list) and data_list else {}

    first_record_summary = {
        "event_type": first_record.get("event_type"),
        "src_ip": first_record.get("src_ip"),
        "dest_ip": first_record.get("dest_ip"),
        "proto": first_record.get("proto"),
        "flow.start": first_record.get("flow.start"),
        "flow.end": first_record.get("flow.end"),
        "flow.bytes_toserver": first_record.get("flow.bytes_toserver"),
        "flow.bytes_toclient": first_record.get("flow.bytes_toclient"),
        "flow.pkts_toserver": first_record.get("flow.pkts_toserver"),
        "flow.pkts_toclient": first_record.get("flow.pkts_toclient"),
    }

    logging.info(
        "[%s] Payload debug -> keys=%s local_prefix=%s record_count=%s first_record=%s",
        request_id,
        payload_keys,
        payload.get("local_prefix"),
        len(data_list) if isinstance(data_list, list) else "invalid",
        first_record_summary,
    )


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
    required_cols = [
        "src_ip",
        "dest_ip",
        "proto",
        "flow.start",
        "flow.end",
        "flow.bytes_toserver",
        "flow.bytes_toclient",
        "flow.pkts_toserver",
        "flow.pkts_toclient",
    ]

    df = raw_df.copy()

    for col in required_cols:
        if col not in df.columns:
            df[col] = None

    df = df.dropna(subset=["src_ip", "dest_ip", "proto"]).copy()
    df = df[df["src_ip"].astype(str) != ""]
    df = df[df["dest_ip"].astype(str) != ""]
    df = df[df["proto"].astype(str) != ""]
    return df.reset_index(drop=True)


def map_suricata_to_model_features(raw_df: pd.DataFrame) -> pd.DataFrame:
    df = raw_df.copy()

    df["Proto"] = df["proto"].astype(str).str.lower()

    df["Dur"] = df.apply(
        lambda row: calculate_duration(row.get("flow.start"), row.get("flow.end")),
        axis=1,
    )

    df["SrcBytes"] = df["flow.bytes_toserver"].apply(safe_numeric)
    df["DstBytes"] = df["flow.bytes_toclient"].apply(safe_numeric)
    df["TotBytes"] = df["SrcBytes"] + df["DstBytes"]

    df["SrcPkts"] = df["flow.pkts_toserver"].apply(safe_numeric)
    df["DstPkts"] = df["flow.pkts_toclient"].apply(safe_numeric)
    df["TotPkts"] = df["SrcPkts"] + df["DstPkts"]

    df["BytesPerSec"] = df.apply(
        lambda row: row["TotBytes"] / row["Dur"] if row["Dur"] > 0 else 0.0,
        axis=1,
    )
    df["PktsPerSec"] = df.apply(
        lambda row: row["TotPkts"] / row["Dur"] if row["Dur"] > 0 else 0.0,
        axis=1,
    )
    df["SrcBytesPerSec"] = df.apply(
        lambda row: row["SrcBytes"] / row["Dur"] if row["Dur"] > 0 else 0.0,
        axis=1,
    )
    df["DstBytesPerSec"] = df.apply(
        lambda row: row["DstBytes"] / row["Dur"] if row["Dur"] > 0 else 0.0,
        axis=1,
    )
    df["SrcPktsPerSec"] = df.apply(
        lambda row: row["SrcPkts"] / row["Dur"] if row["Dur"] > 0 else 0.0,
        axis=1,
    )
    df["DstPktsPerSec"] = df.apply(
        lambda row: row["DstPkts"] / row["Dur"] if row["Dur"] > 0 else 0.0,
        axis=1,
    )
    df["MeanPktSz"] = df.apply(
        lambda row: row["TotBytes"] / row["TotPkts"] if row["TotPkts"] > 0 else 0.0,
        axis=1,
    )
    df["SrcMeanPktSz"] = df.apply(
        lambda row: row["SrcBytes"] / row["SrcPkts"] if row["SrcPkts"] > 0 else 0.0,
        axis=1,
    )
    df["DstMeanPktSz"] = df.apply(
        lambda row: row["DstBytes"] / row["DstPkts"] if row["DstPkts"] > 0 else 0.0,
        axis=1,
    )
    df["SrcByteShare"] = df.apply(
        lambda row: row["SrcBytes"] / row["TotBytes"] if row["TotBytes"] > 0 else 0.0,
        axis=1,
    )
    df["DstByteShare"] = df.apply(
        lambda row: row["DstBytes"] / row["TotBytes"] if row["TotBytes"] > 0 else 0.0,
        axis=1,
    )
    df["SrcPktShare"] = df.apply(
        lambda row: row["SrcPkts"] / row["TotPkts"] if row["TotPkts"] > 0 else 0.0,
        axis=1,
    )
    df["DstPktShare"] = df.apply(
        lambda row: row["DstPkts"] / row["TotPkts"] if row["TotPkts"] > 0 else 0.0,
        axis=1,
    )

    for col in MODEL_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0

    return df[MODEL_COLUMNS].fillna(0.0)


def encode_model_inputs(feature_df: pd.DataFrame) -> pd.DataFrame:
    encoded = feature_df.copy()
    encoded["Proto"] = proto_encoder.transform(encoded["Proto"].tolist())
    return encoded


def append_data(data: pd.DataFrame, file_name: str) -> None:
    try:
        date_str = datetime.now().strftime("%d%m")
        output_dir = f"src/api/auto-update-res/{date_str}"
        os.makedirs(output_dir, exist_ok=True)
        csv_path = os.path.join(output_dir, file_name)

        file_exists = os.path.isfile(csv_path)
        data.to_csv(
            csv_path,
            mode="a",
            header=not file_exists,
            index=False,
            encoding="utf-8",
        )
    except Exception as exc:
        logging.error("Data append error (%s): %s", file_name, exc)


def merge_with_previous_day():
    try:
        today = datetime.now()
        yesterday = today - timedelta(days=1)

        base_dir = Path("src/api/auto-update-res")
        today_dir = base_dir / today.strftime("%d%m")
        yesterday_dir = base_dir / yesterday.strftime("%d%m")

        fn = "will_append_processed.csv"
        today_fp = today_dir / fn
        yest_fp = yesterday_dir / fn
        out_fp = today_dir / "merged_with_previous_day.csv"

        today_dir.mkdir(parents=True, exist_ok=True)

        if today_fp.is_file():
            if yest_fp.is_file():
                df_yest = pd.read_csv(yest_fp)
            else:
                logging.warning(
                    "Yesterday's file is missing. Base dataset will be used instead."
                )
                df_yest = pd.read_csv("src/outputs/datasets/detection/combined_output.csv")

            df_today = pd.read_csv(today_fp)

            merged = pd.concat([df_yest, df_today], ignore_index=True)
            merged = merged.sample(frac=1, random_state=42).reset_index(drop=True)
            merged.to_csv(out_fp, index=False, encoding="utf-8")

            logging.info("merge_with_previous_day başarılı -> %s", out_fp)
        else:
            logging.warning("Today's processed file is missing: %s", today_fp)

    except Exception as exc:
        logging.error("merge_with_previous_day unexpected error -> %s", exc, exc_info=True)


@app.route("/predict", methods=["POST"])
def predict():
    request_id = uuid.uuid4().hex[:8]
    start_time = time.time()
    payload = request.get_json(silent=True)

    debug_request_info(request_id, payload)

    is_valid, error_message = validate_request_payload(payload)
    if not is_valid:
        logging.warning("[%s] Invalid payload: %s", request_id, error_message)
        return jsonify({"error": error_message}), 400

    try:
        raw_input_df = pd.DataFrame(payload["data"])
        local_prefix = payload["local_prefix"].strip()
        append_data(raw_input_df, "will_append_raw.csv")

        logging.info(
            "[%s] Raw dataframe created -> shape=%s columns=%s",
            request_id,
            raw_input_df.shape,
            list(raw_input_df.columns),
        )
    except Exception as exc:
        logging.error("[%s] Data transform error: %s", request_id, exc, exc_info=True)
        return jsonify({"error": f"Data transform error: {exc}"}), 400

    clean_df = semantic_cleaning(raw_input_df)
    logging.info(
        "[%s] After semantic_cleaning -> shape=%s",
        request_id,
        clean_df.shape,
    )

    if clean_df.empty:
        logging.info("[%s] clean_df is empty. Returning empty records.", request_id)
        return jsonify({"records": [], "duration": time.time() - start_time})

    all_local = clean_df.apply(
        lambda row: str(row["src_ip"]).startswith(local_prefix)
        and str(row["dest_ip"]).startswith(local_prefix),
        axis=1,
    )

    if all(all_local):
        logging.info("[%s] All records are local-local. Returning Benign.", request_id)

        records = []
        for i, row in clean_df.iterrows():
            records.append(
                {
                    "record_id": int(i),
                    "src_ip": row["src_ip"],
                    "dst_ip": row["dest_ip"],
                    "detection": "Benign",
                    "detection_confidence": 1.0,
                    "classification": None,
                    "classification_confidence": None,
                    "classification_risk": None,
                }
            )

        return jsonify({"records": records, "duration": time.time() - start_time})

    try:
        model_feature_df = map_suricata_to_model_features(clean_df)
        logging.info(
            "[%s] Feature dataframe -> shape=%s columns=%s",
            request_id,
            model_feature_df.shape,
            list(model_feature_df.columns),
        )

        inference_df = encode_model_inputs(model_feature_df)
        logging.info(
            "[%s] Encoded inference dataframe -> shape=%s",
            request_id,
            inference_df.shape,
        )
    except Exception as exc:
        logging.error("[%s] Feature preparation error: %s", request_id, exc, exc_info=True)
        return jsonify({"error": f"Feature preparation error: {exc}"}), 500

    detection_preds = dtc_model_ops.predict(inference_df)
    detection_probs = dtc_model_ops.predict_proba(inference_df)
    detection_confs = detection_probs.max(axis=1).tolist()

    malicious_count = sum(1 for p in detection_preds if p == 1)
    logging.info(
        "[%s] Detection completed -> total=%s malicious=%s benign=%s",
        request_id,
        len(detection_preds),
        malicious_count,
        len(detection_preds) - malicious_count,
    )

    processed_for_feedback = inference_df.copy()
    processed_for_feedback["Label"] = detection_preds
    processed_for_feedback["Label_Score"] = detection_confs

    perfect_df = processed_for_feedback[processed_for_feedback["Label_Score"] > 0.975]
    if not perfect_df.empty:
        to_save = perfect_df.drop(columns=["Label_Score"]).copy()
        to_save["Proto"] = proto_encoder.inverse_transform(to_save["Proto"].astype(int))
        to_save["Label"] = detection_label_encoder.inverse_transform(
            to_save["Label"].astype(int)
        )
        append_data(to_save, "will_append_processed.csv")
        logging.info("[%s] Saved high-confidence rows -> count=%s", request_id, len(to_save))

    clean_for_clf = processed_for_feedback.drop(columns=["Label", "Label_Score"])
    malicious_idxs = [i for i, pred in enumerate(detection_preds) if pred == 1]
    malicious_df = clean_for_clf.iloc[malicious_idxs]

    if not malicious_df.empty:
        classification_preds = clf_model_ops.predict(malicious_df)
        classification_probs = clf_model_ops.predict_proba(malicious_df)
        classification_confs = classification_probs.max(axis=1).tolist()
        logging.info(
            "[%s] Classification completed -> malicious_samples=%s",
            request_id,
            len(classification_preds),
        )
    else:
        classification_preds = []
        classification_confs = []
        logging.info("[%s] No malicious sample for classification.", request_id)

    records = []
    cls_idx = 0

    for i, row in clean_df.iterrows():
        detection_label = detection_label_encoder.inverse_transform([int(detection_preds[i])])[0]
        is_malicious = i in malicious_idxs

        classification_label = None
        classification_conf = None
        classification_risk = None

        if is_malicious:
            classification_label = classification_label_encoder.inverse_transform(
                [int(classification_preds[cls_idx])]
            )[0]
            classification_conf = float(classification_confs[cls_idx])
            classification_risk = "not_calculated"
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
                "classification_risk": classification_risk,
            }
        )

    duration = time.time() - start_time
    logging.info("[%s] Request completed in %.4f sec", request_id, duration)

    return jsonify({"records": records, "duration": duration})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5005)