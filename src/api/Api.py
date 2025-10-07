import time
import joblib
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import sys
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
from pathlib import Path
import logging
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO
)

def retrain_models():
    try:
        print("04:00:00 - Modeller yeniden eğitiliyor…")
        merge_with_previous_day()

        today = datetime.now()
        base_dir    = Path("api/auto-update-res")
        today_dir   = base_dir / today.strftime("%d%m")
        fn       = "merged_with_previous_day.csv"

        processor = detection_model_processor
        processor.dataset_path = today_dir / fn
        processor.train_model()
        processor.model = processor.load_model()
        print("Modeller güncellendi ve yüklendi.")

    except Exception as e:
        print(f"Modeller güncellenirken hata: {e}")

scheduler = BackgroundScheduler()
scheduler.add_job(retrain_models, 'cron', hour=4, minute=0, second=0)
scheduler.start()

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.join(current_dir, '..')
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

app = Flask(__name__)
CORS(app)

from app.detection.D_ModelProcessor import D_ModelProcessor as DetectionModel
from app.classification.C_ModelProcessor import C_ModelProcessor as ClassificationModel

detection_model_processor = DetectionModel()
classification_model_processor = ClassificationModel()
proto_encoder = joblib.load("src/outputs/encoders/dc_proto_encoder.pkl")
detection_label_encoder = joblib.load("src/outputs/encoders/d_label_encoder.pkl")
classification_label_encoder = joblib.load("src/outputs/encoders/c_label_encoder.pkl")

@app.route('/')
def home():
    return "Aiquila API Home Page"

@app.route('/predict', methods=['POST'])
def predict():
    start_time = time.time()
    data = request.json

    if not data or "data" not in data:
        return jsonify({"error": "Input data is missing."}), 400

    try:
        input_data = pd.DataFrame(data["data"])
        print(input_data)
        if data.get("special_code") != 4141:
            append_data(input_data, "will_append_raw.csv")
    except Exception as e:
        return jsonify({"error": f"Data transform error: {str(e)}"}), 400

    input_formatted_data = input_data.drop(columns=["SrcIp","DstIp"])
    print(input_formatted_data)

    if data.get("special_code") != 4141:
        append_data(input_formatted_data, "will_append_raw_formatted.csv")

    input_formatted_data["Proto"] = int(proto_encoder.transform([input_formatted_data["Proto"]])[0])

    # Threat Detection
    detection_preds = detection_model_processor.predict(input_formatted_data)
    detection_probs = detection_model_processor.predict_proba(input_formatted_data)
    detection_confs = detection_probs.max(axis=1).tolist()

    input_formatted_data["Label"]       = detection_preds
    input_formatted_data["Label_Score"] = detection_confs

    if data.get("special_code") != 4141:
        append_data(input_formatted_data, "will_append_raw_formatted_result.csv")

    perfect_df = input_formatted_data[input_formatted_data["Label_Score"] > 0.975]
    if not perfect_df.empty:
        to_save = perfect_df.drop(columns=["Label_Score"])
        append_data(to_save, "will_append_raw_formatted_result_perfect_scores.csv")

    # Threat Classification (only for Malicious records)
    columns_to_drop = ["Label", "Label_Score"]
    clean_data = input_formatted_data.drop(columns=[c for c in columns_to_drop if c in input_formatted_data.columns])
    malicious_idxs = [i for i,p in enumerate(detection_preds) if p==1] #1 is malicious (one-hat encoding)
    malicious_data = clean_data.iloc[malicious_idxs]

    if not malicious_data.empty:
        classification_preds = classification_model_processor.predict(malicious_data)
        classification_probs = classification_model_processor.predict_proba(malicious_data)
        classification_confs = classification_probs.max(axis=1).tolist()
    else:
        classification_preds, classification_probs, classification_confs = [], [], []

    records, cls_idx = [], 0
    for i, row in input_data.iterrows():
        detection_label = detection_label_encoder.inverse_transform([int(detection_preds[i])])[0]

        is_malicious = i in malicious_idxs
        classification_label = (classification_label_encoder.inverse_transform([int(classification_preds[cls_idx])])[0]
                                if is_malicious else None)
        classification_conf = float(classification_confs[cls_idx]) if is_malicious else None
        classification_risk = "not_calculated" if is_malicious else None

        if is_malicious:
            cls_idx += 1

        records.append({
            "record_id": i,
            "src_ip": row["SrcIp"],
            "dst_ip": row["DstIp"],
            "detection": detection_label,
            "detection_confidence": float(detection_confs[i]),
            "classification": classification_label,
            "classification_confidence": classification_conf,
            "classification_risk": classification_risk
        })

    duration = time.time() - start_time
    return jsonify({"records": records, "duration": duration})

def append_data(data, file_name):
    try:
        date_str = datetime.now().strftime("%d%m")
        output_dir = f"src/api/auto-update-res/{date_str}"
        os.makedirs(output_dir, exist_ok=True)
        csv_path = os.path.join(output_dir, file_name)

        file_exists = os.path.isfile(csv_path)
        data.to_csv(
            csv_path,
            mode='a',
            header=not file_exists,
            index=False,
            encoding='utf-8'
        )
    except Exception as e:
        print(f"Data append error ({csv_path}): {e}")

def merge_with_previous_day():
    try:
        today = datetime.now()
        yesterday = today - timedelta(days=1)

        base_dir       = Path("api/auto-update-res")
        today_dir      = base_dir / today.strftime("%d%m")
        yesterday_dir  = base_dir / yesterday.strftime("%d%m")

        fn          = "will_append_raw_formatted_result_perfect_scores.csv"
        today_fp    = today_dir / fn
        yest_fp     = yesterday_dir / fn
        out_fp      = today_dir / "merged_with_previous_day.csv"

        today_dir.mkdir(parents=True, exist_ok=True)

        if today_fp.is_file():
            if yest_fp.is_file():
                df_yest  = pd.read_csv(yest_fp)
            else:
                logging.warning(
                    f"merge_with_previous_day: Yesterday's file is missing. "
                    "It will be merged with base dataset."
                )
                df_yest = pd.read_csv("api/auto-update-res/Combined_last.csv")

            df_today = pd.read_csv(today_fp)

            merged = pd.concat([df_yest, df_today], ignore_index=True)
            merged = merged.sample(frac=1, random_state=42).reset_index(drop=True)

            merged.to_csv(out_fp, index=False, encoding="utf-8")
            logging.info(f"merge_with_previous_day: Başarılı → {out_fp}")

        else:
            logging.warning(
                f"merge_with_previous_day: Today's file is missing."
                f"Is today's file exist? {today_fp.exists()}, Is yesterday's file exist? {yest_fp.exists()}"
            )

    except Exception as e:
        logging.error(f"merge_with_previous_day: Unexpected error → {e}", exc_info=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)