import os
import time
from datetime import datetime
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    multilabel_confusion_matrix,
)
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder

class ClfModelOperations:
    def __init__(self):
        self.dataset_path = os.path.join('src', 'outputs', 'datasets', 'classification', 'combined_output.csv')
        self.base_dir = os.path.join('src', 'outputs', 'models', 'classification')

        self.timestamp = datetime.now().strftime('%d%m-%H%M')
        self.ts_dir = os.path.join(self.base_dir, self.timestamp)
        self.latest_dir = os.path.join(self.base_dir, 'latest')

        self.proto_encoder = joblib.load("src\outputs\encoders\shared_proto_encoder.pkl")
        self.label_encoder = LabelEncoder()
        self.label_encoder_path = os.path.join('src', 'outputs', 'encoders', 'clf_label_encoder.pkl')
        self.encoders_map_path = os.path.join('src', 'outputs', 'encoders', 'encoders_map.txt')

        self.model_file = os.path.join(self.latest_dir, 'model.pkl')
        self.report_file = os.path.join(self.latest_dir, 'model_evaluation.txt')
        self.model = self.load_model()

    def train_model(self):
        print("Classification model training is starting.")
        df = pd.read_csv(self.dataset_path, encoding='utf-8')

        # --- Proto ENCODING (only transform) ---
        df['Proto'] = self.proto_encoder.transform(df['Proto'])

        # --- Label ENCODING ---
        y = self.label_encoder.fit_transform(df['Attack Type'])

        X = df.drop('Attack Type', axis=1)

        x_train, x_test, y_train, y_test = train_test_split(
            X, y, test_size=0.23, random_state=42, stratify=y
        )

        model = XGBClassifier(n_estimators=100, random_state=42)
        start = time.time()
        model.fit(x_train, y_train)
        train_time = time.time() - start

        y_pred = model.predict(x_test)

        labels = sorted(np.unique(y_test))
        cm = confusion_matrix(y_test, y_pred, labels=labels)
        cm_df = pd.DataFrame(cm, index=labels, columns=labels)

        class_report = classification_report(
            y_test, y_pred, labels=labels, zero_division=0
        )

        mcm = multilabel_confusion_matrix(y_test, y_pred, labels=labels)
        mcm_str = ""
        for idx, cls in enumerate(labels):
            tn, fp, fn, tp = mcm[idx].ravel()
            mcm_str += (f"Class={cls}: TP={tp}, FP={fp}, FN={fn}, TN={tn}\n")

        metrics = self.compute_metrics(y_test, y_pred, train_time)

        self.save_results(model, metrics, cm_df, class_report, mcm_str)

        print("Classification model training is done.")
        return model

    def compute_metrics(self, y_true, y_pred, train_time):
        return {
            'train_time': train_time,
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, average='weighted', zero_division=0),
            'recall': recall_score(y_true, y_pred, average='weighted', zero_division=0),
            'f1_score': f1_score(y_true, y_pred, average='weighted', zero_division=0)
        }

    def save_results(self, model, m, cm_df, class_report, mcm_str):
        self.timestamp = datetime.now().strftime('%d%m-%H%M')
        self.ts_dir = os.path.join(self.base_dir, self.timestamp)
        os.makedirs(self.ts_dir, exist_ok=True)
        os.makedirs(self.latest_dir, exist_ok=True)

        test_count = int(cm_df.values.sum())
        per_class_counts = {label: int(cm_df.loc[label].sum()) for label in cm_df.index}
        per_class_str = "\n".join([f"{lbl}: {cnt}" for lbl, cnt in per_class_counts.items()])

        cm_str = cm_df.to_string()

        proto_map = ", ".join([f"{i}:{cls}" for i, cls in enumerate(self.proto_encoder.classes_)])
        label_map = ", ".join([f"{i}:{cls}" for i, cls in enumerate(self.label_encoder.classes_)])
        
        report = (
            "Model Evaluation Results\n"
            "============================\n"
            f"Timestamp: {self.timestamp}\n"

            f"Proto Encoding Map: {proto_map}\n"
            f"Label Encoding Map: {label_map}\n\n"

            f"Training Time: {m['train_time']:.4f} seconds\n\n"

            f"Number of Test Samples: {test_count}\n"
            f"Number of Each Type Test Samples: \n{per_class_str}\n\n"

            f"Accuracy: {m['accuracy']*100:.2f}%\n"
            f"Precision: {m['precision']*100:.2f}%\n"
            f"Recall: {m['recall']*100:.2f}%\n"
            f"F1 Score: {m['f1_score']*100:.2f}%\n\n"
            "Confusion Matrix (rows=true, cols=predicted):\n"
            f"{cm_str}\n\n"
            "Per-class 2x2 matrices (TP/FP/FN/TN):\n"
            f"{mcm_str}\n"
            "Classification Report:\n"
            f"{class_report}\n"
        )

        for path in [self.report_file, os.path.join(self.ts_dir, 'model_evaluation.txt')]:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(report)
        for path in [self.model_file, os.path.join(self.ts_dir, 'model.pkl')]:
            joblib.dump(model, path)
        for path in [self.label_encoder_path]:
            joblib.dump(self.label_encoder, path)
        with open(self.encoders_map_path, 'a', encoding='utf-8') as f:
                f.write(f"Classification Model Label Encoding Map: {label_map}")

        print(f"Encoders map saved:\n- {self.encoders_map_path}")
        print(f"Model and model report saved:\n- {self.latest_dir}\n- {self.ts_dir}")

    def load_model(self):
        if os.path.exists(self.model_file):
            print(f"Classification model loaded: {self.model_file}")
            return joblib.load(self.model_file)
        else:
            print("Classification model not found.")
            return self.train_model()

    def predict(self, X):
        return self.model.predict(X)

    def predict_proba(self, X):
        return self.model.predict_proba(X)