import joblib
import requests

API_PREDICT_URL = "http://10.0.0.239:5000/predict"

sample_record = {
    "SrcIp":      "0.0.0.0",
    "DstIp":      "0.0.0.0",
    "TotBytes":   66,
    "SrcBytes":   66,
    "DstBytes":   0,
    "TotPkts":    1,
    "SrcPkts":    1,
    "DstPkts":    0,
    "Rate":       0.0,
    "SrcRate":    0.0,
    "DstRate":    0.0,
    "Dur":        0.0,
    "RunTime":    0.0,
    "TcpRtt":     0.034051,
    "SynAck":     0.001364,
    "AckDat":     0.032687,
    "Seq":        25012,
    "Proto":       "udp",
}

proto_encoder = joblib.load("outputs/encoders/dc_proto_encoder.pkl")
sample_record["Proto"] = int(proto_encoder.transform([sample_record["Proto"]])[0])
print(sample_record)

payload = {
    "data": [ sample_record ]
}

resp = requests.post(API_PREDICT_URL, json=payload)
resp.raise_for_status()
result = resp.json()
print(result)