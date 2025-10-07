import joblib
import requests

API_PREDICT_URL = "http://10.0.0.239:5000/predict"

sample_record1 = { #benign
    "SrcIp":      "0.0.0.0",
    "DstIp":      "0.0.0.0",
    "TotBytes":   249093,
    "SrcBytes":   244212,
    "DstBytes":   4881,
    "TotPkts":    214,
    "SrcPkts":    196,
    "DstPkts":    18,
    "Rate":       42.616875,
    "SrcRate":    39.01545,
    "DstRate":    3.401347,
    "Dur":        4.99802,
    "RunTime":    4.99802,
    "TcpRtt":     0.034051,
    "SynAck":     0.001364,
    "AckDat":     0.032687,
    "Seq":        3,
    "Proto":       "udp",
}

sample_record2 = { #malicious
    "SrcIp":      "0.0.0.0",
    "DstIp":      "0.0.0.0",
    "TotBytes":   4529,
    "SrcBytes":   714,
    "DstBytes":   3815,
    "TotPkts":    10,
    "SrcPkts":    5,
    "DstPkts":    5,
    "Rate":       143.195816,
    "SrcRate":    63.642586,
    "DstRate":    63.642586,
    "Dur":        0.062851,
    "RunTime":    0.062851,
    "TcpRtt":     0.03802,
    "SynAck":     0.014252,
    "AckDat":     0.023768,
    "Seq":        844,
    "Proto":       "tcp",
}


payload = {
    "data": [ sample_record2 ]
}

resp = requests.post(API_PREDICT_URL, json=payload)
resp.raise_for_status()
result = resp.json()
print(result)