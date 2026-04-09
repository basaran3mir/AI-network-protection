import json
import requests

API_PREDICT_URL = "http://127.0.0.1:5005/predict"

# Uç cihazın artık gönderdiği format:
# - src_ip, dest_ip, proto
# - flow.start, flow.end
# - flow.bytes_toserver, flow.bytes_toclient
# - flow.pkts_toserver, flow.pkts_toclient
# - event_type = "flow"

sample_record_benign = {
    "timestamp": "2026-04-09T10:15:30.000000+03:00",
    "event_type": "flow",
    "src_ip": "10.0.0.25",
    "dest_ip": "10.0.0.40",
    "src_port": 5353,
    "dest_port": 8080,
    "proto": "tcp",
    "app_proto": "http",
    "flow.start": "2026-04-09T10:15:25.000000+03:00",
    "flow.end": "2026-04-09T10:15:30.000000+03:00",
    "flow.bytes_toserver": 12000,
    "flow.bytes_toclient": 8000,
    "flow.pkts_toserver": 20,
    "flow.pkts_toclient": 16,
    "flow.age": 5,
    "flow.state": "established",
    "flow.tcp_flags": "1b",
}

sample_record_malicious = {
    "timestamp": "2026-04-09T10:16:10.000000+03:00",
    "event_type": "flow",
    "src_ip": "10.0.0.25",
    "dest_ip": "8.8.8.8",
    "src_port": 49152,
    "dest_port": 80,
    "proto": "udp",
    "app_proto": "failed",
    "flow.start": "2026-04-09T10:16:09.500000+03:00",
    "flow.end": "2026-04-09T10:16:10.000000+03:00",
    "flow.bytes_toserver": 250000,
    "flow.bytes_toclient": 500,
    "flow.pkts_toserver": 400,
    "flow.pkts_toclient": 5,
    "flow.age": 0.5,
    "flow.state": "new",
    "flow.tcp_flags": "00",
}

def post_payload(payload: dict) -> None:
    print("\n=== REQUEST PAYLOAD ===")
    print(json.dumps(payload, indent=2, ensure_ascii=False))

    response = requests.post(API_PREDICT_URL, json=payload, timeout=15)
    response.raise_for_status()

    result = response.json()

    print("\n=== RESPONSE ===")
    print(json.dumps(result, indent=2, ensure_ascii=False))


def test_single_benign() -> None:
    payload = {
        "local_prefix": "10.0.0.",
        "data": [sample_record_benign],
    }
    print("\n########## TEST: SINGLE BENIGN ##########")
    post_payload(payload)


def test_single_malicious() -> None:
    payload = {
        "local_prefix": "10.0.0.",
        "data": [sample_record_malicious],
    }
    print("\n########## TEST: SINGLE MALICIOUS ##########")
    post_payload(payload)


def test_mixed_batch() -> None:
    payload = {
        "local_prefix": "10.0.0.",
        "data": [
            sample_record_benign,
            sample_record_malicious,
        ],
    }
    print("\n########## TEST: MIXED BATCH ##########")
    post_payload(payload)


if __name__ == "__main__":
    # İstediğin testi açık bırakabilirsin
    test_single_benign()
    test_single_malicious()
    test_mixed_batch()