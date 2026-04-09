import asyncio
import csv
import json
import logging
import os
import socket
import subprocess
import threading
import time
from typing import Any, Dict, Optional

import aiofiles
import aiohttp

from ai_rules_runner import apply_rules
from save_rules import save_changes

EVE_LOG_PATH = "/var/log/suricata/eve.json"
API_PREDICT_URL = "http://10.0.0.239:5000/predict"

OUTPUT_DIR = "api"
OUTPUT_FILE = "predictions.csv"
OUTPUT_PATH = os.path.join(OUTPUT_DIR, OUTPUT_FILE)

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Uç cihazda yalnızca gönderilecek alanlar tutuluyor.
FORWARDED_FIELDS = [
    "timestamp",
    "event_type",
    "src_ip",
    "dest_ip",
    "src_port",
    "dest_port",
    "proto",
    "app_proto",
    "flow.start",
    "flow.end",
    "flow.bytes_toserver",
    "flow.bytes_toclient",
    "flow.pkts_toserver",
    "flow.pkts_toclient",
    "flow.age",
    "flow.state",
    "flow.tcp_flags",
    "alert.signature",
    "alert.category",
    "alert.severity",
]

REQUIRED_FLOW_FIELDS = [
    "event_type",
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


def keep_sudo_alive(interval: int = 30) -> None:
    def refresh_sudo() -> None:
        while True:
            subprocess.run(["sudo", "-v"], check=False)
            time.sleep(interval)

    thread = threading.Thread(target=refresh_sudo, daemon=True)
    thread.start()


def ensure_output_csv() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if not os.path.exists(OUTPUT_PATH):
        with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["SrcIp", "DstIp", "Attack Type"])


def configure_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler("suricata_log_analysis.log"),
            logging.StreamHandler(),
        ],
    )


def get_local_ipv4_prefix(octets: int = 3) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
    finally:
        sock.close()

    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError("Expected IPv4 address.")

    return ".".join(parts[:octets]) + "."


def extract_forwarded_fields(log_record: Dict[str, Any]) -> Dict[str, Any]:
    filtered: Dict[str, Any] = {}

    for field in FORWARDED_FIELDS:
        if field.startswith("flow.") and "flow" in log_record:
            flow_key = field.split(".", 1)[1]
            if flow_key in log_record["flow"]:
                filtered[field] = log_record["flow"][flow_key]
        elif field.startswith("alert.") and "alert" in log_record:
            alert_key = field.split(".", 1)[1]
            if alert_key in log_record["alert"]:
                filtered[field] = log_record["alert"][alert_key]
        elif field in log_record:
            filtered[field] = log_record[field]

    return filtered


def is_valid_flow_record(record: Dict[str, Any]) -> bool:
    if record.get("event_type") != "flow":
        return False

    for field in REQUIRED_FLOW_FIELDS:
        if field not in record or record[field] in (None, ""):
            return False

    return True


def build_edge_payload(filtered_record: Dict[str, Any], local_prefix: str) -> Dict[str, Any]:
    return {
        "local_prefix": local_prefix,
        "data": [filtered_record],
    }


async def send_post_request(
    session: aiohttp.ClientSession,
    url: str,
    payload: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    try:
        async with session.post(url, json=payload) as response:
            logging.info("POST gönderildi: %s - Status: %s", url, response.status)

            if response.status == 200:
                result = await response.json()
                logging.info("API yanıtı alındı.")
                return result

            error_text = await response.text()
            logging.error("API hata yanıtı (status %s): %s", response.status, error_text)
            return None

    except Exception as exc:
        logging.error("POST isteği sırasında hata oluştu: %s", exc)
        return None


def process_api_result(result: Dict[str, Any], local_prefix: str) -> None:
    for rec in result.get("records", []):
        src = rec.get("src_ip", "")
        dst = rec.get("dst_ip", "")
        attack = rec.get("classification") or rec.get("detection", "")

        if attack and attack != "Benign":
            external_ip = ""
            if src.startswith(local_prefix):
                external_ip = dst
            elif dst.startswith(local_prefix):
                external_ip = src

            with open(OUTPUT_PATH, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([src, dst, attack])

            if external_ip:
                apply_rules(external_ip, attack)
                save_changes()
                logging.info(
                    "Savunma kuralı uygulandı: dış IP=%s, saldırı=%s",
                    external_ip,
                    attack,
                )


async def follow_eve_json(file_path: str) -> None:
    local_prefix = get_local_ipv4_prefix()

    timeout = aiohttp.ClientTimeout(total=10)
    connector = aiohttp.TCPConnector(limit=20)

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        async with aiofiles.open(file_path, "r") as f:
            await f.seek(0, os.SEEK_END)

            while True:
                line = await f.readline()
                if not line:
                    await asyncio.sleep(0.2)
                    continue

                try:
                    log_record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                filtered_record = extract_forwarded_fields(log_record)

                if not is_valid_flow_record(filtered_record):
                    continue

                payload = build_edge_payload(filtered_record, local_prefix)
                api_result = await send_post_request(session, API_PREDICT_URL, payload)

                if api_result and "records" in api_result:
                    await asyncio.to_thread(process_api_result, api_result, local_prefix)


if __name__ == "__main__":
    keep_sudo_alive()
    ensure_output_csv()
    configure_logging()

    logging.info("Real-time Suricata log monitoring is starting...")
    asyncio.run(follow_eve_json(EVE_LOG_PATH))