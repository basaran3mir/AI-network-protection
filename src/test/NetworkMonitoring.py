import json
import os
import socket
import pandas as pd
import numpy as np
from dateutil import parser
import aiohttp
import asyncio
import logging
from pathlib import Path
import aiofiles
import csv
from ai_rules_runner import apply_rules
from save_rules import save_changes

import subprocess
import threading
import time

def keep_sudo_alive(interval=30):
    def refresh_sudo():
        while True:
            subprocess.run(['sudo', '-v'])
            time.sleep(interval)
    thread = threading.Thread(target=refresh_sudo, daemon=True)
    thread.start()

# Ana kodun başında çağır
keep_sudo_alive()

# Dosya yolları
eve_log_path = "/var/log/suricata/eve.json"

# API URL'leri
API_PREDICT_URL = "http://10.0.0.239:5000/predict"

# CSV için çıktı dosyası ayarları (API test kodundaki gibi)
output_dir  = "api"
output_file = "predictions.csv"
output_path = os.path.join(output_dir, output_file)

# CSV dosyasını oluştur (başlıkları yaz) eğer yoksa
os.makedirs(output_dir, exist_ok=True)
if not os.path.exists(output_path):
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["SrcIp", "DstIp", "Attack Type"])

# Loglama yapılandırması
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level),
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("suricata_log_analiz.log"),
        logging.StreamHandler()
    ]
)

# İşlenecek alanlar, protokol tipleri ve son çıktı sütunları
parameters = [
    "timestamp", "event_type", "src_ip", "dest_ip", "src_port", "dest_port", "proto", "app_proto",
    "flow.start", "flow.end", "flow.bytes_toserver", "flow.bytes_toclient", "flow.bytes",
    "flow.bytes_tosrc", "flow.bytes_todst", "flow.pkts", "flow.pkts_tosrc", "flow.pkts_todst",
    "flow.pkts_toserver", "flow.pkts_toclient", "flow.age", "flow.state", "flow.tcp_flags",
    "flow.start_ts", "alert.signature", "alert.category", "alert.severity",
]

proto_types = ['icmp', 'ipv6-icmp', 'llc', 'lldp', 'sctp', 'tcp', 'udp']

final_columns = [
    "SrcIp", "DstIp", "TotBytes", "SrcBytes", "DstBytes", "TotPkts", "SrcPkts", "DstPkts", "Rate", "SrcRate", "DstRate",
    "Dur", "RunTime", "TcpRtt", "SynAck", "AckDat", "Seq",
    "Proto"
]

def get_local_ipv4_prefix(octets=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()

    parts = ip.split('.')
    if len(parts) != 4:
        raise ValueError("Beklenen IPv4 adresi.")

    return '.'.join(parts[:octets]) + '.'

local_prefix = ""

# Fonksiyon: Süre hesaplama
def calculate_duration(start_str, end_str):
    try:
        start = parser.parse(start_str)
        end = parser.parse(end_str)
        duration = (end - start).total_seconds()
        return duration if duration > 0 else np.nan
    except Exception:
        return np.nan

# API'ye veri gönderme (asenkron)
async def send_post_request(url, data):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=data) as response:
                logging.info(f"POST isteği gönderildi: {url} - Status: {response.status}")
                if response.status == 200:
                    result = await response.json()
                    logging.info(f"Yanıt: {json.dumps(result, indent=4)}")
                    return result
                else:
                    error_text = await response.text()
                    logging.error(f"Hata (status {response.status}): {error_text}")
                    return None
    except Exception as e:
        logging.error(f"İstek sırasında hata oluştu: {str(e)}")
        return None

# API sonuçlarını işleyip CSV’ye yazan ve apply_rules'u çağıran fonksiyon (senkron)
def process_api_result(result):
    """
    API'den gelen sonuçları işliyor: 
      - Eğer kaydın saldırı tipi "Benign" değilse, dış IP tespiti yapılıyor.
      - Sonuç CSV'ye ekleniyor.
      - apply_rules fonksiyonu çağrılıyor.
    """
    for rec in result.get("records", []):
        # API'den gelen key adlarının küçük harf olduğunu varsayıyoruz (gerekirse uyarlayın)
        src    = rec.get("src_ip", "")
        dst    = rec.get("dst_ip", "")
        attack = rec.get("classification") or rec.get("detection", "")
        
        # "Benign" olmayan kayıtlar için işlem yapılır
        if attack != "Benign":
            external_ip = ""
            # Kendi IP'nizin "10.0.0. - 10.0.1" aralığında olduğunu varsayarak 'dış' IP belirleniyor
            if src.startswith(local_prefix):
                external_ip = dst
            elif dst.startswith(local_prefix):
                external_ip = src

            # CSV'ye yazma
            with open(output_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([src, dst, attack])
            
            # Dış IP ve saldırı tipine göre kuralların uygulanması
            apply_rules(external_ip, attack)
            logging.info(f"apply_rules çağrıldı: dış IP -> {external_ip}, saldırı -> {attack}")
            save_changes()

MAX_LINES = 100

# Gerçek zamanlı eve.json takibi (asenkron)
async def follow_eve_json_optimized(file_path):
    line_count = 0
    async with aiofiles.open(file_path, 'r') as f:
        # Dosyanın en sonuna git
        await f.seek(0, os.SEEK_END)
        while True:
            line = await f.readline()
            if not line:
                await asyncio.sleep(0.2)
                continue
            line_count += 1
            if line_count >= MAX_LINES:
                await f.seek(0)
                await f.truncate()
                line_count = 0
                logging.info(f"{file_path} satır limiti aşıldı, içerik sıfırlandı.")
                await f.seek(0, os.SEEK_END)
            try:
                log_record = json.loads(line)
                filtered_log = {}
                # Parametre listesindeki her alanı kontrol et
                for param in parameters:
                    if param.startswith("flow.") and "flow" in log_record:
                        flow_key = param.split(".", 1)[1]
                        if flow_key in log_record["flow"]:
                            filtered_log[param] = log_record["flow"][flow_key]
                    elif param.startswith("alert.") and "alert" in log_record:
                        alert_key = param.split(".", 1)[1]
                        if alert_key in log_record["alert"]:
                            filtered_log[param] = log_record["alert"][alert_key]
                    elif param in log_record:
                        filtered_log[param] = log_record[param]
                
                if filtered_log.get("event_type") == "flow":
                    # DataFrame oluşturma ve gerekli dönüştürmeleri yapma
                    df_row = pd.DataFrame([filtered_log])
                    df_row['SrcIp'] = df_row['src_ip']
                    df_row['DstIp'] = df_row['dest_ip']
                    df_row['TotBytes'] = df_row['flow.bytes_toserver'] + df_row['flow.bytes_toclient']
                    df_row['SrcBytes'] = df_row['flow.bytes_toserver']
                    df_row['DstBytes'] = df_row['flow.bytes_toclient']
                    df_row['TotPkts'] = df_row['flow.pkts_toserver'] + df_row['flow.pkts_toclient']
                    df_row['SrcPkts'] = df_row['flow.pkts_toserver']
                    df_row['DstPkts'] = df_row['flow.pkts_toclient']
                    df_row['Dur'] = df_row.apply(lambda row: calculate_duration(row['flow.start'], row['flow.end']), axis=1)
                    df_row['RunTime'] = df_row['Dur']
                    df_row['Rate'] = df_row.apply(lambda row: row['TotBytes'] / row['Dur'] if row['Dur'] and row['Dur'] > 0 else 0.0, axis=1)
                    df_row['SrcRate'] = df_row.apply(lambda row: row['SrcBytes'] / row['Dur'] if row['Dur'] and row['Dur'] > 0 else 0.0, axis=1)
                    df_row['DstRate'] = df_row.apply(lambda row: row['DstBytes'] / row['Dur'] if row['Dur'] and row['Dur'] > 0 else 0.0, axis=1)
                    df_row['TcpRtt'] = 0.0
                    df_row['SynAck'] = 0.0
                    df_row['AckDat'] = 0.0
                    df_row['Seq'] = 1
                    df_row['Proto'] = df_row['proto']
                    for col in final_columns:
                        if col not in df_row.columns:
                            df_row[col] = False
                    df_final = df_row[final_columns].fillna(0)
                    
                    # Hazırlanan veriyi API için sözlük haline getir
                    local_prefix = get_local_ipv4_prefix()
                    sample_data = {
                        "local_prefix": local_prefix,
                        "data": df_final.to_dict(orient="records")
                    }
                    

                    # API'ye asenkron POST isteği yapılıyor
                    api_result = await send_post_request(API_PREDICT_URL, sample_data)
                    
                    # API yanıtı varsa sonuçları işleyip CSV'ye yaz ve apply_rules'u çağır
                    if api_result is not None and "records" in api_result:
                        # Bloklayıcı işlemlerden kaçınmak için to_thread kullanarak senkron fonksiyonu çağırıyoruz
                        await asyncio.to_thread(process_api_result, api_result)
            except json.JSONDecodeError:
                continue

# Ana fonksiyon
if __name__ == "__main__":
    logging.info("Gerçek zamanlı Suricata log takibi başlatılıyor...")
    asyncio.run(follow_eve_json_optimized(eve_log_path))