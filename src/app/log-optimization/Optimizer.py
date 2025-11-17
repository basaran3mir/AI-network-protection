import os
import shutil
import time

# Ayarlar
LOG_FILE = "src/res/logs/eve.json"
MAX_SIZE_MB = 50
ROTATE_COUNT = 5

def rotate_logs():
    # rotate: eve.json.(n-1) -> eve.json.n
    for i in range(ROTATE_COUNT - 1, 0, -1):
        older = f"{LOG_FILE}.{i}"
        newer = f"{LOG_FILE}.{i+1}"

        if os.path.exists(older):
            shutil.move(older, newer)

    # eve.json -> eve.json.1
    if os.path.exists(LOG_FILE):
        shutil.move(LOG_FILE, f"{LOG_FILE}.1")

    # Yeni boş dosya oluştur
    open(LOG_FILE, "w").close()
    print("[INFO] Log rotated.")

def monitor_log_file():
    print("[INFO] Suricata log monitor başlatıldı.")

    while True:
        if os.path.exists(LOG_FILE):
            size_mb = os.path.getsize(LOG_FILE) / (1024 * 1024)

            if size_mb >= MAX_SIZE_MB:
                print(f"[INFO] Boyut limitine ulaşıldı: {size_mb:.2f} MB")
                rotate_logs()

        time.sleep(5)

if __name__ == "__main__":
    monitor_log_file()
