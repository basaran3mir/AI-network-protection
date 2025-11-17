import json
import time
import random
from datetime import datetime

LOG_FILE = "src/res/logs/eve.json"  # Kendi yolun neyse onu yaz

def generate_random_dns_event():
    return {
        "timestamp": datetime.now().isoformat(),
        "flow_id": random.randint(1000000, 9999999999),
        "event_type": "dns",
        "src_ip": f"10.0.1.{random.randint(1, 254)}",
        "src_port": random.randint(1024, 65535),
        "dest_ip": "10.0.0.5",
        "dest_port": 53,
        "proto": "UDP",
        "dns": {
            "type": "query",
            "id": random.randint(1000, 9999),
            "rrname": random.choice([
                "google.com",
                "github.com",
                "debian.pool.ntp.org",
                "cloudflare.com"
            ]),
            "rrtype": random.choice(["A", "AAAA"]),
            "tx_id": random.randint(0, 5)
        }
    }

def write_logs_forever():
    print("[INFO] eve.json log generator çalışıyor...")

    while True:
        event = generate_random_dns_event()
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")

        time.sleep(0.1)  # Çok hızlı dolmasını istersen 0.01 yap

if __name__ == "__main__":
    write_logs_forever()
