import random
import time
from datetime import datetime

LOG_FILE = "server_logs.txt"

NORMAL_IPS = ["192.168.1.5", "192.168.1.10", "10.0.0.5", "172.16.0.22"]
NORMAL_PATHS = ["/home", "/about", "/contact", "/products", "/login", "/dashboard"]

ATTACK_IPS = ["45.22.19.11", "105.99.2.55", "185.200.11.1"] 
ATTACK_PAYLOADS = [
    "/login?user=admin' OR '1'='1",
    "/admin/config.php",
    "/phpmyadmin",
    "/.env",
    "/api/v1/users/delete_all"
]

def generate_log():
    with open(LOG_FILE, "a") as f:
        if random.random() > 0.1:
            ip = random.choice(NORMAL_IPS)
            path = random.choice(NORMAL_PATHS)
            status = 200
        else:
            ip = random.choice(ATTACK_IPS)
            path = random.choice(ATTACK_PAYLOADS)
            status = 403 if random.random() > 0.5 else 200
            
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp} - {ip} - GET {path} - {status}\n"
        
        f.write(log_entry)
        print(f"Logged: {log_entry.strip()}")

if __name__ == "__main__":
    print("Initializing Traffic Simulation...")
    try:
        while True:
            generate_log()
            time.sleep(0.5) 
    except KeyboardInterrupt:
        print("\nSimulation Stopped.")