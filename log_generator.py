import random
import time
from datetime import datetime

# Define the file where we will save the logs
LOG_FILE = "server_logs.txt"

# --- THE "NORMAL" TRAFFIC ---
# These represent regular users just browsing your site
NORMAL_IPS = ["192.168.1.5", "192.168.1.10", "10.0.0.5", "172.16.0.22"]
NORMAL_PATHS = ["/home", "/about", "/contact", "/products", "/login", "/dashboard"]
USER_AGENTS = ["Mozilla/5.0", "Chrome/90.0", "Safari/14.0"]

# --- THE "ATTACK" TRAFFIC (The Security Part) ---
# These IPs represent the "Hackers"
ATTACK_IPS = ["45.22.19.11", "105.99.2.55", "185.200.11.1"] 
# These are real-world attack payloads:
ATTACK_PAYLOADS = [
    "/login?user=admin' OR '1'='1",       # SQL Injection (Trying to bypass login)
    "/admin/config.php",                  # Reconnaissance (Looking for sensitive files)
    "/phpmyadmin",                        # Vulnerability Scanner (Looking for DB tools)
    "/.env",                              # Credential Theft (Looking for API keys)
    "/api/v1/users/delete_all"            # Malicious API Call
]

def generate_log():
    with open(LOG_FILE, "a") as f:
        # 90% chance of normal traffic, 10% chance of attack
        if random.random() > 0.1:
            # Generate SAFE Log
            ip = random.choice(NORMAL_IPS)
            path = random.choice(NORMAL_PATHS)
            status = 200 # OK
        else:
            # Generate ATTACK Log
            ip = random.choice(ATTACK_IPS)
            path = random.choice(ATTACK_PAYLOADS)
            # 50/50 chance the server blocked it (403) or let it through (200)
            status = 403 if random.random() > 0.5 else 200
            
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Format: TIME - IP - REQUEST - STATUS
        log_entry = f"{timestamp} - {ip} - GET {path} - {status}\n"
        
        f.write(log_entry)
        print(f"Generated: {log_entry.strip()}")

if __name__ == "__main__":
    print("--- STARTING TRAFFIC SIMULATION (Press Ctrl+C to stop) ---")
    try:
        while True:
            generate_log()
            # Wait 0.5 seconds between logs so it looks like real-time traffic
            time.sleep(0.5) 
    except KeyboardInterrupt:
        print("\n--- STOPPED ---")