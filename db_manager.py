import sqlite3
import os

DB_NAME = "sentinel.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Updated Schema: Added 'risk_level' column
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_address TEXT,
            endpoint TEXT,
            status_code INTEGER,
            is_threat INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'Low' 
        )
    ''')
    
    conn.commit()
    conn.close()

def import_logs_to_db(log_file_path):
    if not os.path.exists(log_file_path):
        return

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    with open(log_file_path, "r") as f:
        for line in f:
            try:
                parts = line.strip().split(" - ")
                if len(parts) < 4:
                    continue
                
                timestamp = parts[0]
                ip = parts[1]
                endpoint = parts[2].replace("GET ", "") 
                status = int(parts[3])
                
                cursor.execute('''
                    INSERT INTO logs (timestamp, ip_address, endpoint, status_code)
                    VALUES (?, ?, ?, ?)
                ''', (timestamp, ip, endpoint, status))
            except Exception:
                continue
                
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    import_logs_to_db("server_logs.txt")