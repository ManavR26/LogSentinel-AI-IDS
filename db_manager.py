import sqlite3
import os

# The name of our database file
DB_NAME = "sentinel.db"

def init_db():
    """Creates the SQL table if it doesn't exist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # SQL Query to create the table
    # We add an 'is_threat' column that defaults to 0 (Safe)
    # Our AI will later update this to 1 (Dangerous)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_address TEXT,
            endpoint TEXT,
            status_code INTEGER,
            is_threat INTEGER DEFAULT 0
        )
    ''')
    
    conn.commit()
    conn.close()
    print("[DBMS] Database initialized successfully.")

def import_logs_to_db(log_file_path):
    """Reads the raw text log and inserts it into SQLite."""
    if not os.path.exists(log_file_path):
        print(f"[!] Error: File {log_file_path} not found. Run log_generator.py first!")
        return

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    print(f"[DBMS] Importing logs from {log_file_path}...")
    
    count = 0
    with open(log_file_path, "r") as f:
        for line in f:
            try:
                # LINE FORMAT: 2025-10-20 10:00:01 - 192.168.1.1 - GET /home - 200
                
                # Split the line by " - " to get the parts
                parts = line.strip().split(" - ")
                
                if len(parts) < 4:
                    continue # Skip broken lines
                
                timestamp = parts[0]
                ip = parts[1]
                # Remove "GET " so we just have the path like "/home"
                endpoint = parts[2].replace("GET ", "") 
                status = int(parts[3])
                
                # SQL INSERT Command
                cursor.execute('''
                    INSERT INTO logs (timestamp, ip_address, endpoint, status_code)
                    VALUES (?, ?, ?, ?)
                ''', (timestamp, ip, endpoint, status))
                
                count += 1
            except Exception as e:
                print(f"Skipping bad line: {line}")
                continue
                
    conn.commit()
    conn.close()
    print(f"[DBMS] Success! Imported {count} log entries into 'sentinel.db'.")

# This allows us to run this file directly to test it
if __name__ == "__main__":
    init_db()
    import_logs_to_db("server_logs.txt")