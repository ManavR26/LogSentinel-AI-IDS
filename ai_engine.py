import pandas as pd
import sqlite3
from sklearn.ensemble import IsolationForest
import joblib

DB_NAME = "sentinel.db"

def train_anomaly_detector():
    print("[AI] Connecting to Database...")
    conn = sqlite3.connect(DB_NAME)
    
    # 1. LOAD DATA: Read the SQL table into a Pandas DataFrame
    df = pd.read_sql("SELECT * FROM logs", conn)
    conn.close()

    if df.empty:
        print("[!] Error: Database is empty. Run db_manager.py first!")
        return

    # 2. FEATURE ENGINEERING (Converting Text -> Numbers)
    # The AI needs numbers to do math. We create two new features:
    
    # Feature A: Path Length
    # Logic: Normal users visit "/home" (short). 
    # Hackers visit "/login?user=admin' OR '1'='1" (long).
    df['path_length'] = df['endpoint'].apply(len)
    
    # Feature B: Is Admin?
    # Logic: If the URL contains "admin", it's higher risk.
    # Returns 1 if 'admin' is in the path, 0 if not.
    df['is_admin'] = df['endpoint'].apply(lambda x: 1 if 'admin' in x else 0)

    # We only train on these numerical columns
    features = df[['status_code', 'path_length', 'is_admin']]

    print("[AI] Training Isolation Forest Model...")
    
    # 3. TRAIN MODEL
    # contamination=0.1 means "Assume roughly 10% of the data is bad"
    model = IsolationForest(contamination=0.1, random_state=42)
    
    # fit_predict returns: 1 for Normal, -1 for Anomaly
    df['anomaly'] = model.fit_predict(features)
    
    # Convert results: Change -1 (Anomaly) to 1 (True Threat)
    df['is_threat'] = df['anomaly'].apply(lambda x: 1 if x == -1 else 0)

    # Count how many threats we found
    num_threats = df['is_threat'].sum()
    print(f"[AI] Analysis Complete. Detected {num_threats} potential threats.")

    # 4. SAVE RESULTS TO DB
    update_db_threats(df)

def update_db_threats(df):
    """Updates the SQL database with the AI's findings."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    print("[AI] Updating Database tags...")
    
    # Filter only the rows where AI said "Threat"
    threats = df[df['is_threat'] == 1]
    
    for index, row in threats.iterrows():
        # Update the 'is_threat' column for that specific ID
        cursor.execute("UPDATE logs SET is_threat = 1 WHERE id = ?", (row['id'],))
        
    conn.commit()
    conn.close()
    print("[AI] Database updated successfully.")

# Run directly to test
if __name__ == "__main__":
    train_anomaly_detector()