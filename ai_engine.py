import pandas as pd
import sqlite3
from sklearn.ensemble import IsolationForest
import joblib

DB_NAME = "sentinel.db"

def train_anomaly_detector():
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql("SELECT * FROM logs", conn)
    conn.close()

    if df.empty:
        return

    # Feature Engineering
    df['path_length'] = df['endpoint'].apply(len)
    df['is_admin'] = df['endpoint'].apply(lambda x: 1 if 'admin' in x else 0)

    features = df[['status_code', 'path_length', 'is_admin']]

    # Train Model (Isolation Forest)
    model = IsolationForest(contamination=0.1, random_state=42)
    df['anomaly'] = model.fit_predict(features)
    
    # Map results: -1 (Anomaly) -> 1 (Threat)
    df['is_threat'] = df['anomaly'].apply(lambda x: 1 if x == -1 else 0)

    update_db_threats(df)

def update_db_threats(df):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    threats = df[df['is_threat'] == 1]
    
    for index, row in threats.iterrows():
        cursor.execute("UPDATE logs SET is_threat = 1 WHERE id = ?", (row['id'],))
        
    conn.commit()
    conn.close()

if __name__ == "__main__":
    train_anomaly_detector()
    print("Model inference complete.")