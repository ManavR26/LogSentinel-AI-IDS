from flask import Flask, render_template_string, redirect, url_for
import sqlite3
import os
# Import our modules
from db_manager import init_db, import_logs_to_db
from ai_engine import train_anomaly_detector

app = Flask(__name__)

# --- THE FRONTEND UI (HTML + CSS) ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>LogSentinel AI Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; color: #333; padding: 20px; }
        .container { max-width: 1000px; margin: 0 auto; }
        
        /* Header Section */
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; font-size: 24px; }
        
        /* Button Styling */
        .btn { background-color: #e74c3c; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold; transition: 0.3s; border: none; cursor: pointer; }
        .btn:hover { background-color: #c0392b; }
        
        /* Card Styling */
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }
        
        /* Table Styling */
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th { background-color: #34495e; color: white; padding: 12px; text-align: left; }
        td { padding: 12px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f1f1f1; }
        
        /* Threat Highlighting */
        .threat-row { border-left: 5px solid #e74c3c; background-color: #fff5f5; }
        .badge { background: #e74c3c; color: white; padding: 5px 10px; border-radius: 20px; font-size: 12px; }
        .safe { color: #27ae60; font-weight: bold; text-align: center; padding: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ LogSentinel <span style="font-size: 14px; opacity: 0.8;">| AI Intrusion Detection System</span></h1>
            <a href="/scan" class="btn">🔄 RUN NEW SCAN</a>
        </div>

        <div class="card">
            <h2>🚨 Detected Anomalies (High Confidence)</h2>
            <p>These requests were flagged by the Isolation Forest algorithm as statistical outliers.</p>
            
            {% if threats %}
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>IP Address</th>
                        <th>Endpoint (Vector)</th>
                        <th>Status</th>
                        <th>Tag</th>
                    </tr>
                </thead>
                <tbody>
                    {% for log in threats %}
                    <tr class="threat-row">
                        <td>{{ log[1] }}</td>
                        <td><strong>{{ log[2] }}</strong></td>
                        <td style="font-family: monospace; color: #d35400;">{{ log[3] }}</td>
                        <td>{{ log[4] }}</td>
                        <td><span class="badge">THREAT</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
                <div class="safe">✅ No active threats detected in the database.</div>
            {% endif %}
        </div>
        
        <div class="card">
            <h3>System Status</h3>
            <p>Database: <strong>Connected</strong> | AI Model: <strong>Active (IsolationForest)</strong></p>
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def dashboard():
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    # Query: Get only the rows where is_threat = 1
    cursor.execute("SELECT * FROM logs WHERE is_threat = 1 ORDER BY id DESC")
    threats = cursor.fetchall()
    conn.close()
    return render_template_string(HTML_TEMPLATE, threats=threats)

@app.route('/scan')
def run_full_scan():
    # 1. Initialize DB (just in case)
    init_db()
    
    # 2. Check if logs exist, then import
    if os.path.exists("server_logs.txt"):
        import_logs_to_db("server_logs.txt")
    
    # 3. Trigger the AI to analyze the new data
    train_anomaly_detector()
    
    # 4. Refresh the page to show results
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    print("Starting LogSentinel Dashboard...")
    app.run(debug=True, port=5000)