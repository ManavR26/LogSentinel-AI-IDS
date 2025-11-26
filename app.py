from flask import Flask, render_template_string, redirect, url_for
import sqlite3
import os
# Import our modules
from db_manager import init_db, import_logs_to_db
from ai_engine import train_anomaly_detector

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LogSentinel | AI Defense</title>
    
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap" rel="stylesheet">

    <style>
        body { font-family: 'Inter', sans-serif; background-color: #f8f9fa; color: #2c3e50; }
        
        /* Navbar Styling */
        .navbar { background-color: #ffffff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .navbar-brand { font-weight: 600; color: #2c3e50 !important; letter-spacing: -0.5px; }
        .brand-icon { color: #4e73df; }

        /* Card Styling */
        .card { border: none; border-radius: 12px; box-shadow: 0 0.15rem 1.75rem 0 rgba(58, 59, 69, 0.1); margin-bottom: 25px; transition: transform 0.2s; }
        .card:hover { transform: translateY(-2px); }
        .card-header { background-color: white; border-bottom: 1px solid #f0f2f5; font-weight: 600; border-radius: 12px 12px 0 0 !important; padding: 15px 20px; }

        /* Status Indicators */
        .status-dot { height: 10px; width: 10px; border-radius: 50%; display: inline-block; margin-right: 5px; }
        .dot-green { background-color: #1cc88a; box-shadow: 0 0 5px #1cc88a; }
        .dot-red { background-color: #e74a3b; box-shadow: 0 0 5px #e74a3b; }

        /* Table Styling */
        .table-hover tbody tr:hover { background-color: #f8f9fc; }
        .badge-threat { background-color: #e74a3b; color: white; font-size: 0.8rem; padding: 5px 10px; }
        .code-snippet { font-family: 'Consolas', monospace; color: #e74a3b; background: #fff5f5; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }

        /* Button Styling */
        .btn-primary-custom { background-color: #4e73df; border: none; padding: 10px 20px; font-weight: 600; }
        .btn-primary-custom:hover { background-color: #2e59d9; }
    </style>
</head>
<body>

    <nav class="navbar navbar-expand-lg navbar-light fixed-top">
        <div class="container">
            <a class="navbar-brand" href="#">
                <i class="fa-solid fa-shield-halved brand-icon"></i> LogSentinel <span class="text-muted fw-light">| AI IDS</span>
            </a>
            <a href="/scan" class="btn btn-primary-custom btn-sm rounded-pill shadow-sm">
                <i class="fa-solid fa-rotate"></i> Run New Scan
            </a>
        </div>
    </nav>

    <div class="container" style="margin-top: 80px;">
        
        <div class="row">
            <div class="col-md-7">
                <div class="card h-100">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <span><i class="fa-solid fa-chart-pie me-2 text-primary"></i>Traffic Analysis</span>
                        <span class="badge bg-light text-dark border">Real-Time</span>
                    </div>
                    <div class="card-body">
                        <div style="height: 250px;">
                            <canvas id="threatChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-5">
                <div class="card h-100">
                    <div class="card-header">
                        <i class="fa-solid fa-server me-2 text-success"></i>System Health
                    </div>
                    <div class="card-body">
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item d-flex justify-content-between align-items-center border-0 px-0 pb-0">
                                Database Connection
                                <span><span class="status-dot dot-green"></span>Active</span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between align-items-center border-0 px-0 pb-0 mt-3">
                                AI Model Status
                                <span><span class="status-dot dot-green"></span>IsolationForest Ready</span>
                            </li>
                            <hr class="my-4">
                            <li class="list-group-item d-flex justify-content-between align-items-center border-0 px-0">
                                Total Requests Scanned
                                <span class="fw-bold fs-5">{{ total_scanned }}</span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between align-items-center border-0 px-0">
                                High-Risk Threats
                                <span class="fw-bold fs-5 text-danger">{{ threat_count }}</span>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mt-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header bg-danger text-white">
                        <i class="fa-solid fa-triangle-exclamation me-2"></i>Detected Anomalies (High Confidence)
                    </div>
                    <div class="card-body p-0">
                        {% if threats %}
                        <div class="table-responsive">
                            <table class="table table-hover align-middle mb-0">
                                <thead class="table-light">
                                    <tr>
                                        <th class="ps-4">Time</th>
                                        <th>Source IP</th>
                                        <th>Attack Vector (Endpoint)</th>
                                        <th>HTTP Status</th>
                                        <th>Risk Level</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for log in threats %}
                                    <tr>
                                        <td class="ps-4 text-muted small">{{ log[1] }}</td>
                                        <td class="fw-bold text-dark">{{ log[2] }}</td>
                                        <td><span class="code-snippet">{{ log[3] }}</span></td>
                                        <td>
                                            {% if log[4] == 200 %}
                                            <span class="badge bg-warning text-dark">200 (Bypassed)</span>
                                            {% else %}
                                            <span class="badge bg-secondary">{{ log[4] }} (Blocked)</span>
                                            {% endif %}
                                        </td>
                                        <td><span class="badge badge-threat rounded-pill">CRITICAL</span></td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                        {% else %}
                        <div class="text-center p-5">
                            <i class="fa-regular fa-circle-check fa-3x text-success mb-3"></i>
                            <p class="h5">No active threats detected.</p>
                            <p class="text-muted">Your system is clean.</p>
                        </div>
                        {% endif %}
                    </div>
                </div>
            </div>
        </div>
        
        <footer class="text-center mt-5 mb-5 text-muted small">
            <p>LogSentinel AI v1.0 &copy; 2025</p>
        </footer>

    </div>

    <script>
        var ctx = document.getElementById('threatChart').getContext('2d');
        var myChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Safe Traffic', 'Threats Detected'],
                datasets: [{
                    data: [{{ safe_count }}, {{ threat_count }}],
                    backgroundColor: ['#1cc88a', '#e74a3b'],
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '75%',
                plugins: {
                    legend: { position: 'bottom', labels: { usePointStyle: true, padding: 20 } }
                }
            }
        });
    </script>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    conn = sqlite3.connect("sentinel.db")
    cursor = conn.cursor()
    
    #Get the list of threats for the table
    cursor.execute("SELECT * FROM logs WHERE is_threat = 1 ORDER BY id DESC")
    threats = cursor.fetchall()
    
    # Get Counts for the Chart
    # Handle case where tables might be empty on first run
    try:
        cursor.execute("SELECT COUNT(*) FROM logs WHERE is_threat = 0")
        safe_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM logs WHERE is_threat = 1")
        threat_count = cursor.fetchone()[0]
    except:
        safe_count = 0
        threat_count = 0
    
    total_scanned = safe_count + threat_count
    
    conn.close()
    
    return render_template_string(
        HTML_TEMPLATE, 
        threats=threats, 
        safe_count=safe_count, 
        threat_count=threat_count,
        total_scanned=total_scanned
    )

@app.route('/scan')
def run_full_scan():
    init_db()
    if os.path.exists("server_logs.txt"):
        import_logs_to_db("server_logs.txt")
    train_anomaly_detector()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    print("Starting LogSentinel Dashboard...")
    app.run(debug=True, port=5000)