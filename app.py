from flask import Flask, render_template_string, redirect, url_for
import sqlite3
import os
from db_manager import init_db, import_logs_to_db
from ai_engine import train_anomaly_detector

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LogSentinel | Security Dashboard</title>
    
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap" rel="stylesheet">

    <style>
        body { font-family: 'Inter', sans-serif; background-color: #f0f2f5; color: #1e293b; }
        
        .navbar { background: white; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); padding: 1rem; }
        .brand-icon { background: linear-gradient(135deg, #6366f1, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-size: 1.5rem; }
        
        .card { border: none; border-radius: 16px; background: white; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); transition: all 0.3s ease; }
        .card:hover { transform: translateY(-5px); box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1); }
        .card-header { background: white; border-bottom: 1px solid #f1f5f9; padding: 1.5rem; border-radius: 16px 16px 0 0 !important; font-weight: 600; }

        .table-responsive { border-radius: 16px; overflow: hidden; }
        .table { margin-bottom: 0; }
        .table thead th { background: #f8fafc; color: #64748b; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; border-bottom: none; padding: 1rem; }
        .table tbody td { padding: 1rem; vertical-align: middle; border-bottom: 1px solid #f1f5f9; }
        
        .log-row { transition: background-color 0.2s; cursor: pointer; }
        .log-row:hover { background-color: #f8fafc; }
        
        .badge-risk { padding: 0.5em 1em; border-radius: 9999px; font-weight: 600; font-size: 0.75rem; }
        .risk-Critical { background-color: #fef2f2; color: #ef4444; border: 1px solid #fecaca; }
        .risk-High { background-color: #fff7ed; color: #f97316; border: 1px solid #ffedd5; }
        .risk-Medium { background-color: #fefce8; color: #eab308; border: 1px solid #fef9c3; }
        
        .risk-meter { height: 6px; width: 60px; background: #e2e8f0; border-radius: 3px; overflow: hidden; display: inline-block; vertical-align: middle; margin-right: 8px; }
        .risk-fill { height: 100%; border-radius: 3px; }
        
        .endpoint-code { font-family: 'Fira Code', monospace; font-size: 0.85rem; color: #475569; background: #f1f5f9; padding: 4px 8px; border-radius: 6px; border: 1px solid #e2e8f0; }

        .btn-scan { background: linear-gradient(135deg, #6366f1, #8b5cf6); color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 12px; font-weight: 600; box-shadow: 0 4px 14px 0 rgba(99, 102, 241, 0.39); transition: all 0.2s; }
        .btn-scan:hover { transform: scale(1.05); box-shadow: 0 6px 20px rgba(99, 102, 241, 0.23); color: white; }
    </style>
</head>
<body>

    <nav class="navbar fixed-top">
        <div class="container">
            <a class="navbar-brand fw-bold d-flex align-items-center" href="#">
                <i class="fa-solid fa-shield-virus me-2" style="font-size: 1.5rem; color: #6366f1;"></i>
                LogSentinel
            </a>
            <div class="d-flex align-items-center gap-3">
                <span class="text-muted small d-none d-md-block"><i class="fa-solid fa-circle-check text-success me-1"></i>System Online</span>
                <a href="/scan" class="btn-scan text-decoration-none">
                    <i class="fa-solid fa-radar me-2"></i>Analyze Logs
                </a>
            </div>
        </div>
    </nav>

    <div class="container" style="margin-top: 100px; padding-bottom: 50px;">
        
        <div class="row mb-4">
            <div class="col-md-8">
                <div class="card h-100">
                    <div class="card-header d-flex justify-content-between">
                        <span>Traffic Analysis</span>
                        <small class="text-muted">Real-time AI Inference</small>
                    </div>
                    <div class="card-body">
                        <div style="height: 200px;">
                            <canvas id="threatChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card h-100 bg-white">
                    <div class="card-body d-flex flex-column justify-content-center align-items-center text-center">
                        <div class="mb-3 p-3 rounded-circle bg-light">
                            <i class="fa-solid fa-triangle-exclamation text-danger" style="font-size: 2rem;"></i>
                        </div>
                        <h2 class="fw-bold mb-0">{{ threat_count }}</h2>
                        <p class="text-muted mb-0">Threats Detected</p>
                        <hr class="w-50 my-3">
                        <small class="text-muted">Database: <strong>sentinel.db</strong></small>
                    </div>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header bg-white">
                <i class="fa-solid fa-list-ul me-2 text-primary"></i>Recent Security Alerts
            </div>
            <div class="card-body p-0">
                {% if threats %}
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th class="ps-4">Detected At</th>
                                <th>Source IP</th>
                                <th>Target Endpoint</th>
                                <th>Severity</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for log in threats %}
                            <tr class="log-row" title="Click for details">
                                <td class="ps-4 text-muted small">{{ log[1] }}</td>
                                <td class="fw-bold">{{ log[2] }}</td>
                                <td>
                                    <div class="endpoint-code">{{ log[3] }}</div>
                                </td>
                                <td>
                                    <div class="d-flex align-items-center">
                                        {% if log[6] == 'Critical' %}
                                            <div class="risk-meter"><div class="risk-fill" style="width: 100%; background: #ef4444;"></div></div>
                                            <span class="badge-risk risk-Critical">CRITICAL</span>
                                        {% elif log[6] == 'High' %}
                                            <div class="risk-meter"><div class="risk-fill" style="width: 70%; background: #f97316;"></div></div>
                                            <span class="badge-risk risk-High">HIGH</span>
                                        {% else %}
                                            <div class="risk-meter"><div class="risk-fill" style="width: 40%; background: #eab308;"></div></div>
                                            <span class="badge-risk risk-Medium">MEDIUM</span>
                                        {% endif %}
                                    </div>
                                </td>
                                <td>
                                    {% if log[4] == 200 %}
                                        <i class="fa-solid fa-circle-exclamation text-warning" title="Request allowed by server"></i>
                                    {% else %}
                                        <i class="fa-solid fa-shield text-success" title="Blocked (403/404)"></i>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <div class="text-center p-5">
                    <h5 class="text-muted">System Secure</h5>
                    <p class="small text-muted">No anomalies detected in the current log batch.</p>
                </div>
                {% endif %}
            </div>
        </div>

    </div>

    <script>
        var ctx = document.getElementById('threatChart').getContext('2d');
        var myChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Normal Traffic', 'High Risk', 'Medium Risk'],
                datasets: [{
                    data: [{{ safe_count }}, {{ threat_count }}, 0], 
                    backgroundColor: ['#e2e8f0', '#ef4444', '#eab308'],
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '80%',
                plugins: {
                    legend: { position: 'right', labels: { usePointStyle: true, boxWidth: 8 } }
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
    
    # Query: Get threats sorted by ID, including the new risk_level column
    cursor.execute("SELECT * FROM logs WHERE is_threat = 1 ORDER BY id DESC")
    threats = cursor.fetchall()
    
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
    app.run(debug=True, port=5000)